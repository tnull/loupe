use super::*;
use crate::secrets::MasterKey;
use crate::{review_tests, transaction, Db};

fn seed(db: &Db, policy: &CampaignPolicyV2) {
	review_tests::seed(db);
	db.with_conn(|conn| {
		conn.execute_batch("DELETE FROM jobs;
		 INSERT INTO workers(id,name,kind,cert_fingerprint,created_at) VALUES(1,'worker','worker',zeroblob(32),0);")?;
		let snapshot = policy.snapshot()?;
		conn.execute("UPDATE review_campaigns SET effective_policy=?1,effective_policy_digest=?2,deadline_at=1000 WHERE campaign_id=1",
			params![snapshot.expose(),snapshot.digest().as_slice()])?;
		Ok(())
	}).unwrap();
}

fn fixture() -> Db {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	seed(&db, &CampaignPolicyV2::default());
	db
}

fn insert_job(tx: &Transaction<'_>, id: i64, kind: &str, band: &str, queued: bool) -> Result<()> {
	let hash = id.to_be_bytes().repeat(4);
	tx.execute(
		"INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,scheduling_band,
		 attempts,worker_id,job_capability_hash,lease_expires_at,enqueued_at)
		 VALUES(?1,1,?2,?3,1,11,?4,?5,1,?6,100,0)",
		params![
			id,
			kind,
			if queued { "queued" } else { "leased" },
			band,
			if queued { 0 } else { 1 },
			hash
		],
	)?;
	Ok(())
}

#[test]
fn pool_order_and_every_exhaustion_combination_follow_the_contract() {
	let policy = CampaignPolicyV2::default();
	for general_full in [false, true] {
		for urgent_full in [false, true] {
			for verification_full in [false, true] {
				let spent = Spending {
					general: if general_full { 56 } else { 0 },
					urgent: if urgent_full { 4 } else { 0 },
					verification: if verification_full { 4 } else { 0 },
				};
				for (class, eligible) in [
					(WorkClass::Preparation, vec![Pool::General]),
					(WorkClass::Survey, vec![Pool::General]),
					(WorkClass::Drilldown, vec![Pool::General]),
					(WorkClass::UrgentDrilldown, vec![Pool::General, Pool::Urgent]),
					(WorkClass::Verification, vec![Pool::General, Pool::Verification]),
					(
						WorkClass::UrgentVerification,
						vec![Pool::General, Pool::Verification, Pool::Urgent],
					),
				] {
					let expected = eligible
						.iter()
						.find(|pool| match pool {
							Pool::General => !general_full,
							Pool::Urgent => !urgent_full,
							Pool::Verification => !verification_full,
						})
						.copied();
					assert_eq!(
						choose_pool(&policy, spent, class).unwrap(),
						match expected {
							Some(pool) => Selection::Pool(pool),
							None => Selection::Refused(
								if general_full && urgent_full && verification_full {
									CapacityRefusal::CampaignBudget
								} else {
									CapacityRefusal::ProtectedCapacity
								}
							),
						}
					);
				}
			}
		}
	}
	for invalid in [
		Spending { general: -1, ..Spending::default() },
		Spending { general: 57, ..Spending::default() },
		Spending { urgent: 5, ..Spending::default() },
		Spending { general: i64::MAX, urgent: 1, ..Spending::default() },
	] {
		assert!(choose_pool(&policy, invalid, WorkClass::Preparation).is_err());
	}
}

#[test]
fn initialization_never_invents_historical_charges_or_uses_tampered_policy() {
	let db = fixture();
	db.with_conn(|conn| {
		assert!(
			transaction::immediate(conn, |tx| initialize(tx, 2)).is_err(),
			"historical v1/unknown policy never initializes"
		);
		let tx = conn.transaction()?;
		insert_job(&tx, 10, "survey", "normal", true)?;
		assert!(initialize(&tx, 1).is_err(), "nonempty campaigns never backfill");
		tx.rollback()?;
		let tx = conn.transaction()?;
		tx.execute(
			"UPDATE review_campaigns SET effective_policy_digest=zeroblob(32) WHERE campaign_id=1",
			[],
		)?;
		assert!(initialize(&tx, 1).is_err());
		tx.rollback()?;
		transaction::immediate(conn, |tx| {
			assert_eq!(initialize(tx, 1)?, Spending::default());
			assert_eq!(initialize(tx, 1)?, Spending::default());
			Ok(())
		})?;
		Ok(())
	})
	.unwrap();
}

#[test]
fn preparation_and_first_lease_charge_once_retries_and_cancellation_never_refund() {
	let db = fixture();
	db.with_conn(|conn| transaction::immediate(conn,|tx| {
		initialize(tx,1)?;
		insert_job(tx,10,"survey","normal",true)?;
		assert_eq!(charge(tx,10,WorkClass::Preparation,1)?,Charged::Fresh(Pool::General));
		tx.execute("UPDATE jobs SET state='leased',attempts=1 WHERE id=10",[])?;
		assert_eq!(charge(tx,10,WorkClass::Survey,2)?,Charged::Replayed(Pool::General));
		tx.execute("UPDATE jobs SET state='cancelled',worker_id=NULL,job_capability_hash=NULL WHERE id=10",[])?;
		assert_eq!(charge(tx,10,WorkClass::Survey,3)?,Charged::Replayed(Pool::General));
		insert_job(tx,11,"drilldown","high",false)?;
		assert_eq!(charge(tx,11,WorkClass::Drilldown,4)?,Charged::Fresh(Pool::General));
		tx.execute("UPDATE jobs SET attempts=3 WHERE id=11",[])?;
		assert_eq!(charge(tx,11,WorkClass::Drilldown,4)?,Charged::Replayed(Pool::General));
		assert_eq!(get_spending(tx,1)?.unwrap().total()?,2);
		tx.execute("DELETE FROM jobs WHERE id IN(10,11)",[])?;
		assert_eq!(get_spending(tx,1)?.unwrap().total()?,2);
		assert_eq!(tx.query_row("SELECT COUNT(*) FROM job_admission_charges",[],|row|row.get::<_,i64>(0))?,0);
		assert!(tx.execute("UPDATE campaign_admission_spending SET general_spent=0",[]).is_err());
		Ok(())
	})).unwrap();
}

#[test]
fn late_urgent_and_verification_use_protected_pools_without_raising_total() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			initialize(tx, 1)?;
			for id in 10..66 {
				insert_job(tx, id, "survey", "normal", false)?;
				assert_eq!(charge(tx, id, WorkClass::Survey, 1)?, Charged::Fresh(Pool::General));
			}
			insert_job(tx, 70, "drilldown", "normal", false)?;
			assert_eq!(
				charge(tx, 70, WorkClass::Drilldown, 1)?,
				Charged::Refused(CapacityRefusal::ProtectedCapacity)
			);
			for id in 71..75 {
				insert_job(tx, id, "verify", "urgent", false)?;
				assert_eq!(
					charge(tx, id, WorkClass::UrgentVerification, 1)?,
					Charged::Fresh(Pool::Verification)
				);
			}
			insert_job(tx, 75, "verify", "normal", false)?;
			assert_eq!(
				charge(tx, 75, WorkClass::Verification, 1)?,
				Charged::Refused(CapacityRefusal::ProtectedCapacity)
			);
			for id in 76..80 {
				insert_job(tx, id, "drilldown", "urgent", false)?;
				assert_eq!(
					charge(tx, id, WorkClass::UrgentDrilldown, 1)?,
					Charged::Fresh(Pool::Urgent)
				);
			}
			insert_job(tx, 80, "verify", "urgent", false)?;
			assert_eq!(
				charge(tx, 80, WorkClass::UrgentVerification, 1)?,
				Charged::Refused(CapacityRefusal::CampaignBudget)
			);
			assert_eq!(
				get_spending(tx, 1)?.unwrap(),
				Spending { general: 56, urgent: 4, verification: 4 }
			);
			tx.execute("UPDATE jobs SET state='queued',attempts=2 WHERE id=10", [])?;
			assert_eq!(charge(tx, 10, WorkClass::Survey, 1)?, Charged::Replayed(Pool::General));
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn wrong_class_and_speculative_or_expired_children_never_consume_capacity() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			initialize(tx, 1)?;
			insert_job(tx, 10, "drilldown", "normal", false)?;
			assert!(charge(tx, 10, WorkClass::UrgentDrilldown, 1).is_err());
			assert!(charge(tx, 10, WorkClass::Verification, 1).is_err());
			assert!(charge(tx, 10, WorkClass::Preparation, 1).is_err());
			assert!(charge(tx, 10, WorkClass::Drilldown, 100).is_err());
			insert_job(tx, 11, "verify", "normal", true)?;
			assert!(charge(tx, 11, WorkClass::Verification, 1).is_err());
			tx.execute("UPDATE jobs SET state='leased',attempts=2 WHERE id=11", [])?;
			assert!(
				charge(tx, 11, WorkClass::Verification, 1).is_err(),
				"unknown historical attempt must not create its first charge"
			);
			// The composite campaign ownership FK rejects this even before the
			// accounting guard; do not disable it to fabricate a reachable row.
			assert!(tx.execute("UPDATE jobs SET repo_id=2 WHERE id=10", []).is_err());
			assert_eq!(get_spending(tx, 1)?.unwrap(), Spending::default());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn failed_admission_rolls_back_job_and_charge_including_terminal_cancellation() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| initialize(tx, 1))?;
		let result: Result<()> = transaction::immediate(conn, |tx| {
			insert_job(tx, 10, "survey", "normal", false)?;
			charge(tx, 10, WorkClass::Survey, 1)?;
			Err(Error::Conflict(Conflict::Assignment))
		});
		assert!(result.is_err());
		transaction::immediate(conn, |tx| {
			assert_eq!(get_spending(tx, 1)?.unwrap(), Spending::default());
			assert_eq!(
				tx.query_row("SELECT COUNT(*) FROM jobs WHERE id=10", [], |row| row
					.get::<_, i64>(0))?,
				0
			);
			insert_job(tx, 11, "survey", "normal", false)?;
			tx.execute("UPDATE review_campaigns SET state='cancelled' WHERE campaign_id=1", [])?;
			assert!(charge(tx, 11, WorkClass::Survey, 1).is_err());
			assert_eq!(get_spending(tx, 1)?.unwrap(), Spending::default());
			Ok(())
		})?;
		Ok(())
	})
	.unwrap();
}

#[test]
fn spending_survives_restart_and_concurrent_last_slot_claims() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("admission.db");
	let key = MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	seed(
		&db,
		&CampaignPolicyV2 {
			campaign_max_jobs: 1,
			campaign_urgent_reserve: 0,
			campaign_verification_reserve: 0,
			..CampaignPolicyV2::default()
		},
	);
	db.with_conn(|conn| transaction::immediate(conn, |tx| initialize(tx, 1))).unwrap();
	drop(db);
	let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
	let handles: Vec<_> = (10..12)
		.map(|id| {
			let db = Db::open(&path, &key).unwrap();
			let barrier = barrier.clone();
			std::thread::spawn(move || {
				barrier.wait();
				db.with_conn(|conn| {
					transaction::immediate(conn, |tx| {
						insert_job(tx, id, "survey", "normal", false)?;
						match charge(tx, id, WorkClass::Survey, 1)? {
							Charged::Fresh(_) => Ok(true),
							Charged::Refused(_) => Err(Error::Conflict(Conflict::CampaignBudget)),
							Charged::Replayed(_) => panic!("new jobs cannot replay"),
						}
					})
				})
				.is_ok()
			})
		})
		.collect();
	assert_eq!(
		handles.into_iter().map(|handle| handle.join().unwrap()).filter(|won| *won).count(),
		1
	);
	let db = Db::open(&path, &key).unwrap();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			assert_eq!(get_spending(tx, 1)?.unwrap().total()?, 1);
			assert_eq!(
				tx.query_row("SELECT COUNT(*) FROM jobs WHERE campaign_id=1", [], |row| row
					.get::<_, i64>(0))?,
				1
			);
			Ok(())
		})
	})
	.unwrap();
}
