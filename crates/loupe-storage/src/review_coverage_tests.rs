use loupe_core::review_payload::{GeneratedProfile, UnitResultPayloadV1};
use rusqlite::{params, Connection, Transaction};
use serde_json::json;

use crate::{
	generations, review_authority, review_unit_results, review_units, transaction, Db, Result,
};

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn payload(follow_up: bool) -> UnitResultPayloadV1 {
	UnitResultPayloadV1::from_json(
		&json!({
			"format":"loupe.unit_result","version":1,"review_unit_id":31,"assignment_epoch":0,
			"disposition":if follow_up { "needs_follow_up" } else { "no_lead_found" },
			"inspected_refs":[{"path":"cafe\u{301}.rs"}],"created_lead_ids":[],
			"counterevidence":"A guard exists","proof_gaps":"Caller trace",
			"follow_up":follow_up.then_some("Inspect caller"),
			"continuation":follow_up.then_some("source_analysis_remaining")
		})
		.to_string(),
	)
	.unwrap()
}
fn seed(db: &Db, follow_up: bool) {
	crate::review_tests::seed(db);
	db.with_conn(|conn| transaction::immediate(conn, |tx| {
		let profile=GeneratedProfile::new("{}")?;
		let policy=crate::admission_policy::CampaignPolicyV2::default().snapshot()?;
		tx.execute("UPDATE review_generations SET generation_commit_sha=?1,profile_version=1,generated_profile=?2,generated_profile_digest=?3 WHERE generation_id=11",params![SHA,profile.expose(),profile.digest().as_slice()])?;
		tx.execute("UPDATE review_campaigns SET target_commit_sha=?1,effective_policy=?2,effective_policy_digest=?3 WHERE campaign_id=1",params![SHA,policy.expose(),policy.digest().as_slice()])?;
		tx.execute("INSERT INTO campaign_admission_spending(campaign_id,policy_version) VALUES(1,2)",[])?;
		crate::workers::insert(tx,"coverage",crate::workers::WorkerKind::Worker,&[7;32],0)?;
		tx.execute("UPDATE jobs SET state='leased',worker_id=1,attempts=1,lease_expires_at=100,head_sha=?1,workflow_contract_version=1,job_capability_hash=?2 WHERE id=101",params![SHA,[3u8;32].as_slice()])?;
		tx.execute("INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,received_entry_count,expected_digest,created_at,sealed_at) VALUES(11,1,101,1,1,zeroblob(32),0,1)",[])?;
		tx.execute("INSERT INTO generation_inventory(generation_id,path,source_path,raw_path,blob_sha,entry_kind,git_mode,manifest_position,disposition,created_at) VALUES(11,?1,?1,?2,?3,'tracked',33188,0,'context',0)",params!["cafe\u{301}.rs","cafe\u{301}.rs".as_bytes(),SHA])?;
		tx.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_by_job_id,created_at) VALUES(31,11,'unit','Unit','Review source','[]',101,0)",[])?;
		review_unit_results::insert_evidence(tx,&review_unit_results::NewResultEvidence{generation_id:11,produced_by_job:101,commit_sha:SHA,profile_version:1,payload:&payload(follow_up)},0)?;
		Ok(())
	})).unwrap();
}
fn fixture(follow_up: bool) -> Db {
	let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
	seed(&db, follow_up);
	db
}
fn covered(conn: &Connection) -> Result<bool> {
	Ok(conn.query_row(&format!("SELECT {} FROM review_units u JOIN review_generations g USING(generation_id) WHERE u.review_unit_id=31",review_units::UNIT_COVERED),[],|r|r.get(0))?)
}
fn eligible(conn: &Connection) -> Result<bool> {
	Ok(conn.query_row(&format!("SELECT {} FROM review_units u JOIN review_generations g USING(generation_id) WHERE u.review_unit_id=31",*review_units::UNIT_NEEDS_WORK),[],|r|r.get(0))?)
}
fn fresh_authority(tx: &Transaction<'_>) -> Result<bool> {
	let lease = review_authority::authorize(
		tx,
		crate::jobs::ActiveLease {
			identity: crate::jobs::LeaseIdentity {
				job_id: 101,
				worker_id: 1,
				capability_hash: &[3; 32],
			},
			now: 1,
		},
		loupe_core::JobKind::Survey,
	)?
	.unwrap();
	lease.survey_unit(31, 0, true)
}

#[test]
fn managed_historical_result_never_suppresses_current_work() {
	let db = fixture(false);
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			assert!(covered(tx)?, "valid Recorded evidence is the positive control");
			assert!(!fresh_authority(tx)?);
			tx.execute(
				"UPDATE review_unit_results SET result_payload='{}',result_digest=zeroblob(32)",
				[],
			)?;
			assert!(!covered(tx)?, "managed Historical evidence cannot establish coverage");
			assert!(eligible(tx)?);
			assert!(fresh_authority(tx)?);
			assert_eq!(generations::coverage_rollup(tx, 11)?.missing_results, 1);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn managed_corrupt_digest_never_suppresses_current_work() {
	fixture(false)
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				assert!(covered(tx)?);
				tx.execute("UPDATE review_unit_results SET result_digest=zeroblob(32)", [])?;
				assert!(!covered(tx)?, "corrupt result digest cannot establish coverage");
				assert!(eligible(tx)?);
				assert!(fresh_authority(tx)?);
				assert_eq!(generations::coverage_rollup(tx, 11)?.missing_results, 1);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn corrupt_coverage_does_not_deny_fresh_result_authority() {
	fixture(false)
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				assert!(!fresh_authority(tx)?);
				tx.execute("UPDATE review_unit_results SET result_digest=zeroblob(32)", [])?;
				assert!(
					fresh_authority(tx)?,
					"corrupt prior result must not deny exact fresh-result authority"
				);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn historical_coverage_does_not_hide_the_ranked_ordinary_candidate() {
	fixture(false)
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				tx.execute("UPDATE jobs SET state='succeeded'", [])?;
				let policy = crate::scheduler::ClaimPolicy::default();
				let request = crate::admission_candidates::Request {
					worker_id: 1,
					legacy_kinds: &[],
					phase_kinds: &[loupe_core::JobKind::Survey],
					now: 1,
					policy: &policy,
					limit: 16,
				};
				assert!(crate::admission_candidates::ranked(tx, &request)?.is_empty());
				tx.execute(
					"UPDATE review_unit_results SET result_payload='{}',result_digest=zeroblob(32)",
					[],
				)?;
				let rows = crate::admission_candidates::ranked(tx, &request)?;
				assert!(
					rows.iter().any(|row| row.source
						== crate::admission_candidates::CandidateKind::OrdinarySurvey
						&& row.id == 11),
					"historical evidence must not remove the ordinary candidate from ranking"
				);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn current_result_truth_rejects_every_provenance_and_projection_mismatch() {
	for damage in [
		"UPDATE review_units SET assignment_epoch=1",
		"UPDATE review_units SET stale=1",
		"UPDATE review_units SET created_by_job_id=NULL",
		"UPDATE jobs SET kind='drilldown' WHERE id=101",
		"UPDATE jobs SET repo_id=2 WHERE id=101",
		"UPDATE jobs SET generation_id=12 WHERE id=101",
		"UPDATE jobs SET workflow_contract_version=2 WHERE id=101",
		"UPDATE jobs SET head_sha=NULL WHERE id=101",
		"UPDATE review_unit_results SET profile_version=2",
		"UPDATE review_unit_results SET commit_sha='old'",
		"UPDATE review_unit_results SET invalidated=1",
		"UPDATE review_unit_results SET result_payload='{}'",
		"UPDATE review_unit_results SET result_payload='{'",
		"UPDATE review_unit_results SET result_payload=x'01'",
		"UPDATE review_unit_results SET result_digest=x'01'",
		"UPDATE review_unit_results SET inspected_refs='[\"not-an-object\"]'",
		"UPDATE review_unit_results SET inspected_refs='{'",
		"UPDATE review_unit_results SET inspected_refs=x'01'",
		"UPDATE review_unit_results SET counterevidence='different projection'",
		"UPDATE generation_inventory SET source_path='café.rs',raw_path=CAST('café.rs' AS BLOB)",
		"UPDATE generation_inventory SET manifest_position=NULL",
		"UPDATE generation_manifests SET sealed_at=NULL",
		"UPDATE generation_manifests SET received_entry_count=0",
		"DELETE FROM generation_manifests",
		"UPDATE review_generations SET generated_profile='{' WHERE generation_id=11",
		"UPDATE review_generations SET generated_profile=x'01' WHERE generation_id=11",
		"UPDATE review_generations SET generated_profile_digest=zeroblob(32) WHERE generation_id=11",
	] {
		for follow in [false,true] {
			fixture(follow).with_conn(|conn| {
				// Model legacy/corrupt relational provenance that normal FK writes
				// reject; the read predicate must independently refuse it.
				conn.pragma_update(None,"foreign_keys",false)?;
				transaction::immediate(conn,|tx| {
				let before=generations::coverage_rollup(tx,11)?;
				assert_eq!((before.missing_results,before.needs_follow_up),(i64::from(follow),i64::from(follow)));
				tx.execute_batch(damage)?;
				let changes=tx.total_changes();
				assert!(!covered(tx)?,"{damage}");
				let after=generations::coverage_rollup(tx,11)?;
				assert_eq!((after.missing_results,after.needs_follow_up),(1,0),"{damage}");
				assert_eq!(tx.total_changes(),changes,"coverage does not repair or delete data");
				Ok(())
			})}).unwrap();
		}
	}
}

#[test]
fn exact_persisted_assignment_owns_current_evidence_not_live_conflicting_jobs() {
	fixture(false).with_conn(|conn|transaction::immediate(conn,|tx| {
		tx.execute("UPDATE review_units SET created_by_job_id=NULL",[])?;
		assert!(!covered(tx)?);
		tx.execute("INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch,completed) VALUES(101,31,0,0,1)",[])?;
		assert!(covered(tx)?,"completed assignment remains evidence provenance");
		tx.execute("UPDATE job_assigned_review_units SET assignment_epoch=1",[])?;
		assert!(!covered(tx)?);
		tx.execute("UPDATE job_assigned_review_units SET assignment_epoch=0",[])?;
		tx.execute("INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(102,31,0,0)",[])?;
		assert!(!covered(tx)?,"another live owner revokes coverage");
		tx.execute("UPDATE jobs SET state='succeeded' WHERE id=102",[])?;
		assert!(covered(tx)?);
		Ok(())
	})).unwrap();
}

#[test]
fn missing_manifest_never_downgrades_other_managed_provenance() {
	for signal in ["spending", "policy", "publication", "checkpoint", "typed_result"] {
		fixture(false).with_conn(|conn|transaction::immediate(conn,|tx| {
			tx.execute("DELETE FROM generation_manifests",[])?;
			tx.execute("UPDATE review_campaigns SET generation_id=NULL,effective_policy='{' WHERE campaign_id=1",[])?;
			if signal!="spending" {tx.execute("DELETE FROM campaign_admission_spending",[])?;}
			if signal=="policy" {tx.execute("UPDATE review_campaigns SET effective_policy='{\"version\":2}' WHERE campaign_id=1",[])?;}
			if signal=="publication" || signal=="checkpoint" {
				let op=if signal=="publication" {"publish_profile"}else{"submit_unit_result"};
				tx.execute("INSERT INTO job_checkpoints(job_id,client_key,operation,payload_digest,response,created_at) VALUES(101,'accepted',?1,zeroblob(32),'{}',0)",[op])?;
			}
			if signal!="typed_result" {tx.execute("UPDATE review_unit_results SET result_payload='{}'",[])?;}
			assert!(!covered(tx)?,"{signal} remains managed");
			assert!(!generations::coverage_rollup(tx,11)?.complete(),"{signal}");
			Ok(())
		})).unwrap();
	}
}

#[test]
fn unmanaged_historical_coverage_and_follow_up_remain_compatible() {
	for follow in [false, true] {
		fixture(follow).with_conn(|conn|transaction::immediate(conn,|tx| {
			tx.execute("DELETE FROM generation_manifests",[])?;
			tx.execute("DELETE FROM campaign_admission_spending",[])?;
			tx.execute("UPDATE review_campaigns SET effective_policy='{}'",[])?;
			tx.execute("UPDATE review_unit_results SET result_payload='{}',result_digest=zeroblob(32),produced_by_job_id=NULL",[])?;
			assert_eq!(covered(tx)?,!follow);
			let rollup=generations::coverage_rollup(tx,11)?;
			assert!(rollup.ready);
			assert_eq!((rollup.missing_results,rollup.needs_follow_up),(i64::from(follow),i64::from(follow)));
			Ok(())
		})).unwrap();
	}
}

#[test]
fn empty_managed_generation_requires_current_readiness_to_be_complete() {
	for damage in ["DELETE FROM generation_manifests","UPDATE generation_manifests SET sealed_at=NULL","UPDATE review_generations SET generated_profile='{' WHERE generation_id=11","UPDATE review_generations SET generated_profile=x'01' WHERE generation_id=11","UPDATE review_generations SET generated_profile_digest=zeroblob(32) WHERE generation_id=11"] {
		fixture(false).with_conn(|conn|transaction::immediate(conn,|tx| {
			tx.execute("DELETE FROM review_units",[])?;
			tx.execute("UPDATE review_generations SET corroboration_state='satisfied' WHERE generation_id=11",[])?;
			assert!(generations::coverage_rollup(tx,11)?.complete());
			tx.execute_batch(damage)?;
			let rollup=generations::coverage_rollup(tx,11)?;
			assert_eq!((rollup.missing_results,rollup.needs_follow_up,rollup.unresolved_inventory),(0,0,0));
			assert!(!rollup.ready && !rollup.complete(),"{damage}");
			assert!(generations::set_coverage(tx,11,generations::Coverage::Complete).is_err());
			Ok(())
		})).unwrap();
	}
}

#[test]
fn held_work_remains_incomplete_despite_conclusive_projection() {
	fixture(true)
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				crate::unit_holds::record_follow_up(
					tx,
					31,
					1,
					101,
					0,
					loupe_core::review_payload::ContinuationClass::SourceAnalysisRemaining,
					0,
				)?;
				// A hold is scheduling truth independent of any conclusive result.
				review_unit_results::insert_evidence(
					tx,
					&review_unit_results::NewResultEvidence {
						generation_id: 11,
						produced_by_job: 101,
						commit_sha: SHA,
						profile_version: 1,
						payload: &payload(false),
					},
					1,
				)?;
				assert!(covered(tx)?);
				assert!(!eligible(tx)?);
				let rollup = generations::coverage_rollup(tx, 11)?;
				assert_eq!((rollup.missing_results, rollup.needs_follow_up), (1, 1));
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn damaged_mapped_unit_references_leave_inventory_unresolved() {
	let db = fixture(false);
	db.with_conn(|conn| transaction::immediate(conn, |tx| {
		let valid = crate::source_refs::UnitRefs::new(payload(false).inspected_refs)?.expose().to_owned();
		tx.execute("UPDATE review_units SET source_refs=?1 WHERE review_unit_id=31", [&valid])?;
		tx.execute("UPDATE generation_inventory SET disposition='mapped' WHERE generation_id=11", [])?;
		tx.execute("INSERT INTO generation_inventory_units(generation_id,inventory_entry_id,review_unit_id) SELECT 11,inventory_entry_id,31 FROM generation_inventory WHERE generation_id=11", [])?;
		assert_eq!(generations::coverage_rollup(tx, 11)?.unresolved_inventory, 0);
		for raw in ["{".to_owned(), "[\"not-an-object\"]".to_owned(), " ".repeat(65537), "{\"path\":\"cafe\\u0301.rs\"}".to_owned()] {
			tx.execute("UPDATE review_units SET source_refs=?1 WHERE review_unit_id=31", [&raw])?;
			let rollup = generations::coverage_rollup(tx, 11);
			assert!(rollup.is_ok(), "damaged derived references must not abort coverage: {rollup:?}");
			assert_eq!(rollup?.unresolved_inventory, 1);
		}
		tx.execute("UPDATE review_units SET source_refs=x'01' WHERE review_unit_id=31", [])?;
		assert_eq!(generations::coverage_rollup(tx, 11)?.unresolved_inventory, 1);
		tx.execute("UPDATE review_units SET source_refs=?1 WHERE review_unit_id=31", [&valid])?;
		assert_eq!(generations::coverage_rollup(tx, 11)?.unresolved_inventory, 0);
		Ok(())
	})).unwrap();
}

#[test]
fn empty_generation_requires_a_deliverable_profile_version() {
	fixture(false)
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				tx.execute("DELETE FROM review_units", [])?;
				tx.execute(
					"UPDATE review_generations SET profile_version=?1 WHERE generation_id=11",
					[i64::from(u32::MAX)],
				)?;
				assert!(generations::coverage_rollup(tx, 11)?.complete());
				tx.execute(
					"UPDATE review_generations SET profile_version=?1 WHERE generation_id=11",
					[i64::from(u32::MAX) + 1],
				)?;
				let rollup = generations::coverage_rollup(tx, 11)?;
				assert!(
					!rollup.ready && !rollup.complete(),
					"an undeliverable profile cannot establish readiness"
				);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn corruption_is_not_a_sql_error_and_sql_failures_are_not_incomplete_results() {
	fixture(false)
		.with_conn(|conn| {
			conn.execute("DROP TABLE generation_inventory_units", [])?;
			let error = transaction::immediate(conn, |tx| generations::coverage_rollup(tx, 11))
				.unwrap_err();
			assert!(matches!(error, crate::Error::Sqlite(_)));
			Ok(())
		})
		.unwrap();
}

#[test]
fn encrypted_reopen_registers_the_same_read_only_coverage_validator() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("coverage.db");
	let key = crate::secrets::MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	seed(&db, false);
	db.with_conn(|conn| {
		assert!(covered(conn)?);
		Ok(())
	})
	.unwrap();
	drop(db);
	Db::open(&path, &key)
		.unwrap()
		.with_conn(|conn| {
			assert!(covered(conn)?);
			conn.execute("UPDATE review_unit_results SET result_digest=zeroblob(32)", [])?;
			assert!(!covered(conn)?);
			Ok(())
		})
		.unwrap();
}

#[test]
fn scalar_is_bounded_strict_and_explicitly_registered_for_raw_connections() {
	use rusqlite::types::Value;
	let sql = "SELECT loupe_unit_result_epoch(?1,?2,?3,?4,?5,?6,?7,?8,?9)";
	let conn = Connection::open_in_memory().unwrap();
	assert!(conn.prepare(sql).is_err(), "missing registration is a loud error");
	crate::review_coverage::register(&conn).unwrap();
	crate::review_coverage::register(&conn).unwrap();
	let bytes = payload(false).canonical_bytes().unwrap();
	let valid = vec![
		Value::Text(String::from_utf8(bytes.clone()).unwrap()),
		Value::Blob(crate::canonical::digest(&bytes).to_vec()),
		Value::Integer(31),
		Value::Text("no_lead_found".into()),
		Value::Text(
			crate::source_refs::InspectedRefs::new(payload(false).inspected_refs)
				.unwrap()
				.expose()
				.into(),
		),
		Value::Null,
		Value::Null,
		Value::Null,
		Value::Null,
	];
	let epoch = |args: &[Value]| {
		conn.query_row(sql, rusqlite::params_from_iter(args), |row| row.get::<_, Option<i64>>(0))
			.unwrap()
	};
	assert_eq!(epoch(&valid), Some(0));
	for index in 0..9 {
		for bad in [
			Value::Null,
			Value::Blob(vec![255]),
			Value::Integer(-1),
			Value::Real(0.5),
			Value::Text("{".into()),
		] {
			if index >= 5 && bad == Value::Null {
				continue;
			}
			let mut args = valid.clone();
			args[index] = bad;
			assert_eq!(epoch(&args), None, "argument {index}");
		}
	}
	for index in [0, 4] {
		let mut args = valid.clone();
		args[index] = Value::Text(" ".repeat(UnitResultPayloadV1::MAX_BYTES + 1));
		assert_eq!(epoch(&args), None);
	}
	for raw in [
		"{}",
		"{\"format\":\"loupe.unit_result\",\"version\":2}",
		"{\"format\":\"loupe.unit_result\",\"format\":\"loupe.unit_result\"}",
	] {
		let mut args = valid.clone();
		args[0] = Value::Text(raw.into());
		args[1] = Value::Blob(crate::canonical::digest(raw.as_bytes()).to_vec());
		assert_eq!(epoch(&args), None);
	}
}
