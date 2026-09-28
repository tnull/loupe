use super::*;

fn long_campaign() -> (Db, i64, i64) {
	let db = fixture();
	let (campaign, tail) = db.with_conn(|conn| transaction::immediate(conn, |tx| {
		let policy = ReviewPolicy { campaign_max_jobs: 1, campaign_urgent_reserve: 0, campaign_verification_reserve: 0, ..ReviewPolicy::default() };
		let (campaign, generation) = idle_campaign(tx, 1, &policy, 0, false)?;
		for n in 0..257 {
			tx.execute("INSERT INTO review_units(generation_id,client_review_unit_key,title,objective,source_refs,closure_criteria,created_at) VALUES(?1,?2,'Unit','Review boundary','[]',?3,0)", rusqlite::params![generation, format!("unit-{n}"), if n == 256 {"x".repeat(1001)} else {"Complete the source review".into()}])?;
		}
		Ok((campaign, tx.last_insert_rowid()))
	})).unwrap();
	(db, campaign, tail)
}

#[test]
fn normal_completion_waits_for_the_full_bounded_validation_scan() {
	let (db, campaign, tail) = long_campaign();
	let mut maintenance = campaign::Maintenance::default();
	let first = campaign::tick(&db, 1, &mut maintenance).unwrap();
	assert_eq!(first.completed, 0, "normal completion cannot bypass an incomplete validation scan");
	db.with_conn(|conn| {
		assert_eq!(campaigns::get(conn, campaign)?.unwrap().state, campaigns::State::Active);
		assert_eq!(
			conn.query_row("SELECT COUNT(*) FROM review_units WHERE status='open'", [], |r| r
				.get::<_, i64>(0))?,
			257
		);
		Ok(())
	})
	.unwrap();
	let second = campaign::tick(&db, 2, &mut maintenance).unwrap();
	assert_eq!(second.completed, 1);
	db.with_conn(|conn| {
		assert_eq!(
			conn.query_row(
				"SELECT defer_reason FROM review_units WHERE review_unit_id=?1",
				[tail],
				|r| r.get::<_, String>(0)
			)?,
			"invalid_review_state",
			"the healthy prefix must not hide a damaged tail"
		);
		assert_eq!(campaigns::get(conn, campaign)?.unwrap().state, campaigns::State::Finished);
		Ok(())
	})
	.unwrap();
}

#[test]
fn failed_maintenance_transaction_does_not_advance_its_cursor() {
	let (db, campaign, tail) = long_campaign();
	let mut maintenance = campaign::Maintenance::default();
	assert_eq!(campaign::tick(&db, 1, &mut maintenance).unwrap().completed, 0);
	db.with_conn(|conn| {
		conn.execute_batch(&format!("CREATE TEMP TRIGGER reject_tail BEFORE UPDATE OF status ON review_units WHEN OLD.review_unit_id={tail} BEGIN SELECT RAISE(ABORT,'injected maintenance failure'); END"))?;
		Ok(())
	}).unwrap();
	assert_eq!(campaign::tick(&db, 2, &mut maintenance).unwrap().failed, 1);
	db.with_conn(|conn| {
		assert_eq!(campaigns::get(conn, campaign)?.unwrap().state, campaigns::State::Active);
		assert_eq!(
			conn.query_row("SELECT COUNT(*) FROM review_units WHERE status='open'", [], |r| r
				.get::<_, i64>(0))?,
			257
		);
		conn.execute_batch("DROP TRIGGER reject_tail")?;
		Ok(())
	})
	.unwrap();
	assert_eq!(campaign::tick(&db, 3, &mut maintenance).unwrap().completed, 1);
	db.with_conn(|conn| {
		assert_eq!(
			conn.query_row(
				"SELECT defer_reason FROM review_units WHERE review_unit_id=?1",
				[tail],
				|r| r.get::<_, String>(0)
			)?,
			"invalid_review_state",
			"rollback must leave the bad row next in the scan"
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn deadline_control_skips_a_failing_integrity_scan() {
	let db = fixture();
	let campaign = db
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let (campaign, job) = created(campaign::open(
					tx,
					&request(RequestedRef::Pinned(SHA)),
					&ReviewPolicy::default(),
					0,
				)?);
				assert_eq!(jobs::get(tx, job)?.unwrap().state, JobState::Queued);
				tx.execute_batch("DROP TABLE job_admission_charges")?;
				Ok(campaign)
			})
		})
		.unwrap();
	let mut maintenance = campaign::Maintenance::default();
	assert_eq!(
		campaign::tick(&db, 1, &mut maintenance).unwrap().failed,
		1,
		"positive control: integrity scan really fails"
	);
	let report = campaign::tick(&db, 21600, &mut maintenance).unwrap();
	assert_eq!((report.failed, report.deadline_reached), (0, 1));
	db.with_conn(|conn| {
		assert_eq!(campaigns::get(conn, campaign)?.unwrap().state, campaigns::State::Finished);
		assert_eq!(
			conn.query_row("SELECT COUNT(*) FROM jobs WHERE state='cancelled'", [], |r| r
				.get::<_, i64>(0))?,
			1
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn one_shot_finish_cannot_bypass_a_partial_scan_and_restart_rescans_safely() {
	let (db, campaign, _) = long_campaign();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			assert_eq!(campaign::try_finish(tx, campaign, 1)?, None);
			Ok(())
		})
	})
	.unwrap();
	let mut maintenance = campaign::Maintenance::default();
	assert_eq!(campaign::tick(&db, 2, &mut maintenance).unwrap().completed, 0);
	let mut restarted = campaign::Maintenance::default();
	assert_eq!(campaign::tick(&db, 3, &mut restarted).unwrap().completed, 0);
	assert_eq!(campaign::tick(&db, 4, &mut restarted).unwrap().completed, 1);
}
