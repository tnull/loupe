use std::panic::{catch_unwind, AssertUnwindSafe};

use super::fixtures::*;
use super::v4::{run_with_probe, Step};
use super::v4_tests::{populated_v3, Snapshot};
use super::*;

#[test]
fn v4_precommit_failures_reopen_as_complete_v3_and_retry() {
	for step in [
		Step::PreCheck,
		Step::Tables,
		Step::Copy,
		Step::VerifyCopy,
		Step::Replace,
		Step::Additions,
		Step::ForeignKeyCheck,
		Step::IntegrityCheck,
		Step::Commit,
	] {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("v3.sqlite");
		let mut conn = open(&path);
		populated_v3(&mut conn);
		let before = Snapshot::take(&conn);
		let old_schema = schema(&conn);
		let error = run_with_probe(&mut conn, &mut |at, _| {
			if at == step {
				Err(migration_error(format!("injected {step:?}")))
			} else {
				Ok(())
			}
		})
		.expect_err("precommit failure must roll back v4");
		assert!(error.to_string().contains("injected"), "{error}");
		assert!(fk_enabled(&conn));
		drop(conn);
		let mut conn = open(&path);
		assert_eq!(markers(&conn), (3, 3), "{step:?}");
		assert_eq!(schema(&conn), old_schema, "{step:?}");
		before.assert_unchanged(&conn);
		apply_v3(&mut conn).unwrap();
		apply_pending(&mut conn).unwrap();
		assert_eq!(markers(&conn), (4, 4));
		before.assert_unchanged(&conn);
	}
}

#[test]
fn v4_checks_exact_copies_and_foreign_key_and_integrity_validation() {
	for (at, sql, expected) in [
		(Step::VerifyCopy, "UPDATE generation_inventory_new SET path = 'src/bib.rs' WHERE inventory_entry_id = 11", "historical generation_inventory copy differs"),
		(Step::VerifyCopy, "UPDATE finding_review_details_new SET counterevidence = assumptions_gaps, assumptions_gaps = counterevidence WHERE finding_id = 11", "historical finding_review_details copy differs"),
		(Step::VerifyCopy, "UPDATE finding_review_details_new SET profile_digest = x'332211' WHERE finding_id = 11", "historical finding_review_details copy differs"),
		(Step::VerifyCopy, "UPDATE verification_attempt_details_new SET terminal_digest = x'ff2200' WHERE verification_id = 11", "historical verification_attempt_details copy differs"),
		(Step::ForeignKeyCheck, "UPDATE verification_attempt_details SET verification_proof_id = 12 WHERE verification_id = 11", "foreign_key_check"),
		(Step::IntegrityCheck, "PRAGMA ignore_check_constraints = ON; UPDATE generation_inventory SET disposition_revision = -1 WHERE inventory_entry_id = 11; PRAGMA ignore_check_constraints = OFF;", "integrity_check"),
	] {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("v3.sqlite");
		let mut conn = open(&path);
		populated_v3(&mut conn);
		let old_schema = schema(&conn);
		let before = Snapshot::take(&conn);
		let error = run_with_probe(&mut conn, &mut |step, conn| {
			if step == at { conn.execute_batch(sql)?; }
			Ok(())
		}).expect_err("validation must detect injected corruption");
		assert!(error.to_string().contains(expected), "{error}");
		assert!(fk_enabled(&conn));
		drop(conn);
		let mut conn = open(&path);
		assert_eq!(markers(&conn), (3, 3));
		assert_eq!(schema(&conn), old_schema);
		before.assert_unchanged(&conn);
		apply_pending(&mut conn).unwrap();
	}
}

#[test]
fn v4_refuses_leases_before_ddl_and_holds_the_write_lock() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("v3.sqlite");
	let mut conn = open(&path);
	populated_v3(&mut conn);
	busy(&conn);
	let old_schema = schema(&conn);
	let before = Snapshot::take(&conn);
	let error = run_with_probe(&mut conn, &mut |step, _| {
		assert!(matches!(step, Step::PreCheck | Step::Restore), "DDL must not start");
		Ok(())
	})
	.unwrap_err();
	assert!(error.to_string().contains("schema v4 upgrade refused: 1 leased job"), "{error}");
	assert!(fk_enabled(&conn));
	drop(conn);
	let mut conn = open(&path);
	assert_eq!(markers(&conn), (3, 3));
	assert_eq!(schema(&conn), old_schema);
	before.assert_unchanged(&conn);
	apply_v3(&mut conn).unwrap();
	conn.execute("UPDATE jobs SET state = 'cancelled' WHERE id = 9", []).unwrap();
	let writer = open(&path);
	writer.busy_timeout(std::time::Duration::ZERO).unwrap();
	let mut checked = false;
	run_with_probe(&mut conn, &mut |step, _| {
		if step == Step::PreCheck {
			let error =
				writer.execute("UPDATE jobs SET state = 'leased' WHERE id = 7", []).unwrap_err();
			assert_eq!(error.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy));
			checked = true;
		}
		Ok(())
	})
	.unwrap();
	assert!(checked);
	assert_eq!(markers(&conn), (4, 4));
}

#[test]
fn v4_restores_prior_foreign_keys_after_errors_panics_and_success() {
	for prior in [false, true] {
		for fail_at in [None, Some(Step::Copy), Some(Step::Restore)] {
			for panic in [false, true] {
				let mut conn = Connection::open_in_memory().unwrap();
				populated_v3(&mut conn);
				conn.pragma_update(None, "foreign_keys", prior).unwrap();
				let result = catch_unwind(AssertUnwindSafe(|| {
					run_with_probe(&mut conn, &mut |step, _| {
						if Some(step) == fail_at {
							assert!(!panic, "injected panic");
							return Err(migration_error("injected restoration/failure"));
						}
						Ok(())
					})
				}));
				if panic && fail_at.is_some() {
					assert!(result.is_err());
				} else {
					assert_eq!(result.unwrap().is_err(), fail_at.is_some());
				}
				assert!(conn.is_autocommit());
				assert_eq!(fk_enabled(&conn), prior);
				let expected = if fail_at == Some(Step::Copy) { 3 } else { 4 };
				assert_eq!(markers(&conn), (expected, expected));
			}
		}
	}
}

#[test]
fn v4_restoration_failure_rejects_bootstrap_after_complete_commit() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("v3.sqlite");
	let mut conn = open(&path);
	populated_v3(&mut conn);
	let before = Snapshot::take(&conn);
	drop(conn);
	let result = crate::Db::bootstrap_with_migration(
		Connection::open(&path).unwrap(),
		&crate::secrets::MasterKey::for_tests(),
		|conn| {
			run_with_probe(conn, &mut |step, _| {
				if step == Step::Restore {
					Err(migration_error("injected FK restore failure"))
				} else {
					Ok(())
				}
			})
		},
	);
	assert!(result.is_err());
	let db = crate::Db::open(&path, &crate::secrets::MasterKey::for_tests()).unwrap();
	db.with_conn(|conn| {
		assert_eq!(markers(conn), (4, 4));
		assert!(fk_enabled(conn));
		before.assert_unchanged(conn);
		assert!(rows(conn, "PRAGMA foreign_key_check").is_empty());
		Ok(())
	})
	.unwrap();
}

#[test]
fn v4_real_commit_failure_rolls_back_to_v3() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("v3.sqlite");
	let mut conn = open(&path);
	populated_v3(&mut conn);
	conn.pragma_update(None, "journal_mode", "DELETE").unwrap();
	conn.busy_timeout(std::time::Duration::ZERO).unwrap();
	let reader = Connection::open(&path).unwrap();
	reader
		.pragma_update(
			None,
			"key",
			format!("x'{}'", crate::secrets::MasterKey::for_tests().to_hex()),
		)
		.unwrap();
	reader.execute_batch("BEGIN; SELECT * FROM jobs;").unwrap();
	let before = Snapshot::take(&conn);
	let old_schema = schema(&conn);
	let mut reached_commit = false;
	let error = run_with_probe(&mut conn, &mut |step, _| {
		if step == Step::Commit {
			reached_commit = true;
		}
		Ok(())
	})
	.unwrap_err();
	assert!(reached_commit, "{error}");
	assert_eq!(error.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy));
	assert!(fk_enabled(&conn));
	assert!(conn.is_autocommit());
	drop(reader);
	drop(conn);
	let mut conn = open(&path);
	assert_eq!(markers(&conn), (3, 3));
	assert_eq!(schema(&conn), old_schema);
	before.assert_unchanged(&conn);
	apply_pending(&mut conn).unwrap();
}
