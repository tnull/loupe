use rusqlite::{params, Connection};

use super::apply_pending;
use super::fixtures::*;
use super::v4_tests::populated_v3;

fn prepared() -> Connection {
	let mut conn = Connection::open_in_memory().unwrap();
	conn.pragma_update(None, "foreign_keys", true).unwrap();
	populated_v3(&mut conn);
	apply_pending(&mut conn).unwrap();
	for (id, repo, admitted) in [(11, 1, 21), (12, 2, 22)] {
		conn.execute(
			"INSERT INTO jobs (id, repo_id, kind, state, enqueued_at, campaign_id, generation_id)
             VALUES (?1, ?2, 'survey', 'succeeded', 100, ?3, ?3)",
			params![admitted, repo, id],
		)
		.unwrap();
		conn.execute("INSERT INTO generation_manifests (generation_id, format_version, owner_job_id, expected_entry_count, expected_digest, created_at)
             VALUES (?1, 1, ?1, 1, zeroblob(32), 100)", [id]).unwrap();
		conn.execute("INSERT INTO generation_inventory_units VALUES (?1, ?1, ?1)", [id]).unwrap();
		conn.execute("INSERT INTO job_terminal_payloads VALUES (?1, 'drilldown', '{}')", [id])
			.unwrap();
		for (table, subject) in
			[("lead_drilldown_intents", "lead_id"), ("finding_verification_intents", "finding_id")]
		{
			conn.execute(
				&format!(
					"INSERT INTO {table}
                 ({subject}, repo_id, generation_id, originating_job_id, originating_campaign_id,
                  admission_campaign_id, source_commit_sha, profile_version, profile_digest,
                  intent_revision, intent_kind, logical_sequence, state, admitted_job_id,
                  accepted_band, accepted_score, priority_policy_version, created_at, updated_at)
                 VALUES (?1, ?2, ?1, ?1, ?1, ?1, 'commit', 1, zeroblob(32),
                         1, 'initial_handoff', 0, 'admitted', ?3, 'normal', 100, 1, 100, 100)"
				),
				params![id, repo, admitted],
			)
			.unwrap();
		}
		conn.execute("INSERT INTO survey_continuation_batches
             (batch_id, repo_id, generation_id, campaign_id, producer_job_id, batch_ordinal,
              logical_sequence, continuation_class, state, admitted_job_id, expected_unit_count,
              accepted_band, accepted_score, priority_policy_version, created_at)
             VALUES (?1, ?2, ?1, ?1, ?1, 0, 1, 'source_analysis_remaining', 'admitted', ?3, 1, 'normal', 100, 1, 100)", params![id, repo, admitted]).unwrap();
		conn.execute("INSERT INTO review_unit_holds
             (review_unit_id, generation_id, producing_job_id, producing_result_id, source_assignment_epoch,
              continuation_class, pending_batch_id, batch_position, created_at, updated_at)
             VALUES (?1, ?1, ?1, ?1, 9, 'source_analysis_remaining', ?1, 0, 100, 100)", [id]).unwrap();
		conn.execute("INSERT INTO campaign_admission_spending VALUES (?1, 2, 3, 2, 1)", [id])
			.unwrap();
		conn.execute(
			"INSERT INTO job_admission_charges VALUES (?1, ?2, 'general')",
			params![admitted, id],
		)
		.unwrap();
	}
	conn
}

fn rejects(conn: &Connection, sql: &str, code: i32) {
	let error = conn.execute_batch(sql).expect_err("invalid storage contract must be rejected");
	assert_eq!(error.sqlite_error().map(|e| e.extended_code), Some(code), "{sql}: {error}");
}

#[test]
fn v4_ownership_rejects_cross_repository_and_generation_links() {
	let conn = prepared();
	for sql in [
		"UPDATE generation_manifests SET owner_job_id = 12 WHERE generation_id = 11",
		"UPDATE generation_inventory_units SET review_unit_id = 12 WHERE inventory_entry_id = 11",
		"UPDATE generation_inventory_units SET generation_id = 12 WHERE inventory_entry_id = 11",
		"UPDATE lead_drilldown_intents SET repo_id = 2 WHERE lead_id = 11",
		"UPDATE lead_drilldown_intents SET generation_id = 12 WHERE lead_id = 11",
		"UPDATE lead_drilldown_intents SET originating_job_id = 12 WHERE lead_id = 11",
		"UPDATE lead_drilldown_intents SET originating_campaign_id = 12 WHERE lead_id = 11",
		"UPDATE lead_drilldown_intents SET admission_campaign_id = 12 WHERE lead_id = 11",
		"UPDATE lead_drilldown_intents SET admitted_job_id = 22 WHERE lead_id = 11",
		"UPDATE finding_verification_intents SET repo_id = 2 WHERE finding_id = 11",
		"UPDATE finding_verification_intents SET generation_id = 12 WHERE finding_id = 11",
		"UPDATE finding_verification_intents SET originating_job_id = 12 WHERE finding_id = 11",
		"UPDATE finding_verification_intents SET originating_campaign_id = 12 WHERE finding_id = 11",
		"UPDATE finding_verification_intents SET admission_campaign_id = 12 WHERE finding_id = 11",
		"UPDATE finding_verification_intents SET admitted_job_id = 22 WHERE finding_id = 11",
		"UPDATE survey_continuation_batches SET campaign_id = 12 WHERE batch_id = 11",
		"UPDATE survey_continuation_batches SET producer_job_id = 12, batch_ordinal = 1 WHERE batch_id = 11",
		"UPDATE survey_continuation_batches SET generation_id = 12 WHERE batch_id = 11",
		"UPDATE survey_continuation_batches SET admitted_job_id = 12 WHERE batch_id = 11",
		"UPDATE review_unit_holds SET producing_job_id = 12 WHERE review_unit_id = 11",
		"UPDATE review_unit_holds SET producing_result_id = 12 WHERE review_unit_id = 11",
		"UPDATE review_unit_holds SET pending_batch_id = 12, batch_position = 1 WHERE review_unit_id = 11",
		"UPDATE review_unit_holds SET generation_id = 12 WHERE review_unit_id = 11",
		"UPDATE job_admission_charges SET campaign_id = 12 WHERE job_id = 21",
		"UPDATE verification_attempt_details SET verification_proof_id = 12 WHERE verification_id = 11",
		"UPDATE job_terminal_payloads SET phase = 'verify' WHERE job_id = 11",
	] { rejects(&conn, sql, rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY); }
	conn.execute_batch("INSERT INTO review_units (review_unit_id, generation_id, client_review_unit_key, title, objective, source_refs, created_at)
         VALUES (15, 11, 'other', 'title', 'objective', '[]', 100);
         INSERT INTO review_unit_results (review_unit_result_id, review_unit_id, produced_by_job_id, commit_sha, profile_version, disposition, inspected_refs, result_payload, result_digest, created_at)
         VALUES (15, 15, 11, 'commit', 1, 'needs_follow_up', '[]', '{}', zeroblob(32), 100);").unwrap();
	rejects(
		&conn,
		"UPDATE review_unit_holds SET producing_result_id = 15 WHERE review_unit_id = 11",
		rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
	);
}

#[test]
fn v4_generation_purge_preserves_canonical_evidence_and_verification_intent() {
	let conn = prepared();
	let retained = [
		"findings",
		"finding_verifications",
		"verification_attempt_details",
		"verification_proofs",
		"proof_artifact_blobs",
		"proof_artifacts",
		"proof_executions",
		"verification_proof_artifacts",
		"verification_proof_executions",
		"job_terminal_receipts",
		"job_terminal_payloads",
		"campaign_admission_spending",
		"job_admission_charges",
	];
	let before: Vec<_> = retained
		.iter()
		.map(|t| rows(&conn, &format!("SELECT * FROM {t} ORDER BY rowid")))
		.collect();
	conn.execute("DELETE FROM review_generations WHERE generation_id = 11", []).unwrap();
	for (table, expected) in retained.iter().zip(before) {
		assert_eq!(
			rows(&conn, &format!("SELECT * FROM {table} ORDER BY rowid")),
			expected,
			"{table}"
		);
	}
	for table in [
		"generation_inventory",
		"generation_manifests",
		"generation_inventory_units",
		"review_unit_holds",
		"survey_continuation_batches",
		"lead_drilldown_intents",
	] {
		assert!(
			rows(&conn, &format!("SELECT * FROM {table} WHERE generation_id = 11")).is_empty(),
			"{table}"
		);
	}
	assert_eq!(rows(&conn, "SELECT repo_id, generation_id, originating_job_id, originating_campaign_id, admission_campaign_id, state, source_commit_sha, admitted_job_id FROM finding_verification_intents WHERE finding_id = 11"), vec![vec![1.into(), rusqlite::types::Value::Null, 11.into(), 11.into(), 11.into(), "admitted".to_owned().into(), "commit".to_owned().into(), 21.into()]]);
	assert_eq!(
		rows(&conn, "SELECT origin_lead_id FROM finding_review_details WHERE finding_id = 11"),
		vec![vec![rusqlite::types::Value::Null]]
	);
	assert!(rows(&conn, "PRAGMA foreign_key_check").is_empty());
	conn.execute("DELETE FROM registered_repos WHERE id = 1", []).unwrap();
	assert!(
		rows(&conn, "SELECT * FROM finding_verification_intents WHERE finding_id = 11").is_empty()
	);
}

#[test]
fn v4_job_deletion_never_refunds_spending_or_reopens_intents() {
	let conn = prepared();
	conn.execute("UPDATE generation_manifests SET owner_job_id = 21 WHERE generation_id = 11", [])
		.unwrap();
	let before = rows(&conn, "SELECT * FROM campaign_admission_spending ORDER BY campaign_id");
	conn.execute("DELETE FROM jobs WHERE id = 21", []).unwrap();
	assert_eq!(
		rows(&conn, "SELECT * FROM campaign_admission_spending ORDER BY campaign_id"),
		before
	);
	assert!(rows(&conn, "SELECT * FROM job_admission_charges WHERE job_id = 21").is_empty());
	assert_eq!(
		rows(&conn, "SELECT owner_job_id FROM generation_manifests WHERE generation_id = 11"),
		vec![vec![rusqlite::types::Value::Null]]
	);
	for table in
		["lead_drilldown_intents", "finding_verification_intents", "survey_continuation_batches"]
	{
		assert_eq!(
			rows(
				&conn,
				&format!("SELECT repo_id, state, admitted_job_id FROM {table} WHERE repo_id = 1")
			),
			vec![vec![1.into(), "admitted".to_owned().into(), rusqlite::types::Value::Null]]
		);
	}
	for counter in ["general_spent", "urgent_spent", "verification_spent"] {
		rejects(&conn, &format!("UPDATE campaign_admission_spending SET {counter} = {counter} - 1 WHERE campaign_id = 11"), rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER);
	}
	conn.execute("UPDATE campaign_admission_spending SET general_spent = general_spent + 1 WHERE campaign_id = 11", []).unwrap();
	assert!(rows(&conn, "PRAGMA foreign_key_check").is_empty());
}

#[test]
fn v4_schema_enforces_exclusive_evidence_and_preparation_and_closed_states() {
	let conn = prepared();
	for sql in [
		"UPDATE finding_review_details SET evidence_payload = '{}' WHERE finding_id = 11",
		"UPDATE finding_review_details SET l2_argument = NULL WHERE finding_id = 11",
		"UPDATE verification_attempt_details SET evidence_payload = '{}' WHERE verification_id = 11",
		"UPDATE verification_attempt_details SET e2e_applicability = NULL WHERE verification_id = 11",
		"UPDATE jobs SET prepared_attempt = 1 WHERE id = 11",
		"UPDATE jobs SET prepared_at = 100 WHERE id = 11",
		"UPDATE jobs SET prepared_attempt = 1, prepared_at = 100, prepared_capability_hash = x'01' WHERE id = 11",
		"UPDATE job_assigned_review_units SET assignment_epoch = -1 WHERE job_id = 11",
		"UPDATE generation_manifests SET received_entry_count = 2 WHERE generation_id = 11",
		"UPDATE generation_manifests SET format_version = 2 WHERE generation_id = 11",
		"UPDATE generation_manifests SET expected_digest = x'00' WHERE generation_id = 11",
		"UPDATE lead_drilldown_intents SET intent_revision = 0 WHERE lead_id = 11",
		"UPDATE finding_verification_intents SET state = 'waiting' WHERE finding_id = 11",
		"UPDATE finding_verification_intents SET continuation_class = 'invented' WHERE finding_id = 11",
		"UPDATE finding_verification_intents SET block_reason = 'no_worker' WHERE finding_id = 11",
		"UPDATE lead_drilldown_intents SET logical_sequence = 1 WHERE lead_id = 11",
		"UPDATE lead_drilldown_intents SET intent_kind = 'logical_continuation', logical_sequence = 1 WHERE lead_id = 11",
		"UPDATE survey_continuation_batches SET expected_unit_count = 0 WHERE batch_id = 11",
		"UPDATE survey_continuation_batches SET expected_unit_count = 33 WHERE batch_id = 11",
		"UPDATE review_unit_holds SET batch_position = NULL WHERE review_unit_id = 11",
		"UPDATE review_unit_holds SET source_assignment_epoch = -1 WHERE review_unit_id = 11",
		"UPDATE campaign_admission_spending SET policy_version = 1 WHERE campaign_id = 11",
		"UPDATE job_admission_charges SET pool = 'ordinary' WHERE job_id = 21",
	] { rejects(&conn, sql, rusqlite::ffi::SQLITE_CONSTRAINT_CHECK); }
	conn.execute_batch("UPDATE finding_review_details SET evidence_payload = '{}', l2_argument = NULL, counterevidence = NULL, assumptions_gaps = NULL, confidence = NULL WHERE finding_id = 11;
         UPDATE verification_attempt_details SET evidence_payload = '{}', established_rung = NULL, e2e_applicability = NULL, e2e_rationale = NULL, blocker = NULL, retry_condition = NULL, verification_proof_id = NULL WHERE verification_id = 11;
         UPDATE jobs SET prepared_attempt = 1, prepared_at = 100, prepared_capability_hash = zeroblob(32) WHERE id = 11;").unwrap();
	for sql in ["UPDATE finding_review_details SET confidence = 'high' WHERE finding_id = 11",
		"UPDATE verification_attempt_details SET established_rung = 'L4' WHERE verification_id = 11"] {
		rejects(&conn, sql, rusqlite::ffi::SQLITE_CONSTRAINT_CHECK);
	}
}

#[test]
fn v4_inventory_identity_constraints_preserve_display_aliases_and_mapping_owners() {
	let conn = prepared();
	conn.execute("INSERT INTO generation_inventory (inventory_entry_id, generation_id, path, raw_path, entry_kind, created_at) VALUES (41, 11, 'src/%FF.rs', x'7372632fff2e7273', 'tracked', 100)", []).unwrap();
	conn.execute("INSERT INTO generation_inventory (inventory_entry_id, generation_id, path, source_path, raw_path, entry_kind, created_at) VALUES (42, 11, 'src/%FF.rs', 'src/%FF.rs', CAST('src/%FF.rs' AS BLOB), 'tracked', 100)", []).unwrap();
	for sql in [
		"UPDATE generation_inventory SET raw_path = x'01' WHERE inventory_entry_id = 42",
		"UPDATE generation_inventory SET raw_path = zeroblob(65537) WHERE inventory_entry_id = 41",
		"UPDATE generation_inventory SET manifest_position = 0 WHERE inventory_entry_id = 41",
		"UPDATE generation_inventory SET manifest_position = -1 WHERE inventory_entry_id = 41",
		"UPDATE generation_inventory SET disposition_revision = -1 WHERE inventory_entry_id = 41",
		"UPDATE generation_inventory SET manifest_position = 0, git_mode = 33188, blob_sha = 'ABCDEF' WHERE inventory_entry_id = 41",
		"UPDATE generation_inventory SET git_mode = 123 WHERE inventory_entry_id = 41",
	] { rejects(&conn, sql, rusqlite::ffi::SQLITE_CONSTRAINT_CHECK); }
	conn.execute("UPDATE generation_inventory SET manifest_position = 0, git_mode = 33188, blob_sha = ?1 WHERE inventory_entry_id = 41", ["a".repeat(40)]).unwrap();
	for sql in [
		"INSERT INTO generation_inventory (generation_id, path, raw_path, entry_kind, created_at) VALUES (11, 'other', x'7372632fff2e7273', 'tracked', 100)",
		"INSERT INTO generation_inventory (generation_id, path, source_path, entry_kind, created_at) VALUES (11, 'other', 'src/%FF.rs', 'tracked', 100)",
		"UPDATE generation_inventory SET manifest_position = 0, git_mode = 33188, blob_sha = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE inventory_entry_id = 42",
	] { rejects(&conn, sql, rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE); }
	conn.execute("DELETE FROM review_units WHERE review_unit_id = 11", []).unwrap();
	assert!(rows(&conn, "SELECT * FROM generation_inventory_units WHERE inventory_entry_id = 11")
		.is_empty());
	assert!(rows(&conn, "SELECT * FROM review_unit_holds WHERE review_unit_id = 11").is_empty());
	assert_eq!(
		rows(
			&conn,
			"SELECT expected_unit_count FROM survey_continuation_batches WHERE batch_id = 11"
		),
		vec![vec![1.into()]]
	);
}
