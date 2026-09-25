use rusqlite::params;
use rusqlite::types::Value;

use super::fixtures::*;
use super::*;

pub(super) fn populated_v3(conn: &mut Connection) {
	settled(conn);
	apply_v3(conn).unwrap();
	super::ownership_tests::populate_projects(conn);
	conn.execute_batch(
		"UPDATE review_generations SET generated_profile = '{ \"old\": \"unchanged\" }',
             profile_version = 7, generated_profile_digest = x'123456', inventory_digest = x'abcdef'
         WHERE generation_id = 11;
         UPDATE finding_review_details SET profile_digest = x'001122',
             l2_argument = '{ \"verbatim\": true }', counterevidence = 'same', assumptions_gaps = 'size'
         WHERE finding_id = 11;
         UPDATE verification_attempt_details SET terminal_digest = x'0022ff' WHERE verification_id = 11;
         UPDATE review_unit_results SET produced_by_job_id = review_unit_id,
             corroborates_inventory_exclusion_id = review_unit_id;
         UPDATE review_units SET assignment_epoch = 9;
         UPDATE generation_inventory SET disposition = 'excluded', disposition_reason = 'old exclusion'
         WHERE inventory_entry_id = 11;",
	).unwrap();
	for (id, path, reason) in [
		(31, "src/%FF.rs".to_owned(), Some("unrepresentable-path")),
		(32, "src/%FE.rs".to_owned(), None),
		(33, "../outside".to_owned(), None),
		(34, "a".repeat(513), None),
		(35, "src/e\u{301}.rs".to_owned(), None),
		(36, "src/é.rs".to_owned(), None),
		(37, "src/control\0.rs".to_owned(), None),
		(38, "src/\u{202e}name.rs".to_owned(), None),
	] {
		conn.execute(
			"INSERT INTO generation_inventory (inventory_entry_id, generation_id, path,
                 entry_kind, disposition, disposition_reason, created_at)
             VALUES (?1, 11, ?2, 'tracked', 'excluded', ?3, 101)",
			params![id, path, reason],
		)
		.unwrap();
	}
}

pub(super) struct Snapshot(Vec<(String, Vec<Vec<Value>>)>);

impl Snapshot {
	pub(super) fn take(conn: &Connection) -> Self {
		let tables: Vec<String> = conn.prepare(
			"SELECT name FROM sqlite_master WHERE type = 'table' AND name <> 'schema_meta' ORDER BY name",
		).unwrap().query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
		Self(
			tables
				.into_iter()
				.map(|table| {
					let columns: Vec<String> = conn
						.prepare(&format!("PRAGMA table_info('{table}')"))
						.unwrap()
						.query_map([], |r| r.get(1))
						.unwrap()
						.collect::<rusqlite::Result<_>>()
						.unwrap();
					let columns = columns.join(", ");
					let query = format!("SELECT {columns} FROM {table} ORDER BY {columns}");
					let values = rows(conn, &query);
					(query, values)
				})
				.collect(),
		)
	}

	pub(super) fn assert_unchanged(&self, conn: &Connection) {
		for (query, expected) in &self.0 {
			assert_eq!(&rows(conn, query), expected, "historical bytes changed: {query}");
		}
	}
}

#[test]
fn v4_preserves_all_populated_v3_bytes_and_unknown_raw_identity() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("v3.sqlite");
	let mut conn = open(&path);
	populated_v3(&mut conn);
	let before = Snapshot::take(&conn);
	drop(conn);
	let db = crate::Db::open(&path, &crate::secrets::MasterKey::for_tests()).unwrap();
	db.with_conn(|conn| {
		assert_eq!(markers(conn), (4, 4));
		before.assert_unchanged(conn);
		assert!(rows(conn, "PRAGMA foreign_key_check").is_empty());
		assert_eq!(rows(conn, "PRAGMA integrity_check"), vec![vec![Value::Text("ok".into())]]);
		assert_eq!(rows(conn, "SELECT COUNT(*) FROM generation_inventory WHERE raw_path IS NOT NULL OR git_mode IS NOT NULL OR manifest_position IS NOT NULL OR disposition_revision <> 0"), vec![vec![0.into()]]);
		assert_eq!(rows(conn, "SELECT COUNT(*) FROM jobs WHERE prepared_attempt IS NOT NULL OR prepared_capability_hash IS NOT NULL OR prepared_at IS NOT NULL"), vec![vec![0.into()]]);
		assert_eq!(rows(conn, "SELECT COUNT(*) FROM job_assigned_review_units WHERE assignment_epoch IS NOT NULL"), vec![vec![0.into()]]);
		for id in [11, 12, 32, 35, 36] {
			assert_eq!(rows(conn, &format!("SELECT source_path = path FROM generation_inventory WHERE inventory_entry_id = {id}")), vec![vec![1.into()]]);
		}
		for id in [31, 33, 34, 37, 38] {
			assert_eq!(rows(conn, &format!("SELECT source_path IS NULL FROM generation_inventory WHERE inventory_entry_id = {id}")), vec![vec![1.into()]]);
		}
		for table in ["generation_manifests", "generation_inventory_units", "job_terminal_payloads", "lead_drilldown_intents", "finding_verification_intents", "survey_continuation_batches", "review_unit_holds", "campaign_admission_spending", "job_admission_charges"] {
			assert!(rows(conn, &format!("SELECT * FROM {table}")).is_empty(), "migration invented {table}");
		}
		Ok(())
	}).unwrap();
	drop(db);
	let db = crate::Db::open(&path, &crate::secrets::MasterKey::for_tests()).unwrap();
	db.with_conn(|conn| {
		before.assert_unchanged(conn);
		Ok(())
	})
	.unwrap();
}

#[test]
fn v4_installs_storage_contract_on_fresh_and_older_databases() {
	for initial in 0..=3 {
		let mut conn = Connection::open_in_memory().unwrap();
		conn.pragma_update(None, "foreign_keys", true).unwrap();
		if initial != 0 {
			apply_migrations(&mut conn, &MIGRATIONS[..initial]).unwrap();
		}
		apply_pending(&mut conn).unwrap();
		assert_eq!(markers(&conn), (4, 4), "storage contract requires schema v4");
		for table in [
			"generation_manifests",
			"generation_inventory_units",
			"job_terminal_payloads",
			"lead_drilldown_intents",
			"finding_verification_intents",
			"review_unit_holds",
			"survey_continuation_batches",
			"campaign_admission_spending",
			"job_admission_charges",
		] {
			conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
		}
		assert!(fk_enabled(&conn));
		let before = schema(&conn);
		conn.pragma_update(None, "user_version", 0).unwrap();
		apply_pending(&mut conn).unwrap();
		assert_eq!(markers(&conn), (4, 4));
		assert_eq!(schema(&conn), before);
	}
}
