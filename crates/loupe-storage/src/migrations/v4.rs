//! Offline, lossless inventory and retained evidence upgrade.

use loupe_core::text::RepoPath;
use rusqlite::{Connection, TransactionBehavior};

use super::{migration_error, set_version};

mod schema;

pub(super) const COPIES: &[(&str, &str)] = &[
	("generation_inventory", "inventory_entry_id, generation_id, path, blob_sha, entry_kind, disposition, disposition_reason, highlighted, created_at"),
	("finding_review_details", "finding_id, repo_id, workflow_contract_version, profile_version, profile_digest, reviewed_commit_sha, identity_family, identity_anchor, identity_instance_key, identity_fingerprint, l2_argument, counterevidence, assumptions_gaps, confidence, submitted_rung, origin_lead_id, created_at"),
	("verification_attempt_details", "verification_id, workflow_contract_version, checkout_commit_sha, established_rung, e2e_applicability, e2e_rationale, blocker, retry_condition, verification_proof_id, terminal_digest, created_at"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
	PreCheck,
	Tables,
	Copy,
	VerifyCopy,
	Replace,
	Additions,
	ForeignKeyCheck,
	IntegrityCheck,
	Commit,
	Restore,
}

pub(super) fn run(conn: &mut Connection) -> rusqlite::Result<()> {
	run_with_probe(conn, &mut |_, _| Ok(()))
}

pub(super) fn run_with_probe(
	conn: &mut Connection, probe: &mut impl FnMut(Step, &Connection) -> rusqlite::Result<()>,
) -> rusqlite::Result<()> {
	let mut guard = ForeignKeys::disable(conn)?;
	let result = (|| {
		let tx = guard.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		probe(Step::PreCheck, &tx)?;
		let leased: i64 =
			tx.query_row("SELECT COUNT(*) FROM jobs WHERE state = 'leased'", [], |r| r.get(0))?;
		if leased != 0 {
			return Err(migration_error(format!(
				"schema v4 upgrade refused: {leased} leased job(s); wait for in-flight work to finish or cancel it, then stop the old server and all workers before retrying. Database remains at schema v3"
			)));
		}
		tx.execute_batch(schema::REBUILDS)?;
		probe(Step::Tables, &tx)?;
		for (table, columns) in COPIES {
			tx.execute_batch(&format!(
				"INSERT INTO {table}_new ({columns}) SELECT {columns} FROM {table};"
			))?;
		}
		// Display text is not raw identity. Only an exact valid RepoPath can
		// be carried as the old addressable projection; never percent-decode.
		let mut entries = tx.prepare(
			"SELECT inventory_entry_id, path FROM generation_inventory
             WHERE disposition_reason IS NULL OR disposition_reason <> 'unrepresentable-path'",
		)?;
		let mut project = tx.prepare(
			"UPDATE generation_inventory_new SET source_path = ?1 WHERE inventory_entry_id = ?2",
		)?;
		for entry in entries.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))? {
			let (id, path) = entry?;
			if RepoPath::new(&path).is_ok() {
				project.execute(rusqlite::params![path, id])?;
			}
		}
		drop(project);
		drop(entries);
		probe(Step::Copy, &tx)?;
		probe(Step::VerifyCopy, &tx)?;
		for (table, columns) in COPIES {
			let equal: bool = tx.query_row(
				&format!(
					"SELECT (SELECT COUNT(*) FROM {table}) = (SELECT COUNT(*) FROM {table}_new)
                     AND NOT EXISTS (SELECT {columns} FROM {table} EXCEPT SELECT {columns} FROM {table}_new)
                     AND NOT EXISTS (SELECT {columns} FROM {table}_new EXCEPT SELECT {columns} FROM {table})"
				),
				[],
				|r| r.get(0),
			)?;
			if !equal {
				return Err(migration_error(format!(
					"schema v4: historical {table} copy differs; upgrade rolled back to v3"
				)));
			}
		}
		for (table, _) in COPIES {
			tx.execute_batch(&format!(
				"DROP TABLE {table}; ALTER TABLE {table}_new RENAME TO {table};"
			))?;
		}
		probe(Step::Replace, &tx)?;
		tx.execute_batch(schema::ADDITIONS)?;
		probe(Step::Additions, &tx)?;
		probe(Step::ForeignKeyCheck, &tx)?;
		let mut statement = tx.prepare("PRAGMA foreign_key_check")?;
		let mut violations = statement.query([])?;
		if let Some(row) = violations.next()? {
			let table: String = row.get(0)?;
			let rowid: Option<i64> = row.get(1)?;
			let parent: String = row.get(2)?;
			return Err(migration_error(format!(
				"schema v4 foreign_key_check failed: {table} row {rowid:?} references {parent}; upgrade rolled back to v3"
			)));
		}
		drop(violations);
		drop(statement);
		probe(Step::IntegrityCheck, &tx)?;
		let integrity = tx
			.prepare("PRAGMA integrity_check")?
			.query_map([], |r| r.get::<_, String>(0))?
			.collect::<rusqlite::Result<Vec<_>>>()?;
		if integrity != ["ok"] {
			return Err(migration_error(format!(
				"schema v4 integrity_check failed: {integrity:?}; upgrade rolled back to v3"
			)));
		}
		set_version(&tx, 4)?;
		tx.pragma_update(None, "user_version", 4)?;
		probe(Step::Commit, &tx)?;
		tx.commit()
	})();
	probe(Step::Restore, guard.conn).and_then(|()| guard.finish())?;
	result
}

struct ForeignKeys<'a> {
	conn: &'a mut Connection,
	prior: bool,
	restored: bool,
}

impl<'a> ForeignKeys<'a> {
	fn disable(conn: &'a mut Connection) -> rusqlite::Result<Self> {
		if !conn.is_autocommit() {
			return Err(migration_error("schema v4 must run outside a transaction"));
		}
		let prior = conn.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
		let guard = Self { conn, prior, restored: false };
		guard.conn.pragma_update(None, "foreign_keys", false)?;
		let enabled: bool = guard.conn.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
		if enabled {
			return Err(migration_error("schema v4 could not disable foreign keys"));
		}
		Ok(guard)
	}

	fn finish(&mut self) -> rusqlite::Result<()> {
		self.conn.pragma_update(None, "foreign_keys", self.prior)?;
		let enabled: bool = self.conn.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
		if enabled != self.prior {
			return Err(migration_error(
				"schema v4 could not restore foreign keys; discard this connection",
			));
		}
		self.restored = true;
		Ok(())
	}
}

impl Drop for ForeignKeys<'_> {
	fn drop(&mut self) {
		if !self.restored {
			let _ = self.conn.pragma_update(None, "foreign_keys", self.prior);
		}
	}
}
