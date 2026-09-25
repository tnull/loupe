//! Raw inventory identity and the managed-generation compatibility boundary.
use loupe_core::text::{RepoPath, SourceRef};
use rusqlite::{params, Connection};

use super::{fixture, payload, seed};
use crate::{generations as g, inventory as i, transaction, Conflict, Db, Error, Result};

fn entry(path: &i::InventoryPath) -> i::NewEntry<'_> {
	i::NewEntry {
		path,
		blob_sha: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		kind: i::EntryKind::Tracked,
		disposition: i::Disposition::Unresolved,
		reason: None,
		highlighted: false,
	}
}

fn source(path: &str) -> SourceRef {
	SourceRef { path: RepoPath::new(path).unwrap(), symbol: None }
}

fn manage(conn: &Connection, generation: i64, sealed: bool) -> Result<()> {
	conn.execute(
		"INSERT INTO generation_manifests
		(generation_id,format_version,expected_entry_count,expected_digest,
		 received_entry_count,received_canonical_bytes,created_at,sealed_at)
		SELECT ?1,1,COUNT(*),zeroblob(32),COUNT(*),0,0,?2
		FROM generation_inventory WHERE generation_id=?1 AND manifest_position IS NOT NULL",
		params![generation, sealed.then_some(1)],
	)?;
	Ok(())
}

fn positioned(conn: &Connection, generation: i64, path: &str, position: i64) -> Result<i64> {
	conn.execute(
		"INSERT INTO generation_inventory
		(generation_id,path,raw_path,source_path,manifest_position,git_mode,
		 blob_sha,entry_kind,created_at)
		VALUES (?1,?2,?3,?2,?4,33188,
		 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','tracked',0)",
		params![generation, path, path.as_bytes(), position],
	)?;
	Ok(conn.last_insert_rowid())
}

#[test]
fn aliases_round_trip_in_both_orders_chunks_and_retries() {
	for reverse in [false, true] {
		for separate_chunks in [false, true] {
			let directory = tempfile::tempdir().unwrap();
			let path = directory.path().join("inventory.db");
			let key = crate::secrets::MasterKey::for_tests();
			let db = Db::open(&path, &key).unwrap();
			seed(&db);
			let mut paths = [
				i::InventoryPath::from_git_bytes(b"bad\xff.rs"),
				i::InventoryPath::from_git_bytes(b"bad%FF.rs"),
			];
			if reverse {
				paths.reverse();
			}
			let ids = db.with_conn(|conn| {
				if separate_chunks {
					for path in &paths { i::standalone::insert(conn, 1, 11, &[entry(path)], 0)?; }
				} else {
					i::standalone::insert(conn, 1, 11, &[entry(&paths[0]), entry(&paths[1])], 0)?;
				}
				assert_eq!(i::list(conn, 11)?.len(), 2, "each raw Git identity owns a row");
				let retry = i::standalone::insert(conn, 1, 11, &[entry(&paths[1]), entry(&paths[0])], 1)?;
				assert_eq!(retry, i::Inserted { inserted: 0, excluded: 0, skipped: 2 });
				let ids = conn.prepare("SELECT inventory_entry_id,raw_path FROM generation_inventory WHERE generation_id=11 ORDER BY raw_path")?
					.query_map([], |row| Ok((row.get::<_,i64>(0)?, row.get::<_,Vec<u8>>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
				Ok(ids)
			}).unwrap();
			drop(db);
			let db = Db::open(&path, &key).unwrap();
			db.with_conn(|conn| {
				let stored = conn.prepare("SELECT inventory_entry_id,raw_path FROM generation_inventory WHERE generation_id=11 ORDER BY raw_path")?
					.query_map([], |row| Ok((row.get::<_,i64>(0)?, row.get::<_,Vec<u8>>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
				assert_eq!(stored, ids);
				let entries = i::list(conn, 11)?;
				assert_eq!(entries.iter().filter(|row| row.disposition == i::Disposition::Excluded).count(), 1);
				transaction::immediate(conn, |tx| {
					i::verify_refs(tx, 11, &[source("bad%FF.rs")])?;
					assert!(matches!(i::verify_refs(tx, 11, &[source("missing.rs")]), Err(Error::UnknownPaths(_))));
					Ok(())
				})
			}).unwrap();
		}
	}
}

#[test]
fn managed_inventory_rejects_old_insert_including_identical_retries() {
	for sealed in [false, true] {
		let db = fixture();
		db.with_conn(|conn| {
			let path = i::InventoryPath::from_git_bytes(b"source.rs");
			i::standalone::insert(conn, 1, 11, &[entry(&path)], 0)?;
			manage(conn, 11, sealed)?;
			assert!(
				matches!(
					i::standalone::insert(conn, 1, 11, &[entry(&path)], 1),
					Err(Error::Conflict(Conflict::GenerationState))
				),
				"managed inventory cannot accept even replay-looking legacy insertion"
			);
			assert!(i::standalone::insert(conn, 1, 11, &[], 1).is_err());
			assert_eq!(i::list(conn, 11)?.len(), 1);
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn managed_profile_rejects_initial_and_versioned_legacy_writes() {
	for sealed in [false, true] {
		let db = fixture();
		db.with_conn(|conn| {
			g::standalone::set_profile(conn, 11, 1, &payload())?;
			manage(conn, 11, sealed)?;
			manage(conn, 12, sealed)?;
			assert!(
				g::standalone::set_profile(conn, 11, 2, &payload()).is_err(),
				"management must freeze legacy profile replacement"
			);
			assert!(
				g::standalone::set_profile(conn, 12, 1, &payload()).is_err(),
				"initial managed publication cannot bypass its owner"
			);
			assert_eq!(g::get(conn, 11)?.unwrap().profile_version, 1);
			assert!(g::get(conn, 12)?.unwrap().generated_profile.is_none());
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn receiving_manifest_rejects_refs_despite_a_historical_digest() {
	let db = fixture();
	db.with_conn(|conn| {
		positioned(conn, 11, "source.rs", 0)?;
		conn.execute(
			"UPDATE review_generations SET inventory_digest=zeroblob(32) WHERE generation_id=11",
			[],
		)?;
		manage(conn, 11, false)?;
		transaction::immediate(conn, |tx| {
			assert!(
				i::verify_refs(tx, 11, &[source("source.rs")]).is_err(),
				"historical digest cannot authorize an unsealed manifest"
			);
			assert!(i::verify_refs(tx, 11, &[]).is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn sealed_manifest_refs_require_positioned_source_membership() {
	let db = fixture();
	db.with_conn(|conn| {
		positioned(conn, 11, "source.rs", 0)?;
		conn.execute("INSERT INTO generation_inventory (generation_id,path,source_path,entry_kind,created_at) VALUES (11,'historical.rs','historical.rs','tracked',0)", [])?;
		conn.execute("INSERT INTO generation_inventory (generation_id,path,raw_path,manifest_position,git_mode,blob_sha,entry_kind,disposition,disposition_reason,created_at) VALUES (11,'bad%FF.rs',?1,1,33188,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','tracked','excluded','unrepresentable-path',0)", [b"bad\xff.rs".as_slice()])?;
		manage(conn, 11, true)?;
		transaction::immediate(conn, |tx| {
			i::verify_refs(tx, 11, &[source("source.rs")])?;
			for path in ["historical.rs", "bad%FF.rs", "missing.rs"] {
				assert!(matches!(i::verify_refs(tx, 11, &[source(path)]), Err(Error::UnknownPaths(_))), "only positioned source identity is referenceable: {path}");
			}
			Ok(())
		})
	}).unwrap();
}

#[test]
fn receiving_generation_cannot_activate_with_old_profile_and_digest() {
	let db = fixture();
	db.with_conn(|conn| {
		g::standalone::set_profile(conn, 12, 1, &payload())?;
		conn.execute(
			"UPDATE review_generations SET inventory_digest=zeroblob(32) WHERE generation_id=12",
			[],
		)?;
		manage(conn, 12, false)?;
		assert!(
			g::standalone::activate(conn, 12, 1).is_err(),
			"historical profile/digest must not bypass the managed seal"
		);
		assert_eq!(g::get(conn, 11)?.unwrap().state, g::State::Active);
		assert_eq!(g::get(conn, 12)?.unwrap().state, g::State::Building);
		conn.execute("UPDATE generation_manifests SET sealed_at=2 WHERE generation_id=12", [])?;
		g::standalone::activate(conn, 12, 2)?;
		assert_eq!(g::get(conn, 12)?.unwrap().state, g::State::Active);
		Ok(())
	})
	.unwrap();
}

#[test]
fn receiving_generation_cannot_claim_complete_coverage() {
	let db = fixture();
	db.with_conn(|conn| {
		g::standalone::set_corroboration(conn, 11, g::Corroboration::Satisfied)?;
		conn.execute(
			"UPDATE review_generations SET inventory_digest=zeroblob(32) WHERE generation_id=11",
			[],
		)?;
		manage(conn, 11, false)?;
		assert!(
			g::standalone::set_coverage(conn, 11, g::Coverage::Complete).is_err(),
			"a receiving manifest cannot certify complete coverage"
		);
		g::standalone::set_coverage(conn, 11, g::Coverage::Partial)?;
		conn.execute("UPDATE generation_manifests SET sealed_at=2 WHERE generation_id=11", [])?;
		g::standalone::set_coverage(conn, 11, g::Coverage::Complete)?;
		Ok(())
	})
	.unwrap();
}

#[test]
fn managed_mapped_coverage_requires_surviving_source_mappings() {
	let db = fixture();
	db.with_conn(|conn| {
		let member = positioned(conn, 11, "source.rs", 0)?;
		conn.execute("UPDATE generation_inventory SET disposition='mapped' WHERE inventory_entry_id=?1", [member])?;
		conn.execute("INSERT INTO generation_inventory (generation_id,path,entry_kind,disposition,created_at) VALUES (11,'historical.rs','tracked','context',0)", [])?;
		conn.execute("INSERT INTO review_units (review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES (301,11,'mapped','title','objective','[{\"path\":\"source.rs\"}]',0),(302,11,'wrong','title','objective','[{\"path\":\"other.rs\"}]',0)", [])?;
		manage(conn, 11, true)?;
		transaction::immediate(conn, |tx| {
			assert_eq!(g::coverage_rollup(tx, 11)?.unresolved_inventory, 1, "a positioned mapped entry without mappings remains unresolved");
			tx.execute("INSERT INTO generation_inventory_units (generation_id,inventory_entry_id,review_unit_id) VALUES (11,?1,302)", [member])?;
			assert_eq!(g::coverage_rollup(tx, 11)?.unresolved_inventory, 1, "mapping a unit that omits the source cannot establish coverage");
			tx.execute("DELETE FROM generation_inventory_units WHERE inventory_entry_id=?1", [member])?;
			tx.execute("INSERT INTO generation_inventory_units (generation_id,inventory_entry_id,review_unit_id) VALUES (11,?1,301)", [member])?;
			tx.execute("UPDATE generation_inventory SET disposition='unresolved' WHERE generation_id=11 AND path='historical.rs'", [])?;
			assert_eq!(g::coverage_rollup(tx, 11)?.unresolved_inventory, 0, "valid mapping resolves the member; historical nonmembers are excluded from this manifest");
			tx.execute("DELETE FROM review_units WHERE review_unit_id=301", [])?;
			assert_eq!(g::coverage_rollup(tx, 11)?.unresolved_inventory, 1, "deleting the mapped unit removes its coverage");
			Ok(())
		})
	}).unwrap();
}

#[test]
fn inventory_preserves_nfc_distinct_source_paths() {
	let db = fixture();
	db.with_conn(|conn| {
		let decomposed = "cafe\u{301}.rs";
		let composed = "caf\u{e9}.rs";
		let path = i::InventoryPath::from_git_bytes(decomposed.as_bytes());
		i::standalone::insert(conn, 1, 11, &[entry(&path)], 0)?;
		transaction::immediate(conn, |tx| {
			i::verify_refs(tx, 11, &[source(decomposed)])?;
			assert!(i::verify_refs(tx, 11, &[source(composed)]).is_err());
			Ok(())
		})?;
		let path = i::InventoryPath::from_git_bytes(composed.as_bytes());
		i::standalone::insert(conn, 1, 11, &[entry(&path)], 0)?;
		let rows = i::list(conn, 11)?;
		assert_eq!(rows.len(), 2);
		assert!(rows.iter().any(|row| row.path.expose() == decomposed));
		assert!(rows.iter().any(|row| row.path.expose() == composed));
		Ok(())
	})
	.unwrap();
}

#[test]
fn historical_exclusion_identity_and_evidence_are_never_reconstructed_by_display() {
	let db = fixture();
	db.with_conn(|conn| {
		conn.execute_batch("INSERT INTO generation_inventory
			(inventory_entry_id,generation_id,path,blob_sha,entry_kind,disposition,disposition_reason,created_at)
			VALUES (501,11,'bad%FF.rs','old-object','tracked','excluded','unrepresentable-path',0);
			INSERT INTO review_units (review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at)
			VALUES (303,11,'historical','title','objective','[]',0);
			INSERT INTO review_unit_results
			(review_unit_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,corroborates_inventory_exclusion_id,created_at)
			VALUES (303,'base',1,'not_applicable','[]','{}',zeroblob(32),501,0);")?;
		let invalid = i::InventoryPath::from_git_bytes(b"bad\xff.rs");
		let literal = i::InventoryPath::from_git_bytes(b"bad%FF.rs");
		i::standalone::insert(conn, 1, 11, &[entry(&invalid), entry(&literal)], 1)?;
		let rows = i::list(conn, 11)?;
		assert_eq!(rows.len(), 3);
		let historical = rows.iter().find(|row| row.inventory_entry_id == 501).unwrap();
		assert_eq!(historical.path.raw_bytes(), None, "never decode guessed bytes from a historical display");
		assert!(!historical.path.representable());
		assert_eq!(historical.blob_sha.as_deref(), Some("old-object"));
		assert_eq!(conn.query_row("SELECT corroborates_inventory_exclusion_id FROM review_unit_results WHERE review_unit_id=303", [], |row| row.get::<_, i64>(0))?, 501);
		assert_eq!(rows.iter().filter(|row| row.path.raw_bytes() == Some(b"bad\xff.rs")).count(), 1);
		transaction::immediate(conn, |tx| i::verify_refs(tx, 11, &[source("bad%FF.rs")]))?;
		Ok(())
	}).unwrap();
}
