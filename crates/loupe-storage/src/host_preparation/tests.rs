use super::*;
use crate::secrets::MasterKey;
use crate::{review_tests, transaction, Db};

const SHA: &str = "1111111111111111111111111111111111111111";
const CAP: [u8; 32] = [7; 32];

fn lease() -> jobs::ActiveLease<'static> {
	jobs::ActiveLease {
		identity: jobs::LeaseIdentity { job_id: 101, worker_id: 1, capability_hash: &CAP },
		now: 10,
	}
}

fn seed(db: &Db) {
	review_tests::seed(db);
	db.with_conn(|conn| {
		conn.execute_batch("INSERT INTO workers(id,name,kind,cert_fingerprint,created_at) VALUES(1,'host','worker',zeroblob(32),0);
		 UPDATE review_generations SET state='building' WHERE generation_id=11;
		 UPDATE review_campaigns SET deadline_at=1000 WHERE campaign_id=1;
		 UPDATE jobs SET state='leased',worker_id=1,attempts=1,lease_expires_at=100,
		 hard_deadline_at=90,workflow_contract_version=1,
		 recipe='{\"version\":1,\"phase\":\"survey\",\"recipe\":\"bootstrap\",\"assignment_key\":\"ordinary\"}' WHERE id=101;")?;
		conn.execute("UPDATE review_generations SET generation_commit_sha=?1 WHERE generation_id=11", [SHA])?;
		conn.execute("UPDATE review_campaigns SET target_commit_sha=?1 WHERE campaign_id=1", [SHA])?;
		conn.execute("UPDATE jobs SET job_capability_hash=?1 WHERE id=101", [CAP.as_slice()])?;
		Ok(())
	}).unwrap();
}

fn fixture() -> Db {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	seed(&db);
	db
}

fn prepare(db: &Db) {
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| confirm(tx, lease(), JobKind::Survey, SHA))
	})
	.unwrap();
}

fn entry(path: &[u8]) -> ManifestEntry {
	ManifestEntry { raw_path: path.to_vec(), git_mode: 0o100644, object_id: "22".repeat(20) }
}

fn descriptor(entries: &[ManifestEntry]) -> NewManifest {
	let mut hasher = ManifestHasher::new(SHA, entries.len() as u64).unwrap();
	for entry in entries {
		hasher.push(entry).unwrap();
	}
	NewManifest {
		generation_id: 11,
		expected_count: entries.len() as u64,
		digest: hasher.finish().unwrap(),
	}
}

fn ingest(db: &Db, entries: &[ManifestEntry]) {
	prepare(db);
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			declare(tx, lease(), &descriptor(entries))?;
			upload(tx, lease(), 11, 0, entries)?;
			seal(tx, lease(), 11)?;
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn confirmation_is_exact_attempt_bound_and_shared_by_all_phases() {
	for phase in [JobKind::Survey, JobKind::Drilldown, JobKind::Verify] {
		let db = fixture();
		db.with_conn(|conn| {
			conn.execute("UPDATE jobs SET kind=?1 WHERE id=101", [phase.as_str()])?;
			assert!(transaction::immediate(conn, |tx| confirm(
				tx,
				lease(),
				phase.clone(),
				&"33".repeat(20)
			))
			.is_err());
			transaction::immediate(conn, |tx| confirm(tx, lease(), phase.clone(), SHA))?;
			transaction::immediate(conn, |tx| {
				confirm(tx, jobs::ActiveLease { now: 11, ..lease() }, phase.clone(), SHA)
			})?;
			assert_eq!(
				conn.query_row(
					"SELECT prepared_attempt,prepared_at,head_sha FROM jobs WHERE id=101",
					[],
					|r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?))
				)?,
				(1, 10, SHA.to_owned())
			);
			conn.execute(
				"UPDATE jobs SET attempts=2,job_capability_hash=?1 WHERE id=101",
				[[8u8; 32].as_slice()],
			)?;
			assert!(transaction::immediate(conn, |tx| confirm(tx, lease(), phase.clone(), SHA))
				.is_err());
			transaction::immediate(conn, |tx| {
				let current = jobs::ActiveLease {
					identity: jobs::LeaseIdentity { capability_hash: &[8; 32], ..lease().identity },
					now: 12,
				};
				let auth = review_authority::authorize(tx, current, phase.clone())?.unwrap();
				assert!(!auth.prepared(&auth.context()?.unwrap())?);
				confirm(tx, current, phase.clone(), SHA)?;
				let auth = review_authority::authorize(tx, current, phase.clone())?.unwrap();
				assert!(auth.prepared(&auth.context()?.unwrap())?);
				Ok(())
			})?;
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn uploads_require_preparation_owner_and_unexpired_analysis_window() {
	let db = fixture();
	let new = descriptor(&[]);
	db.with_conn(|conn| {
		assert!(transaction::immediate(conn, |tx| declare(tx, lease(), &new)).is_err());
		transaction::immediate(conn, |tx| confirm(tx, lease(), JobKind::Survey, SHA))?;
		for sql in [
			"UPDATE workers SET revoked_at=9 WHERE id=1",
			"UPDATE review_campaigns SET state='cancelled' WHERE campaign_id=1",
			"UPDATE review_campaigns SET deadline_at=10 WHERE campaign_id=1",
			"UPDATE jobs SET hard_deadline_at=10 WHERE id=101",
			"UPDATE review_generations SET state='active' WHERE generation_id=11",
		] {
			let tx = conn.transaction()?;
			tx.execute_batch(sql)?;
			assert!(declare(&tx, lease(), &new).is_err(), "must reject {sql}");
			tx.rollback()?;
		}
		Ok(())
	})
	.unwrap();
}

#[test]
fn lossless_multichunk_manifest_replays_and_survives_restart() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("host.db");
	let key = MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	seed(&db);
	prepare(&db);
	let entries = vec![
		entry(b"bad%FF.rs"),
		entry(b"bad\xff.rs"),
		ManifestEntry { git_mode: 0o160000, ..entry(b"submodule") },
		ManifestEntry { git_mode: 0o120000, ..entry(b"symlink") },
	];
	let new = descriptor(&entries);
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			declare(tx, lease(), &new)?;
			assert_eq!(upload(tx, lease(), 11, 0, &entries[..2])?.received_count, 2);
			assert!(seal(tx, lease(), 11).is_err());
			Ok(())
		})
	})
	.unwrap();
	drop(db);
	let db = Db::open(&path, &key).unwrap();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			assert_eq!(declare(tx, lease(), &new)?.received_count, 2);
			assert_eq!(upload(tx, lease(), 11, 0, &entries[..2])?.received_count, 2);
			upload(tx, lease(), 11, 2, &entries[2..])?;
			let sealed = seal(tx, lease(), 11)?;
			assert_eq!(sealed.received_count, 4);
			assert_eq!(sealed.digest, new.digest);
			assert_eq!(seal(tx, jobs::ActiveLease { now: 11, ..lease() }, 11)?, sealed);
			assert_eq!(upload(tx, lease(), 11, 0, &entries)?, sealed);
			let rows = inventory::list(tx, 11)?;
			assert_eq!(rows.len(), 4);
			assert_eq!(rows[0].path.expose(), rows[1].path.expose());
			assert_ne!(rows[0].path.raw_bytes(), rows[1].path.raw_bytes());
			assert_eq!(
				rows.iter()
					.filter(|row| row.disposition == inventory::Disposition::Excluded)
					.count(),
				1
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn descriptor_prefix_and_sealed_membership_are_immutable() {
	let db = fixture();
	prepare(&db);
	let entries = [entry(b"a"), entry(b"b")];
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			declare(tx, lease(), &descriptor(&entries))?;
			upload(tx, lease(), 11, 0, &entries[..1])?;
			Ok(())
		})?;
		assert!(transaction::immediate(conn, |tx| declare(tx, lease(), &descriptor(&[]))).is_err());
		assert!(
			transaction::immediate(conn, |tx| upload(tx, lease(), 11, 0, &entries)).is_err(),
			"partial overlap is not an append"
		);
		assert!(
			transaction::immediate(conn, |tx| upload(tx, lease(), 11, 2, &[])).is_err(),
			"no prefix holes"
		);
		assert!(
			transaction::immediate(conn, |tx| upload(tx, lease(), 11, 1, &[entry(b"a")])).is_err(),
			"cross-chunk strict ordering"
		);
		transaction::immediate(conn, |tx| {
			upload(tx, lease(), 11, 1, &entries[1..])?;
			seal(tx, lease(), 11)?;
			Ok(())
		})?;
		let changed = [ManifestEntry { object_id: "33".repeat(20), ..entries[0].clone() }];
		assert!(transaction::immediate(conn, |tx| upload(tx, lease(), 11, 0, &changed)).is_err());
		assert!(
			transaction::immediate(conn, |tx| upload(tx, lease(), 11, 2, &[entry(b"c")])).is_err()
		);
		assert_eq!(get(conn, 11)?.unwrap().received_count, 2);
		Ok(())
	})
	.unwrap();
}

#[test]
fn owner_transfer_requires_terminal_owner_and_preserves_prefix() {
	let db = fixture();
	prepare(&db);
	let entries = [entry(b"a"), entry(b"b")];
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| { declare(tx, lease(), &descriptor(&entries))?; upload(tx, lease(), 11, 0, &entries[..1])?; Ok(()) })?;
		conn.execute("UPDATE jobs SET generation_id=11,state='leased',worker_id=1,attempts=1,lease_expires_at=100,hard_deadline_at=90,workflow_contract_version=1,job_capability_hash=?1 WHERE id=102", [[8u8;32].as_slice()])?;
		let next = jobs::ActiveLease { identity: jobs::LeaseIdentity { job_id: 102, capability_hash: &[8;32], ..lease().identity }, ..lease() };
		transaction::immediate(conn, |tx| confirm(tx, next, JobKind::Survey, SHA))?;
		assert!(transaction::immediate(conn, |tx| declare(tx, next, &descriptor(&entries))).is_err());
		conn.execute("UPDATE jobs SET state='failed' WHERE id=101", [])?;
		transaction::immediate(conn, |tx| {
			let transferred = declare(tx, next, &descriptor(&entries))?;
			assert_eq!(transferred.owner_job_id, Some(102));
			assert_eq!(transferred.received_count, 1);
			upload(tx, next, 11, 1, &entries[1..])?;
			seal(tx, next, 11)?;
			Ok(())
		})?;
		assert!(transaction::immediate(conn, |tx| upload(tx, lease(), 11, 0, &entries[..1])).is_err());
		Ok(())
	}).unwrap();
}

#[test]
fn historical_enrichment_preserves_ids_and_never_decodes_display_aliases() {
	let db = fixture();
	db.with_conn(|conn| {
		conn.execute_batch("INSERT INTO generation_inventory(inventory_entry_id,generation_id,path,entry_kind,disposition,disposition_reason,source_path,created_at) VALUES
		 (1,11,'a','tracked','context',NULL,'a',0),
		 (2,11,'bad%FF.rs','tracked','excluded','unrepresentable-path',NULL,0);")?;
		Ok(())
	}).unwrap();
	let entries = [entry(b"a"), entry(b"bad%FF.rs"), entry(b"bad\xff.rs")];
	ingest(&db, &entries);
	db.with_conn(|conn| {
		let rows = inventory::list(conn, 11)?;
		assert_eq!(rows.len(), 4);
		let old = rows.iter().find(|row| row.inventory_entry_id == 1).unwrap();
		assert_eq!(old.path.raw_bytes(), Some(b"a".as_slice()));
		assert_eq!(old.disposition, inventory::Disposition::Context);
		let old_exclusion = rows.iter().find(|row| row.inventory_entry_id == 2).unwrap();
		assert!(old_exclusion.path.raw_bytes().is_none());
		assert!(old_exclusion.path.source_path().is_none());
		assert_eq!(
			conn.query_row(
				"SELECT COUNT(*) FROM generation_inventory WHERE manifest_position IS NOT NULL",
				[],
				|row| row.get::<_, i64>(0)
			)?,
			3
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn historical_conflicts_roll_back_partial_chunk_and_unaccounted_sources_block_seal() {
	let db = fixture();
	prepare(&db);
	let entries = [entry(b"a"), entry(b"b")];
	db.with_conn(|conn| {
		conn.execute("INSERT INTO generation_inventory(generation_id,path,source_path,blob_sha,entry_kind,created_at) VALUES(11,'b','b',?1,'tracked',0)", ["33".repeat(20)])?;
		transaction::immediate(conn, |tx| declare(tx, lease(), &descriptor(&entries)))?;
		assert!(transaction::immediate(conn, |tx| upload(tx, lease(), 11, 0, &entries)).is_err());
		assert_eq!(get(conn, 11)?.unwrap().received_count, 0);
		assert_eq!(inventory::list(conn, 11)?.len(), 1, "earlier chunk insertion must roll back");
		conn.execute("UPDATE generation_inventory SET blob_sha=NULL", [])?;
		transaction::immediate(conn, |tx| upload(tx, lease(), 11, 0, &entries))?;
		conn.execute("INSERT INTO generation_inventory(generation_id,path,source_path,entry_kind,created_at) VALUES(11,'missing','missing','tracked',0)", [])?;
		assert!(transaction::immediate(conn, |tx| seal(tx, lease(), 11)).is_err());
		assert!(get(conn, 11)?.unwrap().sealed_at.is_none());
		Ok(())
	}).unwrap();
}

#[test]
fn seal_checks_digest_counters_and_contiguous_positions() {
	for corruption in [
		"UPDATE generation_manifests SET expected_digest=zeroblob(32)",
		"UPDATE generation_manifests SET received_canonical_bytes=0",
		"UPDATE generation_inventory SET manifest_position=8",
	] {
		let db = fixture();
		prepare(&db);
		let entries = [entry(b"a")];
		db.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				declare(tx, lease(), &descriptor(&entries))?;
				upload(tx, lease(), 11, 0, &entries)?;
				Ok(())
			})?;
			conn.execute_batch(corruption)?;
			assert!(
				transaction::immediate(conn, |tx| seal(tx, lease(), 11)).is_err(),
				"must detect {corruption}"
			);
			assert!(get(conn, 11)?.unwrap().sealed_at.is_none());
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn exact_limits_refuse_without_truncating_or_partially_accepting() {
	let db = fixture();
	prepare(&db);
	db.with_conn(|conn| {
		assert!(transaction::immediate(conn, |tx| declare(
			tx,
			lease(),
			&NewManifest {
				generation_id: 11,
				expected_count: inventory_manifest::MAX_ENTRIES + 1,
				digest: [0; 32]
			}
		))
		.is_err());
		transaction::immediate(conn, |tx| {
			declare(
				tx,
				lease(),
				&NewManifest { generation_id: 11, expected_count: 5000, digest: [0; 32] },
			)
		})?;
		let many: Vec<_> = (0..4097).map(|index| entry(format!("{index:05}").as_bytes())).collect();
		assert!(transaction::immediate(conn, |tx| upload(tx, lease(), 11, 0, &many)).is_err());
		let huge: Vec<_> = (0..17)
			.map(|index| {
				let mut raw = vec![b'a'; 65536];
				raw[0] += index;
				entry(&raw)
			})
			.collect();
		assert!(transaction::immediate(conn, |tx| upload(tx, lease(), 11, 0, &huge)).is_err());
		assert!(transaction::immediate(conn, |tx| upload(
			tx,
			lease(),
			11,
			u64::MAX,
			&[entry(b"a")]
		))
		.is_err());
		assert_eq!(get(conn, 11)?.unwrap().received_count, 0);
		assert!(inventory::list(conn, 11)?.is_empty());
		conn.execute(
			"UPDATE generation_manifests SET received_canonical_bytes=?1",
			[inventory_manifest::MAX_BYTES],
		)?;
		assert!(
			transaction::immediate(conn, |tx| upload(tx, lease(), 11, 0, &[entry(b"a")])).is_err()
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn exact_chunk_count_and_byte_boundaries_are_accepted() {
	let count_entries: Vec<_> =
		(0..4096).map(|index| entry(format!("{index:05}").as_bytes())).collect();
	let byte_entries: Vec<_> = (0..16)
		.map(|index| {
			let mut raw = vec![b'a'; 65536 - 29];
			raw[0] += index;
			entry(&raw)
		})
		.collect();
	assert_eq!(
		byte_entries.iter().map(|entry| entry.canonical_len().unwrap()).sum::<u64>(),
		inventory_manifest::MAX_CHUNK_BYTES
	);
	for entries in [count_entries, byte_entries] {
		let db = fixture();
		ingest(&db, &entries);
		db.with_conn(|conn| {
			let manifest = get(conn, 11)?.unwrap();
			assert_eq!(manifest.received_count, entries.len() as u64);
			assert!(manifest.sealed_at.is_some());
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn empty_manifest_and_immutable_profile_replay_across_execution_attempts() {
	let db = fixture();
	prepare(&db);
	let profile = GeneratedProfile::new("{\"languages\":[\"rust\"]}").unwrap();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| declare(tx, lease(), &descriptor(&[])))?;
		assert!(
			transaction::immediate(conn, |tx| publish_profile(tx, lease(), 11, &profile)).is_err()
		);
		transaction::immediate(conn, |tx| seal(tx, lease(), 11))?;
		let published =
			transaction::immediate(conn, |tx| publish_profile(tx, lease(), 11, &profile))?;
		assert_eq!(
			transaction::immediate(conn, |tx| publish_profile(tx, lease(), 11, &profile))?,
			published
		);
		assert!(transaction::immediate(conn, |tx| publish_profile(
			tx,
			lease(),
			11,
			&GeneratedProfile::new("{}").unwrap()
		))
		.is_err());
		conn.execute(
			"UPDATE jobs SET attempts=2,job_capability_hash=?1 WHERE id=101",
			[[8u8; 32].as_slice()],
		)?;
		let next = jobs::ActiveLease {
			identity: jobs::LeaseIdentity { capability_hash: &[8; 32], ..lease().identity },
			..lease()
		};
		assert!(
			transaction::immediate(conn, |tx| publish_profile(tx, next, 11, &profile)).is_err(),
			"retry must reconfirm checkout"
		);
		transaction::immediate(conn, |tx| confirm(tx, next, JobKind::Survey, SHA))?;
		assert_eq!(
			transaction::immediate(conn, |tx| publish_profile(tx, next, 11, &profile))?,
			published
		);
		assert_eq!(
			conn.query_row("SELECT COUNT(*) FROM job_checkpoints", [], |row| row.get::<_, i64>(0))?,
			1
		);
		assert_eq!(
			conn.query_row(
				"SELECT generated_profile FROM review_generations WHERE generation_id=11",
				[],
				|row| row.get::<_, String>(0)
			)?,
			profile.expose()
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn seal_and_competing_changed_upload_serialize_without_mutating_membership() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("race.db");
	let key = MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	seed(&db);
	prepare(&db);
	let entries = [entry(b"a")];
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			declare(tx, lease(), &descriptor(&entries))?;
			upload(tx, lease(), 11, 0, &entries)?;
			Ok(())
		})
	})
	.unwrap();
	let second = Db::open(&path, &key).unwrap();
	let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
	let other_barrier = barrier.clone();
	let worker = std::thread::spawn(move || {
		other_barrier.wait();
		second
			.with_conn(|conn| {
				transaction::immediate(conn, |tx| upload(tx, lease(), 11, 0, &[entry(b"b")]))
			})
			.is_err()
	});
	barrier.wait();
	db.with_conn(|conn| transaction::immediate(conn, |tx| seal(tx, lease(), 11))).unwrap();
	assert!(worker.join().unwrap());
	db.with_conn(|conn| {
		assert_eq!(inventory::list(conn, 11)?[0].path.raw_bytes(), Some(b"a".as_slice()));
		Ok(())
	})
	.unwrap();
}
