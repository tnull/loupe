use std::sync::{Arc, Barrier};

use loupe_core::review_payload::PromotionV1;
use loupe_core::{FindingState, Severity};
use rusqlite::{params, Connection};
use serde_json::json;

use super::*;
use crate::secrets::MasterKey;
use crate::{findings, transaction, Db, StoredEvidence};

const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PROFILE: [u8; 32] = [42; 32];

fn promotion() -> PromotionV1 {
	PromotionV1::from_json(&json!({
		"version":1,"severity":"high","title":"Untrusted allocation control",
		"description":"Attacker-controlled length reaches the allocator.",
		"identity_family":"allocation","identity_anchor":"request allocator",
		"identity_instance_key":"public endpoint","cwe":"CWE-789",
		"evidence":{"version":1,"l2_argument":{"attacker_source":"remote request",
			"control":"request length","sink":"allocator","reachable_path":"handler to allocator",
			"trust_boundary":"network to process memory"},
			"material_locations":[
				{"role":"entry_point","file":"src/cafe\u{301}.rs","symbol":"entry","line_start":3,"line_end":8},
				{"role":"sink","file":"src/café.rs","symbol":"allocate","line_start":12},
				{"role":"wrapper","file":"src/wrapper.rs"}],
			"counterevidence":"request authentication precedes the allocation",
			"assumptions_gaps":"authenticated remote attacker","confidence":"medium"}
	}).to_string()).unwrap()
}
fn seed(db: &Db) {
	crate::review_tests::seed(db);
	db.with_conn(|conn| {
		conn.execute("UPDATE review_generations SET generation_commit_sha=?1 WHERE generation_id=11",[COMMIT])?;
		for (id,generation,anchor) in [(501,11,"origin first"),(502,11,"origin second"),(521,21,"foreign origin")] {
			let identity=Identity {family:"allocation".parse().unwrap(),anchor:anchor.parse().unwrap(),instance:None};
			conn.execute("INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES (?1,?2,'allocation',?3,?4,'{}',zeroblob(32),?5,0)",params![id,generation,anchor,identity.fingerprint().as_slice(),COMMIT])?;
		}
		conn.execute("INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,assigned_lead_id,head_sha,workflow_contract_version,enqueued_at) VALUES (301,1,'drilldown','succeeded',1,11,501,?1,1,0),(302,1,'drilldown','succeeded',1,11,502,?1,1,0),(401,2,'drilldown','succeeded',2,21,521,?1,1,0)",[COMMIT])?;
		Ok(())
	}).unwrap();
}
fn fixture() -> Db {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	seed(&db);
	db
}
fn new(payload: &PromotionV1) -> NewFinding<'_> {
	NewFinding {
		repo_id: 1,
		job_id: 301,
		origin_lead_id: 501,
		profile_version: 3,
		profile_digest: &PROFILE,
		reviewed_commit_sha: COMMIT,
		promotion: payload,
	}
}
fn counts(conn: &Connection) -> (i64, i64) {
	(
		conn.query_row("SELECT count(*) FROM findings", [], |r| r.get(0)).unwrap(),
		conn.query_row("SELECT count(*) FROM finding_review_details", [], |r| r.get(0)).unwrap(),
	)
}

#[test]
fn promotion_is_always_validating_without_proof_or_legacy_toggle() {
	for enabled in [false, true] {
		fixture()
			.with_conn(|conn| {
				conn.execute(
					"UPDATE registered_repos SET verification_enabled=?1 WHERE id=1",
					[enabled],
				)?;
				let payload = promotion();
				let id = standalone::insert(conn, &new(&payload), 123)?;
				let finding = findings::get(conn, id)?.unwrap();
				assert_eq!(finding.state, FindingState::Validating);
				assert!(finding.verification_required);
				assert_eq!(finding.scanner_id, "llm-code-review");
				assert_eq!(finding.severity, Severity::High);
				assert_eq!(finding.title, payload.title.expose());
				assert_eq!(finding.description, payload.description.expose());
				assert_eq!(finding.file_path.as_deref(), Some("src/cafe\u{301}.rs"));
				assert_eq!((finding.line_start, finding.line_end), (Some(3), Some(8)));
				assert_eq!(finding.cwe.as_deref(), Some("CWE-789"));
				assert_eq!(finding.created_at, 123);
				assert!(finding.patch_unified.is_none() && finding.poc_unified.is_none());
				assert!(finding.approved_at.is_none());
				let identity = identity(&payload);
				let expected = format!(
					"review:v1:{}",
					identity
						.fingerprint()
						.iter()
						.map(|byte| format!("{byte:02x}"))
						.collect::<String>()
				);
				assert_eq!(finding.fingerprint, expected);
				assert_eq!(finding.fingerprint.len(), 74);
				let StoredEvidence::Recorded(details) =
					finding_details::get_review_evidence(conn, id)?
				else {
					panic!("typed details")
				};
				assert_eq!(details.evidence, payload.evidence);
				assert_eq!(details.identity, identity);
				assert_eq!(details.profile_digest, Some(PROFILE));
				assert_eq!(details.profile_version, 3);
				assert_eq!(details.reviewed_commit_sha, COMMIT);
				assert_eq!(details.origin_lead, Some(501));
				assert_eq!(
					details.workflow_contract_version,
					loupe_core::WORKFLOW_CONTRACT_VERSION
				);
				assert_eq!(
					conn.query_row(
						"SELECT submitted_rung FROM finding_review_details WHERE finding_id=?1",
						[id],
						|r| r.get::<_, String>(0)
					)?,
					"L2"
				);
				assert_eq!(
					conn.query_row("SELECT count(*) FROM verification_proofs", [], |r| r
						.get::<_, i64>(0))?,
					0
				);
				Ok(())
			})
			.unwrap();
	}
}

#[test]
fn canonical_evidence_and_all_locations_survive_restart_and_generation_purge() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("finding.sqlite");
	let key = MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	seed(&db);
	let payload = promotion();
	let id = db.with_conn(|conn| standalone::insert(conn, &new(&payload), 123)).unwrap();
	drop(db);
	let db = Db::open(&path, &key).unwrap();
	db.with_conn(|conn| {
		conn.execute("DELETE FROM review_generations WHERE generation_id=11", [])?;
		let StoredEvidence::Recorded(details) = finding_details::get_review_evidence(conn, id)?
		else {
			panic!("retained evidence")
		};
		assert_eq!(details.evidence, payload.evidence);
		assert_eq!(details.evidence.material_locations.len(), 3);
		assert_eq!(details.evidence.material_locations[0].file.expose(), "src/cafe\u{301}.rs");
		assert_eq!(details.evidence.material_locations[1].file.expose(), "src/café.rs");
		assert_eq!(details.origin_lead, None);
		assert_eq!(details.profile_digest, Some(PROFILE));
		assert_eq!(details.reviewed_commit_sha, COMMIT);
		assert_eq!(details.profile_version, 3);
		let raw: String = conn.query_row(
			"SELECT evidence_payload FROM finding_review_details WHERE finding_id=?1",
			[id],
			|r| r.get(0),
		)?;
		assert_eq!(raw.as_bytes(), payload.evidence.canonical_bytes()?);
		assert!(findings::get(conn, id)?.is_some());
		transaction::immediate(conn, |tx| {
			assert_eq!(
				classify_compatibility_collision(tx, id, 1, &identity(&payload))?,
				Conflict::FindingIdentity(id)
			);
			Ok(())
		})?;
		Ok(())
	})
	.unwrap();
}

#[test]
fn normalized_identity_collision_is_semantic_and_distinct_instances_promote() {
	fixture()
		.with_conn(|conn| {
			let payload = promotion();
			let first = standalone::insert(conn, &new(&payload), 0)?;
			let mut same = payload.clone();
			same.identity_anchor = " REQUEST   ALLOCATOR ".parse().unwrap();
			let error = standalone::insert(conn, &new(&same), 1).unwrap_err();
			assert!(matches!(error,Error::Conflict(Conflict::FindingIdentity(id)) if id==first));
			assert_eq!(counts(conn), (1, 1));
			same.identity_instance_key = Some("administrator endpoint".parse().unwrap());
			assert_ne!(standalone::insert(conn, &new(&same), 2)?, first);
			assert_eq!(counts(conn), (2, 2));
			Ok(())
		})
		.unwrap();
}

fn legacy_finding(conn: &Connection, fingerprint: &str) -> i64 {
	conn.execute("INSERT INTO findings(repo_id,job_id,scanner_id,severity,title,description,fingerprint,created_at) VALUES (1,101,'llm-code-review','high','legacy','legacy',?1,0)",[fingerprint]).unwrap();
	conn.last_insert_rowid()
}

#[test]
fn reserved_looking_legacy_key_is_not_phase_provenance() {
	fixture().with_conn(|conn| {
		let payload=promotion();let key=compatibility_key(&identity(&payload));let id=legacy_finding(conn,&key);
		assert!(matches!(standalone::insert(conn,&new(&payload),1),Err(Error::Conflict(Conflict::CompatibilityKey(existing))) if existing==id));
		assert_eq!(counts(conn),(1,0));assert_eq!(findings::get(conn,id)?.unwrap().title,"legacy");
		Ok(())
	}).unwrap();
}

#[test]
fn historical_details_do_not_establish_modern_phase_identity() {
	fixture().with_conn(|conn| {
		let payload=promotion();let id=standalone::insert(conn,&new(&payload),0)?;
		conn.execute("UPDATE finding_review_details SET evidence_payload=NULL,l2_argument='{}',counterevidence='historical',assumptions_gaps='historical',confidence='medium' WHERE finding_id=?1",[id])?;
		assert_eq!(finding_details::get_review_evidence(conn,id)?,StoredEvidence::Historical);
		assert!(matches!(standalone::insert(conn,&new(&payload),1),Err(Error::Conflict(Conflict::CompatibilityKey(existing))) if existing==id));
		assert_eq!(counts(conn),(1,1));Ok(())
	}).unwrap();
}

#[test]
fn malformed_and_mismatched_modern_details_are_compatibility_conflicts() {
	for update in [
		"evidence_payload='{}'",
		"identity_fingerprint=zeroblob(32)",
		"profile_digest=x'00'",
		"identity_family='other-family'",
		"evidence_payload=x'00'",
	] {
		fixture().with_conn(|conn| {
			let payload=promotion();let id=standalone::insert(conn,&new(&payload),0)?;
			conn.execute(&format!("UPDATE finding_review_details SET {update} WHERE finding_id=?1"),[id])?;
			assert!(matches!(standalone::insert(conn,&new(&payload),1),Err(Error::Conflict(Conflict::CompatibilityKey(existing))) if existing==id),"{update}");
			assert_eq!(counts(conn),(1,1));
			Ok(())
		}).unwrap();
	}
}

#[test]
fn valid_different_retained_identity_does_not_match_the_compatibility_key() {
	fixture().with_conn(|conn| {
		let payload=promotion();let id=standalone::insert(conn,&new(&payload),0)?;
		let mut other=payload.clone();other.identity_anchor="another allocator".parse().unwrap();
		conn.execute("UPDATE finding_review_details SET identity_anchor=?2,identity_fingerprint=?3 WHERE finding_id=?1",params![id,other.identity_anchor.expose(),identity(&other).fingerprint().as_slice()])?;
		assert!(matches!(finding_details::get_review_evidence(conn,id)?,StoredEvidence::Recorded(_)));
		assert!(matches!(standalone::insert(conn,&new(&payload),1),Err(Error::Conflict(Conflict::CompatibilityKey(existing))) if existing==id));
		assert_eq!(counts(conn),(1,1));Ok(())
	}).unwrap();
}

#[test]
fn semantic_details_constraint_rolls_back_tentative_finding() {
	fixture()
		.with_conn(|conn| {
			let payload = promotion();
			let id = standalone::insert(conn, &new(&payload), 0)?;
			conn.execute(
				"UPDATE findings SET fingerprint='historical-projection' WHERE id=?1",
				[id],
			)?;
			let error = standalone::insert(conn, &new(&payload), 1).unwrap_err();
			assert!(
				matches!(error,Error::Conflict(Conflict::FindingIdentity(existing)) if existing==id)
			);
			assert_eq!(counts(conn), (1, 1));
			assert_eq!(findings::get(conn, id)?.unwrap().fingerprint, "historical-projection");
			assert_eq!(
				conn.query_row("SELECT status FROM leads WHERE lead_id=501", [], |r| r
					.get::<_, String>(0))?,
				"open"
			);
			Ok(())
		})
		.unwrap();
}

#[test]
fn later_failure_rolls_back_finding_and_details_together() {
	fixture()
		.with_conn(|conn| {
			let payload = promotion();
			let error = transaction::immediate(conn, |tx| {
				insert(tx, &new(&payload), 0)?;
				Err::<(), _>(Error::Conflict(Conflict::Checkpoint))
			})
			.unwrap_err();
			assert!(matches!(error, Error::Conflict(Conflict::Checkpoint)));
			assert_eq!(counts(conn), (0, 0));
			Ok(())
		})
		.unwrap();
}

#[test]
fn scope_and_source_failures_leave_no_tentative_finding() {
	use crate::inventory::{self, InventoryPath, NewEntry};
	fixture()
		.with_conn(|conn| {
			let payload = promotion();
			let mut input = new(&payload);
			input.repo_id = 2;
			assert!(standalone::insert(conn, &input, 0).is_err());
			input = new(&payload);
			input.job_id = 101;
			assert!(
				standalone::insert(conn, &input, 0).is_err(),
				"survey is not a promotion producer"
			);
			input = new(&payload);
			input.origin_lead_id = 502;
			assert!(
				standalone::insert(conn, &input, 0).is_err(),
				"same-generation unassigned lead is not producer provenance"
			);
			input = new(&payload);
			input.profile_version = 0;
			assert!(standalone::insert(conn, &input, 0).is_err());
			input = new(&payload);
			input.origin_lead_id = 521;
			assert!(standalone::insert(conn, &input, 0).is_err());
			input = new(&payload);
			input.reviewed_commit_sha = "different";
			assert!(standalone::insert(conn, &input, 0).is_err());
			let path = InventoryPath::from_git_bytes("src/café.rs".as_bytes());
			inventory::standalone::insert(
				conn,
				1,
				11,
				&[NewEntry {
					path: &path,
					blob_sha: None,
					kind: inventory::EntryKind::Tracked,
					disposition: inventory::Disposition::Unresolved,
					reason: None,
					highlighted: false,
				}],
				0,
			)?;
			assert!(
				matches!(standalone::insert(conn, &new(&payload), 0), Err(Error::UnknownPaths(_))),
				"NFC-equivalent membership must not match a distinct Git path"
			);
			assert_eq!(counts(conn), (0, 0));
			for raw in ["src/cafe\u{301}.rs", "src/wrapper.rs"] {
				let path = InventoryPath::from_git_bytes(raw.as_bytes());
				inventory::standalone::insert(
					conn,
					1,
					11,
					&[NewEntry {
						path: &path,
						blob_sha: None,
						kind: inventory::EntryKind::Tracked,
						disposition: inventory::Disposition::Unresolved,
						reason: None,
						highlighted: false,
					}],
					0,
				)?;
			}
			standalone::insert(conn, &new(&payload), 1)?;
			assert_eq!(counts(conn), (1, 1));
			Ok(())
		})
		.unwrap();
}

#[test]
fn first_display_location_is_optional_but_full_location_list_is_required() {
	fixture()
		.with_conn(|conn| {
			let mut payload = promotion();
			payload.evidence.material_locations.swap(0, 2);
			let id = standalone::insert(conn, &new(&payload), 0)?;
			let row = findings::get(conn, id)?.unwrap();
			assert_eq!(row.file_path.as_deref(), Some("src/wrapper.rs"));
			assert!(row.line_start.is_none() && row.line_end.is_none());
			payload.evidence.material_locations.clear();
			assert!(standalone::insert(conn, &new(&payload), 1).is_err());
			assert_eq!(counts(conn), (1, 1));
			Ok(())
		})
		.unwrap();
}

#[test]
fn unrelated_database_failures_are_not_identity_conflicts() {
	fixture().with_conn(|conn| {
		let payload=promotion();
		conn.execute_batch("CREATE TRIGGER reject_review_insert BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT,'injected failure'); END;")?;
		assert!(matches!(standalone::insert(conn,&new(&payload),0),Err(Error::Sqlite(_))));assert_eq!(counts(conn),(0,0));
		conn.execute_batch("DROP TRIGGER reject_review_insert;")?;
		conn.execute_batch("CREATE TRIGGER reject_review_details BEFORE INSERT ON finding_review_details BEGIN SELECT RAISE(ABORT,'injected details failure'); END;")?;
		assert!(matches!(standalone::insert(conn,&new(&payload),0),Err(Error::Sqlite(_))));assert_eq!(counts(conn),(0,0));
		conn.execute_batch("DROP TRIGGER reject_review_details;")?;
		let _=standalone::insert(conn,&new(&payload),0)?;
		conn.execute_batch("ALTER TABLE finding_review_details RENAME TO temporarily_unavailable_details;")?;
		assert!(matches!(standalone::insert(conn,&new(&payload),0),Err(Error::Sqlite(_))),"missing evidence table is an operational database error, not malformed evidence");
		Ok(())
	}).unwrap();
}

#[test]
fn same_identity_is_independent_across_repositories() {
	fixture()
		.with_conn(|conn| {
			let payload = promotion();
			let first = standalone::insert(conn, &new(&payload), 0)?;
			let mut foreign = new(&payload);
			foreign.repo_id = 2;
			foreign.job_id = 401;
			foreign.origin_lead_id = 521;
			let second = standalone::insert(conn, &foreign, 0)?;
			assert_ne!(first, second);
			assert_eq!(counts(conn), (2, 2));
			Ok(())
		})
		.unwrap();
}

#[test]
fn absent_job_generation_does_not_invent_current_source_membership() {
	fixture()
		.with_conn(|conn| {
			conn.execute("UPDATE jobs SET generation_id=NULL WHERE id=301", [])?;
			let payload = promotion();
			let id = standalone::insert(conn, &new(&payload), 0)?;
			assert!(matches!(
				finding_details::get_review_evidence(conn, id)?,
				StoredEvidence::Recorded(_)
			));
			assert!(conn
				.query_row("SELECT generation_id FROM jobs WHERE id=301", [], |r| r
					.get::<_, Option<i64>>(0))?
				.is_none());
			Ok(())
		})
		.unwrap();
}

#[test]
fn simultaneous_promotions_have_one_winner_and_one_semantic_conflict() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("race.sqlite");
	let key = MasterKey::for_tests();
	let first = Db::open(&path, &key).unwrap();
	seed(&first);
	let second = Db::open(&path, &key).unwrap();
	let barrier = Arc::new(Barrier::new(2));
	let submit = |db: Db, barrier: Arc<Barrier>, job: i64, lead: i64| {
		db.with_conn(|conn| {
			conn.busy_timeout(std::time::Duration::from_secs(5))?;
			barrier.wait();
			let payload = promotion();
			let mut input = new(&payload);
			input.job_id = job;
			input.origin_lead_id = lead;
			standalone::insert(conn, &input, 0)
		})
	};
	let other = barrier.clone();
	let thread = std::thread::spawn(move || submit(second, other, 302, 502));
	let a = submit(first, barrier, 301, 501);
	let b = thread.join().unwrap();
	let winner = match (&a, &b) {
		(Ok(id), Err(Error::Conflict(Conflict::FindingIdentity(other))))
		| (Err(Error::Conflict(Conflict::FindingIdentity(other))), Ok(id)) => {
			assert_eq!(id, other);
			*id
		},
		_ => panic!("one strict winner and one identity conflict: {a:?}, {b:?}"),
	};
	Db::open(&path, &key)
		.unwrap()
		.with_conn(|conn| {
			assert_eq!(counts(conn), (1, 1));
			assert!(findings::get(conn, winner)?.is_some());
			Ok(())
		})
		.unwrap();
}
