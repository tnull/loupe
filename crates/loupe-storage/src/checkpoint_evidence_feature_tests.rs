use loupe_core::review_payload::{LeadEvidenceV1, UnitResultPayloadV1};
use loupe_core::text::{BoundedJson, BoundedText};
use rusqlite::{params, Connection};
use serde_json::json;

use crate::review_tests::fixture;
use crate::review_units::Priority;
use crate::{
	lead_observations as observations, leads, review_unit_results as results, transaction,
	StoredEvidence,
};

fn seed(conn: &Connection) {
	conn.execute_batch("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES (31,11,'first','title','objective','[]',0),(32,11,'second','title','objective','[]',0),(41,21,'foreign','title','objective','[]',0)").unwrap();
}
fn lead() -> LeadEvidenceV1 {
	LeadEvidenceV1::from_json(&json!({
		"format":"loupe.lead_evidence","version":1,"identity_family":"auth-bypass",
		"identity_anchor":"request guard","identity_instance_key":"administrator route",
		"review_unit_id":31,"assignment_epoch":0,"hypothesis":"wrapper bypass",
		"invariant_or_boundary":"authentication boundary","source_refs":[{"path":"cafe\u{301}.rs","symbol":"cafe\u{301}"}],
		"next_proof_step":"trace wrapper","counterevidence":"guard exists","proof_gaps":"entry is uncertain",
		"priority_proposal":{"impact":"high","access":"remote","reachability":"traced",
			"boundary_refs":[{"path":"cafe\u{301}.rs"}],"rationale":"exposed boundary"}
	}).to_string()).unwrap()
}
fn result() -> UnitResultPayloadV1 {
	UnitResultPayloadV1::from_json(
		&json!({
			"format":"loupe.unit_result","version":1,"review_unit_id":31,"assignment_epoch":0,
			"disposition":"needs_follow_up","inspected_refs":[{"path":"cafe\u{301}.rs"}],
			"created_lead_ids":[],"counterevidence":"guard exists","proof_gaps":"entry is uncertain",
			"follow_up":"trace entry","notes":"retain all context","continuation":"source_analysis_remaining"
		})
		.to_string(),
	)
	.unwrap()
}
fn submit(conn: &mut Connection, payload: &LeadEvidenceV1) -> leads::Submitted {
	leads::standalone::submit_evidence(
		conn,
		&leads::NewLeadEvidence {
			generation_id: 11,
			created_by_job: 101,
			commit_sha: "copied-commit",
			priority: Priority::High,
			payload,
		},
		123,
	)
	.unwrap()
}
fn inserted_id(conn: &mut Connection, payload: &LeadEvidenceV1) -> i64 {
	let leads::Submitted::Created(id) = submit(conn, payload) else { panic!("created") };
	id
}
fn insert_result(conn: &mut Connection, payload: &UnitResultPayloadV1) -> i64 {
	results::standalone::insert_evidence(
		conn,
		&results::NewResultEvidence {
			generation_id: 11,
			produced_by_job: 101,
			commit_sha: "copied-commit",
			profile_version: 3,
			payload,
		},
		456,
	)
	.unwrap()
}

#[test]
fn typed_lead_round_trip_has_one_payload_and_exact_paths() {
	fixture().with_conn(|conn| {
		seed(conn);
		let payload = lead(); let id = inserted_id(conn,&payload);
		assert_eq!(leads::get_evidence(conn,id)?,StoredEvidence::Recorded(payload.clone()));
		let metadata = leads::get_metadata(conn,id)?.unwrap();
		assert_eq!(metadata.unit_id,Some(31)); assert_eq!(metadata.priority,Priority::High);
		assert_eq!(metadata.commit_sha,"copied-commit"); assert_eq!(metadata.created_by_job,Some(101));
		assert_eq!(metadata.created_at,123);
		let (raw,digest,proposal):(String,Vec<u8>,Option<String>) = conn.query_row("SELECT anchored_payload,anchored_digest,priority_proposal FROM leads WHERE lead_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
		assert_eq!(raw.as_bytes(),payload.canonical_bytes()?); assert_eq!(digest,payload.digest()?);
		assert!(raw.contains("cafe\u{301}.rs")); assert!(proposal.is_none());
		assert!(leads::get(conn,id).is_err());
		leads::standalone::close(conn,id,&leads::Closure::Rejected,999)?;
		assert_eq!(leads::get_evidence(conn,id)?,StoredEvidence::Recorded(payload));
		assert_eq!(leads::get_metadata(conn,id)?.unwrap().disposition,Some(leads::Disposition::Rejected));
		Ok(())
	}).unwrap();
}

#[test]
fn duplicate_and_closed_identity_retain_complete_new_observations() {
	fixture().with_conn(|conn| {
		seed(conn);
		let original = lead(); let id = inserted_id(conn,&original);
		let mut attached = original.clone();
		attached.review_unit_id = Some(32); attached.assignment_epoch = Some(7);
		attached.hypothesis = BoundedText::new("different hypothesis").unwrap();
		attached.invariant_or_boundary = Some(BoundedText::new("different boundary").unwrap());
		attached.source_refs[0].path = "café.rs".parse().unwrap();
		attached.priority_proposal.as_mut().unwrap().impact = loupe_core::review_priority::Impact::Critical;
		attached.duplicate_hint = Some(loupe_core::review_payload::DuplicateLeadHint {lead_id:id,rationale:BoundedText::new("same identity").unwrap()});
		assert_eq!(submit(conn,&attached),leads::Submitted::Attached {lead_id:id,status:leads::Status::Open});
		leads::standalone::close(conn,id,&leads::Closure::Hardening,200)?;
		assert!(matches!(submit(conn,&attached),leads::Submitted::ClosedExists {lead_id,disposition:leads::Disposition::Hardening,..} if lead_id==id));
		assert_eq!(leads::get_evidence(conn,id)?,StoredEvidence::Recorded(original));
		let rows = observations::list_evidence(conn,id)?;
		assert_eq!(rows.len(),2);
		assert!(rows[0].observation_id < rows[1].observation_id);
		for row in rows {
			assert_eq!(row.payload,StoredEvidence::Recorded(attached.clone()));
			assert_eq!(row.lead_id,id); assert_eq!(row.submitted_by_job,Some(101));
			assert_eq!(row.commit_sha,"copied-commit"); assert_eq!(row.created_at,123);
		}
		assert!(observations::list(conn,id).is_err());
		Ok(())
	}).unwrap();
}

#[test]
fn typed_result_round_trip_preserves_all_fields_and_provenance() {
	fixture().with_conn(|conn| {
		seed(conn); let payload = result(); let id = insert_result(conn,&payload);
		assert_eq!(results::get_evidence(conn,id)?,StoredEvidence::Recorded(payload.clone()));
		let rows = results::list_evidence(conn,31)?; assert_eq!(rows.len(),1);
		let row = &rows[0]; assert_eq!(row.result_id,id); assert_eq!(row.unit_id,31);
		assert_eq!(row.produced_by_job,Some(101)); assert_eq!(row.commit_sha,"copied-commit");
		assert_eq!(row.profile_version,3); assert_eq!(row.created_at,456);
		assert_eq!(row.payload,StoredEvidence::Recorded(payload.clone()));
		let (raw,digest,refs,counter,gaps):(String,Vec<u8>,String,Option<String>,Option<String>) = conn.query_row("SELECT result_payload,result_digest,inspected_refs,counterevidence,proof_gaps FROM review_unit_results WHERE review_unit_result_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
		assert_eq!(raw.as_bytes(),payload.canonical_bytes()?); assert_eq!(digest,payload.digest()?);
		assert!(refs.contains("cafe\u{301}.rs")); assert!(counter.is_none() && gaps.is_none());
		assert!(results::list(conn,31).is_err());
		results::standalone::invalidate(conn,id,&BoundedText::new("source changed").unwrap())?;
		let rows = results::list_evidence(conn,31)?; assert!(rows[0].invalidated);
		assert_eq!(rows[0].invalidated_reason.as_ref().unwrap().expose(),"source changed");
		assert_eq!(rows[0].payload,StoredEvidence::Recorded(payload));
		Ok(())
	}).unwrap();
}

#[test]
fn historical_payloads_stay_readable_and_missing_is_distinct() {
	fixture()
		.with_conn(|conn| {
			seed(conn);
			for raw in ["{}", "[]", "null", r#"{"format":"unrelated","version":99}"#] {
				let data = BoundedJson::new(raw).unwrap();
				let identity = crate::identity::Identity {
					family: "auth-bypass".parse().unwrap(),
					anchor: format!("boundary {}", raw.len()).parse().unwrap(),
					instance: None,
				};
				let outcome = leads::standalone::submit(
					conn,
					&leads::NewLead {
						generation_id: 11,
						unit_id: None,
						identity: &identity,
						payload: &data,
						commit_sha: "base",
						priority: Priority::Normal,
						priority_proposal: None,
						supersedes: None,
						created_by_job: Some(101),
					},
					0,
				)?;
				let id = match outcome {
					leads::Submitted::Created(id) => id,
					leads::Submitted::Attached { lead_id, .. } => lead_id,
					_ => unreachable!(),
				};
				assert_eq!(leads::get_evidence(conn, id)?, StoredEvidence::Historical);
				assert!(leads::get(conn, id)?.is_some());
				observations::standalone::insert(
					conn,
					&observations::NewObservation {
						lead_id: id,
						submitted_by_job: Some(101),
						payload: &data,
						commit_sha: "base",
					},
					1,
				)?;
				assert!(observations::list(conn, id)?.iter().any(|row| row.payload == data));
				assert!(observations::list_evidence(conn, id)?
					.iter()
					.all(|row| row.payload == StoredEvidence::Historical));
				let result_id = results::standalone::insert(
					conn,
					&results::NewResult {
						generation_id: 11,
						unit_id: 31,
						produced_by_job: Some(101),
						commit_sha: "base",
						profile_version: 1,
						disposition: results::Disposition::NoLeadFound,
						inspected_refs: &crate::source_refs::InspectedRefs::new(vec![]).unwrap(),
						counterevidence: None,
						proof_gaps: None,
						payload: &data,
						corroborates_result: None,
						corroborates_exclusion: None,
					},
					0,
				)?;
				assert_eq!(results::get_evidence(conn, result_id)?, StoredEvidence::Historical);
			}
			assert_eq!(results::list(conn, 31)?.len(), 4);
			assert_eq!(leads::get_evidence(conn, 999)?, StoredEvidence::Missing);
			assert_eq!(results::get_evidence(conn, 999)?, StoredEvidence::Missing);
			Ok(())
		})
		.unwrap();
}

#[test]
fn typed_reads_reject_noncanonical_corrupt_and_future_evidence() {
	for bad_kind in
		["digest", "noncanonical", "future", "malformed", "wrong_format", "duplicate_format"]
	{
		fixture()
			.with_conn(|conn| {
				seed(conn);
				let payload = lead();
				let id = inserted_id(conn, &payload);
				let raw = String::from_utf8(payload.canonical_bytes()?).unwrap();
				let bad = match bad_kind {
					"digest" => raw.clone(),
					"noncanonical" => format!(" {raw}"),
					"future" => raw.replace("\"version\":1", "\"version\":2"),
					"malformed" => r#"{"format":"loupe.lead_evidence","version":1}"#.into(),
					"wrong_format" => raw.replace("loupe.lead_evidence", "loupe.future_evidence"),
					_ => format!("{{\"format\":\"loupe.lead_evidence\",{}", &raw[1..]),
				};
				let digest = if bad_kind == "digest" {
					[0u8; 32]
				} else {
					crate::canonical::digest(bad.as_bytes())
				};
				conn.execute(
					"UPDATE leads SET anchored_payload=?2,anchored_digest=?3 WHERE lead_id=?1",
					params![id, bad, digest.as_slice()],
				)?;
				assert!(leads::get_evidence(conn, id).is_err(), "{bad_kind}");
				Ok(())
			})
			.unwrap();
	}
}

#[test]
fn lead_projection_mismatches_are_not_independent_sources() {
	for update in [
		"review_unit_id=32",
		"identity_family='other-family'",
		"identity_anchor='other anchor'",
		"identity_instance_key=NULL",
		"identity_fingerprint=zeroblob(32)",
		"priority_proposal='{}'",
	] {
		fixture()
			.with_conn(|conn| {
				seed(conn);
				let id = inserted_id(conn, &lead());
				conn.execute(&format!("UPDATE leads SET {update} WHERE lead_id=?1"), [id])?;
				assert!(leads::get_evidence(conn, id).is_err(), "{update}");
				Ok(())
			})
			.unwrap();
	}
}

#[test]
fn result_projection_and_digest_mismatches_are_rejected() {
	for update in [
		"review_unit_id=32",
		"disposition='no_lead_found'",
		"inspected_refs='[]'",
		"counterevidence='shadow'",
		"proof_gaps='shadow'",
		"result_digest=zeroblob(32)",
		"result_payload='{}'",
	] {
		fixture()
			.with_conn(|conn| {
				seed(conn);
				let id = insert_result(conn, &result());
				conn.execute(
					&format!(
						"UPDATE review_unit_results SET {update} WHERE review_unit_result_id=?1"
					),
					[id],
				)?;
				if update == "result_payload='{}'" {
					assert_eq!(
						results::get_evidence(conn, id)?,
						StoredEvidence::Historical,
						"untagged historical evidence is never promoted to modern"
					);
				} else {
					assert!(results::get_evidence(conn, id).is_err(), "{update}");
				}
				Ok(())
			})
			.unwrap();
	}
}

#[test]
fn observation_digest_and_identity_are_checked() {
	for update in [
		"observation_digest=zeroblob(32)",
		"observation_payload=' {\"format\":\"loupe.lead_evidence\"}'",
	] {
		fixture()
			.with_conn(|conn| {
				seed(conn);
				let payload = lead();
				let id = inserted_id(conn, &payload);
				submit(conn, &payload);
				conn.execute(
					&format!("UPDATE lead_observations SET {update} WHERE lead_id=?1"),
					[id],
				)?;
				assert!(observations::list_evidence(conn, id).is_err(), "{update}");
				Ok(())
			})
			.unwrap();
	}
	fixture()
		.with_conn(|conn| {
			seed(conn);
			let mut payload = lead();
			let id = inserted_id(conn, &payload);
			payload.identity_anchor = "different identity".parse().unwrap();
			assert!(observations::standalone::insert_evidence(
				conn,
				&observations::NewObservationEvidence {
					lead_id: id,
					submitted_by_job: 101,
					commit_sha: "base",
					payload: &payload
				},
				0
			)
			.is_err());
			Ok(())
		})
		.unwrap();
}

#[test]
fn typed_inserts_validate_scope_and_roll_back_atomically() {
	fixture()
		.with_conn(|conn| {
			seed(conn);
			let mut payload = lead();
			payload.review_unit_id = Some(41);
			assert!(leads::standalone::submit_evidence(
				conn,
				&leads::NewLeadEvidence {
					generation_id: 11,
					created_by_job: 101,
					commit_sha: "base",
					priority: Priority::Normal,
					payload: &payload
				},
				0
			)
			.is_err());
			payload.review_unit_id = Some(31);
			assert!(leads::standalone::submit_evidence(
				conn,
				&leads::NewLeadEvidence {
					generation_id: 11,
					created_by_job: 201,
					commit_sha: "base",
					priority: Priority::Normal,
					payload: &payload
				},
				0
			)
			.is_err());
			let result = transaction::immediate(conn, |tx| {
				leads::submit_evidence(
					tx,
					&leads::NewLeadEvidence {
						generation_id: 11,
						created_by_job: 101,
						commit_sha: "base",
						priority: Priority::Normal,
						payload: &payload,
					},
					0,
				)?;
				Err::<(), _>(crate::Error::Conflict(crate::Conflict::Checkpoint))
			});
			assert!(result.is_err());
			assert_eq!(
				conn.query_row("SELECT count(*) FROM leads", [], |r| r.get::<_, i64>(0))?,
				0
			);
			let mut payload = result_payload_for_foreign_unit();
			assert!(results::standalone::insert_evidence(
				conn,
				&results::NewResultEvidence {
					generation_id: 11,
					produced_by_job: 101,
					commit_sha: "base",
					profile_version: 1,
					payload: &payload
				},
				0
			)
			.is_err());
			payload.review_unit_id = 31;
			assert!(results::standalone::insert_evidence(
				conn,
				&results::NewResultEvidence {
					generation_id: 11,
					produced_by_job: 201,
					commit_sha: "base",
					profile_version: 1,
					payload: &payload
				},
				0
			)
			.is_err());
			assert_eq!(
				conn.query_row("SELECT count(*) FROM review_unit_results", [], |r| r
					.get::<_, i64>(0))?,
				0
			);
			Ok(())
		})
		.unwrap();
}
fn result_payload_for_foreign_unit() -> UnitResultPayloadV1 {
	let mut payload = result();
	payload.review_unit_id = 41;
	payload
}

#[test]
fn typed_results_retain_created_leads_and_reject_foreign_links() {
	fixture()
		.with_conn(|conn| {
			seed(conn);
			let lead_id = inserted_id(conn, &lead());
			let mut payload = result();
			payload.disposition = results::Disposition::LeadCreated;
			payload.created_lead_ids = vec![lead_id];
			payload.follow_up = None;
			payload.continuation = None;
			let id = insert_result(conn, &payload);
			assert_eq!(results::get_evidence(conn, id)?, StoredEvidence::Recorded(payload.clone()));
			payload.created_lead_ids = vec![999];
			assert!(results::standalone::insert_evidence(
				conn,
				&results::NewResultEvidence {
					generation_id: 11,
					produced_by_job: 101,
					commit_sha: "base",
					profile_version: 1,
					payload: &payload
				},
				0
			)
			.is_err());
			let mut foreign = lead();
			foreign.review_unit_id = Some(41);
			let leads::Submitted::Created(foreign_id) = leads::standalone::submit_evidence(
				conn,
				&leads::NewLeadEvidence {
					generation_id: 21,
					created_by_job: 201,
					commit_sha: "foreign",
					priority: Priority::Normal,
					payload: &foreign,
				},
				0,
			)?
			else {
				panic!("foreign lead")
			};
			payload.created_lead_ids = vec![foreign_id];
			assert!(results::standalone::insert_evidence(
				conn,
				&results::NewResultEvidence {
					generation_id: 11,
					produced_by_job: 101,
					commit_sha: "base",
					profile_version: 1,
					payload: &payload
				},
				0
			)
			.is_err());
			assert_eq!(results::list_evidence(conn, 31)?.len(), 1);
			Ok(())
		})
		.unwrap();
}

#[test]
fn evidence_and_priority_refs_use_exact_inventory_membership() {
	use crate::inventory::{self, InventoryPath, NewEntry};
	fixture()
		.with_conn(|conn| {
			seed(conn);
			let path = InventoryPath::from_git_bytes("cafe\u{301}.rs".as_bytes());
			inventory::standalone::insert(
				conn,
				1,
				11,
				&[NewEntry {
					path: &path,
					blob_sha: Some("blob"),
					kind: inventory::EntryKind::Tracked,
					disposition: inventory::Disposition::Unresolved,
					reason: None,
					highlighted: false,
				}],
				0,
			)?;
			let original = lead();
			let id = inserted_id(conn, &original);
			let mut bad = original.clone();
			bad.source_refs[0].path = "café.rs".parse().unwrap();
			assert!(leads::standalone::submit_evidence(
				conn,
				&leads::NewLeadEvidence {
					generation_id: 11,
					created_by_job: 101,
					commit_sha: "base",
					priority: Priority::Normal,
					payload: &bad
				},
				0
			)
			.is_err());
			bad = original.clone();
			bad.priority_proposal.as_mut().unwrap().boundary_refs[0].path =
				"café.rs".parse().unwrap();
			assert!(observations::standalone::insert_evidence(
				conn,
				&observations::NewObservationEvidence {
					lead_id: id,
					submitted_by_job: 101,
					commit_sha: "base",
					payload: &bad
				},
				0
			)
			.is_err());
			let mut bad = result();
			bad.inspected_refs[0].path = "café.rs".parse().unwrap();
			assert!(results::standalone::insert_evidence(
				conn,
				&results::NewResultEvidence {
					generation_id: 11,
					produced_by_job: 101,
					commit_sha: "base",
					profile_version: 1,
					payload: &bad
				},
				0
			)
			.is_err());
			assert!(observations::list_evidence(conn, id)?.is_empty());
			assert!(results::list_evidence(conn, 31)?.is_empty());
			Ok(())
		})
		.unwrap();
}

#[test]
fn direct_typed_observation_retains_payload_and_provenance() {
	fixture()
		.with_conn(|conn| {
			seed(conn);
			let mut payload = lead();
			let id = inserted_id(conn, &payload);
			payload.review_unit_id = Some(32);
			payload.assignment_epoch = Some(10);
			let observation_id = observations::standalone::insert_evidence(
				conn,
				&observations::NewObservationEvidence {
					lead_id: id,
					submitted_by_job: 101,
					commit_sha: "observed-commit",
					payload: &payload,
				},
				300,
			)?;
			let rows = observations::list_evidence(conn, id)?;
			assert_eq!(rows.len(), 1);
			assert_eq!(rows[0].observation_id, observation_id);
			assert_eq!(rows[0].commit_sha, "observed-commit");
			assert_eq!(rows[0].created_at, 300);
			assert_eq!(rows[0].submitted_by_job, Some(101));
			assert_eq!(rows[0].payload, StoredEvidence::Recorded(payload));
			// A changed relational identity must not reinterpret immutable observation bytes.
			conn.execute(
				"UPDATE leads SET identity_anchor='unrelated boundary' WHERE lead_id=?1",
				[id],
			)?;
			assert!(observations::list_evidence(conn, id).is_err());
			Ok(())
		})
		.unwrap();
}

#[test]
fn result_and_observation_readers_reject_future_and_noncanonical_typed_bytes() {
	for noncanonical in [false, true] {
		fixture()
			.with_conn(|conn| {
				seed(conn);
				let lead_payload = lead();
				let lead_id = inserted_id(conn, &lead_payload);
				submit(conn, &lead_payload);
				let result_payload = result();
				let result_id = insert_result(conn, &result_payload);
				for (table, column, digest, id_column, id, bytes) in [
					(
						"lead_observations",
						"observation_payload",
						"observation_digest",
						"lead_id",
						lead_id,
						lead_payload.canonical_bytes()?,
					),
					(
						"review_unit_results",
						"result_payload",
						"result_digest",
						"review_unit_result_id",
						result_id,
						result_payload.canonical_bytes()?,
					),
				] {
					let raw = String::from_utf8(bytes).unwrap();
					let bad = if noncanonical {
						format!(" {raw}")
					} else {
						raw.replace("\"version\":1", "\"version\":2")
					};
					conn.execute(
						&format!("UPDATE {table} SET {column}=?2,{digest}=?3 WHERE {id_column}=?1"),
						params![id, bad, crate::canonical::digest(bad.as_bytes()).as_slice()],
					)?;
				}
				assert!(observations::list_evidence(conn, lead_id).is_err());
				assert!(results::get_evidence(conn, result_id).is_err());
				Ok(())
			})
			.unwrap();
	}
}
