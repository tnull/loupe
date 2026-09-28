use loupe_core::text::{Anchor, BoundedJson, Identifier};
use rusqlite::params;

use crate::identity::Identity;
use crate::review_tests::{fixture, payload};
use crate::review_units::Priority;
use crate::{leads, transaction};

fn identity() -> Identity {
	Identity {
		family: Identifier::new("auth-bypass").unwrap(),
		anchor: Anchor::new("token boundary").unwrap(),
		instance: None,
	}
}

fn historical_lead(conn: &mut rusqlite::Connection) -> i64 {
	let leads::Submitted::Created(id) = leads::standalone::submit(
		conn,
		&leads::NewLead {
			generation_id: 11,
			unit_id: None,
			identity: &identity(),
			payload: &payload(),
			commit_sha: "base",
			priority: Priority::Normal,
			priority_proposal: None,
			supersedes: None,
			created_by_job: Some(101),
		},
		0,
	)
	.unwrap() else {
		panic!("new identity")
	};
	id
}

#[test]
fn legacy_lead_reader_rejects_modern_marker() {
	fixture()
		.with_conn(|conn| {
			let id = historical_lead(conn);
			conn.execute(
				"UPDATE leads SET anchored_payload=?2 WHERE lead_id=?1",
				params![id, r#"{"format":"loupe.lead_evidence","version":1}"#],
			)?;
			assert!(
				leads::get(conn, id).is_err(),
				"modern lead evidence must not traverse generic JSON normalization"
			);
			Ok(())
		})
		.unwrap();
}

#[test]
fn legacy_observation_reader_rejects_modern_marker() {
	fixture().with_conn(|conn| {
		let id = historical_lead(conn);
		conn.execute("INSERT INTO lead_observations(lead_id,observation_payload,observation_digest,commit_sha,created_at) VALUES (?1,?2,zeroblob(32),'base',0)", params![id, r#"{"format":"loupe.lead_evidence","version":1}"#])?;
		assert!(crate::lead_observations::list(conn, id).is_err(), "modern observation evidence must not traverse generic JSON normalization");
		Ok(())
	}).unwrap();
}

#[test]
fn legacy_result_reader_rejects_modern_marker() {
	fixture().with_conn(|conn| {
		conn.execute_batch("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES (31,11,'unit','title','objective','[]',0)")?;
		conn.execute("INSERT INTO review_unit_results(review_unit_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at) VALUES(31,'base',1,'no_lead_found','[]',?1,zeroblob(32),0)", [r#"{"format":"loupe.unit_result","version":1}"#])?;
		assert!(crate::review_unit_results::list(conn, 31).is_err(), "modern result evidence must not traverse generic JSON normalization");
		Ok(())
	}).unwrap();
}

#[test]
fn closing_lead_does_not_decode_unrelated_evidence() {
	fixture()
		.with_conn(|conn| {
			let id = historical_lead(conn);
			conn.execute("UPDATE leads SET anchored_payload=x'00' WHERE lead_id=?1", [id])?;
			assert!(
				leads::standalone::close(conn, id, &leads::Closure::Rejected, 1).is_ok(),
				"scope-only closure must not decode the lead payload"
			);
			Ok(())
		})
		.unwrap();
}

#[test]
fn duplicate_identity_attachment_does_not_decode_original_evidence() {
	fixture().with_conn(|conn| {
		let id = historical_lead(conn);
		conn.execute("UPDATE leads SET anchored_payload=x'00' WHERE lead_id=?1", [id])?;
		let identity = identity();
		let data = BoundedJson::new(r#"{"observation":"new evidence"}"#).unwrap();
		let result = transaction::immediate(conn, |tx| leads::submit(tx, &leads::NewLead {
			generation_id: 11, unit_id: None, identity: &identity, payload: &data,
			commit_sha: "base", priority: Priority::High, priority_proposal: None,
			supersedes: None, created_by_job: Some(101),
		}, 1));
		assert!(matches!(result, Ok(leads::Submitted::Attached { lead_id, .. }) if lead_id == id), "identity attachment must preserve new evidence without decoding unrelated original payload: {result:?}");
		assert_eq!(crate::lead_observations::list(conn, id)?[0].payload, data);
		Ok(())
	}).unwrap();
}

#[test]
fn generic_lead_insertion_rejects_reserved_evidence_formats() {
	fixture()
		.with_conn(|conn| {
			let tagged =
				BoundedJson::new(r#"{"format":"loupe.lead_evidence","version":1}"#).unwrap();
			let result = leads::standalone::submit(
				conn,
				&leads::NewLead {
					generation_id: 11,
					unit_id: None,
					identity: &identity(),
					payload: &tagged,
					commit_sha: "base",
					priority: Priority::Normal,
					priority_proposal: None,
					supersedes: None,
					created_by_job: Some(101),
				},
				0,
			);
			assert!(result.is_err(), "generic writes must not claim a typed evidence format");
			Ok(())
		})
		.unwrap();
}

#[test]
fn generic_observation_insertion_rejects_reserved_evidence_formats() {
	fixture()
		.with_conn(|conn| {
			let lead_id = historical_lead(conn);
			let tagged =
				BoundedJson::new(r#"{"format":"loupe.lead_evidence","version":1}"#).unwrap();
			let result = crate::lead_observations::standalone::insert(
				conn,
				&crate::lead_observations::NewObservation {
					lead_id,
					submitted_by_job: Some(101),
					payload: &tagged,
					commit_sha: "base",
				},
				0,
			);
			assert!(result.is_err(), "generic writes must not claim a typed observation format");
			Ok(())
		})
		.unwrap();
}

#[test]
fn generic_result_insertion_rejects_reserved_evidence_formats() {
	fixture().with_conn(|conn| {
		conn.execute_batch("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES (31,11,'unit','title','objective','[]',0)")?;
		let tagged = BoundedJson::new(r#"{"format":"loupe.unit_result","version":1}"#).unwrap();
		let result = crate::review_unit_results::standalone::insert(conn,&crate::review_unit_results::NewResult {
			generation_id:11,unit_id:31,produced_by_job:Some(101),commit_sha:"base",profile_version:1,
			disposition:crate::review_unit_results::Disposition::NoLeadFound,
			inspected_refs:&crate::source_refs::InspectedRefs::new(vec![]).unwrap(),
			counterevidence:None,proof_gaps:None,payload:&tagged,corroborates_result:None,corroborates_exclusion:None,
		},0);
		assert!(result.is_err(), "generic writes must not claim a typed result format");
		Ok(())
	}).unwrap();
}
