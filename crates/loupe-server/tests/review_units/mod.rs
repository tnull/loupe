//! Unit proposal checkpoints use the actual router and worker identity.
use loupe_storage::{checkpoints, review_units};

use super::*;

const ROUTE: &str = "review-units";
fn payload(key: &str) -> Value {
	json!({"protocol_version":3,"client_review_unit_key":key,"title":"Request boundary",
		"objective":"Inspect the caller boundary","priority_band":"urgent",
		"priority_rationale":"Proposed importance, not L1 evidence",
		"source_refs":[{"path":"z.rs","symbol":"check"}],"depends_on_review_unit_ids":[],
		"closure_criteria":"All entry points accounted for","semantic_context":"Caller context"})
}
async fn ready() -> (Fixture, i64) {
	let f = fixture();
	let generation = prepare(&f).await;
	f.state.db.with_conn(|conn| {
		let policy = ReviewPolicy::default().snapshot_v2().unwrap();
		conn.execute("UPDATE review_campaigns SET effective_policy=?2,effective_policy_digest=?3 WHERE campaign_id=?1",params![f.campaign,policy.expose(),policy.digest().as_slice()])?;
		Ok(())
	}).unwrap();
	(f, generation)
}
fn counts(f: &Fixture) -> (i64, i64) {
	f.state
		.db
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				Ok((
					tx.query_row(
						"SELECT COUNT(*) FROM review_units WHERE created_by_job_id=?1",
						[f.job],
						|r| r.get(0),
					)?,
					checkpoints::accepted_count(
						tx,
						f.job,
						checkpoints::Operation::SubmitReviewUnit,
					)?,
				))
			})
		})
		.unwrap()
}

#[tokio::test]
async fn proposal_preserves_fields_but_does_not_grant_urgent_authority() {
	let (f, generation) = ready().await;
	let key = "k".repeat(128);
	let request = payload(&key);
	let reply = post(&f, ROUTE, request.clone()).await;
	assert_eq!(reply["accepted_priority_band"], "normal");
	assert_eq!(reply["assignment_epoch"], 0);
	let id = reply["review_unit_id"].as_i64().unwrap();
	f.state
		.db
		.with_conn(|conn| {
			let unit = review_units::get(conn, id)?.unwrap();
			assert_eq!(unit.generation_id, generation);
			assert_eq!(unit.priority, review_units::Priority::Normal);
			assert_eq!(unit.source_refs.as_slice()[0].path.expose(), "z.rs");
			assert_eq!(unit.objective.expose(), "Inspect the caller boundary");
			assert_eq!(unit.closure_criteria.unwrap().expose(), "All entry points accounted for");
			assert_eq!(
				serde_json::from_str::<Value>(unit.semantic_context.unwrap().expose()).unwrap(),
				"Caller context"
			);
			assert_eq!(
				serde_json::from_str::<Value>(unit.priority_proposal.unwrap().expose()).unwrap()
					["band"],
				"urgent"
			);
			assert!(unit.client_key.expose().starts_with(&format!("j{}.", f.job)));
			assert!(unit.client_key.expose().len() <= 128);
			Ok(())
		})
		.unwrap();
	assert_eq!(post(&f, ROUTE, request.clone()).await, reply);
	let mut changed = request;
	changed["semantic_context"] = json!("Changed context");
	assert_eq!(super::request(&f, f.job, ROUTE, changed).await.0, StatusCode::CONFLICT);
	assert_eq!(counts(&f), (1, 1));
}

#[tokio::test]
async fn replay_precedes_changed_dependency_ownership_and_concurrent_retries() {
	let (f, _) = ready().await;
	let original = post(&f, ROUTE, payload("parent")).await;
	let unit = original["review_unit_id"].as_i64().unwrap();
	let mut dependent = payload("child");
	dependent["depends_on_review_unit_ids"] = json!([unit]);
	let (left, right) = tokio::join!(
		super::request(&f, f.job, ROUTE, dependent.clone()),
		super::request(&f, f.job, ROUTE, dependent.clone())
	);
	assert_eq!(left.0, StatusCode::OK);
	assert_eq!(left, right);
	assert_eq!(counts(&f), (2, 2));
	f.state.db.with_conn(|conn| {
		conn.execute("INSERT INTO jobs(repo_id,kind,state,campaign_id,generation_id,enqueued_at) SELECT repo_id,'survey','queued',campaign_id,generation_id,?2 FROM jobs WHERE id=?1",params![f.job,now()])?;
		let other = conn.last_insert_rowid();
		conn.execute("INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(?1,?2,0,0)",params![other,unit])?;
		Ok(())
	}).unwrap();
	assert_eq!(super::request(&f, f.job, ROUTE, dependent.clone()).await, left);
	dependent["client_review_unit_key"] = json!("fresh-child");
	assert_eq!(super::request(&f, f.job, ROUTE, dependent).await.0, StatusCode::FORBIDDEN);
	assert_eq!(counts(&f), (2, 2));
}

#[tokio::test]
async fn source_paths_remain_byte_exact_in_storage_and_replay_identity() {
	let f = fixture();
	post(&f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await;
	let entries = ["e\u{301}.rs", "é.rs"]
		.into_iter()
		.map(|path| ManifestEntry {
			raw_path: path.as_bytes().to_vec(),
			git_mode: 0o100644,
			object_id: SHA.into(),
		})
		.collect::<Vec<_>>();
	post(&f, "inventory-batches", chunk(&entries, 0, entries.len())).await;
	post(&f, "seal-inventory", json!({"protocol_version":3})).await;
	post(&f, "publish-profile", json!({"protocol_version":3,"profile":{"scope":"crate"}})).await;
	f.state.db.with_conn(|conn| {
		let policy=ReviewPolicy::default().snapshot_v2().unwrap();
		conn.execute("UPDATE review_campaigns SET effective_policy=?2,effective_policy_digest=?3 WHERE campaign_id=?1",params![f.campaign,policy.expose(),policy.digest().as_slice()])?;
		Ok(())
	}).unwrap();
	let mut first = payload("exact");
	first["source_refs"] = json!([{"path":"e\u{301}.rs"}]);
	let reply = post(&f, ROUTE, first.clone()).await;
	let mut changed = first.clone();
	changed["source_refs"] = json!([{"path":"é.rs"}]);
	assert_eq!(super::request(&f, f.job, ROUTE, changed.clone()).await.0, StatusCode::CONFLICT);
	changed["client_review_unit_key"] = json!("other-exact");
	let other = post(&f, ROUTE, changed).await;
	f.state
		.db
		.with_conn(|conn| {
			for (id, path) in [
				(reply["review_unit_id"].as_i64().unwrap(), "e\u{301}.rs"),
				(other["review_unit_id"].as_i64().unwrap(), "é.rs"),
			] {
				assert_eq!(
					review_units::get(conn, id)?.unwrap().source_refs.as_slice()[0].path.expose(),
					path
				);
			}
			Ok(())
		})
		.unwrap();
	assert_eq!(post(&f, ROUTE, first).await, reply);
}

#[tokio::test]
async fn fresh_quota_is_frozen_across_attempts_and_replay_is_free() {
	let (mut f, _) = ready().await;
	let original = payload("unit-0");
	let reply = post(&f, ROUTE, original.clone()).await;
	for id in 1..32 {
		post(&f, ROUTE, payload(&format!("unit-{id}"))).await;
	}
	assert_eq!(super::request(&f, f.job, ROUTE, payload("overflow")).await.0, StatusCode::CONFLICT);
	f.token = "b".repeat(43);
	f.state.db.with_conn(|conn| {
		conn.execute("UPDATE jobs SET attempts=2,prepared_attempt=2,job_capability_hash=?2,prepared_capability_hash=?2 WHERE id=?1",params![f.job,blake3::hash(f.token.as_bytes()).as_bytes().as_slice()])?;
		Ok(())
	}).unwrap();
	assert_eq!(post(&f, ROUTE, original).await, reply);
	assert_eq!(
		super::request(&f, f.job, ROUTE, payload("after-retry")).await.0,
		StatusCode::CONFLICT
	);
	assert_eq!(counts(&f), (32, 32));
}

#[tokio::test]
async fn dependency_scope_precedes_object_decode_and_namespaces_keys_by_job() {
	let (mut f, generation) = ready().await;
	let first = post(&f, ROUTE, payload("same-key")).await;
	let unit = first["review_unit_id"].as_i64().unwrap();
	let mut dependent = payload("dependent");
	dependent["depends_on_review_unit_ids"] = json!([unit]);
	post(&f, ROUTE, dependent).await;
	let old_job = f.job;
	f.token = "b".repeat(43);
	f.job = f.state.db.with_conn(|conn| transaction::immediate(conn,|tx| {
		tx.execute("UPDATE review_generations SET state='active',activated_at=1 WHERE generation_id=?1",[generation])?;
		tx.execute("INSERT INTO jobs(repo_id,kind,state,campaign_id,generation_id,worker_id,attempts,head_sha,recipe,workflow_contract_version,lease_expires_at,hard_deadline_at,job_capability_hash,prepared_attempt,prepared_capability_hash,prepared_at,enqueued_at) SELECT repo_id,kind,state,campaign_id,generation_id,worker_id,attempts,head_sha,'{\"version\":1,\"phase\":\"survey\",\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}',workflow_contract_version,lease_expires_at,hard_deadline_at,?2,1,?2,?3,?3 FROM jobs WHERE id=?1",params![old_job,blake3::hash(f.token.as_bytes()).as_bytes().as_slice(),now()])?;
		Ok(tx.last_insert_rowid())
	})).unwrap();
	let second = post(&f, ROUTE, payload("same-key")).await;
	assert_ne!(first["review_unit_id"], second["review_unit_id"]);
	// Ordinary proposals do not silently expand the job's assigned scope.
	let mut own_unassigned = payload("unassigned-dependency");
	own_unassigned["depends_on_review_unit_ids"] = json!([second["review_unit_id"]]);
	assert_eq!(super::request(&f, f.job, ROUTE, own_unassigned).await.0, StatusCode::FORBIDDEN);
	f.state
		.db
		.with_conn(|conn| {
			conn.execute(
				"UPDATE review_units SET source_refs='broken' WHERE review_unit_id=?1",
				[unit],
			)?;
			Ok(())
		})
		.unwrap();
	let mut denied = payload("foreign-dependency");
	denied["depends_on_review_unit_ids"] = json!([unit]);
	let existing = super::request(&f, f.job, ROUTE, denied.clone()).await;
	assert_eq!(existing.0, StatusCode::FORBIDDEN);
	denied["depends_on_review_unit_ids"] = json!([999999]);
	assert_eq!(existing, super::request(&f, f.job, ROUTE, denied).await);
	assert_eq!(counts(&f), (1, 1));
}

#[tokio::test]
async fn unit_and_receipt_roll_back_together_on_checkpoint_failure() {
	let (f, _) = ready().await;
	f.state.db.with_conn(|conn| {
		conn.execute_batch("CREATE TRIGGER fail_unit_checkpoint BEFORE INSERT ON job_checkpoints WHEN NEW.operation='submit_review_unit' BEGIN SELECT RAISE(ABORT,'test failure'); END;")?;
		Ok(())
	}).unwrap();
	assert_eq!(
		super::request(&f, f.job, ROUTE, payload("rollback")).await.0,
		StatusCode::INTERNAL_SERVER_ERROR
	);
	assert_eq!(counts(&f), (0, 0));
}

#[tokio::test]
async fn phase_deadline_and_content_encoding_boundaries_precede_mutation() {
	let (f, _) = ready().await;
	let mut encoded = Request::post(format!("/v1/jobs/{}/{ROUTE}", f.job))
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header(JOB_CAPABILITY_HEADER, &f.token)
		.header("content-type", "application/json")
		.header("content-encoding", "gzip")
		.body(Body::from(payload("encoded").to_string()))
		.unwrap();
	encoded.extensions_mut().insert(f.peer.clone());
	assert_eq!(response(&f, encoded).await.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
	let original = post(&f, ROUTE, payload("accepted")).await;
	for mutation in [
		"UPDATE jobs SET kind='drilldown' WHERE id=?1",
		"UPDATE jobs SET kind='survey',hard_deadline_at=1 WHERE id=?1",
		"UPDATE jobs SET hard_deadline_at=9999999999,lease_expires_at=1 WHERE id=?1",
	] {
		f.state
			.db
			.with_conn(|conn| {
				conn.execute(mutation, [f.job])?;
				Ok(())
			})
			.unwrap();
		for key in ["accepted", "denied"] {
			assert_eq!(
				super::request(&f, f.job, ROUTE, payload(key)).await.0,
				StatusCode::FORBIDDEN
			);
		}
	}
	assert!(original["review_unit_id"].is_number());
	assert_eq!(counts(&f), (1, 1));
}

#[tokio::test]
async fn unit_boundaries_reject_unrepresentable_fields_and_unpinned_sources() {
	let (f, _) = ready().await;
	for (field, value) in [
		("closure_criteria", json!("a".repeat(1001))),
		("closure_criteria", json!("line one\nline two")),
		("source_refs", json!([])),
		("source_refs", json!([{"path":"outside.rs"}])),
		("source_refs", json!((0..33).map(|_| json!({"path":"z.rs"})).collect::<Vec<_>>())),
		("depends_on_review_unit_ids", json!([1, 1])),
		("semantic_context", json!("a".repeat(4001))),
		("job_id", json!(f.job)),
	] {
		let mut invalid = payload("invalid");
		invalid[field] = value;
		assert_eq!(
			super::request(&f, f.job, ROUTE, invalid).await.0,
			StatusCode::BAD_REQUEST,
			"{field}"
		);
	}
	assert_eq!(counts(&f), (0, 0));
	let mut maximum = payload("maximum");
	maximum["closure_criteria"] = json!("a".repeat(1000));
	post(&f, ROUTE, maximum).await;
}

#[tokio::test]
async fn unit_transport_and_authority_reject_before_mutation() {
	let (f, _) = ready().await;
	for (raw, expected) in [
		(
			payload("duplicate")
				.to_string()
				.replace("\"protocol_version\":3", "\"protocol_version\":3,\"protocol_version\":3"),
			StatusCode::BAD_REQUEST,
		),
		(" ".repeat(256 * 1024 + 1), StatusCode::PAYLOAD_TOO_LARGE),
	] {
		let mut req = Request::post(format!("/v1/jobs/{}/{ROUTE}", f.job))
			.header(PROTOCOL_VERSION_HEADER, "3")
			.header(JOB_CAPABILITY_HEADER, &f.token)
			.header("content-type", "application/json")
			.body(Body::from(raw))
			.unwrap();
		req.extensions_mut().insert(f.peer.clone());
		assert_eq!(response(&f, req).await.0, expected);
	}
	for peer in [None, Some(f.other_peer.clone())] {
		let mut req = Request::post(format!("/v1/jobs/{}/{ROUTE}", f.job))
			.header(PROTOCOL_VERSION_HEADER, "3")
			.header(JOB_CAPABILITY_HEADER, &f.token)
			.header("content-type", "application/json")
			.body(Body::from(payload("denied").to_string()))
			.unwrap();
		if let Some(peer) = peer {
			req.extensions_mut().insert(peer);
		}
		let (status, error) = response(&f, req).await;
		assert!(status.is_client_error());
		assert!(error.get("error").is_some());
	}
	f.state.db.with_conn(|conn| { conn.execute("UPDATE jobs SET prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id=?1",[f.job])?; Ok(()) }).unwrap();
	assert_eq!(
		super::request(&f, f.job, ROUTE, payload("unprepared")).await.0,
		StatusCode::FORBIDDEN
	);
	assert_eq!(counts(&f), (0, 0));
}
