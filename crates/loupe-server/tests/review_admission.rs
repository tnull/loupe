//! Real HTTP regression guards for the shared lease transaction boundary.
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use loupe_server::{router, AppState, PeerCert};
use loupe_storage::{workers, Db};
use loupe_tls::Ca;
use serde_json::{json, Value};
use tower::Service;

fn fixture() -> (AppState, PeerCert) {
	let db = Arc::new(Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap());
	let ca = Ca::new("admission-tests").unwrap();
	let cert = ca.mint_client("worker").unwrap();
	let peer =
		PeerCert(rustls_pemfile::certs(&mut cert.cert_pem.as_bytes()).next().unwrap().unwrap());
	db.with_conn(|conn| {
		conn.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(1,'u','github.com','owner','repo','{\"kind\":\"manual\"}',0)",[])?;
		workers::insert(conn,"worker",workers::WorkerKind::Worker,&loupe_tls::cert_fingerprint(peer.0.as_ref()),0)?;
		Ok(())
	}).unwrap();
	(
		AppState::new(
			db,
			Arc::new(ca),
			Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()),
		),
		peer,
	)
}

async fn lease(state: &AppState, peer: &PeerCert) -> (StatusCode, Value) {
	let mut req = Request::post("/v1/jobs/lease")
		.header("content-type", "application/json")
		.body(Body::from(
			json!({"protocol_version":3,"capabilities":["verify:llm"],"wait_seconds":0})
				.to_string(),
		))
		.unwrap();
	req.extensions_mut().insert(peer.clone());
	let response = router(state.clone()).call(req).await.unwrap();
	let status = response.status();
	let bytes = to_bytes(response.into_body(), 5 * 1024 * 1024).await.unwrap();
	(
		status,
		serde_json::from_slice(&bytes)
			.unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)})),
	)
}

#[tokio::test]
async fn unreadable_legacy_envelope_is_quarantined_before_any_lease_commits() {
	let (state, peer) = fixture();
	state.db.with_conn(|conn| {
		conn.execute("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(1,1,'verify','queued',0),(2,1,'scan','queued',1)",[])?;
		Ok(())
	}).unwrap();
	let (status, response) = lease(&state, &peer).await;
	assert_eq!(
		status,
		StatusCode::OK,
		"A bad envelope must not strand its lease or poison healthy work: {response}"
	);
	assert_eq!(response["job_id"], 2);
	state
		.db
		.with_conn(|conn| {
			let bad = loupe_storage::jobs::get(conn, 1)?.unwrap();
			assert_eq!(bad.state, loupe_core::JobState::Failed);
			assert_eq!(bad.attempts, 0);
			assert!(bad.worker_id.is_none() && bad.lease_expires_at.is_none());
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn canonical_target_is_not_delivered_through_legacy_verify() {
	let (state, peer) = fixture();
	state.db.with_conn(|conn| {
		conn.execute_batch("INSERT INTO review_campaigns(campaign_id,repo_id,recipe,trigger,target_commit_sha,state,effective_policy,effective_policy_digest,created_at) VALUES(1,1,'bootstrap','manual','main','finished','{}',zeroblob(32),0);
		INSERT INTO jobs(id,repo_id,kind,state,campaign_id,enqueued_at) VALUES(1,1,'drilldown','succeeded',1,0);
		INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,created_at) VALUES(1,1,1,'review','high','Canonical finding','Evidence','canonical','validating',0);
		INSERT INTO jobs(id,repo_id,kind,state,target_finding_id,enqueued_at) VALUES(2,1,'verify','queued',1,0),(3,1,'scan','queued',NULL,1);")?;
		Ok(())
	}).unwrap();
	let (status, response) = lease(&state, &peer).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		response["job_id"], 3,
		"Canonical phase finding provenance must block legacy claim authority"
	);
	state
		.db
		.with_conn(|conn| {
			assert_eq!(loupe_storage::jobs::get(conn, 2)?.unwrap().attempts, 0);
			assert_eq!(
				loupe_storage::findings::get(conn, 1)?.unwrap().state,
				loupe_core::FindingState::Validating
			);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn chunked_lease_body_is_bounded_before_claim() {
	let (state, peer) = fixture();
	state
		.db
		.with_conn(|conn| {
			conn.execute(
				"INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(1,1,'scan','queued',0)",
				[],
			)?;
			Ok(())
		})
		.unwrap();
	let mut body = json!({"protocol_version":3,"capabilities":[],"wait_seconds":0}).to_string();
	body.push_str(&" ".repeat(8192));
	let mut req = Request::post("/v1/jobs/lease")
		.header("content-type", "application/json")
		.header("transfer-encoding", "chunked")
		.body(Body::from(body))
		.unwrap();
	req.extensions_mut().insert(peer);
	let response = router(state.clone()).call(req).await.unwrap();
	assert_eq!(
		response.status(),
		StatusCode::PAYLOAD_TOO_LARGE,
		"actual bytes must be bounded without Content-Length"
	);
	assert_eq!(response.headers()["cache-control"], "no-store");
	assert!(to_bytes(response.into_body(), 4096).await.is_ok());
	state
		.db
		.with_conn(|conn| {
			assert_eq!(loupe_storage::jobs::get(conn, 1)?.unwrap().attempts, 0);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn lease_outer_auth_errors_are_bounded_and_noncacheable() {
	let (state, _) = fixture();
	let request = Request::post("/v1/jobs/lease")
		.header("content-type", "application/json")
		.body(Body::from("{}"))
		.unwrap();
	let response = router(state).call(request).await.unwrap();
	assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
	assert_eq!(response.headers()["cache-control"], "no-store");
	let body = to_bytes(response.into_body(), 4096).await.unwrap();
	assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["protocol_version"], 3);
}

#[tokio::test]
async fn long_poll_has_one_request_wide_quarantine_budget() {
	let (state, peer) = fixture();
	state.db.with_conn(|conn| {
		for id in 1..=40 {conn.execute("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(?1,1,'verify','queued',0)",[id])?;}
		Ok(())
	}).unwrap();
	let mut request = Request::post("/v1/jobs/lease")
		.header("content-type", "application/json")
		.body(Body::from(
			json!({"protocol_version":3,"capabilities":["verify:llm"],"wait_seconds":1})
				.to_string(),
		))
		.unwrap();
	request.extensions_mut().insert(peer);
	assert_eq!(router(state.clone()).call(request).await.unwrap().status(), StatusCode::OK);
	state
		.db
		.with_conn(|conn| {
			assert_eq!(
				conn.query_row("SELECT COUNT(*) FROM jobs WHERE state='failed'", [], |r| r
					.get::<_, i64>(0))?,
				32,
				"long polling must not reset the permanent-repair budget"
			);
			Ok(())
		})
		.unwrap();
}
