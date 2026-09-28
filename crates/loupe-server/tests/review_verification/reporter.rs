//! Local-only GitHub stub shared by router and private crash-gap tests.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use loupe_core::ReportingDestination;
use loupe_storage::{repos, secrets, workers, Db};
use serde_json::{json, Value};
use tower::Service;

use super::server::{router, AppState, PeerCert};

#[derive(Clone)]
pub struct Capture {
	pub calls: Arc<Mutex<Vec<Value>>>,
	pub fail: Arc<AtomicBool>,
	db: Arc<Db>,
	finding: i64,
}
pub struct Stub {
	pub capture: Capture,
	task: tokio::task::JoinHandle<()>,
}
impl Drop for Stub {
	fn drop(&mut self) {
		self.task.abort();
	}
}

async fn issue(
	State(capture): State<Capture>, Json(value): Json<Value>,
) -> (StatusCode, Json<Value>) {
	// This is observed from the receiving side, after the sender released its
	// database transaction. A report can never precede accepted canonical data.
	capture.db.with_conn(|conn| {
		let committed:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM findings f JOIN finding_verifications v ON v.finding_id=f.id JOIN verification_attempt_details d ON d.verification_id=v.id JOIN jobs j ON j.id=v.job_id JOIN job_terminal_receipts r ON r.job_id=j.id JOIN job_terminal_payloads p ON p.job_id=j.id WHERE f.id=?1 AND f.state='confirmed' AND v.verdict='confirmed' AND j.state='succeeded' AND j.job_capability_hash IS NULL)",[capture.finding],|r|r.get(0))?;
		assert!(committed,"delivery must observe the fully committed verification");
		Ok(())
	}).unwrap();
	capture.calls.lock().unwrap().push(value);
	if capture.fail.load(Ordering::SeqCst) {
		(StatusCode::SERVICE_UNAVAILABLE, Json(json!({"message":"local injected failure"})))
	} else {
		(
			StatusCode::CREATED,
			Json(json!({"number":7,"html_url":"https://example.invalid/issues/7"})),
		)
	}
}
pub async fn configure(state: &mut AppState, finding: i64) -> Stub {
	let capture = Capture {
		calls: Arc::new(Mutex::new(Vec::new())),
		fail: Arc::new(AtomicBool::new(false)),
		db: state.db.clone(),
		finding,
	};
	let app = Router::new()
		.route("/repos/{owner}/{repo}/issues", post(issue))
		.route(
			"/repos/{owner}/{repo}/labels",
			post(|Json(value): Json<Value>| async move { (StatusCode::CREATED, Json(value)) }),
		)
		.with_state(capture.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	state.github_reporter = Arc::new(
		super::server::reporters::GithubReporter::with_base(&format!("http://{addr}")).unwrap(),
	);
	state
		.db
		.with_conn(|conn| {
			let secret = secrets::insert(
				conn,
				secrets::SecretKind::GithubPat,
				"local test",
				b"ghp_test",
				0,
			)?;
			repos::update_reporting(
				conn,
				1,
				&ReportingDestination::GithubIssue {
					target_owner: "owner".into(),
					target_repo: "repo".into(),
					pat_secret_id: secret,
				},
			)?;
			Ok(())
		})
		.unwrap();
	Stub { capture, task }
}
pub async fn admin(state: &AppState, finding: i64, action: &str) -> StatusCode {
	let certificate = state.ca.mint_client(&format!("admin-{action}")).unwrap();
	let peer = PeerCert(
		rustls_pemfile::certs(&mut certificate.cert_pem.as_bytes()).next().unwrap().unwrap(),
	);
	state
		.db
		.with_conn(|conn| {
			workers::insert(
				conn,
				&format!("admin-{action}"),
				workers::WorkerKind::Admin,
				&loupe_tls::cert_fingerprint(peer.0.as_ref()),
				0,
			)?;
			Ok(())
		})
		.unwrap();
	let mut request = Request::post(format!("/v1/findings/{finding}/{action}"))
		.header(loupe_proto::PROTOCOL_VERSION_HEADER, "3")
		.body(Body::empty())
		.unwrap();
	request.extensions_mut().insert(peer);
	router(state.clone()).call(request).await.unwrap().status()
}
