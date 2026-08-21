#![cfg(unix)]

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use loupe_worker::llm::model_broker::{ModelBrokerContext, ModelBrokerLimits, ModelCredential};
use loupe_worker::llm::{ClaudeCliBackend, LlmBackend, LlmRequest};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct Captured {
	headers: HeaderMap,
	body: Vec<u8>,
}

fn bwrap_present() -> bool {
	std::process::Command::new("bwrap")
		.arg("--version")
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.status()
		.map(|status| status.success())
		.unwrap_or(false)
}

#[tokio::test]
async fn claude_reaches_fake_upstream_only_through_the_broker() {
	use std::os::unix::fs::PermissionsExt;

	if !bwrap_present() {
		eprintln!("skipping: bwrap missing");
		return;
	}
	let worker_binary = PathBuf::from(env!("CARGO_BIN_EXE_loupe-worker"));
	let network_probe = tempfile::tempdir().unwrap();
	if let Err(error) = loupe_worker::sandbox::smoketest_with_supervisor(
		network_probe.path(),
		Default::default(),
		worker_binary.clone(),
	) {
		eprintln!("skipping: isolated sandbox networking unavailable: {error:#}");
		return;
	}

	let captured = Arc::new(Mutex::new(Vec::<Captured>::new()));
	let app = Router::new()
		.route(
			"/v1/messages",
			post(
				|State(captured): State<Arc<Mutex<Vec<Captured>>>>, request: Request| async move {
					let headers = request.headers().clone();
					let body = to_bytes(request.into_body(), 1024 * 1024).await.unwrap().to_vec();
					captured.lock().await.push(Captured { headers, body });
					Response::new(Body::from("BROKERED"))
				},
			),
		)
		.with_state(captured.clone());
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let upstream: reqwest::Url =
		format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
	tokio::spawn(async move {
		axum::serve(listener, app).await.unwrap();
	});

	let scratch = tempfile::tempdir().unwrap();
	let workdir = tempfile::tempdir().unwrap();
	let fake_claude = scratch.path().join("fake-claude");
	std::fs::write(
		&fake_claude,
		"#!/bin/sh\n\
		if [ -n \"${ANTHROPIC_API_KEY-}\" ] || [ -n \"${CLAUDE_CODE_OAUTH_TOKEN-}\" ]; then\n\
		  echo credential-leaked >&2\n\
		  exit 90\n\
		fi\n\
		if [ \"${ANTHROPIC_AUTH_TOKEN-}\" != \"loupe-brokered\" ]; then\n\
		  echo missing-sentinel >&2\n\
		  exit 91\n\
		fi\n\
		exec /usr/bin/curl --silent --show-error --fail-with-body -X POST \"${ANTHROPIC_BASE_URL}/v1/messages\" -H 'content-type: application/json' -H 'authorization: Bearer loupe-brokered' --data '{\"model\":\"repo-controlled\",\"output_config\":{\"effort\":\"low\"},\"messages\":[],\"max_tokens\":8}'\n",
	)
	.unwrap();
	std::fs::set_permissions(&fake_claude, std::fs::Permissions::from_mode(0o755)).unwrap();

	let context = ModelBrokerContext::new(
		worker_binary,
		upstream,
		ModelCredential::anthropic_api_key("host-anthropic-secret"),
		ModelBrokerLimits::default(),
	);
	let backend = ClaudeCliBackend::with_bin(fake_claude.to_string_lossy())
		.with_model_broker_context(context);
	let response = backend
		.run(LlmRequest {
			prompt: "ignored by fake CLI".into(),
			workdir: workdir.path().to_path_buf(),
			timeout: Duration::from_secs(10),
			cancel: CancellationToken::new(),
			repo_id: None,
			job_id: None,
			job_capability: None,
			finding_id: None,
		})
		.await
		.expect("Claude must run through the real sandbox supervisor and model proxy");
	assert_eq!(response.text, "BROKERED");

	let captured = captured.lock().await;
	assert_eq!(captured.len(), 1);
	assert_eq!(captured[0].headers.get("x-api-key").unwrap(), "host-anthropic-secret");
	assert!(!captured[0].headers.contains_key("authorization"));
	let body: serde_json::Value = serde_json::from_slice(&captured[0].body).unwrap();
	assert_eq!(body["model"], "claude-opus-4-7");
	assert_eq!(body["output_config"]["effort"], "max");
}
