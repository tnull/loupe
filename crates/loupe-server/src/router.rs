use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::http::{HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::Router;
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::rt::TokioIo;
use loupe_proto::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use tower::Service;

use crate::state::AppState;
use crate::{auth, routes, tls, Config};

/// Request extension carrying the peer's leaf certificate (DER bytes), if
/// the connection presented one. The auth middleware (added in a later
/// commit) reads this to identify the worker; route handlers should not
/// touch it directly.
#[derive(Debug, Clone)]
pub struct PeerCert(pub CertificateDer<'static>);

/// Build the axum `Router` for the server. Pure function — exposed so
/// integration tests can mount it without spinning up TLS.
pub fn router(state: AppState) -> Router {
	let admin_only = Router::new()
		.route("/v1/repos", post(routes::repos::create).get(routes::repos::list))
		.route("/v1/repos/{id}", delete(routes::repos::delete).patch(routes::repos::update))
		.route("/v1/repos/{id}/reporting/github-pat", post(routes::repos::rotate_github_pat))
		.route("/v1/repos/{id}/reporting/github", put(routes::repos::set_github_reporting))
		.route("/v1/repos/{id}/scan", post(routes::jobs::enqueue_scan))
		.route("/v1/repos/{id}/findings", get(routes::findings_admin::list_for_repo))
		.route("/v1/findings/retry-verify", post(routes::findings_admin::retry_verify))
		.route("/v1/findings/{id}/approve", post(routes::findings_admin::approve))
		.route("/v1/findings/{id}/retry-report", post(routes::findings_admin::retry_report))
		.route("/v1/findings/{id}/reject", post(routes::findings_admin::reject))
		.route("/v1/workers", post(routes::workers::create))
		.route("/v1/workers/{id}", delete(routes::workers::revoke))
		.route("/v1/jobs", get(routes::jobs::list))
		.route("/v1/jobs/{id}", get(routes::jobs::get))
		.route("/v1/jobs/{id}/retry", post(routes::jobs::retry))
		.route("/v1/jobs/{id}/cancel", post(routes::review_lifecycle::cancel))
		.route("/v1/review-generations/{id}/reset", post(routes::review_compatibility::reset))
		.route_layer(axum::middleware::from_fn(auth::require_admin));

	let worker_only = Router::new()
		.route("/v1/jobs/lease", post(routes::jobs::lease))
		.route("/v1/jobs/{id}/heartbeat", post(routes::review_lifecycle::heartbeat))
		.route("/v1/jobs/{id}/findings", post(routes::jobs::submit_findings))
		.route("/v1/jobs/{id}/llm-findings", post(routes::jobs::submit_llm_finding))
		.route("/v1/jobs/{id}/verdict", post(routes::jobs::submit_verdict))
		.route("/v1/jobs/{id}/complete", post(routes::review_lifecycle::complete))
		.route("/v1/jobs/{id}/pin-target", post(routes::review_host::pin_target))
		.route("/v1/jobs/{id}/inventory-batches", post(routes::review_host::inventory_batch))
		.route("/v1/jobs/{id}/seal-inventory", post(routes::review_host::seal_inventory))
		.route("/v1/jobs/{id}/publish-profile", post(routes::review_host::publish_profile))
		.route("/v1/jobs/{id}/inventory-dispositions", post(routes::review_inventory::submit))
		.route("/v1/jobs/{id}/review-units", post(routes::review_units::submit))
		.route("/v1/jobs/{id}/leads", post(routes::review_evidence::submit_lead))
		.route("/v1/jobs/{id}/sibling-leads", post(routes::review_evidence::submit_sibling_lead))
		.route(
			"/v1/jobs/{id}/review-unit-results",
			post(routes::review_evidence::submit_unit_result),
		)
		.route("/v1/jobs/{id}/finalize-survey", post(routes::review_survey::finalize))
		.route("/v1/jobs/{id}/finalize-drilldown", post(routes::review_drilldown::finalize))
		.route("/v1/jobs/{id}/finalize-verification", post(routes::review_verification::finalize))
		.route("/v1/jobs/{id}/limits", get(routes::review_context::limits))
		.route("/v1/jobs/{id}/lead-candidates", get(routes::review_context::candidates))
		.route_layer(axum::middleware::from_fn(auth::require_worker));

	let authed = Router::new()
		.merge(admin_only)
		.merge(worker_only)
		.route("/v1/whoami", get(routes::whoami::get))
		// Admins can inspect findings directly. Workers reach these
		// through the MCP tools (`query_prior_findings` /
		// `get_finding_by_id`) and the handlers enforce an active
		// lease for the requested repo before returning finding data.
		.route("/v1/repos/{id}/findings/search", get(routes::findings_admin::search))
		.route("/v1/findings/{id}", get(routes::findings_admin::get))
		.route_layer(axum::middleware::from_fn_with_state(state.clone(), auth::mtls_auth));

	Router::new()
		.route("/v1/health", get(routes::health::get))
		.merge(authed)
		.with_state(state)
		.layer(axum::middleware::from_fn(
			|req: axum::extract::Request, next: axum::middleware::Next| async move {
				let control =
					req.extensions().get::<axum::extract::MatchedPath>().is_some_and(|path| {
						matches!(
							path.as_str(),
							"/v1/jobs/{id}/complete" | "/v1/jobs/{id}/heartbeat" | "/v1/jobs/lease"
						)
					});
				let phase = req
					.extensions()
					.get::<axum::extract::MatchedPath>()
					.is_some_and(|path| crate::review::http::is_phase_route(path.as_str()));
				if phase {
					let response = match crate::review::http::require_version(req.headers()) {
						Ok(()) => next.run(req).await,
						Err(error) => error.into_response(),
					};
					let mut response = crate::review::http::bound_phase_errors(response).await;
					response.headers_mut().insert(
						PROTOCOL_VERSION_HEADER,
						PROTOCOL_VERSION.to_string().parse().expect("u16 header"),
					);
					return response;
				}
				if let Some(msg) =
					request_protocol_error(req.headers().get(PROTOCOL_VERSION_HEADER))
				{
					let mut resp = (StatusCode::BAD_REQUEST, msg).into_response();
					if control {
						resp = crate::review::http::bound_control_errors(resp).await;
					}
					resp.headers_mut().insert(
						PROTOCOL_VERSION_HEADER,
						PROTOCOL_VERSION.to_string().parse().expect("u16 parses as header value"),
					);
					return resp;
				}
				let mut resp = next.run(req).await;
				if control {
					resp = crate::review::http::bound_control_errors(resp).await;
				}
				resp.headers_mut().insert(
					PROTOCOL_VERSION_HEADER,
					PROTOCOL_VERSION.to_string().parse().expect("u16 parses as header value"),
				);
				resp
			},
		))
}

fn request_protocol_error(value: Option<&HeaderValue>) -> Option<String> {
	let value = value?;
	let raw = match value.to_str() {
		Ok(v) => v,
		Err(_) => return Some(format!("{PROTOCOL_VERSION_HEADER} must be valid ASCII")),
	};
	match raw.parse::<u16>() {
		Ok(PROTOCOL_VERSION) => None,
		Ok(other) => Some(format!("unsupported {PROTOCOL_VERSION_HEADER} {other}")),
		Err(_) => Some(format!("{PROTOCOL_VERSION_HEADER} must be an integer")),
	}
}

/// Handle returned by [`serve`]. Drop or call `shutdown` to stop the
/// server. The handle owns the http listener task plus the scheduler
/// and reaper background tasks.
pub struct ServeHandle {
	pub local_addr: SocketAddr,
	shutdown_tx: Option<oneshot::Sender<()>>,
	cancel: tokio_util::sync::CancellationToken,
	http_join: Option<tokio::task::JoinHandle<()>>,
	bg_joins: Vec<tokio::task::JoinHandle<()>>,
}

impl ServeHandle {
	pub async fn shutdown(mut self) {
		if let Some(tx) = self.shutdown_tx.take() {
			let _ = tx.send(());
		}
		self.cancel.cancel();
		if let Some(join) = self.http_join.take() {
			let _ = join.await;
		}
		for j in self.bg_joins.drain(..) {
			let _ = j.await;
		}
	}
}

/// Bind to `cfg.bind_addr` and serve over mTLS. Returns once the listener
/// is bound so callers can read `local_addr` synchronously. Spawns the
/// scheduler + reaper alongside the listener; both shut down with the
/// handle.
pub async fn serve(cfg: Config, state: AppState) -> Result<ServeHandle> {
	let rustls_cfg = tls::build(&cfg)?;
	let acceptor = TlsAcceptor::from(Arc::new(rustls_cfg));
	let listener = TcpListener::bind(cfg.bind_addr).await.context("binding loupe-server")?;
	let local_addr = listener.local_addr().context("local_addr on bound listener")?;
	let db = state.db.clone();
	let job_arrived = state.job_arrived.clone();
	let app = router(state);

	let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
	let http_join = tokio::spawn(serve_loop(listener, acceptor, app, shutdown_rx));

	let cancel = tokio_util::sync::CancellationToken::new();
	let bg_joins = vec![
		crate::background::spawn_scheduler(db.clone(), job_arrived, cancel.clone()),
		crate::background::spawn_reaper(db, cancel.clone()),
	];

	Ok(ServeHandle {
		local_addr,
		shutdown_tx: Some(shutdown_tx),
		cancel,
		http_join: Some(http_join),
		bg_joins,
	})
}

async fn serve_loop(
	listener: TcpListener, acceptor: TlsAcceptor, app: Router,
	mut shutdown_rx: oneshot::Receiver<()>,
) {
	loop {
		tokio::select! {
			biased;
			_ = &mut shutdown_rx => {
				tracing::debug!("loupe-server: shutdown signal received");
				return;
			}
			res = listener.accept() => {
				match res {
					Ok((sock, peer_addr)) => {
						tokio::spawn(handle_connection(acceptor.clone(), sock, peer_addr, app.clone()));
					}
					Err(e) => {
						tracing::warn!(error = %e, "accept failed");
					}
				}
			}
		}
	}
}

async fn handle_connection(
	acceptor: TlsAcceptor, sock: tokio::net::TcpStream, peer_addr: SocketAddr, app: Router,
) {
	let tls_stream = match acceptor.accept(sock).await {
		Ok(s) => s,
		Err(e) => {
			// Log loudly: in mTLS the handshake failing usually means
			// either a stale CA on one side after a rotation, a worker
			// connecting before its cert is registered, or a port
			// scanner — all worth surfacing at info+. At debug level
			// these were invisible by default and the operator had no
			// way to know why their workers couldn't connect.
			tracing::error!(peer = %peer_addr, error = %e, "tls handshake failed");
			return;
		},
	};

	let peer_cert = tls_stream
		.get_ref()
		.1
		.peer_certificates()
		.and_then(|certs| certs.first())
		.map(|c| PeerCert(c.clone().into_owned()));

	let io = TokioIo::new(tls_stream);

	// Wrap the axum service in a per-connection layer that injects the
	// peer cert into request extensions before the router dispatches.
	let svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
		if let Some(cert) = peer_cert.clone() {
			req.extensions_mut().insert(cert);
		}
		let mut app = app.clone();
		async move {
			let resp = match app.call(req).await {
				Ok(r) => r,
				Err(e) => match e {},
			};
			Ok::<_, std::convert::Infallible>(resp)
		}
	});

	if let Err(e) = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await {
		tracing::debug!(peer = %peer_addr, error = %e, "connection terminated");
	}
}
