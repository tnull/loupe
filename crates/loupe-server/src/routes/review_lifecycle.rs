//! Shared lifecycle dispatch observes exact lease identity, never a bare job ID.
//! This preliminary read only chooses transport; mutation reauthorizes inside
//! its immediate transaction after capturing the current time.
use axum::extract::{Path, Request, State};
use axum::handler::Handler;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use loupe_core::text::BoundedText;
use loupe_core::JobKind;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_lifecycle::{
	PhaseControlResponse, PhaseControlState, PhaseFailureRequest, PhaseHeartbeatRequest,
};
use loupe_proto::{HeartbeatResponse, PROTOCOL_VERSION};
use loupe_storage::{phase_lifecycle, scheduler};
use rusqlite::params;

use crate::auth::AuthedWorker;
use crate::review::authority::Access;
use crate::review::http::{self, ApiError};
use crate::{job_capability, AppState};

fn phase_lease(
	state: &AppState, worker: &AuthedWorker, headers: &HeaderMap, job: i64,
) -> http::Result<bool> {
	let Ok(hash) = job_capability::parse_hash(headers) else { return Ok(false) };
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs() as i64;
	Ok(state.db.with_conn(|conn| Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM jobs j JOIN workers w ON w.id=j.worker_id WHERE j.id=?1 AND j.worker_id=?2 AND j.job_capability_hash=?3 AND j.state='leased' AND j.lease_expires_at>?4 AND j.campaign_id IS NOT NULL AND j.kind IN('survey','drilldown','verify') AND w.kind='worker' AND w.revoked_at IS NULL)",params![job,worker.id(),hash.as_slice(),now],|r|r.get(0))?))?)
}
const PHASES: &[JobKind] = &[JobKind::Survey, JobKind::Drilldown, JobKind::Verify];

pub async fn complete(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, request: Request,
) -> Response {
	match phase_lease(&state, &worker, request.headers(), job) {
		Ok(true) => failure(state, worker, job, request).await.into_response(),
		Ok(false) => super::jobs::complete.call(request, state).await,
		Err(error) => error.into_response(),
	}
}
async fn failure(
	state: AppState, worker: AuthedWorker, job: i64, request: Request,
) -> http::Result<Response> {
	let (parts, body) = request.into_parts();
	let request: PhaseFailureRequest = http::json(&parts.headers, body, 8192).await?;
	let error = request
		.error
		.unwrap_or(BoundedText::new("phase execution failed").map_err(ApiError::invalid)?);
	let response = http::transaction(&state.db, 8192, |tx, now| {
		http::authorize(tx, &worker, &parts.headers, job, PHASES, Access::LeaseControl, now)?;
		let outcome = scheduler::retry_or_fail(tx, job, now, &error)?;
		let (state, eligible_at) = match outcome {
			scheduler::RetryOutcome::Failed => (PhaseControlState::Failed, None),
			scheduler::RetryOutcome::Requeued { eligible_at } => {
				(PhaseControlState::Queued, Some(eligible_at))
			},
		};
		Ok(PhaseControlResponse {
			protocol_version: ReviewProtocol,
			job_id: job.try_into().map_err(ApiError::invalid)?,
			state,
			eligible_at,
		})
	})?;
	state.job_arrived.notify_waiters();
	Ok(response)
}
pub async fn heartbeat(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, request: Request,
) -> Response {
	match phase_lease(&state, &worker, request.headers(), job) {
		Ok(true) => phase_heartbeat(state, worker, job, request).await.into_response(),
		Ok(false) => super::jobs::heartbeat.call(request, state).await,
		Err(error) => error.into_response(),
	}
}
async fn phase_heartbeat(
	state: AppState, worker: AuthedWorker, job: i64, request: Request,
) -> http::Result<Response> {
	let (parts, body) = request.into_parts();
	let _: PhaseHeartbeatRequest = http::json(&parts.headers, body, 8192).await?;
	http::transaction(&state.db, 8192, |tx, now| {
		http::authorize(tx, &worker, &parts.headers, job, PHASES, Access::LeaseControl, now)?;
		let lease_expires_at = phase_lifecycle::heartbeat(
			tx,
			job,
			now,
			state.review_policy.lease_seconds,
			state.review_policy.lease_report_grace_seconds,
		)?;
		Ok(HeartbeatResponse { protocol_version: PROTOCOL_VERSION, lease_expires_at })
	})
}

/// Admins may inspect target identity; workers never use this dispatch path.
pub async fn cancel(
	State(state): State<AppState>, Path(job): Path<i64>, request: Request,
) -> Response {
	let phase=state.db.with_conn(|conn|Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND campaign_id IS NOT NULL AND kind IN('survey','drilldown','verify'))",[job],|r|r.get::<_,bool>(0))?));
	match phase {
		Ok(false) => super::jobs::cancel.call(request, state).await,
		Err(error) => ApiError::from(error).into_response(),
		Ok(true) => http::transaction(&state.db, 8192, |tx, now| {
			phase_lifecycle::cancel(tx, job, now)?;
			Ok(PhaseControlResponse {
				protocol_version: ReviewProtocol,
				job_id: job.try_into().map_err(ApiError::invalid)?,
				state: PhaseControlState::Cancelled,
				eligible_at: None,
			})
		})
		.into_response(),
	}
}
