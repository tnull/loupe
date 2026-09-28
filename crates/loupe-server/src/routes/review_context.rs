//! Bounded worker context. Candidate reads durably issue narrowly scoped IDs.
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Uri};
use axum::response::Response;
use axum::Extension;
use loupe_core::review_candidates::CandidateQuery;
use loupe_core::JobKind;
use loupe_proto::review_api::{
	CandidatesResponse, Capacity, PhaseLimitsResponse, ReviewProtocol, TokenCapacity, Unavailable,
	UnknownSpend,
};
use loupe_proto::review_lease::LeaseList;
use loupe_storage::checkpoints::Operation;
use loupe_storage::{admission, checkpoints, duplicate_candidates};

use crate::auth::AuthedWorker;
use crate::review::authority::Access;
use crate::review::http::{self, ApiError};
use crate::AppState;

pub async fn limits(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, headers: HeaderMap, uri: Uri, body: Body,
) -> http::Result<Response> {
	http::no_body(&headers, body).await?;
	if uri.query().is_some_and(|query| !query.is_empty()) {
		return Err(ApiError::invalid("limits has no query parameters"));
	}
	http::transaction(&state.db, 8192, |tx, now| {
		let scope = http::authorize(
			tx,
			&worker,
			&headers,
			job,
			&[JobKind::Survey, JobKind::Drilldown, JobKind::Verify],
			Access::Checkout,
			now,
		)?;
		let policy = admission::load_policy(tx, scope.job().campaign_id)?;
		let spend = admission::get_spending(tx, scope.job().campaign_id)?
			.ok_or_else(|| ApiError::conflict("compatibility_policy"))?;
		admission::choose_pool(&policy, spend, admission::WorkClass::Survey)?;
		let (soft, submit, hard, tokens) = tx.query_row(
			"SELECT soft_deadline_at,submit_by,hard_deadline_at,token_budget FROM jobs WHERE id=?1",
			[job],
			|row| {
				Ok((
					row.get::<_, i64>(0)?,
					row.get::<_, i64>(1)?,
					row.get::<_, i64>(2)?,
					row.get::<_, Option<i64>>(3)?,
				))
			},
		)?;
		if soft > submit || submit > hard || tokens.is_some_and(|value| value <= 0) {
			return Err(ApiError::conflict("invalid_limits"));
		}
		let campaign_deadline: Option<i64> = tx.query_row(
			"SELECT deadline_at FROM review_campaigns WHERE campaign_id=?1",
			[scope.job().campaign_id],
			|row| row.get(0),
		)?;
		// Source authority ends at the first deadline, even for historical
		// leases whose recorded job window extends beyond the campaign.
		let hard = campaign_deadline.map_or(hard, |deadline| deadline.min(hard));
		let submit = submit.min(hard);
		let soft = soft.min(submit);
		let capacity = |operation, limit: u32| -> http::Result<Capacity> {
			let used = checkpoints::accepted_count(tx, job, operation)?;
			let remaining = (i64::from(limit) - used).max(0) as u32;
			Ok(Capacity { limit, remaining })
		};
		Ok(PhaseLimitsResponse {
			protocol_version: ReviewProtocol,
			soft_deadline_at: soft,
			submit_by: submit,
			hard_deadline_at: hard,
			remaining_seconds: hard.saturating_sub(now).max(0) as u64,
			new_units: capacity(
				Operation::SubmitReviewUnit,
				if scope.job().kind == JobKind::Survey { policy.max_units_per_survey } else { 0 },
			)?,
			leads: capacity(
				Operation::SubmitLead,
				if scope.job().kind == JobKind::Survey { policy.max_leads_per_survey } else { 0 },
			)?,
			siblings: capacity(
				Operation::SubmitSiblingLead,
				if scope.job().kind == JobKind::Drilldown {
					policy.max_sibling_leads_per_drilldown
				} else {
					0
				},
			)?,
			candidate_queries: capacity(
				Operation::IssueDuplicateCandidates,
				if scope.job().kind == JobKind::Verify {
					0
				} else {
					duplicate_candidates::QUERY_LIMIT as u32
				},
			)?,
			campaign_jobs_limit: policy.campaign_max_jobs as u64,
			campaign_jobs_admitted: spend.total()? as u64,
			campaign_general_remaining: (policy.general_capacity()? - spend.general) as u64,
			campaign_urgent_remaining: (policy.campaign_urgent_reserve - spend.urgent) as u64,
			campaign_verification_remaining: (policy.campaign_verification_reserve
				- spend.verification) as u64,
			proof_capacity: Unavailable::Unavailable,
			artifact_capacity: Unavailable::Unavailable,
			output_capacity: Unavailable::Unavailable,
			tokens: tokens.map_or(TokenCapacity::None, |limit| TokenCapacity::HostEnforced {
				limit: limit as u64,
				spent: UnknownSpend::Unknown,
			}),
		})
	})
}

pub async fn candidates(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, headers: HeaderMap, uri: Uri, body: Body,
) -> http::Result<Response> {
	http::no_body(&headers, body).await?;
	if uri.query().is_some_and(|query| query.len() > 8192) {
		return Err(ApiError::invalid("query string exceeds 8 KiB"));
	}
	let Query(query) = Query::<CandidateQuery>::try_from_uri(&uri).map_err(ApiError::invalid)?;
	query.validate().map_err(ApiError::invalid)?;
	http::transaction(&state.db, 64 * 1024, |tx, now| {
		let scope = http::authorize(
			tx,
			&worker,
			&headers,
			job,
			&[JobKind::Survey, JobKind::Drilldown],
			Access::Domain,
			now,
		)?;
		Ok(CandidatesResponse {
			protocol_version: ReviewProtocol,
			candidates: LeaseList::new(duplicate_candidates::issue(
				tx,
				job,
				scope.job().repo_id,
				&query,
				now,
			)?)
			.map_err(ApiError::invalid)?,
		})
	})
}
