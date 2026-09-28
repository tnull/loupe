//! Job-scoped, replayable scope proposals. Creating a unit does not assign it.
use axum::extract::{Path, Request, State};
use axum::response::Response;
use axum::Extension;
use loupe_core::text::{BoundedJson, BoundedText, Identifier};
use loupe_core::JobKind;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_units::{PriorityBand, ReviewUnitRequest, ReviewUnitResponse};
use loupe_storage::checkpoints::{self, Operation, Recorded};
use loupe_storage::source_refs::UnitRefs;
use loupe_storage::{admission, review_units};
use rusqlite::{params, OptionalExtension};

use crate::auth::AuthedWorker;
use crate::review::authority::Access;
use crate::review::http::{self, ApiError};
use crate::AppState;

pub async fn submit(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, request: Request,
) -> http::Result<Response> {
	let (parts, body) = request.into_parts();
	let headers = parts.headers;
	let request: ReviewUnitRequest = http::json(&headers, body, 256 * 1024).await?;
	request.validate().map_err(ApiError::invalid)?;
	let digest = request.digest().map_err(ApiError::invalid)?;
	http::transaction(&state.db, 8192, |tx, now| {
		let scope =
			http::authorize(tx, &worker, &headers, job, &[JobKind::Survey], Access::Domain, now)?;
		let operation = Operation::SubmitReviewUnit;
		let key = &request.client_review_unit_key;
		if let Some(response) = checkpoints::lookup(tx, job, operation, key, &digest)? {
			return serde_json::from_str::<ReviewUnitResponse>(response.expose())
				.map_err(ApiError::invalid);
		}
		let generation = scope.job().generation_id.ok_or_else(ApiError::denied)?;
		for id in request.depends_on_review_unit_ids.as_slice() {
			let id = i64::from(*id);
			// Read only scoped numeric metadata before consulting reference
			// authority; never decode a foreign unit's potentially damaged prose.
			let epoch: Option<i64> = tx.query_row(
				"SELECT u.assignment_epoch FROM review_units u WHERE u.review_unit_id=?1 AND u.generation_id=?2 AND ((?4 AND u.created_by_job_id=?3) OR EXISTS(SELECT 1 FROM job_assigned_review_units a WHERE a.job_id=?3 AND a.review_unit_id=u.review_unit_id AND a.assignment_epoch=u.assignment_epoch))",
				params![id,generation,job,scope.is_bootstrap()], |row| row.get(0)).optional()?;
			if !match epoch {
				Some(epoch) => scope.survey_unit_reference(id, epoch)?,
				None => false,
			} {
				return Err(ApiError::denied());
			}
		}
		let policy = admission::load_policy(tx, scope.job().campaign_id)?;
		if checkpoints::accepted_count(tx, job, operation)?
			>= i64::from(policy.max_units_per_survey)
		{
			return Err(ApiError::conflict("checkpoint_limit"));
		}
		let refs =
			UnitRefs::new(request.source_refs.as_slice().to_vec()).map_err(ApiError::invalid)?;
		let storage_key =
			Identifier::new(&format!("j{job}.{}", blake3::hash(key.expose().as_bytes()).to_hex()))
				.map_err(ApiError::invalid)?;
		// Generic JSON contains metadata only; authoritative paths stay typed.
		let proposal = BoundedJson::new(&serde_json::json!({"band":request.priority_band,"rationale":request.priority_rationale}).to_string()).map_err(ApiError::invalid)?;
		let dependencies = BoundedJson::new(
			&serde_json::to_string(&request.depends_on_review_unit_ids)
				.map_err(ApiError::invalid)?,
		)
		.map_err(ApiError::invalid)?;
		let closure = request
			.closure_criteria
			.as_ref()
			.map(|value| BoundedText::new(value.expose()))
			.transpose()
			.map_err(ApiError::invalid)?;
		let context = request
			.semantic_context
			.as_ref()
			.map(|value| BoundedJson::new(&serde_json::json!(value).to_string()))
			.transpose()
			.map_err(ApiError::invalid)?;
		let id = review_units::create(
			tx,
			&review_units::NewUnit {
				generation_id: generation,
				client_key: &storage_key,
				title: &request.title,
				objective: &request.objective,
				priority: review_units::Priority::Normal,
				priority_proposal: Some(&proposal),
				source_refs: &refs,
				depends_on: Some(&dependencies),
				closure_criteria: closure.as_ref(),
				semantic_context: context.as_ref(),
				carried_from: None,
				created_by_job: Some(job),
			},
			now,
		)?;
		let response = ReviewUnitResponse {
			protocol_version: ReviewProtocol,
			review_unit_id: id.try_into().map_err(ApiError::invalid)?,
			assignment_epoch: 0,
			accepted_priority_band: PriorityBand::Normal,
		};
		let canonical =
			BoundedJson::new(&serde_json::to_string(&response).map_err(ApiError::invalid)?)
				.map_err(ApiError::invalid)?;
		if checkpoints::record_or_replay(tx, job, operation, key, &digest, &canonical, now)?
			!= Recorded::Recorded
		{
			return Err(ApiError::conflict("checkpoint_conflict"));
		}
		Ok(response)
	})
}
