//! Independent disposition updates. Scope, CAS, mappings and durable replay
//! share the same transaction; a stale entry never rolls back other entries.
use axum::extract::{Path, Request, State};
use axum::response::Response;
use axum::Extension;
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_core::JobKind;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_inventory::{
	Disposition, InventoryDispositionRequest, InventoryDispositionResponse,
};
use loupe_storage::checkpoints::{self, Operation, Recorded};
use loupe_storage::{inventory, inventory_disposition as stored};

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
	let request: InventoryDispositionRequest = http::json(&headers, body, 8192).await?;
	let digest = request.digest().map_err(ApiError::invalid)?;
	http::transaction(&state.db, 8192, |tx, now| {
		let scope =
			http::authorize(tx, &worker, &headers, job, &[JobKind::Survey], Access::Domain, now)?;
		let op = Operation::SubmitInventoryDisposition;
		let key = &request.client_inventory_disposition_key;
		// Explicit equivalent of checkpoints::run: the fresh body needs typed
		// HTTP scope/revision errors. Lookup MUST precede every mutable guard;
		// only the original numeric response is stored as generic bounded JSON.
		if let Some(response) = checkpoints::lookup(tx, job, op, key, &digest)? {
			return serde_json::from_str::<InventoryDispositionResponse>(response.expose())
				.map_err(ApiError::invalid);
		}
		let generation = scope.job().generation_id.ok_or_else(ApiError::denied)?;
		let entry =
			stored::resolve(tx, job, generation, scope.is_bootstrap(), &request.source_path)?
				.ok_or_else(ApiError::denied)?;
		if entry.revision() != request.expected_revision {
			return Err(ApiError::inventory_revision_conflict(entry.revision()));
		}
		let mut mappings = Vec::with_capacity(request.mappings.as_slice().len());
		for mapping in request.mappings.as_slice() {
			let unit_id = i64::from(mapping.review_unit_id);
			let assignment_epoch =
				i64::try_from(mapping.assignment_epoch).map_err(ApiError::invalid)?;
			if !scope.survey_unit_reference(unit_id, assignment_epoch)? {
				return Err(ApiError::denied());
			}
			mappings.push(stored::Mapping { unit_id, assignment_epoch });
		}
		if checkpoints::accepted_count(tx, job, op)? >= stored::MAX_OPERATIONS {
			return Err(ApiError::conflict("checkpoint_limit"));
		}
		let reason = request
			.reason
			.as_ref()
			.map(|reason| BoundedText::new(reason.expose()))
			.transpose()
			.map_err(ApiError::invalid)?;
		let disposition = match request.disposition {
			Disposition::Mapped => inventory::Disposition::Mapped,
			Disposition::Context => inventory::Disposition::Context,
			Disposition::Excluded => inventory::Disposition::Excluded,
			Disposition::Unresolved => inventory::Disposition::Unresolved,
		};
		let revision = stored::replace(
			tx,
			&entry,
			&stored::Update {
				expected_revision: request.expected_revision,
				disposition,
				reason: reason.as_ref(),
				mappings: &mappings,
			},
		)?;
		let response = InventoryDispositionResponse {
			protocol_version: ReviewProtocol,
			inventory_entry_id: entry.id().try_into().map_err(ApiError::invalid)?,
			revision: revision.try_into().map_err(ApiError::invalid)?,
		};
		let canonical =
			BoundedJson::new(&serde_json::to_string(&response).map_err(ApiError::invalid)?)
				.map_err(ApiError::invalid)?;
		if checkpoints::record_or_replay(tx, job, op, key, &digest, &canonical, now)?
			!= Recorded::Recorded
		{
			return Err(ApiError::conflict("checkpoint_conflict"));
		}
		Ok(response)
	})
}
