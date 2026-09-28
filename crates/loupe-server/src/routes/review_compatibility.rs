use axum::extract::{Path, Request, State};
use axum::response::Response;
use axum::Extension;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_compatibility::{ResetGenerationRequest, ResetGenerationResponse};

use crate::auth::AuthedWorker;
use crate::review::http::{self, ApiError};
use crate::AppState;

pub async fn reset(
	State(state): State<AppState>, Path(generation): Path<i64>,
	Extension(admin): Extension<AuthedWorker>, request: Request,
) -> http::Result<Response> {
	let (parts, body) = request.into_parts();
	let _: ResetGenerationRequest = http::json(&parts.headers, body, 8192).await?;
	http::transaction(&state.db, 4096, |tx, now| {
		// Middleware resolved the certificate before locking. Recheck its role
		// and revocation under the same lock as this destructive admin action.
		if !tx.query_row("SELECT EXISTS(SELECT 1 FROM workers WHERE id=?1 AND kind='admin' AND revoked_at IS NULL)",[admin.id()],|r|r.get::<_,bool>(0))? {
			return Err(ApiError::denied());
		}
		let reset = loupe_storage::review_compatibility::reset(tx, generation, now)?;
		Ok(ResetGenerationResponse {
			protocol_version: ReviewProtocol,
			inventory_entries_removed: reset.inventory_entries_removed,
			review_units_removed: reset.review_units_removed,
			leads_removed: reset.leads_removed,
			verification_intents_blocked: reset.verification_intents_blocked,
		})
	})
}
