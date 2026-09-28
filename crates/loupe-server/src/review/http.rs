//! Shared phase transport boundaries. Serialize the bounded response before
//! committing the same transaction that granted authority or changed state.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use loupe_core::JobKind;
use loupe_proto::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use loupe_storage::Db;
use rusqlite::{Transaction, TransactionBehavior};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::authority::{self, Access, Authorized};
use crate::auth::AuthedWorker;

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug)]
pub struct ApiError {
	status: StatusCode,
	code: &'static str,
	detail: Option<String>,
	current_revision: Option<i64>,
}
impl ApiError {
	pub fn new(status: StatusCode, code: &'static str) -> Self {
		Self { status, code, detail: None, current_revision: None }
	}
	pub fn denied() -> Self {
		Self::new(StatusCode::FORBIDDEN, "denied")
	}
	pub fn conflict(code: &'static str) -> Self {
		Self::new(StatusCode::CONFLICT, code)
	}
	/// Only after entry scope authorization; never disclose an unscoped revision.
	pub fn inventory_revision_conflict(current_revision: i64) -> Self {
		Self {
			current_revision: Some(current_revision),
			..Self::conflict("inventory_revision_conflict")
		}
	}
	pub fn invalid(detail: impl std::fmt::Display) -> Self {
		Self {
			status: StatusCode::BAD_REQUEST,
			code: "invalid_request",
			// JSON escaping can expand every scalar: this keeps errors below 4 KiB.
			detail: Some(detail.to_string().chars().take(256).collect()),
			current_revision: None,
		}
	}
}
impl From<loupe_storage::Error> for ApiError {
	fn from(error: loupe_storage::Error) -> Self {
		use loupe_storage::{Conflict, Error};
		match error {
			Error::Ownership(_) | Error::NotFound(_, _) => Self::denied(),
			Error::Conflict(Conflict::Checkpoint) => Self::conflict("checkpoint_conflict"),
			Error::Conflict(Conflict::InventoryLimit) => Self::conflict("inventory_limit"),
			Error::Conflict(Conflict::CheckpointLimit) => Self::conflict("checkpoint_limit"),
			Error::Conflict(Conflict::CampaignPinned) => Self::conflict("checkout_conflict"),
			Error::Conflict(_) => Self::conflict("state_conflict"),
			Error::Validation(error) => Self::invalid(error),
			Error::ReviewPayload(error) => Self::invalid(error),
			Error::UnknownPaths(_) => Self::invalid("source outside pinned inventory"),
			error => {
				tracing::error!(error = %error, "phase transaction failed");
				Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
			},
		}
	}
}
impl From<rusqlite::Error> for ApiError {
	fn from(error: rusqlite::Error) -> Self {
		loupe_storage::Error::from(error).into()
	}
}
impl IntoResponse for ApiError {
	fn into_response(self) -> Response {
		let mut error = serde_json::json!({"code":self.code,"detail":self.detail});
		if let Some(revision) = self.current_revision {
			error["current_revision"] = serde_json::json!(revision);
		}
		let mut response = (
			self.status,
			axum::Json(serde_json::json!({
				"protocol_version": PROTOCOL_VERSION,
				"error": error
			})),
		)
			.into_response();
		response.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
		response
	}
}

pub fn require_version(headers: &HeaderMap) -> Result<()> {
	let mut versions = headers.get_all(PROTOCOL_VERSION_HEADER).iter();
	let valid = versions.next().is_some_and(|value| {
		value.to_str().ok().and_then(|raw| raw.parse::<u16>().ok()) == Some(PROTOCOL_VERSION)
	});
	if !valid || versions.next().is_some() {
		return Err(ApiError::invalid("one exact X-Loupe-Protocol header is required"));
	}
	Ok(())
}

/// Use the registered matched path, not arbitrary URI suffixes. The outer
/// boundary must include role middleware and extractor rejections too.
pub fn is_phase_route(path: &str) -> bool {
	matches!(
		path,
		"/v1/jobs/{id}/pin-target"
			| "/v1/jobs/{id}/inventory-batches"
			| "/v1/jobs/{id}/seal-inventory"
			| "/v1/jobs/{id}/publish-profile"
			| "/v1/jobs/{id}/inventory-dispositions"
			| "/v1/jobs/{id}/limits"
			| "/v1/jobs/{id}/lead-candidates"
	)
}

pub async fn bound_phase_errors(response: Response) -> Response {
	if !response.status().is_client_error() && !response.status().is_server_error() {
		return response;
	}
	let (mut parts, body) = response.into_parts();
	let json = parts
		.headers
		.get(header::CONTENT_TYPE)
		.is_some_and(|value| value.as_bytes() == b"application/json");
	if json && let Ok(bytes) = to_bytes(body, 4096).await {
		parts.headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
		return Response::from_parts(parts, Body::from(bytes));
	}
	// Never echo an extractor's arbitrary-size untrusted path or middleware
	// text. Preserve its status, with the same bounded structured vocabulary.
	let code = match parts.status {
		StatusCode::UNAUTHORIZED => "unauthenticated",
		StatusCode::FORBIDDEN => "denied",
		StatusCode::NOT_FOUND => "not_found",
		StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
		StatusCode::PAYLOAD_TOO_LARGE => "request_too_large",
		StatusCode::BAD_REQUEST => "invalid_request",
		_ => "request_failed",
	};
	ApiError::new(parts.status, code).into_response()
}

pub async fn json<T: DeserializeOwned>(
	headers: &HeaderMap, body: Body, max_bytes: usize,
) -> Result<T> {
	require_version(headers)?;
	if headers.get_all(header::CONTENT_ENCODING).iter().any(|value| value.as_bytes() != b"identity")
	{
		return Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "content_encoding"));
	}
	if !headers.get(header::CONTENT_TYPE).is_some_and(|value| {
		value.to_str().is_ok_and(|raw| {
			raw.split(';').next().is_some_and(|mime| mime.trim() == "application/json")
		})
	}) {
		return Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "content_type"));
	}
	let bytes = to_bytes(body, max_bytes)
		.await
		.map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large"))?;
	serde_json::from_slice(&bytes).map_err(ApiError::invalid)
}

pub async fn no_body(headers: &HeaderMap, body: Body) -> Result<()> {
	require_version(headers)?;
	if headers.get_all(header::CONTENT_ENCODING).iter().any(|value| value.as_bytes() != b"identity")
	{
		return Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "content_encoding"));
	}
	to_bytes(body, 0).await.map_err(|_| ApiError::invalid("this operation has no request body"))?;
	Ok(())
}

pub fn authorize<'tx, 'conn>(
	tx: &'tx Transaction<'conn>, worker: &AuthedWorker, headers: &HeaderMap, job: i64,
	phases: &[JobKind], access: Access, now: i64,
) -> Result<Authorized<'tx, 'conn>> {
	for phase in phases {
		if let Some(scope) =
			authority::authorize(tx, worker, headers, job, phase.clone(), access, now)?
		{
			return Ok(scope);
		}
	}
	Err(ApiError::denied())
}

struct BoundedBody {
	bytes: Vec<u8>,
	limit: usize,
}
impl Write for BoundedBody {
	fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
		if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
			return Err(std::io::Error::other("phase response exceeds its byte limit"));
		}
		self.bytes.extend_from_slice(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

/// The result is serialized under the write lock. A response overflow or any
/// operation error drops the uncommitted transaction, including prior writes.
pub fn transaction<T: Serialize>(
	db: &Db, response_limit: usize, body: impl FnOnce(&Transaction<'_>, i64) -> Result<T>,
) -> Result<Response> {
	db.with_conn(|conn| {
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
		let outcome = (|| {
			let value = body(&tx, now)?;
			let mut output = BoundedBody { bytes: Vec::new(), limit: response_limit };
			serde_json::to_writer(&mut output, &value).map_err(|_| {
				ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "response_too_large")
			})?;
			Ok(output.bytes)
		})();
		match outcome {
			Ok(bytes) => {
				tx.commit()?;
				Ok(Ok((
					[
						(header::CONTENT_TYPE, "application/json"),
						(header::CACHE_CONTROL, "no-store"),
					],
					bytes,
				)
					.into_response()))
			},
			Err(error) => Ok(Err(error)),
		}
	})
	.map_err(ApiError::from)?
}

#[cfg(test)]
mod tests {
	use loupe_proto::review_api::SealInventoryRequest;

	use super::*;

	fn headers() -> HeaderMap {
		let mut headers = HeaderMap::new();
		headers.insert(PROTOCOL_VERSION_HEADER, "3".parse().unwrap());
		headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
		headers
	}

	#[tokio::test]
	async fn limits_count_actual_bytes_without_a_content_length() {
		let headers = headers();
		let body = " ".repeat(2048) + r#"{"protocol_version":3}"#;
		let err = json::<SealInventoryRequest>(&headers, Body::from(body), 2048).await.unwrap_err();
		assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
		assert!(json::<SealInventoryRequest>(
			&headers,
			Body::from(r#"{"protocol_version":3}"#),
			2048
		)
		.await
		.is_ok());
	}

	#[tokio::test]
	async fn phase_transport_rejects_missing_version_and_encoded_bodies() {
		let mut headers = headers();
		headers.remove(PROTOCOL_VERSION_HEADER);
		assert!(require_version(&headers).is_err());
		headers.insert(PROTOCOL_VERSION_HEADER, "3".parse().unwrap());
		headers.append(PROTOCOL_VERSION_HEADER, "3".parse().unwrap());
		assert!(require_version(&headers).is_err());
		headers.insert(PROTOCOL_VERSION_HEADER, "3".parse().unwrap());
		headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
		assert_eq!(
			json::<SealInventoryRequest>(&headers, Body::empty(), 2048).await.unwrap_err().status,
			StatusCode::UNSUPPORTED_MEDIA_TYPE
		);
	}

	#[test]
	fn response_overflow_and_callback_error_roll_back_writes() {
		let db = Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap();
		for fail_callback in [false, true] {
			let result = transaction(&db, 4, |tx, _| {
				tx.execute("UPDATE scheduler_clock SET seq=seq+1 WHERE singleton=1", [])?;
				if fail_callback {
					return Err(ApiError::conflict("injected"));
				}
				Ok("too large")
			});
			assert!(result.is_err());
			let seq: i64 = db
				.with_conn(|conn| {
					Ok(conn.query_row("SELECT seq FROM scheduler_clock", [], |row| row.get(0))?)
				})
				.unwrap();
			assert_eq!(seq, 0, "failed responses must not commit prior mutations");
		}
	}
}
