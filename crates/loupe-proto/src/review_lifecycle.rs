//! Strict phase execution control on shared legacy/phase lifecycle routes.
use loupe_core::text::policy::Reason;
use loupe_core::text::BoundedText;
use serde::{Deserialize, Serialize};

use crate::review_api::ReviewProtocol;
use crate::review_lease::ReviewId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailedOutcome {
	Failed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseFailureRequest {
	pub protocol_version: ReviewProtocol,
	pub outcome: FailedOutcome,
	pub error: Option<BoundedText<Reason>>,
}
/// Phase heartbeat requires this body; legacy heartbeat may still be empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseHeartbeatRequest {
	pub protocol_version: ReviewProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseControlState {
	Queued,
	Failed,
	Cancelled,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseControlResponse {
	pub protocol_version: ReviewProtocol,
	pub job_id: ReviewId,
	pub state: PhaseControlState,
	pub eligible_at: Option<i64>,
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn failure_is_strict_bounded_and_cannot_override_checkout_or_succeed() {
		for raw in [
			r#"{"protocol_version":3,"outcome":"succeeded"}"#,
			r#"{"protocol_version":3,"outcome":"failed","head_sha":null}"#,
			r#"{"protocol_version":3,"outcome":"failed","extra":true}"#,
			r#"{"protocol_version":3,"protocol_version":3,"outcome":"failed"}"#,
			r#"{"protocol_version":2,"outcome":"failed"}"#,
			r#"{"outcome":"failed"}"#,
		] {
			assert!(serde_json::from_str::<PhaseFailureRequest>(raw).is_err(), "{raw}");
		}
		let good =
			serde_json::json!({"protocol_version":3,"outcome":"failed","error":"a".repeat(1000)});
		assert!(serde_json::from_value::<PhaseFailureRequest>(good).is_ok());
		let too_long =
			serde_json::json!({"protocol_version":3,"outcome":"failed","error":"a".repeat(1001)});
		assert!(serde_json::from_value::<PhaseFailureRequest>(too_long).is_err());
	}
	#[test]
	fn phase_heartbeat_requires_exact_version_only() {
		assert!(serde_json::from_str::<PhaseHeartbeatRequest>(r#"{"protocol_version":3}"#).is_ok());
		for raw in [
			"",
			"{}",
			r#"{"protocol_version":2}"#,
			r#"{"protocol_version":3,"extra":null}"#,
			r#"{"protocol_version":3,"protocol_version":3}"#,
		] {
			assert!(serde_json::from_str::<PhaseHeartbeatRequest>(raw).is_err());
		}
	}
}
