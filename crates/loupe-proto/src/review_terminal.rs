//! Strict terminal requests and constant-size sealed receipts. Full accepted
//! evidence is retained server-side, never echoed into this response envelope.
use loupe_core::review_payload::{SurveyTerminalReason, SurveyTerminalV1, Version1};
use serde::{Deserialize, Serialize};

use crate::review_api::ReviewProtocol;
use crate::review_lease::{ReviewCommit, ReviewDigest, ReviewId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeSurveyRequest {
	pub protocol_version: ReviewProtocol,
	pub payload: SurveyTerminalV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurveyCoverage {
	Complete,
	Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurveySummary {
	pub version: Version1,
	pub coverage: SurveyCoverage,
	pub corroboration_satisfied: bool,
	pub missing_results: u64,
	pub needs_follow_up: u64,
	pub unresolved_inventory: u64,
	pub follow_up_batches: u64,
	pub follow_up_units: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurveyReceipt {
	pub receipt_id: ReviewId,
	pub job_id: ReviewId,
	pub commit_sha: ReviewCommit,
	pub result_digest: ReviewDigest,
	pub terminal_reason: SurveyTerminalReason,
	pub summary: SurveySummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurveyTerminalResponse {
	pub protocol_version: ReviewProtocol,
	pub receipt: SurveyReceipt,
}
