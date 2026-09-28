//! Full evidence enters once; replies contain only a constant-size sealed
//! summary, including the server's durable continuation decision.
use loupe_core::review_payload::{ContinuationClass, DrilldownTerminalV1, Version1};
use serde::{Deserialize, Serialize};

use crate::review_api::ReviewProtocol;
use crate::review_lease::{ReviewCommit, ReviewDigest, ReviewId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeDrilldownRequest {
	pub protocol_version: ReviewProtocol,
	pub payload: DrilldownTerminalV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrilldownDisposition {
	Promoted,
	Rejected,
	Duplicate,
	Hardening,
	Deferred,
}
impl DrilldownDisposition {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Promoted => "promoted",
			Self::Rejected => "rejected",
			Self::Duplicate => "duplicate",
			Self::Hardening => "hardening",
			Self::Deferred => "deferred",
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuationBlockReason {
	AwaitingProofInfrastructure,
	ExternalDependency,
	RequiresSuccessor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContinuationSummary {
	Pending {
		class: ContinuationClass,
		revision: u64,
		logical_sequence: u64,
		not_before: i64,
	},
	Blocked {
		class: ContinuationClass,
		revision: u64,
		logical_sequence: u64,
		reason: ContinuationBlockReason,
	},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrilldownSummary {
	pub version: Version1,
	pub lead_id: ReviewId,
	pub disposition: DrilldownDisposition,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub promoted_finding_id: Option<ReviewId>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub continuation: Option<ContinuationSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrilldownReceipt {
	pub receipt_id: ReviewId,
	pub job_id: ReviewId,
	pub commit_sha: ReviewCommit,
	pub result_digest: ReviewDigest,
	pub summary: DrilldownSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrilldownTerminalResponse {
	pub protocol_version: ReviewProtocol,
	pub receipt: DrilldownReceipt,
}
