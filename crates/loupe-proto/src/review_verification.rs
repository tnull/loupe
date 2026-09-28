//! Pre-proof verification accepts independent typed evidence and returns only
//! the bounded receipt sealed before any external report delivery.
use loupe_core::review_payload::{VerificationTerminalV1, Version1};
use loupe_core::FindingState;
use serde::{Deserialize, Serialize};

use crate::review_api::ReviewProtocol;
use crate::review_lease::{ReviewCommit, ReviewDigest, ReviewId};
use crate::review_terminal::ContinuationSummary;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeVerificationRequest {
	pub protocol_version: ReviewProtocol,
	pub payload: VerificationTerminalV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdict {
	Verified,
	Rejected,
	Inconclusive,
}
impl VerificationVerdict {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Verified => "verified",
			Self::Rejected => "rejected",
			Self::Inconclusive => "inconclusive",
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSummary {
	pub version: Version1,
	pub finding_id: ReviewId,
	pub verification_id: ReviewId,
	pub verdict: VerificationVerdict,
	/// State at finalization, not a mutable delivery/approval status query.
	pub finding_state: FindingState,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub continuation: Option<ContinuationSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReceipt {
	pub receipt_id: ReviewId,
	pub job_id: ReviewId,
	pub commit_sha: ReviewCommit,
	pub result_digest: ReviewDigest,
	pub summary: VerificationSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationTerminalResponse {
	pub protocol_version: ReviewProtocol,
	pub receipt: VerificationReceipt,
}
