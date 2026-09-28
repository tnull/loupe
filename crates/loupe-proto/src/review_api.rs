//! Worker-host preparation and phase HTTP contracts. These payloads never
//! accept repository, campaign, generation or worker ownership from callers.

use loupe_core::review_payload::{GeneratedProfile, Version1};
use loupe_core::text::{IdentPolicy, Identifier};
use serde::{Deserialize, Serialize};

use crate::review_lease::{
	FrozenReviewProfile, LeaseList, ReviewAssignments, ReviewCommit, ReviewDigest,
	ReviewGeneration, ReviewId,
};
use crate::PROTOCOL_VERSION;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capacity {
	pub limit: u32,
	pub remaining: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseLimitsResponse {
	pub protocol_version: ReviewProtocol,
	pub soft_deadline_at: i64,
	pub submit_by: i64,
	pub hard_deadline_at: i64,
	pub remaining_seconds: u64,
	pub new_units: Capacity,
	pub leads: Capacity,
	pub siblings: Capacity,
	pub candidate_queries: Capacity,
	pub campaign_jobs_limit: u64,
	pub campaign_jobs_admitted: u64,
	pub campaign_general_remaining: u64,
	pub campaign_urgent_remaining: u64,
	pub campaign_verification_remaining: u64,
	pub proof_capacity: Unavailable,
	pub artifact_capacity: Unavailable,
	pub output_capacity: Unavailable,
	pub tokens: TokenCapacity,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unavailable {
	Unavailable,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum TokenCapacity {
	None,
	HostEnforced { limit: u64, spent: UnknownSpend },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownSpend {
	Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatesResponse {
	pub protocol_version: ReviewProtocol,
	pub candidates: LeaseList<loupe_core::review_candidates::Candidate, 20>,
}

/// New phase requests always carry the exact protocol version, in addition
/// to the required HTTP header. Legacy request policy is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct ReviewProtocol;
impl TryFrom<u16> for ReviewProtocol {
	type Error = &'static str;
	fn try_from(value: u16) -> Result<Self, Self::Error> {
		if value == PROTOCOL_VERSION {
			Ok(Self)
		} else {
			Err("unsupported protocol_version")
		}
	}
}
impl From<ReviewProtocol> for u16 {
	fn from(_: ReviewProtocol) -> Self {
		PROTOCOL_VERSION
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawPathHexPolicy;
impl IdentPolicy for RawPathHexPolicy {
	const FIELD: &'static str = "raw_path_hex";
	const MAX_LEN: usize = 128 * 1024;
	fn accepts(value: &str) -> bool {
		!value.is_empty()
			&& value.len().is_multiple_of(2)
			&& value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
	}
}
/// Lowercase hex preserves every raw Git path byte, including non-UTF-8
/// entries. Whether those bytes form a valid Git path is a host/store check.
pub type RawPathHex = Identifier<RawPathHexPolicy>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinTargetRequest {
	pub protocol_version: ReviewProtocol,
	pub commit_sha: ReviewCommit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
	pub raw_path_hex: RawPathHex,
	pub git_mode: u32,
	pub object_id: ReviewCommit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryBatchRequest {
	pub protocol_version: ReviewProtocol,
	pub format_version: Version1,
	pub expected_entry_count: u64,
	pub expected_digest: ReviewDigest,
	pub start_position: u64,
	pub entries: LeaseList<ManifestEntry, 4096>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealInventoryRequest {
	pub protocol_version: ReviewProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishProfileRequest {
	pub protocol_version: ReviewProtocol,
	pub profile: GeneratedProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestProgress {
	pub protocol_version: ReviewProtocol,
	pub expected_entry_count: u64,
	pub expected_digest: ReviewDigest,
	pub received_entry_count: u64,
	pub received_canonical_bytes: u64,
	pub sealed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedProfile {
	pub protocol_version: ReviewProtocol,
	pub profile_version: u32,
	pub profile_digest: ReviewDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationDeferral {
	pub receipt_id: ReviewId,
	pub commit_sha: ReviewCommit,
	pub reason: UnsupportedRecipe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedRecipe {
	UnsupportedRecipe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum PinTargetResponse {
	Prepared {
		protocol_version: ReviewProtocol,
		generation: ReviewGeneration,
		/// Bootstrap has no profile before publication. Ordinary jobs reuse it.
		profile: Option<FrozenReviewProfile>,
		/// Only ordinary surveys receive an assignment batch, including empty.
		assignments: Option<ReviewAssignments>,
	},
	Deferred {
		protocol_version: ReviewProtocol,
		receipt: PreparationDeferral,
	},
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn phase_requests_require_exact_version_and_no_ownership_fields() {
		let sha = "a".repeat(40);
		let valid = format!(r#"{{"protocol_version":3,"commit_sha":"{sha}"}}"#);
		assert!(serde_json::from_str::<PinTargetRequest>(&valid).is_ok());
		for invalid in [
			valid.replace(":3", ":2"),
			valid.replace("\"protocol_version\":3,", ""),
			valid.replace(
				"\"protocol_version\":3,",
				"\"protocol_version\":3,\"protocol_version\":3,",
			),
			valid.replace('}', ",\"generation_id\":1}"),
		] {
			assert!(serde_json::from_str::<PinTargetRequest>(&invalid).is_err(), "{invalid}");
		}
	}

	#[test]
	fn raw_identity_is_lossless_and_bounded_not_a_display_path() {
		assert!(RawPathHex::new("61ff").is_ok());
		assert_ne!(RawPathHex::new("61ff").unwrap(), RawPathHex::new("61254646").unwrap());
		for invalid in ["", "0", "AA", "gg"] {
			assert!(RawPathHex::new(invalid).is_err());
		}
		assert!(RawPathHex::new(&"61".repeat(64 * 1024)).is_ok());
		assert!(RawPathHex::new(&"61".repeat(64 * 1024 + 1)).is_err());
	}
}
