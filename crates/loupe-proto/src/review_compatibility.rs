//! Explicit administrative reset; never accepts replacement evidence/profile.
use serde::{Deserialize, Serialize};

use crate::review_api::ReviewProtocol;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetGenerationRequest {
	pub protocol_version: ReviewProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetGenerationResponse {
	pub protocol_version: ReviewProtocol,
	pub inventory_entries_removed: u64,
	pub review_units_removed: u64,
	pub leads_removed: u64,
	pub verification_intents_blocked: u64,
}
