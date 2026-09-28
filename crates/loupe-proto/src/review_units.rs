//! Survey proposals describe scopes; their priority labels grant no authority.
use loupe_core::canonical;
use loupe_core::text::policy::{Argument, ClientKey, Objective, Reason, Title};
use loupe_core::text::{BoundedText, Identifier, SourceRef};
use serde::{Deserialize, Serialize};

use crate::review_api::ReviewProtocol;
use crate::review_lease::{LeaseList, ReviewId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityBand {
	Urgent,
	High,
	Normal,
	Background,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewUnitRequest {
	pub protocol_version: ReviewProtocol,
	pub client_review_unit_key: Identifier<ClientKey>,
	pub title: BoundedText<Title>,
	pub objective: BoundedText<Objective>,
	pub priority_band: PriorityBand,
	pub priority_rationale: Option<BoundedText<Reason>>,
	pub source_refs: LeaseList<SourceRef, 32, 1>,
	#[serde(default)]
	pub depends_on_review_unit_ids: LeaseList<ReviewId, 8>,
	// New work must fit the bounded lease without truncating its obligations.
	pub closure_criteria: Option<BoundedText<Reason>>,
	pub semantic_context: Option<BoundedText<Argument>>,
}
impl ReviewUnitRequest {
	pub fn validate(&self) -> Result<(), &'static str> {
		let mut seen = std::collections::HashSet::new();
		if self.depends_on_review_unit_ids.as_slice().iter().any(|id| !seen.insert(i64::from(*id)))
		{
			return Err("dependencies must be distinct");
		}
		Ok(())
	}
	pub fn digest(&self) -> Result<[u8; 32], serde_json::Error> {
		Ok(canonical::digest(&canonical::canonical_bytes(&serde_json::to_value(self)?)))
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewUnitResponse {
	pub protocol_version: ReviewProtocol,
	pub review_unit_id: ReviewId,
	pub assignment_epoch: u64,
	pub accepted_priority_band: PriorityBand,
}
