//! Minimal duplicate-search projections. These contain no source or finding body.
use serde::{Deserialize, Serialize};

use crate::text::policy::{AnchorText, Family, InstanceKey};
use crate::text::{Anchor, BoundedText, Identifier, TextPolicy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryPolicy;
impl TextPolicy for QueryPolicy {
	const FIELD: &'static str = "query";
	const MAX_CHARS: usize = 500;
	const MAX_BYTES: usize = 1000;
	const MULTILINE: bool = false;
}
pub type QueryText = BoundedText<QueryPolicy>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
	Lead,
	Finding,
}

/// Immutable identity/provenance copied at issuance. Mutable lifecycle state
/// is deliberately absent: it cannot silently grant authority to another row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
	pub kind: CandidateKind,
	pub id: i64,
	pub producer_job_id: i64,
	pub commit_sha: String,
	pub created_at: i64,
	pub identity_family: Identifier<Family>,
	pub identity_anchor: Anchor<AnchorText>,
	pub identity_instance_key: Option<Anchor<InstanceKey>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateQuery {
	pub query: QueryText,
	#[serde(default = "default_limit")]
	pub limit: u8,
}
fn default_limit() -> u8 {
	10
}
impl CandidateQuery {
	pub fn validate(&self) -> Result<(), &'static str> {
		if (1..=20).contains(&self.limit) {
			Ok(())
		} else {
			Err("candidate limit must be between 1 and 20")
		}
	}
}
