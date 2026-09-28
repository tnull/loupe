//! Strict typed checkpoint envelopes; paths retain their exact Git identity.
use loupe_core::canonical;
use loupe_core::review_payload::{LeadEvidenceV1, UnitResultDisposition, UnitResultPayloadV1};
use loupe_core::text::policy::ClientKey;
use loupe_core::text::Identifier;
use serde::{Deserialize, Serialize};

use crate::review_api::ReviewProtocol;
use crate::review_lease::ReviewId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeadCheckpointRequest {
	pub protocol_version: ReviewProtocol,
	pub client_lead_key: Identifier<ClientKey>,
	pub evidence: LeadEvidenceV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitResultCheckpointRequest {
	pub protocol_version: ReviewProtocol,
	pub client_result_key: Identifier<ClientKey>,
	pub result: UnitResultPayloadV1,
}

impl LeadCheckpointRequest {
	pub fn digest(&self) -> Result<[u8; 32], serde_json::Error> {
		Ok(canonical::digest(&canonical::canonical_bytes(&serde_json::to_value(self)?)))
	}
}
impl UnitResultCheckpointRequest {
	pub fn digest(&self) -> Result<[u8; 32], serde_json::Error> {
		Ok(canonical::digest(&canonical::canonical_bytes(&serde_json::to_value(self)?)))
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeadOutcome {
	Created,
	Attached,
	ClosedExists,
}

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
pub struct AcceptedPriority {
	pub band: PriorityBand,
	pub score: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeadCheckpointResponse {
	pub protocol_version: ReviewProtocol,
	pub lead_id: ReviewId,
	pub outcome: LeadOutcome,
	pub observation_id: Option<ReviewId>,
	pub accepted_priority: AcceptedPriority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitResultCheckpointResponse {
	pub protocol_version: ReviewProtocol,
	pub result_id: ReviewId,
	pub review_unit_id: ReviewId,
	pub assignment_epoch: u64,
	pub disposition: UnitResultDisposition,
}

#[cfg(test)]
mod tests {
	use serde_json::{json, Value};

	use super::*;
	fn lead() -> Value {
		json!({"protocol_version":3,"client_lead_key":"lead","evidence":{"format":"loupe.lead_evidence","version":1,"identity_family":"auth-bypass","identity_anchor":"handler","review_unit_id":1,"assignment_epoch":0,"hypothesis":"Attacker crosses boundary","source_refs":[{"path":"e\u{301}.rs"}],"next_proof_step":"Trace entry","counterevidence":"No guard found","proof_gaps":"Need proof"}})
	}
	#[test]
	fn complete_request_digest_binds_key_epoch_hint_and_exact_paths() {
		let value = lead();
		let original: LeadCheckpointRequest = serde_json::from_value(value.clone()).unwrap();
		let digest = original.digest().unwrap();
		for (field, replacement) in [
			("assignment_epoch", json!(1)),
			("source_refs", json!([{"path":"é.rs"}])),
			("duplicate_hint", json!({"lead_id":2,"rationale":"same boundary"})),
		] {
			let mut changed = value.clone();
			changed["evidence"][field] = replacement;
			assert_ne!(
				serde_json::from_value::<LeadCheckpointRequest>(changed).unwrap().digest().unwrap(),
				digest,
				"{field}"
			);
		}
		let mut changed = value;
		changed["client_lead_key"] = json!("another");
		assert_ne!(
			serde_json::from_value::<LeadCheckpointRequest>(changed).unwrap().digest().unwrap(),
			digest
		);
		assert_eq!(original.evidence.source_refs[0].path.expose(), "e\u{301}.rs");
	}
	#[test]
	fn request_envelopes_reject_unknown_duplicate_versions_and_invalid_typed_evidence() {
		let original = lead();
		for (field, value) in [("protocol_version", json!(2)), ("unexpected", json!(0))] {
			let mut invalid = original.clone();
			invalid[field] = value;
			assert!(serde_json::from_value::<LeadCheckpointRequest>(invalid).is_err());
		}
		for (field, value) in [
			("version", json!(2)),
			("source_refs", json!([])),
			("assignment_epoch", json!(-1)),
			("unexpected", json!(0)),
		] {
			let mut invalid = original.clone();
			invalid["evidence"][field] = value;
			assert!(serde_json::from_value::<LeadCheckpointRequest>(invalid).is_err());
		}
		for raw in [
			original
				.to_string()
				.replace("\"protocol_version\":3", "\"protocol_version\":3,\"protocol_version\":3"),
			original.to_string().replace("\"version\":1", "\"version\":1,\"version\":1"),
		] {
			assert!(serde_json::from_str::<LeadCheckpointRequest>(&raw).is_err());
		}
		let result = json!({"protocol_version":3,"client_result_key":"result","result":{"format":"loupe.unit_result","version":1,"review_unit_id":1,"assignment_epoch":0,"disposition":"no_lead_found","inspected_refs":[{"path":"a.rs"}],"created_lead_ids":[],"counterevidence":"Guard holds","proof_gaps":"None"}});
		let valid: UnitResultCheckpointRequest = serde_json::from_value(result.clone()).unwrap();
		assert!(valid.digest().is_ok());
		for (field, value) in [
			("created_lead_ids", json!([1])),
			("disposition", json!("needs_follow_up")),
			("review_unit_id", json!(0)),
			("unknown", json!(1)),
		] {
			let mut invalid = result.clone();
			invalid["result"][field] = value;
			assert!(serde_json::from_value::<UnitResultCheckpointRequest>(invalid).is_err());
		}
	}
}
