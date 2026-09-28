//! Complete semantic checkpoint submissions; transport keys and producer
//! provenance remain with their owning checkpoint/row, not these payloads.
use super::*;
use crate::review_priority::{Access, Impact, Reachability};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeadEvidenceFormat {
	#[serde(rename = "loupe.lead_evidence")]
	V1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnitResultFormat {
	#[serde(rename = "loupe.unit_result")]
	V1,
}

checked_struct!(PriorityProposal, "PriorityProposal" {
	impact: Impact,
	access: Access,
	reachability: Reachability,
	boundary_refs: Vec<SourceRef>,
	rationale: BoundedText<policy::Reason>,
});
impl PriorityProposal {
	fn validate(&self) -> Result<(), Error> {
		if self.boundary_refs.len() > 16 {
			return Err(invalid("boundary_refs", "expected at most 16 entries"));
		}
		Ok(())
	}
}
checked_struct!(DuplicateLeadHint, "DuplicateLeadHint" {
	lead_id: i64,
	rationale: BoundedText<policy::DuplicateRationale>,
});
impl DuplicateLeadHint {
	fn validate(&self) -> Result<(), Error> {
		if self.lead_id <= 0 {
			return Err(invalid("duplicate_hint.lead_id", "must be positive"));
		}
		Ok(())
	}
}

checked_struct!(LeadEvidenceV1, "LeadEvidenceV1", canonical_bytes {
	format: LeadEvidenceFormat,
	version: Version1,
	identity_family: Identifier<policy::Family>,
	identity_anchor: Anchor<policy::AnchorText>,
	#[serde(skip_serializing_if = "Option::is_none")]
	identity_instance_key: Option<Anchor<policy::InstanceKey>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	review_unit_id: Option<i64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	assignment_epoch: Option<i64>,
	hypothesis: BoundedText<policy::Argument>,
	#[serde(skip_serializing_if = "Option::is_none")]
	invariant_or_boundary: Option<BoundedText<policy::Reason>>,
	source_refs: Vec<SourceRef>,
	next_proof_step: BoundedText<policy::Reason>,
	counterevidence: BoundedText<policy::Objective>,
	proof_gaps: BoundedText<policy::Objective>,
	#[serde(skip_serializing_if = "Option::is_none")]
	priority_proposal: Option<PriorityProposal>,
	#[serde(skip_serializing_if = "Option::is_none")]
	duplicate_hint: Option<DuplicateLeadHint>,
});
impl LeadEvidenceV1 {
	pub const FORMAT: &'static str = "loupe.lead_evidence";
	fn validate(&self) -> Result<(), Error> {
		match (self.review_unit_id, self.assignment_epoch) {
			(None, None) => {},
			(Some(unit), Some(epoch)) if unit > 0 && epoch >= 0 => {},
			_ => {
				return Err(invalid(
					"review_unit_id",
					"requires a positive unit and nonnegative paired assignment_epoch",
				))
			},
		}
		reference_count("source_refs", self.source_refs.len())?;
		if let Some(proposal) = &self.priority_proposal {
			proposal.validate()?;
		}
		if let Some(hint) = &self.duplicate_hint {
			hint.validate()?;
		}
		Ok(())
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitResultDisposition {
	LeadCreated,
	NoLeadFound,
	NotApplicable,
	NeedsFollowUp,
}
impl UnitResultDisposition {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::LeadCreated => "lead_created",
			Self::NoLeadFound => "no_lead_found",
			Self::NotApplicable => "not_applicable",
			Self::NeedsFollowUp => "needs_follow_up",
		}
	}
}
impl std::str::FromStr for UnitResultDisposition {
	type Err = Error;
	fn from_str(raw: &str) -> Result<Self, Error> {
		match raw {
			"lead_created" => Ok(Self::LeadCreated),
			"no_lead_found" => Ok(Self::NoLeadFound),
			"not_applicable" => Ok(Self::NotApplicable),
			"needs_follow_up" => Ok(Self::NeedsFollowUp),
			_ => Err(invalid("disposition", "unknown unit result disposition")),
		}
	}
}
checked_struct!(UnitResultPayloadV1, "UnitResultPayloadV1", canonical_bytes {
	format: UnitResultFormat,
	version: Version1,
	review_unit_id: i64,
	assignment_epoch: i64,
	disposition: UnitResultDisposition,
	inspected_refs: Vec<SourceRef>,
	created_lead_ids: Vec<i64>,
	counterevidence: BoundedText<policy::Objective>,
	proof_gaps: BoundedText<policy::Objective>,
	#[serde(skip_serializing_if = "Option::is_none")]
	follow_up: Option<BoundedText<policy::Objective>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	notes: Option<BoundedText<policy::ReviewNotes>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	continuation: Option<ContinuationClass>,
});
impl UnitResultPayloadV1 {
	pub const FORMAT: &'static str = "loupe.unit_result";
	fn validate(&self) -> Result<(), Error> {
		if self.review_unit_id <= 0 || self.assignment_epoch < 0 {
			return Err(invalid(
				"review_unit_id",
				"requires a positive unit and nonnegative assignment_epoch",
			));
		}
		if !(1..=64).contains(&self.inspected_refs.len()) {
			return Err(invalid("inspected_refs", "expected 1 to 64 entries"));
		}
		let ids = &self.created_lead_ids;
		if ids.len() > 16
			|| ids.iter().any(|id| *id <= 0)
			|| ids.iter().enumerate().any(|(index, id)| ids[..index].contains(id))
		{
			return Err(invalid("created_lead_ids", "expected at most 16 unique positive ids"));
		}
		if (self.disposition == UnitResultDisposition::LeadCreated) == ids.is_empty() {
			return Err(invalid("created_lead_ids", "nonempty exactly for lead_created"));
		}
		if self.disposition == UnitResultDisposition::NeedsFollowUp {
			if self.follow_up.is_none() || self.continuation.is_none() {
				return Err(invalid(
					"follow_up",
					"needs_follow_up requires follow_up and continuation",
				));
			}
		} else if self.follow_up.is_some() || self.continuation.is_some() {
			return Err(invalid(
				"follow_up",
				"only needs_follow_up accepts follow_up or continuation",
			));
		}
		Ok(())
	}
}
canonical_payload!(LeadEvidenceV1, "lead_evidence", 64 * 1024);
canonical_payload!(UnitResultPayloadV1, "unit_result", 64 * 1024);

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;
