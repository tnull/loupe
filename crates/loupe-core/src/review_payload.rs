//! Typed pre-proof evidence. These types validate structure, not source truth,
//! inventory membership, job authority or HTTP body sizes.
//!
//! Canonical bytes retain every nested `RepoPath` exactly. Do not convert these
//! payloads through generic `BoundedJson`, whose prose leaves normalize NFC.

use serde::{Deserialize, Serialize};

use crate::text::{policy, Anchor, BoundedJson, BoundedText, Identifier, RepoPath, SourceRef};
use crate::{canonical, Severity};

pub type GeneratedProfile = BoundedJson<policy::GeneratedProfile>;
pub const SURVEY_TERMINAL_MAX_BYTES: usize = 32 * 1024;
pub const EVIDENCE_MAX_BYTES: usize = 128 * 1024;
pub const AWAITING_PROOF_INFRASTRUCTURE: &str = "awaiting proof infrastructure";

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("{field}: {rule}")]
	Invalid { field: &'static str, rule: &'static str },
	#[error("{field}: canonical payload exceeds {max_bytes} bytes")]
	Bytes { field: &'static str, max_bytes: usize },
	#[error("invalid review payload JSON: {0}")]
	Json(#[from] serde_json::Error),
}

fn invalid(field: &'static str, rule: &'static str) -> Error {
	Error::Invalid { field, rule }
}

/// A version that cannot represent a future or unversioned payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct Version1;

impl TryFrom<u32> for Version1 {
	type Error = Error;
	fn try_from(value: u32) -> Result<Self, Error> {
		if value == 1 {
			Ok(Self)
		} else {
			Err(invalid("version", "expected 1"))
		}
	}
}
impl From<Version1> for u32 {
	fn from(_: Version1) -> Self {
		1
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationRole {
	RootControl,
	EntryPoint,
	Wrapper,
	Sink,
	Implementation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
	Low,
	Medium,
	High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L2Argument {
	pub attacker_source: BoundedText<policy::AttackerSource>,
	pub control: BoundedText<policy::AttackerControl>,
	pub sink: BoundedText<policy::EvidenceSink>,
	pub reachable_path: BoundedText<policy::ReachablePath>,
	pub trust_boundary: BoundedText<policy::TrustBoundary>,
}

// Keep the field declarations single-sourced while placing every unchecked
// derived method on a private Wire helper. Deriving remote="Self" directly on
// a public type would expose unchecked inherent serialize/deserialize methods.
macro_rules! checked_serde {
	($name:ident $(, $canonical:ident)?) => {
		impl $name {
			fn serialize_fields<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
				Wire::serialize(self, serializer)
			}
		}
		impl Serialize for $name {
			fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
				self.validate().map_err(serde::ser::Error::custom)?;
				$(self.$canonical().map_err(serde::ser::Error::custom)?;)?
				self.serialize_fields(serializer)
			}
		}
		impl<'de> Deserialize<'de> for $name {
			fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
				let value = Wire::deserialize(deserializer)?;
				value.validate().map_err(serde::de::Error::custom)?;
				$(value.$canonical().map_err(serde::de::Error::custom)?;)?
				Ok(value)
			}
		}
	};
}
macro_rules! checked_struct {
	($name:ident, $remote:literal $(, $canonical:ident)? {
		$($(#[$attribute:meta])* $field:ident: $ty:ty),* $(,)?
	}) => {
		#[derive(Debug, Clone, PartialEq, Eq)]
		pub struct $name { $(pub $field: $ty),* }
		const _: () = {
			#[derive(Serialize, Deserialize)]
			#[serde(remote = $remote, deny_unknown_fields)]
			struct Wire { $($(#[$attribute])* $field: $ty),* }
			checked_serde!($name $(, $canonical)?);
		};
	};
}
macro_rules! checked_enum {
	($name:ident, $remote:literal, $tag:literal $(, $canonical:ident)? {
		$($variant:ident { $($(#[$attribute:meta])* $field:ident: $ty:ty),* $(,)? }),* $(,)?
	}) => {
		#[derive(Debug, Clone, PartialEq, Eq)]
		pub enum $name { $($variant { $($field: $ty),* }),* }
		const _: () = {
			#[derive(Serialize, Deserialize)]
			#[serde(remote = $remote, tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
			enum Wire { $($variant { $($(#[$attribute])* $field: $ty),* }),* }
			checked_serde!($name $(, $canonical)?);
		};
	};
}

checked_struct!(MaterialLocation, "MaterialLocation" {
	role: LocationRole,
	file: RepoPath,
	#[serde(skip_serializing_if = "Option::is_none")]
	symbol: Option<BoundedText<policy::MaterialSymbol>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	line_start: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	line_end: Option<u32>,
});
impl MaterialLocation {
	fn validate(&self) -> Result<(), Error> {
		if self.line_start == Some(0) || self.line_end == Some(0) {
			return Err(invalid("material_locations", "line numbers must be positive"));
		}
		if let Some(end) = self.line_end {
			let start =
				self.line_start.ok_or_else(|| invalid("line_end", "requires line_start"))?;
			if end < start {
				return Err(invalid("line_end", "precedes line_start"));
			}
		}
		Ok(())
	}
}

fn reference_count(field: &'static str, count: usize) -> Result<(), Error> {
	if (1..=16).contains(&count) {
		Ok(())
	} else {
		Err(invalid(field, "expected 1 to 16 entries"))
	}
}

checked_struct!(Revalidation, "Revalidation" {
	current_source_refs: Vec<SourceRef>,
	rationale: BoundedText<policy::RevalidationRationale>,
});
impl Revalidation {
	fn validate(&self) -> Result<(), Error> {
		reference_count("current_source_refs", self.current_source_refs.len())
	}
}
checked_struct!(SourceCounterargument, "SourceCounterargument" {
	argument: BoundedText<policy::RejectionArgument>,
	source_refs: Vec<SourceRef>,
});
impl SourceCounterargument {
	fn validate(&self) -> Result<(), Error> {
		reference_count("source_refs", self.source_refs.len())
	}
}
checked_struct!(SourceHardening, "SourceHardening" {
	argument: BoundedText<policy::HardeningArgument>,
	source_refs: Vec<SourceRef>,
});
impl SourceHardening {
	fn validate(&self) -> Result<(), Error> {
		reference_count("source_refs", self.source_refs.len())
	}
}
checked_struct!(PartialSourceEvidence, "PartialSourceEvidence" {
	argument: BoundedText<policy::Argument>,
	source_refs: Vec<SourceRef>,
});
impl PartialSourceEvidence {
	fn validate(&self) -> Result<(), Error> {
		reference_count("source_refs", self.source_refs.len())
	}
}
checked_struct!(FindingEvidenceV1, "FindingEvidenceV1", canonical_bytes {
	version: Version1,
	l2_argument: L2Argument,
	material_locations: Vec<MaterialLocation>,
	counterevidence: BoundedText<policy::EvidenceCounterevidence>,
	assumptions_gaps: BoundedText<policy::AssumptionsGaps>,
	confidence: Confidence,
});
impl FindingEvidenceV1 {
	fn validate(&self) -> Result<(), Error> {
		reference_count("material_locations", self.material_locations.len())?;
		for location in &self.material_locations {
			location.validate()?;
		}
		Ok(())
	}
}
checked_struct!(PromotionV1, "PromotionV1", canonical_bytes {
	version: Version1,
	severity: Severity,
	title: BoundedText<policy::FindingTitle>,
	description: BoundedText<policy::FindingDescription>,
	identity_family: Identifier<policy::Family>,
	identity_anchor: Anchor<policy::AnchorText>,
	#[serde(skip_serializing_if = "Option::is_none")]
	identity_instance_key: Option<Anchor<policy::InstanceKey>>,
	evidence: FindingEvidenceV1,
	#[serde(skip_serializing_if = "Option::is_none")]
	cwe: Option<Identifier<policy::Cwe>>,
});
impl PromotionV1 {
	fn validate(&self) -> Result<(), Error> {
		self.evidence.validate()
	}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurveyTerminalReason {
	Completed,
	Partial,
	Deferred,
}

checked_struct!(SurveyTerminalV1, "SurveyTerminalV1", canonical_bytes {
	version: Version1,
	terminal_reason: SurveyTerminalReason,
	#[serde(skip_serializing_if = "Option::is_none")]
	continuation: Option<BoundedText<policy::SurveyContinuation>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	security_model_notes: Option<BoundedText<policy::SecurityModelNotes>>,
});
impl SurveyTerminalV1 {
	fn validate(&self) -> Result<(), Error> {
		Ok(())
	}
}
/// A classification for later server policy, never a scheduling command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuationClass {
	SourceAnalysisRemaining,
	AwaitingProofInfrastructure,
	ExternalDependency,
	RequiresSuccessor,
}

checked_enum!(DuplicateTarget, "DuplicateTarget", "kind" {
	Lead { id: i64 },
	Finding { id: i64 },
});
impl DuplicateTarget {
	fn validate(&self) -> Result<(), Error> {
		let (Self::Lead { id } | Self::Finding { id }) = self;
		if *id > 0 {
			Ok(())
		} else {
			Err(invalid("target.id", "must be positive"))
		}
	}
}
checked_enum!(DrilldownTerminalV1, "DrilldownTerminalV1", "disposition", canonical_bytes {
	Promote {
		version: Version1,
		promotion: Box<PromotionV1>,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation>,
	},
	Reject {
		version: Version1,
		counterargument: SourceCounterargument,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation>,
	},
	Duplicate {
		version: Version1,
		target: DuplicateTarget,
		rationale: BoundedText<policy::DuplicateRationale>,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation>,
	},
	Hardening {
		version: Version1,
		explanation: SourceHardening,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation>,
	},
	Defer {
		version: Version1,
		reason: BoundedText<policy::DeferReason>,
		continuation: ContinuationClass,
		#[serde(skip_serializing_if = "Option::is_none")]
		retry_explanation: Option<BoundedText<policy::RetryExplanation>>,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation>,
	},
});
impl DrilldownTerminalV1 {
	fn validate(&self) -> Result<(), Error> {
		let revalidation = match self {
			Self::Promote { promotion, revalidation, .. } => {
				promotion.validate()?;
				revalidation
			},
			Self::Reject { counterargument, revalidation, .. } => {
				counterargument.validate()?;
				revalidation
			},
			Self::Duplicate { target, revalidation, .. } => {
				target.validate()?;
				revalidation
			},
			Self::Hardening { explanation, revalidation, .. } => {
				explanation.validate()?;
				revalidation
			},
			Self::Defer { revalidation, .. } => revalidation,
		};
		if let Some(value) = revalidation {
			value.validate()?;
		}
		Ok(())
	}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreProofRung {
	L2,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreProofApplicability {
	NotApplicable,
}

checked_enum!(VerificationTerminalV1, "VerificationTerminalV1", "verdict", canonical_bytes {
	Verified {
		version: Version1,
		established_rung: PreProofRung,
		e2e_applicability: PreProofApplicability,
		e2e_rationale: BoundedText<policy::ApplicabilityRationale>,
		evidence: Box<FindingEvidenceV1>,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation>,
		#[serde(skip_serializing_if = "Option::is_none")]
		notes: Option<BoundedText<policy::ReviewNotes>>,
	},
	Rejected {
		version: Version1,
		counterargument: SourceCounterargument,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation>,
		#[serde(skip_serializing_if = "Option::is_none")]
		notes: Option<BoundedText<policy::ReviewNotes>>,
	},
	Inconclusive {
		version: Version1,
		blocker: BoundedText<policy::VerificationBlocker>,
		continuation: ContinuationClass,
		#[serde(skip_serializing_if = "Option::is_none")]
		partial_evidence: Option<PartialSourceEvidence>,
		#[serde(skip_serializing_if = "Option::is_none")]
		retry_explanation: Option<BoundedText<policy::RetryExplanation>>,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation>,
		#[serde(skip_serializing_if = "Option::is_none")]
		notes: Option<BoundedText<policy::ReviewNotes>>,
	},
});
impl VerificationTerminalV1 {
	fn validate(&self) -> Result<(), Error> {
		let revalidation = match self {
			Self::Verified { evidence, revalidation, .. } => {
				evidence.validate()?;
				revalidation
			},
			Self::Rejected { counterargument, revalidation, .. } => {
				counterargument.validate()?;
				revalidation
			},
			Self::Inconclusive {
				blocker, continuation, partial_evidence, revalidation, ..
			} => {
				if *continuation == ContinuationClass::AwaitingProofInfrastructure
					&& blocker.expose() != AWAITING_PROOF_INFRASTRUCTURE
				{
					return Err(invalid("blocker", "expected awaiting proof infrastructure"));
				}
				if let Some(value) = partial_evidence {
					value.validate()?;
				}
				revalidation
			},
		};
		if let Some(value) = revalidation {
			value.validate()?;
		}
		Ok(())
	}
}
// Concrete payload methods share only rendering. No open-ended validation
// registry or generic JSON policy can reinterpret their field semantics.
macro_rules! canonical_payload {
	($name:ident, $field:literal, $limit:expr) => {
		impl $name {
			pub const MAX_BYTES: usize = $limit;
			pub fn from_json(raw: &str) -> Result<Self, Error> {
				Ok(serde_json::from_str(raw)?)
			}
			pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
				self.validate()?;
				// Call the derived field serializer directly to avoid recursing
				// through this type's aggregate-checking Serialize implementation.
				let value = self.serialize_fields(serde_json::value::Serializer)?;
				let bytes = canonical::canonical_bytes(&value);
				if bytes.len() > Self::MAX_BYTES {
					return Err(Error::Bytes { field: $field, max_bytes: Self::MAX_BYTES });
				}
				Ok(bytes)
			}
			pub fn digest(&self) -> Result<[u8; 32], Error> {
				Ok(canonical::digest(&self.canonical_bytes()?))
			}
		}
	};
}
canonical_payload!(FindingEvidenceV1, "finding_evidence", EVIDENCE_MAX_BYTES);
canonical_payload!(PromotionV1, "promotion", EVIDENCE_MAX_BYTES);
canonical_payload!(SurveyTerminalV1, "survey_terminal", SURVEY_TERMINAL_MAX_BYTES);
canonical_payload!(DrilldownTerminalV1, "drilldown_terminal", EVIDENCE_MAX_BYTES);
canonical_payload!(VerificationTerminalV1, "verification_terminal", EVIDENCE_MAX_BYTES);
