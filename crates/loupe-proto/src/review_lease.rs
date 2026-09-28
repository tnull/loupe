//! Inert, narrowly scoped review leases. Representation is not authorization:
//! the server must check preparation, assignment ownership and runtime gates.

use std::num::{NonZeroU32, NonZeroU64};

use loupe_core::review_payload::{FindingEvidenceV1, GeneratedProfile, Version1};
use loupe_core::text::policy::{
	AnchorText, Argument, Family, FindingDescription, FindingTitle, InstanceKey, Objective, Reason,
	Title,
};
use loupe_core::text::{Anchor, BoundedText, IdentPolicy, Identifier, SourceRef};
use loupe_core::Severity;
use serde::{Deserialize, Serialize};

/// Phase advertisement is deliberately independent of legacy `verify:*` tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewCapability {
	#[serde(rename = "review:survey:v1")]
	Survey,
	#[serde(rename = "review:drilldown:v1")]
	Drilldown,
	#[serde(rename = "review:verify:v1")]
	Verify,
}

/// Positive SQLite identifiers, not opaque agent-selected ownership fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct ReviewId(i64);
impl TryFrom<i64> for ReviewId {
	type Error = &'static str;
	fn try_from(value: i64) -> Result<Self, Self::Error> {
		if value > 0 {
			Ok(Self(value))
		} else {
			Err("review id must be positive")
		}
	}
}
impl From<ReviewId> for i64 {
	fn from(value: ReviewId) -> Self {
		value.0
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitPolicy;
impl IdentPolicy for CommitPolicy {
	const FIELD: &'static str = "commit_sha";
	const MAX_LEN: usize = 64;
	fn accepts(value: &str) -> bool {
		loupe_core::inventory_manifest::is_git_oid(value)
	}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DigestPolicy;
impl IdentPolicy for DigestPolicy {
	const FIELD: &'static str = "digest";
	const MAX_LEN: usize = 64;
	fn accepts(value: &str) -> bool {
		value.len() == 64 && lower_hex(value)
	}
}
fn lower_hex(value: &str) -> bool {
	value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub type ReviewCommit = Identifier<CommitPolicy>;
pub type ReviewDigest = Identifier<DigestPolicy>;

/// Bounded collections reject the first excess element while decoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct LeaseList<T, const MAX: usize, const MIN: usize = 0>(Vec<T>);
impl<T, const MAX: usize, const MIN: usize> LeaseList<T, MAX, MIN> {
	pub fn new(values: Vec<T>) -> Result<Self, &'static str> {
		if !(MIN..=MAX).contains(&values.len()) {
			Err("review collection outside its bounds")
		} else {
			Ok(Self(values))
		}
	}
	pub fn as_slice(&self) -> &[T] {
		&self.0
	}
}
impl<T, const MAX: usize> Default for LeaseList<T, MAX> {
	fn default() -> Self {
		Self(Vec::new())
	}
}
impl<'de, T: Deserialize<'de>, const MAX: usize, const MIN: usize> Deserialize<'de>
	for LeaseList<T, MAX, MIN>
{
	fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct Visitor<T, const MAX: usize, const MIN: usize>(std::marker::PhantomData<T>);
		impl<'de, T: Deserialize<'de>, const MAX: usize, const MIN: usize> serde::de::Visitor<'de>
			for Visitor<T, MAX, MIN>
		{
			type Value = LeaseList<T, MAX, MIN>;
			fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				write!(formatter, "at most {MAX} review items")
			}
			fn visit_seq<A: serde::de::SeqAccess<'de>>(
				self, mut seq: A,
			) -> Result<Self::Value, A::Error> {
				let mut values = Vec::new();
				while let Some(value) = seq.next_element()? {
					if values.len() == MAX {
						return Err(serde::de::Error::custom(
							"review collection exceeds its bound",
						));
					}
					values.push(value);
				}
				LeaseList::new(values).map_err(serde::de::Error::custom)
			}
		}
		deserializer.deserialize_seq(Visitor::<T, MAX, MIN>(std::marker::PhantomData))
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLimits {
	pub soft_deadline_at: i64,
	pub submit_by: i64,
	pub hard_deadline_at: i64,
	pub token_budget: Option<NonZeroU64>,
	pub new_unit_limit: u32,
	pub lead_limit: u32,
	pub sibling_limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewProvenance {
	pub workflow_contract_version: Version1,
	pub campaign_id: ReviewId,
	pub attempt: NonZeroU32,
	pub limits: ReviewLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewGeneration {
	pub generation_id: ReviewId,
	pub commit_sha: ReviewCommit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenReviewProfile {
	pub profile_version: NonZeroU32,
	pub profile_digest: ReviewDigest,
	pub profile: GeneratedProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignedReviewUnit {
	pub review_unit_id: ReviewId,
	pub assignment_epoch: NonZeroU64,
	pub title: BoundedText<Title>,
	pub objective: BoundedText<Objective>,
	pub source_refs: LeaseList<SourceRef, 32>,
	pub depends_on: LeaseList<ReviewId, 8>,
	pub closure_criteria: Option<BoundedText<Reason>>,
}

/// Array order is assignment order; a unit can occur only once in a batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "LeaseList<AssignedReviewUnit, 32>", into = "LeaseList<AssignedReviewUnit, 32>")]
pub struct ReviewAssignments(LeaseList<AssignedReviewUnit, 32>);
impl TryFrom<LeaseList<AssignedReviewUnit, 32>> for ReviewAssignments {
	type Error = &'static str;
	fn try_from(units: LeaseList<AssignedReviewUnit, 32>) -> Result<Self, Self::Error> {
		for (index, unit) in units.as_slice().iter().enumerate() {
			if units.as_slice()[..index]
				.iter()
				.any(|prior| prior.review_unit_id == unit.review_unit_id)
			{
				return Err("duplicate review unit assignment");
			}
		}
		Ok(Self(units))
	}
}
impl From<ReviewAssignments> for LeaseList<AssignedReviewUnit, 32> {
	fn from(value: ReviewAssignments) -> Self {
		value.0
	}
}
impl ReviewAssignments {
	pub fn as_slice(&self) -> &[AssignedReviewUnit] {
		self.0.as_slice()
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrdinarySurveyRecipe {
	Coverage,
	SameCommitIncremental,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BootstrapTarget {
	/// The original ref remains in the enclosing repo/head-branch fields.
	Unresolved {},
	Pinned {
		generation: ReviewGeneration,
		published_profile: Option<FrozenReviewProfile>,
	},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "recipe", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReviewSurveyContext {
	Bootstrap {
		target: BootstrapTarget,
	},
	/// Preparation only: an unknown target is not an ordinary empty batch.
	ResolveTarget {},
	Ordinary {
		generation: ReviewGeneration,
		profile: FrozenReviewProfile,
		ordinary_recipe: OrdinarySurveyRecipe,
		assignments: ReviewAssignments,
	},
	/// The shape cannot carry a generated profile; runtime remains B8-held.
	Corroboration {
		generation: ReviewGeneration,
		assignments: ReviewAssignments,
	},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewSurveyLease {
	pub provenance: ReviewProvenance,
	pub context: ReviewSurveyContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignedReviewLead {
	pub lead_id: ReviewId,
	pub producer_commit_sha: ReviewCommit,
	pub identity_family: Identifier<Family>,
	pub identity_anchor: Anchor<AnchorText>,
	pub identity_instance_key: Option<Anchor<InstanceKey>>,
	pub hypothesis: BoundedText<Argument>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub invariant_or_boundary: Option<BoundedText<Reason>>,
	pub source_refs: LeaseList<SourceRef, 16, 1>,
	pub next_proof_step: BoundedText<Reason>,
	pub counterevidence: BoundedText<Objective>,
	pub proof_gaps: BoundedText<Objective>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewDrilldownLease {
	pub provenance: ReviewProvenance,
	pub generation: ReviewGeneration,
	pub profile: FrozenReviewProfile,
	pub lead: AssignedReviewLead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignedReviewFinding {
	pub finding_id: ReviewId,
	pub reviewed_commit_sha: ReviewCommit,
	pub severity: Severity,
	pub title: BoundedText<FindingTitle>,
	pub description: BoundedText<FindingDescription>,
	pub identity_family: Identifier<Family>,
	pub identity_anchor: Anchor<AnchorText>,
	pub identity_instance_key: Option<Anchor<InstanceKey>>,
	pub evidence: FindingEvidenceV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewVerifyLease {
	pub provenance: ReviewProvenance,
	pub generation: ReviewGeneration,
	pub profile: FrozenReviewProfile,
	pub finding: AssignedReviewFinding,
}

#[cfg(test)]
mod tests {
	use serde_json::{json, Value};

	use super::*;
	use crate::{LeasePayload, LeaseRequest, PROTOCOL_VERSION};

	#[test]
	fn assigned_lead_retains_optional_invariant_and_exact_paths() {
		let raw = serde_json::json!({
			"lead_id":1,"producer_commit_sha":"a".repeat(40),
			"identity_family":"auth-bypass","identity_anchor":"request guard",
			"hypothesis":"wrapper bypass","invariant_or_boundary":"authentication boundary",
			"source_refs":[{"path":"cafe\u{301}.rs"}],"next_proof_step":"trace wrapper",
			"counterevidence":"guard exists","proof_gaps":"entry is uncertain"
		});
		let lead: AssignedReviewLead = serde_json::from_value(raw.clone()).unwrap();
		assert_eq!(
			lead.invariant_or_boundary.as_ref().unwrap().expose(),
			"authentication boundary"
		);
		assert_eq!(lead.source_refs.as_slice()[0].path.expose(), "cafe\u{301}.rs");
		assert_eq!(
			serde_json::from_str::<AssignedReviewLead>(&serde_json::to_string(&lead).unwrap())
				.unwrap(),
			lead
		);
		let mut without = raw;
		without.as_object_mut().unwrap().remove("invariant_or_boundary");
		assert!(serde_json::from_value::<AssignedReviewLead>(without)
			.unwrap()
			.invariant_or_boundary
			.is_none());
	}

	fn provenance() -> Value {
		json!({"workflow_contract_version":1,"campaign_id":2,"attempt":1,
			"limits":{"soft_deadline_at":100,"submit_by":100,"hard_deadline_at":200,
				"token_budget":null,"new_unit_limit":32,"lead_limit":16,"sibling_limit":4}})
	}
	fn generation() -> Value {
		json!({"generation_id":3,"commit_sha":"a".repeat(40)})
	}
	fn profile() -> Value {
		json!({"profile_version":1,"profile_digest":"b".repeat(64),"profile":{"purpose":"test"}})
	}
	fn unit(id: i64, path: &str) -> Value {
		json!({"review_unit_id":id,"assignment_epoch":2,"title":"Review parser",
			"objective":"Check input bounds","source_refs":[{"path":path}],
			"depends_on":[],"closure_criteria":null})
	}
	fn ordinary() -> Value {
		json!({"kind":"review_survey","provenance":provenance(),
			"context":{"recipe":"ordinary","generation":generation(),"profile":profile(),
				"ordinary_recipe":"coverage","assignments":[unit(5,"src/e\u{301}.rs"),unit(4,"src/é.rs")]}})
	}
	fn evidence() -> Value {
		json!({"version":1,"l2_argument":{"attacker_source":"Remote request","control":"Request length",
			"sink":"Allocation","reachable_path":"Handler calls the allocator","trust_boundary":"Request to memory"},
			"material_locations":[{"role":"sink","file":"src/lib.rs","line_start":3,"line_end":4}],
			"counterevidence":"Authentication precedes allocation","assumptions_gaps":"Authenticated attacker",
			"confidence":"medium"})
	}

	#[test]
	fn ordinary_assignments_preserve_order_epochs_and_path_bytes() {
		let payload: LeasePayload = serde_json::from_value(ordinary()).unwrap();
		let LeasePayload::ReviewSurvey(lease) = &payload else { panic!("review survey") };
		let ReviewSurveyContext::Ordinary { assignments, .. } = &lease.context else {
			panic!("ordinary")
		};
		assert_eq!(i64::from(assignments.as_slice()[0].review_unit_id), 5);
		assert_eq!(assignments.as_slice()[0].assignment_epoch.get(), 2);
		assert_eq!(
			assignments.as_slice()[0].source_refs.as_slice()[0].path.expose(),
			"src/e\u{301}.rs"
		);
		assert_eq!(assignments.as_slice()[1].source_refs.as_slice()[0].path.expose(), "src/é.rs");
		assert_eq!(
			serde_json::from_str::<LeasePayload>(&serde_json::to_string(&payload).unwrap())
				.unwrap(),
			payload
		);
	}

	#[test]
	fn review_verify_is_distinct_from_legacy_verify() {
		let raw = json!({"kind":"review_verify","provenance":provenance(),"generation":generation(),
			"profile":profile(),"finding":{"finding_id":4,"reviewed_commit_sha":"a".repeat(40),
				"severity":"high","title":"Unbounded allocation","description":"Requests allocate without a limit",
				"identity_family":"memory-safety","identity_anchor":"request allocation","evidence":evidence()}});
		let payload: LeasePayload = serde_json::from_value(raw.clone()).unwrap();
		assert!(matches!(payload, LeasePayload::ReviewVerify(_)));
		let mut legacy_tag = raw;
		legacy_tag["kind"] = json!("verify");
		assert!(serde_json::from_value::<LeasePayload>(legacy_tag).is_err());
	}

	#[test]
	fn bootstrap_and_corroboration_cannot_inherit_ordinary_scope() {
		let mut bootstrap = json!({"kind":"review_survey","provenance":provenance(),
			"context":{"recipe":"bootstrap","target":{"kind":"unresolved"}}});
		assert!(serde_json::from_value::<LeasePayload>(bootstrap.clone()).is_ok());
		bootstrap["context"]["assignments"] = json!([unit(4, "src/lib.rs")]);
		assert!(serde_json::from_value::<LeasePayload>(bootstrap).is_err());
		let mut corroboration = json!({"kind":"review_survey","provenance":provenance(),
			"context":{"recipe":"corroboration","generation":generation(),"assignments":[]}});
		assert!(serde_json::from_value::<LeasePayload>(corroboration.clone()).is_ok());
		corroboration["context"]["profile"] = profile();
		assert!(serde_json::from_value::<LeasePayload>(corroboration).is_err());
	}

	#[test]
	fn review_payload_rejects_unknown_fields_at_each_boundary() {
		for pointer in [
			"",
			"/provenance",
			"/provenance/limits",
			"/context",
			"/context/generation",
			"/context/profile",
			"/context/assignments/0",
			"/context/assignments/0/source_refs/0",
		] {
			let mut raw = ordinary();
			raw.pointer_mut(pointer)
				.unwrap()
				.as_object_mut()
				.unwrap()
				.insert("unexpected".into(), json!(true));
			assert!(
				serde_json::from_value::<LeasePayload>(raw).is_err(),
				"unknown field accepted at {pointer}"
			);
		}
	}

	#[test]
	fn review_assignment_bounds_and_identity_are_enforced() {
		let mut raw = ordinary();
		raw["context"]["assignments"] = json!([unit(5, "src/lib.rs"), unit(5, "src/other.rs")]);
		assert!(serde_json::from_value::<LeasePayload>(raw.clone()).is_err());
		raw["context"]["assignments"] =
			Value::Array((1..=33).map(|id| unit(id, "src/lib.rs")).collect());
		assert!(serde_json::from_value::<LeasePayload>(raw).is_err());
		for (pointer, value) in [
			("/provenance/attempt", json!(0)),
			("/provenance/campaign_id", json!(-1)),
			("/context/generation/commit_sha", json!("main")),
			("/context/assignments/0/assignment_epoch", json!(0)),
		] {
			let mut raw = ordinary();
			*raw.pointer_mut(pointer).unwrap() = value;
			assert!(serde_json::from_value::<LeasePayload>(raw).is_err(), "invalid {pointer}");
		}
	}

	#[test]
	fn review_provenance_rejects_unknown_versions_and_duplicate_fields() {
		let mut raw = ordinary();
		raw["provenance"]["workflow_contract_version"] = json!(2);
		assert!(serde_json::from_value::<LeasePayload>(raw).is_err());
		let raw = ordinary().to_string().replace("\"attempt\":1", "\"attempt\":1,\"attempt\":1");
		assert!(serde_json::from_str::<LeasePayload>(&raw).is_err());
	}

	#[test]
	fn legacy_request_does_not_advertise_phase_verification() {
		let request: LeaseRequest =
			serde_json::from_value(json!({"protocol_version":PROTOCOL_VERSION,
			"capabilities":["verify:llm"],"wait_seconds":0}))
			.unwrap();
		assert!(request.review_capabilities.as_slice().is_empty());
		let mut raw = serde_json::to_value(request).unwrap();
		raw["review_capabilities"] = json!(["verify:llm"]);
		assert!(serde_json::from_value::<LeaseRequest>(raw).is_err());
	}
}
