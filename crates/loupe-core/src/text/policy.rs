//! Field policies shared by domain validation and DAO parameter types.
use super::{AnchorPolicy, IdentPolicy, JsonPolicy, TextPolicy};

macro_rules! texts {
	($( $name:ident, $field:literal, $chars:literal, $multi:literal; )*) => { $(
		#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub struct $name;
		impl TextPolicy for $name {
			const FIELD: &'static str = $field;
			const MAX_CHARS: usize = $chars;
			const MAX_BYTES: usize = $chars * 2;
			const MULTILINE: bool = $multi;
		}
	)* };
}
texts! {
	Title, "title", 200, false;
	Objective, "objective", 2000, true;
	Reason, "reason", 1000, false;
	Argument, "argument", 4000, true;
	Symbol, "symbol", 256, false;
	MediaType, "media_type", 100, false;
	OriginalName, "original_name", 512, false;
	AnchorText, "identity_anchor", 300, false;
	InstanceKey, "identity_instance_key", 200, false;
	FindingTitle, "title", 100, false;
	FindingDescription, "description", 16384, true;
	SecurityModelNotes, "security_model_notes", 8000, true;
	RejectionArgument, "rejection_argument", 8000, true;
	HardeningArgument, "hardening_argument", 8000, true;
	AttackerSource, "attacker_source", 2000, true;
	AttackerControl, "control", 2000, true;
	EvidenceSink, "sink", 2000, true;
	ReachablePath, "reachable_path", 4000, true;
	TrustBoundary, "trust_boundary", 1000, true;
	EvidenceCounterevidence, "counterevidence", 4000, true;
	AssumptionsGaps, "assumptions_gaps", 4000, true;
	MaterialSymbol, "symbol", 200, false;
	RevalidationRationale, "revalidation_rationale", 2000, true;
	ApplicabilityRationale, "e2e_rationale", 2000, true;
	VerificationBlocker, "blocker", 2000, true;
	ReviewNotes, "notes", 4000, true;
	SurveyContinuation, "continuation", 4000, true;
	DuplicateRationale, "duplicate_rationale", 1000, true;
	DeferReason, "defer_reason", 1000, true;
	RetryExplanation, "retry_explanation", 1000, true;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonLeaf;
impl TextPolicy for JsonLeaf {
	const FIELD: &'static str = "json_leaf";
	const MAX_CHARS: usize = 4000;
	const MAX_BYTES: usize = 8000;
	const MULTILINE: bool = true;
	const ALLOW_EMPTY: bool = true;
}
impl AnchorPolicy for AnchorText {}
impl AnchorPolicy for InstanceKey {}

macro_rules! ident {
	($name:ident, $field:literal, $max:literal, $predicate:expr) => {
		#[derive(Debug, Clone, Copy, PartialEq, Eq)]
		pub struct $name;
		impl IdentPolicy for $name {
			const FIELD: &'static str = $field;
			const MAX_LEN: usize = $max;
			fn accepts(s: &str) -> bool {
				($predicate)(s)
			}
		}
	};
}
ident!(ClientKey, "client_key", 128, |s: &str| s
	.as_bytes()
	.first()
	.is_some_and(u8::is_ascii_alphanumeric)
	&& s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)));
ident!(Family, "identity_family", 64, |s: &str| s.len() >= 3
	&& s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
ident!(Label, "label", 64, |s: &str| s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
	&& s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._ -".contains(&b)));
ident!(JsonKey, "json_key", 64, |s: &str| s
	.as_bytes()
	.first()
	.is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
	&& s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
ident!(Cwe, "cwe", 64, |s: &str| s
	.strip_prefix("CWE-")
	.is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payload;
impl JsonPolicy for Payload {
	const FIELD: &'static str = "payload";
	const MAX_BYTES: usize = 64 * 1024;
	const MAX_DEPTH: usize = 16;
	const MAX_NODES: usize = 4096;
}

/// Generated metadata contains prose leaves, never authoritative source refs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratedProfile;
impl JsonPolicy for GeneratedProfile {
	const FIELD: &'static str = "generated_profile";
	const MAX_BYTES: usize = 32 * 1024;
	const MAX_DEPTH: usize = 16;
	const MAX_NODES: usize = 4096;
}
