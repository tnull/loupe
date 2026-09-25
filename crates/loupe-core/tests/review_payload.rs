use loupe_core::review_payload::{
	DrilldownTerminalV1, FindingEvidenceV1, GeneratedProfile, MaterialLocation, PromotionV1,
	SurveyTerminalV1, VerificationTerminalV1,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn evidence() -> Value {
	json!({
		"version": 1,
		"l2_argument": {
			"attacker_source": "Remote request",
			"control": "Request length",
			"sink": "Allocation",
			"reachable_path": "Handler calls the allocator",
			"trust_boundary": "Untrusted request to process memory"
		},
		"material_locations": [{"role": "sink", "file": "src/cafe\u{301}.rs", "line_start": 3, "line_end": 4}],
		"counterevidence": "Authentication precedes allocation",
		"assumptions_gaps": "An authenticated attacker is assumed",
		"confidence": "medium"
	})
}

fn promotion() -> Value {
	json!({
		"version": 1, "severity": "high", "title": "Bound allocation",
		"description": "An attacker controls the allocation size",
		"identity_family": "resource-exhaustion",
		"identity_anchor": "request allocator",
		"evidence": evidence()
	})
}

fn verified() -> Value {
	json!({
		"version": 1, "verdict": "verified", "established_rung": "L2",
		"e2e_applicability": "not_applicable", "e2e_rationale": "The property is source-defined",
		"evidence": evidence()
	})
}

#[test]
fn canonical_evidence_preserves_nested_path_bytes_and_every_location() {
	let raw = evidence();
	let mut parsed: FindingEvidenceV1 = serde_json::from_value(raw.clone()).unwrap();
	let first = parsed.canonical_bytes().unwrap();
	assert_eq!(serde_json::from_slice::<Value>(&first).unwrap(), raw);
	assert_eq!(parsed.digest().unwrap(), loupe_core::canonical::digest(&first));
	let restored = FindingEvidenceV1::from_json(std::str::from_utf8(&first).unwrap()).unwrap();
	assert_eq!(restored.canonical_bytes().unwrap(), first);

	let mut composed = raw.clone();
	composed["material_locations"][0]["file"] = json!("src/café.rs");
	let composed: FindingEvidenceV1 = serde_json::from_value(composed).unwrap();
	assert_ne!(parsed.digest().unwrap(), composed.digest().unwrap());

	parsed.material_locations.push(
		serde_json::from_value(json!({
			"role": "wrapper", "file": "src/wrapper.rs"
		}))
		.unwrap(),
	);
	assert_eq!(
		serde_json::from_slice::<Value>(&parsed.canonical_bytes().unwrap()).unwrap()
			["material_locations"]
			.as_array()
			.unwrap()
			.len(),
		2
	);
}

#[test]
fn public_rust_mutation_is_checked_again_at_serialization() {
	let mut value: FindingEvidenceV1 = serde_json::from_value(evidence()).unwrap();
	value.material_locations.clear();
	assert!(value.canonical_bytes().is_err());
	assert!(serde_json::to_string(&value).is_err());
	let mut value: FindingEvidenceV1 = serde_json::from_value(evidence()).unwrap();
	value.material_locations[0].line_start = Some(0);
	assert!(value.canonical_bytes().is_err());
}

#[test]
fn public_associated_deserialize_cannot_bypass_location_validation() {
	let mut deserializer =
		serde_json::Deserializer::from_str(r#"{"role":"sink","file":"src/lib.rs","line_start":0}"#);
	assert!(
		MaterialLocation::deserialize(&mut deserializer).is_err(),
		"public associated deserialize must reject zero source lines"
	);
}

#[test]
fn public_associated_serialize_cannot_bypass_evidence_validation() {
	let mut value: FindingEvidenceV1 = serde_json::from_value(evidence()).unwrap();
	value.material_locations.clear();
	assert!(
		FindingEvidenceV1::serialize(&value, serde_json::value::Serializer).is_err(),
		"public associated serialize must reject missing material locations"
	);
}

#[test]
fn versions_roles_lines_and_reference_counts_are_strict() {
	for version in [json!(0), json!(2), json!(1.0), json!("1")] {
		let mut raw = evidence();
		raw["version"] = version;
		assert!(serde_json::from_value::<FindingEvidenceV1>(raw).is_err());
	}
	for location in [
		json!({"file":"a.rs"}),
		json!({"file":"a.rs", "role":"unknown"}),
		json!({"file":"a.rs", "role":"sink", "line_start":0}),
		json!({"file":"a.rs", "role":"sink", "line_end":1}),
		json!({"file":"a.rs", "role":"sink", "line_start":2, "line_end":1}),
	] {
		assert!(serde_json::from_value::<MaterialLocation>(location).is_err());
	}
	for count in [0, 17] {
		let mut raw = evidence();
		raw["material_locations"] = json!(vec![raw["material_locations"][0].clone(); count]);
		assert!(serde_json::from_value::<FindingEvidenceV1>(raw).is_err());
	}
}

#[test]
fn nested_unknown_and_duplicate_fields_never_disappear() {
	for field in ["proof", "staged_artifact_ids", "fix_patch_unified"] {
		let mut raw = verified();
		raw[field] = json!([]);
		assert!(serde_json::from_value::<VerificationTerminalV1>(raw).is_err());
	}
	let mut raw = evidence();
	raw["l2_argument"]["unexpected"] = json!(true);
	assert!(serde_json::from_value::<FindingEvidenceV1>(raw).is_err());
	let duplicate = serde_json::to_string(&evidence()).unwrap().replace(
		"\"attacker_source\":\"Remote request\"",
		"\"attacker_source\":\"Remote request\",\"attacker_source\":\"Other\"",
	);
	assert!(FindingEvidenceV1::from_json(&duplicate).is_err());
	let duplicate = serde_json::to_string(&verified()).unwrap().replacen(
		"\"version\":1",
		"\"version\":1,\"version\":1",
		1,
	);
	assert!(VerificationTerminalV1::from_json(&duplicate).is_err());
}

#[test]
fn preproof_branches_require_their_own_evidence() {
	assert!(serde_json::from_value::<VerificationTerminalV1>(verified()).is_ok());
	for (field, replacement) in [
		("established_rung", json!("L3")),
		("e2e_applicability", json!("applicable")),
		("evidence", Value::Null),
	] {
		let mut raw = verified();
		raw[field] = replacement;
		assert!(serde_json::from_value::<VerificationTerminalV1>(raw).is_err());
	}
	let rejected = json!({"version":1,"verdict":"rejected","counterargument":{
		"argument":"The input is bounded", "source_refs":[{"path":"src/lib.rs"}]
	}});
	assert!(serde_json::from_value::<VerificationTerminalV1>(rejected.clone()).is_ok());
	let mut missing_refs = rejected.clone();
	missing_refs["counterargument"]["source_refs"] = json!([]);
	assert!(serde_json::from_value::<VerificationTerminalV1>(missing_refs).is_err());
	let mut irrelevant = rejected;
	irrelevant["established_rung"] = json!("L2");
	assert!(serde_json::from_value::<VerificationTerminalV1>(irrelevant).is_err());
	let inconclusive = json!({"version":1,"verdict":"inconclusive",
		"blocker":"awaiting proof infrastructure","continuation":"awaiting_proof_infrastructure"});
	assert!(serde_json::from_value::<VerificationTerminalV1>(inconclusive).is_ok());
}

#[test]
fn all_drilldown_dispositions_and_survey_are_expressible() {
	let source = json!({"argument":"The boundary enforces its contract", "source_refs":[{"path":"src/lib.rs"}]});
	for raw in [
		json!({"version":1,"disposition":"promote","promotion":promotion()}),
		json!({"version":1,"disposition":"reject","counterargument":source}),
		json!({"version":1,"disposition":"duplicate","target":{"kind":"finding","id":42},"rationale":"Same invariant"}),
		json!({"version":1,"disposition":"hardening","explanation":source}),
		json!({"version":1,"disposition":"defer","reason":"More source remains","continuation":"source_analysis_remaining"}),
	] {
		let value: DrilldownTerminalV1 = serde_json::from_value(raw).unwrap();
		assert!(DrilldownTerminalV1::from_json(
			std::str::from_utf8(&value.canonical_bytes().unwrap()).unwrap()
		)
		.is_ok());
	}
	assert!(serde_json::from_value::<SurveyTerminalV1>(
		json!({"version":1,"terminal_reason":"completed"})
	)
	.is_ok());
	assert!(serde_json::from_value::<SurveyTerminalV1>(
		json!({"version":1,"terminal_reason":"completed","inventory_dispositions":[]})
	)
	.is_err());
	let mut incomplete = promotion();
	incomplete.as_object_mut().unwrap().remove("identity_family");
	assert!(serde_json::from_value::<PromotionV1>(incomplete).is_err());
}

#[test]
fn destination_limits_accept_long_fields_without_relaxing_generic_json() {
	let mut raw = promotion();
	raw["description"] = json!("d".repeat(16_384));
	let accepted: PromotionV1 = serde_json::from_value(raw.clone()).unwrap();
	assert!(accepted.canonical_bytes().is_ok());
	raw["description"] = json!("d".repeat(16_385));
	assert!(serde_json::from_value::<PromotionV1>(raw.clone()).is_err());
	raw["description"] = json!("界".repeat(10_923));
	assert!(serde_json::from_value::<PromotionV1>(raw).is_err());
	let survey =
		json!({"version":1,"terminal_reason":"partial","security_model_notes":"n".repeat(8_000)});
	assert!(serde_json::from_value::<SurveyTerminalV1>(survey).is_ok());
	assert!(loupe_core::text::BoundedJson::<loupe_core::text::policy::Payload>::new(
		&json!({"text":"n".repeat(4_001)}).to_string()
	)
	.is_err());
}

#[test]
fn aggregate_limits_and_profile_limit_are_independent_of_leaf_limits() {
	let profile = json!({"a":"a".repeat(4_000),"b":"b".repeat(4_000)}).to_string();
	assert!(GeneratedProfile::new(&profile).is_ok());
	let mut oversized = serde_json::Map::new();
	for index in 0..9 {
		oversized.insert(format!("field_{index}"), json!("a".repeat(4_000)));
	}
	assert!(GeneratedProfile::new(&Value::Object(oversized).to_string()).is_err());
	let survey = json!({"version":1,"terminal_reason":"partial",
		"security_model_notes":"\"".repeat(8_000),"continuation":"\"".repeat(4_000)});
	assert!(serde_json::from_value::<SurveyTerminalV1>(survey).is_ok());
	let mut exact = serde_json::Map::new();
	for index in 0..8 {
		exact.insert(format!("field_{index}"), json!("a".repeat(4_000)));
	}
	exact.insert("remainder".into(), json!(""));
	let remaining = 32 * 1024 - serde_json::to_vec(&exact).unwrap().len();
	exact.insert("remainder".into(), json!("a".repeat(remaining)));
	let raw = serde_json::to_string(&exact).unwrap();
	assert_eq!(raw.len(), 32 * 1024);
	assert_eq!(GeneratedProfile::new(&raw).unwrap().canonical().len(), 32 * 1024);
	exact.insert("remainder".into(), json!("a".repeat(remaining + 1)));
	assert!(GeneratedProfile::new(&serde_json::to_string(&exact).unwrap()).is_err());
}

fn large_terminal_json(text: impl Fn(usize) -> String) -> Value {
	let mut full = promotion();
	full["severity"] = json!("critical");
	full["title"] = json!(text(100));
	full["description"] = json!(text(16_384));
	full["identity_family"] = json!("a".repeat(64));
	full["identity_anchor"] = json!(text(300));
	full["identity_instance_key"] = json!(text(200));
	full["cwe"] = json!(format!("CWE-{}", "9".repeat(60)));
	for name in ["attacker_source", "control", "sink"] {
		full["evidence"]["l2_argument"][name] = json!(text(2_000));
	}
	full["evidence"]["l2_argument"]["reachable_path"] = json!(text(4_000));
	full["evidence"]["l2_argument"]["trust_boundary"] = json!(text(1_000));
	full["evidence"]["counterevidence"] = json!(text(4_000));
	full["evidence"]["assumptions_gaps"] = json!(text(4_000));
	full["evidence"]["confidence"] = json!("medium");
	full["evidence"]["material_locations"] = json!(vec![
		json!({
			"role":"implementation", "file":"\"".repeat(512),
			"symbol":text(200), "line_start":u32::MAX, "line_end":u32::MAX
		});
		16
	]);
	let refs = vec![json!({"path":"\"".repeat(512), "symbol":text(256)}); 16];
	json!({"version":1,"disposition":"promote","promotion":full,
		"revalidation":{"current_source_refs":refs,"rationale":text(2_000)}})
}

#[test]
fn large_complete_terminal_retains_all_fields_under_the_aggregate_cap() {
	let raw = large_terminal_json(|chars| "\"".repeat(chars));
	let value: DrilldownTerminalV1 = serde_json::from_value(raw.clone()).unwrap();
	let bytes = value.canonical_bytes().unwrap();
	assert!(bytes.len() > 64 * 1024, "complete evidence cannot use generic 64 KiB JSON");
	assert!(bytes.len() <= DrilldownTerminalV1::MAX_BYTES);
	assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), raw);
	assert_eq!(
		DrilldownTerminalV1::from_json(std::str::from_utf8(&bytes).unwrap()).unwrap(),
		value
	);
}

#[test]
fn valid_leaf_limits_cannot_bypass_the_combined_terminal_byte_limit() {
	use loupe_core::review_payload::{Error, Revalidation, Version1};
	// N/2 quotes and N/2 three-byte characters use N characters and 2N
	// source bytes, but their canonical JSON content takes 2.5N bytes.
	let raw = large_terminal_json(|chars| "\"".repeat(chars / 2) + &"界".repeat(chars / 2));
	let promotion: PromotionV1 = serde_json::from_value(raw["promotion"].clone()).unwrap();
	assert!(promotion.canonical_bytes().is_ok(), "promotion is independently within its cap");
	let revalidation: Revalidation = serde_json::from_value(raw["revalidation"].clone()).unwrap();
	assert!(serde_json::to_string(&revalidation).is_ok(), "every revalidation field is valid");
	let canonical = loupe_core::canonical::canonical_bytes(&raw);
	assert!(canonical.len() > DrilldownTerminalV1::MAX_BYTES);
	let value = DrilldownTerminalV1::Promote {
		version: Version1,
		promotion: Box::new(promotion),
		revalidation: Some(revalidation),
	};
	assert!(
		matches!(
			value.canonical_bytes(),
			Err(Error::Bytes {
				field: "drilldown_terminal",
				max_bytes: DrilldownTerminalV1::MAX_BYTES
			})
		),
		"otherwise-valid public construction must fail the aggregate byte policy"
	);
	assert!(serde_json::to_string(&value)
		.unwrap_err()
		.to_string()
		.contains("drilldown_terminal: canonical payload exceeds"));
	assert!(serde_json::from_value::<DrilldownTerminalV1>(raw)
		.unwrap_err()
		.to_string()
		.contains("drilldown_terminal: canonical payload exceeds"));
	println!("valid-leaf terminal canonical bytes rejected: {}", canonical.len());
}
