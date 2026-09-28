use super::*;

#[test]
fn v2_snapshot_is_strict_complete_and_never_upgrades_v1() {
	let policy = CampaignPolicyV2::default();
	let snapshot = policy.snapshot().unwrap();
	assert_eq!(CampaignPolicyV2::from_snapshot(&snapshot).unwrap(), policy);
	assert_eq!(policy.general_capacity().unwrap(), 56);
	assert!(CampaignPolicy::from_snapshot(&snapshot).is_err());
	let old =
		BoundedJson::new(&serde_json::to_string(&CampaignPolicy::default()).unwrap()).unwrap();
	let old_bytes = old.expose().to_owned();
	assert!(CampaignPolicyV2::from_snapshot(&old).is_err());
	assert_eq!(old.expose(), old_bytes);
	assert!(CampaignPolicy::from_snapshot(&old).is_ok());
	let value: serde_json::Value = serde_json::from_str(snapshot.expose()).unwrap();
	for key in value.as_object().unwrap().keys() {
		let mut missing = value.clone();
		missing.as_object_mut().unwrap().remove(key);
		assert!(CampaignPolicyV2::from_json(&missing.to_string()).is_err(), "missing {key}");
	}
	let duplicate = snapshot.expose().replacen("{", "{\"version\":2,", 1);
	assert!(CampaignPolicyV2::from_json(&duplicate).is_err());
	let mut unknown = value;
	unknown["campaign_handoff_reserve"] = 2.into();
	assert!(CampaignPolicyV2::from_json(&unknown.to_string()).is_err());
}

#[test]
fn v2_rejects_invalid_frozen_limits_and_checked_reserve_overflow() {
	let value = serde_json::to_value(CampaignPolicyV2::default()).unwrap();
	for (key, bad) in [
		("version", 1),
		("priority_policy_version", 2),
		("survey_units_per_job", 33),
		("max_units_per_survey", 0),
		("max_leads_per_survey", 0),
		("max_sibling_leads_per_drilldown", 0),
		("campaign_urgent_reserve", -1),
		("campaign_verification_reserve", -1),
		("campaign_urgent_reserve", 60),
		("campaign_urgent_reserve", i64::MAX),
		("campaign_max_jobs", 0),
		("max_attempts", 0),
		("retry_backoff_base_seconds", 0),
		("retry_backoff_base_seconds", 3601),
		("verify_submit_margin_seconds", 3600),
		("campaign_deadline_seconds", 3599),
		("verify_token_budget", 0),
	] {
		let mut invalid = value.clone();
		invalid[key] = bad.into();
		assert!(CampaignPolicyV2::from_json(&invalid.to_string()).is_err(), "{key}={bad}");
	}
	let policy = CampaignPolicyV2 {
		max_units_per_survey: u32::MAX,
		max_leads_per_survey: u32::MAX,
		max_sibling_leads_per_drilldown: u32::MAX,
		campaign_max_jobs: 1,
		campaign_urgent_reserve: 0,
		campaign_verification_reserve: 0,
		..CampaignPolicyV2::default()
	};
	assert_eq!(policy.general_capacity().unwrap(), 1);
}

#[test]
fn logical_backoff_uses_sequence_not_attempts_and_never_busy_polls() {
	let policy = CampaignPolicyV2::default();
	for (sequence, delay) in [(1, 60), (2, 120), (3, 240), (7, 3600), (u64::MAX, 3600)] {
		assert_eq!(policy.logical_delay(sequence).unwrap(), delay);
		assert_eq!(policy.logical_not_before(100, sequence).unwrap(), 100 + delay);
	}
	assert!(policy.logical_delay(0).is_err());
	assert!(policy.logical_not_before(i64::MAX, 1).is_err());
	assert_eq!(policy.retry_delay(3), 240);
	assert_eq!(policy.phase(&JobKind::Verify).unwrap().deadline_seconds, 3600);
}

#[test]
fn every_priority_combination_obeys_supported_risk_policy() {
	for (impact, impact_score) in
		[(Impact::Low, 0), (Impact::Medium, 100), (Impact::High, 200), (Impact::Critical, 300)]
	{
		for (access, access_score) in
			[(Access::Privileged, 0), (Access::Local, 50), (Access::Remote, 100)]
		{
			for reachability in [Reachability::Plausible, Reachability::Traced] {
				for boundary in [false, true] {
					let accepted = classify_priority(impact, access, reachability, boundary, true);
					let traced = reachability == Reachability::Traced;
					assert_eq!(
						accepted.score,
						impact_score
							+ access_score
							+ if traced { 100 } else { 0 }
							+ if boundary { 50 } else { 0 }
					);
					assert!(accepted.score <= 550);
					let high = matches!(impact, Impact::High | Impact::Critical);
					assert_eq!(
						accepted.band == Band::Urgent,
						high && access == Access::Remote && traced && boundary
					);
					assert_eq!(
						accepted.band == Band::High,
						high && traced && !(access == Access::Remote && boundary)
					);
					assert_eq!(accepted.band == Band::Background, impact == Impact::Low);
					assert_eq!(
						classify_priority(impact, access, reachability, boundary, false),
						AcceptedPriority { band: Band::Normal, score: 0 }
					);
				}
			}
		}
	}
}
