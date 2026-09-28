//! Frozen version-2 policy and pure admission decisions. No live claim producer.
use loupe_core::review_priority::{Access, Impact, Reachability};
use loupe_core::text::policy::Payload;
use loupe_core::text::BoundedJson;
use loupe_core::JobKind;
use serde::{Deserialize, Serialize};

use crate::scheduler::{Band, CampaignPolicy, PhasePolicy};
use crate::{Conflict, Error, Result};

pub const PRIORITY_POLICY_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignPolicyV2 {
	pub version: u32,
	pub survey_units_per_job: i64,
	pub survey_deadline_seconds: i64,
	pub survey_submit_margin_seconds: i64,
	pub drilldown_deadline_seconds: i64,
	pub drilldown_submit_margin_seconds: i64,
	pub verify_deadline_seconds: i64,
	pub verify_submit_margin_seconds: i64,
	pub max_attempts: u32,
	pub retry_backoff_base_seconds: i64,
	pub retry_backoff_cap_seconds: i64,
	pub campaign_deadline_seconds: i64,
	pub campaign_max_jobs: i64,
	#[serde(deserialize_with = "required_option")]
	pub survey_token_budget: Option<u64>,
	#[serde(deserialize_with = "required_option")]
	pub drilldown_token_budget: Option<u64>,
	#[serde(deserialize_with = "required_option")]
	pub verify_token_budget: Option<u64>,
	pub max_units_per_survey: u32,
	pub max_leads_per_survey: u32,
	pub max_sibling_leads_per_drilldown: u32,
	pub campaign_urgent_reserve: i64,
	pub campaign_verification_reserve: i64,
	pub priority_policy_version: u32,
}

impl Default for CampaignPolicyV2 {
	fn default() -> Self {
		let execution = CampaignPolicy::default();
		Self {
			version: 2,
			survey_units_per_job: execution.survey_units_per_job,
			survey_deadline_seconds: execution.survey_deadline_seconds,
			survey_submit_margin_seconds: execution.survey_submit_margin_seconds,
			drilldown_deadline_seconds: execution.drilldown_deadline_seconds,
			drilldown_submit_margin_seconds: execution.drilldown_submit_margin_seconds,
			verify_deadline_seconds: execution.verify_deadline_seconds,
			verify_submit_margin_seconds: execution.verify_submit_margin_seconds,
			max_attempts: execution.max_attempts,
			retry_backoff_base_seconds: execution.retry_backoff_base_seconds,
			retry_backoff_cap_seconds: execution.retry_backoff_cap_seconds,
			campaign_deadline_seconds: execution.campaign_deadline_seconds,
			campaign_max_jobs: execution.campaign_max_jobs,
			survey_token_budget: execution.survey_token_budget,
			drilldown_token_budget: execution.drilldown_token_budget,
			verify_token_budget: execution.verify_token_budget,
			max_units_per_survey: 32,
			max_leads_per_survey: 16,
			max_sibling_leads_per_drilldown: 4,
			campaign_urgent_reserve: 4,
			campaign_verification_reserve: 4,
			priority_policy_version: PRIORITY_POLICY_VERSION,
		}
	}
}

fn invalid() -> Error {
	Error::Conflict(Conflict::CampaignPolicy)
}

fn required_option<'de, D: serde::Deserializer<'de>>(
	deserializer: D,
) -> std::result::Result<Option<u64>, D::Error> {
	Option::<u64>::deserialize(deserializer)
}

impl CampaignPolicyV2 {
	pub fn from_snapshot(snapshot: &BoundedJson<Payload>) -> Result<Self> {
		Self::from_json(snapshot.expose())
	}

	/// Parse stored bytes before a generic JSON value can erase duplicate keys.
	pub fn from_json(raw: &str) -> Result<Self> {
		let policy: Self = serde_json::from_str(raw).map_err(|_| invalid())?;
		policy.validate()?;
		Ok(policy)
	}

	pub fn snapshot(&self) -> Result<BoundedJson<Payload>> {
		self.validate()?;
		Ok(BoundedJson::new(&serde_json::to_string(self).map_err(|_| invalid())?)?)
	}

	pub fn validate(&self) -> Result<()> {
		self.execution().validate()?;
		if self.version != 2
			|| self.priority_policy_version != PRIORITY_POLICY_VERSION
			|| self.max_units_per_survey == 0
			|| self.max_leads_per_survey == 0
			|| self.max_sibling_leads_per_drilldown == 0
			|| self.campaign_urgent_reserve < 0
			|| self.campaign_verification_reserve < 0
			|| self
				.campaign_urgent_reserve
				.checked_add(self.campaign_verification_reserve)
				.is_none_or(|sum| sum >= self.campaign_max_jobs)
		{
			return Err(invalid());
		}
		Ok(())
	}

	/// A private execution-only view shares deadlines/retry validation. It does
	/// not decode or upgrade a historical snapshot or assign historical pools.
	fn execution(&self) -> CampaignPolicy {
		CampaignPolicy {
			version: 1,
			survey_units_per_job: self.survey_units_per_job,
			survey_deadline_seconds: self.survey_deadline_seconds,
			survey_submit_margin_seconds: self.survey_submit_margin_seconds,
			drilldown_deadline_seconds: self.drilldown_deadline_seconds,
			drilldown_submit_margin_seconds: self.drilldown_submit_margin_seconds,
			verify_deadline_seconds: self.verify_deadline_seconds,
			verify_submit_margin_seconds: self.verify_submit_margin_seconds,
			max_attempts: self.max_attempts,
			retry_backoff_base_seconds: self.retry_backoff_base_seconds,
			retry_backoff_cap_seconds: self.retry_backoff_cap_seconds,
			campaign_handoff_reserve: 0,
			campaign_deadline_seconds: self.campaign_deadline_seconds,
			campaign_max_jobs: self.campaign_max_jobs,
			survey_token_budget: self.survey_token_budget,
			drilldown_token_budget: self.drilldown_token_budget,
			verify_token_budget: self.verify_token_budget,
		}
	}

	pub fn phase(&self, kind: &JobKind) -> Result<PhasePolicy> {
		self.execution().phase(kind)
	}
	pub fn retry_delay(&self, attempt: u32) -> i64 {
		self.execution().retry_delay(attempt)
	}

	/// Sequence belongs to the logical continuation chain, never lease attempts.
	pub fn logical_delay(&self, sequence: u64) -> Result<i64> {
		self.validate()?;
		if sequence == 0 {
			return Err(invalid());
		}
		let exponent = u32::try_from(sequence - 1).unwrap_or(u32::MAX);
		let multiplier = 2_i64.checked_pow(exponent).unwrap_or(i64::MAX);
		Ok(self
			.retry_backoff_base_seconds
			.saturating_mul(multiplier)
			.min(self.retry_backoff_cap_seconds))
	}

	pub fn logical_not_before(&self, now: i64, sequence: u64) -> Result<i64> {
		now.checked_add(self.logical_delay(sequence)?).ok_or_else(invalid)
	}

	pub fn general_capacity(&self) -> Result<i64> {
		self.validate()?;
		Ok(self.campaign_max_jobs
			- self.campaign_urgent_reserve
			- self.campaign_verification_reserve)
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedPriority {
	pub band: Band,
	pub score: u32,
}

/// Inputs describe endpoint-validated evidence. No agent band is accepted;
/// missing structural/source support always falls back to ordinary rank.
pub fn classify_priority(
	impact: Impact, access: Access, reachability: Reachability, boundary_cited: bool,
	structurally_supported: bool,
) -> AcceptedPriority {
	if !structurally_supported {
		return AcceptedPriority { band: Band::Normal, score: 0 };
	}
	let traced = reachability == Reachability::Traced;
	let high_impact = matches!(impact, Impact::High | Impact::Critical);
	let band = if high_impact && access == Access::Remote && traced && boundary_cited {
		Band::Urgent
	} else if high_impact && traced {
		Band::High
	} else if impact == Impact::Low {
		Band::Background
	} else {
		Band::Normal
	};
	let score = match impact {
		Impact::Low => 0,
		Impact::Medium => 100,
		Impact::High => 200,
		Impact::Critical => 300,
	} + match access {
		Access::Privileged => 0,
		Access::Local => 50,
		Access::Remote => 100,
	} + if traced { 100 } else { 0 }
		+ if boundary_cited { 50 } else { 0 };
	AcceptedPriority { band, score }
}

#[cfg(test)]
mod tests;
