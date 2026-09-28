//! Monotonic admission accounting in the caller's creation/first-lease transaction.
//! No helper here enqueues a speculative child or selects from a second queue.
use loupe_core::JobKind;
use rusqlite::{params, OptionalExtension, Transaction};

use crate::admission_policy::CampaignPolicyV2;
use crate::review::{parsed, string_enum};
use crate::{campaigns, Conflict, Entity, Error, Result};

string_enum!(Pool { General => "general", Urgent => "urgent", Verification => "verification" });

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkClass {
	Preparation,
	Survey,
	Drilldown,
	UrgentDrilldown,
	Verification,
	UrgentVerification,
}

impl WorkClass {
	fn pools(self) -> &'static [Pool] {
		match self {
			Self::Preparation | Self::Survey | Self::Drilldown => &[Pool::General],
			Self::UrgentDrilldown => &[Pool::General, Pool::Urgent],
			Self::Verification => &[Pool::General, Pool::Verification],
			Self::UrgentVerification => &[Pool::General, Pool::Verification, Pool::Urgent],
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Spending {
	pub general: i64,
	pub urgent: i64,
	pub verification: i64,
}

impl Spending {
	pub fn total(self) -> Result<i64> {
		self.general
			.checked_add(self.urgent)
			.and_then(|sum| sum.checked_add(self.verification))
			.filter(|_| self.general >= 0 && self.urgent >= 0 && self.verification >= 0)
			.ok_or(Error::Conflict(Conflict::CampaignPolicy))
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityRefusal {
	CampaignBudget,
	ProtectedCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
	Pool(Pool),
	Refused(CapacityRefusal),
}

pub fn choose_pool(
	policy: &CampaignPolicyV2, spent: Spending, class: WorkClass,
) -> Result<Selection> {
	let general = policy.general_capacity()?;
	let total = spent.total()?;
	if spent.general > general
		|| spent.urgent > policy.campaign_urgent_reserve
		|| spent.verification > policy.campaign_verification_reserve
	{
		return Err(Error::Conflict(Conflict::CampaignPolicy));
	}
	if total == policy.campaign_max_jobs {
		return Ok(Selection::Refused(CapacityRefusal::CampaignBudget));
	}
	for pool in class.pools() {
		let available = match pool {
			Pool::General => spent.general < general,
			Pool::Urgent => spent.urgent < policy.campaign_urgent_reserve,
			Pool::Verification => spent.verification < policy.campaign_verification_reserve,
		};
		if available {
			return Ok(Selection::Pool(*pool));
		}
	}
	Ok(Selection::Refused(CapacityRefusal::ProtectedCapacity))
}

pub fn get_spending(tx: &Transaction<'_>, campaign: i64) -> Result<Option<Spending>> {
	Ok(tx.query_row("SELECT general_spent,urgent_spent,verification_spent FROM campaign_admission_spending WHERE campaign_id=?1 AND policy_version=2",
		[campaign], |row| Ok(Spending { general: row.get(0)?, urgent: row.get(1)?, verification: row.get(2)? })).optional()?)
}

/// Validate exact frozen bytes/digest, never reinterpret them through live defaults.
pub fn load_policy(tx: &Transaction<'_>, campaign: i64) -> Result<CampaignPolicyV2> {
	let (raw, digest) = tx.query_row("SELECT effective_policy,effective_policy_digest FROM review_campaigns WHERE campaign_id=?1",
		[campaign], |row| Ok((row.get::<_,String>(0)?,row.get::<_,Vec<u8>>(1)?)))
		.optional()?.ok_or(Error::NotFound(Entity::Campaign, campaign))?;
	let policy = CampaignPolicyV2::from_json(&raw)?;
	let canonical = policy.snapshot()?;
	if canonical.expose() != raw || canonical.digest().as_slice() != digest {
		return Err(Error::Conflict(Conflict::CampaignPolicy));
	}
	Ok(policy)
}

/// Initialize before creating a new campaign's first preparation job. Never
/// infer old charges from surviving rows or retrofit version-1 campaigns.
pub fn initialize(tx: &Transaction<'_>, campaign_id: i64) -> Result<Spending> {
	let campaign =
		campaigns::get(tx, campaign_id)?.ok_or(Error::NotFound(Entity::Campaign, campaign_id))?;
	let policy = load_policy(tx, campaign_id)?;
	if let Some(spent) = get_spending(tx, campaign_id)? {
		choose_pool(&policy, spent, WorkClass::Preparation)?;
		return Ok(spent);
	}
	let nonempty: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM jobs WHERE campaign_id=?1)",
		[campaign_id],
		|row| row.get(0),
	)?;
	if nonempty || campaign.state != campaigns::State::Active {
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	tx.execute(
		"INSERT INTO campaign_admission_spending(campaign_id,policy_version) VALUES(?1,2)",
		[campaign_id],
	)?;
	Ok(Spending::default())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charged {
	Fresh(Pool),
	Replayed(Pool),
	Refused(CapacityRefusal),
}

/// The selector creates and leases a chosen child before calling this helper
/// in that same transaction. Execution retry returns its original charge.
pub fn charge(tx: &Transaction<'_>, job_id: i64, class: WorkClass, now: i64) -> Result<Charged> {
	let row = tx.query_row(
		"SELECT campaign_id,kind,scheduling_band,state,attempts,continuation_of_job_id,
		 worker_id IS NOT NULL AND job_capability_hash IS NOT NULL AND length(job_capability_hash)=32 AND lease_expires_at>?2,repo_id
		 FROM jobs WHERE id=?1", params![job_id,now], |row| Ok((row.get::<_,Option<i64>>(0)?,
		 parsed::<JobKind>(row,1)?, row.get::<_,Option<String>>(2)?, row.get::<_,String>(3)?, row.get::<_,i64>(4)?, row.get::<_,Option<i64>>(5)?, row.get::<_,Option<bool>>(6)?.unwrap_or(false),row.get::<_,i64>(7)?)),
	).optional()?.ok_or(Error::NotFound(Entity::Job, job_id))?;
	let (campaign_id, kind, band, state, attempts, continuation, live_lease, repo_id) = row;
	let campaign_id = campaign_id.ok_or(Error::Conflict(Conflict::CampaignPolicy))?;
	let campaign =
		campaigns::get(tx, campaign_id)?.ok_or(Error::NotFound(Entity::Campaign, campaign_id))?;
	let policy = load_policy(tx, campaign_id)?;
	if repo_id != campaign.repo_id {
		return Err(Error::Conflict(Conflict::CampaignPolicy));
	}
	let compatible = match class {
		WorkClass::Preparation | WorkClass::Survey => kind == JobKind::Survey,
		WorkClass::Drilldown => kind == JobKind::Drilldown && band.as_deref() != Some("urgent"),
		WorkClass::UrgentDrilldown => {
			kind == JobKind::Drilldown && band.as_deref() == Some("urgent")
		},
		WorkClass::Verification => kind == JobKind::Verify && band.as_deref() != Some("urgent"),
		WorkClass::UrgentVerification => {
			kind == JobKind::Verify && band.as_deref() == Some("urgent")
		},
	};
	if !compatible || !matches!(band.as_deref(), Some("urgent" | "high" | "normal" | "background"))
	{
		return Err(Error::Conflict(Conflict::JobState));
	}
	let spent = get_spending(tx, campaign_id)?.ok_or(Error::Conflict(Conflict::CampaignPolicy))?;
	choose_pool(&policy, spent, class)?;
	let existing: Option<Pool> = tx
		.query_row(
			"SELECT pool FROM job_admission_charges WHERE job_id=?1 AND campaign_id=?2",
			params![job_id, campaign_id],
			|row| parsed(row, 0),
		)
		.optional()?;
	if let Some(pool) = existing {
		if !class.pools().contains(&pool) {
			return Err(Error::Conflict(Conflict::CampaignPolicy));
		}
		return Ok(Charged::Replayed(pool));
	}
	if campaign.state != campaigns::State::Active
		|| campaign.deadline_at.is_some_and(|deadline| deadline <= now)
	{
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	let valid_state = if class == WorkClass::Preparation {
		state == "queued"
			&& attempts == 0
			&& continuation.is_none()
			&& spent.total()? == 0
			&& tx.query_row(
				"SELECT COUNT(*)=1 FROM jobs WHERE campaign_id=?1",
				[campaign_id],
				|row| row.get::<_, bool>(0),
			)?
	} else {
		state == "leased" && attempts == 1 && live_lease
	};
	if !valid_state {
		return Err(Error::Conflict(Conflict::JobState));
	}
	let pool = match choose_pool(&policy, spent, class)? {
		Selection::Pool(pool) => pool,
		Selection::Refused(reason) => return Ok(Charged::Refused(reason)),
	};
	let column = match pool {
		Pool::General => "general_spent",
		Pool::Urgent => "urgent_spent",
		Pool::Verification => "verification_spent",
	};
	tx.execute(
		&format!("UPDATE campaign_admission_spending SET {column}={column}+1 WHERE campaign_id=?1"),
		[campaign_id],
	)?;
	tx.execute(
		"INSERT INTO job_admission_charges(job_id,campaign_id,pool) VALUES(?1,?2,?3)",
		params![job_id, campaign_id, pool.as_str()],
	)?;
	Ok(Charged::Fresh(pool))
}

#[cfg(test)]
mod tests;
