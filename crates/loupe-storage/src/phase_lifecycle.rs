//! Payload-independent phase control. Callers own an immediate transaction;
//! worker-facing calls must first obtain exact LeaseControl authority in it.
use loupe_core::review_payload::GeneratedProfile;
use loupe_core::text::policy::{Payload, Reason};
use loupe_core::text::{BoundedJson, BoundedText};
use rusqlite::types::Value;
use rusqlite::{params, OptionalExtension, Transaction};

use crate::admission_policy::CampaignPolicyV2;
use crate::review::changed;
use crate::review_intents::{self, BlockReason};
use crate::scheduler::{CampaignPolicy, RetryOutcome};
use crate::{Conflict, Entity, Error, Result};

fn compatible_policy(raw: &Value, digest: &Value, attempt: u32) -> Option<(u32, i64)> {
	let (Value::Text(raw), Value::Blob(digest)) = (raw, digest) else { return None };
	let canonical = BoundedJson::<Payload>::new(raw).ok()?;
	if canonical.expose() != raw || canonical.digest().as_slice() != digest {
		return None;
	}
	if let Ok(policy) = CampaignPolicyV2::from_json(raw) {
		return Some((policy.max_attempts, policy.retry_delay(attempt)));
	}
	// Historical execution control only. This does not authorize v1 admission.
	let policy: CampaignPolicy = serde_json::from_str(raw).ok()?;
	policy.validate().ok()?;
	Some((policy.max_attempts, policy.retry_delay(attempt)))
}
fn compatible_recipe(value: &Value) -> bool {
	match value {
		Value::Null => true,
		Value::Text(raw) => BoundedJson::<Payload>::new(raw).is_ok(),
		_ => false,
	}
}
fn compatible_profile(value: &Value) -> bool {
	match value {
		Value::Null => true,
		Value::Text(raw) => GeneratedProfile::new(raw).is_ok(),
		_ => false,
	}
}

/// Decide an execution retry without decoding job/generation/subject objects.
/// Known incompatible stored payloads fail safely; database failures propagate.
pub fn retry_or_fail(
	tx: &Transaction<'_>, job: i64, now: i64, error: &BoundedText<Reason>,
) -> Result<RetryOutcome> {
	let row=tx.query_row("SELECT j.state,j.kind,j.campaign_id,j.attempts,c.state,c.deadline_at,c.effective_policy,c.effective_policy_digest,j.recipe,g.generated_profile FROM jobs j LEFT JOIN review_campaigns c ON c.campaign_id=j.campaign_id AND c.repo_id=j.repo_id LEFT JOIN review_generations g ON g.generation_id=j.generation_id AND g.repo_id=j.repo_id WHERE j.id=?1",[job],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<i64>>(2)?,r.get::<_,i64>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,Option<i64>>(5)?,r.get::<_,Value>(6)?,r.get::<_,Value>(7)?,r.get::<_,Value>(8)?,r.get::<_,Value>(9)?))).optional()?.ok_or(Error::NotFound(Entity::Job,job))?;
	let (
		state,
		kind,
		campaign,
		attempts,
		campaign_state,
		deadline,
		policy,
		digest,
		recipe,
		profile,
	) = row;
	if state != "leased"
		|| !matches!(kind.as_str(), "survey" | "drilldown" | "verify")
		|| campaign.is_none()
	{
		return Err(Error::Conflict(Conflict::JobState));
	}
	let (reason, message) = if campaign_state.as_deref() != Some("active") {
		(BlockReason::CampaignCancelled, "campaign inactive")
	} else if deadline.is_some_and(|at| at <= now) {
		(BlockReason::CampaignDeadline, "campaign deadline")
	} else if !compatible_recipe(&recipe) || !compatible_profile(&profile) {
		(BlockReason::CompatibilityPolicy, "incompatible stored review payload")
	} else if let Ok(attempt) = u32::try_from(attempts)
		&& attempt > 0
		&& let Some((maximum, delay)) = compatible_policy(&policy, &digest, attempt)
	{
		if attempt >= maximum {
			(BlockReason::ExecutionExhausted, error.expose())
		} else if let Some(eligible) = now.checked_add(delay) {
			changed(tx.execute("UPDATE jobs SET state='queued',worker_id=NULL,lease_expires_at=NULL,job_capability_hash=NULL,prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL,eligible_at=?2,hard_deadline_at=NULL,soft_deadline_at=NULL,submit_by=NULL,error=?3 WHERE id=?1 AND state='leased'",params![job,eligible,error.expose()])?,Conflict::JobState)?;
			return Ok(RetryOutcome::Requeued { eligible_at: eligible });
		} else {
			(BlockReason::CompatibilityPolicy, "retry timestamp overflow")
		}
	} else {
		(BlockReason::CompatibilityPolicy, "incompatible CampaignPolicy")
	};
	terminalize(tx, job, now, "failed", message, reason)?;
	Ok(RetryOutcome::Failed)
}

fn terminalize(
	tx: &Transaction<'_>, job: i64, now: i64, state: &str, message: &str, reason: BlockReason,
) -> Result<()> {
	changed(tx.execute("UPDATE jobs SET state=?2,error=?3,finished_at=?4,worker_id=NULL,lease_expires_at=NULL,job_capability_hash=NULL,prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL,hard_deadline_at=NULL,soft_deadline_at=NULL,submit_by=NULL WHERE id=?1 AND campaign_id IS NOT NULL AND kind IN('survey','drilldown','verify') AND state IN('queued','leased')",params![job,state,message,now])?,Conflict::JobState)?;
	review_intents::block_job_work(tx, job, reason, now)
}

/// Individual administrative cancellation is immediate, unlike campaign soft-stop.
pub fn cancel(tx: &Transaction<'_>, job: i64, now: i64) -> Result<()> {
	terminalize(
		tx,
		job,
		now,
		"cancelled",
		crate::jobs::JOB_CANCELLED_BY_ADMIN_ERROR,
		BlockReason::CampaignCancelled,
	)
}

pub(crate) fn cancel_queued(
	tx: &Transaction<'_>, campaign: i64, now: i64, error: &BoundedText<Reason>,
) -> Result<usize> {
	let deadline: Option<i64> = tx.query_row(
		"SELECT deadline_at FROM review_campaigns WHERE campaign_id=?1",
		[campaign],
		|r| r.get(0),
	)?;
	let reason = if deadline.is_some_and(|at| at <= now) {
		BlockReason::CampaignDeadline
	} else {
		BlockReason::CampaignCancelled
	};
	let ids:Vec<i64>=tx.prepare("SELECT id FROM jobs WHERE campaign_id=?1 AND state='queued' AND kind IN('survey','drilldown','verify')")?.query_map([campaign],|r|r.get(0))?.collect::<rusqlite::Result<_>>()?;
	for job in &ids {
		terminalize(tx, *job, now, "cancelled", error.expose(), reason)?;
	}
	Ok(ids.len())
}

/// Checked live deployment clamp; grace permits reporting, never Domain writes.
pub fn heartbeat(
	tx: &Transaction<'_>, job: i64, now: i64, lease_seconds: i64, grace_seconds: i64,
) -> Result<i64> {
	if lease_seconds <= 0 || grace_seconds <= 0 || grace_seconds > lease_seconds {
		return Err(Error::Conflict(Conflict::CampaignPolicy));
	}
	let deadline:Option<i64>=tx.query_row("SELECT hard_deadline_at FROM jobs WHERE id=?1 AND campaign_id IS NOT NULL AND state='leased' AND lease_expires_at>?2",params![job,now],|r|r.get(0))?;
	let until = now
		.checked_add(lease_seconds)
		.zip(deadline.and_then(|at| at.checked_add(grace_seconds)))
		.map(|(lease, hard)| lease.min(hard))
		.filter(|until| *until > now)
		.ok_or(Error::Conflict(Conflict::JobState))?;
	changed(
		tx.execute(
			"UPDATE jobs SET lease_expires_at=?2 WHERE id=?1 AND state='leased'",
			params![job, until],
		)?,
		Conflict::JobState,
	)?;
	Ok(until)
}
