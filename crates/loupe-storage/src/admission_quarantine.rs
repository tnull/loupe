//! Durable exclusion of one permanently incompatible admission source.
//! The server chooses the category; this layer never changes canonical verdicts,
//! evidence, admission spending, assignment epochs or scheduler fairness.
use rusqlite::{params, Transaction};

use crate::{Conflict, Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
	Job(i64),
	Lead(i64),
	Finding(i64),
	Batch(i64),
	Unit(i64),
	Ordinary(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
	InvalidData,
	CompatibilityPolicy,
	UnsupportedRecipe,
}
impl Reason {
	pub fn diagnostic(self) -> &'static str {
		match self {
			Self::InvalidData => "invalid_review_state",
			Self::CompatibilityPolicy => "compatibility_policy",
			Self::UnsupportedRecipe => "unsupported_recipe",
		}
	}
	fn block(self) -> &'static str {
		match self {
			Self::UnsupportedRecipe => "unsupported_recipe",
			_ => "compatibility_policy",
		}
	}
}

/// Must follow rollback of the tentative candidate savepoint. Queued-job holds
/// affect only work admitted to it, never independent accepted producer leads.
pub fn hold(tx: &Transaction<'_>, source: Source, reason: Reason, now: i64) -> Result<bool> {
	let block = reason.block();
	let changed=match source {
		Source::Job(id)=>{
			let n=tx.execute("UPDATE jobs SET state=?2,error=?3,finished_at=?4,worker_id=NULL,lease_expires_at=NULL,job_capability_hash=NULL,prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id=?1 AND state='queued'",params![id,if reason==Reason::InvalidData {"failed"}else{"cancelled"},reason.diagnostic(),now])?;
			if n>0 {
				for table in ["lead_drilldown_intents","finding_verification_intents"] {
					tx.execute(&format!("UPDATE {table} SET state='blocked',block_reason=?2,not_before=NULL,updated_at=?3 WHERE admitted_job_id=?1 AND state='admitted'"),params![id,block,now])?;
				}
				tx.execute("UPDATE review_unit_holds SET block_reason=?2,updated_at=?3 WHERE pending_batch_id IN(SELECT batch_id FROM survey_continuation_batches WHERE admitted_job_id=?1)",params![id,block,now])?;
				tx.execute("UPDATE survey_continuation_batches SET state='blocked',block_reason=?2,not_before=NULL WHERE admitted_job_id=?1 AND state='admitted'",params![id,block])?;
				tx.execute("UPDATE review_units SET status='deferred',defer_reason=?2 WHERE status='open' AND EXISTS(SELECT 1 FROM job_assigned_review_units a WHERE a.job_id=?1 AND a.review_unit_id=review_units.review_unit_id AND a.completed=0 AND a.assignment_epoch=review_units.assignment_epoch)",params![id,reason.diagnostic()])?;
			} n
		},
		Source::Lead(id)=>tx.execute("UPDATE lead_drilldown_intents SET state='blocked',block_reason=?2,not_before=NULL,updated_at=?3 WHERE lead_id=?1 AND state='pending'",params![id,block,now])?,
		Source::Finding(id)=>tx.execute("UPDATE finding_verification_intents SET state='blocked',block_reason=?2,not_before=NULL,updated_at=?3 WHERE finding_id=?1 AND state='pending'",params![id,block,now])?,
		Source::Batch(id)=>{
			let n=tx.execute("UPDATE survey_continuation_batches SET state='blocked',block_reason=?2,not_before=NULL WHERE batch_id=?1 AND state='pending'",params![id,block])?;
			if n>0 { tx.execute("UPDATE review_unit_holds SET block_reason=?2,updated_at=?3 WHERE pending_batch_id=?1",params![id,block,now])?; } n
		},
		Source::Unit(id)=>tx.execute("UPDATE review_units SET status='deferred',defer_reason=?2 WHERE review_unit_id=?1 AND status='open' AND NOT EXISTS(SELECT 1 FROM job_assigned_review_units a JOIN jobs j ON j.id=a.job_id WHERE a.review_unit_id=?1 AND j.state IN('queued','leased'))",params![id,reason.diagnostic()])?,
		Source::Ordinary(generation)=>tx.execute(&format!("UPDATE review_units SET status='deferred',defer_reason=?2 WHERE review_unit_id IN(SELECT u.review_unit_id FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.generation_id=?1 AND {})",*crate::review_units::UNIT_NEEDS_WORK),params![generation,reason.diagnostic()])?,
	};
	Ok(changed > 0)
}

/// Opaque continuation for a bounded independent maintenance walk. It is not
/// admission order or persistent scheduling state; restart begins a new walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
	source: i64,
	id: i64,
}
impl Cursor {
	pub fn after(source: Source) -> Result<Self> {
		let (source, id) = match source {
			Source::Job(id) => (0, id),
			Source::Lead(id) => (1, id),
			Source::Finding(id) => (2, id),
			Source::Batch(id) => (3, id),
			Source::Unit(id) => (4, id),
			Source::Ordinary(_) => return Err(Error::Conflict(Conflict::JobState)),
		};
		Ok(Self { source, id })
	}
}

pub fn page(
	tx: &Transaction<'_>, campaign: i64, cursor: Option<Cursor>, limit: u32,
) -> Result<Vec<Source>> {
	if !(1..=256).contains(&limit) {
		return Err(Error::Conflict(Conflict::CampaignPolicy));
	}
	let cursor = cursor.unwrap_or(Cursor { source: -1, id: 0 });
	let sql="WITH candidates(source,id) AS (
	 SELECT 0,id FROM jobs WHERE campaign_id=?1 AND state='queued'
	 UNION ALL SELECT 1,lead_id FROM lead_drilldown_intents WHERE admission_campaign_id=?1 AND state='pending'
	 UNION ALL SELECT 2,finding_id FROM finding_verification_intents WHERE admission_campaign_id=?1 AND state='pending'
	 UNION ALL SELECT 3,batch_id FROM survey_continuation_batches WHERE campaign_id=?1 AND state='pending'
	 UNION ALL SELECT 4,u.review_unit_id FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id JOIN review_campaigns c ON c.generation_id=g.generation_id AND c.repo_id=g.repo_id
	 WHERE c.campaign_id=?1 AND g.state='active' AND u.status='open' AND u.stale=0
	 AND NOT EXISTS(SELECT 1 FROM review_unit_holds h WHERE h.review_unit_id=u.review_unit_id)
	 AND NOT EXISTS(SELECT 1 FROM job_assigned_review_units a JOIN jobs j ON j.id=a.job_id WHERE a.review_unit_id=u.review_unit_id AND j.state IN('queued','leased')))
	 SELECT source,id FROM candidates WHERE source>?2 OR (source=?2 AND id>?3) ORDER BY source,id LIMIT ?4";
	Ok(tx
		.prepare(sql)?
		.query_map(params![campaign, cursor.source, cursor.id, limit], |r| {
			let id = r.get(1)?;
			Ok(match r.get::<_, i64>(0)? {
				0 => Source::Job(id),
				1 => Source::Lead(id),
				2 => Source::Finding(id),
				3 => Source::Batch(id),
				4 => Source::Unit(id),
				_ => return Err(rusqlite::Error::InvalidQuery),
			})
		})?
		.collect::<rusqlite::Result<_>>()?)
}
