//! Bounded, metadata-only campaign maintenance. This is not an admission queue:
//! it never ranks candidates, creates jobs, or consumes a pool.
use rusqlite::{params, OptionalExtension, Transaction};

use crate::admission::WorkClass;
use crate::review_intents::BlockReason;
use crate::scheduler::Band;
use crate::{review_units, Entity, Error, Result};

/// Check ready-generation provenance without granting checkout authority.
pub fn validate_ready_job(tx: &Transaction<'_>, job: i64) -> Result<()> {
	crate::review_intents::job_context(tx, job).map(|_| ())
}

pub fn has_unfinished(tx: &Transaction<'_>, campaign: i64) -> Result<bool> {
	Ok(tx.query_row("SELECT EXISTS(SELECT 1 FROM lead_drilldown_intents WHERE admission_campaign_id=?1 AND state!='complete' UNION ALL SELECT 1 FROM finding_verification_intents WHERE admission_campaign_id=?1 AND state!='complete' UNION ALL SELECT 1 FROM survey_continuation_batches WHERE campaign_id=?1 AND state!='complete')",[campaign],|r|r.get(0))?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
	Lead,
	Finding,
	ExactBatch,
	Ordinary,
}
impl Source {
	fn relation(self) -> (&'static str, &'static str) {
		match self {
			Self::Lead => ("lead_drilldown_intents", "admission_campaign_id"),
			Self::Finding => ("finding_verification_intents", "admission_campaign_id"),
			Self::ExactBatch => ("survey_continuation_batches", "campaign_id"),
			Self::Ordinary => unreachable!("ordinary work has no pending relation"),
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingGroup {
	pub source: Source,
	pub band: Band,
	pub before_deadline: bool,
	pub count: i64,
}
impl PendingGroup {
	pub fn work_class(self) -> WorkClass {
		match (self.source, self.band) {
			(Source::Lead, Band::Urgent) => WorkClass::UrgentDrilldown,
			(Source::Lead, _) => WorkClass::Drilldown,
			(Source::Finding, Band::Urgent) => WorkClass::UrgentVerification,
			(Source::Finding, _) => WorkClass::Verification,
			_ => WorkClass::Survey,
		}
	}
}

/// At most 25 groups, independent of repository size or connected workers.
/// A future due time before the cutoff is work, not an empty campaign.
pub fn pending(
	tx: &Transaction<'_>, campaign: i64, deadline: Option<i64>,
) -> Result<Vec<PendingGroup>> {
	let mut groups = Vec::new();
	for source in [Source::Lead, Source::Finding, Source::ExactBatch] {
		let (table, owner) = source.relation();
		let sql = format!("SELECT accepted_band, (?2 IS NULL OR not_before IS NULL OR not_before < ?2), COUNT(*) FROM {table} WHERE {owner}=?1 AND state='pending' GROUP BY 1,2 ORDER BY 1,2");
		let mut statement = tx.prepare(&sql)?;
		for row in statement.query_map(params![campaign, deadline], |r| {
			Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?))
		})? {
			let (band, before_deadline, count) = row?;
			groups.push(PendingGroup { source, band: band.parse()?, before_deadline, count });
		}
	}
	let count = tx.query_row(&format!("SELECT COUNT(*) FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id JOIN review_campaigns c ON c.generation_id=g.generation_id WHERE c.campaign_id=?1 AND g.state='active' AND {}", *review_units::UNIT_NEEDS_WORK), [campaign], |r| r.get(0))?;
	if count > 0 {
		groups.push(PendingGroup {
			source: Source::Ordinary,
			band: Band::Normal,
			before_deadline: true,
			count,
		});
	}
	Ok(groups)
}

/// Block only the examined pending group; do not revise or erase its evidence,
/// accepted priority, exact membership, or logical continuation provenance.
pub fn block_pending(
	tx: &Transaction<'_>, campaign: i64, group: PendingGroup, deadline: Option<i64>,
	reason: BlockReason, now: i64,
) -> Result<()> {
	if group.source == Source::Ordinary {
		tx.execute(&format!("UPDATE review_units SET status='deferred',defer_reason=?2 WHERE review_unit_id IN(SELECT u.review_unit_id FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id JOIN review_campaigns c ON c.generation_id=g.generation_id WHERE c.campaign_id=?1 AND {})", *review_units::UNIT_NEEDS_WORK), params![campaign, reason.as_str()])?;
		return Ok(());
	}
	let (table, owner) = group.source.relation();
	let predicate = format!("{owner}=?1 AND state='pending' AND accepted_band=?2 AND (?3 IS NULL OR not_before IS NULL OR not_before < ?3)=?4");
	if group.source == Source::ExactBatch {
		tx.execute(&format!("UPDATE review_unit_holds SET block_reason=?5,updated_at=?6 WHERE pending_batch_id IN(SELECT batch_id FROM {table} WHERE {predicate})"), params![campaign, group.band.as_str(), deadline, group.before_deadline, reason.as_str(), now])?;
		tx.execute(&format!("UPDATE review_units SET status='deferred',defer_reason=?5 WHERE status IN('open','deferred') AND review_unit_id IN(SELECT review_unit_id FROM review_unit_holds WHERE pending_batch_id IN(SELECT batch_id FROM {table} WHERE {predicate}))"),params![campaign,group.band.as_str(),deadline,group.before_deadline,reason.as_str()])?;
	}
	let updated = if group.source == Source::ExactBatch { "" } else { ",updated_at=?6" };
	let sql = format!("UPDATE {table} SET state='blocked',not_before=NULL,block_reason=?5{updated} WHERE {predicate}");
	if group.source == Source::ExactBatch {
		tx.execute(
			&sql,
			params![
				campaign,
				group.band.as_str(),
				deadline,
				group.before_deadline,
				reason.as_str()
			],
		)?;
	} else {
		tx.execute(
			&sql,
			params![
				campaign,
				group.band.as_str(),
				deadline,
				group.before_deadline,
				reason.as_str(),
				now
			],
		)?;
	}
	Ok(())
}

/// Campaign cancellation/deadline is broader than one producer's execution
/// failure: every unfinished admitted or pending subject must remain held.
/// Live job identities are deliberately untouched so workers can report failure.
pub fn block_all(tx: &Transaction<'_>, campaign: i64, reason: BlockReason, now: i64) -> Result<()> {
	block(tx, campaign, reason, now, false)
}

/// Preserve existing dependency/budget reasons when closing an idle campaign.
pub fn block_unexplained(tx: &Transaction<'_>, campaign: i64, now: i64) -> Result<()> {
	block(tx, campaign, BlockReason::RequiresSuccessor, now, true)
}

fn block(
	tx: &Transaction<'_>, campaign: i64, reason: BlockReason, now: i64, only_unexplained: bool,
) -> Result<()> {
	let generation: Option<i64> = tx
		.query_row(
			"SELECT generation_id FROM review_campaigns WHERE campaign_id=?1",
			[campaign],
			|r| r.get(0),
		)
		.optional()?
		.ok_or(Error::NotFound(Entity::Campaign, campaign))?;
	let filter = if only_unexplained { " AND block_reason IS NULL" } else { "" };
	for table in ["lead_drilldown_intents", "finding_verification_intents"] {
		tx.execute(&format!("UPDATE {table} SET state='blocked',not_before=NULL,block_reason=?2,updated_at=?3 WHERE admission_campaign_id=?1 AND state!='complete'{filter}"), params![campaign, reason.as_str(), now])?;
	}
	tx.execute(&format!("UPDATE review_unit_holds SET block_reason=?2,updated_at=?3 WHERE (pending_batch_id IN(SELECT batch_id FROM survey_continuation_batches WHERE campaign_id=?1) OR (pending_batch_id IS NULL AND producing_job_id IN(SELECT id FROM jobs WHERE campaign_id=?1))){filter}"), params![campaign, reason.as_str(), now])?;
	tx.execute(&format!("UPDATE survey_continuation_batches SET state='blocked',not_before=NULL,block_reason=?2 WHERE campaign_id=?1 AND state!='complete'{filter}"), params![campaign, reason.as_str()])?;
	let defer_filter = if only_unexplained { " AND u.defer_reason IS NULL" } else { "" };
	tx.execute(&format!("UPDATE review_units SET status='deferred',defer_reason=?2 WHERE review_unit_id IN(SELECT u.review_unit_id FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.generation_id=?1 AND u.status IN('open','deferred'){defer_filter} AND (EXISTS(SELECT 1 FROM review_unit_holds h WHERE h.review_unit_id=u.review_unit_id) OR NOT ({})))", review_units::UNIT_COVERED), params![generation, reason.as_str()])?;
	Ok(())
}

/// Bounded state/reason groups, without decoding canonical finding payloads.
pub fn summary(tx: &Transaction<'_>, campaign: i64) -> Result<serde_json::Value> {
	let mut out = serde_json::Map::new();
	for (name, table, owner) in [
		("leads", "lead_drilldown_intents", "admission_campaign_id"),
		("findings", "finding_verification_intents", "admission_campaign_id"),
		("exact_batches", "survey_continuation_batches", "campaign_id"),
	] {
		let mut rows = Vec::new();
		let mut statement = tx.prepare(&format!("SELECT state,block_reason,COUNT(*) FROM {table} WHERE {owner}=?1 GROUP BY state,block_reason ORDER BY state,block_reason"))?;
		for row in statement.query_map([campaign], |r| {
			Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, i64>(2)?))
		})? {
			let (state, reason, count) = row?;
			rows.push(serde_json::json!({"state":state,"reason":reason,"count":count}));
		}
		out.insert(name.into(), rows.into());
	}
	let mut holds = Vec::new();
	let mut statement = tx.prepare("SELECT h.block_reason,COUNT(*) FROM review_unit_holds h WHERE h.pending_batch_id IN(SELECT batch_id FROM survey_continuation_batches WHERE campaign_id=?1) OR (h.pending_batch_id IS NULL AND h.producing_job_id IN(SELECT id FROM jobs WHERE campaign_id=?1)) GROUP BY h.block_reason ORDER BY h.block_reason")?;
	for row in statement
		.query_map([campaign], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, i64>(1)?)))?
	{
		let (reason, count) = row?;
		holds.push(serde_json::json!({"reason":reason,"count":count}));
	}
	out.insert("unit_holds".into(), holds.into());
	Ok(out.into())
}
