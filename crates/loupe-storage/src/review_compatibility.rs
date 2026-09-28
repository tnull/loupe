//! Explicit, quiescent poison reset. Only the rebuildable generation graph is
//! purged; canonical obligations and job-owned audit/replay history survive.
use rusqlite::{params, OptionalExtension, Transaction};

use crate::review::changed;
use crate::{Conflict, Entity, Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reset {
	pub inventory_entries_removed: u64,
	pub review_units_removed: u64,
	pub leads_removed: u64,
	pub verification_intents_blocked: u64,
}

/// Caller holds an IMMEDIATE transaction through response serialization. This
/// administrative operation deliberately reads numeric ownership and lifecycle
/// state only: malformed derived profiles/criteria must remain recoverable.
pub fn reset(tx: &Transaction<'_>, generation: i64, now: i64) -> Result<Reset> {
	let (repo, state, commit, workflow, created) = tx
		.query_row(
			"SELECT repo_id,state,generation_commit_sha,workflow_contract_version,created_at FROM review_generations WHERE generation_id=?1",
			[generation],
			|r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?,r.get::<_,String>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?)),
		)
		.optional()?
		.ok_or(Error::NotFound(Entity::Generation, generation))?;
	if !matches!(state.as_str(), "active" | "building") {
		return Err(Error::Conflict(Conflict::GenerationState));
	}
	if tx.query_row("SELECT EXISTS(SELECT 1 FROM review_generations WHERE repo_id=?1 AND generation_id<>?2 AND state IN('active','building'))",params![repo,generation],|r|r.get::<_,bool>(0))? {
		return Err(Error::Conflict(Conflict::ActiveGeneration));
	}
	// An unpinned active campaign also prevents the next ordinary open from
	// choosing a new bootstrap. It must settle before resetting its repository.
	if tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM review_campaigns WHERE repo_id=?1 AND state='active')",
		[repo],
		|r| r.get::<_, bool>(0),
	)? {
		return Err(Error::Conflict(Conflict::ActiveCampaign));
	}
	let busy=tx.query_row("SELECT EXISTS(SELECT 1 FROM jobs j WHERE j.state IN('queued','leased') AND (
		j.generation_id=?1
		OR EXISTS(SELECT 1 FROM job_assigned_review_units a JOIN review_units u ON u.review_unit_id=a.review_unit_id WHERE a.job_id=j.id AND u.generation_id=?1)
		OR EXISTS(SELECT 1 FROM leads l WHERE l.lead_id=j.assigned_lead_id AND l.generation_id=?1)
		OR EXISTS(SELECT 1 FROM finding_verification_intents i WHERE i.generation_id=?1 AND (i.admitted_job_id=j.id OR i.finding_id=j.target_finding_id))
		OR EXISTS(SELECT 1 FROM lead_drilldown_intents i WHERE i.generation_id=?1 AND i.admitted_job_id=j.id)
		OR EXISTS(SELECT 1 FROM survey_continuation_batches b WHERE b.generation_id=?1 AND b.admitted_job_id=j.id)))",[generation],|r|r.get::<_,bool>(0))?;
	if busy {
		return Err(Error::Conflict(Conflict::JobState));
	}
	let (inventory_entries_removed, review_units_removed, leads_removed) = tx.query_row(
		"SELECT (SELECT COUNT(*) FROM generation_inventory WHERE generation_id=?1),
		(SELECT COUNT(*) FROM review_units WHERE generation_id=?1),
		(SELECT COUNT(*) FROM leads WHERE generation_id=?1)",
		[generation],
		|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
	)?;
	changed(tx.execute("UPDATE review_generations SET state='retired',retired_at=?2,retired_reason='operator compatibility reset' WHERE generation_id=?1 AND state IN('active','building')",params![generation,now])?,Conflict::GenerationState)?;
	// Keep original kind/class, not-before, revision, priority, admitted job and
	// evidence provenance. A reset is not permission to rebind or drop work.
	let verification_intents_blocked=tx.execute("UPDATE finding_verification_intents SET state='blocked',block_reason='requires_successor',updated_at=?2 WHERE generation_id=?1 AND state<>'complete'",params![generation,now])? as u64;
	changed(
		tx.execute(
			"DELETE FROM review_generations WHERE generation_id=?1 AND state='retired'",
			[generation],
		)?,
		Conflict::GenerationState,
	)?;
	// Preserve an identity tombstone for the lifetime of this repository.
	// SQLite may otherwise reuse the deleted maximum rowid for a bootstrap,
	// letting a delayed reset target its replacement. Delete first to retain
	// the established cascade/SET NULL boundary; the immediate transaction
	// makes the gap invisible. Future GC must not remove these stubs without
	// a durable nonreuse mechanism. Explicit repository deletion is separate.
	tx.execute("INSERT INTO review_generations(generation_id,repo_id,generation_commit_sha,state,workflow_contract_version,created_at,retired_at,retired_reason) VALUES(?1,?2,?3,'retired',?4,?5,?6,'operator compatibility reset')",params![generation,repo,commit,workflow,created,now])?;
	Ok(Reset {
		inventory_entries_removed,
		review_units_removed,
		leads_removed,
		verification_intents_blocked,
	})
}
