//! Exact, durable ownership of unfinished survey work.
//!
//! Holds are domain state, not timed leases: due times and execution retries
//! never return them to the ordinary pool. Every write uses the caller's
//! transaction together with its accepted result or terminal transition.
use loupe_core::review_payload::{ContinuationClass, UnitResultDisposition};
use loupe_core::{JobKind, JobState};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::admission_policy::AcceptedPriority;
use crate::review::{changed, optional, parsed};
use crate::review_intents::{self, class_str, continuation_state, parse_class, BlockReason, State};
use crate::{review_unit_results, review_units, Conflict, Error, Result, StoredEvidence};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hold {
	pub unit_id: i64,
	pub generation_id: i64,
	pub producing_job_id: i64,
	pub producing_result_id: i64,
	pub source_assignment_epoch: i64,
	pub continuation_class: ContinuationClass,
	pub block_reason: Option<BlockReason>,
	pub pending_batch_id: Option<i64>,
	pub batch_position: Option<i64>,
}
const HOLD_COLUMNS:&str="review_unit_id,generation_id,producing_job_id,producing_result_id,source_assignment_epoch,continuation_class,block_reason,pending_batch_id,batch_position";
fn hold_row(r: &Row<'_>) -> rusqlite::Result<Hold> {
	Ok(Hold {
		unit_id: r.get(0)?,
		generation_id: r.get(1)?,
		producing_job_id: r.get(2)?,
		producing_result_id: r.get(3)?,
		source_assignment_epoch: r.get(4)?,
		continuation_class: parse_class(&r.get::<_, String>(5)?, 5)?,
		block_reason: optional(r, 6)?,
		pending_batch_id: r.get(7)?,
		batch_position: r.get(8)?,
	})
}
pub fn get_hold(conn: &Connection, unit: i64) -> Result<Option<Hold>> {
	Ok(conn
		.query_row(
			&format!("SELECT {HOLD_COLUMNS} FROM review_unit_holds WHERE review_unit_id=?1"),
			[unit],
			hold_row,
		)
		.optional()?)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
	pub batch_id: i64,
	pub repo_id: i64,
	pub generation_id: i64,
	pub campaign_id: i64,
	pub producer_job_id: i64,
	pub ordinal: i64,
	pub logical_sequence: i64,
	pub continuation_class: ContinuationClass,
	pub state: State,
	pub not_before: Option<i64>,
	pub block_reason: Option<BlockReason>,
	pub admitted_job_id: Option<i64>,
	pub expected_unit_count: u32,
	pub priority: AcceptedPriority,
}
const BATCH_COLUMNS:&str="batch_id,repo_id,generation_id,campaign_id,producer_job_id,batch_ordinal,logical_sequence,continuation_class,state,not_before,block_reason,admitted_job_id,expected_unit_count,accepted_band,accepted_score";
fn batch_row(r: &Row<'_>) -> rusqlite::Result<Batch> {
	Ok(Batch {
		batch_id: r.get(0)?,
		repo_id: r.get(1)?,
		generation_id: r.get(2)?,
		campaign_id: r.get(3)?,
		producer_job_id: r.get(4)?,
		ordinal: r.get(5)?,
		logical_sequence: r.get(6)?,
		continuation_class: parse_class(&r.get::<_, String>(7)?, 7)?,
		state: parsed(r, 8)?,
		not_before: r.get(9)?,
		block_reason: optional(r, 10)?,
		admitted_job_id: r.get(11)?,
		expected_unit_count: r.get(12)?,
		priority: AcceptedPriority { band: parsed(r, 13)?, score: r.get(14)? },
	})
}
pub fn get_batch(conn: &Connection, id: i64) -> Result<Option<Batch>> {
	Ok(conn
		.query_row(
			&format!("SELECT {BATCH_COLUMNS} FROM survey_continuation_batches WHERE batch_id=?1"),
			[id],
			batch_row,
		)
		.optional()?)
}
pub fn list_batches(
	conn: &Connection, campaign: i64, after_id: i64, limit: u32,
) -> Result<Vec<Batch>> {
	if !(1..=256).contains(&limit) {
		return Err(Error::Conflict(Conflict::Assignment));
	}
	Ok(conn.prepare(&format!("SELECT {BATCH_COLUMNS} FROM survey_continuation_batches WHERE campaign_id=?1 AND batch_id>?2 ORDER BY batch_id LIMIT ?3"))?.query_map(params![campaign,after_id,limit],batch_row)?.collect::<rusqlite::Result<_>>()?)
}
/// Read one beyond the 32-member cap so admission detects excess membership
/// instead of silently truncating it to the persisted expected count.
pub fn batch_holds(conn: &Connection, batch: i64) -> Result<Vec<Hold>> {
	Ok(conn.prepare(&format!("SELECT {HOLD_COLUMNS} FROM review_unit_holds WHERE pending_batch_id=?1 ORDER BY batch_position LIMIT 33"))?.query_map([batch],hold_row)?.collect::<rusqlite::Result<_>>()?)
}

/// The source epoch belongs to the result's producer, not to a future child.
pub fn record_follow_up(
	tx: &Transaction<'_>, unit: i64, result: i64, producing_job: i64, epoch: i64,
	class: ContinuationClass, now: i64,
) -> Result<()> {
	let p = validate_result(tx, unit, result, producing_job, epoch, Some(class))?;
	let existing = get_hold(tx, unit)?;
	if existing.as_ref().is_some_and(|held| {
		held.producing_job_id == producing_job
			&& held.producing_result_id == result
			&& held.source_assignment_epoch == epoch
			&& held.continuation_class == class
	}) {
		return Ok(());
	}
	check_unit_owner(tx, unit, producing_job, epoch)?;
	let (_, _, reason) = continuation_state(&p.policy, class, 1, now)?;
	tx.execute("INSERT INTO review_unit_holds(review_unit_id,generation_id,producing_job_id,producing_result_id,source_assignment_epoch,continuation_class,block_reason,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8) ON CONFLICT(review_unit_id) DO UPDATE SET producing_job_id=excluded.producing_job_id,producing_result_id=excluded.producing_result_id,source_assignment_epoch=excluded.source_assignment_epoch,continuation_class=excluded.continuation_class,block_reason=excluded.block_reason,pending_batch_id=NULL,batch_position=NULL,updated_at=excluded.updated_at",params![unit,p.generation,producing_job,result,epoch,class_str(class),reason.map(BlockReason::as_str),now])?;
	complete_assignment(tx, producing_job, unit, epoch)?;
	if let Some(batch) = existing.and_then(|h| h.pending_batch_id) {
		complete_empty_batch(tx, batch)?;
	}
	Ok(())
}

/// Only a current owner's ordinary conclusive result can release a hold.
pub fn release_conclusive(
	tx: &Transaction<'_>, unit: i64, result: i64, producing_job: i64, epoch: i64, _now: i64,
) -> Result<()> {
	validate_result(tx, unit, result, producing_job, epoch, None)?;
	check_unit_owner(tx, unit, producing_job, epoch)?;
	let previous = get_hold(tx, unit)?;
	tx.execute("DELETE FROM review_unit_holds WHERE review_unit_id=?1", [unit])?;
	complete_assignment(tx, producing_job, unit, epoch)?;
	if let Some(batch) = previous.and_then(|h| h.pending_batch_id) {
		complete_empty_batch(tx, batch)?;
	}
	Ok(())
}
fn validate_result(
	tx: &Transaction<'_>, unit: i64, result: i64, job: i64, epoch: i64,
	class: Option<ContinuationClass>,
) -> Result<review_intents::JobContext> {
	let p = review_intents::producer(tx, job)?;
	if p.job.kind != JobKind::Survey || p.job.state != JobState::Leased {
		return Err(Error::Conflict(Conflict::JobState));
	}
	validate_evidence(tx, result, unit, epoch, class)?;
	let follow_up = class.is_some();
	let valid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM review_unit_results r JOIN review_units u ON u.review_unit_id=r.review_unit_id WHERE r.review_unit_result_id=?1 AND r.review_unit_id=?2 AND r.produced_by_job_id=?3 AND u.generation_id=?4 AND u.assignment_epoch=?5 AND u.status='open' AND u.stale=0 AND r.commit_sha=?6 AND r.profile_version=?7 AND r.invalidated=0 AND r.corroborates_review_unit_result_id IS NULL AND r.corroborates_inventory_exclusion_id IS NULL AND ((?8=1 AND r.disposition='needs_follow_up') OR (?8=0 AND r.disposition IN('lead_created','no_lead_found','not_applicable'))))",params![result,unit,job,p.generation,epoch,p.sha,p.profile_version,follow_up],|r|r.get(0))?;
	if !valid {
		return Err(Error::Conflict(Conflict::Assignment));
	}
	Ok(p)
}
fn validate_evidence(
	tx: &Transaction<'_>, result: i64, unit: i64, epoch: i64, class: Option<ContinuationClass>,
) -> Result<()> {
	let StoredEvidence::Recorded(payload) = review_unit_results::get_evidence(tx, result)? else {
		return Err(Error::Conflict(Conflict::CheckpointEvidence));
	};
	if payload.review_unit_id != unit
		|| payload.assignment_epoch != epoch
		|| payload.continuation != class
		|| (payload.disposition == UnitResultDisposition::NeedsFollowUp) != class.is_some()
	{
		return Err(Error::Conflict(Conflict::CheckpointEvidence));
	}
	Ok(())
}
fn check_unit_owner(tx: &Transaction<'_>, unit: i64, job: i64, epoch: i64) -> Result<()> {
	let valid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM review_units u WHERE u.review_unit_id=?1 AND u.assignment_epoch=?3 AND ((u.created_by_job_id=?2 AND ?3=0) OR EXISTS(SELECT 1 FROM job_assigned_review_units a WHERE a.job_id=?2 AND a.review_unit_id=u.review_unit_id AND a.assignment_epoch=?3)) AND NOT EXISTS(SELECT 1 FROM job_assigned_review_units a JOIN jobs j ON j.id=a.job_id WHERE a.review_unit_id=u.review_unit_id AND a.job_id<>?2 AND j.state IN('queued','leased')) AND NOT EXISTS(SELECT 1 FROM review_unit_holds h WHERE h.review_unit_id=u.review_unit_id AND NOT EXISTS(SELECT 1 FROM survey_continuation_batches b JOIN job_assigned_review_units a ON a.job_id=b.admitted_job_id WHERE b.batch_id=h.pending_batch_id AND b.state='admitted' AND b.admitted_job_id=?2 AND b.generation_id=u.generation_id AND a.review_unit_id=u.review_unit_id AND a.position=h.batch_position AND a.assignment_epoch=?3)))",params![unit,job,epoch],|r|r.get(0))?;
	if !valid {
		return Err(Error::Conflict(Conflict::Assignment));
	}
	Ok(())
}
fn complete_assignment(tx: &Transaction<'_>, job: i64, unit: i64, epoch: i64) -> Result<()> {
	tx.execute("UPDATE job_assigned_review_units SET completed=1 WHERE job_id=?1 AND review_unit_id=?2 AND assignment_epoch=?3",params![job,unit,epoch])?;
	Ok(())
}
fn complete_empty_batch(tx: &Transaction<'_>, batch: i64) -> Result<()> {
	tx.execute("UPDATE survey_continuation_batches SET state='complete',not_before=NULL,block_reason=NULL WHERE batch_id=?1 AND state='admitted' AND NOT EXISTS(SELECT 1 FROM review_unit_holds WHERE pending_batch_id=?1)",[batch])?;
	Ok(())
}

/// A handoff producer owns scheduling, not necessarily the retained evidence.
/// Carried holds retain their original result/source epoch; only an immutable
/// exact assignment permits deriving a later handoff epoch.
fn incoming_batch(tx: &Transaction<'_>, p: &review_intents::JobContext) -> Result<Option<Batch>> {
	let id = tx
		.query_row(
			"SELECT batch_id FROM survey_continuation_batches WHERE admitted_job_id=?1",
			[p.job.id],
			|r| r.get(0),
		)
		.optional()?;
	let Some(id) = id else { return Ok(None) };
	let batch = get_batch(tx, id)?.ok_or(Error::Conflict(Conflict::Assignment))?;
	let assigned = assigned_units(tx, p.job.id)?;
	if !matches!(batch.state, State::Admitted | State::Complete)
		|| batch.repo_id != p.job.repo_id
		|| batch.generation_id != p.generation
		|| batch.campaign_id != p.campaign
		|| p.job.parent_job_id != Some(batch.producer_job_id)
		|| p.job.continuation_of_job_id != Some(batch.producer_job_id)
		|| assigned.len() != batch.expected_unit_count as usize
		|| assigned.iter().enumerate().any(|(index, a)| a.position != index as i64)
	{
		return Err(Error::Conflict(Conflict::Assignment));
	}
	Ok(Some(batch))
}

fn handoff_epoch(
	tx: &Transaction<'_>, h: &Hold, p: &review_intents::JobContext, incoming: Option<&Batch>,
) -> Result<i64> {
	if h.producing_job_id == p.job.id {
		return Ok(h.source_assignment_epoch);
	}
	let batch = incoming.ok_or(Error::Conflict(Conflict::Assignment))?;
	// Positions compact when resolved siblings disappear. Membership comes
	// from the original assignment, never equality to a new batch position.
	let epoch:Option<i64>=tx.query_row("SELECT assignment_epoch FROM job_assigned_review_units WHERE job_id=?1 AND review_unit_id=?2 AND completed=0 AND position>=0 AND position<?3",params![p.job.id,h.unit_id,batch.expected_unit_count],|r|r.get(0)).optional()?;
	epoch.ok_or(Error::Conflict(Conflict::Assignment))
}

fn validate_held_source(
	tx: &Transaction<'_>, h: &Hold, p: &review_intents::JobContext, epoch: i64,
) -> Result<()> {
	validate_evidence(
		tx,
		h.producing_result_id,
		h.unit_id,
		h.source_assignment_epoch,
		Some(h.continuation_class),
	)?;
	let valid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM review_units u JOIN review_unit_results r ON r.review_unit_id=u.review_unit_id JOIN jobs j ON j.id=r.produced_by_job_id
		WHERE u.review_unit_id=?1 AND u.generation_id=?2 AND u.assignment_epoch=?3 AND u.assignment_epoch<9223372036854775807
		AND u.status IN('open','deferred') AND u.stale=0 AND r.review_unit_result_id=?4 AND r.produced_by_job_id=?5
		AND j.kind='survey' AND j.generation_id=u.generation_id AND j.repo_id=?8 AND j.head_sha=?6 AND j.workflow_contract_version=1
		AND ((u.created_by_job_id=j.id AND ?9=0) OR EXISTS(SELECT 1 FROM job_assigned_review_units a WHERE a.job_id=j.id AND a.review_unit_id=u.review_unit_id AND a.assignment_epoch=?9))
		AND r.invalidated=0 AND r.disposition='needs_follow_up' AND r.commit_sha=?6 AND r.profile_version=?7
		AND r.corroborates_review_unit_result_id IS NULL AND r.corroborates_inventory_exclusion_id IS NULL
		AND NOT EXISTS(SELECT 1 FROM job_assigned_review_units a JOIN jobs live ON live.id=a.job_id WHERE a.review_unit_id=u.review_unit_id AND live.state IN('queued','leased')))",
		params![h.unit_id,p.generation,epoch,h.producing_result_id,h.producing_job_id,p.sha,p.profile_version,p.job.repo_id,h.source_assignment_epoch],|r|r.get(0))?;
	if !valid || h.generation_id != p.generation {
		return Err(Error::Conflict(Conflict::Assignment));
	}
	Ok(())
}

/// Freeze new evidence and untouched members of this producer's exact incoming
/// reservation. Original evidence provenance survives every logical handoff.
/// No work can be appended to an already-frozen producer.
pub fn freeze_survey_batches(
	tx: &Transaction<'_>, producer_job: i64, now: i64,
) -> Result<Vec<Batch>> {
	let p = review_intents::producer(tx, producer_job)?;
	if p.job.kind != JobKind::Survey || p.job.state != JobState::Succeeded {
		return Err(Error::Conflict(Conflict::JobState));
	}
	let existing:Vec<Batch>=tx.prepare(&format!("SELECT {BATCH_COLUMNS} FROM survey_continuation_batches WHERE producer_job_id=?1 ORDER BY batch_ordinal"))?.query_map([producer_job],batch_row)?.collect::<rusqlite::Result<_>>()?;
	if !existing.is_empty() {
		let unbatched:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM review_unit_holds WHERE producing_job_id=?1 AND pending_batch_id IS NULL)",[producer_job],|r|r.get(0))?;
		if unbatched {
			return Err(Error::Conflict(Conflict::Assignment));
		}
		return Ok(existing);
	}
	let policy = &p.policy;
	let incoming = incoming_batch(tx, &p)?;
	if let Some(batch) = &incoming {
		for assignment in assigned_units(tx, producer_job)? {
			let hold = get_hold(tx, assignment.unit_id)?;
			if !assignment.completed {
				let hold = hold.ok_or(Error::Conflict(Conflict::Assignment))?;
				if batch.state != State::Admitted
					|| hold.pending_batch_id != Some(batch.batch_id)
					|| hold.batch_position != Some(assignment.position)
				{
					return Err(Error::Conflict(Conflict::Assignment));
				}
			} else if hold.is_some_and(|h| h.pending_batch_id == Some(batch.batch_id)) {
				return Err(Error::Conflict(Conflict::Assignment));
			}
		}
	}
	let incoming_id = incoming.as_ref().filter(|b| b.state == State::Admitted).map(|b| b.batch_id);
	let previous = incoming.as_ref().map(|b| b.logical_sequence);
	let sequence =
		previous.unwrap_or(0).checked_add(1).ok_or(Error::Conflict(Conflict::Assignment))?;
	let mut batches = Vec::new();
	for class in [
		ContinuationClass::SourceAnalysisRemaining,
		ContinuationClass::AwaitingProofInfrastructure,
		ContinuationClass::ExternalDependency,
		ContinuationClass::RequiresSuccessor,
	] {
		loop {
			let members:Vec<(i64,review_units::Priority)>=tx.prepare("SELECT h.review_unit_id,u.priority_band FROM review_unit_holds h JOIN review_units u ON u.review_unit_id=h.review_unit_id LEFT JOIN job_assigned_review_units a ON a.job_id=?1 AND a.review_unit_id=h.review_unit_id WHERE ((h.producing_job_id=?1 AND h.pending_batch_id IS NULL) OR h.pending_batch_id=?4) AND h.continuation_class=?2 ORDER BY COALESCE(a.position,u.review_unit_id),u.review_unit_id LIMIT ?3")?.query_map(params![producer_job,class_str(class),policy.survey_units_per_job,incoming_id],|r|Ok((r.get(0)?,parsed(r,1)?)))?.collect::<rusqlite::Result<_>>()?;
			if members.is_empty() {
				break;
			}
			let band = members
				.iter()
				.map(|m| m.1)
				.min_by_key(|b| match b {
					review_units::Priority::Urgent => 0,
					review_units::Priority::High => 1,
					review_units::Priority::Normal => 2,
					review_units::Priority::Background => 3,
				})
				.ok_or(Error::Conflict(Conflict::Assignment))?;
			let (state, not_before, reason) = continuation_state(policy, class, sequence, now)?;
			tx.execute("INSERT INTO survey_continuation_batches(repo_id,generation_id,campaign_id,producer_job_id,batch_ordinal,logical_sequence,continuation_class,state,not_before,block_reason,expected_unit_count,accepted_band,accepted_score,priority_policy_version,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,0,1,?13)",params![p.job.repo_id,p.generation,p.campaign,producer_job,batches.len() as i64,sequence,class_str(class),state.as_str(),not_before,reason.map(BlockReason::as_str),members.len() as i64,band.as_str(),now])?;
			let batch = tx.last_insert_rowid();
			for (position, (unit, _)) in members.iter().enumerate() {
				let hold = get_hold(tx, *unit)?.ok_or(Error::Conflict(Conflict::Assignment))?;
				let epoch = handoff_epoch(tx, &hold, &p, incoming.as_ref())?;
				validate_held_source(tx, &hold, &p, epoch)?;
				if let Some(old) = hold.pending_batch_id {
					let assignment = assigned_units(tx, p.job.id)?
						.into_iter()
						.find(|a| a.unit_id == *unit)
						.ok_or(Error::Conflict(Conflict::Assignment))?;
					if Some(old) != incoming_id
						|| hold.batch_position != Some(assignment.position)
						|| assignment.completed
					{
						return Err(Error::Conflict(Conflict::Assignment));
					}
				}
				changed(tx.execute("UPDATE review_unit_holds SET pending_batch_id=?2,batch_position=?3,updated_at=?4 WHERE review_unit_id=?1 AND generation_id=?5 AND ((producing_job_id=?6 AND pending_batch_id IS NULL) OR pending_batch_id=?7)",params![unit,batch,position as i64,now,p.generation,producer_job,incoming_id])?,Conflict::Assignment)?;
			}
			batches.push(get_batch(tx, batch)?.ok_or(Error::Conflict(Conflict::Assignment))?);
		}
	}
	if let Some(old) = incoming_id {
		complete_empty_batch(tx, old)?;
	}
	Ok(batches)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssignedUnit {
	pub unit_id: i64,
	pub position: i64,
	pub assignment_epoch: i64,
	pub completed: bool,
}
fn assigned_units(tx: &Transaction<'_>, job: i64) -> Result<Vec<AssignedUnit>> {
	Ok(tx.prepare("SELECT review_unit_id,position,assignment_epoch,completed FROM job_assigned_review_units WHERE job_id=?1 ORDER BY position LIMIT 33")?.query_map([job],|r|Ok(AssignedUnit{unit_id:r.get(0)?,position:r.get(1)?,assignment_epoch:r.get(2)?,completed:r.get(3)?}))?.collect::<rusqlite::Result<_>>()?)
}
/// Exact reservation only: caller creates/leases/charges the child atomically.
/// Execution retries read the immutable existing assignments, never refill.
pub fn admit_exact_batch(
	tx: &Transaction<'_>, batch_id: i64, child_job: i64, now: i64,
) -> Result<Vec<AssignedUnit>> {
	let batch = get_batch(tx, batch_id)?.ok_or(Error::Conflict(Conflict::Assignment))?;
	let p = review_intents::job_context(tx, child_job)?;
	if p.job.kind != JobKind::Survey
		|| p.generation != batch.generation_id
		|| p.campaign != batch.campaign_id
		|| p.job.repo_id != batch.repo_id
		|| p.job.parent_job_id != Some(batch.producer_job_id)
		|| p.job.continuation_of_job_id != Some(batch.producer_job_id)
		|| p.job.scheduling_band != Some(batch.priority.band)
	{
		return Err(Error::Conflict(Conflict::Assignment));
	}
	if matches!(batch.state, State::Admitted | State::Complete)
		&& batch.admitted_job_id == Some(child_job)
	{
		let assigned = assigned_units(tx, child_job)?;
		if assigned.len() != batch.expected_unit_count as usize
			|| assigned.iter().enumerate().any(|(i, a)| a.position != i as i64)
		{
			return Err(Error::Conflict(Conflict::Assignment));
		}
		return Ok(assigned);
	}
	review_intents::validate_child(tx, &p, batch.producer_job_id, now)?;
	if batch.state != State::Pending
		|| batch.continuation_class != ContinuationClass::SourceAnalysisRemaining
		|| batch.block_reason.is_some()
		|| batch.not_before.is_none_or(|due| due > now)
		|| !assigned_units(tx, child_job)?.is_empty()
	{
		return Err(Error::Conflict(Conflict::Assignment));
	}
	let (holds, epochs) = pending_members(tx, &batch, &p)?;
	changed(tx.execute("UPDATE survey_continuation_batches SET state='admitted',admitted_job_id=?2 WHERE batch_id=?1 AND state='pending' AND admitted_job_id IS NULL",params![batch_id,child_job])?,Conflict::Assignment)?;
	for (h, epoch) in holds.iter().zip(epochs) {
		changed(tx.execute("UPDATE review_units SET status='open',defer_reason=NULL,assignment_epoch=assignment_epoch+1 WHERE review_unit_id=?1 AND assignment_epoch=?2",params![h.unit_id,epoch])?,Conflict::Assignment)?;
		tx.execute("INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) SELECT ?1,review_unit_id,?3,assignment_epoch FROM review_units WHERE review_unit_id=?2",params![child_job,h.unit_id,h.batch_position])?;
	}
	assigned_units(tx, child_job)
}

/// Read-only integrity check for maintenance, irrespective of due time or
/// worker advertisements. This never admits, leases, charges or takes epochs.
pub fn validate_pending_batch(tx: &Transaction<'_>, batch_id: i64) -> Result<()> {
	let batch = get_batch(tx, batch_id)?.ok_or(Error::Conflict(Conflict::Assignment))?;
	let p = review_intents::producer(tx, batch.producer_job_id)?;
	if batch.state != State::Pending
		|| batch.admitted_job_id.is_some()
		|| batch.continuation_class != ContinuationClass::SourceAnalysisRemaining
		|| batch.block_reason.is_some()
		|| batch.not_before.is_none()
		|| !(1..=32).contains(&batch.expected_unit_count)
		|| batch.priority.score > 550
		|| p.job.kind != JobKind::Survey
		|| p.generation != batch.generation_id
		|| p.campaign != batch.campaign_id
		|| p.job.repo_id != batch.repo_id
	{
		return Err(Error::Conflict(Conflict::Assignment));
	}
	pending_members(tx, &batch, &p)?;
	Ok(())
}

fn pending_members(
	tx: &Transaction<'_>, batch: &Batch, p: &review_intents::JobContext,
) -> Result<(Vec<Hold>, Vec<i64>)> {
	let holds = batch_holds(tx, batch.batch_id)?;
	if holds.len() != batch.expected_unit_count as usize {
		return Err(Error::Conflict(Conflict::Assignment));
	}
	let producer = review_intents::producer(tx, batch.producer_job_id)?;
	if producer.job.state != JobState::Succeeded {
		return Err(Error::Conflict(Conflict::Assignment));
	}
	let incoming = incoming_batch(tx, &producer)?;
	let mut epochs = Vec::with_capacity(holds.len());
	for (position, h) in holds.iter().enumerate() {
		if h.batch_position != Some(position as i64)
			|| h.generation_id != batch.generation_id
			|| h.continuation_class != batch.continuation_class
			|| h.block_reason.is_some()
		{
			return Err(Error::Conflict(Conflict::Assignment));
		}
		let epoch = handoff_epoch(tx, h, &producer, incoming.as_ref())?;
		validate_held_source(tx, h, p, epoch)?;
		epochs.push(epoch);
	}
	Ok((holds, epochs))
}

pub(crate) fn block_job_work(
	tx: &Transaction<'_>, job: i64, reason: BlockReason, now: i64,
) -> Result<()> {
	tx.execute("UPDATE review_unit_holds SET block_reason=?2,updated_at=?3 WHERE producing_job_id=?1 OR pending_batch_id IN(SELECT batch_id FROM survey_continuation_batches WHERE admitted_job_id=?1)",params![job,reason.as_str(),now])?;
	tx.execute("UPDATE survey_continuation_batches SET state='blocked',not_before=NULL,block_reason=?2 WHERE (admitted_job_id=?1 OR producer_job_id=?1) AND state IN('pending','admitted')",params![job,reason.as_str()])?;
	// Untouched work has no accepted result to anchor a hold. Retain its exact
	// assignment and an explicit deferral instead of inventing model evidence.
	tx.execute("UPDATE review_units SET status='deferred',defer_reason=?2 WHERE status='open' AND (EXISTS(SELECT 1 FROM job_assigned_review_units a WHERE a.job_id=?1 AND a.review_unit_id=review_units.review_unit_id AND a.completed=0 AND a.assignment_epoch=review_units.assignment_epoch) OR (created_by_job_id=?1 AND assignment_epoch=0 AND NOT EXISTS(SELECT 1 FROM review_unit_results r WHERE r.review_unit_id=review_units.review_unit_id AND r.invalidated=0)))",params![job,reason.as_str()])?;
	Ok(())
}

#[cfg(test)]
mod tests;
