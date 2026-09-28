//! Strict precommit validation and independent bounded maintenance. Recipe
//! support remains owned by `authority::Recipe`; data errors are classified
//! narrowly, never by catching every SQLite failure as a malformed row.
use loupe_core::JobKind;
use loupe_storage::admission_quarantine::{self as quarantine, Reason, Source};
use loupe_storage::{
	admission, jobs, review_authority as stored, review_intents, Error as StorageError,
};
use rusqlite::{params, Transaction};

use super::authority::{Access, Recipe};

#[derive(Debug)]
pub(crate) enum Failure {
	Defect(Reason),
	Unit(i64, Reason),
	Unexpected(StorageError),
}
pub(crate) type Result<T> = std::result::Result<T, Failure>;
pub(crate) fn invalid() -> Failure {
	Failure::Defect(Reason::InvalidData)
}
impl From<StorageError> for Failure {
	fn from(error: StorageError) -> Self {
		match error {
			StorageError::Validation(_)
			| StorageError::ReviewPayload(_)
			| StorageError::UnknownPaths(_)
			| StorageError::Ownership(_)
			| StorageError::NotFound(_, _) => invalid(),
			StorageError::Conflict(
				loupe_storage::Conflict::CampaignPolicy
				| loupe_storage::Conflict::GenerationState
				| loupe_storage::Conflict::Assignment
				| loupe_storage::Conflict::Checkpoint
				| loupe_storage::Conflict::CheckpointEvidence
				| loupe_storage::Conflict::FindingDetails
				| loupe_storage::Conflict::LeadState
				| loupe_storage::Conflict::JobState,
			) => invalid(),
			StorageError::Sqlite(
				rusqlite::Error::FromSqlConversionFailure(..)
				| rusqlite::Error::InvalidColumnType(..)
				| rusqlite::Error::IntegralValueOutOfRange(..)
				| rusqlite::Error::QueryReturnedNoRows
				| rusqlite::Error::Utf8Error(_),
			) => invalid(),
			other => Self::Unexpected(other),
		}
	}
}
impl From<rusqlite::Error> for Failure {
	fn from(error: rusqlite::Error) -> Self {
		StorageError::from(error).into()
	}
}

pub(crate) fn source(candidate: &loupe_storage::admission_candidates::Candidate) -> Source {
	use loupe_storage::admission_candidates::CandidateKind as K;
	match candidate.source {
		K::QueuedJob => Source::Job(candidate.id),
		K::LeadIntent => Source::Lead(candidate.id),
		K::FindingIntent => Source::Finding(candidate.id),
		K::ExactSurveyBatch => Source::Batch(candidate.id),
		K::OrdinarySurvey => Source::Ordinary(candidate.id),
	}
}

pub(crate) struct Planned {
	pub repo: i64,
	pub campaign: i64,
	pub generation: Option<i64>,
	pub kind: JobKind,
	pub(super) recipe: Recipe,
	pub context: stored::Context,
}

/// Reads original stored recipe bytes before `JobRow` can normalize JSON.
pub(crate) fn planned(tx: &Transaction<'_>, source: Source) -> Result<Option<Planned>> {
	let (repo,campaign,generation,kind,raw,head,attempts)=match source {
		Source::Job(id)=>tx.query_row("SELECT repo_id,campaign_id,generation_id,kind,recipe,head_sha,attempts FROM jobs WHERE id=?1",[id],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,Option<i64>>(1)?,r.get::<_,Option<i64>>(2)?,r.get::<_,String>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,Option<String>>(5)?,r.get::<_,i64>(6)?)))?,
		Source::Lead(id)|Source::Finding(id)=>{
			let subject=if matches!(source,Source::Lead(_)) {review_intents::Subject::Lead(id)}else{review_intents::Subject::Finding(id)};
			let intent=review_intents::get_subject(tx,subject)?.ok_or_else(invalid)?;
			(intent.repo_id,Some(intent.admission_campaign_id),intent.generation_id,if matches!(source,Source::Lead(_)){"drilldown"}else{"verify"}.into(),None,None,0)
		},
		Source::Batch(id)=>{let b=loupe_storage::unit_holds::get_batch(tx,id)?.ok_or_else(invalid)?;(b.repo_id,Some(b.campaign_id),Some(b.generation_id),"survey".into(),None,None,0)},
		Source::Ordinary(id)|Source::Unit(id)=>{
			let sql=if matches!(source,Source::Unit(_)){"SELECT c.repo_id,c.campaign_id,c.generation_id FROM review_campaigns c JOIN review_units u ON u.generation_id=c.generation_id WHERE u.review_unit_id=?1 AND c.state='active'"}else{"SELECT repo_id,campaign_id,generation_id FROM review_campaigns WHERE generation_id=?1 AND state='active'"};
			let (repo,campaign,generation)=tx.query_row(sql,[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
			(repo,Some(campaign),generation,"survey".into(),None,None,0)
		},
	};
	let Some(campaign) = campaign else {
		if let Source::Job(id) = source
			&& jobs::targets_phase_finding(tx, id)?
		{
			return Err(Failure::Defect(Reason::CompatibilityPolicy));
		}
		return Ok(None);
	};
	let kind: JobKind = kind.parse().expect("infallible job kind");
	let raw = if matches!(source, Source::Job(_)) {
		raw.ok_or_else(invalid)?
	} else if kind == JobKind::Survey {
		r#"{"version":1,"phase":"survey","recipe":"coverage","assignment_key":"ordinary"}"#.into()
	} else {
		format!(r#"{{"version":1,"phase":"{}"}}"#, kind.as_str())
	};
	let recipe: Recipe = serde_json::from_str(&raw).map_err(|_| invalid())?;
	if recipe.phase() != kind {
		return Err(invalid());
	}
	let (campaign_recipe,active,deadline,target,campaign_generation,policy_raw):(String,bool,Option<i64>,String,Option<i64>,String)=tx.query_row("SELECT recipe,state='active',deadline_at,target_commit_sha,generation_id,effective_policy FROM review_campaigns WHERE campaign_id=?1 AND repo_id=?2",params![campaign,repo],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
	if serde_json::from_str::<loupe_storage::scheduler::CampaignPolicy>(&policy_raw)
		.ok()
		.is_some_and(|p| p.version == 1)
	{
		return Err(Failure::Defect(Reason::CompatibilityPolicy));
	}
	let policy = admission::load_policy(tx, campaign)?;
	let spent = admission::get_spending(tx, campaign)?.ok_or_else(invalid)?;
	// Validate accounting without interpreting capacity refusal as corruption.
	admission::choose_pool(&policy, spent, admission::WorkClass::Preparation)?;
	if generation != campaign_generation {
		return Err(invalid());
	}
	let generation_context = if let Some(id) = generation {
		Some(tx.query_row("SELECT predecessor_generation_id,generation_commit_sha,state FROM review_generations WHERE generation_id=?1 AND repo_id=?2 AND workflow_contract_version=1",params![id,repo],|r|Ok(stored::Generation{id,predecessor:r.get(0)?,commit:r.get(1)?,state:r.get(2)?}))?)
	} else {
		None
	};
	let context = stored::Context {
		campaign_recipe,
		campaign_active: active,
		campaign_deadline: deadline,
		target_commit: target,
		generation: generation_context,
		head_sha: head,
		hard_deadline_at: None,
		recipe: Some(raw),
	};
	if context.head_sha.as_ref().is_some_and(|sha| sha != &context.target_commit)
		|| context.generation.as_ref().is_some_and(|g| g.commit != context.target_commit)
	{
		return Err(invalid());
	}
	if !recipe.supported(&context, Access::Checkout) {
		return Err(Failure::Defect(Reason::UnsupportedRecipe));
	}
	if let Source::Job(id) = source {
		let workflow: Option<i64> =
			tx.query_row("SELECT workflow_contract_version FROM jobs WHERE id=?1", [id], |r| {
				r.get(0)
			})?;
		if workflow != Some(1) {
			return Err(invalid());
		}
		let charge: bool = tx.query_row(
			"SELECT EXISTS(SELECT 1 FROM job_admission_charges WHERE job_id=?1 AND campaign_id=?2)",
			params![id, campaign],
			|r| r.get(0),
		)?;
		if !charge {
			return Err(invalid());
		}
		if attempts > 0
			&& generation.is_some()
			&& kind == JobKind::Survey
			&& !recipe.bootstrap()
			&& !loupe_storage::admission_claim::has_survey_retry_history(tx, id)?
		{
			return Err(invalid());
		}
	}
	if let Some(id) = generation {
		let profile = super::envelope::profile_snapshot(tx, id)?;
		if !recipe.bootstrap() {
			let ready:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM generation_manifests WHERE generation_id=?1 AND sealed_at IS NOT NULL AND received_entry_count=expected_entry_count)",[id],|r|r.get(0))?;
			if !ready || profile.is_none() {
				return Err(invalid());
			}
		}
	}
	Ok(Some(Planned { repo, campaign, generation, kind, recipe, context }))
}

#[derive(Debug)]
pub struct MaintenanceProgress {
	/// Original source rows examined, including healthy rows.
	pub inspected: u32,
	/// Sources durably excluded; no tentative admissions count as repairs.
	pub repaired: u32,
	/// Retain per campaign only after committing this transaction.
	pub next: Option<quarantine::Cursor>,
	/// A full pass ended. An exactly full page needs another bounded call.
	pub scan_complete: bool,
}

/// Independent from worker advertisements and due/cap/ranking predicates.
/// The caller retains `next` between bounded ticks; no blocked work is polled.
/// Use an immediate transaction for an active campaign, roll back on any error,
/// and advance the cursor only after commit. Deadline/budget/campaign finishing
/// policy belongs to the lifecycle coordinator, not this data-integrity walk.
pub fn maintain_campaign(
	tx: &Transaction<'_>, campaign: i64, now: i64, cursor: Option<quarantine::Cursor>,
	max_rows: u32, max_repairs: u32,
) -> loupe_storage::Result<MaintenanceProgress> {
	if !(1..=32).contains(&max_repairs) {
		return Err(StorageError::Conflict(loupe_storage::Conflict::CampaignPolicy));
	}
	let page = quarantine::page(tx, campaign, cursor, max_rows)?;
	let mut out =
		MaintenanceProgress { inspected: 0, repaired: 0, next: None, scan_complete: false };
	for source in &page {
		out.inspected += 1;
		out.next = Some(quarantine::Cursor::after(*source)?);
		match validate_source(tx, *source) {
			Ok(()) => {},
			Err(Failure::Defect(reason) | Failure::Unit(_, reason)) => {
				if quarantine::hold(tx, *source, reason, now)? {
					out.repaired += 1;
				}
			},
			Err(Failure::Unexpected(error)) => return Err(error),
		}
		if out.repaired == max_repairs {
			return Ok(out);
		}
	}
	if page.len() < max_rows as usize {
		out.next = None;
		out.scan_complete = true;
	}
	Ok(out)
}

pub(crate) fn validate_source(tx: &Transaction<'_>, source: Source) -> Result<()> {
	let Some(plan) = planned(tx, source)? else { return Ok(()) };
	match source {
		Source::Lead(id) => {
			validate_pending_subject(tx, review_intents::Subject::Lead(id), &plan)?;
			super::envelope::lead_snapshot(tx, id, &plan)?;
		},
		Source::Finding(id) => {
			validate_pending_subject(tx, review_intents::Subject::Finding(id), &plan)?;
			super::envelope::finding_snapshot(tx, id, &plan)?;
		},
		Source::Unit(id) => {
			super::envelope::unit_snapshot(tx, id, plan.generation.ok_or_else(invalid)?, None)?;
		},
		Source::Job(id) => {
			let job = jobs::get(tx, id)?.ok_or_else(invalid)?;
			if job.scheduling_band.is_none()
				|| job.effective_priority.is_none_or(|n| !(0..=550).contains(&n))
			{
				return Err(invalid());
			}
			loupe_storage::admission_claim::validate_retry_subject(tx, &job)?;
			if job.kind == JobKind::Drilldown {
				super::envelope::lead_snapshot(
					tx,
					job.assigned_lead_id.ok_or_else(invalid)?,
					&plan,
				)?;
			}
			if job.kind == JobKind::Verify {
				super::envelope::finding_snapshot(
					tx,
					job.target_finding_id.ok_or_else(invalid)?,
					&plan,
				)?;
			}
			if job.kind == JobKind::Survey && plan.generation.is_some() && !plan.recipe.bootstrap()
			{
				super::envelope::assignment_snapshot(tx, id)?;
			}
		},
		Source::Batch(id) => {
			let b = loupe_storage::unit_holds::get_batch(tx, id)?.ok_or_else(invalid)?;
			let holds = loupe_storage::unit_holds::batch_holds(tx, id)?;
			for hold in &holds {
				if !matches!(
					loupe_storage::review_unit_results::get_evidence(tx, hold.producing_result_id)?,
					loupe_storage::StoredEvidence::Recorded(_)
				) {
					return Err(Failure::Defect(Reason::CompatibilityPolicy));
				}
				super::envelope::unit_snapshot(tx, hold.unit_id, b.generation_id, None)?;
			}
			loupe_storage::unit_holds::validate_pending_batch(tx, id)?;
		},
		Source::Ordinary(_) => {},
	}
	Ok(())
}

fn validate_pending_subject(
	tx: &Transaction<'_>, subject: review_intents::Subject, plan: &Planned,
) -> Result<()> {
	let intent = review_intents::get_subject(tx, subject)?.ok_or_else(invalid)?;
	loupe_storage::admission_claim::validate_parent(tx, &intent, &plan.kind)?;
	let profile = super::envelope::profile_snapshot(tx, plan.generation.ok_or_else(invalid)?)?
		.ok_or_else(invalid)?;
	if intent.state != review_intents::State::Pending
		|| !review_intents::pending_subject_eligible(tx, &intent)?
		|| intent.admitted_job_id.is_some()
		|| intent.block_reason.is_some()
		|| (intent.kind == review_intents::IntentKind::LogicalContinuation
			&& intent.not_before.is_none())
		|| intent.priority.score > 550
		|| intent.source_commit_sha != plan.context.target_commit
		|| intent.profile_version != i64::from(profile.profile_version.get())
		|| super::envelope::digest_snapshot(&intent.profile_digest)? != profile.profile_digest
	{
		return Err(invalid());
	}
	Ok(())
}
