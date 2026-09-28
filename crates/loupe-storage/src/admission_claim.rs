//! Transactional materialization of one ranked admission candidate.
//!
//! This leaf does not activate any runtime kind. Callers must use an immediate
//! transaction, intersect their advertised kinds with runtime gates, and validate
//! recipes, evidence and the complete delivery envelope before committing. Any
//! error (including subsequent serialization failure) requires rollback of the
//! entire candidate attempt. A returned job is not delivery authorization.
//!
//! Before calling this leaf, the consumer must reject a ready ordinary execution
//! retry whose assignment rows and InitializeSurveyBatch checkpoint are both
//! missing. Otherwise initialization would conceal the lost history by selecting
//! new work. Unpinned/bootstrap attempts require the consumer's explicit recipe
//! exception; the storage leaf does not maintain a second recipe parser.

use loupe_core::text::{BoundedJson, Identifier};
use loupe_core::{JobKind, JobState, WORKFLOW_CONTRACT_VERSION};
use rusqlite::{params, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};

use crate::admission::{self, CapacityRefusal, Charged, Selection, WorkClass};
use crate::admission_candidates::{self, Candidate, CandidateKind, Request};
use crate::admission_policy::CampaignPolicyV2;
use crate::review_intents::{self, IntentKind, Subject};
use crate::scheduler::{self, Band, Claimed};
use crate::{campaigns, jobs, unit_holds, Conflict, Entity, Error, Result};

#[derive(Debug)]
pub enum Outcome {
	/// Tentative database effects only; caller still owns validation and commit.
	Uncommitted(Box<Claimed>),
	/// No writes: the supplied candidate is no longer the first ranked source.
	Stale,
	/// No writes: validated frozen spending cannot fund this work class.
	CapacityRefused(CapacityRefusal),
}

fn conflict() -> Error {
	Error::Conflict(Conflict::JobState)
}

/// Read retained survey initialization without creating a marker or assigning
/// any work. The consumer chooses the ordinary retry recipe cases that require
/// this check, then separately validates every retained assignment and epoch.
/// Keep the original initializer's SHA-256 marker, not the newer evidence hash.
pub fn has_survey_retry_history(tx: &Transaction<'_>, job: i64) -> Result<bool> {
	let assigned: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM job_assigned_review_units WHERE job_id=?1)",
		[job],
		|row| row.get(0),
	)?;
	if assigned {
		return Ok(true);
	}
	let marker = crate::checkpoints::lookup(
		tx,
		job,
		crate::checkpoints::Operation::InitializeSurveyBatch,
		&Identifier::new("ordinary")?,
		&Sha256::digest(b"{}").into(),
	)?;
	Ok(marker.is_some_and(|body| body.expose() == "{}"))
}

/// Rechecks the single global selector, then joins creation, first lease,
/// assignment/intent CAS, charge and fairness in the caller's transaction.
pub fn materialize(
	tx: &Transaction<'_>, candidate: &Candidate, req: &Request<'_>, capability_hash: &[u8; 32],
	legacy_lease_seconds: i64,
) -> Result<Outcome> {
	let active_worker: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM workers WHERE id=?1 AND kind='worker' AND revoked_at IS NULL)",
		[req.worker_id],
		|r| r.get(0),
	)?;
	if !active_worker {
		return Err(conflict());
	}
	let checked = Request { limit: 1, ..*req };
	if admission_candidates::ranked(tx, &checked)?.first() != Some(candidate) {
		return Ok(Outcome::Stale);
	}
	let Some(campaign_id) = candidate.campaign_id else {
		if candidate.source != CandidateKind::QueuedJob || legacy_lease_seconds <= 0 {
			return Err(conflict());
		}
		let expiry = req.now.checked_add(legacy_lease_seconds).ok_or_else(conflict)?;
		lease(tx, candidate.id, req, capability_hash, expiry, None, None)?;
		return Ok(Outcome::Uncommitted(Box::new(Claimed {
			job: get_job(tx, candidate.id)?,
			assigned_units: Vec::new(),
			resumed: false,
		})));
	};
	let campaign =
		campaigns::get(tx, campaign_id)?.ok_or(Error::NotFound(Entity::Campaign, campaign_id))?;
	if campaign.repo_id != candidate.repo_id
		|| campaign.generation_id != candidate.generation_id
		|| campaign.state != campaigns::State::Active
		|| campaign.deadline_at.is_some_and(|d| d <= req.now)
	{
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	let policy = admission::load_policy(tx, campaign_id)?;
	let band = candidate.stored_band.ok_or_else(conflict)?;
	let score = candidate.stored_score.filter(|s| (0..=550).contains(s)).ok_or_else(conflict)?;
	let class = work_class(&candidate.kind, band)?;
	let spent = admission::get_spending(tx, campaign_id)?
		.ok_or(Error::Conflict(Conflict::CampaignPolicy))?;
	let selection = admission::choose_pool(&policy, spent, class)?;
	let fresh = candidate.source != CandidateKind::QueuedJob;
	if fresh && let Selection::Refused(reason) = selection {
		return Ok(Outcome::CapacityRefused(reason));
	}
	let phase = policy.phase(&candidate.kind)?;
	if req.policy.lease_seconds <= 0 || req.policy.lease_report_grace_seconds <= 0 {
		return Err(conflict());
	}
	let hard = req.now.checked_add(phase.deadline_seconds).ok_or_else(conflict)?;
	let hard = campaign.deadline_at.map_or(hard, |d| d.min(hard));
	let submit = hard.checked_sub(phase.submit_margin_seconds).ok_or_else(conflict)?;
	let expiry = req
		.now
		.checked_add(req.policy.lease_seconds)
		.ok_or_else(conflict)?
		.min(hard.checked_add(req.policy.lease_report_grace_seconds).ok_or_else(conflict)?);
	let job_id = if fresh {
		let (parent, continuation, lead, finding) = match candidate.source {
			CandidateKind::LeadIntent | CandidateKind::FindingIntent => {
				let subject = subject(candidate)?;
				let intent = review_intents::get_subject(tx, subject)?.ok_or_else(conflict)?;
				if Some(intent.revision) != candidate.intent_revision
					|| intent.priority.band != band
					|| i64::from(intent.priority.score) != score
					|| intent.repo_id != candidate.repo_id
					|| intent.admission_campaign_id != campaign_id
					|| intent.generation_id != candidate.generation_id
				{
					return Err(conflict());
				}
				validate_parent(tx, &intent, &candidate.kind)?;
				(
					Some(intent.originating_job_id),
					(intent.kind == IntentKind::LogicalContinuation)
						.then_some(intent.originating_job_id),
					match subject {
						Subject::Lead(id) => Some(id),
						_ => None,
					},
					match subject {
						Subject::Finding(id) => Some(id),
						_ => None,
					},
				)
			},
			CandidateKind::ExactSurveyBatch => {
				let batch = unit_holds::get_batch(tx, candidate.id)?.ok_or_else(conflict)?;
				if batch.repo_id != candidate.repo_id
					|| batch.campaign_id != campaign_id
					|| Some(batch.generation_id) != candidate.generation_id
					|| batch.priority.band != band
					|| i64::from(batch.priority.score) != score
				{
					return Err(conflict());
				}
				(Some(batch.producer_job_id), Some(batch.producer_job_id), None, None)
			},
			CandidateKind::OrdinarySurvey => {
				let parent=tx.query_row("SELECT id FROM jobs WHERE repo_id=?1 AND campaign_id=?2 AND generation_id=?3 AND kind='survey' AND state='succeeded' ORDER BY id DESC LIMIT 1",params![candidate.repo_id,campaign_id,candidate.generation_id],|r|r.get(0)).optional()?;
				(parent, None, None, None)
			},
			CandidateKind::QueuedJob => unreachable!(),
		};
		insert_job(
			tx,
			&campaign,
			&policy,
			&NewJob {
				kind: &candidate.kind,
				band,
				score,
				parent,
				continuation,
				lead,
				finding,
				survey_recipe: "coverage",
			},
			req.now,
		)?
	} else {
		let job = get_job(tx, candidate.id)?;
		validate_planned_scope(tx, &job, &campaign)?;
		if job.attempts >= policy.max_attempts
			|| job.token_budget != phase.token_budget
			|| job.workflow_contract_version != Some(WORKFLOW_CONTRACT_VERSION)
			|| job.scheduling_band != Some(band)
			|| job.effective_priority != Some(score)
		{
			return Err(conflict());
		}
		let charged: bool = tx.query_row(
			"SELECT EXISTS(SELECT 1 FROM job_admission_charges WHERE job_id=?1 AND campaign_id=?2)",
			params![job.id, campaign_id],
			|r| r.get(0),
		)?;
		if !charged {
			return Err(Error::Conflict(Conflict::CampaignPolicy));
		}
		validate_retry_subject(tx, &job)?;
		job.id
	};
	lease(tx, job_id, req, capability_hash, expiry, Some(hard), Some(submit))?;
	let mut assigned_units = Vec::new();
	let mut resumed = false;
	match candidate.source {
		CandidateKind::LeadIntent | CandidateKind::FindingIntent => {
			review_intents::admit_subject(
				tx,
				subject(candidate)?,
				candidate.intent_revision.ok_or_else(conflict)?,
				job_id,
				req.now,
			)?;
		},
		CandidateKind::ExactSurveyBatch => {
			assigned_units = unit_holds::admit_exact_batch(tx, candidate.id, job_id, req.now)?
				.into_iter()
				.filter(|a| !a.completed)
				.map(|a| a.unit_id)
				.collect();
		},
		CandidateKind::OrdinarySurvey => {
			review_intents::job_context(tx, job_id)?;
			let batch = scheduler::initialize_ordinary_batch(tx, job_id, req.now)?;
			assigned_units = batch.units;
			resumed = batch.resumed;
		},
		CandidateKind::QueuedJob => {
			let job = get_job(tx, job_id)?;
			if job.kind == JobKind::Survey && job.generation_id.is_some() {
				let batch = scheduler::initialize_ordinary_batch(tx, job_id, req.now)?;
				assigned_units = batch.units;
				resumed = batch.resumed;
			}
		},
	}
	match (fresh, admission::charge(tx, job_id, class, req.now)?) {
		(true, Charged::Fresh(_)) | (false, Charged::Replayed(_)) => {},
		_ => return Err(Error::Conflict(Conflict::CampaignPolicy)),
	}
	fairness(tx, candidate, req)?;
	Ok(Outcome::Uncommitted(Box::new(Claimed {
		job: get_job(tx, job_id)?,
		assigned_units,
		resumed,
	})))
}

fn get_job(tx: &Transaction<'_>, id: i64) -> Result<jobs::JobRow> {
	jobs::get(tx, id)?.ok_or(Error::NotFound(Entity::Job, id))
}
fn subject(c: &Candidate) -> Result<Subject> {
	match c.source {
		CandidateKind::LeadIntent => Ok(Subject::Lead(c.id)),
		CandidateKind::FindingIntent => Ok(Subject::Finding(c.id)),
		_ => Err(conflict()),
	}
}
fn work_class(kind: &JobKind, band: Band) -> Result<WorkClass> {
	match (kind, band) {
		(JobKind::Survey, _) => Ok(WorkClass::Survey),
		(JobKind::Drilldown, Band::Urgent) => Ok(WorkClass::UrgentDrilldown),
		(JobKind::Drilldown, _) => Ok(WorkClass::Drilldown),
		(JobKind::Verify, Band::Urgent) => Ok(WorkClass::UrgentVerification),
		(JobKind::Verify, _) => Ok(WorkClass::Verification),
		_ => Err(conflict()),
	}
}

/// Read-only provenance check shared with independent admission maintenance.
/// The caller must separately validate current campaign readiness, canonical
/// subject evidence and intent state; this alone never authorizes delivery.
pub fn validate_parent(
	tx: &Transaction<'_>, intent: &review_intents::Intent, kind: &JobKind,
) -> Result<()> {
	let parent = get_job(tx, intent.originating_job_id)?;
	if parent.repo_id != intent.repo_id
		|| parent.campaign_id != Some(intent.originating_campaign_id)
		|| parent.generation_id != intent.generation_id
	{
		return Err(conflict());
	}
	let valid = if intent.kind == IntentKind::LogicalContinuation {
		parent.kind == *kind
			&& matches!(parent.state, JobState::Succeeded | JobState::Failed | JobState::Cancelled)
			&& match intent.subject {
				Subject::Lead(id) => parent.assigned_lead_id == Some(id),
				Subject::Finding(id) => parent.target_finding_id == Some(id),
			}
	} else {
		match kind {
			JobKind::Drilldown => matches!(parent.kind, JobKind::Survey | JobKind::Drilldown),
			JobKind::Verify => parent.kind == JobKind::Drilldown,
			_ => false,
		}
	};
	if !valid {
		return Err(conflict());
	}
	Ok(())
}

/// Read-only retained subject/parent/profile binding for a queued phase retry.
/// This does not validate recipe support or grant fresh admission authority.
pub fn validate_retry_subject(tx: &Transaction<'_>, job: &jobs::JobRow) -> Result<()> {
	let subject = match job.kind {
		JobKind::Drilldown if job.target_finding_id.is_none() => {
			Subject::Lead(job.assigned_lead_id.ok_or_else(conflict)?)
		},
		JobKind::Verify if job.assigned_lead_id.is_none() => {
			Subject::Finding(job.target_finding_id.ok_or_else(conflict)?)
		},
		JobKind::Survey if job.assigned_lead_id.is_none() && job.target_finding_id.is_none() => {
			return Ok(())
		},
		_ => return Err(conflict()),
	};
	let intent = review_intents::get_subject(tx, subject)?.ok_or_else(conflict)?;
	let context = review_intents::job_context(tx, job.id)?;
	if intent.state != review_intents::State::Admitted
		|| intent.admitted_job_id != Some(job.id)
		|| intent.repo_id != job.repo_id
		|| Some(intent.admission_campaign_id) != job.campaign_id
		|| intent.generation_id != job.generation_id
		|| job.parent_job_id != Some(intent.originating_job_id)
		|| job.continuation_of_job_id
			!= (intent.kind == IntentKind::LogicalContinuation).then_some(intent.originating_job_id)
		|| job.scheduling_band != Some(intent.priority.band)
		|| job.effective_priority != Some(i64::from(intent.priority.score))
	{
		return Err(conflict());
	}
	if context.sha != intent.source_commit_sha
		|| context.profile_version != intent.profile_version
		|| context.profile_digest != intent.profile_digest
	{
		return Err(conflict());
	}
	validate_parent(tx, &intent, &job.kind)?;
	let eligible:bool=match subject {
		Subject::Lead(id)=>tx.query_row("SELECT EXISTS(SELECT 1 FROM leads WHERE lead_id=?1 AND generation_id=?2 AND status='open')",params![id,job.generation_id],|r|r.get(0))?,
		Subject::Finding(id)=>tx.query_row("SELECT EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?2 AND state='validating')",params![id,job.repo_id],|r|r.get(0))?,
	};
	if !eligible {
		return Err(conflict());
	}
	Ok(())
}

fn validate_planned_scope(
	tx: &Transaction<'_>, job: &jobs::JobRow, campaign: &campaigns::Campaign,
) -> Result<()> {
	if job.repo_id != campaign.repo_id
		|| job.campaign_id != Some(campaign.campaign_id)
		|| job.generation_id != campaign.generation_id
		|| job.head_sha.as_ref().is_some_and(|s| s != &campaign.target_commit_sha)
	{
		return Err(conflict());
	}
	if let Some(generation) = job.generation_id {
		let valid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM review_generations WHERE generation_id=?1 AND repo_id=?2 AND generation_commit_sha=?3 AND workflow_contract_version=?4)",params![generation,campaign.repo_id,campaign.target_commit_sha,WORKFLOW_CONTRACT_VERSION],|r|r.get(0))?;
		if !valid {
			return Err(Error::Conflict(Conflict::GenerationState));
		}
	} else if job.head_sha.is_some() {
		return Err(conflict());
	}
	Ok(())
}

fn lease(
	tx: &Transaction<'_>, id: i64, req: &Request<'_>, hash: &[u8; 32], expiry: i64,
	hard: Option<i64>, submit: Option<i64>,
) -> Result<()> {
	let attempts = get_job(tx, id)?.attempts.checked_add(1).ok_or_else(conflict)?;
	let changed=tx.execute("UPDATE jobs SET state='leased',worker_id=?2,lease_expires_at=?3,attempts=?4,started_at=COALESCE(started_at,?5),job_capability_hash=?6,hard_deadline_at=?7,soft_deadline_at=?8,submit_by=?8,prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id=?1 AND state='queued'",params![id,req.worker_id,expiry,attempts,req.now,hash.as_slice(),hard,submit])?;
	if changed != 1 {
		return Err(conflict());
	}
	Ok(())
}

struct NewJob<'a> {
	kind: &'a JobKind,
	band: Band,
	score: i64,
	parent: Option<i64>,
	continuation: Option<i64>,
	lead: Option<i64>,
	finding: Option<i64>,
	survey_recipe: &'a str,
}

fn insert_job(
	tx: &Transaction<'_>, campaign: &campaigns::Campaign, policy: &CampaignPolicyV2,
	new: &NewJob<'_>, now: i64,
) -> Result<i64> {
	let NewJob { kind, band, score, parent, continuation, lead, finding, survey_recipe } = *new;
	let recipe = if *kind == JobKind::Survey {
		serde_json::json!({"version":1,"phase":"survey","recipe":survey_recipe,"assignment_key":"ordinary"})
	} else {
		serde_json::json!({"version":1,"phase":kind.as_str()})
	};
	let recipe = BoundedJson::<loupe_core::text::policy::Payload>::new(&recipe.to_string())?;
	let budget = policy.phase(kind)?.token_budget;
	tx.execute("INSERT INTO jobs(repo_id,kind,state,enqueued_at,campaign_id,generation_id,parent_job_id,continuation_of_job_id,assigned_lead_id,target_finding_id,scheduling_band,effective_priority,eligible_at,token_budget,recipe,workflow_contract_version) VALUES(?1,?2,'queued',?3,?4,?5,?6,?7,?8,?9,?10,?11,?3,?12,?13,?14)",params![campaign.repo_id,kind.as_str(),now,campaign.campaign_id,campaign.generation_id,parent,continuation,lead,finding,band.as_str(),score,budget.map(|n|n as i64),recipe.expose(),WORKFLOW_CONTRACT_VERSION])?;
	Ok(tx.last_insert_rowid())
}

fn fairness(tx: &Transaction<'_>, candidate: &Candidate, req: &Request<'_>) -> Result<()> {
	let seq: i64 =
		tx.query_row("SELECT seq FROM scheduler_clock WHERE singleton=1", [], |r| r.get(0))?;
	let seq = seq.checked_add(1).filter(|n| *n > 0).ok_or_else(conflict)?;
	tx.execute("UPDATE scheduler_clock SET seq=?1 WHERE singleton=1", [seq])?;
	tx.execute("INSERT INTO scheduler_repo_state(repo_id,last_claim_seq,burst) VALUES(?1,?2,CASE WHEN ?3='survey' THEN 0 ELSE 1 END) ON CONFLICT(repo_id) DO UPDATE SET last_claim_seq=excluded.last_claim_seq,burst=CASE WHEN ?3='survey' OR scheduler_repo_state.burst>=?4 THEN 0 ELSE scheduler_repo_state.burst+1 END",params![candidate.repo_id,seq,candidate.kind.as_str(),req.policy.urgency_burst_length])?;
	Ok(())
}

/// Initial preparation is the sole job admitted before its first lease. This
/// function is also uncommitted; errors require rollback of initialization and
/// insertion. Historical policies are never upgraded or retroactively charged.
pub fn create_preparation(tx: &Transaction<'_>, campaign_id: i64, now: i64) -> Result<i64> {
	let campaign =
		campaigns::get(tx, campaign_id)?.ok_or(Error::NotFound(Entity::Campaign, campaign_id))?;
	let policy = admission::load_policy(tx, campaign_id)?;
	if now < 0
		|| (campaign.generation_id.is_some()
			&& !loupe_core::inventory_manifest::is_git_oid(&campaign.target_commit_sha))
		|| campaign.state != campaigns::State::Active
		|| campaign.deadline_at.is_some_and(|d| d <= now)
		|| !matches!(campaign.recipe, campaigns::Recipe::Bootstrap | campaigns::Recipe::Incremental)
	{
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	let recipe = if let Some(generation) = campaign.generation_id {
		let context:Option<(String,Option<i64>)>=tx.query_row("SELECT state,predecessor_generation_id FROM review_generations WHERE generation_id=?1 AND repo_id=?2 AND generation_commit_sha=?3 AND workflow_contract_version=?4",params![generation,campaign.repo_id,campaign.target_commit_sha,WORKFLOW_CONTRACT_VERSION],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
		match context {
			Some((state, _)) if state == "active" => {
				if campaign.recipe == campaigns::Recipe::Bootstrap {
					"coverage"
				} else {
					"incremental"
				}
			},
			Some((state, None))
				if state == "building" && campaign.recipe == campaigns::Recipe::Bootstrap =>
			{
				"bootstrap"
			},
			_ => return Err(Error::Conflict(Conflict::GenerationState)),
		}
	} else {
		campaign.recipe.as_str()
	};
	admission::initialize(tx, campaign_id)?;
	let id = insert_job(
		tx,
		&campaign,
		&policy,
		&NewJob {
			kind: &JobKind::Survey,
			band: Band::Normal,
			score: 0,
			parent: None,
			continuation: None,
			lead: None,
			finding: None,
			survey_recipe: recipe,
		},
		now,
	)?;
	if campaign.generation_id.is_some() && recipe != "bootstrap" {
		// Reuse the already published seal/profile; never create or republish it.
		review_intents::job_context(tx, id)?;
	}
	if !matches!(admission::charge(tx, id, WorkClass::Preparation, now)?, Charged::Fresh(_)) {
		return Err(Error::Conflict(Conflict::CampaignPolicy));
	}
	Ok(id)
}

#[cfg(test)]
mod tests;
