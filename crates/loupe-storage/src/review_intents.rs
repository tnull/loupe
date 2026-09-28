//! One durable, revisioned handoff per lead or canonical finding.
//!
//! All writes belong to the caller's immediate transaction, together with the
//! accepted checkpoint/terminal result. This module neither creates jobs nor
//! spends admission capacity. A successful first lease and its charge must be
//! committed atomically with `admit_subject`.
use loupe_core::inventory_manifest::is_git_oid;
use loupe_core::review_payload::{ContinuationClass, GeneratedProfile};
use loupe_core::{JobKind, JobState};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::admission_policy::{AcceptedPriority, CampaignPolicyV2};
use crate::review::{changed, optional, parsed, string_enum};
use crate::{admission, jobs, unit_holds, Conflict, Entity, Error, Result};

string_enum!(State { Pending=>"pending", Blocked=>"blocked", Admitted=>"admitted", Complete=>"complete" });
string_enum!(IntentKind { InitialHandoff=>"initial_handoff", LogicalContinuation=>"logical_continuation" });
string_enum!(BlockReason {
 AwaitingProofInfrastructure=>"awaiting_proof_infrastructure", ExternalDependency=>"external_dependency",
 RequiresSuccessor=>"requires_successor", CampaignBudget=>"campaign_budget", ProtectedCapacity=>"protected_capacity",
 CampaignCancelled=>"campaign_cancelled", CampaignDeadline=>"campaign_deadline", ExecutionExhausted=>"execution_exhausted",
 UnsupportedRecipe=>"unsupported_recipe", CompatibilityPolicy=>"compatibility_policy"
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
	Lead(i64),
	Finding(i64),
}
impl Subject {
	pub fn id(self) -> i64 {
		match self {
			Self::Lead(id) | Self::Finding(id) => id,
		}
	}
	fn table(self) -> &'static str {
		match self {
			Self::Lead(_) => "lead_drilldown_intents",
			Self::Finding(_) => "finding_verification_intents",
		}
	}
	fn key(self) -> &'static str {
		match self {
			Self::Lead(_) => "lead_id",
			Self::Finding(_) => "finding_id",
		}
	}
	fn phase(self) -> JobKind {
		match self {
			Self::Lead(_) => JobKind::Drilldown,
			Self::Finding(_) => JobKind::Verify,
		}
	}
	fn with_id(self, id: i64) -> Self {
		match self {
			Self::Lead(_) => Self::Lead(id),
			Self::Finding(_) => Self::Finding(id),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
	pub subject: Subject,
	pub repo_id: i64,
	pub generation_id: Option<i64>,
	pub originating_job_id: i64,
	pub originating_campaign_id: i64,
	pub admission_campaign_id: i64,
	pub source_commit_sha: String,
	pub profile_version: i64,
	pub profile_digest: Vec<u8>,
	pub revision: i64,
	pub kind: IntentKind,
	pub continuation_class: Option<ContinuationClass>,
	pub logical_sequence: i64,
	pub state: State,
	pub not_before: Option<i64>,
	pub block_reason: Option<BlockReason>,
	pub admitted_job_id: Option<i64>,
	pub priority: AcceptedPriority,
	pub created_at: i64,
	pub updated_at: i64,
}
const COLUMNS: &str = "repo_id,generation_id,originating_job_id,originating_campaign_id,admission_campaign_id,source_commit_sha,profile_version,profile_digest,intent_revision,intent_kind,continuation_class,logical_sequence,state,not_before,block_reason,admitted_job_id,accepted_band,accepted_score,created_at,updated_at";
fn row(r: &Row<'_>, subject: Subject) -> rusqlite::Result<Intent> {
	Ok(Intent {
		subject,
		repo_id: r.get(0)?,
		generation_id: r.get(1)?,
		originating_job_id: r.get(2)?,
		originating_campaign_id: r.get(3)?,
		admission_campaign_id: r.get(4)?,
		source_commit_sha: r.get(5)?,
		profile_version: r.get(6)?,
		profile_digest: r.get(7)?,
		revision: r.get(8)?,
		kind: parsed(r, 9)?,
		continuation_class: r
			.get::<_, Option<String>>(10)?
			.map(|s| parse_class(&s, 10))
			.transpose()?,
		logical_sequence: r.get(11)?,
		state: parsed(r, 12)?,
		not_before: r.get(13)?,
		block_reason: optional(r, 14)?,
		admitted_job_id: r.get(15)?,
		priority: AcceptedPriority { band: parsed(r, 16)?, score: r.get(17)? },
		created_at: r.get(18)?,
		updated_at: r.get(19)?,
	})
}
pub fn get_subject(conn: &Connection, subject: Subject) -> Result<Option<Intent>> {
	Ok(conn
		.query_row(
			&format!("SELECT {COLUMNS} FROM {} WHERE {}=?1", subject.table(), subject.key()),
			[subject.id()],
			|r| row(r, subject),
		)
		.optional()?)
}
/// Bounded metadata pagination; selection/ranking belongs to the joined scheduler.
/// `kind` selects the lead/finding table; its contained ID is ignored.
pub fn list_subjects(
	conn: &Connection, kind: Subject, campaign: i64, after_id: i64, limit: u32,
) -> Result<Vec<Intent>> {
	if !(1..=256).contains(&limit) {
		return Err(Error::Conflict(Conflict::CampaignPolicy));
	}
	Ok(conn.prepare(&format!("SELECT {COLUMNS},{} FROM {} WHERE admission_campaign_id=?1 AND {}>?2 ORDER BY {} LIMIT ?3",kind.key(),kind.table(),kind.key(),kind.key()))?.query_map(params![campaign,after_id,limit],|r|row(r,kind.with_id(r.get(20)?)))?.collect::<rusqlite::Result<_>>()?)
}

pub(crate) fn class_str(class: ContinuationClass) -> &'static str {
	match class {
		ContinuationClass::SourceAnalysisRemaining => "source_analysis_remaining",
		ContinuationClass::AwaitingProofInfrastructure => "awaiting_proof_infrastructure",
		ContinuationClass::ExternalDependency => "external_dependency",
		ContinuationClass::RequiresSuccessor => "requires_successor",
	}
}
pub(crate) fn parse_class(raw: &str, index: usize) -> rusqlite::Result<ContinuationClass> {
	serde_json::from_value(serde_json::Value::String(raw.to_owned())).map_err(|e| {
		rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, Box::new(e))
	})
}
pub(crate) fn continuation_state(
	policy: &CampaignPolicyV2, class: ContinuationClass, sequence: i64, now: i64,
) -> Result<(State, Option<i64>, Option<BlockReason>)> {
	let reason = match class {
		ContinuationClass::SourceAnalysisRemaining => {
			return Ok((
				State::Pending,
				Some(policy.logical_not_before(
					now,
					sequence.try_into().map_err(|_| Error::Conflict(Conflict::JobState))?,
				)?),
				None,
			))
		},
		ContinuationClass::AwaitingProofInfrastructure => BlockReason::AwaitingProofInfrastructure,
		ContinuationClass::ExternalDependency => BlockReason::ExternalDependency,
		ContinuationClass::RequiresSuccessor => BlockReason::RequiresSuccessor,
	};
	Ok((State::Blocked, None, Some(reason)))
}

pub(crate) struct JobContext {
	pub job: jobs::JobRow,
	pub generation: i64,
	pub campaign: i64,
	pub sha: String,
	pub profile_version: i64,
	pub profile_digest: Vec<u8>,
	pub policy: CampaignPolicyV2,
}
/// Planned identity is available before a new child confirms its checkout.
/// Reading it grants no preparation or evidence-producing authority.
pub(crate) fn job_context(tx: &Transaction<'_>, id: i64) -> Result<JobContext> {
	let job = jobs::get(tx, id)?.ok_or(Error::NotFound(Entity::Job, id))?;
	let generation = job.generation_id.ok_or(Error::Conflict(Conflict::GenerationState))?;
	let campaign = job.campaign_id.ok_or(Error::Conflict(Conflict::CampaignState))?;
	let context=tx.query_row("SELECT g.generation_commit_sha,g.profile_version,g.generated_profile,g.generated_profile_digest FROM review_generations g JOIN review_campaigns c ON c.generation_id=g.generation_id AND c.repo_id=g.repo_id WHERE g.generation_id=?1 AND g.repo_id=?2 AND c.campaign_id=?3 AND c.target_commit_sha=g.generation_commit_sha AND g.workflow_contract_version=1 AND g.state IN('building','active') AND EXISTS(SELECT 1 FROM generation_manifests m WHERE m.generation_id=g.generation_id AND m.sealed_at IS NOT NULL AND m.received_entry_count=m.expected_entry_count)",params![generation,job.repo_id,campaign],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,Option<Vec<u8>>>(3)?))).optional()?;
	let Some((sha, profile_version, Some(raw), Some(profile_digest))) = context else {
		return Err(Error::Conflict(Conflict::GenerationState));
	};
	let profile = GeneratedProfile::new(&raw)?;
	if !is_git_oid(&sha)
		|| job.head_sha.as_ref().is_some_and(|head| head != &sha)
		|| !(1..=i64::from(u32::MAX)).contains(&profile_version)
		|| profile.expose() != raw
		|| profile.digest().as_slice() != profile_digest
		|| job.workflow_contract_version != Some(1)
	{
		return Err(Error::Conflict(Conflict::GenerationState));
	}
	let policy = admission::load_policy(tx, campaign)?;
	Ok(JobContext { job, generation, campaign, sha, profile_version, profile_digest, policy })
}
/// Evidence provenance still requires a confirmed pinned checkout.
pub(crate) fn producer(tx: &Transaction<'_>, id: i64) -> Result<JobContext> {
	let context = job_context(tx, id)?;
	if context.job.head_sha.as_deref() != Some(context.sha.as_str()) {
		return Err(Error::Conflict(Conflict::GenerationState));
	}
	Ok(context)
}

pub fn ensure_drilldown_intent(
	tx: &Transaction<'_>, lead: i64, producing_job: i64, priority: AcceptedPriority, now: i64,
) -> Result<Option<Intent>> {
	let p = producer(tx, producing_job)?;
	if !matches!(p.job.kind, JobKind::Survey | JobKind::Drilldown) {
		return Err(Error::Conflict(Conflict::JobState));
	}
	let status=tx.query_row("SELECT status FROM leads l WHERE lead_id=?1 AND generation_id=?2 AND commit_sha=?3 AND (created_by_job_id=?4 OR EXISTS(SELECT 1 FROM lead_observations o WHERE o.lead_id=l.lead_id AND o.submitted_by_job_id=?4 AND o.commit_sha=?3))",params![lead,p.generation,p.sha,producing_job],|r|r.get::<_,String>(0)).optional()?.ok_or(Error::Conflict(Conflict::LeadState))?;
	let subject = Subject::Lead(lead);
	if let Some(existing) = get_subject(tx, subject)? {
		return Ok(Some(existing));
	}
	if status!="open" || tx.query_row("SELECT EXISTS(SELECT 1 FROM jobs WHERE assigned_lead_id=?1 AND kind='drilldown' AND state IN('queued','leased'))",[lead],|r|r.get::<_,bool>(0))? {return Ok(None);}
	insert_initial(tx, subject, &p, priority, now)?;
	get_subject(tx, subject)
}
pub fn ensure_verification_intent(
	tx: &Transaction<'_>, finding: i64, producing_job: i64, priority: AcceptedPriority, now: i64,
) -> Result<Option<Intent>> {
	let p = producer(tx, producing_job)?;
	if p.job.kind != JobKind::Drilldown {
		return Err(Error::Conflict(Conflict::JobState));
	}
	let valid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM findings f JOIN finding_review_details d ON d.finding_id=f.id JOIN leads l ON l.lead_id=d.origin_lead_id WHERE f.id=?1 AND f.repo_id=?2 AND d.repo_id=f.repo_id AND d.reviewed_commit_sha=?3 AND d.profile_version=?4 AND d.profile_digest=?5 AND d.workflow_contract_version=1 AND l.lead_id=?6 AND l.generation_id=?7 AND l.status='closed' AND l.disposition='promoted' AND l.promoted_finding_id=f.id)",params![finding,p.job.repo_id,p.sha,p.profile_version,p.profile_digest,p.job.assigned_lead_id,p.generation],|r|r.get(0))?;
	if !valid {
		return Err(Error::Conflict(Conflict::FindingDetails));
	}
	let subject = Subject::Finding(finding);
	if let Some(existing) = get_subject(tx, subject)? {
		return Ok(Some(existing));
	}
	let eligible:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM findings f WHERE f.id=?1 AND f.state='validating' AND NOT EXISTS(SELECT 1 FROM jobs j WHERE j.target_finding_id=f.id AND j.kind='verify' AND j.state IN('queued','leased')))",[finding],|r|r.get(0))?;
	if !eligible {
		return Ok(None);
	}
	insert_initial(tx, subject, &p, priority, now)?;
	get_subject(tx, subject)
}
fn insert_initial(
	tx: &Transaction<'_>, subject: Subject, p: &JobContext, priority: AcceptedPriority, now: i64,
) -> Result<()> {
	if priority.score > 550 || !matches!(p.job.state, JobState::Leased | JobState::Succeeded) {
		return Err(Error::Conflict(Conflict::JobState));
	}
	tx.execute(&format!("INSERT INTO {} ({},repo_id,generation_id,originating_job_id,originating_campaign_id,admission_campaign_id,source_commit_sha,profile_version,profile_digest,intent_revision,intent_kind,logical_sequence,state,accepted_band,accepted_score,priority_policy_version,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?5,?6,?7,?8,1,'initial_handoff',0,'pending',?9,?10,1,?11,?11)",subject.table(),subject.key()),params![subject.id(),p.job.repo_id,p.generation,p.job.id,p.campaign,p.sha,p.profile_version,p.profile_digest,priority.band.as_str(),priority.score,now])?;
	Ok(())
}

/// Read-only permanent eligibility shared by admission and maintenance. This
/// does not filter by due time, worker capability, active jobs or capacity, and
/// does not authorize admission by itself. Admitted execution retries retain
/// their separate (open-only lead) checks.
pub fn pending_subject_eligible(conn: &Connection, intent: &Intent) -> Result<bool> {
	let continuation = match intent.kind {
		IntentKind::InitialHandoff
			if intent.logical_sequence == 0 && intent.continuation_class.is_none() =>
		{
			false
		},
		IntentKind::LogicalContinuation
			if intent.logical_sequence > 0
				&& intent.continuation_class
					== Some(ContinuationClass::SourceAnalysisRemaining) =>
		{
			true
		},
		_ => return Ok(false),
	};
	Ok(match intent.subject {
		Subject::Lead(id)=>conn.query_row("SELECT EXISTS(SELECT 1 FROM leads WHERE lead_id=?1 AND generation_id=?2 AND (status='open' OR (status='deferred' AND ?3=1)))",params![id,intent.generation_id,continuation],|r|r.get(0))?,
		Subject::Finding(id)=>conn.query_row("SELECT EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?2 AND state='validating')",params![id,intent.repo_id],|r|r.get(0))?,
	})
}

/// Called after the child received its first live lease, in the same transaction.
pub fn admit_subject(
	tx: &Transaction<'_>, subject: Subject, revision: i64, child: i64, now: i64,
) -> Result<Intent> {
	let intent = get_subject(tx, subject)?.ok_or(Error::Conflict(Conflict::JobState))?;
	let p = job_context(tx, child)?;
	validate_child(tx, &p, intent.originating_job_id, now)?;
	if p.job.kind != subject.phase()
		|| p.job.repo_id != intent.repo_id
		|| Some(p.generation) != intent.generation_id
		|| p.campaign != intent.admission_campaign_id
		|| p.sha != intent.source_commit_sha
		|| p.profile_version != intent.profile_version
		|| p.profile_digest != intent.profile_digest
		|| match subject {
			Subject::Lead(id) => p.job.assigned_lead_id != Some(id),
			Subject::Finding(id) => p.job.target_finding_id != Some(id),
		}
		|| p.job.scheduling_band != Some(intent.priority.band)
	{
		return Err(Error::Conflict(Conflict::Assignment));
	}
	if intent.revision == revision
		&& intent.state == State::Admitted
		&& intent.admitted_job_id == Some(child)
	{
		return Ok(intent);
	}
	if p.job.continuation_of_job_id
		!= match intent.kind {
			IntentKind::InitialHandoff => None,
			IntentKind::LogicalContinuation => Some(intent.originating_job_id),
		} {
		return Err(Error::Conflict(Conflict::Assignment));
	}
	if !pending_subject_eligible(tx, &intent)? {
		return Err(Error::Conflict(Conflict::Assignment));
	}
	changed(tx.execute(&format!("UPDATE {} SET state='admitted',admitted_job_id=?3,updated_at=?4 WHERE {}=?1 AND intent_revision=?2 AND state='pending' AND block_reason IS NULL AND (not_before IS NULL OR not_before<=?4)",subject.table(),subject.key()),params![subject.id(),revision,child,now])?,Conflict::Assignment)?;
	if let Subject::Lead(id) = subject {
		tx.execute("UPDATE leads SET status='open',defer_reason=NULL,retry_condition=NULL WHERE lead_id=?1 AND status='deferred'",[id])?;
	}
	get_subject(tx, subject)?.ok_or(Error::Conflict(Conflict::JobState))
}

pub(crate) fn validate_child(
	tx: &Transaction<'_>, child: &JobContext, parent: i64, now: i64,
) -> Result<()> {
	let valid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM jobs j JOIN review_campaigns c ON c.campaign_id=j.campaign_id JOIN review_generations g ON g.generation_id=j.generation_id JOIN workers w ON w.id=j.worker_id WHERE j.id=?1 AND j.state='leased' AND j.attempts=1 AND j.job_capability_hash IS NOT NULL AND length(j.job_capability_hash)=32 AND j.lease_expires_at>?2 AND c.state='active' AND (c.deadline_at IS NULL OR c.deadline_at>?2) AND (g.state='active' OR (j.kind IN('drilldown','verify') AND g.state='building' AND g.predecessor_generation_id IS NULL AND c.recipe='bootstrap')) AND w.revoked_at IS NULL AND w.kind='worker')",params![child.job.id,now],|r|r.get(0))?;
	if !valid || child.job.parent_job_id != Some(parent) {
		return Err(Error::Conflict(Conflict::Assignment));
	}
	Ok(())
}

/// Advance only the admitted current revision; the finishing job becomes the
/// next revision's producer, never the previously admitted child's successor.
pub fn continue_subject(
	tx: &Transaction<'_>, subject: Subject, finishing_job: i64, class: ContinuationClass, now: i64,
) -> Result<Intent> {
	let intent = get_subject(tx, subject)?.ok_or(Error::Conflict(Conflict::JobState))?;
	let p = producer(tx, finishing_job)?;
	check_finisher(&intent, &p)?;
	let sequence =
		intent.logical_sequence.checked_add(1).ok_or(Error::Conflict(Conflict::JobState))?;
	let revision = intent.revision.checked_add(1).ok_or(Error::Conflict(Conflict::JobState))?;
	let (state, not_before, reason) = continuation_state(&p.policy, class, sequence, now)?;
	changed(tx.execute(&format!("UPDATE {} SET originating_job_id=?3,originating_campaign_id=?4,admission_campaign_id=?4,intent_revision=?5,intent_kind='logical_continuation',continuation_class=?6,logical_sequence=?7,state=?8,not_before=?9,block_reason=?10,admitted_job_id=NULL,updated_at=?11 WHERE {}=?1 AND intent_revision=?2 AND state='admitted' AND admitted_job_id=?3",subject.table(),subject.key()),params![subject.id(),intent.revision,finishing_job,p.campaign,revision,class_str(class),sequence,state.as_str(),not_before,reason.map(BlockReason::as_str),now])?,Conflict::JobState)?;
	get_subject(tx, subject)?.ok_or(Error::Conflict(Conflict::JobState))
}
fn check_finisher(intent: &Intent, p: &JobContext) -> Result<()> {
	if intent.state != State::Admitted
		|| intent.admitted_job_id != Some(p.job.id)
		|| p.job.kind != intent.subject.phase()
		|| p.job.state != JobState::Succeeded
		|| p.job.repo_id != intent.repo_id
		|| p.campaign != intent.admission_campaign_id
		|| Some(p.generation) != intent.generation_id
		|| p.sha != intent.source_commit_sha
		|| p.profile_version != intent.profile_version
		|| p.profile_digest != intent.profile_digest
		|| match intent.subject {
			Subject::Lead(id) => p.job.assigned_lead_id != Some(id),
			Subject::Finding(id) => p.job.target_finding_id != Some(id),
		} {
		return Err(Error::Conflict(Conflict::JobState));
	}
	Ok(())
}
pub fn finish_subject_intent(
	tx: &Transaction<'_>, subject: Subject, finishing_job: i64, now: i64,
) -> Result<()> {
	let intent = get_subject(tx, subject)?.ok_or(Error::Conflict(Conflict::JobState))?;
	check_finisher(&intent, &producer(tx, finishing_job)?)?;
	changed(tx.execute(&format!("UPDATE {} SET state='complete',not_before=NULL,block_reason=NULL,updated_at=?3 WHERE {}=?1 AND state='admitted' AND admitted_job_id=?2",subject.table(),subject.key()),params![subject.id(),finishing_job,now])?,Conflict::JobState)
}

/// Lifecycle control, deliberately independent of the already revoked token.
/// Accepted evidence survives cancellation/deadline/execution exhaustion.
pub fn block_job_work(
	tx: &Transaction<'_>, job_id: i64, reason: BlockReason, now: i64,
) -> Result<()> {
	let terminal = tx
		.query_row("SELECT state IN ('failed','cancelled') FROM jobs WHERE id=?1", [job_id], |r| {
			r.get::<_, bool>(0)
		})
		.optional()?
		.ok_or(Error::NotFound(Entity::Job, job_id))?;
	if !terminal
		|| !matches!(
			reason,
			BlockReason::CampaignCancelled
				| BlockReason::CampaignDeadline
				| BlockReason::ExecutionExhausted
				| BlockReason::UnsupportedRecipe
				| BlockReason::CompatibilityPolicy
		) {
		return Err(Error::Conflict(Conflict::JobState));
	}
	for table in ["lead_drilldown_intents", "finding_verification_intents"] {
		tx.execute(&format!("UPDATE {table} SET state='blocked',not_before=NULL,block_reason=?2,updated_at=?3 WHERE admitted_job_id=?1 AND state='admitted'"),params![job_id,reason.as_str(),now])?;
	}
	unit_holds::block_job_work(tx, job_id, reason, now)
}

#[cfg(test)]
pub(crate) mod tests;
