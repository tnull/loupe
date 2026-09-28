//! Transactional campaign orchestration. Worker checkout pins the commit.
use loupe_core::text::policy::Reason;
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_core::{JobKind, JobState, WORKFLOW_CONTRACT_VERSION};
use loupe_storage::admission::{self, CapacityRefusal, Selection};
use loupe_storage::admission_policy::CampaignPolicyV2;
use loupe_storage::review_intents::BlockReason;
use loupe_storage::{
	admission_claim, campaign_work, campaigns, generations, jobs, scheduler, transaction, Conflict,
	Db, Entity, Error, Ownership, Result,
};
use rusqlite::{params, OptionalExtension, Transaction};

use super::policy::ReviewPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindHint {
	FullReview,
	Incremental,
}
impl KindHint {
	fn as_str(self) -> &'static str {
		match self {
			Self::FullReview => "full_review",
			Self::Incremental => "incremental",
		}
	}
}

#[derive(Debug, Clone, Copy)]
pub enum RequestedRef<'a> {
	Pinned(&'a str),
	Branch(&'a str),
}
impl<'a> RequestedRef<'a> {
	fn as_str(self) -> &'a str {
		match self {
			Self::Pinned(value) | Self::Branch(value) => value,
		}
	}
}

pub struct OpenCampaign<'a> {
	pub repo_id: i64,
	pub trigger: campaigns::Trigger,
	pub requested_ref: RequestedRef<'a>,
	pub base_sha: Option<&'a str>,
	pub kind_hint: KindHint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
	Created {
		campaign_id: i64,
		job_id: i64,
	},
	Coalesced {
		campaign_id: i64,
	},
	Pending {
		campaign_id: i64,
	},
	/// Known B8-only work is retained without a preparation job or budget charge.
	Deferred {
		campaign_id: i64,
	},
}

fn get(tx: &Transaction<'_>, id: i64) -> Result<campaigns::Campaign> {
	campaigns::get(tx, id)?.ok_or(Error::NotFound(Entity::Campaign, id))
}

pub fn open(
	tx: &Transaction<'_>, new: &OpenCampaign<'_>, policy: &ReviewPolicy, now: i64,
) -> Result<Opened> {
	policy.validate_v2().map_err(|_| Error::Conflict(Conflict::CampaignPolicy))?;
	let active: Option<i64> = tx
		.query_row(
			"SELECT campaign_id FROM review_campaigns WHERE repo_id=?1 AND state='active'",
			[new.repo_id],
			|r| r.get(0),
		)
		.optional()?;
	if let Some(campaign_id) = active {
		let campaign = get(tx, campaign_id)?;
		let Some(generation_id) = campaign.generation_id else {
			return Ok(Opened::Pending { campaign_id });
		};
		let generation = generations::get(tx, generation_id)?
			.ok_or(Error::NotFound(Entity::Generation, generation_id))?;
		let previous = generation
			.pending_follow_up
			.as_ref()
			.and_then(|p| serde_json::from_str::<serde_json::Value>(p.expose()).ok());
		// Intent outlives the bounded trigger history: incremental requests
		// must not downgrade a pending full review, even after it is pruned.
		let kind_hint = if previous.as_ref().is_some_and(|p| p["kind_hint"] == "full_review") {
			KindHint::FullReview
		} else {
			new.kind_hint
		};
		let mut triggers =
			previous.and_then(|p| p["triggers"].as_array().cloned()).unwrap_or_default();
		triggers.push(
			serde_json::json!({"trigger":new.trigger.as_str(),"ref":new.requested_ref.as_str(),"at":now,"kind_hint":new.kind_hint.as_str()}),
		);
		if triggers.len() > 16 {
			triggers.drain(..triggers.len() - 16);
		}
		let pending=BoundedJson::new(&serde_json::json!({"version":1,"triggers":triggers,"newest_ref":new.requested_ref.as_str(),"kind_hint":kind_hint.as_str()}).to_string())?;
		generations::set_pending_follow_up(tx, generation_id, &pending)?;
		return Ok(Opened::Coalesced { campaign_id });
	}
	let baseline: Option<String> = tx.query_row(
		"SELECT generation_commit_sha FROM review_generations WHERE repo_id=?1 AND state='active'",
		[new.repo_id],
		|r| r.get(0),
	).optional()?;
	let known_successor = match new.requested_ref {
		RequestedRef::Pinned(sha) => {
			if !loupe_core::inventory_manifest::is_git_oid(sha) {
				return Err(loupe_core::text::Error::new(
					"commit_sha",
					loupe_core::text::Rule::Identifier,
				)
				.into());
			}
			baseline.as_ref().is_some_and(|base| base != sha)
		},
		RequestedRef::Branch(_) => false,
	};
	let initial = if baseline.is_none() {
		campaigns::Recipe::Bootstrap
	} else if new.kind_hint == KindHint::FullReview {
		campaigns::Recipe::Reconciliation
	} else {
		campaigns::Recipe::Incremental
	};
	let snapshot = policy.snapshot_v2().map_err(|_| Error::Conflict(Conflict::CampaignPolicy))?;
	let deadline = now
		.checked_add(policy.campaign_deadline_seconds)
		.ok_or(Error::Conflict(Conflict::CampaignPolicy))?;
	let campaign_id = campaigns::create(
		tx,
		&campaigns::NewCampaign {
			repo_id: new.repo_id,
			recipe: initial,
			trigger: new.trigger,
			requested_base_sha: new.base_sha,
			target_commit_sha: new.requested_ref.as_str(),
			generation_id: None,
			effective_policy: &snapshot,
			deadline_at: Some(deadline),
			root_campaign_id: None,
			continuation_of_campaign_id: None,
		},
		now,
	)?;
	if initial == campaigns::Recipe::Reconciliation || known_successor {
		let summary = campaigns::summarize(tx, campaign_id)?;
		campaigns::finish(
			tx,
			campaign_id,
			&summary,
			&BoundedText::new("unsupported_recipe")?,
			now,
		)?;
		return Ok(Opened::Deferred { campaign_id });
	}
	// Charge the single preparation job before the first lease. Branch names
	// remain unresolved until the checkout owner pins the target.
	let job_id = admission_claim::create_preparation(tx, campaign_id, now)?;
	if let RequestedRef::Pinned(sha) = new.requested_ref {
		pin(tx, campaign_id, job_id, sha, now)?;
	}
	Ok(Opened::Created { campaign_id, job_id })
}

pub fn pin(
	tx: &Transaction<'_>, campaign_id: i64, job_id: i64, sha: &str, now: i64,
) -> Result<i64> {
	if !loupe_core::inventory_manifest::is_git_oid(sha) {
		return Err(
			loupe_core::text::Error::new("commit_sha", loupe_core::text::Rule::Identifier).into()
		);
	}
	let campaign = get(tx, campaign_id)?;
	if campaign.state != campaigns::State::Active {
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	let job = jobs::get(tx, job_id)?.ok_or(Error::NotFound(Entity::Job, job_id))?;
	if job.campaign_id != Some(campaign_id)
		|| job.repo_id != campaign.repo_id
		|| job.kind != JobKind::Survey
		|| !matches!(job.state, JobState::Queued | JobState::Leased)
	{
		return Err(Error::Ownership(Ownership::CampaignJob));
	}
	if let Some(generation) = campaign.generation_id {
		return if campaign.target_commit_sha == sha {
			Ok(generation)
		} else {
			Err(Error::Conflict(Conflict::CampaignPinned))
		};
	}
	let generations = generations::list_for_repo(tx, campaign.repo_id)?;
	let active = generations.iter().find(|g| g.state == generations::State::Active);
	let existing = active.and_then(|g| {
		if g.commit_sha == sha && g.workflow_contract_version == WORKFLOW_CONTRACT_VERSION {
			Some(g.generation_id)
		} else if g.commit_sha != sha {
			generations
				.iter()
				.find(|s| {
					s.state == generations::State::Building
						&& s.commit_sha == sha
						&& s.workflow_contract_version == WORKFLOW_CONTRACT_VERSION
						&& s.predecessor_generation_id == Some(g.generation_id)
				})
				.map(|s| s.generation_id)
		} else {
			None
		}
	});
	let generation_id = if let Some(existing) = existing {
		existing
	} else {
		if active.is_none() {
			let reason = BoundedText::new("superseded bootstrap")?;
			for g in generations.iter().filter(|g| g.state == generations::State::Building) {
				generations::abandon(tx, g.generation_id, &reason, now)?;
			}
		}
		generations::create(
			tx,
			&generations::NewGeneration {
				repo_id: campaign.repo_id,
				predecessor_generation_id: active.map(|g| g.generation_id),
				commit_sha: sha,
				workflow_contract_version: WORKFLOW_CONTRACT_VERSION,
			},
			now,
		)?
	};
	tx.execute(
		"UPDATE review_campaigns SET target_commit_sha=?2,generation_id=?3 WHERE campaign_id=?1",
		params![campaign_id, sha, generation_id],
	)?;
	tx.execute("UPDATE jobs SET generation_id=?2 WHERE id=?1", params![job_id, generation_id])?;
	// A leased host request has its own uniform readiness/authorization denial.
	// Creation must validate reused ready state before committing the queued job.
	if job.state == JobState::Queued && active.is_some_and(|g| g.generation_id == generation_id) {
		campaign_work::validate_ready_job(tx, job_id)?;
	}
	Ok(generation_id)
}

/// B5 calls this once inside the bootstrap finalize checkpoint transaction.
pub fn activate_generation(tx: &Transaction<'_>, campaign_id: i64, now: i64) -> Result<()> {
	let campaign = get(tx, campaign_id)?;
	if campaign.state != campaigns::State::Active {
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	let id = campaign.generation_id.ok_or(Error::Conflict(Conflict::GenerationState))?;
	let generation = generations::get(tx, id)?.ok_or(Error::NotFound(Entity::Generation, id))?;
	if generation.predecessor_generation_id.is_some() {
		return Err(Error::Conflict(Conflict::GenerationPredecessor));
	}
	if generation.state != generations::State::Building
		|| generation.generated_profile.is_none()
		|| generation.inventory_digest.is_none()
	{
		return Err(Error::Conflict(Conflict::GenerationState));
	}
	generations::activate(tx, id, now)
}

/// Compatibility hook: coverage is materialized only when it wins first claim.
/// Observing ordinary work cannot reserve a child or consume budget.
pub fn replenish(_tx: &Transaction<'_>, _campaign_id: i64, _now: i64) -> Result<Option<i64>> {
	Ok(None)
}

pub fn cancel(
	tx: &Transaction<'_>, campaign_id: i64, reason: &BoundedText<Reason>, now: i64,
) -> Result<()> {
	scheduler::cancel_queued_children(tx, campaign_id, now, reason)?;
	campaign_work::block_all(tx, campaign_id, BlockReason::CampaignCancelled, now)?;
	campaigns::cancel(tx, campaign_id, reason, now)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
	Completed,
	DeadlineReached,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TickReport {
	pub enqueued: usize,
	pub completed: usize,
	pub deadline_reached: usize,
	pub budget_exhausted: usize,
	/// A failed campaign transaction is rolled back; other campaigns proceed.
	pub failed: usize,
}

#[derive(Default)]
struct Progress {
	finish: Option<Finish>,
	budget_exhausted: bool,
}

pub fn try_finish(tx: &Transaction<'_>, campaign_id: i64, now: i64) -> Result<Option<Finish>> {
	Ok(advance(tx, campaign_id, now)?.finish)
}

fn frozen_budget(
	tx: &Transaction<'_>, campaign: i64,
) -> Result<(CampaignPolicyV2, admission::Spending)> {
	let policy = admission::load_policy(tx, campaign)?;
	let spending =
		admission::get_spending(tx, campaign)?.ok_or(Error::Conflict(Conflict::CampaignPolicy))?;
	admission::choose_pool(&policy, spending, admission::WorkClass::Survey)?;
	Ok((policy, spending))
}

fn advance(tx: &Transaction<'_>, campaign_id: i64, now: i64) -> Result<Progress> {
	// Lifecycle decisions do not deserialize model prose or historical policy.
	let (state, recipe, deadline): (String, String, Option<i64>) = tx
		.query_row(
			"SELECT state,recipe,deadline_at FROM review_campaigns WHERE campaign_id=?1",
			[campaign_id],
			|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
		)
		.optional()?
		.ok_or(Error::NotFound(Entity::Campaign, campaign_id))?;
	let mut progress = Progress::default();
	if state != "active" {
		return Ok(progress);
	}
	let expired = deadline.is_some_and(|at| at <= now);
	let mut terminal_reason = if expired {
		Some(BlockReason::CampaignDeadline)
	} else if !matches!(recipe.as_str(), "bootstrap" | "incremental") {
		Some(BlockReason::UnsupportedRecipe)
	} else {
		None
	};
	let budget = if terminal_reason.is_none() {
		match frozen_budget(tx, campaign_id) {
			Ok(budget) => Some(budget),
			Err(Error::Conflict(Conflict::CampaignPolicy))
			| Err(Error::Sqlite(
				rusqlite::Error::InvalidColumnType(..)
				| rusqlite::Error::FromSqlConversionFailure(..),
			)) => {
				// Only incompatible frozen policy/accounting is held; unexpected
				// database failures still roll back this campaign transaction.
				terminal_reason = Some(BlockReason::CompatibilityPolicy);
				None
			},
			Err(error) => return Err(error),
		}
	} else {
		None
	};
	if let Some(reason) = terminal_reason {
		scheduler::cancel_queued_children(
			tx,
			campaign_id,
			now,
			&BoundedText::new(reason.as_str())?,
		)?;
		campaign_work::block_all(tx, campaign_id, reason, now)?;
	}
	let busy: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM jobs WHERE campaign_id=?1 AND state IN ('queued','leased'))",
		[campaign_id],
		|r| r.get(0),
	)?;
	if busy {
		return Ok(progress);
	}
	if let Some((policy, spending)) = budget {
		let mut fundable = false;
		for group in campaign_work::pending(tx, campaign_id, deadline)? {
			let reason = if !group.before_deadline {
				Some(BlockReason::CampaignDeadline)
			} else {
				match admission::choose_pool(&policy, spending, group.work_class())? {
					Selection::Pool(_) => {
						fundable = true;
						None
					},
					Selection::Refused(CapacityRefusal::CampaignBudget) => {
						progress.budget_exhausted = true;
						Some(BlockReason::CampaignBudget)
					},
					Selection::Refused(CapacityRefusal::ProtectedCapacity) => {
						Some(BlockReason::ProtectedCapacity)
					},
				}
			};
			if let Some(reason) = reason {
				campaign_work::block_pending(tx, campaign_id, group, deadline, reason, now)?;
				terminal_reason.get_or_insert(reason);
			}
		}
		if fundable {
			return Ok(progress);
		}
	}
	campaign_work::block_unexplained(tx, campaign_id, now)?;
	let summary = campaigns::summarize(tx, campaign_id)?;
	let (finish, reason) = if expired {
		(Finish::DeadlineReached, "deadline")
	} else {
		(
			Finish::Completed,
			terminal_reason.map(BlockReason::as_str).unwrap_or(
				if summary.coverage == generations::Coverage::Complete
					&& !campaign_work::has_unfinished(tx, campaign_id)?
				{
					"completed"
				} else {
					"partial"
				},
			),
		)
	};
	campaigns::finish(tx, campaign_id, &summary, &BoundedText::new(reason)?, now)?;
	progress.finish = Some(finish);
	Ok(progress)
}

/// No active campaigns means no write transaction. Each campaign otherwise
/// advances independently, so a malformed row cannot stall another repository.
pub fn tick(db: &Db, now: i64) -> Result<TickReport> {
	let active: Vec<i64> = db.with_conn(|c| {
		Ok(c.prepare(
			"SELECT campaign_id FROM review_campaigns WHERE state='active' ORDER BY campaign_id",
		)?
		.query_map([], |r| r.get(0))?
		.collect::<rusqlite::Result<_>>()?)
	})?;
	let mut report = TickReport::default();
	for campaign_id in active {
		let progress =
			db.with_conn(|c| transaction::immediate(c, |tx| advance(tx, campaign_id, now)));
		let progress = match progress {
			Ok(progress) => progress,
			Err(error) => {
				report.failed += 1;
				tracing::warn!(campaign_id, %error, "campaign tick rolled back");
				continue;
			},
		};
		match progress.finish {
			Some(Finish::Completed) => report.completed += 1,
			Some(Finish::DeadlineReached) => report.deadline_reached += 1,
			None => {},
		}
		if progress.budget_exhausted {
			report.budget_exhausted += 1;
			// The finish committed above; subsequent ticks cannot log this again.
			tracing::info!(campaign_id, "campaign budget exhausted with retained unfinished work");
		}
	}
	Ok(report)
}
