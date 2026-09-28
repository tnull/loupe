//! Caller-transactional terminal mechanics. Domain consumers validate evidence
//! and pending work; this module seals durable audit copies and replay identity.
use axum::http::HeaderMap;
use loupe_core::review_payload::ContinuationClass;
use loupe_core::text::policy::Payload;
use loupe_core::text::BoundedJson;
use loupe_proto::review_lease::FrozenReviewProfile;
use loupe_proto::review_terminal::{ContinuationBlockReason, ContinuationSummary};
use loupe_storage::review_intents::{
	self, BlockReason, Intent, IntentKind, State as IntentState, Subject,
};
use loupe_storage::terminal_payloads::TerminalPayload;
use loupe_storage::{admission, host_preparation, jobs, terminal_payloads, terminal_receipt};
use rusqlite::{params, Transaction};

use super::authority::{self, Authorized};
use super::envelope;
use super::http::{ApiError, Result};
use crate::auth::AuthedWorker;

pub fn replay(
	tx: &Transaction<'_>, worker: &AuthedWorker, headers: &HeaderMap, job: i64,
	payload: &TerminalPayload,
) -> Result<Option<Box<terminal_receipt::Receipt>>> {
	match authority::replay_terminal(tx, worker, headers, job, payload.phase(), payload)? {
		terminal_receipt::Replayed::Receipt(receipt) => Ok(Some(receipt)),
		terminal_receipt::Replayed::Reject(terminal_receipt::Reject::WrongDigest) => {
			Err(ApiError::conflict("terminal_conflict"))
		},
		terminal_receipt::Replayed::Reject(terminal_receipt::Reject::Denied) => Ok(None),
	}
}

pub struct Audit {
	pub pinned_commit_sha: String,
	pub effective_recipe: BoundedJson<Payload>,
}

/// Copies only provenance into generic JSON: no source refs or canonical
/// evidence pass through its prose normalization. The profile itself stays
/// frozen in the generation; its digest/version survive in this job audit.
pub fn audit(tx: &Transaction<'_>, scope: &Authorized<'_, '_>) -> Result<Audit> {
	let job = scope.job();
	let row = jobs::get(tx, job.id)?.ok_or_else(ApiError::denied)?;
	let generation = job.generation_id.ok_or_else(ApiError::denied)?;
	let profile = envelope::profile(tx, generation)?.ok_or_else(ApiError::denied)?;
	let manifest = host_preparation::get(tx, generation)?.ok_or_else(ApiError::denied)?;
	let policy = admission::load_policy(tx, job.campaign_id)?.snapshot()?;
	let recipe = row.recipe.ok_or_else(ApiError::denied)?;
	let sha = row.head_sha.ok_or_else(ApiError::denied)?;
	let effective_recipe = BoundedJson::new(
		&serde_json::json!({
			"version":1,"workflow_contract_version":row.workflow_contract_version,
			"recipe":serde_json::from_str::<serde_json::Value>(recipe.expose()).map_err(ApiError::invalid)?,
			"policy":serde_json::from_str::<serde_json::Value>(policy.expose()).map_err(ApiError::invalid)?,
			"policy_digest":envelope::digest(policy.digest())?,
			"profile_version":profile.profile_version,"profile_digest":profile.profile_digest,
			"manifest_digest":envelope::digest(&manifest.digest)?,"manifest_entries":manifest.expected_count,
			"manifest_canonical_bytes":manifest.received_bytes,"generation_id":generation,
			"campaign_id":job.campaign_id,"repo_id":job.repo_id,"commit_sha":sha
		})
		.to_string(),
	)
	.map_err(ApiError::invalid)?;
	Ok(Audit { pinned_commit_sha: sha, effective_recipe })
}

/// Do this before dependent intent/batch freezing in the same transaction.
/// Keep the finishing worker: receipt-only replay still binds that identity.
pub fn succeed(tx: &Transaction<'_>, job: i64, now: i64) -> Result<()> {
	let changed = tx.execute(
		"UPDATE jobs SET state='succeeded',finished_at=?2,error=NULL,
		job_capability_hash=NULL,lease_expires_at=NULL,prepared_attempt=NULL,
		prepared_capability_hash=NULL,prepared_at=NULL WHERE id=?1 AND state='leased'",
		params![job, now],
	)?;
	if changed != 1 {
		return Err(ApiError::conflict("terminal_conflict"));
	}
	Ok(())
}

pub fn seal(
	tx: &Transaction<'_>, receipt: &terminal_receipt::NewReceipt<'_>, payload: &TerminalPayload,
	now: i64,
) -> Result<terminal_receipt::Receipt> {
	terminal_receipt::insert(tx, receipt, now)?;
	terminal_payloads::insert(tx, receipt.job_id, payload)?;
	terminal_receipt::get(tx, receipt.job_id)?.ok_or_else(ApiError::denied)
}

fn incompatible() -> ApiError {
	ApiError::conflict("incompatible_review_state")
}

/// The retained accepted priority and exact admitted revision are the only
/// source of downstream admission rank. A missing intent cannot be fabricated.
pub fn admitted_subject(
	tx: &Transaction<'_>, scope: &Authorized<'_, '_>, subject: Subject, sha: &str,
	profile: &FrozenReviewProfile,
) -> Result<Intent> {
	let intent = review_intents::get_subject(tx, subject)?.ok_or_else(incompatible)?;
	let job = jobs::get(tx, scope.job().id)?.ok_or_else(ApiError::denied)?;
	let owns_subject = match subject {
		Subject::Lead(id) => {
			job.kind == loupe_core::JobKind::Drilldown && job.assigned_lead_id == Some(id)
		},
		Subject::Finding(id) => {
			job.kind == loupe_core::JobKind::Verify && job.target_finding_id == Some(id)
		},
	};
	if !owns_subject
		|| intent.state != IntentState::Admitted
		|| intent.admitted_job_id != Some(job.id)
		|| intent.repo_id != job.repo_id
		|| intent.generation_id != job.generation_id
		|| Some(intent.admission_campaign_id) != job.campaign_id
		|| intent.source_commit_sha != sha
		|| intent.profile_version != i64::from(profile.profile_version.get())
		|| intent.profile_digest != profile.profile.digest()
		|| intent.revision <= 0
		|| intent.logical_sequence < 0
		|| intent.priority.score > 550
		|| job.parent_job_id != Some(intent.originating_job_id)
		|| job.scheduling_band != Some(intent.priority.band)
		|| job.continuation_of_job_id
			!= match intent.kind {
				IntentKind::InitialHandoff => None,
				IntentKind::LogicalContinuation => Some(intent.originating_job_id),
			} {
		return Err(incompatible());
	}
	Ok(intent)
}

pub fn continuation(intent: &Intent) -> Result<ContinuationSummary> {
	let class = intent.continuation_class.ok_or_else(incompatible)?;
	let revision = intent.revision.try_into().map_err(|_| incompatible())?;
	let logical_sequence = intent.logical_sequence.try_into().map_err(|_| incompatible())?;
	match intent.state {
		IntentState::Pending
			if class == ContinuationClass::SourceAnalysisRemaining
				&& intent.block_reason.is_none() =>
		{
			Ok(ContinuationSummary::Pending {
				class,
				revision,
				logical_sequence,
				not_before: intent.not_before.ok_or_else(incompatible)?,
			})
		},
		IntentState::Blocked if intent.not_before.is_none() => {
			let reason = match (class, intent.block_reason) {
				(
					ContinuationClass::AwaitingProofInfrastructure,
					Some(BlockReason::AwaitingProofInfrastructure),
				) => ContinuationBlockReason::AwaitingProofInfrastructure,
				(ContinuationClass::ExternalDependency, Some(BlockReason::ExternalDependency)) => {
					ContinuationBlockReason::ExternalDependency
				},
				(ContinuationClass::RequiresSuccessor, Some(BlockReason::RequiresSuccessor)) => {
					ContinuationBlockReason::RequiresSuccessor
				},
				_ => return Err(incompatible()),
			};
			Ok(ContinuationSummary::Blocked { class, revision, logical_sequence, reason })
		},
		_ => Err(incompatible()),
	}
}
