//! Caller-transactional terminal mechanics. Domain consumers validate evidence
//! and pending work; this module seals durable audit copies and replay identity.
use axum::http::HeaderMap;
use loupe_core::text::policy::Payload;
use loupe_core::text::BoundedJson;
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
