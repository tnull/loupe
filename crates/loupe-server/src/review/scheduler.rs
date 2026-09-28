//! The sole production claim owner: rank, validate, tentatively materialize,
//! serialize, then commit. Permanent data repair is bounded and transactional.
use std::time::{SystemTime, UNIX_EPOCH};

use loupe_core::JobKind;
use loupe_proto::review_lease::ReviewCapability;
use loupe_proto::{JobCapability, LeaseRequest, LeaseResponse};
use loupe_storage::{
	admission_candidates as candidates, admission_claim, admission_quarantine as quarantine, jobs,
	scheduler, Result,
};
use rusqlite::{Transaction, TransactionBehavior};

use super::admission_validation::{self as validation, Failure};
use crate::state::AppState;

pub(crate) const MAX_REPAIRS: u32 = 32;
const LEASE_BYTES: usize = 4 * 1024 * 1024;

pub fn claim_for_worker(
	state: &AppState, worker_id: i64, request: &LeaseRequest, repairs_left: &mut u32,
) -> Result<Option<Vec<u8>>> {
	if *repairs_left > MAX_REPAIRS {
		return Err(loupe_storage::Error::Conflict(loupe_storage::Conflict::CampaignPolicy));
	}
	// The route owns this budget across every long-poll wakeup. Only commit
	// consumes it: an unexpected error rolls back both work and local progress.
	let mut remaining = *repairs_left;
	let legacy: Vec<_> = jobs::LEGACY_RUNTIME_KINDS
		.iter()
		.filter(|kind| {
			**kind != JobKind::Verify
				|| request.capabilities.iter().any(|c| c.starts_with("verify:"))
		})
		.cloned()
		.collect();
	let phase: Vec<_> = request
		.review_capabilities
		.as_slice()
		.iter()
		.map(|c| match c {
			ReviewCapability::Survey => JobKind::Survey,
			ReviewCapability::Drilldown => JobKind::Drilldown,
			ReviewCapability::Verify => JobKind::Verify,
		})
		.filter(|kind| {
			jobs::RUNTIME_KINDS.contains(kind) && scheduler::PHASE_RUNTIME_KINDS.contains(kind)
		})
		.collect();
	let (capability, hash) = crate::job_capability::issue();
	let bytes = state.db.with_conn(|conn| {
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
		let req = candidates::Request {
			worker_id,
			legacy_kinds: &legacy,
			phase_kinds: &phase,
			now,
			policy: &state.review_policy.claim_policy(),
			limit: 1,
		};
		let bytes =
			claim_in_transaction(&tx, &req, &capability, &hash, LEASE_BYTES, &mut remaining)?;
		tx.commit()?;
		Ok(bytes)
	})?;
	*repairs_left = remaining;
	Ok(bytes)
}

fn claim_in_transaction(
	tx: &Transaction<'_>, req: &candidates::Request<'_>, capability: &JobCapability,
	hash: &[u8; 32], limit: usize, repairs_left: &mut u32,
) -> Result<Option<Vec<u8>>> {
	let active: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM workers WHERE id=?1 AND kind='worker' AND revoked_at IS NULL)",
		[req.worker_id],
		|row| row.get(0),
	)?;
	if !active {
		return Err(loupe_storage::Error::Conflict(loupe_storage::Conflict::JobState));
	}
	while *repairs_left > 0 {
		let Some(candidate) = candidates::ranked(tx, req)?.into_iter().next() else {
			return Ok(None);
		};
		let source = validation::source(&candidate);
		tx.execute_batch("SAVEPOINT review_claim_candidate")?;
		let attempt = (|| -> validation::Result<Option<Vec<u8>>> {
			validation::validate_source(tx, source)?;
			let claim = match admission_claim::materialize(
				tx,
				&candidate,
				req,
				hash,
				jobs::DEFAULT_LEASE_SECONDS,
			)? {
				admission_claim::Outcome::Uncommitted(claim) => claim,
				admission_claim::Outcome::Stale | admission_claim::Outcome::CapacityRefused(_) => {
					return Ok(None)
				},
			};
			let envelope = super::envelope::build(tx, &claim.job, capability.clone())?;
			let bytes =
				super::http::serialize_bounded(&LeaseResponse::Lease(Box::new(envelope)), limit)
					.map_err(|_| validation::invalid())?;
			Ok(Some(bytes))
		})();
		match attempt {
			Ok(bytes) => {
				tx.execute_batch("RELEASE review_claim_candidate")?;
				return Ok(bytes);
			},
			Err(Failure::Unexpected(error)) => return Err(error),
			Err(error) => {
				tx.execute_batch(
					"ROLLBACK TO review_claim_candidate; RELEASE review_claim_candidate",
				)?;
				let (source, reason) = match error {
					Failure::Defect(reason) => (source, reason),
					Failure::Unit(id, reason)
						if matches!(source, quarantine::Source::Ordinary(_)) =>
					{
						(quarantine::Source::Unit(id), reason)
					},
					Failure::Unit(_, reason) => (source, reason),
					Failure::Unexpected(_) => unreachable!(),
				};
				if !quarantine::hold(tx, source, reason, req.now)? {
					return Err(loupe_storage::Error::Conflict(loupe_storage::Conflict::JobState));
				}
				*repairs_left -= 1;
			},
		}
	}
	Ok(None)
}

#[cfg(test)]
mod tests;
