//! Shared phase authority. Call inside the same immediate transaction as each
//! mutation or authority-issuing read, never only as an HTTP precheck.
//!
//! This module does not enable routes or runtime claims. Access purpose and
//! expected phase are selected by the server, never deserialized from requests.
use axum::http::HeaderMap;
use loupe_core::review_payload::Version1;
use loupe_core::JobKind;
use loupe_storage::terminal_payloads::TerminalPayload;
use loupe_storage::{jobs, review_authority as stored, terminal_receipt, Result};
use rusqlite::Transaction;
use serde::Deserialize;

use crate::auth::AuthedWorker;
use crate::job_capability;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
	/// Payload-free execution failure only, including after analysis deadline.
	LeaseControl,
	Checkout,
	PreparedHost,
	Domain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SurveyRecipe {
	Bootstrap,
	Coverage,
	Incremental,
	Reconciliation,
	Corroboration,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum AssignmentKey {
	Ordinary,
}

#[derive(Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Recipe {
	Survey {
		#[serde(rename = "version")]
		_version: Version1,
		recipe: SurveyRecipe,
		#[serde(rename = "assignment_key")]
		_assignment_key: AssignmentKey,
	},
	Drilldown {
		#[serde(rename = "version")]
		_version: Version1,
	},
	Verify {
		#[serde(rename = "version")]
		_version: Version1,
	},
}

impl Recipe {
	fn phase(&self) -> JobKind {
		match self {
			Self::Survey { .. } => JobKind::Survey,
			Self::Drilldown { .. } => JobKind::Drilldown,
			Self::Verify { .. } => JobKind::Verify,
		}
	}
	fn bootstrap(&self) -> bool {
		matches!(self, Self::Survey { recipe: SurveyRecipe::Bootstrap, .. })
	}
	fn supported(&self, context: &stored::Context, access: Access) -> bool {
		if !matches!(context.campaign_recipe.as_str(), "bootstrap" | "incremental") {
			return false;
		}
		let Some(generation) = &context.generation else {
			return access == Access::Checkout
				&& context.head_sha.is_none()
				&& match self {
					Self::Survey { recipe: SurveyRecipe::Bootstrap, .. } => {
						context.campaign_recipe == "bootstrap"
					},
					Self::Survey { recipe: SurveyRecipe::Incremental, .. } => {
						context.campaign_recipe == "incremental"
					},
					_ => false,
				};
		};
		if generation.commit != context.target_commit {
			return false;
		}
		let active = generation.state == "active";
		let bootstrap = generation.state == "building"
			&& generation.predecessor.is_none()
			&& context.campaign_recipe == "bootstrap";
		match self {
			Self::Survey { recipe: SurveyRecipe::Bootstrap, .. } => bootstrap,
			Self::Survey { recipe: SurveyRecipe::Coverage, .. } => active,
			Self::Survey { recipe: SurveyRecipe::Incremental, .. } => {
				active && context.campaign_recipe == "incremental"
			},
			Self::Survey { .. } => false,
			Self::Drilldown { .. } | Self::Verify { .. } => active || bootstrap,
		}
	}
}

/// Private construction and a borrow of the actual transaction keep an HTTP
/// precheck snapshot from becoming an authorization token for a later write.
pub struct Authorized<'tx, 'conn> {
	lease: stored::Lease<'tx, 'conn>,
	access: Access,
	bootstrap: bool,
}

impl Authorized<'_, '_> {
	pub fn job(&self) -> &stored::Job {
		self.lease.job()
	}

	/// Fresh-only subject checks belong inside `checkpoints::run`'s callback,
	/// after exact replay lookup. Scope alone never grants payload/quota validity.
	pub fn survey_unit(&self, unit: i64, epoch: i64) -> Result<bool> {
		Ok(self.access == Access::Domain
			&& self.job().kind == JobKind::Survey
			&& self.lease.survey_unit(unit, epoch, self.bootstrap)?)
	}
	pub fn assigned_lead(&self, lead: i64) -> Result<bool> {
		Ok(self.access == Access::Domain
			&& self.job().kind == JobKind::Drilldown
			&& self.lease.assigned_lead(lead)?)
	}
	pub fn assigned_finding(&self, finding: i64) -> Result<bool> {
		Ok(self.access == Access::Domain
			&& self.job().kind == JobKind::Verify
			&& self.lease.assigned_finding(finding)?)
	}
}

/// Recheck active identity and selected purpose in the caller's transaction.
/// Supply the current time after acquiring the transaction, not a precheck time.
/// Operation-specific manifest/profile ownership and mutation preconditions
/// are still required in host producers. Propagate errors and roll back.
pub fn authorize<'tx, 'conn>(
	tx: &'tx Transaction<'conn>, worker: &AuthedWorker, headers: &HeaderMap, job_id: i64,
	phase: JobKind, access: Access, now: i64,
) -> Result<Option<Authorized<'tx, 'conn>>> {
	let Ok(hash) = job_capability::parse_hash(headers) else { return Ok(None) };
	let identity = jobs::LeaseIdentity { job_id, worker_id: worker.id(), capability_hash: &hash };
	let Some(lease) = stored::authorize(tx, jobs::ActiveLease { identity, now }, phase.clone())?
	else {
		return Ok(None);
	};
	if access == Access::LeaseControl {
		return Ok(Some(Authorized { lease, access, bootstrap: false }));
	}
	let Some(context) = lease.context()? else { return Ok(None) };
	if !context.campaign_active
		|| context.campaign_deadline.is_some_and(|deadline| now >= deadline)
		|| !context.hard_deadline_at.is_some_and(|deadline| now < deadline)
	{
		return Ok(None);
	}
	let Some(recipe) =
		context.recipe.as_deref().and_then(|raw| serde_json::from_str::<Recipe>(raw).ok())
	else {
		return Ok(None);
	};
	if recipe.phase() != phase || !recipe.supported(&context, access) {
		return Ok(None);
	}
	if matches!(access, Access::PreparedHost | Access::Domain) && !lease.prepared(&context)? {
		return Ok(None);
	}
	if phase == JobKind::Drilldown
		&& !lease
			.job()
			.assigned_lead_id
			.map(|id| lease.assigned_lead(id))
			.transpose()?
			.unwrap_or(false)
		|| phase == JobKind::Verify
			&& !lease
				.job()
				.target_finding_id
				.map(|id| lease.assigned_finding(id))
				.transpose()?
				.unwrap_or(false)
	{
		return Ok(None);
	}
	if access == Access::Domain || phase != JobKind::Survey {
		let Some(generation) = &context.generation else { return Ok(None) };
		if !lease.ready(generation)? {
			return Ok(None);
		}
	}
	Ok(Some(Authorized { lease, access, bootstrap: recipe.bootstrap() }))
}

/// The only terminal retry authority is the sealed receipt. No live lease or
/// rebuildable generation is needed; no general read/write token is returned.
pub fn replay_terminal(
	tx: &Transaction<'_>, worker: &AuthedWorker, headers: &HeaderMap, job: i64, phase: JobKind,
	payload: &TerminalPayload,
) -> Result<terminal_receipt::Replayed> {
	let Ok(hash) = job_capability::parse_hash(headers) else {
		return Ok(terminal_receipt::Replayed::Reject(terminal_receipt::Reject::Denied));
	};
	if payload.phase() != phase {
		return Ok(terminal_receipt::Replayed::Reject(terminal_receipt::Reject::Denied));
	}
	terminal_receipt::replay_terminal(
		tx,
		jobs::LeaseIdentity { job_id: job, worker_id: worker.id(), capability_hash: &hash },
		phase,
		&payload.digest()?,
	)
}

#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
