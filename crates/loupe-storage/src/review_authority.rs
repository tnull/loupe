//! Persisted review authority facts in the caller's immediate transaction.
//!
//! This layer does not select supported recipes or access purposes. The server
//! combines these facts with its phase policy. Do not carry them across a
//! transaction boundary or authorize once in HTTP middleware and reuse later.
use loupe_core::review_payload::GeneratedProfile;
use loupe_core::{JobKind, WORKFLOW_CONTRACT_VERSION};
use rusqlite::{params, OptionalExtension, Transaction};

use crate::{jobs, review_units, Result};

pub struct Lease<'tx, 'conn> {
	tx: &'tx Transaction<'conn>,
	job: Job,
	capability_hash: [u8; 32],
	now: i64,
}

/// Narrow identity metadata, deliberately excluding untrusted stored payloads.
/// Lease-control failure must still work when a recipe/profile is malformed.
pub struct Job {
	pub id: i64,
	pub repo_id: i64,
	pub kind: JobKind,
	pub campaign_id: i64,
	pub generation_id: Option<i64>,
	pub assigned_lead_id: Option<i64>,
	pub target_finding_id: Option<i64>,
}

/// Server policy input, not an independently usable authorization token.
pub struct Context {
	pub campaign_recipe: String,
	pub campaign_active: bool,
	pub campaign_deadline: Option<i64>,
	pub target_commit: String,
	pub generation: Option<Generation>,
	pub head_sha: Option<String>,
	pub hard_deadline_at: Option<i64>,
	pub recipe: Option<String>,
}

pub struct Generation {
	pub id: i64,
	pub predecessor: Option<i64>,
	pub commit: String,
	pub state: String,
}

/// Uniform absence for unknown or out-of-scope identities. The worker is
/// rechecked here even if certificate middleware accepted it earlier.
pub fn authorize<'tx, 'conn>(
	tx: &'tx Transaction<'conn>, lease: jobs::ActiveLease<'_>, phase: JobKind,
) -> Result<Option<Lease<'tx, 'conn>>> {
	if !matches!(phase, JobKind::Survey | JobKind::Drilldown | JobKind::Verify) {
		return Ok(None);
	}
	let identity = lease.identity;
	let Ok(capability_hash) = <[u8; 32]>::try_from(identity.capability_hash) else {
		return Ok(None);
	};
	let bound: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM jobs j JOIN workers w ON w.id=j.worker_id
		 WHERE j.id=?1 AND j.worker_id=?2 AND j.job_capability_hash=?3 AND j.kind=?4
		 AND j.state='leased' AND j.lease_expires_at>?5 AND j.attempts>0
		 AND j.campaign_id IS NOT NULL AND w.kind='worker' AND w.revoked_at IS NULL)",
		params![
			identity.job_id,
			identity.worker_id,
			identity.capability_hash,
			phase.as_str(),
			lease.now
		],
		|row| row.get(0),
	)?;
	if !bound {
		return Ok(None);
	}
	let job = tx.query_row(
		"SELECT id,repo_id,campaign_id,generation_id,assigned_lead_id,target_finding_id FROM jobs WHERE id=?1",
		[identity.job_id], |row| Ok(Job { id: row.get(0)?, repo_id: row.get(1)?, kind: phase,
			campaign_id: row.get(2)?, generation_id: row.get(3)?, assigned_lead_id: row.get(4)?,
			target_finding_id: row.get(5)?, }),
	)?;
	Ok(Some(Lease { tx, job, capability_hash, now: lease.now }))
}

impl Lease<'_, '_> {
	pub fn job(&self) -> &Job {
		&self.job
	}

	/// Exact campaign/generation links and workflow identity. NULL generation
	/// is meaningful only when both the job and campaign are still unpinned.
	pub fn context(&self) -> Result<Option<Context>> {
		// Decode nonidentity fields only for host/domain access. Preserve raw
		// recipe JSON so the server's strict decoder sees duplicate keys.
		let row = self.tx.query_row(
			"SELECT c.recipe,c.state,c.deadline_at,c.target_commit_sha,c.generation_id,j.head_sha,j.hard_deadline_at,j.recipe
			 FROM review_campaigns c JOIN jobs j ON j.campaign_id=c.campaign_id
			 WHERE j.id=?1 AND c.repo_id=?2 AND j.workflow_contract_version=?3",
			params![self.job.id, self.job.repo_id, WORKFLOW_CONTRACT_VERSION],
			|row| Ok((Context {
				campaign_recipe: row.get(0)?, campaign_active: row.get::<_,String>(1)? == "active",
				campaign_deadline: row.get(2)?, target_commit: row.get(3)?, generation: None,
				head_sha: row.get(5)?, hard_deadline_at: row.get(6)?, recipe: row.get(7)?,
			}, row.get::<_,Option<i64>>(4)?)),
		).optional()?;
		let Some((mut context, generation_id)) = row else { return Ok(None) };
		if generation_id != self.job.generation_id {
			return Ok(None);
		}
		context.generation = if let Some(id) = generation_id {
			let value = self.tx.query_row(
				"SELECT predecessor_generation_id,generation_commit_sha,state FROM review_generations
				 WHERE generation_id=?1 AND repo_id=?2 AND workflow_contract_version=?3",
				params![id, self.job.repo_id, WORKFLOW_CONTRACT_VERSION],
				|row| Ok(Generation { id, predecessor: row.get(0)?, commit: row.get(1)?, state: row.get(2)? }),
			).optional()?;
			let Some(value) = value else { return Ok(None) };
			Some(value)
		} else {
			None
		};
		Ok(Some(context))
	}

	pub fn prepared(&self, context: &Context) -> Result<bool> {
		let Some(generation) = &context.generation else { return Ok(false) };
		let Some(head) = &context.head_sha else { return Ok(false) };
		if !matches!(head.len(), 40 | 64)
			|| !head.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
			|| *head != context.target_commit
			|| *head != generation.commit
		{
			return Ok(false);
		}
		Ok(self.tx.query_row(
			"SELECT prepared_attempt=attempts AND prepared_capability_hash=?2 AND prepared_at<=?3
			 FROM jobs WHERE id=?1",
			params![self.job.id, self.capability_hash.as_slice(), self.now],
			|row| row.get::<_,Option<bool>>(0),
		)?.unwrap_or(false))
	}

	/// Only a managed, sealed inventory plus a valid published bounded profile
	/// establishes readiness. Historical digests alone grant no authority.
	pub fn ready(&self, generation: &Generation) -> Result<bool> {
		let row = self
			.tx
			.query_row(
				"SELECT g.generated_profile,g.generated_profile_digest FROM review_generations g
			 JOIN generation_manifests m ON m.generation_id=g.generation_id
			 WHERE g.generation_id=?1 AND g.profile_version>0 AND m.sealed_at IS NOT NULL
			 AND m.received_entry_count=m.expected_entry_count",
				[generation.id],
				|row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
			)
			.optional()?;
		let Some((Some(raw), Some(digest))) = row else { return Ok(false) };
		let Ok(profile) = GeneratedProfile::new(&raw) else { return Ok(false) };
		Ok(profile.expose() == raw && digest == profile.digest())
	}

	/// Fresh-only check. Run after checkpoint replay lookup, not before it.
	pub fn survey_unit(&self, id: i64, epoch: i64, bootstrap: bool) -> Result<bool> {
		let membership = if bootstrap {
			"u.created_by_job_id=?3"
		} else {
			"EXISTS(SELECT 1 FROM job_assigned_review_units a WHERE a.job_id=?3 AND a.review_unit_id=u.review_unit_id AND a.assignment_epoch=?4)"
		};
		Ok(self.tx.query_row(
			&format!("SELECT EXISTS(SELECT 1 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id
			 WHERE u.review_unit_id=?1 AND u.generation_id=?2 AND {membership}
			 AND u.assignment_epoch=?4 AND u.status='open' AND u.stale=0
			 AND NOT EXISTS(SELECT 1 FROM review_unit_holds h WHERE h.review_unit_id=u.review_unit_id)
			 AND NOT EXISTS(SELECT 1 FROM job_assigned_review_units a JOIN jobs j ON j.id=a.job_id
			 WHERE a.review_unit_id=u.review_unit_id AND a.job_id<>?3 AND j.state IN ('queued','leased'))
			 AND NOT ({}))", review_units::UNIT_COVERED),
			params![id, self.job.generation_id, self.job.id, epoch], |row| row.get(0),
		)?)
	}

	pub fn assigned_lead(&self, id: i64) -> Result<bool> {
		Ok(self.job.assigned_lead_id == Some(id) && self.tx.query_row(
			"SELECT EXISTS(SELECT 1 FROM leads l JOIN review_generations g ON g.generation_id=l.generation_id
			 WHERE l.lead_id=?1 AND l.generation_id=?2 AND g.repo_id=?3)",
			params![id, self.job.generation_id, self.job.repo_id], |row| row.get(0),
		)?)
	}

	pub fn assigned_finding(&self, id: i64) -> Result<bool> {
		// Findings are canonical and repository-owned, not generation-owned:
		// their originating lead may already have been cleaned up. The job's
		// exact generation is independently bound by context/preparation.
		Ok(self.job.target_finding_id == Some(id)
			&& self.tx.query_row(
				"SELECT EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?2)",
				params![id, self.job.repo_id],
				|row| row.get(0),
			)?)
	}
}
