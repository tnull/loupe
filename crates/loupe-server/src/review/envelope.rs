//! Bounded snapshots shared by preparation responses and transactional claims.
//! Raw canonical evidence is checked before constructing the delivery DTO.
use loupe_core::review_payload::{GeneratedProfile, Version1};
use loupe_core::text::{BoundedText, SourceRef};
use loupe_core::JobKind;
use loupe_proto::review_lease::*;
use loupe_proto::{JobCapability, LeaseEnvelope, LeasePayload, PROTOCOL_VERSION};
use loupe_storage::{
	admission, finding_details, findings, inventory, jobs, leads, repos, review_units,
	StoredEvidence,
};
use rusqlite::{params, Transaction};

use super::admission_validation::{self as validation, invalid, Failure, Planned};
use super::authority::{Recipe, SurveyRecipe};
use super::http::{ApiError, Result};

fn http_error(error: Failure) -> ApiError {
	match error {
		Failure::Defect(_) | Failure::Unit(_, _) => ApiError::conflict("incompatible_review_state"),
		Failure::Unexpected(error) => error.into(),
	}
}
pub fn digest(bytes: &[u8]) -> Result<ReviewDigest> {
	digest_snapshot(bytes).map_err(http_error)
}
pub(super) fn digest_snapshot(bytes: &[u8]) -> validation::Result<ReviewDigest> {
	ReviewDigest::new(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
		.map_err(|_| invalid())
}
pub fn profile(tx: &Transaction<'_>, generation: i64) -> Result<Option<FrozenReviewProfile>> {
	profile_snapshot(tx, generation).map_err(http_error)
}
pub(crate) fn profile_snapshot(
	tx: &Transaction<'_>, generation: i64,
) -> validation::Result<Option<FrozenReviewProfile>> {
	let (version,raw,hash):(u32,Option<String>,Option<Vec<u8>>)=tx.query_row("SELECT profile_version,generated_profile,generated_profile_digest FROM review_generations WHERE generation_id=?1",[generation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
	let (raw, hash) = match (raw, hash) {
		(None, None) => return Ok(None),
		(Some(raw), Some(hash)) => (raw, hash),
		_ => return Err(invalid()),
	};
	let profile = GeneratedProfile::new(&raw).map_err(|_| invalid())?;
	if profile.expose() != raw || profile.digest().as_slice() != hash {
		return Err(invalid());
	}
	Ok(Some(FrozenReviewProfile {
		profile_version: version.try_into().map_err(|_| invalid())?,
		profile_digest: digest_snapshot(&hash)?,
		profile,
	}))
}

pub fn assignments(tx: &Transaction<'_>, job: i64) -> Result<ReviewAssignments> {
	assignment_snapshot(tx, job).map_err(http_error)
}
pub(crate) fn assignment_snapshot(
	tx: &Transaction<'_>, job: i64,
) -> validation::Result<ReviewAssignments> {
	let generation: Option<i64> =
		tx.query_row("SELECT generation_id FROM jobs WHERE id=?1", [job], |r| r.get(0))?;
	let generation = generation.ok_or_else(invalid)?;
	let rows=tx.prepare("SELECT review_unit_id,assignment_epoch,position,completed FROM job_assigned_review_units WHERE job_id=?1 ORDER BY position LIMIT 33")?.query_map([job],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,Option<u64>>(1)?,r.get::<_,i64>(2)?,r.get::<_,bool>(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
	if rows.len() > 32 || rows.iter().enumerate().any(|(i, r)| r.2 != i as i64) {
		return Err(invalid());
	}
	let mut units = Vec::new();
	for (id, epoch, _, completed) in rows {
		if !completed {
			units.push(unit_snapshot(tx, id, generation, Some(epoch.ok_or_else(invalid)?))?);
		}
	}
	LeaseList::new(units).and_then(ReviewAssignments::try_from).map_err(|_| invalid())
}

/// `None` validates a future ordinary/exact member without taking its epoch.
pub(crate) fn unit_snapshot(
	tx: &Transaction<'_>, id: i64, generation: i64, epoch: Option<u64>,
) -> validation::Result<AssignedReviewUnit> {
	unit_inner(tx, id, generation, epoch).map_err(|error| match error {
		Failure::Defect(reason) => Failure::Unit(id, reason),
		other => other,
	})
}
fn unit_inner(
	tx: &Transaction<'_>, id: i64, generation: i64, epoch: Option<u64>,
) -> validation::Result<AssignedReviewUnit> {
	let unit = review_units::get(tx, id)?.ok_or_else(invalid)?;
	if unit.generation_id != generation
		|| unit.stale
		|| (unit.status != review_units::Status::Open
			&& !(epoch.is_none() && unit.status == review_units::Status::Deferred))
	{
		return Err(invalid());
	}
	if epoch.is_some_and(|epoch| i64::try_from(epoch).ok() != Some(unit.assignment_epoch)) {
		return Err(invalid());
	}
	inventory::verify_refs(tx, generation, unit.source_refs.as_slice())?;
	let dependencies: Vec<ReviewId> = unit
		.depends_on
		.as_ref()
		.map(|raw| serde_json::from_str(raw.expose()))
		.transpose()
		.map_err(|_| invalid())?
		.unwrap_or_default();
	let dependencies = LeaseList::new(dependencies).map_err(|_| invalid())?;
	for (position, dependency) in dependencies.as_slice().iter().enumerate() {
		if i64::from(*dependency) == id || dependencies.as_slice()[..position].contains(dependency)
		{
			return Err(invalid());
		}
		let belongs:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM review_units WHERE review_unit_id=?1 AND generation_id=?2)",params![i64::from(*dependency),generation],|r|r.get(0))?;
		if !belongs {
			return Err(invalid());
		}
	}
	let epoch = match epoch {
		Some(epoch) => epoch,
		None => u64::try_from(unit.assignment_epoch)
			.ok()
			.and_then(|e| e.checked_add(1))
			.ok_or_else(invalid)?,
	};
	Ok(AssignedReviewUnit {
		review_unit_id: id.try_into().map_err(|_| invalid())?,
		assignment_epoch: epoch.try_into().map_err(|_| invalid())?,
		title: unit.title,
		objective: unit.objective,
		source_refs: LeaseList::new(unit.source_refs.as_slice().to_vec()).map_err(|_| invalid())?,
		depends_on: dependencies,
		closure_criteria: unit
			.closure_criteria
			.as_ref()
			.map(|t| BoundedText::new(t.expose()))
			.transpose()
			.map_err(|_| invalid())?,
	})
}

pub(crate) fn lead_snapshot(
	tx: &Transaction<'_>, id: i64, plan: &Planned,
) -> validation::Result<AssignedReviewLead> {
	let meta = leads::get_metadata(tx, id)?.ok_or_else(invalid)?;
	if Some(meta.generation_id) != plan.generation || meta.commit_sha != plan.context.target_commit
	{
		return Err(invalid());
	}
	let producer = meta.created_by_job.ok_or_else(invalid)?;
	let provenance:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?2 AND generation_id=?3 AND campaign_id IS NOT NULL AND kind IN('survey','drilldown') AND head_sha=?4 AND workflow_contract_version=1)",params![producer,plan.repo,meta.generation_id,meta.commit_sha],|r|r.get(0))?;
	if !provenance {
		return Err(invalid());
	}
	let StoredEvidence::Recorded(payload) = leads::get_evidence(tx, id)? else {
		return Err(Failure::Defect(
			loupe_storage::admission_quarantine::Reason::CompatibilityPolicy,
		));
	};
	inventory::verify_refs(tx, meta.generation_id, payload.source_refs.as_slice())?;
	Ok(AssignedReviewLead {
		lead_id: id.try_into().map_err(|_| invalid())?,
		producer_commit_sha: meta.commit_sha.parse().map_err(|_| invalid())?,
		identity_family: payload.identity_family,
		identity_anchor: payload.identity_anchor,
		identity_instance_key: payload.identity_instance_key,
		hypothesis: payload.hypothesis,
		invariant_or_boundary: payload.invariant_or_boundary,
		source_refs: LeaseList::new(payload.source_refs.as_slice().to_vec())
			.map_err(|_| invalid())?,
		next_proof_step: payload.next_proof_step,
		counterevidence: payload.counterevidence,
		proof_gaps: payload.proof_gaps,
	})
}

pub(crate) fn finding_snapshot(
	tx: &Transaction<'_>, id: i64, plan: &Planned,
) -> validation::Result<AssignedReviewFinding> {
	let finding = findings::get(tx, id)?.ok_or_else(invalid)?;
	let StoredEvidence::Recorded(details) = finding_details::get_review_evidence(tx, id)? else {
		return Err(Failure::Defect(
			loupe_storage::admission_quarantine::Reason::CompatibilityPolicy,
		));
	};
	let generation = plan.generation.ok_or_else(invalid)?;
	let profile = profile_snapshot(tx, generation)?.ok_or_else(invalid)?;
	if finding.repo_id != plan.repo
		|| details.repo_id != plan.repo
		|| details.workflow_contract_version != 1
		|| details.reviewed_commit_sha != plan.context.target_commit
		|| details.profile_version != i64::from(profile.profile_version.get())
		|| details.profile_digest.as_ref().map(|d| digest_snapshot(d)).transpose()?.as_ref()
			!= Some(&profile.profile_digest)
	{
		return Err(invalid());
	}
	let refs: Vec<_> = details
		.evidence
		.material_locations
		.as_slice()
		.iter()
		.map(|l| SourceRef { path: l.file.clone(), symbol: None })
		.collect();
	inventory::verify_refs(tx, generation, &refs)?;
	Ok(AssignedReviewFinding {
		finding_id: id.try_into().map_err(|_| invalid())?,
		reviewed_commit_sha: details.reviewed_commit_sha.parse().map_err(|_| invalid())?,
		severity: finding.severity,
		title: BoundedText::new(&finding.title).map_err(|_| invalid())?,
		description: BoundedText::new(&finding.description).map_err(|_| invalid())?,
		identity_family: details.identity.family,
		identity_anchor: details.identity.anchor,
		identity_instance_key: details.identity.instance,
		evidence: details.evidence,
	})
}

pub(crate) fn build(
	tx: &Transaction<'_>, job: &jobs::JobRow, capability: JobCapability,
) -> validation::Result<LeaseEnvelope> {
	let repo = repos::get(tx, job.repo_id)?.ok_or_else(invalid)?;
	let mut branch = repo.default_branch.clone();
	let payload = if job.campaign_id.is_some() {
		let plan =
			validation::planned(tx, loupe_storage::admission_quarantine::Source::Job(job.id))?
				.ok_or_else(invalid)?;
		if plan.generation.is_none() {
			branch = Some(plan.context.target_commit.clone());
		}
		let policy = admission::load_policy(tx, plan.campaign)?;
		let provenance = ReviewProvenance {
			workflow_contract_version: Version1,
			campaign_id: plan.campaign.try_into().map_err(|_| invalid())?,
			attempt: job.attempts.try_into().map_err(|_| invalid())?,
			limits: ReviewLimits {
				soft_deadline_at: job.soft_deadline_at.ok_or_else(invalid)?,
				submit_by: job.submit_by.ok_or_else(invalid)?,
				hard_deadline_at: job.hard_deadline_at.ok_or_else(invalid)?,
				token_budget: job
					.token_budget
					.map(|n| n.try_into())
					.transpose()
					.map_err(|_| invalid())?,
				new_unit_limit: policy.max_units_per_survey,
				lead_limit: policy.max_leads_per_survey,
				sibling_limit: policy.max_sibling_leads_per_drilldown,
			},
		};
		let generation = plan
			.context
			.generation
			.as_ref()
			.map(|g| -> validation::Result<_> {
				Ok(ReviewGeneration {
					generation_id: g.id.try_into().map_err(|_| invalid())?,
					commit_sha: g.commit.parse().map_err(|_| invalid())?,
				})
			})
			.transpose()?;
		match plan.kind {
			JobKind::Survey => {
				let context = match (&plan.recipe, generation) {
					(Recipe::Survey { recipe: SurveyRecipe::Bootstrap, .. }, None) => {
						ReviewSurveyContext::Bootstrap { target: BootstrapTarget::Unresolved {} }
					},
					(Recipe::Survey { recipe: SurveyRecipe::Bootstrap, .. }, Some(generation)) => {
						ReviewSurveyContext::Bootstrap {
							target: BootstrapTarget::Pinned {
								generation,
								published_profile: profile_snapshot(
									tx,
									plan.generation.ok_or_else(invalid)?,
								)?,
							},
						}
					},
					(Recipe::Survey { recipe: SurveyRecipe::Incremental, .. }, None) => {
						ReviewSurveyContext::ResolveTarget {}
					},
					(Recipe::Survey { recipe, .. }, Some(generation)) => {
						ReviewSurveyContext::Ordinary {
							generation,
							profile: profile_snapshot(tx, plan.generation.ok_or_else(invalid)?)?
								.ok_or_else(invalid)?,
							ordinary_recipe: match recipe {
								SurveyRecipe::Coverage => OrdinarySurveyRecipe::Coverage,
								SurveyRecipe::Incremental => {
									OrdinarySurveyRecipe::SameCommitIncremental
								},
								_ => return Err(invalid()),
							},
							assignments: assignment_snapshot(tx, job.id)?,
						}
					},
					_ => return Err(invalid()),
				};
				LeasePayload::ReviewSurvey(Box::new(ReviewSurveyLease { provenance, context }))
			},
			JobKind::Drilldown => LeasePayload::ReviewDrilldown(Box::new(ReviewDrilldownLease {
				provenance,
				generation: generation.ok_or_else(invalid)?,
				profile: profile_snapshot(tx, plan.generation.ok_or_else(invalid)?)?
					.ok_or_else(invalid)?,
				lead: lead_snapshot(tx, job.assigned_lead_id.ok_or_else(invalid)?, &plan)?,
			})),
			JobKind::Verify => LeasePayload::ReviewVerify(Box::new(ReviewVerifyLease {
				provenance,
				generation: generation.ok_or_else(invalid)?,
				profile: profile_snapshot(tx, plan.generation.ok_or_else(invalid)?)?
					.ok_or_else(invalid)?,
				finding: finding_snapshot(tx, job.target_finding_id.ok_or_else(invalid)?, &plan)?,
			})),
			_ => return Err(invalid()),
		}
	} else {
		if jobs::targets_phase_finding(tx, job.id)? {
			return Err(Failure::Defect(
				loupe_storage::admission_quarantine::Reason::CompatibilityPolicy,
			));
		}
		match job.kind {
			JobKind::Scan => LeasePayload::Scan { since_sha: job.since_sha.clone() },
			JobKind::Verify => {
				let target = job.target_finding_id.ok_or_else(invalid)?;
				let finding = findings::get(tx, target)?.ok_or_else(invalid)?;
				if finding.repo_id != job.repo_id {
					return Err(invalid());
				}
				let reviewed = jobs::get(tx, job.parent_job_id.unwrap_or(finding.job_id))?;
				if reviewed.as_ref().is_some_and(|j| j.repo_id != job.repo_id) {
					return Err(invalid());
				}
				let reviewed_sha =
					reviewed.and_then(|j| if j.kind == JobKind::Scan { j.head_sha } else { None });
				LeasePayload::Verify {
					finding_id: target,
					finding: Box::new(finding.into_finding()),
					reviewed_sha,
				}
			},
			_ => return Err(invalid()),
		}
	};
	Ok(LeaseEnvelope {
		protocol_version: PROTOCOL_VERSION,
		job_id: job.id,
		job_capability: capability,
		repo_id: repo.id,
		repo: loupe_core::RepoSpec {
			host: repo.host,
			owner: repo.owner,
			repo: repo.repo,
			clone_url: repo.clone_url,
			branch: branch.clone(),
		},
		head_branch: branch,
		lease_expires_at: job.lease_expires_at.ok_or_else(invalid)?,
		scanner_config: repo.scanner_config,
		github_pat: None,
		payload,
	})
}
