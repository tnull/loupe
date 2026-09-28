//! Lease-bound typed evidence checkpoints. Replay precedes every fresh guard.
use axum::extract::{Path, Request, State};
use axum::response::Response;
use axum::Extension;
use loupe_core::review_candidates::CandidateKind;
use loupe_core::review_payload::LeadEvidenceV1;
use loupe_core::text::BoundedJson;
use loupe_core::JobKind;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_evidence::{
	self as wire, LeadCheckpointRequest, LeadCheckpointResponse, LeadOutcome,
	UnitResultCheckpointRequest, UnitResultCheckpointResponse,
};
use loupe_storage::admission_policy::{self, AcceptedPriority};
use loupe_storage::checkpoints::{self, Operation, Recorded};
use loupe_storage::scheduler::Band;
use loupe_storage::{
	admission, duplicate_candidates, generations, inventory, lead_observations, leads,
	review_intents, review_unit_results, review_units, unit_holds, StoredEvidence,
};
use rusqlite::{params, Transaction};

use crate::auth::AuthedWorker;
use crate::review::authority::Access;
use crate::review::http::{self, ApiError};
use crate::AppState;

pub async fn submit_lead(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, request: Request,
) -> http::Result<Response> {
	submit(state, job, worker, request, JobKind::Survey).await
}
pub async fn submit_sibling_lead(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, request: Request,
) -> http::Result<Response> {
	submit(state, job, worker, request, JobKind::Drilldown).await
}

async fn submit(
	state: AppState, job: i64, worker: AuthedWorker, request: Request, phase: JobKind,
) -> http::Result<Response> {
	let (parts, body) = request.into_parts();
	let request: LeadCheckpointRequest = http::json(&parts.headers, body, 256 * 1024).await?;
	let digest = request.digest().map_err(ApiError::invalid)?;
	let response = http::transaction(&state.db, 8192, |tx, now| {
		let scope = http::authorize(
			tx,
			&worker,
			&parts.headers,
			job,
			std::slice::from_ref(&phase),
			Access::Domain,
			now,
		)?;
		let op = if phase == JobKind::Survey {
			Operation::SubmitLead
		} else {
			Operation::SubmitSiblingLead
		};
		let key = &request.client_lead_key;
		if let Some(response) = checkpoints::lookup(tx, job, op, key, &digest)? {
			return serde_json::from_str::<LeadCheckpointResponse>(response.expose())
				.map_err(ApiError::invalid);
		}
		let generation = scope.job().generation_id.ok_or_else(ApiError::denied)?;
		let campaign = scope.job().campaign_id;
		let policy = admission::load_policy(tx, campaign)?;
		let limit = if phase == JobKind::Survey {
			policy.max_leads_per_survey
		} else {
			policy.max_sibling_leads_per_drilldown
		};
		if checkpoints::accepted_count(tx, job, op)? >= i64::from(limit) {
			return Err(ApiError::conflict("checkpoint_limit"));
		}
		let evidence = &request.evidence;
		if phase == JobKind::Survey {
			if let (Some(unit), Some(epoch)) = (evidence.review_unit_id, evidence.assignment_epoch)
				&& !scope.survey_unit_reference(unit, epoch)?
			{
				return Err(ApiError::denied());
			}
		} else {
			let assigned = scope.job().assigned_lead_id.ok_or_else(ApiError::denied)?;
			if !scope.assigned_lead(assigned)? {
				return Err(ApiError::denied());
			}
			let lead = leads::get_metadata(tx, assigned)?.ok_or_else(ApiError::denied)?;
			if let (Some(unit), Some(epoch)) = (evidence.review_unit_id, evidence.assignment_epoch)
			{
				if lead.unit_id != Some(unit) {
					return Err(ApiError::denied());
				}
				let belongs: bool = tx.query_row(
					"SELECT EXISTS(SELECT 1 FROM review_units WHERE review_unit_id=?1 AND generation_id=?2 AND assignment_epoch=?3)",
					params![unit,generation,epoch], |row| row.get(0))?;
				if !belongs {
					return Err(ApiError::denied());
				}
			}
		}
		if let Some(hint) = &evidence.duplicate_hint
			&& !duplicate_candidates::issued_target(
				tx,
				job,
				scope.job().repo_id,
				CandidateKind::Lead,
				hint.lead_id,
			)? {
			return Err(ApiError::denied());
		}
		validate_refs(tx, generation, evidence)?;
		let priority = classify(evidence);
		let generation = generations::get(tx, generation)?.ok_or_else(ApiError::denied)?;
		let submitted = leads::submit_evidence(
			tx,
			&leads::NewLeadEvidence {
				generation_id: generation.generation_id,
				created_by_job: job,
				commit_sha: &generation.commit_sha,
				priority: unit_priority(priority.band),
				payload: evidence,
			},
			now,
		)?;
		let (lead_id, outcome) = match submitted {
			leads::Submitted::Created(id) => (id, LeadOutcome::Created),
			leads::Submitted::Attached { lead_id, .. } => (lead_id, LeadOutcome::Attached),
			leads::Submitted::ClosedExists { lead_id, .. } => (lead_id, LeadOutcome::ClosedExists),
		};
		let observation_id = if outcome == LeadOutcome::Created {
			None
		} else {
			Some(
				lead_observations::latest_evidence_for_job(tx, lead_id, job, None)?
					.ok_or_else(ApiError::denied)?
					.observation_id
					.try_into()
					.map_err(ApiError::invalid)?,
			)
		};
		// Attachment adds evidence, not a second owner or a new priority policy.
		let accepted = if let Some(intent) =
			review_intents::get_subject(tx, review_intents::Subject::Lead(lead_id))?
		{
			intent.priority
		} else {
			let original = leads::get_metadata(tx, lead_id)?.ok_or_else(ApiError::denied)?;
			let priority = match leads::get_evidence(tx, lead_id)? {
				StoredEvidence::Recorded(value) => {
					validate_refs(tx, generation.generation_id, &value)?;
					classify(&value)
				},
				StoredEvidence::Historical | StoredEvidence::Missing => {
					return Err(ApiError::conflict("incompatible_review_state"));
				},
			};
			if priority.band != original.priority {
				return Err(ApiError::conflict("incompatible_review_state"));
			}
			priority
		};
		let intent = review_intents::ensure_drilldown_intent(tx, lead_id, job, accepted, now)?;
		let accepted = intent.map_or(accepted, |intent| intent.priority);
		let response = LeadCheckpointResponse {
			protocol_version: ReviewProtocol,
			lead_id: lead_id.try_into().map_err(ApiError::invalid)?,
			outcome,
			observation_id,
			accepted_priority: wire_priority(accepted),
		};
		let canonical =
			BoundedJson::new(&serde_json::to_string(&response).map_err(ApiError::invalid)?)
				.map_err(ApiError::invalid)?;
		if checkpoints::record_or_replay(tx, job, op, key, &digest, &canonical, now)?
			!= Recorded::Recorded
		{
			return Err(ApiError::conflict("checkpoint_conflict"));
		}
		Ok(response)
	})?;
	state.job_arrived.notify_one();
	Ok(response)
}

fn validate_refs(
	tx: &Transaction<'_>, generation: i64, evidence: &LeadEvidenceV1,
) -> http::Result<()> {
	inventory::verify_refs(tx, generation, &evidence.source_refs)?;
	if let Some(proposal) = &evidence.priority_proposal {
		inventory::verify_refs(tx, generation, &proposal.boundary_refs)?;
	}
	Ok(())
}
fn classify(evidence: &LeadEvidenceV1) -> AcceptedPriority {
	evidence.priority_proposal.as_ref().map_or(
		AcceptedPriority { band: Band::Normal, score: 0 },
		|p| {
			admission_policy::classify_priority(
				p.impact,
				p.access,
				p.reachability,
				evidence.invariant_or_boundary.is_some() && !p.boundary_refs.is_empty(),
				true,
			)
		},
	)
}
fn unit_priority(band: Band) -> review_units::Priority {
	match band {
		Band::Urgent => review_units::Priority::Urgent,
		Band::High => review_units::Priority::High,
		Band::Normal => review_units::Priority::Normal,
		Band::Background => review_units::Priority::Background,
	}
}
fn wire_priority(priority: AcceptedPriority) -> wire::AcceptedPriority {
	wire::AcceptedPriority {
		band: match priority.band {
			Band::Urgent => wire::PriorityBand::Urgent,
			Band::High => wire::PriorityBand::High,
			Band::Normal => wire::PriorityBand::Normal,
			Band::Background => wire::PriorityBand::Background,
		},
		score: priority.score,
	}
}

pub async fn submit_unit_result(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, request: Request,
) -> http::Result<Response> {
	let (parts, body) = request.into_parts();
	let request: UnitResultCheckpointRequest = http::json(&parts.headers, body, 256 * 1024).await?;
	let digest = request.digest().map_err(ApiError::invalid)?;
	let response = http::transaction(&state.db, 8192, |tx, now| {
		let scope = http::authorize(
			tx,
			&worker,
			&parts.headers,
			job,
			&[JobKind::Survey],
			Access::Domain,
			now,
		)?;
		let op = Operation::SubmitUnitResult;
		let key = &request.client_result_key;
		if let Some(response) = checkpoints::lookup(tx, job, op, key, &digest)? {
			return serde_json::from_str::<UnitResultCheckpointResponse>(response.expose())
				.map_err(ApiError::invalid);
		}
		let result = &request.result;
		if !scope.survey_unit(result.review_unit_id, result.assignment_epoch)? {
			return Err(ApiError::denied());
		}
		if tx.query_row("SELECT EXISTS(SELECT 1 FROM review_unit_results WHERE review_unit_id=?1 AND produced_by_job_id=?2)", params![result.review_unit_id, job], |r| r.get::<_,bool>(0))? { return Err(ApiError::conflict("unit_result_exists")); }
		let generation = scope.job().generation_id.ok_or_else(ApiError::denied)?;
		for lead in &result.created_lead_ids {
			if !accepted_for_unit(
				tx,
				*lead,
				job,
				generation,
				result.review_unit_id,
				result.assignment_epoch,
			)? {
				return Err(ApiError::denied());
			}
		}
		inventory::verify_refs(tx, generation, &result.inspected_refs)?;
		let generation = generations::get(tx, generation)?.ok_or_else(ApiError::denied)?;
		let id = review_unit_results::insert_evidence(
			tx,
			&review_unit_results::NewResultEvidence {
				generation_id: generation.generation_id,
				produced_by_job: job,
				commit_sha: &generation.commit_sha,
				profile_version: generation.profile_version,
				payload: result,
			},
			now,
		)?;
		if let Some(class) = result.continuation {
			unit_holds::record_follow_up(
				tx,
				result.review_unit_id,
				id,
				job,
				result.assignment_epoch,
				class,
				now,
			)?;
		} else {
			unit_holds::release_conclusive(
				tx,
				result.review_unit_id,
				id,
				job,
				result.assignment_epoch,
				now,
			)?;
		}
		let response = UnitResultCheckpointResponse {
			protocol_version: ReviewProtocol,
			result_id: id.try_into().map_err(ApiError::invalid)?,
			review_unit_id: result.review_unit_id.try_into().map_err(ApiError::invalid)?,
			assignment_epoch: result.assignment_epoch.try_into().map_err(ApiError::invalid)?,
			disposition: result.disposition,
		};
		let canonical =
			BoundedJson::new(&serde_json::to_string(&response).map_err(ApiError::invalid)?)
				.map_err(ApiError::invalid)?;
		if checkpoints::record_or_replay(tx, job, op, key, &digest, &canonical, now)?
			!= Recorded::Recorded
		{
			return Err(ApiError::conflict("checkpoint_conflict"));
		}
		Ok(response)
	})?;
	state.job_arrived.notify_one();
	Ok(response)
}

/// Generation membership alone is insufficient. The exact typed submission
/// (including attached observations) and its successful receipt belong to this
/// producer and unit epoch. No unbounded evidence history is loaded.
fn accepted_for_unit(
	tx: &Transaction<'_>, lead: i64, job: i64, generation: i64, unit: i64, epoch: i64,
) -> http::Result<bool> {
	let matches = |payload: &LeadEvidenceV1| {
		payload.review_unit_id == Some(unit) && payload.assignment_epoch == Some(epoch)
	};
	// Numeric scope and the accepted receipt must precede even metadata:
	// decoding a foreign malformed identity would otherwise leak existence.
	let original_owned: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM leads WHERE lead_id=?1 AND generation_id=?2 AND created_by_job_id=?3)",
		params![lead,generation,job], |row| row.get(0))?;
	if original_owned
		&& accepted_receipt(tx, job, lead, None)?
		&& let StoredEvidence::Recorded(payload) = leads::get_evidence(tx, lead)?
		&& matches(&payload)
	{
		return Ok(true);
	}
	if let Some(observation) =
		lead_observations::accepted_evidence_for_unit(tx, lead, job, generation, unit, epoch)?
		&& let StoredEvidence::Recorded(payload) = observation.payload
		&& matches(&payload)
	{
		return Ok(true);
	}
	Ok(false)
}
fn accepted_receipt(
	tx: &Transaction<'_>, job: i64, lead: i64, observation: Option<i64>,
) -> http::Result<bool> {
	Ok(tx.query_row("SELECT EXISTS(SELECT 1 FROM job_checkpoints WHERE job_id=?1 AND operation='submit_lead' AND json_extract(response,'$.lead_id')=?2 AND json_extract(response,'$.observation_id') IS ?3)", params![job, lead, observation], |r| r.get(0))?)
}
