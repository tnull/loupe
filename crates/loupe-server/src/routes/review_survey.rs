//! A survey seals accepted evidence, not an agent-declared repository-complete
//! claim. No scheduler or child-job creation runs inside this endpoint.
use axum::extract::{Path, Request, State};
use axum::response::Response;
use axum::Extension;
use loupe_core::review_payload::{
	SurveyTerminalReason, UnitResultDisposition, UnitResultPayloadV1, Version1,
};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_core::JobKind;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_lease::ReviewCommit;
use loupe_proto::review_terminal::{
	FinalizeSurveyRequest, SurveyCoverage, SurveyReceipt, SurveySummary, SurveyTerminalResponse,
};
use loupe_storage::terminal_payloads::TerminalPayload;
use loupe_storage::{
	generations, host_preparation, inventory, review_unit_results, terminal_receipt, unit_holds,
	StoredEvidence,
};
use rusqlite::{params, Transaction};

use crate::auth::AuthedWorker;
use crate::review::authority::{Access, Authorized};
use crate::review::http::{self, ApiError, Result};
use crate::review::{envelope, terminal};
use crate::{job_capability, AppState};

fn incompatible() -> ApiError {
	ApiError::conflict("incompatible_review_state")
}

fn evidence(tx: &Transaction<'_>, result: i64) -> Result<StoredEvidence<UnitResultPayloadV1>> {
	review_unit_results::get_evidence(tx, result).map_err(|error| match error {
		loupe_storage::Error::ReviewPayload(_) | loupe_storage::Error::Validation(_) => {
			incompatible()
		},
		other => other.into(),
	})
}

/// Terminal validation cannot use the checkpoint's fresh-write predicate: that
/// deliberately denies already-conclusive units. Persisted assignments remain
/// authoritative even after their checkpoint marked them completed.
fn owned_result(
	tx: &Transaction<'_>, generation: i64, producer: i64, payload: &UnitResultPayloadV1,
) -> Result<bool> {
	Ok(tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM review_units u JOIN jobs j ON j.id=?3
		JOIN review_generations g ON g.generation_id=u.generation_id
		WHERE u.review_unit_id=?1 AND u.generation_id=?2 AND j.generation_id=u.generation_id
		AND j.kind='survey' AND j.repo_id=g.repo_id AND j.workflow_contract_version=1 AND j.head_sha=g.generation_commit_sha
		AND u.assignment_epoch=?4 AND u.stale=0 AND u.status IN('open','deferred')
		AND NOT EXISTS(SELECT 1 FROM job_assigned_review_units other JOIN jobs live ON live.id=other.job_id
		WHERE other.review_unit_id=u.review_unit_id AND other.job_id<>j.id AND live.state IN('queued','leased'))
		AND ((u.created_by_job_id=j.id AND ?4=0) OR EXISTS(SELECT 1 FROM job_assigned_review_units a
		WHERE a.job_id=j.id AND a.review_unit_id=u.review_unit_id AND a.assignment_epoch=?4)))",
		params![payload.review_unit_id, generation, producer, payload.assignment_epoch],
		|r| r.get(0),
	)?)
}

fn validate_producer(
	tx: &Transaction<'_>, scope: &Authorized<'_, '_>, generation: &generations::Generation,
) -> Result<()> {
	let mut statement = tx.prepare("SELECT r.review_unit_result_id,r.commit_sha,r.profile_version
		FROM review_unit_results r WHERE r.produced_by_job_id=?1 AND r.invalidated=0 ORDER BY r.review_unit_result_id")?;
	let mut rows = statement.query([scope.job().id])?;
	while let Some(row) = rows.next()? {
		let id: i64 = row.get(0)?;
		let payload = match evidence(tx, id)? {
			StoredEvidence::Recorded(value) => value,
			StoredEvidence::Historical => continue,
			StoredEvidence::Missing => return Err(incompatible()),
		};
		if row.get::<_, String>(1)? != generation.commit_sha
			|| row.get::<_, i64>(2)? != generation.profile_version
			|| !owned_result(tx, generation.generation_id, scope.job().id, &payload)?
		{
			return Err(incompatible());
		}
		if !scope.is_bootstrap() {
			let assigned: bool = tx.query_row(
				"SELECT EXISTS(SELECT 1 FROM job_assigned_review_units
				WHERE job_id=?1 AND review_unit_id=?2 AND assignment_epoch=?3)",
				params![scope.job().id, payload.review_unit_id, payload.assignment_epoch],
				|r| r.get(0),
			)?;
			if !assigned {
				return Err(incompatible());
			}
		}
		inventory::verify_refs(tx, generation.generation_id, &payload.inspected_refs)?;
		let held = unit_holds::get_hold(tx, payload.review_unit_id)?;
		if payload.disposition == UnitResultDisposition::NeedsFollowUp {
			let Some(hold) = held else { return Err(incompatible()) };
			if hold.generation_id != generation.generation_id
				|| hold.producing_job_id != scope.job().id
				|| hold.producing_result_id != id
				|| hold.source_assignment_epoch != payload.assignment_epoch
				|| Some(hold.continuation_class) != payload.continuation
			{
				return Err(incompatible());
			}
		} else if held.is_some() {
			return Err(incompatible());
		}
	}
	// A dangling/corrupted hold cannot be hidden by the result iteration above.
	let mut statement=tx.prepare("SELECT review_unit_id,producing_result_id FROM review_unit_holds WHERE producing_job_id=?1")?;
	let mut rows = statement.query([scope.job().id])?;
	while let Some(row) = rows.next()? {
		let unit: i64 = row.get(0)?;
		let result: i64 = row.get(1)?;
		let StoredEvidence::Recorded(payload) = evidence(tx, result)? else {
			return Err(incompatible());
		};
		if payload.review_unit_id != unit
			|| payload.disposition != UnitResultDisposition::NeedsFollowUp
		{
			return Err(incompatible());
		}
	}
	Ok(())
}

/// Stream rather than collecting repository-size evidence. Relational legacy
/// projections alone never certify modern coverage; historical evidence stays
/// retained and simply leaves work incomplete.
fn coverage(tx: &Transaction<'_>, generation: &generations::Generation) -> Result<SurveySummary> {
	let legacy = generations::coverage_rollup(tx, generation.generation_id)?;
	let mut summary = SurveySummary {
		version: Version1,
		coverage: SurveyCoverage::Partial,
		corroboration_satisfied: generation.corroboration == generations::Corroboration::Satisfied,
		missing_results: 0,
		needs_follow_up: 0,
		unresolved_inventory: legacy.unresolved_inventory.try_into().map_err(|_| incompatible())?,
		follow_up_batches: 0,
		follow_up_units: 0,
	};
	let mut statement=tx.prepare("SELECT u.review_unit_id,EXISTS(SELECT 1 FROM review_unit_holds h WHERE h.review_unit_id=u.review_unit_id)
		FROM review_units u WHERE u.generation_id=?1 AND (u.status IN('open','deferred') OR EXISTS(SELECT 1 FROM review_unit_holds h WHERE h.review_unit_id=u.review_unit_id)) ORDER BY u.review_unit_id")?;
	let mut rows = statement.query([generation.generation_id])?;
	while let Some(row) = rows.next()? {
		let unit: i64 = row.get(0)?;
		let held: bool = row.get(1)?;
		let mut conclusive = false;
		let mut follows = held;
		let mut results=tx.prepare("SELECT review_unit_result_id,produced_by_job_id FROM review_unit_results
			WHERE review_unit_id=?1 AND invalidated=0 AND commit_sha=?2 AND profile_version=?3
			AND corroborates_review_unit_result_id IS NULL AND corroborates_inventory_exclusion_id IS NULL ORDER BY review_unit_result_id DESC")?;
		let mut evidence_rows =
			results.query(params![unit, generation.commit_sha, generation.profile_version])?;
		while let Some(row) = evidence_rows.next()? {
			let id: i64 = row.get(0)?;
			let producer: Option<i64> = row.get(1)?;
			let StoredEvidence::Recorded(payload) = evidence(tx, id)? else { continue };
			if let Some(producer) = producer
				&& owned_result(tx, generation.generation_id, producer, &payload)?
			{
				inventory::verify_refs(tx, generation.generation_id, &payload.inspected_refs)?;
				if payload.disposition == UnitResultDisposition::NeedsFollowUp {
					follows = true;
				} else {
					conclusive = true;
				}
			}
		}
		if held || !conclusive {
			summary.missing_results += 1;
			if follows {
				summary.needs_follow_up += 1;
			}
		}
	}
	if summary.missing_results == 0
		&& summary.unresolved_inventory == 0
		&& summary.corroboration_satisfied
	{
		summary.coverage = SurveyCoverage::Complete;
	}
	Ok(summary)
}

fn reply(receipt: &terminal_receipt::Receipt) -> Result<SurveyTerminalResponse> {
	if receipt.phase != JobKind::Survey {
		return Err(incompatible());
	}
	let terminal_reason = match receipt.terminal_reason.expose() {
		"completed" => SurveyTerminalReason::Completed,
		"partial" => SurveyTerminalReason::Partial,
		"deferred" => SurveyTerminalReason::Deferred,
		_ => return Err(incompatible()),
	};
	let summary =
		serde_json::from_str(receipt.result_counts.as_ref().ok_or_else(incompatible)?.expose())
			.map_err(|_| incompatible())?;
	Ok(SurveyTerminalResponse {
		protocol_version: ReviewProtocol,
		receipt: SurveyReceipt {
			receipt_id: receipt.receipt_id.try_into().map_err(|_| incompatible())?,
			job_id: receipt.job_id.try_into().map_err(|_| incompatible())?,
			commit_sha: ReviewCommit::new(&receipt.pinned_commit_sha)
				.map_err(|_| incompatible())?,
			result_digest: envelope::digest(&receipt.result_digest)?,
			terminal_reason,
			summary,
		},
	})
}

pub async fn finalize(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, request: Request,
) -> Result<Response> {
	let (parts, body) = request.into_parts();
	let headers = parts.headers;
	let request: FinalizeSurveyRequest = http::json(&headers, body, 128 * 1024).await?;
	let reason = match request.payload.terminal_reason {
		SurveyTerminalReason::Completed => "completed",
		SurveyTerminalReason::Partial => "partial",
		SurveyTerminalReason::Deferred => "deferred",
	};
	let payload = TerminalPayload::Survey(request.payload);
	let digest = payload.digest().map_err(ApiError::invalid)?;
	let response = http::transaction(&state.db, 16 * 1024, |tx, now| {
		if let Some(receipt) = terminal::replay(tx, &worker, &headers, job, &payload)? {
			return reply(&receipt);
		}
		let scope =
			http::authorize(tx, &worker, &headers, job, &[JobKind::Survey], Access::Domain, now)?;
		let generation =
			generations::get(tx, scope.job().generation_id.ok_or_else(ApiError::denied)?)?
				.ok_or_else(ApiError::denied)?;
		if generation.state == generations::State::Building {
			let manifest = host_preparation::get(tx, generation.generation_id)?
				.ok_or_else(ApiError::denied)?;
			if !scope.is_bootstrap()
				|| generation.predecessor_generation_id.is_some()
				|| manifest.owner_job_id != Some(job)
			{
				return Err(ApiError::denied());
			}
		}
		let audit = terminal::audit(tx, &scope)?;
		validate_producer(tx, &scope, &generation)?;
		let mut summary = coverage(tx, &generation)?;
		if generation.state == generations::State::Building {
			generations::activate(tx, generation.generation_id, now)?;
		}
		generations::set_coverage(
			tx,
			generation.generation_id,
			match summary.coverage {
				SurveyCoverage::Complete => generations::Coverage::Complete,
				SurveyCoverage::Partial => generations::Coverage::Partial,
			},
		)?;
		terminal::succeed(tx, job, now)?;
		let batches = unit_holds::freeze_survey_batches(tx, job, now)?;
		summary.follow_up_batches = batches.len() as u64;
		summary.follow_up_units =
			batches.iter().map(|batch| u64::from(batch.expected_unit_count)).sum();
		let counts = BoundedJson::new(&serde_json::to_string(&summary).map_err(ApiError::invalid)?)
			.map_err(ApiError::invalid)?;
		let hash = job_capability::parse_hash(&headers).map_err(|_| ApiError::denied())?;
		let receipt = terminal::seal(
			tx,
			&terminal_receipt::NewReceipt {
				job_id: job,
				phase: JobKind::Survey,
				terminal_reason: &BoundedText::new(reason).map_err(ApiError::invalid)?,
				subject_title: None,
				subject_digest: None,
				pinned_commit_sha: &audit.pinned_commit_sha,
				effective_recipe: &audit.effective_recipe,
				result_digest: &digest,
				evidence_rung: None,
				result_counts: Some(&counts),
				finishing_capability_hash: Some(&hash),
			},
			&payload,
			now,
		)?;
		reply(&receipt)
	})?;
	state.job_arrived.notify_waiters();
	Ok(response)
}
