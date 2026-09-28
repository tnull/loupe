//! Assigned-lead finalization is one transaction: evidence, closure, mandatory
//! verification handoff, terminal audit and capability revocation. No admission
//! or external reporting occurs here.
use axum::extract::{Path, Request, State};
use axum::response::Response;
use axum::Extension;
use loupe_core::review_candidates::CandidateKind;
use loupe_core::review_payload::{
	ContinuationClass, DrilldownTerminalV1, DuplicateTarget, Version1,
};
use loupe_core::text::{BoundedJson, BoundedText, SourceRef};
use loupe_core::JobKind;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_drilldown::{
	DrilldownDisposition, DrilldownReceipt, DrilldownSummary, DrilldownTerminalResponse,
	FinalizeDrilldownRequest,
};
use loupe_proto::review_lease::ReviewCommit;
use loupe_storage::review_intents::Subject;
use loupe_storage::terminal_payloads::TerminalPayload;
use loupe_storage::{
	duplicate_candidates, inventory, leads, review_findings, review_intents, terminal_receipt,
	Conflict, StoredEvidence,
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

/// Scope is checked before any assigned evidence is decoded. Old evidence may
/// originate in a predecessor generation; its SHA is never relabeled current.
fn original_digest(
	tx: &Transaction<'_>, scope: &Authorized<'_, '_>, lead: &leads::Metadata,
) -> Result<[u8; 32]> {
	let Some(producer) = lead.created_by_job.filter(|id| *id > 0) else {
		return Err(incompatible());
	};
	if !loupe_core::inventory_manifest::is_git_oid(&lead.commit_sha) {
		return Err(incompatible());
	}
	let valid: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?2
		AND kind IN('survey','drilldown') AND workflow_contract_version=1 AND head_sha=?3)",
		params![producer, scope.job().repo_id, lead.commit_sha],
		|row| row.get(0),
	)?;
	if !valid {
		return Err(incompatible());
	}
	let stored = leads::get_evidence(tx, lead.lead_id).map_err(|error| match error {
		loupe_storage::Error::ReviewPayload(_) | loupe_storage::Error::Validation(_) => {
			incompatible()
		},
		other => other.into(),
	})?;
	let StoredEvidence::Recorded(payload) = stored else { return Err(incompatible()) };
	payload.digest().map_err(|_| incompatible())
}

fn validate_sources(
	tx: &Transaction<'_>, generation: i64, lead: &leads::Metadata, sha: &str,
	payload: &DrilldownTerminalV1,
) -> Result<()> {
	let revalidation = match payload {
		DrilldownTerminalV1::Promote { promotion, revalidation, .. } => {
			let refs: Vec<_> = promotion
				.evidence
				.material_locations
				.iter()
				.map(|location| SourceRef { path: location.file.clone(), symbol: None })
				.collect();
			inventory::verify_refs(tx, generation, &refs)?;
			revalidation
		},
		DrilldownTerminalV1::Reject { counterargument, revalidation, .. } => {
			inventory::verify_refs(tx, generation, &counterargument.source_refs)?;
			revalidation
		},
		DrilldownTerminalV1::Hardening { explanation, revalidation, .. } => {
			inventory::verify_refs(tx, generation, &explanation.source_refs)?;
			revalidation
		},
		DrilldownTerminalV1::Duplicate { revalidation, .. }
		| DrilldownTerminalV1::Defer { revalidation, .. } => revalidation,
	};
	if (lead.needs_revalidation || lead.commit_sha != sha) && revalidation.is_none() {
		return Err(ApiError::conflict("revalidation_required"));
	}
	if let Some(revalidation) = revalidation {
		inventory::verify_refs(tx, generation, &revalidation.current_source_refs)?;
	}
	Ok(())
}

fn reply(receipt: &terminal_receipt::Receipt) -> Result<DrilldownTerminalResponse> {
	if receipt.phase != JobKind::Drilldown {
		return Err(incompatible());
	}
	let summary: DrilldownSummary =
		serde_json::from_str(receipt.result_counts.as_ref().ok_or_else(incompatible)?.expose())
			.map_err(|_| incompatible())?;
	if receipt.terminal_reason.expose() != summary.disposition.as_str() {
		return Err(incompatible());
	}
	Ok(DrilldownTerminalResponse {
		protocol_version: ReviewProtocol,
		receipt: DrilldownReceipt {
			receipt_id: receipt.receipt_id.try_into().map_err(|_| incompatible())?,
			job_id: receipt.job_id.try_into().map_err(|_| incompatible())?,
			commit_sha: ReviewCommit::new(&receipt.pinned_commit_sha)
				.map_err(|_| incompatible())?,
			result_digest: envelope::digest(&receipt.result_digest)?,
			summary,
		},
	})
}

fn finding_error(error: loupe_storage::Error) -> ApiError {
	match error {
		loupe_storage::Error::Conflict(Conflict::FindingIdentity(_)) => {
			ApiError::conflict("finding_identity_conflict")
		},
		loupe_storage::Error::Conflict(Conflict::CompatibilityKey(_)) => {
			ApiError::conflict("compatibility_key_conflict")
		},
		other => other.into(),
	}
}

pub async fn finalize(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, request: Request,
) -> Result<Response> {
	let (parts, body) = request.into_parts();
	let headers = parts.headers;
	let request: FinalizeDrilldownRequest = http::json(&headers, body, 512 * 1024).await?;
	let payload = TerminalPayload::Drilldown(request.payload);
	let digest = payload.digest().map_err(ApiError::invalid)?;
	let response = http::transaction(&state.db, 16 * 1024, |tx, now| {
		if let Some(receipt) = terminal::replay(tx, &worker, &headers, job, &payload)? {
			return reply(&receipt);
		}
		let scope = http::authorize(
			tx,
			&worker,
			&headers,
			job,
			&[JobKind::Drilldown],
			Access::Domain,
			now,
		)?;
		let generation = scope.job().generation_id.ok_or_else(ApiError::denied)?;
		let lead_id = scope.job().assigned_lead_id.ok_or_else(ApiError::denied)?;
		let lead = leads::get_metadata(tx, lead_id)?.ok_or_else(ApiError::denied)?;
		if lead.generation_id != generation || lead.status != leads::Status::Open {
			return Err(incompatible());
		}
		let original = original_digest(tx, &scope, &lead)?;
		let audit = terminal::audit(tx, &scope)?;
		let profile = envelope::profile(tx, generation)?.ok_or_else(incompatible)?;
		let intent = terminal::admitted_subject(
			tx,
			&scope,
			Subject::Lead(lead_id),
			&audit.pinned_commit_sha,
			&profile,
		)?;
		let TerminalPayload::Drilldown(terminal_payload) = &payload else { unreachable!() };
		validate_sources(tx, generation, &lead, &audit.pinned_commit_sha, terminal_payload)?;
		let mut summary = DrilldownSummary {
			version: Version1,
			lead_id: lead_id.try_into().map_err(|_| incompatible())?,
			disposition: DrilldownDisposition::Deferred,
			promoted_finding_id: None,
			continuation: None,
		};
		match terminal_payload {
			DrilldownTerminalV1::Promote { promotion, .. } => {
				let finding = review_findings::insert(
					tx,
					&review_findings::NewFinding {
						repo_id: scope.job().repo_id,
						job_id: job,
						origin_lead_id: lead_id,
						profile_version: i64::from(profile.profile_version.get()),
						profile_digest: profile.profile.digest(),
						reviewed_commit_sha: &audit.pinned_commit_sha,
						promotion,
					},
					now,
				)
				.map_err(finding_error)?;
				leads::close(tx, lead_id, &leads::Closure::Promoted { finding }, now)?;
				review_intents::ensure_verification_intent(tx, finding, job, intent.priority, now)?
					.ok_or_else(incompatible)?;
				summary.disposition = DrilldownDisposition::Promoted;
				summary.promoted_finding_id = Some(finding.try_into().map_err(|_| incompatible())?);
			},
			DrilldownTerminalV1::Reject { .. } => {
				leads::close(tx, lead_id, &leads::Closure::Rejected, now)?;
				summary.disposition = DrilldownDisposition::Rejected;
			},
			DrilldownTerminalV1::Duplicate { target, .. } => {
				let (kind, id, closure) = match target {
					DuplicateTarget::Lead { id } if *id != lead_id => (
						CandidateKind::Lead,
						*id,
						leads::Closure::Duplicate { lead: Some(*id), finding: None },
					),
					DuplicateTarget::Finding { id } => (
						CandidateKind::Finding,
						*id,
						leads::Closure::Duplicate { lead: None, finding: Some(*id) },
					),
					_ => return Err(ApiError::denied()),
				};
				if !duplicate_candidates::issued_target(tx, job, scope.job().repo_id, kind, id)? {
					return Err(ApiError::denied());
				}
				leads::close(tx, lead_id, &closure, now)?;
				summary.disposition = DrilldownDisposition::Duplicate;
			},
			DrilldownTerminalV1::Hardening { .. } => {
				leads::close(tx, lead_id, &leads::Closure::Hardening, now)?;
				summary.disposition = DrilldownDisposition::Hardening;
			},
			DrilldownTerminalV1::Defer { continuation, .. } => {
				// Legacy projections contain machine state only. Multiline reasons
				// and retry explanations remain losslessly in the typed payload.
				let class = match continuation {
					ContinuationClass::SourceAnalysisRemaining => "source_analysis_remaining",
					ContinuationClass::AwaitingProofInfrastructure => {
						"awaiting_proof_infrastructure"
					},
					ContinuationClass::ExternalDependency => "external_dependency",
					ContinuationClass::RequiresSuccessor => "requires_successor",
				};
				leads::defer(
					tx,
					lead_id,
					&BoundedText::new(class).map_err(ApiError::invalid)?,
					None,
				)?;
			},
		}
		terminal::succeed(tx, job, now)?;
		if let DrilldownTerminalV1::Defer { continuation: class, .. } = terminal_payload {
			summary.continuation = Some(terminal::continuation(
				&review_intents::continue_subject(tx, Subject::Lead(lead_id), job, *class, now)?,
			)?);
		} else {
			review_intents::finish_subject_intent(tx, Subject::Lead(lead_id), job, now)?;
		}
		let counts = BoundedJson::new(&serde_json::to_string(&summary).map_err(ApiError::invalid)?)
			.map_err(ApiError::invalid)?;
		let hash = job_capability::parse_hash(&headers).map_err(|_| ApiError::denied())?;
		let receipt = terminal::seal(
			tx,
			&terminal_receipt::NewReceipt {
				job_id: job,
				phase: JobKind::Drilldown,
				terminal_reason: &BoundedText::new(summary.disposition.as_str())
					.map_err(ApiError::invalid)?,
				subject_title: None,
				subject_digest: Some(&original),
				pinned_commit_sha: &audit.pinned_commit_sha,
				effective_recipe: &audit.effective_recipe,
				result_digest: &digest,
				evidence_rung: summary
					.promoted_finding_id
					.map(|_| terminal_receipt::EvidenceRung::L2),
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
