//! Pre-proof finalization records independent evidence, never a proof claim.
//! Reporting follows a newly committed confirmed transition. If the process
//! stops between commit and delivery, the existing admin retry-report endpoint
//! recovers the confirmed/unreported finding; receipt replay never dispatches.
use axum::extract::{Path, Request, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Extension;
use loupe_core::review_payload::{VerificationTerminalV1, Version1};
use loupe_core::text::{BoundedJson, BoundedText, SourceRef};
use loupe_core::{FindingState, JobKind, WORKFLOW_CONTRACT_VERSION};
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_lease::ReviewCommit;
use loupe_proto::review_verification::{
	FinalizeVerificationRequest, VerificationReceipt, VerificationSummary,
	VerificationTerminalResponse, VerificationVerdict,
};
use loupe_storage::review_intents::Subject;
use loupe_storage::terminal_payloads::TerminalPayload;
use loupe_storage::{
	finding_details, findings, inventory, repos, review_intents, terminal_receipt, StoredEvidence,
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

fn original(
	tx: &Transaction<'_>, scope: &Authorized<'_, '_>, finding: i64,
) -> Result<finding_details::ReviewEvidence> {
	let StoredEvidence::Recorded(details) = finding_details::get_review_evidence(tx, finding)
		.map_err(|error| match error {
			loupe_storage::Error::ReviewPayload(_) | loupe_storage::Error::Validation(_) => {
				incompatible()
			},
			other => other.into(),
		})?
	else {
		return Err(incompatible());
	};
	if details.repo_id != scope.job().repo_id
		|| details.workflow_contract_version != WORKFLOW_CONTRACT_VERSION
		|| details.profile_version <= 0
		|| details.profile_digest.is_none()
		|| !loupe_core::inventory_manifest::is_git_oid(&details.reviewed_commit_sha)
	{
		return Err(incompatible());
	}
	// The original copied profile/SHA remain historical provenance, including
	// after its generation or origin lead is removed. Never require that lead.
	let valid: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM findings f JOIN jobs j ON j.id=f.job_id
		WHERE f.id=?1 AND f.repo_id=?2 AND j.repo_id=f.repo_id AND j.kind='drilldown'
		AND j.campaign_id IS NOT NULL AND j.workflow_contract_version=1 AND j.head_sha=?3)",
		params![finding, scope.job().repo_id, details.reviewed_commit_sha],
		|row| row.get(0),
	)?;
	if !valid {
		return Err(incompatible());
	}
	Ok(details)
}

fn validate_sources(
	tx: &Transaction<'_>, generation: i64, original_sha: &str, current_sha: &str,
	payload: &VerificationTerminalV1,
) -> Result<()> {
	let revalidation = match payload {
		VerificationTerminalV1::Verified { evidence, revalidation, .. } => {
			let refs: Vec<_> = evidence
				.material_locations
				.iter()
				.map(|location| SourceRef { path: location.file.clone(), symbol: None })
				.collect();
			inventory::verify_refs(tx, generation, &refs)?;
			revalidation
		},
		VerificationTerminalV1::Rejected { counterargument, revalidation, .. } => {
			inventory::verify_refs(tx, generation, &counterargument.source_refs)?;
			revalidation
		},
		VerificationTerminalV1::Inconclusive { partial_evidence, revalidation, .. } => {
			if let Some(evidence) = partial_evidence {
				inventory::verify_refs(tx, generation, &evidence.source_refs)?;
			}
			revalidation
		},
	};
	if original_sha != current_sha && revalidation.is_none() {
		return Err(ApiError::conflict("revalidation_required"));
	}
	if let Some(revalidation) = revalidation {
		inventory::verify_refs(tx, generation, &revalidation.current_source_refs)?;
	}
	Ok(())
}

fn reply(receipt: &terminal_receipt::Receipt) -> Result<VerificationTerminalResponse> {
	if receipt.phase != JobKind::Verify {
		return Err(incompatible());
	}
	let summary: VerificationSummary =
		serde_json::from_str(receipt.result_counts.as_ref().ok_or_else(incompatible)?.expose())
			.map_err(|_| incompatible())?;
	if receipt.terminal_reason.expose() != summary.verdict.as_str() {
		return Err(incompatible());
	}
	Ok(VerificationTerminalResponse {
		protocol_version: ReviewProtocol,
		receipt: VerificationReceipt {
			receipt_id: receipt.receipt_id.try_into().map_err(|_| incompatible())?,
			job_id: receipt.job_id.try_into().map_err(|_| incompatible())?,
			commit_sha: ReviewCommit::new(&receipt.pinned_commit_sha)
				.map_err(|_| incompatible())?,
			result_digest: envelope::digest(&receipt.result_digest)?,
			summary,
		},
	})
}

/// Private transaction half: the only production caller dispatches afterwards.
/// Keeping delivery out of this function also makes the real crash gap testable.
fn finish(
	state: &AppState, worker: &AuthedWorker, headers: &HeaderMap, job: i64,
	evidence: VerificationTerminalV1,
) -> Result<(Response, Option<(i64, i64)>)> {
	let payload = TerminalPayload::Verification(evidence);
	let digest = payload.digest().map_err(ApiError::invalid)?;
	let mut dispatch = None;
	let response = http::transaction(&state.db, 16 * 1024, |tx, now| {
		if let Some(receipt) = terminal::replay(tx, worker, headers, job, &payload)? {
			return reply(&receipt);
		}
		let scope =
			http::authorize(tx, worker, headers, job, &[JobKind::Verify], Access::Domain, now)?;
		let finding = scope.job().target_finding_id.ok_or_else(ApiError::denied)?;
		let generation = scope.job().generation_id.ok_or_else(ApiError::denied)?;
		let row = findings::get(tx, finding)?.ok_or_else(ApiError::denied)?;
		if row.repo_id != scope.job().repo_id
			|| row.state != FindingState::Validating
			|| !row.verification_required
		{
			return Err(incompatible());
		}
		let original = original(tx, &scope, finding)?;
		let audit = terminal::audit(tx, &scope)?;
		let profile = envelope::profile(tx, generation)?.ok_or_else(incompatible)?;
		terminal::admitted_subject(
			tx,
			&scope,
			Subject::Finding(finding),
			&audit.pinned_commit_sha,
			&profile,
		)?;
		let TerminalPayload::Verification(evidence) = &payload else { unreachable!() };
		validate_sources(
			tx,
			generation,
			&original.reviewed_commit_sha,
			&audit.pinned_commit_sha,
			evidence,
		)?;
		let (verdict, stored_verdict) = match evidence {
			VerificationTerminalV1::Verified { .. } => (VerificationVerdict::Verified, "confirmed"),
			VerificationTerminalV1::Rejected { .. } => (VerificationVerdict::Rejected, "dismissed"),
			VerificationTerminalV1::Inconclusive { .. } => {
				(VerificationVerdict::Inconclusive, "inconclusive")
			},
		};
		let require_approval = repos::get(tx, row.repo_id)?
			.ok_or_else(ApiError::denied)?
			.effective_require_approval(state.require_approval_default);
		// The complete explanation/notes live in typed attempt evidence. A NULL
		// legacy notes projection cannot truncate or mislabel accepted prose.
		tx.execute("INSERT INTO finding_verifications(finding_id,job_id,verdict,notes,created_at) VALUES(?1,?2,?3,NULL,?4)",params![finding,job,stored_verdict,now])?;
		let verification = tx.last_insert_rowid();
		finding_details::insert_attempt_evidence(
			tx,
			&finding_details::NewAttemptEvidence {
				verification_id: verification,
				repo_id: row.repo_id,
				workflow_contract_version: WORKFLOW_CONTRACT_VERSION,
				checkout_commit_sha: &audit.pinned_commit_sha,
				evidence,
			},
			now,
		)?;
		// Exhaustion, infrastructure blockers and deadlines are never a phase
		// dismissal. Only actual accepted confirmed/dismissed verdicts roll up.
		let transition =
			findings::roll_up_verdicts_for_finding(tx, finding, false, require_approval, now)?;
		let finding_state = transition.unwrap_or(row.state);
		terminal::succeed(tx, job, now)?;
		let continuation =
			if let VerificationTerminalV1::Inconclusive { continuation, .. } = evidence {
				Some(terminal::continuation(&review_intents::continue_subject(
					tx,
					Subject::Finding(finding),
					job,
					*continuation,
					now,
				)?)?)
			} else {
				review_intents::finish_subject_intent(tx, Subject::Finding(finding), job, now)?;
				None
			};
		let summary = VerificationSummary {
			version: Version1,
			finding_id: finding.try_into().map_err(|_| incompatible())?,
			verification_id: verification.try_into().map_err(|_| incompatible())?,
			verdict,
			finding_state,
			continuation,
		};
		let counts = BoundedJson::new(&serde_json::to_string(&summary).map_err(ApiError::invalid)?)
			.map_err(ApiError::invalid)?;
		let original_digest = original.evidence.digest().map_err(|_| incompatible())?;
		let hash = job_capability::parse_hash(headers).map_err(|_| ApiError::denied())?;
		let receipt = terminal::seal(
			tx,
			&terminal_receipt::NewReceipt {
				job_id: job,
				phase: JobKind::Verify,
				terminal_reason: &BoundedText::new(verdict.as_str()).map_err(ApiError::invalid)?,
				subject_title: None,
				subject_digest: Some(&original_digest),
				pinned_commit_sha: &audit.pinned_commit_sha,
				effective_recipe: &audit.effective_recipe,
				result_digest: &digest,
				evidence_rung: (verdict == VerificationVerdict::Verified)
					.then_some(terminal_receipt::EvidenceRung::L2),
				result_counts: Some(&counts),
				finishing_capability_hash: Some(&hash),
			},
			&payload,
			now,
		)?;
		if transition == Some(FindingState::Confirmed) {
			dispatch = Some((finding, now));
		}
		reply(&receipt)
	})?;
	Ok((response, dispatch))
}

pub async fn finalize(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, request: Request,
) -> Result<Response> {
	let (parts, body) = request.into_parts();
	let input: FinalizeVerificationRequest = http::json(&parts.headers, body, 512 * 1024).await?;
	let (response, dispatch) = finish(&state, &worker, &parts.headers, job, input.payload)?;
	state.job_arrived.notify_waiters();
	if let Some((finding, now)) = dispatch
		&& let Err(error) = super::jobs::dispatch_finding(&state, finding, now).await
	{
		tracing::warn!(finding_id=finding,error=%super::jobs::format_error_chain(&error),"dispatch on phase verification failed; admin retry-report remains available");
	}
	Ok(response)
}

#[cfg(test)]
#[path = "../../tests/review_verification/gap.rs"]
mod tests;
