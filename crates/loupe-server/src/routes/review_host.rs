//! Trusted worker-host preparation. None of these operations grants source
//! authority to an agent before current-attempt checkout and manifest readiness.

use axum::extract::{Path, Request, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Extension;
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_core::JobKind;
use loupe_proto::review_api::{
	InventoryBatchRequest, ManifestProgress, PinTargetRequest, PinTargetResponse,
	PreparationDeferral, PublishProfileRequest, PublishedProfile, ReviewProtocol,
	SealInventoryRequest, UnsupportedRecipe,
};
use loupe_proto::review_lease::{ReviewCommit, ReviewGeneration};
use loupe_storage::jobs::{ActiveLease, LeaseIdentity};
use loupe_storage::{campaigns, generations, host_preparation, jobs, scheduler, terminal_receipt};
use rusqlite::{params, Transaction};

use crate::auth::AuthedWorker;
use crate::review::authority::Access;
use crate::review::http::{self, ApiError, Result};
use crate::review::{campaign, envelope};
use crate::{job_capability, AppState};

const PHASES: &[JobKind] = &[JobKind::Survey, JobKind::Drilldown, JobKind::Verify];

fn identity<'a>(job: i64, worker: &AuthedWorker, hash: &'a [u8; 32]) -> LeaseIdentity<'a> {
	LeaseIdentity { job_id: job, worker_id: worker.id(), capability_hash: hash }
}

fn decode_hex(raw: &str) -> Result<Vec<u8>> {
	if !raw.len().is_multiple_of(2) || !raw.is_ascii() {
		return Err(ApiError::invalid("invalid hex bytes"));
	}
	(0..raw.len())
		.step_by(2)
		.map(|index| u8::from_str_radix(&raw[index..index + 2], 16).map_err(ApiError::invalid))
		.collect()
}

fn progress(manifest: host_preparation::Manifest) -> Result<ManifestProgress> {
	Ok(ManifestProgress {
		protocol_version: ReviewProtocol,
		expected_entry_count: manifest.expected_count,
		expected_digest: envelope::digest(&manifest.digest)?,
		received_entry_count: manifest.received_count,
		received_canonical_bytes: manifest.received_bytes,
		sealed: manifest.sealed_at.is_some(),
	})
}

fn pin_digest(request: &PinTargetRequest) -> Result<[u8; 32]> {
	let value = serde_json::to_value(request).map_err(ApiError::invalid)?;
	let mut hasher = blake3::Hasher::new();
	hasher.update(b"loupe.host.pin.v1\0");
	hasher.update(&loupe_core::canonical::canonical_bytes(&value));
	Ok(*hasher.finalize().as_bytes())
}

fn deferred(receipt: &terminal_receipt::Receipt) -> Result<PinTargetResponse> {
	if receipt.terminal_reason.expose() != "unsupported_recipe" {
		return Err(ApiError::denied());
	}
	Ok(PinTargetResponse::Deferred {
		protocol_version: ReviewProtocol,
		receipt: PreparationDeferral {
			receipt_id: receipt.receipt_id.try_into().map_err(ApiError::invalid)?,
			commit_sha: ReviewCommit::new(&receipt.pinned_commit_sha).map_err(ApiError::invalid)?,
			reason: UnsupportedRecipe::UnsupportedRecipe,
		},
	})
}

/// Unsupported successor discovery is a control transition, not a successful
/// survey assessment. Retained campaign/receipt metadata owns the follow-up.
fn defer_successor(
	tx: &Transaction<'_>, job: i64, generation: i64, requested_ref: &str,
	request: &PinTargetRequest, hash: &[u8; 32], now: i64,
) -> Result<PinTargetResponse> {
	let row = jobs::get(tx, job)?.ok_or_else(ApiError::denied)?;
	let campaign_id = row.campaign_id.ok_or_else(ApiError::denied)?;
	let campaign = campaigns::get(tx, campaign_id)?.ok_or_else(ApiError::denied)?;
	let reason = BoundedText::new("unsupported_recipe").map_err(ApiError::invalid)?;
	let recipe = row.recipe.as_ref().ok_or_else(ApiError::denied)?;
	let audit = BoundedJson::new(&serde_json::json!({
		"version":1,
		"recipe": serde_json::from_str::<serde_json::Value>(recipe.expose()).map_err(ApiError::invalid)?,
		"policy": serde_json::from_str::<serde_json::Value>(campaign.effective_policy.expose()).map_err(ApiError::invalid)?,
		"requested_ref":requested_ref,
		"resolved_commit":request.commit_sha.expose(),
		"requires":"successor_generation"
	}).to_string()).map_err(ApiError::invalid)?;
	let mut follow_up: serde_json::Value = tx.query_row(
		"SELECT COALESCE(pending_follow_up,'{}') FROM review_generations WHERE generation_id=?1",
		[generation], |row| row.get::<_, String>(0),
	).map(|raw| serde_json::from_str(&raw)).map_err(ApiError::from)?
		.map_err(ApiError::invalid)?;
	if !follow_up.is_object() {
		return Err(ApiError::conflict("incompatible_review_state"));
	}
	follow_up["unsupported_review"] = serde_json::json!({
		"campaign_id":campaign_id,"job_id":job,"reason":"requires_successor",
		"requested_ref":requested_ref,"resolved_commit":request.commit_sha.expose()
	});
	generations::set_pending_follow_up(
		tx,
		generation,
		&BoundedJson::new(&follow_up.to_string()).map_err(ApiError::invalid)?,
	)?;
	terminal_receipt::insert(
		tx,
		&terminal_receipt::NewReceipt {
			job_id: job,
			phase: JobKind::Survey,
			terminal_reason: &reason,
			subject_title: None,
			subject_digest: None,
			pinned_commit_sha: request.commit_sha.expose(),
			effective_recipe: &audit,
			result_digest: &pin_digest(request)?,
			evidence_rung: None,
			result_counts: None,
			finishing_capability_hash: Some(hash),
		},
		now,
	)?;
	tx.execute(
		"UPDATE jobs SET state='cancelled',finished_at=?2,error='unsupported_recipe',
		 job_capability_hash=NULL,lease_expires_at=NULL,prepared_attempt=NULL,
		 prepared_capability_hash=NULL,prepared_at=NULL WHERE id=?1",
		params![job, now],
	)?;
	let other_work: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM jobs WHERE campaign_id=?1 AND state IN ('queued','leased'))",
		[campaign_id],
		|row| row.get(0),
	)?;
	if !other_work {
		let summary = campaigns::summarize(tx, campaign_id)?;
		campaigns::finish(tx, campaign_id, &summary, &reason, now)?;
	}
	deferred(&terminal_receipt::get(tx, job)?.ok_or_else(ApiError::denied)?)
}

pub async fn pin_target(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, request: Request,
) -> Result<Response> {
	let (parts, body) = request.into_parts();
	let headers = parts.headers;
	let request: PinTargetRequest = http::json(&headers, body, 2 * 1024).await?;
	let hash = job_capability::parse_hash(&headers).map_err(|_| ApiError::denied())?;
	http::transaction(&state.db, 4 * 1024 * 1024, |tx, now| {
		let identity = identity(job, &worker, &hash);
		match terminal_receipt::replay_terminal(
			tx,
			identity,
			JobKind::Survey,
			&pin_digest(&request)?,
		)? {
			terminal_receipt::Replayed::Receipt(receipt) => return deferred(&receipt),
			terminal_receipt::Replayed::Reject(terminal_receipt::Reject::WrongDigest) => {
				return Err(ApiError::conflict("terminal_conflict"))
			},
			terminal_receipt::Replayed::Reject(terminal_receipt::Reject::Denied) => {},
		}
		let scope = http::authorize(tx, &worker, &headers, job, PHASES, Access::Checkout, now)?;
		let phase = scope.job().kind.clone();
		let campaign_id = scope.job().campaign_id;
		let bootstrap = scope.is_bootstrap();
		let campaign = campaigns::get(tx, campaign_id)?.ok_or_else(ApiError::denied)?;
		let generation = if scope.job().generation_id.is_none() {
			let generation = campaign::pin(tx, campaign_id, job, request.commit_sha.expose(), now)?;
			let successor: bool = tx.query_row(
				"SELECT state='building' AND predecessor_generation_id IS NOT NULL
				 FROM review_generations WHERE generation_id=?1",
				[generation],
				|row| row.get(0),
			)?;
			if successor {
				return defer_successor(
					tx,
					job,
					generation,
					&campaign.target_commit_sha,
					&request,
					&hash,
					now,
				);
			}
			generation
		} else {
			if campaign.target_commit_sha != request.commit_sha.expose() {
				return Err(ApiError::conflict("checkout_conflict"));
			}
			scope.job().generation_id.ok_or_else(ApiError::denied)?
		};
		host_preparation::confirm(
			tx,
			ActiveLease { identity, now },
			phase.clone(),
			request.commit_sha.expose(),
		)?;
		// Recheck the resolved generation classification after pinning, inside
		// this transaction. The old unpinned scope is not preparation authority.
		let access = if bootstrap { Access::PreparedHost } else { Access::Domain };
		http::authorize(tx, &worker, &headers, job, std::slice::from_ref(&phase), access, now)?;
		let assignments = if phase == JobKind::Survey && !bootstrap {
			scheduler::initialize_ordinary_batch(tx, job, now)?;
			Some(envelope::assignments(tx, job)?)
		} else {
			None
		};
		Ok(PinTargetResponse::Prepared {
			protocol_version: ReviewProtocol,
			generation: ReviewGeneration {
				generation_id: generation.try_into().map_err(ApiError::invalid)?,
				commit_sha: request.commit_sha.clone(),
			},
			profile: envelope::profile(tx, generation)?,
			assignments,
		})
	})
}

fn bootstrap_generation(
	tx: &Transaction<'_>, worker: &AuthedWorker, headers: &HeaderMap, job: i64, now: i64,
) -> Result<i64> {
	let scope =
		http::authorize(tx, worker, headers, job, &[JobKind::Survey], Access::PreparedHost, now)?;
	if !scope.is_bootstrap() {
		return Err(ApiError::denied());
	}
	scope.job().generation_id.ok_or_else(ApiError::denied)
}

pub async fn inventory_batch(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, request: Request,
) -> Result<Response> {
	let (parts, body) = request.into_parts();
	let headers = parts.headers;
	let request: InventoryBatchRequest = http::json(&headers, body, 2 * 1024 * 1024).await?;
	let hash = job_capability::parse_hash(&headers).map_err(|_| ApiError::denied())?;
	let digest: [u8; 32] = decode_hex(request.expected_digest.expose())?
		.try_into()
		.map_err(|_| ApiError::invalid("manifest digest must be 32 bytes"))?;
	let entries = request
		.entries
		.as_slice()
		.iter()
		.map(|entry| {
			Ok(host_preparation::ManifestEntry {
				raw_path: decode_hex(entry.raw_path_hex.expose())?,
				git_mode: entry.git_mode,
				object_id: entry.object_id.expose().to_owned(),
			})
		})
		.collect::<Result<Vec<_>>>()?;
	http::transaction(&state.db, 8 * 1024, |tx, now| {
		let generation = bootstrap_generation(tx, &worker, &headers, job, now)?;
		let lease = ActiveLease { identity: identity(job, &worker, &hash), now };
		host_preparation::declare(
			tx,
			lease,
			&host_preparation::NewManifest {
				generation_id: generation,
				expected_count: request.expected_entry_count,
				digest,
			},
		)?;
		progress(host_preparation::upload(tx, lease, generation, request.start_position, &entries)?)
	})
}

pub async fn seal_inventory(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, request: Request,
) -> Result<Response> {
	let (parts, body) = request.into_parts();
	let headers = parts.headers;
	let _: SealInventoryRequest = http::json(&headers, body, 2 * 1024).await?;
	let hash = job_capability::parse_hash(&headers).map_err(|_| ApiError::denied())?;
	http::transaction(&state.db, 8 * 1024, |tx, now| {
		let generation = bootstrap_generation(tx, &worker, &headers, job, now)?;
		progress(host_preparation::seal(
			tx,
			ActiveLease { identity: identity(job, &worker, &hash), now },
			generation,
		)?)
	})
}

pub async fn publish_profile(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, request: Request,
) -> Result<Response> {
	let (parts, body) = request.into_parts();
	let headers = parts.headers;
	let request: PublishProfileRequest = http::json(&headers, body, 256 * 1024).await?;
	let hash = job_capability::parse_hash(&headers).map_err(|_| ApiError::denied())?;
	http::transaction(&state.db, 4 * 1024, |tx, now| {
		let generation = bootstrap_generation(tx, &worker, &headers, job, now)?;
		let profile = host_preparation::publish_profile(
			tx,
			ActiveLease { identity: identity(job, &worker, &hash), now },
			generation,
			&request.profile,
		)?;
		Ok(PublishedProfile {
			protocol_version: ReviewProtocol,
			profile_version: profile.version.try_into().map_err(ApiError::invalid)?,
			profile_digest: envelope::digest(&profile.digest)?,
		})
	})
}
