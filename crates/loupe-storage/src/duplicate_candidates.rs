//! Job-issued, bounded duplicate context. Caller owns lease authorization and
//! the write transaction; issuance is durable across attempts and restarts.
use loupe_core::review_candidates::{Candidate, CandidateKind, CandidateQuery};
use loupe_core::text::policy::{ClientKey, Payload};
use loupe_core::text::{BoundedJson, Identifier};
use rusqlite::{params, OptionalExtension, Row, Transaction};

use crate::checkpoints::{self, Operation, Outcome};
use crate::identity::Identity;
use crate::review::{optional, parsed};
use crate::{Conflict, Error, Ownership, Result};

pub const QUERY_LIMIT: i64 = 32;

#[cfg(test)]
mod tests;

fn invalid() -> Error {
	Error::Conflict(Conflict::Candidate)
}

fn row(row: &Row<'_>) -> rusqlite::Result<(Candidate, Vec<u8>)> {
	Ok((
		Candidate {
			kind: if row.get::<_, String>(0)? == "lead" {
				CandidateKind::Lead
			} else {
				CandidateKind::Finding
			},
			id: row.get(1)?,
			producer_job_id: row.get(2)?,
			commit_sha: row.get(3)?,
			created_at: row.get(4)?,
			identity_family: parsed(row, 5)?,
			identity_anchor: parsed(row, 6)?,
			identity_instance_key: optional(row, 7)?,
		},
		row.get(8)?,
	))
}

const CANDIDATES: &str = "
SELECT 'lead' AS kind,l.lead_id AS id,l.created_by_job_id AS producer_job_id,
 l.commit_sha,l.created_at,l.identity_family,l.identity_anchor,l.identity_instance_key,l.identity_fingerprint
 FROM leads l JOIN review_generations g ON g.generation_id=l.generation_id
 WHERE g.repo_id=?1 AND l.created_by_job_id IS NOT NULL
UNION ALL
SELECT 'finding',f.id,f.job_id,d.reviewed_commit_sha,f.created_at,
 d.identity_family,d.identity_anchor,d.identity_instance_key,d.identity_fingerprint
 FROM findings f JOIN finding_review_details d ON d.finding_id=f.id AND d.repo_id=f.repo_id
 WHERE f.repo_id=?1";

fn checked((candidate, fingerprint): (Candidate, Vec<u8>)) -> Result<Candidate> {
	let identity = Identity {
		family: candidate.identity_family.clone(),
		anchor: candidate.identity_anchor.clone(),
		instance: candidate.identity_instance_key.clone(),
	};
	if candidate.id <= 0
		|| candidate.producer_job_id <= 0
		|| !loupe_core::inventory_manifest::is_git_oid(&candidate.commit_sha)
		|| fingerprint != identity.fingerprint()
	{
		return Err(invalid());
	}
	Ok(candidate)
}

pub fn issue(
	tx: &Transaction<'_>, job: i64, repo: i64, query: &CandidateQuery, now: i64,
) -> Result<Vec<Candidate>> {
	query.validate().map_err(|_| invalid())?;
	crate::ownership::require(tx, "SELECT EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?2 AND campaign_id IS NOT NULL AND kind IN ('survey','drilldown'))", params![job,repo], Ownership::Candidate)?;
	let bytes =
		crate::canonical::canonical_bytes(&serde_json::to_value(query).map_err(|_| invalid())?);
	let digest = crate::canonical::digest(&bytes);
	let key = Identifier::<ClientKey>::new(
		&digest.iter().map(|b| format!("{b:02x}")).collect::<String>(),
	)?;
	let outcome = checkpoints::run(
		tx,
		job,
		Operation::IssueDuplicateCandidates,
		&key,
		&digest,
		now,
		|tx| {
			if checkpoints::accepted_count(tx, job, Operation::IssueDuplicateCandidates)?
				>= QUERY_LIMIT
			{
				return Err(Error::Conflict(Conflict::CheckpointLimit));
			}
			let sql = format!("SELECT * FROM ({CANDIDATES}) WHERE instr(lower(identity_family),lower(?2))>0 OR instr(lower(identity_anchor),lower(?2))>0 ORDER BY kind,id LIMIT ?3");
			let mut stmt = tx.prepare(&sql)?;
			let candidates = stmt
				.query_map(params![repo, query.query.expose(), query.limit], row)?
				.map(|value| checked(value?))
				.collect::<Result<Vec<_>>>()?;
			Ok(BoundedJson::<Payload>::new(
				&serde_json::to_string(&candidates).map_err(|_| invalid())?,
			)?)
		},
	)?;
	let (Outcome::Fresh(payload) | Outcome::Replayed(payload)) = outcome;
	serde_json::from_str(payload.expose()).map_err(|_| invalid())
}

/// Issuance grants no general search permission. Revalidate retained immutable
/// identity against the current same-project row immediately before closure.
pub fn issued_target(
	tx: &Transaction<'_>, job: i64, repo: i64, kind: CandidateKind, id: i64,
) -> Result<bool> {
	let mut stmt = tx.prepare("SELECT response FROM job_checkpoints WHERE job_id=?1 AND operation=?2 ORDER BY client_key LIMIT ?3")?;
	let responses = stmt.query_map(
		params![job, Operation::IssueDuplicateCandidates.as_str(), QUERY_LIMIT + 1],
		|row| row.get::<_, String>(0),
	)?;
	let mut issued = Vec::new();
	for (index, response) in responses.enumerate() {
		if index >= QUERY_LIMIT as usize {
			return Err(invalid());
		}
		let response = BoundedJson::<Payload>::new(&response?)?;
		let candidates: Vec<Candidate> =
			serde_json::from_str(response.expose()).map_err(|_| invalid())?;
		if candidates.len() > 20 {
			return Err(invalid());
		}
		issued.extend(
			candidates.into_iter().filter(|candidate| candidate.kind == kind && candidate.id == id),
		);
	}
	// Out-of-scope IDs must not cause any current target decoding, including
	// errors from malformed rows that would reveal that an unissued ID exists.
	if issued.is_empty() {
		return Ok(false);
	}
	let sql = format!("SELECT * FROM ({CANDIDATES}) WHERE kind=?2 AND id=?3");
	let current = tx
		.query_row(
			&sql,
			params![
				repo,
				match kind {
					CandidateKind::Lead => "lead",
					CandidateKind::Finding => "finding",
				},
				id
			],
			row,
		)
		.optional()?;
	let Some(current) = current else { return Ok(false) };
	let current = checked(current)?;
	Ok(issued.iter().any(|candidate| candidate == &current))
}
