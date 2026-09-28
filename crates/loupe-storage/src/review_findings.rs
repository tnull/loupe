//! Strict phase promotion storage, independent of legacy scan acceptance.
//!
//! The caller must propagate errors and roll back its transaction, including a
//! tentative finding when canonical detail insertion conflicts. Lease authority,
//! revalidation, frozen-profile readiness, lead closure, verification intent and
//! terminal receipts remain the caller's responsibility.
use std::fmt::Write;

use loupe_core::review_payload::PromotionV1;
use loupe_core::text::SourceRef;
use rusqlite::{params, OptionalExtension, Transaction};

use crate::finding_details::{self, NewReviewEvidence};
use crate::identity::Identity;
use crate::review::{is_unique, standalone};
use crate::{inventory, ownership, Conflict, Error, Ownership, Result, StoredEvidence};

const SCANNER_ID: &str = "llm-code-review";

pub struct NewFinding<'a> {
	pub repo_id: i64,
	pub job_id: i64,
	pub origin_lead_id: i64,
	pub profile_version: i64,
	pub profile_digest: &'a [u8; 32],
	pub reviewed_commit_sha: &'a str,
	pub promotion: &'a PromotionV1,
}

fn identity(promotion: &PromotionV1) -> Identity {
	Identity {
		family: promotion.identity_family.clone(),
		anchor: promotion.identity_anchor.clone(),
		instance: promotion.identity_instance_key.clone(),
	}
}

fn compatibility_key(identity: &Identity) -> String {
	let mut key = String::from("review:v1:");
	for byte in identity.fingerprint() {
		write!(&mut key, "{byte:02x}").expect("writing into a String cannot fail");
	}
	key
}

/// Always creates a validating, verification-required L2 finding. No legacy
/// configuration can waive verification and no proof/patch field is accepted.
pub fn insert(tx: &Transaction<'_>, new: &NewFinding<'_>, now: i64) -> Result<i64> {
	new.promotion.canonical_bytes()?;
	if new.profile_version <= 0 {
		return Err(Error::Conflict(Conflict::FindingDetails));
	}
	ownership::lead_in_repo(tx, new.origin_lead_id, new.repo_id, Ownership::FindingLead)?;
	let generation: Option<i64> = tx
		.query_row(
			"SELECT generation_id FROM jobs WHERE id=?1 AND repo_id=?2 AND kind='drilldown'
		 AND campaign_id IS NOT NULL AND assigned_lead_id=?3
		 AND (head_sha IS NULL OR head_sha=?4)
		 AND (workflow_contract_version IS NULL OR workflow_contract_version=?5)",
			params![
				new.job_id,
				new.repo_id,
				new.origin_lead_id,
				new.reviewed_commit_sha,
				loupe_core::WORKFLOW_CONTRACT_VERSION
			],
			|row| row.get(0),
		)
		.optional()?
		.ok_or(Error::Ownership(Ownership::Finding))?;
	if let Some(generation) = generation {
		ownership::generation(tx, new.repo_id, generation, Ownership::Finding)?;
		ownership::lead_in_generation(tx, new.origin_lead_id, generation, Ownership::FindingLead)?;
		// Symbols remain in canonical material locations. Membership is path-only.
		let refs: Vec<_> = new
			.promotion
			.evidence
			.material_locations
			.iter()
			.map(|location| SourceRef { path: location.file.clone(), symbol: None })
			.collect();
		inventory::verify_refs(tx, generation, &refs)?;
	}
	let identity = identity(new.promotion);
	let key = compatibility_key(&identity);
	// Validation above guarantees one or more locations. Array order is the
	// deterministic display policy; every location is retained in evidence below.
	let display = &new.promotion.evidence.material_locations[0];
	let inserted = tx.execute(
		"INSERT INTO findings
		 (repo_id,job_id,scanner_id,severity,title,description,file_path,line_start,line_end,cwe,
		 fingerprint,state,verification_required,created_at)
		 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'validating',1,?12)",
		params![
			new.repo_id,
			new.job_id,
			SCANNER_ID,
			new.promotion.severity.as_str(),
			new.promotion.title.expose(),
			new.promotion.description.expose(),
			display.file.expose(),
			display.line_start,
			display.line_end,
			new.promotion.cwe.as_ref().map(|value| value.expose()),
			key,
			now
		],
	);
	if let Err(error) = inserted {
		if is_unique(&error, "findings.repo_id, findings.fingerprint") {
			let existing: i64 = tx.query_row(
				"SELECT id FROM findings WHERE repo_id=?1 AND fingerprint=?2",
				params![new.repo_id, key],
				|row| row.get(0),
			)?;
			return Err(Error::Conflict(classify_compatibility_collision(
				tx,
				existing,
				new.repo_id,
				&identity,
			)?));
		}
		return Err(error.into());
	}
	let finding_id = tx.last_insert_rowid();
	finding_details::insert_review_evidence(
		tx,
		&NewReviewEvidence {
			finding_id,
			repo_id: new.repo_id,
			workflow_contract_version: loupe_core::WORKFLOW_CONTRACT_VERSION,
			profile_version: new.profile_version,
			profile_digest: Some(new.profile_digest),
			reviewed_commit_sha: new.reviewed_commit_sha,
			identity: &identity,
			evidence: &new.promotion.evidence,
			origin_lead: Some(new.origin_lead_id),
		},
		now,
	)?;
	Ok(finding_id)
}

fn classify_compatibility_collision(
	tx: &Transaction<'_>, existing: i64, repo: i64, identity: &Identity,
) -> Result<Conflict> {
	match finding_details::get_review_evidence(tx, existing) {
		Ok(StoredEvidence::Recorded(details))
			if details.repo_id == repo
				&& details.workflow_contract_version == loupe_core::WORKFLOW_CONTRACT_VERSION
				&& &details.identity == identity =>
		{
			Ok(Conflict::FindingIdentity(existing))
		},
		Ok(_) => Ok(Conflict::CompatibilityKey(existing)),
		Err(
			Error::ReviewPayload(_)
			| Error::Validation(_)
			| Error::Conflict(Conflict::FindingDetails)
			| Error::Ownership(Ownership::Finding),
		) => Ok(Conflict::CompatibilityKey(existing)),
		// These errors describe malformed stored column values, not database
		// availability/SQL failures. Do not collapse unrelated SQLite errors.
		Err(Error::Sqlite(
			rusqlite::Error::FromSqlConversionFailure(..)
			| rusqlite::Error::InvalidColumnType(..)
			| rusqlite::Error::IntegralValueOutOfRange(..),
		)) => Ok(Conflict::CompatibilityKey(existing)),
		Err(error) => Err(error),
	}
}

standalone! {insert(new:&NewFinding<'_>,now:i64)->i64;}

#[cfg(test)]
mod tests;
