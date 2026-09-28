//! Bounded snapshots shared by preparation responses and transactional claims.
//! Invalid rebuildable state is never silently truncated into a valid lease.

use loupe_core::review_payload::GeneratedProfile;
use loupe_core::text::BoundedText;
use loupe_proto::review_lease::{
	AssignedReviewUnit, FrozenReviewProfile, LeaseList, ReviewAssignments, ReviewDigest, ReviewId,
};
use loupe_storage::review_units;
use rusqlite::Transaction;

use super::http::{ApiError, Result};

fn incompatible() -> ApiError {
	ApiError::conflict("incompatible_review_state")
}

pub fn digest(bytes: &[u8]) -> Result<ReviewDigest> {
	let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
	ReviewDigest::new(&hex).map_err(|_| incompatible())
}

pub fn profile(tx: &Transaction<'_>, generation: i64) -> Result<Option<FrozenReviewProfile>> {
	let (version, raw, hash): (u32, Option<String>, Option<Vec<u8>>) = tx.query_row(
		"SELECT profile_version,generated_profile,generated_profile_digest
		 FROM review_generations WHERE generation_id=?1",
		[generation],
		|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
	)?;
	let (raw, hash) = match (raw, hash) {
		(None, None) => return Ok(None),
		(Some(raw), Some(hash)) => (raw, hash),
		_ => return Err(incompatible()),
	};
	let profile = GeneratedProfile::new(&raw).map_err(|_| incompatible())?;
	if profile.expose() != raw || profile.digest().as_slice() != hash {
		return Err(incompatible());
	}
	Ok(Some(FrozenReviewProfile {
		profile_version: version.try_into().map_err(|_| incompatible())?,
		profile_digest: digest(&hash)?,
		profile,
	}))
}

pub fn assignments(tx: &Transaction<'_>, job: i64) -> Result<ReviewAssignments> {
	let generation: Option<i64> =
		tx.query_row("SELECT generation_id FROM jobs WHERE id=?1", [job], |row| row.get(0))?;
	let generation = generation.ok_or_else(incompatible)?;
	let rows = tx
		.prepare(
			"SELECT review_unit_id,assignment_epoch FROM job_assigned_review_units
		 WHERE job_id=?1 AND completed=0 ORDER BY position LIMIT 33",
		)?
		.query_map([job], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<u64>>(1)?)))?
		.collect::<rusqlite::Result<Vec<_>>>()?;
	if rows.len() > 32 {
		return Err(incompatible());
	}
	let mut units = Vec::new();
	for (id, epoch) in rows {
		let unit = review_units::get(tx, id)?.ok_or_else(incompatible)?;
		let epoch = epoch.ok_or_else(incompatible)?;
		if unit.generation_id != generation
			|| unit.assignment_epoch != i64::try_from(epoch).map_err(|_| incompatible())?
		{
			return Err(incompatible());
		}
		loupe_storage::inventory::verify_refs(tx, generation, unit.source_refs.as_slice())
			.map_err(|error| match error {
				loupe_storage::Error::UnknownPaths(_) => incompatible(),
				other => ApiError::from(other),
			})?;
		let dependencies: Vec<ReviewId> = unit
			.depends_on
			.as_ref()
			.map(|raw| serde_json::from_str(raw.expose()))
			.transpose()
			.map_err(|_| incompatible())?
			.unwrap_or_default();
		let dependencies = LeaseList::new(dependencies).map_err(|_| incompatible())?;
		for dependency in dependencies.as_slice() {
			let belongs: bool = tx.query_row(
				"SELECT EXISTS(SELECT 1 FROM review_units WHERE review_unit_id=?1 AND generation_id=?2)",
				rusqlite::params![i64::from(*dependency), generation], |row| row.get(0),
			)?;
			if !belongs {
				return Err(incompatible());
			}
		}
		units.push(AssignedReviewUnit {
			review_unit_id: id.try_into().map_err(|_| incompatible())?,
			assignment_epoch: epoch.try_into().map_err(|_| incompatible())?,
			title: unit.title,
			objective: unit.objective,
			source_refs: LeaseList::new(unit.source_refs.as_slice().to_vec())
				.map_err(|_| incompatible())?,
			depends_on: dependencies,
			closure_criteria: unit
				.closure_criteria
				.as_ref()
				.map(|text| BoundedText::new(text.expose()))
				.transpose()
				.map_err(|_| incompatible())?,
		});
	}
	LeaseList::new(units).and_then(ReviewAssignments::try_from).map_err(|_| incompatible())
}
