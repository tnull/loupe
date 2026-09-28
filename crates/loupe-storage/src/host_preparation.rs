//! Attempt-bound host preparation and immutable, resumable manifest ingestion.
//!
//! Callers authorize server recipe policy and own the immediate transaction.
//! Every error must roll back that whole transaction, not only the last entry.
pub use loupe_core::inventory_manifest::ManifestEntry;
use loupe_core::inventory_manifest::{self, ManifestHasher};
use loupe_core::review_payload::GeneratedProfile;
use loupe_core::text::{BoundedJson, Identifier, RepoPath};
use loupe_core::JobKind;
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::{checkpoints, inventory, jobs, review_authority, Conflict, Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
	pub generation_id: i64,
	pub owner_job_id: Option<i64>,
	pub expected_count: u64,
	pub digest: [u8; 32],
	pub received_count: u64,
	pub received_bytes: u64,
	pub sealed_at: Option<i64>,
}

pub struct NewManifest {
	pub generation_id: i64,
	pub expected_count: u64,
	pub digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedProfile {
	pub version: i64,
	pub digest: [u8; 32],
}

fn denied() -> Error {
	Error::Conflict(Conflict::GenerationState)
}
fn invalid() -> Error {
	Error::Conflict(Conflict::InventoryPath)
}
fn limit() -> Error {
	Error::Conflict(Conflict::InventoryLimit)
}

fn context(
	tx: &Transaction<'_>, lease: jobs::ActiveLease<'_>, phase: JobKind, prepared: bool,
) -> Result<review_authority::Context> {
	let authorization = review_authority::authorize(tx, lease, phase)?.ok_or_else(denied)?;
	let context = authorization.context()?.ok_or_else(denied)?;
	if !context.campaign_active
		|| context.campaign_deadline.is_some_and(|deadline| deadline <= lease.now)
		|| context.hard_deadline_at.is_none_or(|deadline| deadline <= lease.now)
		|| (prepared && !authorization.prepared(&context)?)
	{
		return Err(denied());
	}
	Ok(context)
}

/// Pinning happened earlier in this same transaction. Confirm the host's actual
/// checkout for this attempt; a previous head SHA is not preparation authority.
pub fn confirm(
	tx: &Transaction<'_>, lease: jobs::ActiveLease<'_>, phase: JobKind, sha: &str,
) -> Result<()> {
	let context = context(tx, lease, phase, false)?;
	let generation = context.generation.ok_or_else(denied)?;
	if !inventory_manifest::is_git_oid(sha)
		|| sha != context.target_commit
		|| sha != generation.commit
	{
		return Err(denied());
	}
	// Keep the original confirmation time for an exact retry of this attempt.
	tx.execute(
		"UPDATE jobs SET head_sha=?2, prepared_at=CASE
		 WHEN prepared_attempt=attempts AND prepared_capability_hash=?3 AND head_sha=?2
		 THEN prepared_at ELSE ?4 END, prepared_attempt=attempts, prepared_capability_hash=?3
		 WHERE id=?1",
		params![lease.identity.job_id, sha, lease.identity.capability_hash, lease.now],
	)?;
	Ok(())
}

fn bootstrap_owner(
	tx: &Transaction<'_>, lease: jobs::ActiveLease<'_>, generation: i64,
) -> Result<String> {
	let context = context(tx, lease, JobKind::Survey, true)?;
	let owned = context.generation.ok_or_else(denied)?;
	if owned.id != generation
		|| owned.state != "building"
		|| owned.predecessor.is_some()
		|| context.campaign_recipe != "bootstrap"
	{
		return Err(denied());
	}
	Ok(owned.commit)
}

pub fn get(conn: &Connection, generation: i64) -> Result<Option<Manifest>> {
	Ok(conn
		.query_row(
			"SELECT owner_job_id,expected_entry_count,expected_digest,received_entry_count,
		 received_canonical_bytes,sealed_at FROM generation_manifests WHERE generation_id=?1",
			[generation],
			|row| {
				let digest: Vec<u8> = row.get(2)?;
				let digest = digest.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
				Ok(Manifest {
					generation_id: generation,
					owner_job_id: row.get(0)?,
					expected_count: row.get(1)?,
					digest,
					received_count: row.get(3)?,
					received_bytes: row.get(4)?,
					sealed_at: row.get(5)?,
				})
			},
		)
		.optional()?)
}

fn owned_manifest(
	tx: &Transaction<'_>, lease: jobs::ActiveLease<'_>, generation: i64,
) -> Result<(String, Manifest)> {
	let commit = bootstrap_owner(tx, lease, generation)?;
	let manifest = get(tx, generation)?.ok_or_else(denied)?;
	if manifest.owner_job_id != Some(lease.identity.job_id) {
		return Err(denied());
	}
	Ok((commit, manifest))
}

/// The descriptor is immutable. Only an absent/terminal logical owner may be
/// replaced, and no counters or accepted prefix change during ownership transfer.
pub fn declare(
	tx: &Transaction<'_>, lease: jobs::ActiveLease<'_>, new: &NewManifest,
) -> Result<Manifest> {
	bootstrap_owner(tx, lease, new.generation_id)?;
	if new.expected_count > inventory_manifest::MAX_ENTRIES {
		return Err(limit());
	}
	if let Some(existing) = get(tx, new.generation_id)? {
		if existing.expected_count != new.expected_count || existing.digest != new.digest {
			return Err(invalid());
		}
		if existing.owner_job_id != Some(lease.identity.job_id) {
			let live: bool = tx.query_row(
				"SELECT EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND state IN ('queued','leased'))",
				[existing.owner_job_id],
				|row| row.get(0),
			)?;
			if live {
				return Err(denied());
			}
			tx.execute(
				"UPDATE generation_manifests SET owner_job_id=?2 WHERE generation_id=?1",
				params![new.generation_id, lease.identity.job_id],
			)?;
		}
	} else {
		tx.execute(
			"INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,
			 expected_entry_count,expected_digest,created_at) VALUES(?1,1,?2,?3,?4,?5)",
			params![
				new.generation_id,
				lease.identity.job_id,
				new.expected_count,
				new.digest.as_slice(),
				lease.now
			],
		)?;
	}
	get(tx, new.generation_id)?.ok_or_else(denied)
}

fn chunk_bytes(entries: &[ManifestEntry]) -> Result<u64> {
	if entries.len() > inventory_manifest::MAX_CHUNK_ENTRIES {
		return Err(limit());
	}
	let mut bytes = 0u64;
	for (index, entry) in entries.iter().enumerate() {
		bytes =
			bytes.checked_add(entry.canonical_len().map_err(|_| invalid())?).ok_or_else(limit)?;
		if index > 0 && entries[index - 1].raw_path >= entry.raw_path {
			return Err(invalid());
		}
	}
	if bytes > inventory_manifest::MAX_CHUNK_BYTES {
		return Err(limit());
	}
	Ok(bytes)
}

fn identical_entry(
	tx: &Transaction<'_>, generation: i64, position: u64, entry: &ManifestEntry,
) -> Result<bool> {
	Ok(tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM generation_inventory WHERE generation_id=?1
		 AND manifest_position=?2 AND raw_path=?3 AND git_mode=?4 AND blob_sha=?5)",
		params![generation, position, entry.raw_path, entry.git_mode, entry.object_id],
		|row| row.get(0),
	)?)
}

/// Upload an ordered prefix extension, or replay a wholly accepted range.
/// Overlapping append/replay requests must be split at the acknowledged prefix.
pub fn upload(
	tx: &Transaction<'_>, lease: jobs::ActiveLease<'_>, generation: i64, start: u64,
	entries: &[ManifestEntry],
) -> Result<Manifest> {
	let (_, manifest) = owned_manifest(tx, lease, generation)?;
	let bytes = chunk_bytes(entries)?;
	let end = start.checked_add(entries.len() as u64).ok_or_else(limit)?;
	if end > manifest.expected_count {
		return Err(limit());
	}
	if start < manifest.received_count || manifest.sealed_at.is_some() {
		if end > manifest.received_count {
			return Err(invalid());
		}
		for (offset, entry) in entries.iter().enumerate() {
			if !identical_entry(tx, generation, start + offset as u64, entry)? {
				return Err(invalid());
			}
		}
		return Ok(manifest);
	}
	if start != manifest.received_count {
		return Err(invalid());
	}
	let total_bytes = manifest
		.received_bytes
		.checked_add(bytes)
		.filter(|bytes| *bytes <= inventory_manifest::MAX_BYTES)
		.ok_or_else(limit)?;
	if let Some(first) = entries.first() {
		let previous: Option<Vec<u8>> = tx
			.query_row(
				"SELECT raw_path FROM generation_inventory WHERE generation_id=?1
			 AND manifest_position IS NOT NULL ORDER BY manifest_position DESC LIMIT 1",
				[generation],
				|row| row.get(0),
			)
			.optional()?;
		if previous.is_some_and(|previous| previous >= first.raw_path) {
			return Err(invalid());
		}
	}
	for (offset, entry) in entries.iter().enumerate() {
		insert_entry(tx, generation, start + offset as u64, entry, lease.now)?;
	}
	tx.execute(
		"UPDATE generation_manifests SET received_entry_count=?2,received_canonical_bytes=?3 WHERE generation_id=?1",
		params![generation, end, total_bytes],
	)?;
	get(tx, generation)?.ok_or_else(denied)
}

struct ExistingEntry {
	id: i64,
	raw: Option<Vec<u8>>,
	oid: Option<String>,
	kind: String,
	position: Option<u64>,
}

fn insert_entry(
	tx: &Transaction<'_>, generation: i64, position: u64, entry: &ManifestEntry, now: i64,
) -> Result<()> {
	let path = inventory::InventoryPath::from_git_bytes(&entry.raw_path);
	let kind = if inventory_manifest::is_submodule_mode(entry.git_mode).map_err(|_| invalid())? {
		"submodule"
	} else {
		"tracked"
	};
	// Historical addressable rows may be enriched, never retargeted. Raw-only
	// exclusions match solely by exact raw bytes; display aliases are irrelevant.
	let existing: Option<ExistingEntry> = tx
		.query_row(
			"SELECT inventory_entry_id,raw_path,blob_sha,entry_kind,manifest_position
		 FROM generation_inventory WHERE generation_id=?1 AND
		 (raw_path=?2 OR (?3 IS NOT NULL AND source_path=?3))",
			params![generation, entry.raw_path, path.source_path().map(RepoPath::expose)],
			|row| {
				Ok(ExistingEntry {
					id: row.get(0)?,
					raw: row.get(1)?,
					oid: row.get(2)?,
					kind: row.get(3)?,
					position: row.get(4)?,
				})
			},
		)
		.optional()?;
	if let Some(existing) = existing {
		if existing.raw.as_ref().is_some_and(|raw| *raw != entry.raw_path)
			|| existing.oid.as_ref().is_some_and(|oid| *oid != entry.object_id)
			|| existing.kind != kind
			|| existing.position.is_some()
		{
			return Err(invalid());
		}
		tx.execute(
			"UPDATE generation_inventory SET raw_path=?2,blob_sha=?3,git_mode=?4,manifest_position=?5 WHERE inventory_entry_id=?1",
			params![existing.id, entry.raw_path, entry.object_id, entry.git_mode, position],
		)?;
	} else {
		let excluded = !path.representable();
		tx.execute(
			"INSERT INTO generation_inventory(generation_id,path,blob_sha,entry_kind,
			 disposition,disposition_reason,created_at,raw_path,source_path,manifest_position,git_mode)
			 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
			params![
				generation,
				path.expose(),
				entry.object_id,
				kind,
				if excluded { "excluded" } else { "unresolved" },
				if excluded { Some("unrepresentable-path") } else { None },
				now,
				entry.raw_path,
				path.source_path().map(RepoPath::expose),
				position,
				entry.git_mode
			],
		)?;
	}
	Ok(())
}

/// Stream all members at seal time; a received prefix or historical digest is
/// never a completeness certificate. Repeated seal preserves its first time.
pub fn seal(
	tx: &Transaction<'_>, lease: jobs::ActiveLease<'_>, generation: i64,
) -> Result<Manifest> {
	let (commit, manifest) = owned_manifest(tx, lease, generation)?;
	if manifest.sealed_at.is_some() {
		return Ok(manifest);
	}
	if manifest.received_count != manifest.expected_count {
		return Err(invalid());
	}
	let orphaned: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM generation_inventory WHERE generation_id=?1
		 AND source_path IS NOT NULL AND manifest_position IS NULL)",
		[generation],
		|row| row.get(0),
	)?;
	if orphaned {
		return Err(invalid());
	}
	let mut hasher =
		ManifestHasher::new(&commit, manifest.expected_count).map_err(|_| invalid())?;
	let mut statement = tx.prepare(
		"SELECT manifest_position,raw_path,git_mode,blob_sha FROM generation_inventory
		 WHERE generation_id=?1 AND manifest_position IS NOT NULL ORDER BY manifest_position",
	)?;
	let mut rows = statement.query([generation])?;
	let mut position = 0u64;
	while let Some(row) = rows.next()? {
		if row.get::<_, u64>(0)? != position {
			return Err(invalid());
		}
		hasher
			.push(&ManifestEntry {
				raw_path: row.get(1)?,
				git_mode: row.get(2)?,
				object_id: row.get(3)?,
			})
			.map_err(|_| invalid())?;
		position += 1;
	}
	if hasher.bytes() != manifest.received_bytes
		|| hasher.finish().map_err(|_| invalid())? != manifest.digest
	{
		return Err(invalid());
	}
	tx.execute(
		"UPDATE generation_manifests SET sealed_at=?2 WHERE generation_id=?1 AND sealed_at IS NULL",
		params![generation, lease.now],
	)?;
	tx.execute(
		"UPDATE review_generations SET inventory_digest=?2 WHERE generation_id=?1",
		params![generation, manifest.digest.as_slice()],
	)?;
	get(tx, generation)?.ok_or_else(denied)
}

/// Publish once under a logical-job checkpoint; execution retries replay this
/// receipt, but can never rewrite or increment the generation's frozen profile.
pub fn publish_profile(
	tx: &Transaction<'_>, lease: jobs::ActiveLease<'_>, generation: i64, profile: &GeneratedProfile,
) -> Result<PublishedProfile> {
	let (_, manifest) = owned_manifest(tx, lease, generation)?;
	if manifest.sealed_at.is_none() {
		return Err(denied());
	}
	let digest = *profile.digest();
	checkpoints::run(
		tx,
		lease.identity.job_id,
		checkpoints::Operation::PublishProfile,
		&Identifier::new("bootstrap")?,
		&digest,
		lease.now,
		|tx| {
			let changed = tx.execute(
				"UPDATE review_generations SET profile_version=1,generated_profile=?2,generated_profile_digest=?3
				 WHERE generation_id=?1 AND state='building' AND generated_profile IS NULL AND profile_version=1",
				params![generation, profile.expose(), digest.as_slice()],
			)?;
			if changed != 1 {
				return Err(denied());
			}
			Ok(BoundedJson::new("{\"profile_version\":1}")?)
		},
	)?;
	Ok(PublishedProfile { version: 1, digest })
}

#[cfg(test)]
mod tests;
