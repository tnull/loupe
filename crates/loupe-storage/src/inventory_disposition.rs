//! Single-entry disposition CAS. The caller owns live phase authority and
//! checkpoint replay, and propagates errors out of its immediate transaction.
use loupe_core::text::policy::Reason;
use loupe_core::text::{BoundedText, RepoPath};
use rusqlite::{params, OptionalExtension, Transaction};

use crate::inventory::Disposition;
use crate::review::changed;
use crate::{Conflict, Error, Result};

pub const MAX_OPERATIONS: i64 = 4096;
pub const MAX_MAPPINGS: usize = 8;

#[derive(Debug, Clone)]
pub struct Entry {
	id: i64,
	generation: i64,
	path: RepoPath,
	revision: i64,
}
impl Entry {
	pub fn id(&self) -> i64 {
		self.id
	}
	pub fn revision(&self) -> i64 {
		self.revision
	}
}
#[derive(Debug, Clone, Copy)]
pub struct Mapping {
	pub unit_id: i64,
	pub assignment_epoch: i64,
}
pub struct Update<'a> {
	pub expected_revision: i64,
	pub disposition: Disposition,
	pub reason: Option<&'a BoundedText<Reason>>,
	pub mappings: &'a [Mapping],
}

/// Resolve source identity and job scope together, before returning revision.
/// Bootstrap/ordinary classification is derived by the server's authority.
/// Completed assignments still describe source scope; fresh mapped-unit write
/// authority is checked separately by the caller after replay and CAS lookup.
pub fn resolve(
	tx: &Transaction<'_>, job: i64, generation: i64, bootstrap: bool, path: &RepoPath,
) -> Result<Option<Entry>> {
	Ok(tx.query_row("SELECT i.inventory_entry_id,i.disposition_revision FROM generation_inventory i JOIN generation_manifests m ON m.generation_id=i.generation_id JOIN jobs j ON j.id=?1 AND j.generation_id=i.generation_id WHERE i.generation_id=?2 AND i.source_path=?3 AND i.raw_path=CAST(?3 AS BLOB) AND i.manifest_position IS NOT NULL AND m.sealed_at IS NOT NULL AND m.received_entry_count=m.expected_entry_count AND (?4 OR EXISTS(SELECT 1 FROM job_assigned_review_units a JOIN review_units u ON u.review_unit_id=a.review_unit_id WHERE a.job_id=j.id AND u.generation_id=i.generation_id AND a.assignment_epoch=u.assignment_epoch AND EXISTS(SELECT 1 FROM json_each(u.source_refs) r WHERE json_extract(r.value,'$.path')=?3)))",params![job,generation,path.expose(),bootstrap],|r|Ok(Entry{id:r.get(0)?,generation,path:path.clone(),revision:r.get(1)?})).optional()?)
}

/// Replace all mappings and advance exactly this entry's revision. Input unit
/// ownership must already pass the transaction-bound survey authority check;
/// these relational checks additionally bind every unit to this exact path.
pub fn replace(tx: &Transaction<'_>, entry: &Entry, update: &Update<'_>) -> Result<i64> {
	if update.expected_revision < 0 || update.expected_revision != entry.revision {
		return Err(Error::Conflict(Conflict::InventoryPath));
	}
	let revision =
		entry.revision.checked_add(1).ok_or(Error::Conflict(Conflict::InventoryLimit))?;
	if update.mappings.len() > MAX_MAPPINGS
		|| (update.disposition == Disposition::Mapped) == update.mappings.is_empty()
		|| (matches!(update.disposition, Disposition::Context | Disposition::Excluded)
			&& update.reason.is_none())
		|| update
			.reason
			.is_some_and(|r| r.expose().chars().count() > 500 || r.expose().len() > 1000)
	{
		return Err(Error::Conflict(Conflict::InventoryPath));
	}
	let mut seen = std::collections::HashSet::new();
	for mapping in update.mappings {
		if mapping.unit_id <= 0 || mapping.assignment_epoch < 0 || !seen.insert(mapping.unit_id) {
			return Err(Error::Conflict(Conflict::Assignment));
		}
		let valid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM review_units u WHERE u.review_unit_id=?1 AND u.generation_id=?2 AND u.assignment_epoch=?3 AND EXISTS(SELECT 1 FROM json_each(u.source_refs) r WHERE json_extract(r.value,'$.path')=?4))",params![mapping.unit_id,entry.generation,mapping.assignment_epoch,entry.path.expose()],|r|r.get(0))?;
		if !valid {
			return Err(Error::Conflict(Conflict::Assignment));
		}
	}
	changed(tx.execute("UPDATE generation_inventory SET disposition=?3,disposition_reason=?4,disposition_revision=?5 WHERE inventory_entry_id=?1 AND generation_id=?2 AND disposition_revision=?6",params![entry.id,entry.generation,update.disposition.as_str(),update.reason.map(BoundedText::expose),revision,update.expected_revision])?,Conflict::InventoryPath)?;
	tx.execute("DELETE FROM generation_inventory_units WHERE inventory_entry_id=?1", [entry.id])?;
	for mapping in update.mappings {
		tx.execute("INSERT INTO generation_inventory_units(generation_id,inventory_entry_id,review_unit_id) VALUES(?1,?2,?3)",params![entry.generation,entry.id,mapping.unit_id])?;
	}
	Ok(revision)
}

#[cfg(test)]
mod tests;
