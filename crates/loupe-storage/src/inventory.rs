//! Byte-exact inventory references, including visibly unrepresentable entries.
use loupe_core::text::policy::Reason;
use loupe_core::text::{BoundedText, RepoPath, SourceRef};
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::review::{is_unique, optional, parsed, standalone, string_enum};
use crate::{ownership, Conflict, Error, Ownership, Result};
string_enum!(EntryKind { Tracked => "tracked", Submodule => "submodule" });
string_enum!(Disposition { Mapped => "mapped", Context => "context", Excluded => "excluded", Unresolved => "unresolved" });
pub const MAX_ENTRIES: usize = 4096;
pub const MAX_RAW_PATH_BYTES: usize = loupe_core::inventory_manifest::MAX_PATH_BYTES;

#[derive(Clone)]
pub struct InventoryPath {
	rendering: String,
	raw: Option<Vec<u8>>,
	source: Option<RepoPath>,
}
impl InventoryPath {
	pub fn from_git_bytes(raw: &[u8]) -> Self {
		if let Ok(text) = std::str::from_utf8(raw)
			&& let Ok(source) = RepoPath::new(text)
		{
			return Self {
				rendering: text.to_owned(),
				raw: Some(raw.to_vec()),
				source: Some(source),
			};
		}
		let mut rendering = String::new();
		for &byte in raw {
			if (0x20..=0x7e).contains(&byte) {
				rendering.push(byte as char);
			} else {
				use std::fmt::Write;
				write!(&mut rendering, "%{byte:02X}").expect("writing a String");
			}
		}
		Self { rendering, raw: Some(raw.to_vec()), source: None }
	}
	pub fn expose(&self) -> &str {
		&self.rendering
	}
	pub fn representable(&self) -> bool {
		self.source.is_some()
	}
	/// Historical display strings never supply guessed raw bytes.
	pub fn raw_bytes(&self) -> Option<&[u8]> {
		self.raw.as_deref()
	}
	pub fn source_path(&self) -> Option<&RepoPath> {
		self.source.as_ref()
	}
}
impl std::fmt::Debug for InventoryPath {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"InventoryPath(len={}, representable={})",
			self.rendering.len(),
			self.representable()
		)
	}
}
pub struct NewEntry<'a> {
	pub path: &'a InventoryPath,
	pub blob_sha: Option<&'a str>,
	pub kind: EntryKind,
	pub disposition: Disposition,
	pub reason: Option<&'a BoundedText<Reason>>,
	pub highlighted: bool,
}
#[derive(Debug, Clone)]
pub struct Entry {
	pub inventory_entry_id: i64,
	pub generation_id: i64,
	pub path: InventoryPath,
	pub blob_sha: Option<String>,
	pub kind: EntryKind,
	pub disposition: Disposition,
	pub reason: Option<BoundedText<Reason>>,
	pub highlighted: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inserted {
	/// Newly inserted raw identities, including distinct display aliases.
	pub inserted: usize,
	pub excluded: usize,
	/// Identical retries only. Distinct raw paths are never skipped.
	pub skipped: usize,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownPaths(pub Vec<RepoPath>);
impl std::fmt::Display for UnknownPaths {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{} references are outside the pinned inventory", self.0.len())
	}
}
impl std::error::Error for UnknownPaths {}

/// `None` preserves legacy setup behavior; it never certifies preparation.
pub(crate) fn manifest_sealed(tx: &Transaction<'_>, generation: i64) -> Result<Option<bool>> {
	Ok(tx
		.query_row(
			"SELECT sealed_at IS NOT NULL FROM generation_manifests WHERE generation_id=?1",
			[generation],
			|row| row.get(0),
		)
		.optional()?)
}

/// Legacy setup only. Managed generations require the host-owned upload path.
pub fn insert(
	tx: &Transaction<'_>, repo: i64, generation: i64, entries: &[NewEntry<'_>], now: i64,
) -> Result<Inserted> {
	ownership::generation(tx, repo, generation, Ownership::InventoryGeneration)?;
	if manifest_sealed(tx, generation)?.is_some() {
		return Err(Error::Conflict(Conflict::GenerationState));
	}
	if entries.len() > MAX_ENTRIES {
		return Err(Error::Conflict(Conflict::InventoryLimit));
	}
	let mut outcome = Inserted { inserted: 0, excluded: 0, skipped: 0 };
	let mut insert = tx.prepare("INSERT INTO generation_inventory (generation_id,path,blob_sha,entry_kind,disposition,disposition_reason,highlighted,created_at,raw_path,source_path) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)")?;
	// The complete accepted entry must agree; another display alias never
	// makes an upload a retry or changes the target of historical evidence.
	let mut identical = tx.prepare(
		"SELECT EXISTS(SELECT 1 FROM generation_inventory
		   WHERE generation_id=?1 AND raw_path=?2 AND blob_sha IS ?3 AND entry_kind=?4
		     AND disposition=?5 AND disposition_reason IS ?6 AND highlighted=?7)",
	)?;
	for entry in entries {
		let raw = entry.path.raw_bytes().ok_or_else(|| {
			loupe_core::text::Error::new("raw_path", loupe_core::text::Rule::Path)
		})?;
		if raw.is_empty() || raw.len() > MAX_RAW_PATH_BYTES {
			return Err(
				loupe_core::text::Error::new("raw_path", loupe_core::text::Rule::Bytes).into()
			);
		}
		let excluded = !entry.path.representable();
		if !excluded && entry.reason.is_some_and(|r| r.expose() == "unrepresentable-path") {
			return Err(loupe_core::text::Error::new(
				"disposition_reason",
				loupe_core::text::Rule::Identifier,
			)
			.into());
		}
		let disposition = if excluded { Disposition::Excluded } else { entry.disposition };
		let reason = if excluded {
			Some("unrepresentable-path")
		} else {
			entry.reason.map(BoundedText::expose)
		};
		if disposition == Disposition::Excluded && reason.is_none() {
			return Err(loupe_core::text::Error::new(
				"disposition_reason",
				loupe_core::text::Rule::Empty,
			)
			.into());
		}
		let row = params![
			generation,
			entry.path.expose(),
			entry.blob_sha,
			entry.kind.as_str(),
			disposition.as_str(),
			reason,
			entry.highlighted,
			now,
			raw,
			entry.path.source_path().map(RepoPath::expose)
		];
		match insert.execute(row) {
			Ok(_) => {
				outcome.inserted += 1;
				outcome.excluded += usize::from(excluded);
			},
			Err(e)
				if is_unique(
					&e,
					"generation_inventory.generation_id, generation_inventory.raw_path",
				) || is_unique(
					&e,
					"generation_inventory.generation_id, generation_inventory.source_path",
				) =>
			{
				if identical.query_row(
					params![
						generation,
						raw,
						entry.blob_sha,
						entry.kind.as_str(),
						disposition.as_str(),
						reason,
						entry.highlighted
					],
					|r| r.get::<_, bool>(0),
				)? {
					outcome.skipped += 1;
				} else {
					return Err(Error::Conflict(Conflict::InventoryPath));
				}
			},
			Err(e) => return Err(e.into()),
		}
	}
	Ok(outcome)
}
pub fn list(conn: &Connection, generation: i64) -> Result<Vec<Entry>> {
	Ok(conn.prepare("SELECT inventory_entry_id,generation_id,path,blob_sha,entry_kind,disposition,disposition_reason,highlighted,raw_path,source_path FROM generation_inventory WHERE generation_id=?1 ORDER BY path,inventory_entry_id")?.query_map([generation],|r| {
		let reason: Option<BoundedText<Reason>> = optional(r,6)?;
		let path = InventoryPath { rendering:r.get(2)?,raw:r.get(8)?,source:optional(r,9)? };
		Ok(Entry { inventory_entry_id:r.get(0)?,generation_id:r.get(1)?,path,blob_sha:r.get(3)?,kind:parsed(r,4)?,disposition:parsed(r,5)?,reason,highlighted:r.get(7)? })
	})?.collect::<rusqlite::Result<_>>()?)
}
pub fn verify_refs(tx: &Transaction<'_>, generation: i64, refs: &[SourceRef]) -> Result<()> {
	ownership::generation_repo(tx, generation)?;
	let managed = match manifest_sealed(tx, generation)? {
		Some(false) => return Err(Error::Conflict(Conflict::GenerationState)),
		Some(true) => true,
		None => false,
	};
	if !managed {
		let exists: bool = tx.query_row("SELECT inventory_digest IS NOT NULL OR EXISTS(SELECT 1 FROM generation_inventory WHERE generation_id=?1) FROM review_generations WHERE generation_id=?1",[generation],|r|r.get(0))?;
		if !exists {
			return Ok(());
		}
	}
	let mut unknown = Vec::new();
	let mut statement = tx.prepare("SELECT EXISTS(SELECT 1 FROM generation_inventory
		WHERE generation_id=?1 AND (
		 (?3 AND source_path=?2 AND manifest_position IS NOT NULL) OR
		 (NOT ?3 AND path=?2 AND (disposition_reason IS NULL OR disposition_reason<>'unrepresentable-path'))))")?;
	for source in refs {
		if !statement.query_row(params![generation, source.path.expose(), managed], |r| {
			r.get::<_, bool>(0)
		})? {
			unknown.push(source.path.clone());
		}
	}
	if unknown.is_empty() {
		Ok(())
	} else {
		Err(Error::UnknownPaths(UnknownPaths(unknown)))
	}
}
standalone! { insert(repo: i64, generation: i64, entries: &[NewEntry<'_>], now: i64) -> Inserted; }
