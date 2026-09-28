//! Append-only unit evidence and explicit invalidation.
pub use loupe_core::review_payload::UnitResultDisposition as Disposition;
use loupe_core::review_payload::UnitResultPayloadV1;
use loupe_core::text::policy::{Argument, Payload, Reason};
use loupe_core::text::{BoundedJson, BoundedText};
use rusqlite::{params, Connection, Row, Transaction};

use crate::review::{changed, historical_payload, optional, parsed, standalone};
use crate::source_refs::InspectedRefs;
use crate::{inventory, ownership, Conflict, Error, Ownership, Result, StoredEvidence};
pub struct NewResult<'a> {
	pub generation_id: i64,
	pub unit_id: i64,
	pub produced_by_job: Option<i64>,
	pub commit_sha: &'a str,
	pub profile_version: i64,
	pub disposition: Disposition,
	pub inspected_refs: &'a InspectedRefs,
	pub counterevidence: Option<&'a BoundedText<Argument>>,
	pub proof_gaps: Option<&'a BoundedText<Argument>>,
	pub payload: &'a BoundedJson<Payload>,
	pub corroborates_result: Option<i64>,
	pub corroborates_exclusion: Option<i64>,
}
/// Semantic columns derive only from the typed payload. Callers own authority,
/// exact assignment validation, checkpoint replay and continuation production.
pub struct NewResultEvidence<'a> {
	pub generation_id: i64,
	pub produced_by_job: i64,
	pub commit_sha: &'a str,
	pub profile_version: i64,
	pub payload: &'a UnitResultPayloadV1,
}
#[derive(Debug, Clone)]
pub struct EvidenceResult {
	pub result_id: i64,
	pub unit_id: i64,
	pub produced_by_job: Option<i64>,
	pub commit_sha: String,
	pub profile_version: i64,
	pub payload: StoredEvidence<UnitResultPayloadV1>,
	pub invalidated: bool,
	pub invalidated_reason: Option<BoundedText<Reason>>,
	pub created_at: i64,
}
#[derive(Debug, Clone)]
pub struct UnitResult {
	pub result_id: i64,
	pub unit_id: i64,
	pub produced_by_job: Option<i64>,
	pub commit_sha: String,
	pub profile_version: i64,
	pub disposition: Disposition,
	pub inspected_refs: InspectedRefs,
	pub counterevidence: Option<BoundedText<Argument>>,
	pub proof_gaps: Option<BoundedText<Argument>>,
	pub payload: BoundedJson<Payload>,
	pub invalidated: bool,
	pub invalidated_reason: Option<BoundedText<Reason>>,
	pub corroborates_result: Option<i64>,
	pub corroborates_exclusion: Option<i64>,
	pub created_at: i64,
}
pub fn insert(tx: &Transaction<'_>, new: &NewResult<'_>, now: i64) -> Result<i64> {
	crate::review::require_historical_payload(new.payload.expose())?;
	ownership::unit_in_generation(tx, new.unit_id, new.generation_id, Ownership::ResultUnit)?;
	if let Some(job) = new.produced_by_job {
		ownership::job_for_generation(tx, job, new.generation_id, Ownership::ResultJob)?;
	}
	if new.corroborates_result.is_some() && new.corroborates_exclusion.is_some() {
		return Err(Error::Conflict(Conflict::Corroboration));
	}
	if let Some(id) = new.corroborates_result {
		ownership::require(tx,"SELECT EXISTS(SELECT 1 FROM review_unit_results r JOIN review_units u ON u.review_unit_id=r.review_unit_id WHERE r.review_unit_result_id=?1 AND u.generation_id=?2 AND r.corroborates_review_unit_result_id IS NULL AND r.corroborates_inventory_exclusion_id IS NULL)",params![id,new.generation_id],Ownership::CorroboratedResult)?;
	}
	if let Some(id) = new.corroborates_exclusion {
		ownership::require(tx,"SELECT EXISTS(SELECT 1 FROM generation_inventory WHERE inventory_entry_id=?1 AND generation_id=?2 AND disposition='excluded')",params![id,new.generation_id],Ownership::CorroboratedExclusion)?;
	}
	inventory::verify_refs(tx, new.generation_id, new.inspected_refs.as_slice())?;
	tx.execute("INSERT INTO review_unit_results (review_unit_id,produced_by_job_id,commit_sha,profile_version,disposition,inspected_refs,counterevidence,proof_gaps,result_payload,result_digest,corroborates_review_unit_result_id,corroborates_inventory_exclusion_id,created_at)
 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",params![new.unit_id,new.produced_by_job,new.commit_sha,new.profile_version,new.disposition.as_str(),new.inspected_refs.expose(),new.counterevidence.map(BoundedText::expose),new.proof_gaps.map(BoundedText::expose),new.payload.expose(),new.payload.digest().as_slice(),new.corroborates_result,new.corroborates_exclusion,now])?;
	Ok(tx.last_insert_rowid())
}
pub fn list(conn: &Connection, unit: i64) -> Result<Vec<UnitResult>> {
	Ok(conn.prepare("SELECT review_unit_result_id,review_unit_id,produced_by_job_id,commit_sha,profile_version,disposition,inspected_refs,counterevidence,proof_gaps,result_payload,invalidated,invalidated_reason,corroborates_review_unit_result_id,corroborates_inventory_exclusion_id,created_at FROM review_unit_results WHERE review_unit_id=?1 ORDER BY review_unit_result_id")?.query_map([unit],|r|Ok(UnitResult{result_id:r.get(0)?,unit_id:r.get(1)?,produced_by_job:r.get(2)?,commit_sha:r.get(3)?,profile_version:r.get(4)?,disposition:parsed(r,5)?,inspected_refs:parsed(r,6)?,counterevidence:optional(r,7)?,proof_gaps:optional(r,8)?,payload:historical_payload(r,9)?,invalidated:r.get(10)?,invalidated_reason:optional(r,11)?,corroborates_result:r.get(12)?,corroborates_exclusion:r.get(13)?,created_at:r.get(14)?}))?.collect::<rusqlite::Result<_>>()?)
}
pub fn insert_evidence(tx: &Transaction<'_>, new: &NewResultEvidence<'_>, now: i64) -> Result<i64> {
	let bytes = new.payload.canonical_bytes()?;
	let payload = new.payload;
	ownership::unit_in_generation(
		tx,
		payload.review_unit_id,
		new.generation_id,
		Ownership::ResultUnit,
	)?;
	ownership::job_for_generation(
		tx,
		new.produced_by_job,
		new.generation_id,
		Ownership::ResultJob,
	)?;
	for lead in &payload.created_lead_ids {
		ownership::lead_in_generation(tx, *lead, new.generation_id, Ownership::LeadUnit)?;
	}
	inventory::verify_refs(tx, new.generation_id, &payload.inspected_refs)?;
	let refs = InspectedRefs::new(payload.inspected_refs.clone())?;
	tx.execute("INSERT INTO review_unit_results(review_unit_id,produced_by_job_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![payload.review_unit_id,new.produced_by_job,new.commit_sha,new.profile_version,payload.disposition.as_str(),refs.expose(),std::str::from_utf8(&bytes).expect("canonical JSON is UTF-8"),crate::canonical::digest(&bytes).as_slice(),now])?;
	Ok(tx.last_insert_rowid())
}
const EVIDENCE_COLUMNS:&str="review_unit_result_id,review_unit_id,produced_by_job_id,commit_sha,profile_version,result_payload,result_digest,disposition,inspected_refs,counterevidence,proof_gaps,corroborates_review_unit_result_id,corroborates_inventory_exclusion_id,invalidated,invalidated_reason,created_at";
fn evidence_row(row: &Row<'_>) -> Result<EvidenceResult> {
	let raw: String = row.get(5)?;
	let digest: Vec<u8> = row.get(6)?;
	let payload = crate::review::checkpoint_evidence(
		&raw,
		&digest,
		UnitResultPayloadV1::from_json,
		UnitResultPayloadV1::canonical_bytes,
	)?;
	let unit_id: i64 = row.get(1)?;
	if let StoredEvidence::Recorded(value) = &payload
		&& (value.review_unit_id != unit_id
			|| row.get::<_, String>(7)? != value.disposition.as_str()
			|| row.get::<_, String>(8)?
				!= InspectedRefs::new(value.inspected_refs.clone())?.expose()
			|| row.get::<_, Option<String>>(9)?.is_some()
			|| row.get::<_, Option<String>>(10)?.is_some()
			|| row.get::<_, Option<i64>>(11)?.is_some()
			|| row.get::<_, Option<i64>>(12)?.is_some())
	{
		return Err(Error::Conflict(Conflict::CheckpointEvidence));
	}
	Ok(EvidenceResult {
		result_id: row.get(0)?,
		unit_id,
		produced_by_job: row.get(2)?,
		commit_sha: row.get(3)?,
		profile_version: row.get(4)?,
		payload,
		invalidated: row.get(13)?,
		invalidated_reason: optional(row, 14)?,
		created_at: row.get(15)?,
	})
}
pub fn get_evidence(conn: &Connection, id: i64) -> Result<StoredEvidence<UnitResultPayloadV1>> {
	let mut statement = conn.prepare(&format!(
		"SELECT {EVIDENCE_COLUMNS} FROM review_unit_results WHERE review_unit_result_id=?1"
	))?;
	let mut rows = statement.query([id])?;
	match rows.next()? {
		Some(row) => Ok(evidence_row(row)?.payload),
		None => Ok(StoredEvidence::Missing),
	}
}
pub fn list_evidence(conn: &Connection, unit: i64) -> Result<Vec<EvidenceResult>> {
	let mut statement = conn.prepare(&format!("SELECT {EVIDENCE_COLUMNS} FROM review_unit_results WHERE review_unit_id=?1 ORDER BY review_unit_result_id"))?;
	let mut rows = statement.query([unit])?;
	let mut result = Vec::new();
	while let Some(row) = rows.next()? {
		result.push(evidence_row(row)?);
	}
	Ok(result)
}
pub fn invalidate(tx: &Transaction<'_>, id: i64, reason: &BoundedText<Reason>) -> Result<()> {
	changed(tx.execute("UPDATE review_unit_results SET invalidated=1,invalidated_reason=?2 WHERE review_unit_result_id=?1 AND invalidated=0",params![id,reason.expose()])?,Conflict::Corroboration)
}
standalone! {insert(new:&NewResult<'_>,now:i64)->i64;insert_evidence(new:&NewResultEvidence<'_>,now:i64)->i64;invalidate(id:i64,reason:&BoundedText<Reason>)->();}
