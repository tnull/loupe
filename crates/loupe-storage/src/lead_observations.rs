//! Immutable observations attached to a lead's stable identity.
use loupe_core::review_payload::LeadEvidenceV1;
use loupe_core::text::policy::Payload;
use loupe_core::text::BoundedJson;
use rusqlite::{params, Connection, Transaction};

use crate::review::{historical_payload, standalone};
use crate::{leads, ownership, Conflict, Entity, Error, Ownership, Result, StoredEvidence};
pub struct NewObservation<'a> {
	pub lead_id: i64,
	pub submitted_by_job: Option<i64>,
	pub payload: &'a BoundedJson<Payload>,
	pub commit_sha: &'a str,
}
#[derive(Debug, Clone)]
pub struct Observation {
	pub observation_id: i64,
	pub lead_id: i64,
	pub submitted_by_job: Option<i64>,
	pub payload: BoundedJson<Payload>,
	pub commit_sha: String,
	pub created_at: i64,
}
pub struct NewObservationEvidence<'a> {
	pub lead_id: i64,
	pub submitted_by_job: i64,
	pub commit_sha: &'a str,
	pub payload: &'a LeadEvidenceV1,
}
#[derive(Debug, Clone)]
pub struct EvidenceObservation {
	pub observation_id: i64,
	pub lead_id: i64,
	pub submitted_by_job: Option<i64>,
	pub payload: StoredEvidence<LeadEvidenceV1>,
	pub commit_sha: String,
	pub created_at: i64,
}
pub fn insert(tx: &Transaction<'_>, new: &NewObservation<'_>, now: i64) -> Result<i64> {
	crate::review::require_historical_payload(new.payload.expose())?;
	insert_raw(
		tx,
		new.lead_id,
		new.submitted_by_job,
		new.payload.expose(),
		new.payload.digest(),
		new.commit_sha,
		now,
	)
}
pub fn insert_evidence(
	tx: &Transaction<'_>, new: &NewObservationEvidence<'_>, now: i64,
) -> Result<i64> {
	let bytes = new.payload.canonical_bytes()?;
	let lead =
		leads::get_metadata(tx, new.lead_id)?.ok_or(Error::NotFound(Entity::Lead, new.lead_id))?;
	if lead.identity != leads::evidence_identity(new.payload) {
		return Err(Error::Conflict(Conflict::CheckpointEvidence));
	}
	leads::validate_evidence_scope(tx, lead.generation_id, new.payload)?;
	insert_raw(
		tx,
		new.lead_id,
		Some(new.submitted_by_job),
		std::str::from_utf8(&bytes).expect("canonical JSON is UTF-8"),
		&crate::canonical::digest(&bytes),
		new.commit_sha,
		now,
	)
}
pub(crate) fn insert_raw(
	tx: &Transaction<'_>, lead_id: i64, submitted_by_job: Option<i64>, payload: &str,
	digest: &[u8; 32], commit_sha: &str, now: i64,
) -> Result<i64> {
	let lead = leads::get_metadata(tx, lead_id)?.ok_or(Error::NotFound(Entity::Lead, lead_id))?;
	if let Some(job) = submitted_by_job {
		ownership::job_for_generation(tx, job, lead.generation_id, Ownership::ObservationJob)?;
	}
	tx.execute("INSERT INTO lead_observations (lead_id,submitted_by_job_id,observation_payload,observation_digest,commit_sha,created_at) VALUES (?1,?2,?3,?4,?5,?6)",params![lead_id,submitted_by_job,payload,digest.as_slice(),commit_sha,now])?;
	Ok(tx.last_insert_rowid())
}
pub fn list(conn: &Connection, lead: i64) -> Result<Vec<Observation>> {
	Ok(conn.prepare("SELECT lead_observation_id,lead_id,submitted_by_job_id,observation_payload,commit_sha,created_at FROM lead_observations WHERE lead_id=?1 ORDER BY lead_observation_id")?.query_map([lead],|r|Ok(Observation{observation_id:r.get(0)?,lead_id:r.get(1)?,submitted_by_job:r.get(2)?,payload:historical_payload(r,3)?,commit_sha:r.get(4)?,created_at:r.get(5)?}))?.collect::<rusqlite::Result<_>>()?)
}
pub fn list_evidence(conn: &Connection, lead: i64) -> Result<Vec<EvidenceObservation>> {
	let identity = leads::get_metadata(conn, lead)?.map(|metadata| metadata.identity);
	let mut statement = conn.prepare("SELECT lead_observation_id,lead_id,submitted_by_job_id,observation_payload,observation_digest,commit_sha,created_at FROM lead_observations WHERE lead_id=?1 ORDER BY lead_observation_id")?;
	let mut rows = statement.query([lead])?;
	let mut result = Vec::new();
	while let Some(row) = rows.next()? {
		let raw: String = row.get(3)?;
		let digest: Vec<u8> = row.get(4)?;
		let payload = crate::review::checkpoint_evidence(
			&raw,
			&digest,
			LeadEvidenceV1::from_json,
			LeadEvidenceV1::canonical_bytes,
		)?;
		if let StoredEvidence::Recorded(value) = &payload
			&& identity.as_ref() != Some(&leads::evidence_identity(value))
		{
			return Err(Error::Conflict(Conflict::CheckpointEvidence));
		}
		result.push(EvidenceObservation {
			observation_id: row.get(0)?,
			lead_id: row.get(1)?,
			submitted_by_job: row.get(2)?,
			payload,
			commit_sha: row.get(5)?,
			created_at: row.get(6)?,
		});
	}
	Ok(result)
}
standalone! {insert(new:&NewObservation<'_>,now:i64)->i64;insert_evidence(new:&NewObservationEvidence<'_>,now:i64)->i64;}
