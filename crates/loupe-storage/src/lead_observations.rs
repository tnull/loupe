//! Immutable observations attached to a lead's stable identity.
use loupe_core::review_payload::LeadEvidenceV1;
use loupe_core::text::policy::Payload;
use loupe_core::text::BoundedJson;
use rusqlite::{params, Connection, Row, Transaction};

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
		result.push(evidence_row(row, identity.as_ref())?);
	}
	Ok(result)
}

/// A bounded producer-scoped lookup, optionally for one exact unit and epoch.
/// JSON predicates only select a candidate; canonical/digest/identity checking
/// remains mandatory before this evidence can establish submission provenance.
pub fn latest_evidence_for_job(
	conn: &Connection, lead: i64, job: i64, unit_epoch: Option<(i64, i64)>,
) -> Result<Option<EvidenceObservation>> {
	let identity = leads::get_metadata(conn, lead)?.map(|metadata| metadata.identity);
	let mut statement = conn.prepare("SELECT lead_observation_id,lead_id,submitted_by_job_id,observation_payload,observation_digest,commit_sha,created_at FROM lead_observations WHERE lead_id=?1 AND submitted_by_job_id=?2 AND (?3 IS NULL OR (json_extract(observation_payload,'$.review_unit_id')=?3 AND json_extract(observation_payload,'$.assignment_epoch')=?4)) ORDER BY lead_observation_id DESC LIMIT 1")?;
	let mut rows =
		statement.query(params![lead, job, unit_epoch.map(|v| v.0), unit_epoch.map(|v| v.1)])?;
	rows.next()?.map(|row| evidence_row(row, identity.as_ref())).transpose()
}

fn evidence_row(
	row: &Row<'_>, identity: Option<&crate::identity::Identity>,
) -> Result<EvidenceObservation> {
	let raw: String = row.get(3)?;
	let digest: Vec<u8> = row.get(4)?;
	let payload = crate::review::checkpoint_evidence(
		&raw,
		&digest,
		LeadEvidenceV1::from_json,
		LeadEvidenceV1::canonical_bytes,
	)?;
	if let StoredEvidence::Recorded(value) = &payload
		&& identity != Some(&leads::evidence_identity(value))
	{
		return Err(Error::Conflict(Conflict::CheckpointEvidence));
	}
	Ok(EvidenceObservation {
		observation_id: row.get(0)?,
		lead_id: row.get(1)?,
		submitted_by_job: row.get(2)?,
		payload,
		commit_sha: row.get(5)?,
		created_at: row.get(6)?,
	})
}

/// One accepted observation for this producer's exact result association.
/// Check receipt membership before JSON predicates or metadata decoding. A
/// malformed accepted record remains an integrity error, not a missing match.
pub fn accepted_evidence_for_unit(
	conn: &Connection, lead: i64, job: i64, generation: i64, unit: i64, epoch: i64,
) -> Result<Option<EvidenceObservation>> {
	let mut statement = conn.prepare("SELECT o.lead_observation_id,o.lead_id,o.submitted_by_job_id,o.observation_payload,o.observation_digest,o.commit_sha,o.created_at
		FROM lead_observations o JOIN leads l ON l.lead_id=o.lead_id
		WHERE o.lead_id=?1 AND o.submitted_by_job_id=?2 AND l.generation_id=?3
		AND CASE WHEN EXISTS(SELECT 1 FROM job_checkpoints c WHERE c.job_id=?2 AND c.operation='submit_lead'
		AND json_extract(c.response,'$.lead_id')=?1 AND json_extract(c.response,'$.observation_id')=o.lead_observation_id)
		THEN CASE WHEN json_valid(o.observation_payload)
		THEN json_extract(o.observation_payload,'$.review_unit_id')=?4 AND json_extract(o.observation_payload,'$.assignment_epoch')=?5
		ELSE 1 END ELSE 0 END ORDER BY o.lead_observation_id DESC LIMIT 1")?;
	let mut rows = statement.query(params![lead, job, generation, unit, epoch])?;
	let Some(row) = rows.next()? else { return Ok(None) };
	let identity = leads::get_metadata(conn, lead)?.map(|metadata| metadata.identity);
	Ok(Some(evidence_row(row, identity.as_ref())?))
}
standalone! {insert(new:&NewObservation<'_>,now:i64)->i64;insert_evidence(new:&NewObservationEvidence<'_>,now:i64)->i64;}
