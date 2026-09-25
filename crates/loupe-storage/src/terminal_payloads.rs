//! Job-owned canonical terminal audits. Lease authority and finalization remain
//! the caller's responsibility; insert the matching receipt in the same transaction.
use loupe_core::review_payload::{DrilldownTerminalV1, SurveyTerminalV1, VerificationTerminalV1};
use loupe_core::JobKind;
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::review::classify;
use crate::{Conflict, Error, Result, StoredEvidence};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalPayload {
	Survey(SurveyTerminalV1),
	Drilldown(DrilldownTerminalV1),
	Verification(VerificationTerminalV1),
}

impl TerminalPayload {
	pub fn phase(&self) -> JobKind {
		match self {
			Self::Survey(_) => JobKind::Survey,
			Self::Drilldown(_) => JobKind::Drilldown,
			Self::Verification(_) => JobKind::Verify,
		}
	}

	pub fn canonical_bytes(
		&self,
	) -> std::result::Result<Vec<u8>, loupe_core::review_payload::Error> {
		match self {
			Self::Survey(value) => value.canonical_bytes(),
			Self::Drilldown(value) => value.canonical_bytes(),
			Self::Verification(value) => value.canonical_bytes(),
		}
	}

	pub fn digest(&self) -> std::result::Result<[u8; 32], loupe_core::review_payload::Error> {
		Ok(loupe_core::canonical::digest(&self.canonical_bytes()?))
	}

	fn from_stored(phase: &str, raw: &str) -> Result<Self> {
		let value = match phase {
			"survey" => Self::Survey(SurveyTerminalV1::from_json(raw)?),
			"drilldown" => Self::Drilldown(DrilldownTerminalV1::from_json(raw)?),
			"verify" => Self::Verification(VerificationTerminalV1::from_json(raw)?),
			_ => return Err(Error::Conflict(Conflict::TerminalReceipt)),
		};
		if value.canonical_bytes()? != raw.as_bytes() {
			return Err(Error::Conflict(Conflict::TerminalReceipt));
		}
		Ok(value)
	}
}

/// Requires a receipt for this job with the same phase and canonical digest.
/// Propagate errors out of the caller's transaction to roll back its other writes.
pub fn insert(tx: &Transaction<'_>, job_id: i64, payload: &TerminalPayload) -> Result<()> {
	let bytes = payload.canonical_bytes()?;
	let digest = loupe_core::canonical::digest(&bytes);
	let matches: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM job_terminal_receipts r JOIN jobs j ON j.id=r.job_id
		 WHERE r.job_id=?1 AND r.phase=?2 AND j.kind=?2 AND j.campaign_id IS NOT NULL
		 AND r.result_digest=?3)",
		params![job_id, payload.phase().as_str(), digest.as_slice()],
		|r| r.get(0),
	)?;
	if !matches {
		return Err(Error::Conflict(Conflict::TerminalReceipt));
	}
	let raw = std::str::from_utf8(&bytes).expect("canonical JSON is UTF-8");
	tx.execute(
		"INSERT INTO job_terminal_payloads(job_id,phase,payload) VALUES (?1,?2,?3)",
		params![job_id, payload.phase().as_str(), raw],
	)
	.map_err(|error| classify(error, "job_terminal_payloads.job_id", Conflict::TerminalReceipt))?;
	Ok(())
}

/// Historical receipts remain readable without pretending their digest is evidence.
pub fn get(conn: &Connection, job_id: i64) -> Result<StoredEvidence<TerminalPayload>> {
	let row = conn
		.query_row(
			"SELECT p.phase,p.payload,r.phase,r.result_digest,
		 CASE WHEN j.campaign_id IS NOT NULL THEN j.kind END
		 FROM job_terminal_payloads p
		 LEFT JOIN job_terminal_receipts r ON r.job_id=p.job_id
		 LEFT JOIN jobs j ON j.id=p.job_id WHERE p.job_id=?1",
			[job_id],
			|r| {
				Ok((
					r.get::<_, String>(0)?,
					r.get::<_, String>(1)?,
					r.get::<_, Option<String>>(2)?,
					r.get::<_, Option<Vec<u8>>>(3)?,
					r.get::<_, Option<String>>(4)?,
				))
			},
		)
		.optional()?;
	let Some((phase, raw, receipt_phase, digest, job_phase)) = row else {
		let historical: bool = conn.query_row(
			"SELECT EXISTS(SELECT 1 FROM job_terminal_receipts WHERE job_id=?1)",
			[job_id],
			|r| r.get(0),
		)?;
		return Ok(if historical { StoredEvidence::Historical } else { StoredEvidence::Missing });
	};
	let payload = TerminalPayload::from_stored(&phase, &raw)?;
	if receipt_phase.as_deref() != Some(phase.as_str())
		|| job_phase.as_deref() != Some(phase.as_str())
		|| digest.as_deref() != Some(loupe_core::canonical::digest(raw.as_bytes()).as_slice())
	{
		return Err(Error::Conflict(Conflict::TerminalReceipt));
	}
	Ok(StoredEvidence::Recorded(payload))
}
