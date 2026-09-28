//! Terminal retries are authenticated by their original finishing capability.
use loupe_core::text::policy::{Payload, Reason, Title};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_core::JobKind;
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::review::{is_unique, optional, parsed, standalone, string_enum};
use crate::{Conflict, Entity, Error, Result};
// The receipt's phase is the job's kind; reusing `JobKind` keeps the two
// from drifting when a kind is added.
string_enum!(EvidenceRung { L1=>"L1", L2=>"L2", L3=>"L3", L4=>"L4" });
pub struct NewReceipt<'a> {
	pub job_id: i64,
	pub phase: JobKind,
	pub terminal_reason: &'a BoundedText<Reason>,
	pub subject_title: Option<&'a BoundedText<Title>>,
	pub subject_digest: Option<&'a [u8; 32]>,
	pub pinned_commit_sha: &'a str,
	pub effective_recipe: &'a BoundedJson<Payload>,
	pub result_digest: &'a [u8; 32],
	pub evidence_rung: Option<EvidenceRung>,
	pub result_counts: Option<&'a BoundedJson<Payload>>,
	pub finishing_capability_hash: Option<&'a [u8; 32]>,
}
#[derive(Clone)]
pub struct Receipt {
	pub receipt_id: i64,
	pub job_id: i64,
	pub phase: JobKind,
	pub terminal_reason: BoundedText<Reason>,
	pub subject_title: Option<BoundedText<Title>>,
	pub subject_digest: Option<Vec<u8>>,
	pub pinned_commit_sha: String,
	pub effective_recipe: BoundedJson<Payload>,
	pub result_digest: Vec<u8>,
	pub evidence_rung: Option<EvidenceRung>,
	pub result_counts: Option<BoundedJson<Payload>>,
	pub created_at: i64,
}
impl std::fmt::Debug for Receipt {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Receipt")
			.field("job_id", &self.job_id)
			.field("phase", &self.phase)
			.finish_non_exhaustive()
	}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
	Denied,
	WrongDigest,
}
#[derive(Debug, Clone)]
pub enum Replayed {
	Receipt(Box<Receipt>),
	Reject(Reject),
}
/// Lease validation and the job's terminal transition belong to the caller.
pub fn insert(tx: &Transaction<'_>, new: &NewReceipt<'_>, now: i64) -> Result<i64> {
	let phase: String = tx
		.query_row("SELECT kind FROM jobs WHERE id=?1", [new.job_id], |r| r.get(0))
		.optional()?
		.ok_or(Error::NotFound(Entity::Job, new.job_id))?;
	if !new.phase.is_known() || phase != new.phase.as_str() {
		return Err(Error::Conflict(Conflict::TerminalReceipt));
	}
	tx.execute("INSERT INTO job_terminal_receipts (job_id,phase,terminal_reason,subject_title,subject_digest,pinned_commit_sha,effective_recipe,result_digest,evidence_rung,result_counts,finishing_capability_hash,created_at)
 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",params![new.job_id,new.phase.as_str(),new.terminal_reason.expose(),new.subject_title.map(BoundedText::expose),new.subject_digest.map(|d|d.as_slice()),new.pinned_commit_sha,new.effective_recipe.expose(),new.result_digest.as_slice(),new.evidence_rung.map(EvidenceRung::as_str),new.result_counts.map(BoundedJson::expose),new.finishing_capability_hash.map(|d|d.as_slice()),now])
 .map_err(|error| {
     if is_unique(&error, "job_terminal_receipts.job_id")
         || is_unique(&error, "job_terminal_receipts.job_id, job_terminal_receipts.phase")
     {
         Error::Conflict(Conflict::TerminalReceipt)
     } else {
         error.into()
     }
 })?;
	Ok(tx.last_insert_rowid())
}
pub fn get(conn: &Connection, job: i64) -> Result<Option<Receipt>> {
	Ok(conn.query_row("SELECT job_terminal_receipt_id,job_id,phase,terminal_reason,subject_title,subject_digest,pinned_commit_sha,effective_recipe,result_digest,evidence_rung,result_counts,created_at FROM job_terminal_receipts WHERE job_id=?1",[job],|r|Ok(Receipt{receipt_id:r.get(0)?,job_id:r.get(1)?,phase:parsed(r,2)?,terminal_reason:parsed(r,3)?,subject_title:optional(r,4)?,subject_digest:r.get(5)?,pinned_commit_sha:r.get(6)?,effective_recipe:parsed(r,7)?,result_digest:r.get(8)?,evidence_rung:optional(r,9)?,result_counts:optional(r,10)?,created_at:r.get(11)?})).optional()?)
}
/// Receipt-only authentication, independent of rebuildable campaign state.
/// `digest` must be computed from the validated terminal payload by the server.
/// Finalizers retain `jobs.worker_id` with the receipt in the same transaction.
pub fn replay_terminal(
	tx: &Transaction<'_>, identity: crate::jobs::LeaseIdentity<'_>, phase: JobKind,
	digest: &[u8; 32],
) -> Result<Replayed> {
	if identity.capability_hash.len() != 32
		|| !matches!(phase, JobKind::Survey | JobKind::Drilldown | JobKind::Verify)
	{
		return Ok(Replayed::Reject(Reject::Denied));
	}
	let bound: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM jobs j JOIN workers w ON w.id=j.worker_id
		 JOIN job_terminal_receipts r ON r.job_id=j.id
		 WHERE j.id=?1 AND j.worker_id=?2 AND w.kind='worker' AND w.revoked_at IS NULL
		 AND j.kind=?3 AND j.campaign_id IS NOT NULL
		 AND r.phase=?3 AND r.finishing_capability_hash=?4
		 AND j.state IN ('succeeded','failed','cancelled'))",
		params![identity.job_id, identity.worker_id, phase.as_str(), identity.capability_hash],
		|row| row.get(0),
	)?;
	if !bound {
		return Ok(Replayed::Reject(Reject::Denied));
	}
	let job = identity.job_id;
	let Some(receipt) = get(tx, job)? else {
		return Ok(Replayed::Reject(Reject::Denied));
	};
	if receipt.result_digest != digest {
		return Ok(Replayed::Reject(Reject::WrongDigest));
	}
	Ok(Replayed::Receipt(Box::new(receipt)))
}
standalone! {insert(new:&NewReceipt<'_>,now:i64)->i64;}
