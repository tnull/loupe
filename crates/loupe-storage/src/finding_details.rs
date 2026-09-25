//! Canonical review identity and verification-attempt provenance.
//!
//! Typed writes validate the stored producer/target relationship and any known
//! checkout/workflow metadata. Lease authority, source membership, immutable
//! profile readiness and finding-state transitions belong to the caller.
use loupe_core::review_payload::{FindingEvidenceV1, VerificationTerminalV1};
use loupe_core::text::policy::{Argument, Payload, Reason};
use loupe_core::text::{BoundedJson, BoundedText};
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::identity::Identity;
use crate::review::{classify, is_unique, parsed, standalone, string_enum};
use crate::{ownership, Conflict, Error, Ownership, Result, StoredEvidence};
string_enum!(Confidence { Low=>"low", Medium=>"medium", High=>"high" });
string_enum!(SubmittedRung { L2=>"L2", L3=>"L3" });
string_enum!(EstablishedRung { L2=>"L2", L3=>"L3", L4=>"L4" });
string_enum!(Applicability { Applicable=>"applicable", NotApplicable=>"not_applicable" });
pub struct NewReview<'a> {
	pub finding_id: i64,
	pub repo_id: i64,
	pub workflow_contract_version: i64,
	pub profile_version: i64,
	pub profile_digest: Option<&'a [u8; 32]>,
	pub reviewed_commit_sha: &'a str,
	pub identity: &'a Identity,
	pub l2_argument: &'a BoundedJson<Payload>,
	pub counterevidence: &'a BoundedText<Argument>,
	pub assumptions_gaps: &'a BoundedText<Argument>,
	pub confidence: Confidence,
	pub submitted_rung: SubmittedRung,
	pub origin_lead: Option<i64>,
}
pub struct NewAttempt<'a> {
	pub verification_id: i64,
	pub repo_id: i64,
	pub workflow_contract_version: i64,
	pub checkout_commit_sha: &'a str,
	pub established_rung: Option<EstablishedRung>,
	pub e2e_applicability: Applicability,
	pub e2e_rationale: Option<&'a BoundedText<Reason>>,
	pub blocker: Option<&'a BoundedText<Reason>>,
	pub retry_condition: Option<&'a BoundedText<Reason>>,
	pub verification_proof: Option<i64>,
	pub terminal_digest: &'a [u8; 32],
}

/// Modern evidence is stored once; historical projection fields remain NULL.
pub struct NewReviewEvidence<'a> {
	pub finding_id: i64,
	pub repo_id: i64,
	pub workflow_contract_version: i64,
	pub profile_version: i64,
	pub profile_digest: Option<&'a [u8; 32]>,
	pub reviewed_commit_sha: &'a str,
	pub identity: &'a Identity,
	pub evidence: &'a FindingEvidenceV1,
	pub origin_lead: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewEvidence {
	pub finding_id: i64,
	pub repo_id: i64,
	pub workflow_contract_version: i64,
	pub profile_version: i64,
	pub profile_digest: Option<[u8; 32]>,
	pub reviewed_commit_sha: String,
	pub identity: Identity,
	pub evidence: FindingEvidenceV1,
	pub origin_lead: Option<i64>,
	pub created_at: i64,
}

pub struct NewAttemptEvidence<'a> {
	pub verification_id: i64,
	pub repo_id: i64,
	pub workflow_contract_version: i64,
	pub checkout_commit_sha: &'a str,
	pub evidence: &'a VerificationTerminalV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptEvidence {
	pub verification_id: i64,
	pub repo_id: i64,
	pub workflow_contract_version: i64,
	pub checkout_commit_sha: String,
	pub evidence: VerificationTerminalV1,
	pub created_at: i64,
}

fn review_provenance(
	conn: &Connection, finding: i64, repo: i64, commit: &str, workflow: i64,
) -> Result<()> {
	let valid: bool = conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM findings f JOIN jobs j ON j.id=f.job_id
		 WHERE f.id=?1 AND f.repo_id=?2 AND j.repo_id=?2 AND j.kind='drilldown'
		 AND j.campaign_id IS NOT NULL AND (j.head_sha IS NULL OR j.head_sha=?3)
		 AND (j.workflow_contract_version IS NULL OR j.workflow_contract_version=?4))",
		params![finding, repo, commit, workflow],
		|r| r.get(0),
	)?;
	if !valid {
		return Err(Error::Ownership(Ownership::Finding));
	}
	Ok(())
}

fn evidence_verdict(evidence: &VerificationTerminalV1) -> &'static str {
	match evidence {
		VerificationTerminalV1::Verified { .. } => "confirmed",
		VerificationTerminalV1::Rejected { .. } => "dismissed",
		VerificationTerminalV1::Inconclusive { .. } => "inconclusive",
	}
}

fn attempt_provenance(
	conn: &Connection, verification: i64, repo: i64, commit: &str, workflow: i64,
	evidence: &VerificationTerminalV1,
) -> Result<()> {
	let valid: bool = conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM finding_verifications v
		 JOIN findings f ON f.id=v.finding_id JOIN jobs j ON j.id=v.job_id
		 WHERE v.id=?1 AND f.repo_id=?2 AND j.repo_id=?2
		 AND j.kind='verify' AND j.campaign_id IS NOT NULL AND j.target_finding_id=f.id
		 AND v.verdict=?3 AND (j.head_sha IS NULL OR j.head_sha=?4)
		 AND (j.workflow_contract_version IS NULL OR j.workflow_contract_version=?5))",
		params![verification, repo, evidence_verdict(evidence), commit, workflow],
		|r| r.get(0),
	)?;
	if !valid {
		return Err(Error::Ownership(Ownership::Verification));
	}
	Ok(())
}

/// Store a complete L2 finding argument without using generic JSON normalization.
/// This is evidence persistence, not the finding-promotion transaction.
pub fn insert_review_evidence(
	tx: &Transaction<'_>, new: &NewReviewEvidence<'_>, now: i64,
) -> Result<()> {
	let bytes = new.evidence.canonical_bytes()?;
	review_provenance(
		tx,
		new.finding_id,
		new.repo_id,
		new.reviewed_commit_sha,
		new.workflow_contract_version,
	)?;
	if let Some(lead) = new.origin_lead {
		ownership::lead_in_repo(tx, lead, new.repo_id, Ownership::FindingLead)?;
	}
	let fingerprint = new.identity.fingerprint();
	let result = tx.execute(
		"INSERT INTO finding_review_details
		(finding_id,repo_id,workflow_contract_version,profile_version,profile_digest,reviewed_commit_sha,
		 identity_family,identity_anchor,identity_instance_key,identity_fingerprint,submitted_rung,
		 origin_lead_id,evidence_payload,created_at)
		 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'L2',?11,?12,?13)",
		params![
			new.finding_id,
			new.repo_id,
			new.workflow_contract_version,
			new.profile_version,
			new.profile_digest.map(|d| d.as_slice()),
			new.reviewed_commit_sha,
			new.identity.family.expose(),
			new.identity.anchor.expose(),
			new.identity.instance.as_ref().map(|v| v.expose()),
			fingerprint.as_slice(),
			new.origin_lead,
			std::str::from_utf8(&bytes).expect("canonical JSON is UTF-8"),
			now
		],
	);
	review_insert_result(tx, result, new.repo_id, &fingerprint)
}

/// Store independently supplied verification evidence, deriving its digest and
/// checking the already-inserted authoritative verification row.
pub fn insert_attempt_evidence(
	tx: &Transaction<'_>, new: &NewAttemptEvidence<'_>, now: i64,
) -> Result<()> {
	let bytes = new.evidence.canonical_bytes()?;
	attempt_provenance(
		tx,
		new.verification_id,
		new.repo_id,
		new.checkout_commit_sha,
		new.workflow_contract_version,
		new.evidence,
	)?;
	tx.execute("INSERT INTO verification_attempt_details
		(verification_id,workflow_contract_version,checkout_commit_sha,terminal_digest,evidence_payload,created_at)
		VALUES (?1,?2,?3,?4,?5,?6)",
		params![new.verification_id,new.workflow_contract_version,new.checkout_commit_sha,
			loupe_core::canonical::digest(&bytes).as_slice(),std::str::from_utf8(&bytes).expect("canonical JSON is UTF-8"),now])
		.map_err(|error|classify(error,"verification_attempt_details.verification_id",Conflict::AttemptDetails))?;
	Ok(())
}

pub fn get_review_evidence(
	conn: &Connection, finding: i64,
) -> Result<StoredEvidence<ReviewEvidence>> {
	let stored = conn
		.query_row(
			"SELECT evidence_payload,l2_argument IS NOT NULL AND counterevidence IS NOT NULL
			 AND assumptions_gaps IS NOT NULL AND confidence IS NOT NULL
			 FROM finding_review_details WHERE finding_id=?1",
			[finding],
			|r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, bool>(1)?)),
		)
		.optional()?;
	let Some((raw, historical)) = stored else {
		return Ok(StoredEvidence::Missing);
	};
	let Some(raw) = raw else {
		if !historical {
			return Err(Error::Conflict(Conflict::FindingDetails));
		}
		return Ok(StoredEvidence::Historical);
	};
	let evidence = FindingEvidenceV1::from_json(&raw)?;
	if evidence.canonical_bytes()? != raw.as_bytes() {
		return Err(Error::Conflict(Conflict::FindingDetails));
	}
	let (record, digest, fingerprint, modern) = conn.query_row(
		"SELECT repo_id,workflow_contract_version,profile_version,profile_digest,reviewed_commit_sha,
		 identity_family,identity_anchor,identity_instance_key,origin_lead_id,created_at,identity_fingerprint,
		 submitted_rung='L2' AND l2_argument IS NULL AND counterevidence IS NULL AND assumptions_gaps IS NULL AND confidence IS NULL
		 FROM finding_review_details WHERE finding_id=?1",
		[finding],
		|r| {
			Ok((
				ReviewEvidence {
					finding_id: finding,
					repo_id: r.get(0)?,
					workflow_contract_version: r.get(1)?,
					profile_version: r.get(2)?,
					profile_digest: None,
					reviewed_commit_sha: r.get(4)?,
					identity: Identity {
						family: parsed(r, 5)?,
						anchor: parsed(r, 6)?,
						instance: crate::review::optional(r, 7)?,
					},
					evidence,
					origin_lead: r.get(8)?,
					created_at: r.get(9)?,
				},
				r.get::<_, Option<Vec<u8>>>(3)?,
				r.get::<_, Vec<u8>>(10)?,
				r.get::<_, bool>(11)?,
			))
		},
	)?;
	if !modern || record.identity.fingerprint().as_slice() != fingerprint {
		return Err(Error::Conflict(Conflict::FindingDetails));
	}
	let profile_digest = digest
		.map(|d| d.try_into().map_err(|_| Error::Conflict(Conflict::FindingDetails)))
		.transpose()?;
	review_provenance(
		conn,
		finding,
		record.repo_id,
		&record.reviewed_commit_sha,
		record.workflow_contract_version,
	)?;
	Ok(StoredEvidence::Recorded(ReviewEvidence { profile_digest, ..record }))
}

pub fn get_attempt_evidence(
	conn: &Connection, verification: i64,
) -> Result<StoredEvidence<AttemptEvidence>> {
	let stored = conn
		.query_row(
			"SELECT evidence_payload,e2e_applicability IS NOT NULL
			 FROM verification_attempt_details WHERE verification_id=?1",
			[verification],
			|r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, bool>(1)?)),
		)
		.optional()?;
	let Some((raw, historical)) = stored else {
		return Ok(StoredEvidence::Missing);
	};
	let Some(raw) = raw else {
		if !historical {
			return Err(Error::Conflict(Conflict::AttemptDetails));
		}
		return Ok(StoredEvidence::Historical);
	};
	let evidence = VerificationTerminalV1::from_json(&raw)?;
	let bytes = evidence.canonical_bytes()?;
	if bytes != raw.as_bytes() {
		return Err(Error::Conflict(Conflict::AttemptDetails));
	}
	let (record, digest, modern) = conn.query_row(
		"SELECT f.repo_id,d.workflow_contract_version,d.checkout_commit_sha,d.created_at,d.terminal_digest,
		 d.established_rung IS NULL AND d.e2e_applicability IS NULL AND d.e2e_rationale IS NULL
		 AND d.blocker IS NULL AND d.retry_condition IS NULL AND d.verification_proof_id IS NULL
		 FROM verification_attempt_details d JOIN finding_verifications v ON v.id=d.verification_id
		 JOIN findings f ON f.id=v.finding_id WHERE d.verification_id=?1",
		[verification],
		|r| {
			Ok((
				AttemptEvidence {
					verification_id: verification,
					repo_id: r.get(0)?,
					workflow_contract_version: r.get(1)?,
					checkout_commit_sha: r.get(2)?,
					evidence,
					created_at: r.get(3)?,
				},
				r.get::<_, Vec<u8>>(4)?,
				r.get::<_, bool>(5)?,
			))
		},
	)?;
	if !modern || loupe_core::canonical::digest(&bytes).as_slice() != digest {
		return Err(Error::Conflict(Conflict::AttemptDetails));
	}
	attempt_provenance(
		conn,
		verification,
		record.repo_id,
		&record.checkout_commit_sha,
		record.workflow_contract_version,
		&record.evidence,
	)?;
	Ok(StoredEvidence::Recorded(record))
}
pub fn insert_review_details(tx: &Transaction<'_>, new: &NewReview<'_>, now: i64) -> Result<()> {
	ownership::finding(tx, new.finding_id, new.repo_id, Ownership::Finding)?;
	if let Some(lead) = new.origin_lead {
		ownership::lead_in_repo(tx, lead, new.repo_id, Ownership::FindingLead)?;
	}
	let fingerprint = new.identity.fingerprint();
	let result=tx.execute("INSERT INTO finding_review_details (finding_id,repo_id,workflow_contract_version,profile_version,profile_digest,reviewed_commit_sha,identity_family,identity_anchor,identity_instance_key,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,origin_lead_id,created_at)
 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",params![new.finding_id,new.repo_id,new.workflow_contract_version,new.profile_version,new.profile_digest.map(|d|d.as_slice()),new.reviewed_commit_sha,new.identity.family.expose(),new.identity.anchor.expose(),new.identity.instance.as_ref().map(|v|v.expose()),fingerprint.as_slice(),new.l2_argument.expose(),new.counterevidence.expose(),new.assumptions_gaps.expose(),new.confidence.as_str(),new.submitted_rung.as_str(),new.origin_lead,now]);
	review_insert_result(tx, result, new.repo_id, &fingerprint)
}

fn review_insert_result(
	tx: &Transaction<'_>, result: rusqlite::Result<usize>, repo: i64, fingerprint: &[u8; 32],
) -> Result<()> {
	match result {
		Ok(_) => Ok(()),
		Err(error) if is_unique(&error, "finding_review_details.finding_id") => {
			Err(Error::Conflict(Conflict::FindingDetails))
		},
		Err(error)
			if is_unique(
				&error,
				"finding_review_details.repo_id, finding_review_details.identity_fingerprint",
			) =>
		{
			let existing=tx.query_row("SELECT finding_id FROM finding_review_details WHERE repo_id=?1 AND identity_fingerprint=?2",params![repo,fingerprint.as_slice()],|r|r.get(0))?;
			Err(Error::Conflict(Conflict::FindingIdentity(existing)))
		},
		Err(error) => Err(error.into()),
	}
}
pub fn insert_attempt_details(tx: &Transaction<'_>, new: &NewAttempt<'_>, now: i64) -> Result<()> {
	ownership::require(tx,"SELECT EXISTS(SELECT 1 FROM finding_verifications v JOIN findings f ON f.id=v.finding_id WHERE v.id=?1 AND f.repo_id=?2)",params![new.verification_id,new.repo_id],Ownership::Verification)?;
	if let Some(proof) = new.verification_proof {
		ownership::require(tx,"SELECT EXISTS(SELECT 1 FROM verification_proofs WHERE verification_proof_id=?1 AND verification_id=?2 AND repo_id=?3)",params![proof,new.verification_id,new.repo_id],Ownership::VerificationProof)?;
	}
	if new.e2e_applicability == Applicability::NotApplicable && new.e2e_rationale.is_none() {
		return Err(
			loupe_core::text::Error::new("e2e_rationale", loupe_core::text::Rule::Empty).into()
		);
	}
	tx.execute("INSERT INTO verification_attempt_details (verification_id,workflow_contract_version,checkout_commit_sha,established_rung,e2e_applicability,e2e_rationale,blocker,retry_condition,verification_proof_id,terminal_digest,created_at)
 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![new.verification_id,new.workflow_contract_version,new.checkout_commit_sha,new.established_rung.map(EstablishedRung::as_str),new.e2e_applicability.as_str(),new.e2e_rationale.map(BoundedText::expose),new.blocker.map(BoundedText::expose),new.retry_condition.map(BoundedText::expose),new.verification_proof,new.terminal_digest.as_slice(),now])
	.map_err(|e| classify(e, "verification_attempt_details.verification_id", Conflict::AttemptDetails))?;
	Ok(())
}
standalone! {insert_review_details(new:&NewReview<'_>,now:i64)->();insert_attempt_details(new:&NewAttempt<'_>,now:i64)->();}
