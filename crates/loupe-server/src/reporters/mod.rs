//! Reporter trait plus the built-in automatic reporting destinations.
//!
//! The dispatcher hands a freshly-completed scan's findings to whatever
//! `Reporter` matches the repo's `ReportingDestination`. Manual mode
//! short-circuits before a reporter is selected.

use std::sync::Arc;

use anyhow::Result;
use loupe_core::{Finding, ReportingDestination};
use loupe_storage::findings::FindingRow;
use loupe_storage::repos::RepoRow;
use loupe_storage::{finding_details, jobs, StoredEvidence};
use rusqlite::Connection;

pub mod email;
pub mod github;

pub use email::EmailReporter;
pub use github::GithubReporter;

/// Result of a successful dispatch — opaque receipt the caller can stamp
/// onto `findings.reported_at` (or scan_history) for audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchReceipt {
	pub kind: &'static str,
	pub external_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportFinding {
	pub finding: Finding,
	pub reviewed_revision: Option<String>,
	// Only stored review provenance selects the phase-safe presentation.
	phase_review: bool,
}

impl ReportFinding {
	pub fn from_row(conn: &Connection, row: FindingRow) -> loupe_storage::Result<Self> {
		let (phase_review, reviewed_revision) = match finding_details::get_review_evidence(
			conn, row.id,
		)? {
			StoredEvidence::Missing => {
				let job = jobs::get(conn, row.job_id)?;
				if job.as_ref().is_some_and(|job| job.campaign_id.is_some()) {
					return Err(loupe_storage::Error::Conflict(
						loupe_storage::Conflict::FindingDetails,
					));
				}
				(false, job.and_then(|job| job.head_sha))
			},
			StoredEvidence::Historical => (
				true,
				Some(conn.query_row(
					"SELECT reviewed_commit_sha FROM finding_review_details WHERE finding_id=?1",
					[row.id],
					|record| record.get(0),
				)?),
			),
			StoredEvidence::Recorded(evidence) => (true, Some(evidence.reviewed_commit_sha)),
		};
		Ok(Self { finding: row.into_finding(), reviewed_revision, phase_review })
	}

	/// Values, not rendered fragments. Each sink owns its literal encoding.
	fn phase_fields(&self, repo: &RepoRow) -> Vec<(&'static str, String)> {
		let finding = &self.finding;
		let mut fields = vec![
			("Repository", format!("{}/{}", repo.owner, repo.repo)),
			("Clone URL", repo.clone_url.clone()),
			(
				"Reviewed revision",
				self.reviewed_revision.clone().unwrap_or_else(|| "not recorded".into()),
			),
			("Title", finding.title.clone()),
			("Severity", finding.severity.to_string()),
		];
		if let Some(location) = finding_location(finding) {
			fields.push(("Location", location));
		}
		if let Some(cwe) = &finding.cwe {
			fields.push(("CWE", cwe.clone()));
		}
		fields.push(("Scanner", finding.scanner_id.clone()));
		fields.push(("Fingerprint", finding.fingerprint.clone()));
		fields
	}
}

fn finding_location(finding: &Finding) -> Option<String> {
	let path = finding.file_path.as_ref()?;
	let suffix = match (finding.line_start, finding.line_end) {
		(Some(start), Some(end)) if end != start => format!(":{start}-{end}"),
		(Some(start), _) => format!(":{start}"),
		_ => String::new(),
	};
	Some(format!("{path}{suffix}"))
}

#[async_trait::async_trait]
pub trait Reporter: Send + Sync {
	fn kind(&self) -> &'static str;
	async fn dispatch(
		&self, repo: &RepoRow, findings: &[ReportFinding], pat: &str,
	) -> Result<DispatchReceipt>;
}

/// Pick the right reporter for `repo.reporting`. Returns `None` for
/// `Manual` (the dispatcher short-circuits before reaching this — the
/// `None` here just keeps the API total) or for a destination this
/// build doesn't understand (forward compatibility — older builds
/// shouldn't crash on a future variant).
pub fn select(
	repo: &RepoRow, github: Arc<GithubReporter>, email: Arc<EmailReporter>,
) -> Option<Arc<dyn Reporter>> {
	match &repo.reporting {
		ReportingDestination::GithubIssue { .. } => Some(github),
		ReportingDestination::Email { .. } => Some(email),
		ReportingDestination::Manual => None,
	}
}

#[cfg(test)]
mod tests {
	use loupe_storage::secrets::MasterKey;
	use loupe_storage::{findings, Db};

	use super::*;

	#[test]
	fn reporting_provenance_comes_from_retained_details_not_agent_markers() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		db.with_conn(|conn| {
			conn.execute_batch("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at)
			 VALUES(1,'url','github.com','owner','repo','{\"kind\":\"manual\"}',0);
			 INSERT INTO jobs(id,repo_id,kind,state,head_sha,enqueued_at) VALUES(1,1,'scan','succeeded','legacy-head',0);
			 INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,created_at)
			 VALUES(1,1,1,'llm-code-review','high','title','description','review:v1:spoof',0);")?;
			let legacy = ReportFinding::from_row(conn, findings::get(conn,1)?.unwrap())?;
			assert!(!legacy.phase_review, "scanner and fingerprint do not establish provenance");
			assert_eq!(legacy.reviewed_revision.as_deref(), Some("legacy-head"));
			conn.execute_batch("INSERT INTO review_campaigns(campaign_id,repo_id,recipe,trigger,target_commit_sha,state,effective_policy,effective_policy_digest,created_at)
			 VALUES(1,1,'bootstrap','manual','base','finished','{}',zeroblob(32),0);
			 UPDATE jobs SET kind='drilldown',campaign_id=1 WHERE id=1;")?;
			assert!(ReportFinding::from_row(conn, findings::get(conn,1)?.unwrap()).is_err(), "missing phase evidence must not downgrade to legacy rendering");
			conn.execute_batch("INSERT INTO finding_review_details(finding_id,repo_id,workflow_contract_version,profile_version,reviewed_commit_sha,identity_family,identity_anchor,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,created_at)
			 VALUES(1,1,1,1,'retained-review-head','family','anchor',zeroblob(32),'{}','counter','gaps','high','L2',0);
			 UPDATE jobs SET head_sha=NULL WHERE id=1;")?;
			let phase = ReportFinding::from_row(conn, findings::get(conn,1)?.unwrap())?;
			assert!(phase.phase_review);
			assert_eq!(phase.reviewed_revision.as_deref(), Some("retained-review-head"));
			assert_eq!(phase.finding, legacy.finding, "provenance does not rewrite content");
			let evidence = loupe_core::review_payload::FindingEvidenceV1::from_json(r#"{
			 "version":1,"l2_argument":{"attacker_source":"source","control":"control","sink":"sink","reachable_path":"path","trust_boundary":"boundary"},
			 "material_locations":[{"role":"sink","file":"src/lib.rs"}],"counterevidence":"counter","assumptions_gaps":"gaps","confidence":"high"
			}"#)?;
			let identity = loupe_storage::identity::Identity {
				family: loupe_core::text::Identifier::new("family")?,
				anchor: loupe_core::text::Anchor::new("anchor")?, instance: None,
			};
			conn.execute("UPDATE finding_review_details SET evidence_payload=?1,identity_fingerprint=?2,l2_argument=NULL,counterevidence=NULL,assumptions_gaps=NULL,confidence=NULL WHERE finding_id=1",
			 rusqlite::params![String::from_utf8(evidence.canonical_bytes()?).unwrap(),identity.fingerprint().as_slice()])?;
			let modern = ReportFinding::from_row(conn, findings::get(conn,1)?.unwrap())?;
			assert!(modern.phase_review);
			assert_eq!(modern.reviewed_revision, phase.reviewed_revision);
			conn.execute_batch("UPDATE finding_review_details SET evidence_payload='broken',l2_argument=NULL,counterevidence=NULL,assumptions_gaps=NULL,confidence=NULL WHERE finding_id=1;")?;
			assert!(ReportFinding::from_row(conn, findings::get(conn,1)?.unwrap()).is_err(), "malformed modern evidence must not downgrade to legacy rendering");
			Ok(())
		}).unwrap();
	}
}
