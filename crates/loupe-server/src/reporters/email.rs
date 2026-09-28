//! Email reporter that shells out to a `sendmail`-compatible binary.
//!
//! No SMTP crate by design — operators run a local mail-submission
//! agent (`postfix`, `msmtp`, `nullmailer`, ...) and we hand it an RFC
//! 5322 message via stdin. The binary is configurable at construction
//! so tests can swap in a script that captures stdin to disk.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{anyhow, bail, Context, Result};
use loupe_core::{ReportingDestination, Severity};
use loupe_storage::repos::RepoRow;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::{DispatchReceipt, ReportFinding, Reporter};

const DEFAULT_SENDMAIL_BIN: &str = "/usr/sbin/sendmail";
const DEFAULT_FROM: &str = "loupe-noreply@localhost";

pub struct EmailReporter {
	sendmail_bin: PathBuf,
	default_from: String,
}

impl EmailReporter {
	pub fn new() -> Self {
		Self::with_bin(DEFAULT_SENDMAIL_BIN)
	}

	pub fn with_bin(bin: impl Into<PathBuf>) -> Self {
		Self { sendmail_bin: bin.into(), default_from: DEFAULT_FROM.to_owned() }
	}
}

impl Default for EmailReporter {
	fn default() -> Self {
		Self::new()
	}
}

#[async_trait::async_trait]
impl Reporter for EmailReporter {
	fn kind(&self) -> &'static str {
		"email"
	}

	async fn dispatch(
		&self, repo: &RepoRow, findings: &[ReportFinding], _pat: &str,
	) -> Result<DispatchReceipt> {
		let (to, from, subject_prefix) = match &repo.reporting {
			ReportingDestination::Email { to, from, subject_prefix } => {
				(to.clone(), from.clone(), subject_prefix.clone())
			},
			_ => bail!("EmailReporter dispatched against a non-email destination"),
		};
		if to.is_empty() {
			bail!("email destination has no recipients");
		}
		if findings.is_empty() {
			return Ok(DispatchReceipt { kind: self.kind(), external_id: None });
		}

		let from = from.unwrap_or_else(|| self.default_from.clone());
		let prefix = subject_prefix.as_deref().unwrap_or("[loupe]");
		let max_sev = max_severity(findings);
		let subject = format!(
			"{prefix} {} {max_sev} finding(s) in {}/{}",
			findings.len(),
			repo.owner,
			repo.repo,
		);
		validate_header_value("From", &from)?;
		for recipient in &to {
			validate_header_value("To", recipient)?;
		}
		validate_header_value("Subject", &subject)?;
		let message = render_message(&from, &to, &subject, repo, findings);

		let mut child = Command::new(&self.sendmail_bin)
			// `-t` — read recipients from To/Cc/Bcc headers.
			// `-i` — don't treat a leading "." on a line as end-of-input.
			.args(["-t", "-i"])
			.stdin(Stdio::piped())
			.stdout(Stdio::null())
			.stderr(Stdio::piped())
			.spawn()
			.with_context(|| format!("spawning sendmail at {}", self.sendmail_bin.display()))?;
		{
			let mut stdin = child.stdin.take().ok_or_else(|| anyhow!("no stdin for sendmail"))?;
			stdin.write_all(message.as_bytes()).await.context("writing message to sendmail")?;
		}
		let output = child.wait_with_output().await.context("waiting on sendmail")?;
		if !output.status.success() {
			let stderr = String::from_utf8_lossy(&output.stderr);
			bail!("sendmail exited with {}: {stderr}", output.status);
		}
		Ok(DispatchReceipt { kind: self.kind(), external_id: None })
	}
}

fn validate_header_value(name: &str, value: &str) -> Result<()> {
	if value.bytes().any(|b| matches!(b, b'\r' | b'\n')) {
		bail!("{name} header contains a newline");
	}
	Ok(())
}

fn render_message(
	from: &str, to: &[String], subject: &str, repo: &RepoRow, findings: &[ReportFinding],
) -> String {
	let mut out = String::new();
	out.push_str(&format!("From: {from}\r\n"));
	out.push_str(&format!("To: {}\r\n", to.join(", ")));
	out.push_str(&format!("Subject: {subject}\r\n"));
	out.push_str("MIME-Version: 1.0\r\n");
	out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
	out.push_str("\r\n");

	if findings.iter().any(|finding| finding.phase_review) {
		out.push_str("loupe finding report.\n");
	} else {
		out.push_str(&format!(
			"loupe has finished a scan of {}/{} (clone url {}).\n",
			repo.owner, repo.repo, repo.clone_url
		));
	}
	out.push_str(&format!("Findings: {}\n\n", findings.len()));
	for (i, report_finding) in findings.iter().enumerate() {
		if report_finding.phase_review {
			out.push_str(&format!("Finding {}\n\n", i + 1));
			for (label, value) in report_finding.phase_fields(repo) {
				plain_field(&mut out, label, &value);
			}
			plain_field(&mut out, "Description", &report_finding.finding.description);
			continue;
		}
		let f = &report_finding.finding;
		out.push_str(&format!("{}. [{}] {}\n", i + 1, f.severity, f.title));
		match &report_finding.reviewed_revision {
			Some(revision) => out.push_str(&format!("   reviewed revision: {revision}\n")),
			None => out.push_str("   reviewed revision: not recorded\n"),
		}
		if let Some(path) = &f.file_path {
			out.push_str(&format!("   file: {path}"));
			if let Some(line) = f.line_start {
				out.push_str(&format!(":{line}"));
			}
			out.push('\n');
		}
		if let Some(cwe) = &f.cwe {
			out.push_str(&format!("   cwe:  {cwe}\n"));
		}
		out.push_str(&format!("   scanner: {}\n", f.scanner_id));
		out.push_str(&format!("   {}\n\n", f.description));
	}
	out
}

fn plain_field(out: &mut String, label: &str, value: &str) {
	out.push_str(label);
	out.push_str(":\n");
	// Prefix every physical line, including empty lines and bare-CR breaks.
	// This is plain-text field separation, not Markdown or HTML encoding.
	for line in value.split(['\n', '\r']) {
		out.push_str("| ");
		out.push_str(line);
		out.push('\n');
	}
	out.push('\n');
}

fn max_severity(findings: &[ReportFinding]) -> Severity {
	findings.iter().map(|f| f.finding.severity).max().unwrap_or(Severity::Info)
}

#[cfg(test)]
mod tests {
	use loupe_core::Finding;

	use super::*;

	fn repo_with_email(
		from: Option<String>, to: Vec<String>, subject_prefix: Option<String>,
	) -> RepoRow {
		RepoRow {
			id: 1,
			clone_url: "https://github.com/acme/widget.git".into(),
			host: "github.com".into(),
			owner: "acme".into(),
			repo: "widget".into(),
			default_branch: None,
			scan_interval_seconds: None,
			scanner_config: serde_json::Value::Null,
			reporting: ReportingDestination::Email { to, from, subject_prefix },
			verification_enabled: false,
			require_approval: None,
			last_scanned_sha: None,
			last_scanned_at: None,
			created_at: 0,
			disabled_at: None,
		}
	}

	fn finding() -> Finding {
		Finding {
			scanner_id: "test".into(),
			severity: Severity::High,
			title: "bug".into(),
			description: "description".into(),
			file_path: Some("src/lib.rs".into()),
			line_start: Some(1),
			line_end: Some(1),
			cwe: None,
			patch_unified: None,
			poc_unified: None,
			fingerprint: "fp".into(),
		}
	}

	fn report_finding() -> ReportFinding {
		ReportFinding {
			finding: finding(),
			reviewed_revision: Some("abc123".into()),
			phase_review: false,
		}
	}

	#[test]
	fn phase_email_separates_every_untrusted_line() {
		let hostile =
			"ordinary [link](url)\nscanner: forged\n\n2. [critical] forged\rscanner: forged";
		let mut f = report_finding();
		f.phase_review = true;
		f.finding.title = hostile.into();
		f.finding.description = hostile.into();
		f.finding.scanner_id = hostile.into();
		f.finding.file_path = Some(hostile.into());
		f.finding.cwe = Some(hostile.into());
		f.finding.fingerprint = hostile.into();
		f.reviewed_revision = Some(hostile.into());
		let mut repo = repo_with_email(None, vec![], None);
		repo.owner = hostile.into();
		repo.repo = hostile.into();
		repo.clone_url = hostile.into();
		let message = render_message("from", &["to".into()], "subject", &repo, &[f]);
		assert!(message.contains("Content-Type: text/plain; charset=utf-8\r\n"));
		let body = message.split_once("\r\n\r\n").unwrap().1;
		assert!(
			!body.lines().any(|line| line == "scanner: forged" || line == "2. [critical] forged"),
			"phase content must not masquerade as a report field"
		);
		assert!(
			body.contains("| ordinary [link](url)"),
			"plain text must not receive Markdown escapes"
		);
		// Eight metadata values plus description; severity is a trusted enum.
		assert_eq!(
			body.lines().filter(|line| *line == "| ordinary [link](url)").count(),
			9,
			"every phase metadata/body field is present and plain"
		);
		assert!(body.contains("Severity:\n| high\n"));
	}

	#[test]
	fn legacy_email_layout_remains_unchanged() {
		let message = render_message(
			"from",
			&["to".into()],
			"subject",
			&repo_with_email(None, vec![], None),
			&[report_finding()],
		);
		assert_eq!(message, "From: from\r\nTo: to\r\nSubject: subject\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nloupe has finished a scan of acme/widget (clone url https://github.com/acme/widget.git).\nFindings: 1\n\n1. [high] bug\n   reviewed revision: abc123\n   file: src/lib.rs:1\n   scanner: test\n   description\n\n");
	}

	#[tokio::test]
	async fn dispatch_rejects_header_injection_values() {
		let reporter = EmailReporter::with_bin("/definitely/missing/sendmail");
		let mut cases = vec![
			repo_with_email(
				Some("loupe@example.com\r\nBcc: attacker@example.com".into()),
				vec!["security@example.com".into()],
				None,
			),
			repo_with_email(
				Some("loupe@example.com".into()),
				vec!["security@example.com\nBcc: attacker@example.com".into()],
				None,
			),
			repo_with_email(
				Some("loupe@example.com".into()),
				vec!["security@example.com".into()],
				Some("[loupe]\r\nBcc: attacker@example.com".into()),
			),
		];
		let mut repo = repo_with_email(None, vec!["security@example.com".into()], None);
		repo.owner = "acme\r\nBcc: attacker@example.com".into();
		cases.push(repo);

		for repo in cases {
			for phase_review in [false, true] {
				let mut finding = report_finding();
				finding.phase_review = phase_review;
				let err = reporter.dispatch(&repo, &[finding], "").await.expect_err("must reject");
				let msg = err.to_string();
				assert!(msg.contains("header contains a newline"), "got: {msg}");
			}
		}
	}
}
