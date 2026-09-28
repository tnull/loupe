//! GitHub issue reporter — hand-rolled `reqwest` POST to
//! `/repos/{owner}/{repo}/issues`. Deliberately not using `octocrab` to
//! keep the dependency tree minimal; the integration we need is small
//! enough to maintain ourselves.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use loupe_core::{Finding, ReportingDestination, Severity};
use loupe_storage::repos::RepoRow;
use reqwest::{StatusCode, Url};
use serde::Serialize;

use super::{DispatchReceipt, ReportFinding, Reporter};

const DEFAULT_API_BASE: &str = "https://api.github.com";
const MAX_TITLE_CHARS: usize = 100;

pub struct GithubReporter {
	http: reqwest::Client,
	api_base: Url,
}

impl GithubReporter {
	/// Build the default reporter that talks to api.github.com.
	pub fn new() -> Result<Self> {
		Self::with_base(DEFAULT_API_BASE)
	}

	/// Build a reporter pointed at a custom API root. Used by the
	/// integration tests' fake-github stub.
	pub fn with_base(base: &str) -> Result<Self> {
		let api_base = base.parse::<Url>().context("parsing GithubReporter API base URL")?;
		let http = reqwest::Client::builder()
			.user_agent("loupe-server/0.0.0")
			.use_rustls_tls()
			.build()
			.context("building GithubReporter http client")?;
		Ok(Self { http, api_base })
	}
}

#[derive(Serialize)]
struct CreateIssueBody<'a> {
	title: &'a str,
	body: String,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	labels: Vec<String>,
}

#[derive(Serialize)]
struct CreateLabelBody<'a> {
	name: &'a str,
	color: &'a str,
	description: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LabelSpec {
	name: &'static str,
	color: &'static str,
	description: &'static str,
}

#[async_trait]
impl Reporter for GithubReporter {
	fn kind(&self) -> &'static str {
		"github_issue"
	}

	async fn dispatch(
		&self, repo: &RepoRow, findings: &[ReportFinding], pat: &str,
	) -> Result<DispatchReceipt> {
		let (target_owner, target_repo) = match &repo.reporting {
			ReportingDestination::GithubIssue { target_owner, target_repo, .. } => {
				(target_owner.as_str(), target_repo.as_str())
			},
			_ => anyhow::bail!("GithubReporter dispatched against a non-github destination"),
		};
		if findings.is_empty() {
			return Ok(DispatchReceipt { kind: self.kind(), external_id: None });
		}

		let mut external_ids = Vec::new();
		for report_finding in findings {
			let finding = &report_finding.finding;
			let severity = severity_label(finding.severity);
			self.ensure_label(target_owner, target_repo, pat, severity).await?;
			let title = render_title(finding);
			let body = render_body(repo, report_finding);
			let labels = vec!["loupe".to_owned(), severity.name.to_owned()];

			let resp = self
				.http
				.post(
					self.api_base
						.join(&format!("/repos/{target_owner}/{target_repo}/issues"))
						.map_err(|e| anyhow!("building issues URL: {e}"))?,
				)
				.bearer_auth(pat)
				.header("Accept", "application/vnd.github+json")
				.header("X-GitHub-Api-Version", "2022-11-28")
				.json(&CreateIssueBody { title: &title, body, labels })
				.send()
				.await
				.context("posting github issue")?;
			let status = resp.status();
			if !status.is_success() {
				let body = resp.text().await.unwrap_or_default();
				anyhow::bail!("github returned {} when opening issue: {}", status, body);
			}
			let json: serde_json::Value = resp.json().await.context("parsing issue response")?;
			if let Some(external_id) =
				json.get("number").and_then(|v| v.as_i64()).map(|n| n.to_string())
			{
				external_ids.push(external_id);
			}
		}
		let external_id = (!external_ids.is_empty()).then(|| external_ids.as_slice().join(","));
		Ok(DispatchReceipt { kind: self.kind(), external_id })
	}
}

impl GithubReporter {
	async fn ensure_label(
		&self, target_owner: &str, target_repo: &str, pat: &str, label: LabelSpec,
	) -> Result<()> {
		let url = self
			.api_base
			.join(&format!("/repos/{target_owner}/{target_repo}/labels"))
			.map_err(|e| anyhow!("building labels URL: {e}"))?;
		let resp = self
			.http
			.post(url)
			.bearer_auth(pat)
			.header("Accept", "application/vnd.github+json")
			.header("X-GitHub-Api-Version", "2022-11-28")
			.json(&CreateLabelBody {
				name: label.name,
				color: label.color,
				description: label.description,
			})
			.send()
			.await
			.with_context(|| format!("creating github label {}", label.name))?;
		let status = resp.status();
		if status.is_success() {
			return Ok(());
		}
		let body = resp.text().await.unwrap_or_default();
		if status == StatusCode::UNPROCESSABLE_ENTITY && body.contains("already_exists") {
			return Ok(());
		}
		anyhow::bail!("github returned {} when creating label {}: {}", status, label.name, body);
	}
}

fn severity_label(severity: Severity) -> LabelSpec {
	match severity {
		Severity::Info => LabelSpec {
			name: "severity:info",
			color: "cfd3d7",
			description: "Loupe severity: info",
		},
		Severity::Low => {
			LabelSpec { name: "severity:low", color: "fef2c0", description: "Loupe severity: low" }
		},
		Severity::Medium => LabelSpec {
			name: "severity:medium",
			color: "fbca04",
			description: "Loupe severity: medium",
		},
		Severity::High => LabelSpec {
			name: "severity:high",
			color: "d93f0b",
			description: "Loupe severity: high",
		},
		Severity::Critical => LabelSpec {
			name: "severity:critical",
			color: "b60205",
			description: "Loupe severity: critical",
		},
	}
}

fn render_title(finding: &Finding) -> String {
	compact_title(&finding.title)
}

fn compact_title(raw: &str) -> String {
	let mut compact = String::new();
	for word in raw.split_whitespace() {
		if !compact.is_empty() {
			compact.push(' ');
		}
		compact.push_str(word);
	}
	if compact.is_empty() {
		compact.push_str("Untitled finding");
	}
	if compact.chars().count() <= MAX_TITLE_CHARS {
		return compact;
	}

	let mut truncated: String = compact.chars().take(MAX_TITLE_CHARS - 3).collect();
	while truncated.ends_with(char::is_whitespace) {
		truncated.pop();
	}
	truncated.push_str("...");
	truncated
}

fn render_body(repo: &RepoRow, report_finding: &ReportFinding) -> String {
	if report_finding.phase_review {
		return render_phase_body(repo, report_finding);
	}
	let finding = &report_finding.finding;
	let mut out = String::new();
	out.push_str("## Finding\n\n");
	out.push_str(&format!("- repo: `{}/{}` (`{}`)\n", repo.owner, repo.repo, repo.clone_url));
	match &report_finding.reviewed_revision {
		Some(revision) => out.push_str(&format!("- reviewed revision: `{revision}`\n")),
		None => out.push_str("- reviewed revision: _not recorded_\n"),
	}
	out.push_str(&format!("- title: {}\n", finding.title));
	out.push_str(&format!("- severity: `{}`\n", finding.severity));
	if let Some(location) = render_location(finding) {
		out.push_str(&format!("- location: {location}\n"));
	}
	if let Some(cwe) = &finding.cwe {
		out.push_str(&format!("- cwe: {cwe}\n"));
	}
	out.push_str(&format!("- scanner: `{}`\n", finding.scanner_id));
	out.push_str(&format!("- fingerprint: `{}`\n\n", finding.fingerprint));

	out.push_str("## Description\n\n");
	out.push_str(&finding.description);
	out.push_str("\n\n");

	if let Some(poc) = &finding.poc_unified {
		out.push_str("## Proof of Concept\n\n```diff\n");
		out.push_str(poc);
		out.push_str("\n```\n\n");
	}

	if let Some(patch) = &finding.patch_unified {
		out.push_str("## Suggested Fix\n\n```diff\n");
		out.push_str(patch);
		out.push_str("\n```\n\n");
	}

	out.push_str(
		"_This finding was discovered by [Project Loupe](https://github.com/project-loupe/loupe)._\n",
	);

	out
}

fn render_location(finding: &Finding) -> Option<String> {
	Some(format!("`{}`", super::finding_location(finding)?))
}

/// The delimiter exceeds every backtick run in the value, including runs
/// on otherwise valid fence-closing lines. The language is trusted template text.
fn literal_block(value: &str, language: &str) -> String {
	let fence = "`".repeat(backtick_run(value).saturating_add(1).max(3));
	let newline = if value.ends_with('\n') { "" } else { "\n" };
	format!("{fence}{language}\n{value}{newline}{fence}\n")
}

fn backtick_run(value: &str) -> usize {
	value.as_bytes().split(|byte| *byte != b'`').map(<[u8]>::len).max().unwrap_or(0)
}

fn literal_inline(value: &str) -> Option<String> {
	// Code spans normalize line endings and boundary spaces. Use a block
	// whenever an inline representation would lose that literal content.
	if value.is_empty()
		|| value.contains(['\r', '\n', '\t'])
		|| value.starts_with(' ')
		|| value.ends_with(' ')
	{
		return None;
	}
	let delimiter = "`".repeat(backtick_run(value).saturating_add(1));
	let padding = if value.starts_with('`') || value.ends_with('`') { " " } else { "" };
	Some(format!("{delimiter}{padding}{value}{padding}{delimiter}"))
}

fn render_phase_body(repo: &RepoRow, report: &ReportFinding) -> String {
	let mut out = String::from("## Finding\n\n");
	for (label, value) in report.phase_fields(repo) {
		out.push_str(&format!("**{label}:**"));
		if let Some(inline) = literal_inline(&value) {
			out.push_str(&format!(" {inline}\n\n"));
		} else {
			out.push_str("\n\n");
			out.push_str(&literal_block(&value, ""));
			out.push('\n');
		}
	}
	for (heading, value, language) in [
		("Description", Some(&report.finding.description), ""),
		("Proof of Concept", report.finding.poc_unified.as_ref(), "diff"),
		("Suggested Fix", report.finding.patch_unified.as_ref(), "diff"),
	] {
		if let Some(value) = value {
			out.push_str(&format!("## {heading}\n\n"));
			out.push_str(&literal_block(value, language));
			out.push('\n');
		}
	}
	// Rendering existing fields does not authorize new proof/patch submissions.
	out.push_str("_This finding was discovered by [Project Loupe](https://github.com/project-loupe/loupe)._\n");
	out
}

#[cfg(test)]
mod tests {
	use loupe_core::Severity;

	use super::*;

	fn repo() -> RepoRow {
		RepoRow {
			id: 1,
			clone_url: "https://github.com/acme/widget.git".into(),
			host: "github.com".into(),
			owner: "acme".into(),
			repo: "widget".into(),
			default_branch: None,
			scan_interval_seconds: None,
			scanner_config: serde_json::Value::Null,
			reporting: ReportingDestination::GithubIssue {
				target_owner: "acme".into(),
				target_repo: "tracker".into(),
				pat_secret_id: 7,
			},
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
			scanner_id: "llm-code-review".into(),
			severity: Severity::High,
			title: "Out-of-bounds index in idx".into(),
			description: "The idx helper indexes without checking bounds.".into(),
			file_path: Some("src/lib.rs".into()),
			line_start: Some(4),
			line_end: Some(6),
			cwe: Some("CWE-129".into()),
			patch_unified: Some("--- a/src/lib.rs\n+++ b/src/lib.rs\n".into()),
			poc_unified: Some("--- a/src/lib.rs\n+++ b/src/lib.rs\n".into()),
			fingerprint: "fp".into(),
		}
	}

	#[test]
	fn title_is_per_finding_without_loupe_or_severity_prefix() {
		assert_eq!(render_title(&finding()), "Out-of-bounds index in idx");
	}

	#[test]
	fn severity_labels_are_namespaced_and_colored_by_urgency() {
		assert_eq!(
			severity_label(Severity::Info),
			LabelSpec {
				name: "severity:info",
				color: "cfd3d7",
				description: "Loupe severity: info"
			}
		);
		assert_eq!(severity_label(Severity::Low).name, "severity:low");
		assert_eq!(severity_label(Severity::Low).color, "fef2c0");
		assert_eq!(severity_label(Severity::Medium).color, "fbca04");
		assert_eq!(severity_label(Severity::High).color, "d93f0b");
		assert_eq!(severity_label(Severity::Critical).color, "b60205");
	}

	#[test]
	fn body_describes_one_finding_not_a_scan_batch() {
		let body = render_body(
			&repo(),
			&ReportFinding {
				finding: finding(),
				reviewed_revision: Some("abc123".into()),
				phase_review: false,
			},
		);
		assert!(body.starts_with("## Finding\n\n"));
		assert!(body.contains("- repo: `acme/widget` (`https://github.com/acme/widget.git`)"));
		assert!(body.contains("- reviewed revision: `abc123`"));
		assert!(body.contains("- title: Out-of-bounds index in idx"));
		assert!(body.contains("- severity: `high`"));
		assert!(body.contains("- location: `src/lib.rs:4-6`"));
		assert!(body.contains("## Proof of Concept"));
		assert!(body.contains("## Suggested Fix"));
		assert!(body.ends_with(
			"_This finding was discovered by [Project Loupe](https://github.com/project-loupe/loupe)._\n"
		));
		assert!(!body.contains("This issue tracks one loupe finding"));
		assert!(!body.contains("finished a scan"));
		assert!(!body.contains("Findings:"));
	}

	#[test]
	fn phase_report_cannot_inject_markdown_structure() {
		use pulldown_cmark::{Event, Parser, Tag};
		let hostile = "[link](https://attacker.invalid) ![image](https://attacker.invalid/i)\n\n# forged heading\n\n- forged list\n\n<script>attack()</script>\n\n```\n```diff\n";
		let mut f = finding();
		f.title = hostile.into();
		f.description = hostile.into();
		f.file_path = Some("src/` [path](https://attacker.invalid)\n# forged.rs".into());
		f.scanner_id = hostile.into();
		f.fingerprint = hostile.into();
		f.cwe = Some(hostile.into());
		f.poc_unified = Some(hostile.into());
		f.patch_unified = Some(hostile.into());
		let mut r = repo();
		r.owner = hostile.into();
		r.repo = hostile.into();
		r.clone_url = hostile.into();
		let report = ReportFinding {
			finding: f.clone(),
			reviewed_revision: Some(hostile.into()),
			phase_review: true,
		};
		let body = render_body(&r, &report);
		let mut links = Vec::new();
		let mut headings = 0;
		for event in Parser::new(&body) {
			match event {
				Event::Start(Tag::Link { dest_url, .. }) => links.push(dest_url.to_string()),
				Event::Start(Tag::Image { .. } | Tag::List(_) | Tag::BlockQuote(_))
				| Event::Rule
				| Event::Html(_)
				| Event::InlineHtml(_) => {
					panic!("phase values must remain literal, not active Markdown/HTML: {event:?}")
				},
				Event::Start(Tag::Heading { .. }) => headings += 1,
				_ => {},
			}
		}
		assert_eq!(
			links,
			["https://github.com/project-loupe/loupe"],
			"phase fields cannot create links"
		);
		assert_eq!(headings, 4, "only trusted report headings are present");
		let literals = literal_values(&body);
		for (_, value) in report.phase_fields(&r) {
			assert!(
				literals
					.iter()
					.any(|literal| literal == &value || literal == &format!("{value}\n")),
				"report must preserve literal field {value:?}"
			);
		}
		assert_eq!(
			literals.iter().filter(|value| value.as_str() == hostile).count(),
			9,
			"metadata, description and attachments all preserve their literal text"
		);
		assert_eq!(report.finding, f, "rendering must not rewrite evidence");
	}

	fn literal_values(body: &str) -> Vec<String> {
		use pulldown_cmark::{Event, Parser, Tag, TagEnd};
		let mut values = Vec::new();
		let mut block = None::<String>;
		for event in Parser::new(body) {
			match event {
				Event::Code(value) => values.push(value.into_string()),
				Event::Start(Tag::CodeBlock(_)) => block = Some(String::new()),
				Event::Text(value) if block.is_some() => block.as_mut().unwrap().push_str(&value),
				Event::End(TagEnd::CodeBlock) => values.push(block.take().unwrap()),
				_ => {},
			}
		}
		values
	}

	#[test]
	fn phase_location_and_description_preserve_delimiters_and_whitespace() {
		for path in [
			"src/lib.rs",
			"src/`one``two.rs",
			"`surrounded`",
			" leading and trailing ",
			"src/line\n# heading.rs",
			"src/tab\tfile.rs",
			"src/cafe\u{301}.rs",
		] {
			let mut f = finding();
			f.file_path = Some(path.into());
			f.description = "```\n``````\n~~~\n# literal\n".into();
			f.poc_unified = None;
			f.patch_unified = None;
			let report = ReportFinding { finding: f, reviewed_revision: None, phase_review: true };
			let body = render_body(&repo(), &report);
			let values = literal_values(&body);
			let location = format!("{path}:4-6");
			assert!(
				values.iter().any(|v| v == &location || v == &format!("{location}\n")),
				"path is literal: {path:?}"
			);
			assert!(values.contains(&report.finding.description));
			assert!(values.contains(&"Out-of-bounds index in idx".into()));
			assert!(values.contains(&"acme/widget".into()));
		}
	}

	#[test]
	fn phase_issue_title_uses_plain_compaction_not_markdown_encoding() {
		let mut f = finding();
		f.title = " [title](url)\n<img> `ticks` ".into();
		assert_eq!(render_title(&f), "[title](url) <img> `ticks`");
	}
}
