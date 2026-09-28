//! One globally ranked view of queued and not-yet-materialized review work.
//!
//! This read-only leaf neither authorizes admission nor opens runtime gates.
//! Its caller intersects worker capabilities with runtime support, then validates
//! exact policy/digest, recipe, evidence, identity and envelope in the same
//! immediate transaction as materialization, charging and leasing. Use limit 1
//! and rerank after each durable quarantine; a returned page is not an allocation
//! plan. No source is prelimitted before the final global ordering.
//!
//! Ordinary coverage currently shares `UNIT_NEEDS_WORK`'s historical-evidence
//! rules. Compatibility regeneration must join that predicate before activation.
//! Bounded maintenance with all enabled phase kinds must also validate/quarantine
//! rows independently of worker advertisements: scalar eligibility cannot prove
//! a retained payload or policy digest valid.
use loupe_core::JobKind;
use rusqlite::{named_params, Row, Transaction};

use crate::scheduler::{Band, ClaimPolicy};
use crate::{review_units, Conflict, Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
	QueuedJob,
	LeadIntent,
	FindingIntent,
	ExactSurveyBatch,
	OrdinarySurvey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
	pub source: CandidateKind,
	/// Job, lead, finding, batch or generation ID, according to `source`.
	pub id: i64,
	pub repo_id: i64,
	pub campaign_id: Option<i64>,
	pub generation_id: Option<i64>,
	pub kind: JobKind,
	pub intent_revision: Option<i64>,
	pub created_at: i64,
	pub age_seconds: i64,
	/// Stored scalar projections, not validated admission authority. Unknown
	/// bands and noninteger scores remain discoverable without decode failure.
	pub stored_band: Option<Band>,
	pub stored_score: Option<i64>,
	pub rank_band: Band,
	pub rank_score: i64,
	pub promoted: bool,
}

pub struct Request<'a> {
	pub worker_id: i64,
	pub legacy_kinds: &'a [JobKind],
	pub phase_kinds: &'a [JobKind],
	pub now: i64,
	pub policy: &'a ClaimPolicy,
	pub limit: u32,
}

fn band(value: i64) -> rusqlite::Result<Band> {
	match value {
		0 => Ok(Band::Urgent),
		1 => Ok(Band::High),
		2 => Ok(Band::Normal),
		3 => Ok(Band::Background),
		_ => Err(rusqlite::Error::InvalidQuery),
	}
}

fn row(row: &Row<'_>) -> rusqlite::Result<Candidate> {
	let source = match row.get::<_, i64>(0)? {
		0 => CandidateKind::QueuedJob,
		1 => CandidateKind::LeadIntent,
		2 => CandidateKind::FindingIntent,
		3 => CandidateKind::ExactSurveyBatch,
		4 => CandidateKind::OrdinarySurvey,
		_ => return Err(rusqlite::Error::InvalidQuery),
	};
	let kind = match row.get::<_, String>(5)?.as_str() {
		"scan" => JobKind::Scan,
		"survey" => JobKind::Survey,
		"drilldown" => JobKind::Drilldown,
		"verify" => JobKind::Verify,
		_ => return Err(rusqlite::Error::InvalidQuery),
	};
	Ok(Candidate {
		source,
		id: row.get(1)?,
		repo_id: row.get(2)?,
		campaign_id: row.get(3)?,
		generation_id: row.get(4)?,
		kind,
		intent_revision: row.get(6)?,
		created_at: row.get(7)?,
		age_seconds: row.get(8)?,
		stored_band: row.get::<_, Option<i64>>(9)?.map(band).transpose()?,
		stored_score: row.get(10)?,
		rank_band: band(row.get(11)?)?,
		rank_score: row.get(12)?,
		promoted: row.get(13)?,
	})
}

/// Bounded metadata only. Full payload validation belongs to the claim owner.
/// Missing readiness and known unsupported work are ineligible; malformed
/// scalar policy/recipe data remains inspectable for permanent-data quarantine.
/// Verification reservation uses the eligibility relation *before* filtering
/// by this worker's advertised kinds, never an independent queued-only query.
pub fn ranked(tx: &Transaction<'_>, req: &Request<'_>) -> Result<Vec<Candidate>> {
	let p = req.policy;
	if !(1..=256).contains(&req.limit)
		|| req.now < 0
		|| p.active_jobs_per_repo < 1
		|| p.active_jobs_total.is_some_and(|n| n < 1)
		|| p.active_surveys_per_repo < 1
		|| p.active_drilldowns_per_repo < 1
		|| p.active_verifications_per_repo < 1
		|| p.verify_reserved_slots < 0
		|| p.verify_reserved_slots >= p.active_jobs_per_repo
		|| p.verify_reserved_slots > p.active_verifications_per_repo
		|| p.urgency_burst_length < 1
		|| p.priority_aging_interval_seconds < 1
		|| !(0..=i64::MAX - 1000).contains(&p.priority_aging_cap)
	{
		return Err(Error::Conflict(Conflict::CampaignPolicy));
	}
	let sql = format!(
		r#"
WITH active AS (
 SELECT repo_id,COUNT(*) AS total,SUM(kind='survey') AS surveys,
 SUM(kind='drilldown') AS drilldowns,SUM(kind='verify') AS verifies
 FROM jobs WHERE state='leased' AND campaign_id IS NOT NULL GROUP BY repo_id
), policy_json AS (
 SELECT c.*,CASE WHEN json_valid(effective_policy) THEN effective_policy ELSE '{{}}' END AS policy
 FROM review_campaigns c
), policies AS (
 SELECT c.*,json_extract(policy,'$.version') AS version,
 CASE WHEN json_type(policy,'$.max_attempts')='integer'
 THEN json_extract(policy,'$.max_attempts') END AS max_attempts,
 CASE WHEN json_type(policy,'$.campaign_max_jobs')='integer'
 THEN json_extract(policy,'$.campaign_max_jobs') END AS job_cap,
 CASE WHEN json_type(policy,'$.campaign_urgent_reserve')='integer'
 THEN json_extract(policy,'$.campaign_urgent_reserve') END AS urgent_cap,
 CASE WHEN json_type(policy,'$.campaign_verification_reserve')='integer'
 THEN json_extract(policy,'$.campaign_verification_reserve') END AS verify_cap
 FROM policy_json c
), ordinary_units AS (
 SELECT u.generation_id,u.created_at,u.review_unit_id,
 CASE u.priority_band WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END AS band_rank,
 ROW_NUMBER() OVER(PARTITION BY u.generation_id ORDER BY
 CASE u.priority_band WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END,u.created_at,u.review_unit_id) AS position
 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id
 WHERE {needs_work}
), sources(source,id,repo_id,campaign_id,generation_id,kind,stored_band,stored_score,created_at,revision,finding_id,attempts,due_at,recipe) AS (
 SELECT 0,j.id,j.repo_id,j.campaign_id,j.generation_id,j.kind,j.scheduling_band,j.effective_priority,j.enqueued_at,NULL,j.target_finding_id,j.attempts,j.eligible_at,j.recipe
 FROM jobs j WHERE j.state='queued' AND ((j.campaign_id IS NULL AND j.kind IN('scan','verify')) OR (j.campaign_id IS NOT NULL AND j.kind IN('survey','drilldown','verify')))
 UNION ALL
 SELECT 1,i.lead_id,i.repo_id,i.admission_campaign_id,i.generation_id,'drilldown',i.accepted_band,i.accepted_score,i.created_at,i.intent_revision,NULL,0,i.not_before,NULL
 FROM lead_drilldown_intents i JOIN leads l ON l.lead_id=i.lead_id
 JOIN jobs parent ON parent.id=i.originating_job_id
 WHERE i.state='pending' AND i.block_reason IS NULL AND i.admitted_job_id IS NULL
 AND (l.status='open' OR (l.status='deferred' AND i.intent_kind='logical_continuation'))
 AND (i.intent_kind='initial_handoff' OR (i.continuation_class='source_analysis_remaining' AND parent.state IN('succeeded','failed','cancelled')))
 AND NOT EXISTS(SELECT 1 FROM jobs j WHERE j.assigned_lead_id=i.lead_id AND j.kind='drilldown' AND j.state IN('queued','leased'))
 UNION ALL
 SELECT 2,i.finding_id,i.repo_id,i.admission_campaign_id,i.generation_id,'verify',i.accepted_band,i.accepted_score,i.created_at,i.intent_revision,i.finding_id,0,i.not_before,NULL
 FROM finding_verification_intents i JOIN findings f ON f.id=i.finding_id
 JOIN jobs parent ON parent.id=i.originating_job_id
 WHERE i.state='pending' AND i.block_reason IS NULL AND i.admitted_job_id IS NULL AND f.state='validating'
 AND (i.intent_kind='initial_handoff' OR (i.continuation_class='source_analysis_remaining' AND parent.state IN('succeeded','failed','cancelled')))
 AND NOT EXISTS(SELECT 1 FROM jobs j WHERE j.target_finding_id=i.finding_id AND j.kind='verify' AND j.state IN('queued','leased'))
 UNION ALL
 SELECT 3,b.batch_id,b.repo_id,b.campaign_id,b.generation_id,'survey',b.accepted_band,b.accepted_score,b.created_at,NULL,NULL,0,b.not_before,NULL
 FROM survey_continuation_batches b JOIN jobs parent ON parent.id=b.producer_job_id
 WHERE b.state='pending' AND b.block_reason IS NULL AND b.admitted_job_id IS NULL
 AND b.continuation_class='source_analysis_remaining' AND b.not_before IS NOT NULL
 AND parent.state IN('succeeded','failed','cancelled')
 AND NOT EXISTS(SELECT 1 FROM review_unit_holds h JOIN job_assigned_review_units a ON a.review_unit_id=h.review_unit_id
 JOIN jobs j ON j.id=a.job_id WHERE h.pending_batch_id=b.batch_id AND j.state IN('queued','leased'))
 UNION ALL
 SELECT 4,g.generation_id,g.repo_id,c.campaign_id,g.generation_id,'survey',
 CASE u.band_rank WHEN 0 THEN 'urgent' WHEN 1 THEN 'high' WHEN 2 THEN 'normal' ELSE 'background' END,
 0,u.created_at,NULL,NULL,0,NULL,NULL
 FROM review_generations g JOIN review_campaigns c ON c.generation_id=g.generation_id AND c.repo_id=g.repo_id
 JOIN ordinary_units u ON u.generation_id=g.generation_id AND u.position=1
 WHERE g.state='active'
 AND NOT EXISTS(SELECT 1 FROM jobs j WHERE j.campaign_id=c.campaign_id AND j.kind='survey' AND j.state='queued'
 AND NOT EXISTS(SELECT 1 FROM survey_continuation_batches b WHERE b.admitted_job_id=j.id))
), context AS (
 SELECT q.*,c.state AS campaign_state,c.deadline_at,c.recipe AS campaign_recipe,
 c.target_commit_sha,c.generation_id AS campaign_generation,c.version,c.max_attempts,
 c.job_cap,c.urgent_cap,c.verify_cap,s.general_spent,s.urgent_spent,s.verification_spent,
 g.state AS generation_state,g.predecessor_generation_id,g.generation_commit_sha,
 g.generated_profile IS NOT NULL AND g.generated_profile_digest IS NOT NULL AND g.profile_version>0
 AND EXISTS(SELECT 1 FROM generation_manifests m WHERE m.generation_id=g.generation_id AND m.sealed_at IS NOT NULL AND m.received_entry_count=m.expected_entry_count) AS ready,
 CASE WHEN json_valid(q.recipe) THEN json_extract(q.recipe,'$.recipe') END AS survey_recipe,
 COALESCE(a.total,0) AS active_count,COALESCE(a.surveys,0) AS surveys,
 COALESCE(a.drilldowns,0) AS drilldowns,COALESCE(a.verifies,0) AS verifies,
 COALESCE(f.last_claim_seq,0) AS last_claim_seq,COALESCE(f.burst,0) AS burst,
 CASE WHEN q.stored_band='urgent' THEN 0 WHEN q.stored_band='high' THEN 1 WHEN q.stored_band='normal' THEN 2 WHEN q.stored_band='background' THEN 3 END AS band_value,
 CASE WHEN typeof(q.stored_score)='integer' THEN q.stored_score END AS score_value
 FROM sources q LEFT JOIN policies c ON c.campaign_id=q.campaign_id
 LEFT JOIN review_generations g ON g.generation_id=q.generation_id
 LEFT JOIN campaign_admission_spending s ON s.campaign_id=q.campaign_id AND s.policy_version=2
 LEFT JOIN active a ON a.repo_id=q.repo_id LEFT JOIN scheduler_repo_state f ON f.repo_id=q.repo_id
), eligible AS (
 SELECT *,version=2 AND max_attempts>0 AND job_cap>0 AND urgent_cap>=0 AND verify_cap>=0
 AND urgent_cap<job_cap AND verify_cap<job_cap-urgent_cap
 AND general_spent IS NOT NULL AND urgent_spent IS NOT NULL AND verification_spent IS NOT NULL
 AND (kind<>'verify' OR EXISTS(SELECT 1 FROM findings f WHERE f.id=q.finding_id AND f.repo_id=q.repo_id AND f.state='validating'))
 AND (source<>0 OR CASE WHEN json_valid(recipe) THEN json_extract(recipe,'$.version')=1 AND json_extract(recipe,'$.phase')=kind ELSE 0 END)
 AS reservation_ready
 FROM context q WHERE campaign_id IS NULL OR (
 campaign_state='active' AND (deadline_at IS NULL OR deadline_at>:now) AND (due_at IS NULL OR due_at<=:now)
 AND campaign_recipe IN('bootstrap','incremental')
 AND active_count<:repo_cap AND (:global_cap IS NULL OR COALESCE((SELECT SUM(total) FROM active),0)<:global_cap)
 AND CASE kind WHEN 'survey' THEN surveys<:survey_cap WHEN 'drilldown' THEN drilldowns<:drilldown_cap WHEN 'verify' THEN verifies<:verify_cap ELSE 0 END
 AND (source<>0 OR max_attempts IS NULL OR max_attempts<=0 OR attempts<max_attempts)
 AND (source=0 OR version IS NOT 2 OR job_cap IS NULL OR urgent_cap IS NULL OR verify_cap IS NULL
 OR job_cap<=0 OR urgent_cap<0 OR verify_cap<0 OR urgent_cap>=job_cap OR verify_cap>=job_cap-urgent_cap
 OR general_spent IS NULL OR urgent_spent IS NULL OR verification_spent IS NULL
 OR general_spent>job_cap-urgent_cap-verify_cap OR urgent_spent>urgent_cap OR verification_spent>verify_cap
 OR (general_spent+urgent_spent+verification_spent<job_cap AND (
 general_spent<job_cap-urgent_cap-verify_cap OR (kind='verify' AND verification_spent<verify_cap)
 OR (stored_band='urgent' AND kind IN('verify','drilldown') AND urgent_spent<urgent_cap))))
 AND CASE
 WHEN source=0 AND kind='survey' THEN CASE
 WHEN survey_recipe IN('reconciliation','corroboration') THEN 0
 WHEN survey_recipe='bootstrap' THEN campaign_recipe='bootstrap' AND (generation_id IS NULL OR (generation_state='building' AND predecessor_generation_id IS NULL))
 WHEN survey_recipe='incremental' THEN campaign_recipe='incremental' AND (generation_id IS NULL OR (generation_state='active' AND generation_commit_sha=target_commit_sha AND ready))
 WHEN survey_recipe='coverage' THEN generation_state='active' AND generation_commit_sha=target_commit_sha AND ready
 ELSE 1 END
 WHEN kind IN('drilldown','verify') THEN ready AND generation_commit_sha=target_commit_sha
 AND (generation_state='active' OR (generation_state='building' AND predecessor_generation_id IS NULL AND campaign_recipe='bootstrap'))
 ELSE ready AND generation_state='active' AND generation_commit_sha=target_commit_sha END
 )
), ranked AS (
 SELECT q.*,
 CASE WHEN campaign_id IS NULL THEN 2 ELSE COALESCE(band_value,3) END AS rank_band,
 CASE WHEN campaign_id IS NOT NULL AND kind='survey' AND burst>=:burst_length THEN 1 ELSE 0 END AS promoted,
 CASE WHEN created_at>=:now THEN 0 WHEN created_at<0 AND :now>9223372036854775807+created_at THEN 9223372036854775807 ELSE :now-created_at END AS age_seconds,
 CASE WHEN kind='verify' AND campaign_id IS NOT NULL AND EXISTS(
 SELECT 1 FROM finding_review_details d JOIN jobs p ON p.assigned_lead_id=d.origin_lead_id AND p.kind='drilldown'
 WHERE d.finding_id=q.finding_id AND p.worker_id=:worker) THEN 1 ELSE 0 END AS anti_affinity
 FROM eligible q WHERE campaign_id IS NULL OR kind='verify' OR NOT EXISTS(
 SELECT 1 FROM eligible v WHERE v.repo_id=q.repo_id AND v.campaign_id IS NOT NULL AND v.kind='verify' AND v.reservation_ready)
 OR active_count<:repo_cap-MAX(0,:reserved-verifies)
), scored AS (
 SELECT *,CASE WHEN campaign_id IS NULL THEN CASE kind WHEN 'verify' THEN 1 ELSE 0 END
 ELSE MIN(MAX(COALESCE(score_value,0),0),1000)+MIN(age_seconds/:aging_interval,:aging_cap) END AS rank_score
 FROM ranked
)
SELECT source,id,repo_id,campaign_id,generation_id,kind,revision,created_at,age_seconds,band_value,score_value,rank_band,rank_score,promoted
FROM scored WHERE (campaign_id IS NULL AND ((kind='scan' AND :legacy_scan) OR (kind='verify' AND :legacy_verify)))
 OR (campaign_id IS NOT NULL AND ((kind='survey' AND :phase_survey) OR (kind='drilldown' AND :phase_drilldown) OR (kind='verify' AND :phase_verify)))
ORDER BY promoted DESC,CASE WHEN promoted THEN created_at ELSE 0 END,rank_band,anti_affinity,
 CASE WHEN campaign_id IS NULL THEN 0 ELSE active_count END,
 CASE WHEN campaign_id IS NULL THEN 0 ELSE last_claim_seq END,
 rank_score DESC,created_at,source,id LIMIT :limit
"#,
		needs_work = *review_units::UNIT_NEEDS_WORK
	);
	let mut statement = tx.prepare(&sql)?;
	Ok(statement.query_map(named_params! {
		":now":req.now, ":worker":req.worker_id, ":limit":req.limit,
		":repo_cap":p.active_jobs_per_repo, ":global_cap":p.active_jobs_total,
		":survey_cap":p.active_surveys_per_repo, ":drilldown_cap":p.active_drilldowns_per_repo,
		":verify_cap":p.active_verifications_per_repo, ":reserved":p.verify_reserved_slots,
		":burst_length":p.urgency_burst_length, ":aging_interval":p.priority_aging_interval_seconds,
		":aging_cap":p.priority_aging_cap,
		":legacy_scan":req.legacy_kinds.contains(&JobKind::Scan), ":legacy_verify":req.legacy_kinds.contains(&JobKind::Verify),
		":phase_survey":req.phase_kinds.contains(&JobKind::Survey), ":phase_drilldown":req.phase_kinds.contains(&JobKind::Drilldown), ":phase_verify":req.phase_kinds.contains(&JobKind::Verify),
	},row)?.collect::<rusqlite::Result<_>>()?)
}

#[cfg(test)]
mod tests;
