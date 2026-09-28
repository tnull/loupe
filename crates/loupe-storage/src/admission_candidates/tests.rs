//! Selection-only fixtures do not claim public lifecycle or materialization.
use rusqlite::params;

use super::*;
use crate::admission_policy::CampaignPolicyV2;
use crate::{review_tests, transaction, Db};

const ALL: &[JobKind] = &[JobKind::Survey, JobKind::Drilldown, JobKind::Verify];
const SHA: &str = "0123456789012345678901234567890123456789";

fn fixture() -> Db {
	let db = review_tests::fixture();
	db.with_conn(|conn| {
		let policy=CampaignPolicyV2::default().snapshot()?;
		conn.execute("UPDATE review_campaigns SET effective_policy=?1,effective_policy_digest=?2,target_commit_sha=?3,deadline_at=100000",params![policy.expose(),policy.digest().as_slice(),SHA])?;
		conn.execute("UPDATE review_generations SET generation_commit_sha=?1,profile_version=1,generated_profile='{}',generated_profile_digest=zeroblob(32)",[SHA])?;
		conn.execute_batch("UPDATE jobs SET state='succeeded';
		 INSERT INTO generation_manifests(generation_id,format_version,expected_entry_count,expected_digest,created_at,sealed_at) VALUES(11,1,0,zeroblob(32),0,0),(21,1,0,zeroblob(32),0,0);
		 INSERT INTO campaign_admission_spending VALUES(1,2,1,0,0),(2,2,1,0,0);
		 INSERT INTO workers VALUES(1,'worker','worker',x'01',0,0,NULL),(2,'other','worker',x'02',0,0,NULL);")?;
		Ok(())
	}).unwrap();
	db
}
fn mutate(db: &Db, sql: &str) {
	db.with_conn(|c| {
		c.execute_batch(sql)?;
		Ok(())
	})
	.unwrap();
}

fn queued(db: &Db, id: i64, repo: i64, kind: JobKind, band: &str, score: i64, at: i64) {
	db.with_conn(|c| {
		let recipe=if kind==JobKind::Survey {r#"{"version":1,"phase":"survey","recipe":"coverage","assignment_key":"ordinary"}"#.to_owned()} else {format!(r#"{{"version":1,"phase":"{}"}}"#,kind.as_str())};
		c.execute("INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,recipe,workflow_contract_version,scheduling_band,effective_priority,enqueued_at) VALUES(?1,?2,?3,'queued',?2,?4,?5,1,?6,?7,?8)",params![id,repo,kind.as_str(),repo*10+1,recipe,band,score,at])?;
		Ok(())
	}).unwrap();
}

fn intent(db: &Db, id: i64, repo: i64, verify: bool, band: &str, score: i64, at: i64) {
	db.with_conn(|c| {
		let generation=repo*10+1; let parent=repo*100+1;
		let (table,key)=if verify {
			c.execute("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,created_at) VALUES(?1,?2,?3,'review','high','title','description',?4,'validating',0)",params![id,repo,parent,format!("f{id}")])?;
			("finding_verification_intents","finding_id")
		} else {
			c.execute("INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES(?1,?2,'family','anchor',?3,'{}',zeroblob(32),?4,0)",params![id,generation,id.to_be_bytes().repeat(4),SHA])?;
			("lead_drilldown_intents","lead_id")
		};
		c.execute(&format!("INSERT INTO {table}({key},repo_id,generation_id,originating_job_id,originating_campaign_id,admission_campaign_id,source_commit_sha,profile_version,profile_digest,intent_revision,intent_kind,logical_sequence,state,accepted_band,accepted_score,priority_policy_version,created_at,updated_at) VALUES(?1,?2,?3,?4,?2,?2,?5,1,zeroblob(32),1,'initial_handoff',0,'pending',?6,?7,1,?8,?8)"),params![id,repo,generation,parent,SHA,band,score,at])?;
		Ok(())
	}).unwrap();
}
fn unit(db: &Db, id: i64, repo: i64, band: &str, at: i64) {
	db.with_conn(|c|{c.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,priority_band,source_refs,created_at) VALUES(?1,?2,?3,'t','o',?4,'[]',?5)",params![id,repo*10+1,format!("u{id}"),band,at])?;Ok(())}).unwrap();
}
fn batch(db: &Db, id: i64, unit: i64, due: i64) {
	db.with_conn(|c|{
		c.execute("INSERT INTO survey_continuation_batches(batch_id,repo_id,generation_id,campaign_id,producer_job_id,batch_ordinal,logical_sequence,continuation_class,state,not_before,expected_unit_count,accepted_band,accepted_score,priority_policy_version,created_at) VALUES(?1,1,11,1,101,?1,1,'source_analysis_remaining','pending',?2,1,'normal',0,1,0)",params![id,due])?;
		c.execute("INSERT INTO review_unit_results(review_unit_result_id,review_unit_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,produced_by_job_id,created_at) VALUES(?1,?2,?3,1,'needs_follow_up','[]','{}',zeroblob(32),101,0)",params![id,unit,SHA])?;
		c.execute("INSERT INTO review_unit_holds(review_unit_id,generation_id,producing_job_id,producing_result_id,source_assignment_epoch,continuation_class,pending_batch_id,batch_position,created_at,updated_at) VALUES(?1,11,101,?2,0,'source_analysis_remaining',?2,0,0,0)",params![unit,id])?;Ok(())
	}).unwrap();
}
fn select(db: &Db, kinds: &[JobKind], policy: &ClaimPolicy, limit: u32) -> Vec<Candidate> {
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			ranked(
				tx,
				&Request {
					worker_id: 1,
					legacy_kinds: &[JobKind::Scan, JobKind::Verify],
					phase_kinds: kinds,
					now: 10000,
					policy,
					limit,
				},
			)
		})
	})
	.unwrap()
}

#[test]
fn urgent_pending_work_outranks_queued_and_has_no_first_arrival_cutoff() {
	let db = fixture();
	queued(&db, 300, 1, JobKind::Survey, "background", 0, 0);
	for id in 1..=100 {
		intent(&db, id, 1, false, "background", 0, id);
	}
	intent(&db, 101, 1, false, "urgent", 550, 9999);
	let rows = select(&db, ALL, &ClaimPolicy::default(), 1);
	assert_eq!((rows[0].source, rows[0].id), (CandidateKind::LeadIntent, 101));
	assert_eq!(rows[0].rank_band, Band::Urgent);
	assert_eq!(select(&db, ALL, &ClaimPolicy::default(), 256).len(), 102);
}

#[test]
fn live_caps_and_fairness_precede_score() {
	let db = fixture();
	intent(&db, 1, 1, false, "high", 550, 0);
	intent(&db, 2, 2, false, "high", 0, 1);
	mutate(&db, "UPDATE jobs SET state='leased',kind='survey' WHERE id=101;");
	assert_eq!(select(&db, ALL, &ClaimPolicy::default(), 1)[0].repo_id, 2);
	mutate(&db,"UPDATE jobs SET state='succeeded' WHERE id=101; INSERT INTO scheduler_repo_state VALUES(1,10,0),(2,1,0);");
	assert_eq!(select(&db, ALL, &ClaimPolicy::default(), 1)[0].repo_id, 2);
	let policy = ClaimPolicy { active_jobs_total: Some(1), ..ClaimPolicy::default() };
	mutate(&db, "UPDATE jobs SET state='leased',kind='survey' WHERE id=101;");
	assert!(select(&db, ALL, &policy, 1).is_empty());
	let policy = ClaimPolicy { active_drilldowns_per_repo: 1, ..ClaimPolicy::default() };
	mutate(&db,"UPDATE jobs SET kind='drilldown' WHERE id=101; UPDATE review_campaigns SET state='cancelled' WHERE campaign_id=2;");
	assert!(select(&db, ALL, &policy, 1).is_empty());
}

#[test]
fn burst_promotes_the_oldest_eligible_survey_across_sources() {
	let db = fixture();
	unit(&db, 1, 1, "background", 5);
	intent(&db, 2, 2, false, "urgent", 550, 0);
	queued(&db, 300, 2, JobKind::Survey, "urgent", 550, 10);
	mutate(&db, "INSERT INTO scheduler_repo_state VALUES(1,10,4),(2,0,4)");
	let rows = select(&db, ALL, &ClaimPolicy::default(), 3);
	assert_eq!((rows[0].source, rows[0].id), (CandidateKind::OrdinarySurvey, 11));
	assert!(rows[0].promoted && rows[1].promoted);
	assert!(!rows[2].promoted);
}

#[test]
fn aging_is_bounded_and_never_crosses_bands() {
	let db = fixture();
	intent(&db, 1, 1, false, "normal", 0, 0);
	intent(&db, 2, 1, false, "normal", 4, 9999);
	let policy = ClaimPolicy {
		priority_aging_interval_seconds: 1000,
		priority_aging_cap: 8,
		..ClaimPolicy::default()
	};
	assert_eq!(select(&db, ALL, &policy, 1)[0].id, 1);
	intent(&db, 3, 1, false, "normal", 9, 9999);
	assert_eq!(select(&db, ALL, &policy, 1)[0].id, 3);
	intent(&db, 4, 1, false, "high", 0, 9999);
	assert_eq!(select(&db, ALL, &policy, 1)[0].id, 4);
	mutate(
		&db,
		"UPDATE lead_drilldown_intents SET created_at=-9223372036854775808 WHERE lead_id=1",
	);
	let oldest = select(&db, ALL, &policy, 10).into_iter().find(|row| row.id == 1).unwrap();
	assert_eq!(oldest.age_seconds, i64::MAX);
	assert_eq!(oldest.rank_score, 8);
}

#[test]
fn verification_anti_affinity_is_soft_and_covers_pending_work() {
	let db = fixture();
	intent(&db, 1, 1, true, "normal", 550, 0);
	intent(&db, 2, 1, true, "normal", 0, 1);
	intent(&db, 10, 1, false, "background", 0, 0);
	mutate(&db,"UPDATE jobs SET kind='drilldown',worker_id=1,assigned_lead_id=10 WHERE id=101;
	 INSERT INTO finding_review_details(finding_id,repo_id,workflow_contract_version,profile_version,reviewed_commit_sha,identity_family,identity_anchor,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,origin_lead_id,created_at) VALUES(1,1,1,1,'base','f','a',zeroblob(32),'{}','counter','gaps','high','L2',10,0);");
	let rows = select(&db, &[JobKind::Verify], &ClaimPolicy::default(), 2);
	assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), vec![2, 1]);
}

#[test]
fn eligible_pending_verify_reserves_without_worker_advertisement() {
	let db = fixture();
	intent(&db, 1, 1, true, "normal", 0, 0);
	intent(&db, 2, 1, false, "urgent", 550, 0);
	mutate(&db,"UPDATE jobs SET state='leased',kind='survey' WHERE id=101; UPDATE jobs SET state='leased',kind='drilldown' WHERE id=102;");
	assert!(select(&db, &[JobKind::Drilldown], &ClaimPolicy::default(), 1).is_empty());
	assert_eq!(select(&db, ALL, &ClaimPolicy::default(), 1)[0].kind, JobKind::Verify);
	mutate(&db, "UPDATE finding_verification_intents SET not_before=10001");
	assert_eq!(select(&db, &[JobKind::Drilldown], &ClaimPolicy::default(), 1)[0].id, 2);
	mutate(&db,"UPDATE finding_verification_intents SET not_before=NULL,state='blocked',block_reason='external_dependency'");
	assert_eq!(select(&db, &[JobKind::Drilldown], &ClaimPolicy::default(), 1)[0].id, 2);
}

#[test]
fn reservation_ignores_budget_refused_and_obviously_malformed_verify() {
	let db = fixture();
	intent(&db, 1, 1, true, "normal", 0, 0);
	queued(&db, 300, 1, JobKind::Drilldown, "normal", 0, 0);
	mutate(&db,"UPDATE jobs SET state='leased',kind='survey' WHERE id=101; UPDATE jobs SET state='leased',kind='drilldown' WHERE id=102;
	 UPDATE campaign_admission_spending SET general_spent=56,verification_spent=4 WHERE campaign_id=1;");
	assert_eq!(
		select(&db, &[JobKind::Drilldown], &ClaimPolicy::default(), 1)[0].id,
		300,
		"already counted retry is not budget blocked"
	);
	mutate(&db, "UPDATE review_campaigns SET effective_policy='broken JSON' WHERE campaign_id=1");
	assert_eq!(select(&db, &[JobKind::Drilldown], &ClaimPolicy::default(), 1)[0].id, 300);
	assert!(
		select(&db, ALL, &ClaimPolicy::default(), 10)
			.iter()
			.any(|r| r.source == CandidateKind::FindingIntent),
		"malformed candidate stays available to maintenance quarantine"
	);
}

#[test]
fn queued_verify_reservation_is_due_and_scalar_valid_without_advertisement() {
	let db = fixture();
	intent(&db, 1, 1, true, "normal", 0, 0);
	queued(&db, 300, 1, JobKind::Verify, "normal", 0, 0);
	queued(&db, 301, 1, JobKind::Drilldown, "normal", 0, 0);
	mutate(&db,"UPDATE jobs SET state='leased',kind='survey' WHERE id=101; UPDATE jobs SET state='leased',kind='drilldown' WHERE id=102;
	 UPDATE jobs SET target_finding_id=1 WHERE id=300;
	 UPDATE finding_verification_intents SET state='admitted',admitted_job_id=300;");
	assert!(select(&db, &[JobKind::Drilldown], &ClaimPolicy::default(), 1).is_empty());
	for sql in [
		"UPDATE jobs SET eligible_at=10001 WHERE id=300",
		"UPDATE jobs SET eligible_at=NULL,recipe='broken JSON' WHERE id=300",
		"UPDATE jobs SET recipe='{\"version\":1,\"phase\":\"verify\"}',target_finding_id=NULL WHERE id=300",
	] {
		mutate(&db,sql);
		assert_eq!(select(&db,&[JobKind::Drilldown],&ClaimPolicy::default(),1)[0].id,301,"{sql}");
	}
}

#[test]
fn selection_is_read_only_and_rejects_unbounded_requests() {
	let db = fixture();
	intent(&db, 1, 1, false, "urgent", 550, 0);
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let before: i64 = tx.query_row("SELECT total_changes()", [], |r| r.get(0))?;
			let p = ClaimPolicy::default();
			let mut req = Request {
				worker_id: 1,
				legacy_kinds: &[],
				phase_kinds: ALL,
				now: 10000,
				policy: &p,
				limit: 1,
			};
			assert_eq!(ranked(tx, &req)?.len(), 1);
			assert_eq!(before, tx.query_row("SELECT total_changes()", [], |r| r.get::<_, i64>(0))?);
			for limit in [0, 257, u32::MAX] {
				req.limit = limit;
				assert!(ranked(tx, &req).is_err());
			}
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn exact_batches_do_not_suppress_unrelated_ordinary_coverage() {
	let db = fixture();
	unit(&db, 1, 1, "urgent", 0);
	unit(&db, 2, 1, "normal", 1);
	batch(&db, 1, 1, 10001);
	let rows = select(&db, ALL, &ClaimPolicy::default(), 10);
	assert_eq!(rows.len(), 1);
	assert_eq!(rows[0].source, CandidateKind::OrdinarySurvey);
	assert_eq!(
		rows[0].rank_band,
		Band::Normal,
		"held urgent member must not set ordinary priority"
	);
	mutate(&db, "UPDATE survey_continuation_batches SET not_before=10000");
	let rows = select(&db, ALL, &ClaimPolicy::default(), 10);
	assert_eq!(rows.len(), 2);
	assert!(rows.iter().any(|r| r.source == CandidateKind::ExactSurveyBatch));
	queued(&db, 300, 1, JobKind::Survey, "normal", 0, 0);
	mutate(&db,"UPDATE jobs SET eligible_at=10001 WHERE id=300; UPDATE survey_continuation_batches SET state='admitted',admitted_job_id=300 WHERE batch_id=1");
	let rows = select(&db, ALL, &ClaimPolicy::default(), 10);
	assert_eq!(rows.len(), 1);
	assert_eq!(rows[0].source, CandidateKind::OrdinarySurvey);
	mutate(&db, "UPDATE survey_continuation_batches SET state='complete',admitted_job_id=NULL");
	assert!(
		select(&db, ALL, &ClaimPolicy::default(), 10).is_empty(),
		"queued ordinary suppresses duplicate replenishment"
	);
}

#[test]
fn ordinary_uses_highest_band_oldest_member_and_excludes_ineligible_units() {
	let db = fixture();
	unit(&db, 1, 1, "urgent", 0);
	unit(&db, 2, 1, "high", 7);
	unit(&db, 3, 1, "high", 6);
	unit(&db, 4, 1, "normal", 1);
	mutate(&db,"UPDATE review_units SET stale=1 WHERE review_unit_id=1; UPDATE review_units SET status='deferred' WHERE review_unit_id=2;");
	let rows = select(&db, ALL, &ClaimPolicy::default(), 1);
	assert_eq!(rows[0].rank_band, Band::High);
	assert_eq!(rows[0].created_at, 6);
	mutate(&db,"UPDATE jobs SET state='leased' WHERE id=101; INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(101,3,0,0)");
	let policy = ClaimPolicy { active_surveys_per_repo: 2, ..ClaimPolicy::default() };
	assert_eq!(select(&db, ALL, &policy, 1)[0].rank_band, Band::Normal);
	mutate(&db,"INSERT INTO review_unit_results(review_unit_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at) SELECT 4,generation_commit_sha,1,'no_lead_found','[]','{}',zeroblob(32),0 FROM review_generations WHERE generation_id=11");
	assert!(select(&db, ALL, &policy, 1).is_empty());
}

#[test]
fn active_subject_uniqueness_dependencies_and_campaign_windows_filter() {
	let db = fixture();
	intent(&db, 1, 1, false, "urgent", 550, 0);
	intent(&db, 2, 1, true, "high", 300, 0);
	queued(&db, 300, 1, JobKind::Drilldown, "normal", 0, 0);
	mutate(&db, "UPDATE jobs SET assigned_lead_id=1 WHERE id=300");
	assert!(!select(&db, ALL, &ClaimPolicy::default(), 10)
		.iter()
		.any(|r| r.source == CandidateKind::LeadIntent));
	mutate(&db,"UPDATE jobs SET state='succeeded' WHERE id=300; UPDATE lead_drilldown_intents SET intent_kind='logical_continuation',logical_sequence=1,continuation_class='source_analysis_remaining'; UPDATE jobs SET state='leased' WHERE id=101;");
	assert!(!select(&db, ALL, &ClaimPolicy::default(), 10)
		.iter()
		.any(|r| r.source == CandidateKind::LeadIntent));
	mutate(&db,"UPDATE jobs SET state='succeeded' WHERE id=101; UPDATE review_campaigns SET deadline_at=10000 WHERE campaign_id=1");
	assert!(select(&db, ALL, &ClaimPolicy::default(), 10).is_empty());
}

#[test]
fn bootstrap_preparation_and_ready_child_recipe_matrix() {
	let db = fixture();
	queued(&db, 300, 1, JobKind::Survey, "normal", 0, 0);
	intent(&db, 1, 1, false, "normal", 0, 0);
	mutate(&db,"UPDATE review_generations SET state='building' WHERE generation_id=11; UPDATE jobs SET recipe='{\"version\":1,\"phase\":\"survey\",\"recipe\":\"bootstrap\",\"assignment_key\":\"ordinary\"}' WHERE id=300");
	assert_eq!(select(&db, ALL, &ClaimPolicy::default(), 10).len(), 2);
	mutate(&db, "UPDATE generation_manifests SET sealed_at=NULL WHERE generation_id=11");
	let rows = select(&db, ALL, &ClaimPolicy::default(), 10);
	assert_eq!(rows.len(), 1);
	assert_eq!(rows[0].id, 300);
	mutate(
		&db,
		"UPDATE review_generations SET predecessor_generation_id=12 WHERE generation_id=11",
	);
	assert!(select(&db, ALL, &ClaimPolicy::default(), 10).is_empty());
	mutate(&db,"UPDATE jobs SET generation_id=NULL WHERE id=300; UPDATE review_campaigns SET generation_id=NULL WHERE campaign_id=1");
	assert_eq!(select(&db, ALL, &ClaimPolicy::default(), 10)[0].id, 300);
	mutate(&db, "UPDATE review_campaigns SET recipe='reconciliation' WHERE campaign_id=1");
	assert!(select(&db, ALL, &ClaimPolicy::default(), 10).is_empty());
}

#[test]
fn budget_pools_filter_new_work_but_not_existing_jobs() {
	let db = fixture();
	intent(&db, 1, 1, false, "normal", 100, 0);
	intent(&db, 2, 1, false, "urgent", 550, 0);
	intent(&db, 3, 1, true, "normal", 100, 0);
	queued(&db, 300, 1, JobKind::Survey, "background", 0, 0);
	mutate(&db, "UPDATE campaign_admission_spending SET general_spent=56 WHERE campaign_id=1");
	let rows = select(&db, ALL, &ClaimPolicy::default(), 10);
	assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), vec![2, 3, 300]);
	mutate(&db,"UPDATE campaign_admission_spending SET urgent_spent=4,verification_spent=4 WHERE campaign_id=1");
	let rows = select(&db, ALL, &ClaimPolicy::default(), 10);
	assert_eq!(rows.len(), 1);
	assert_eq!(rows[0].id, 300);
}

#[test]
fn malformed_rank_and_payload_do_not_poison_metadata_selection() {
	let db = fixture();
	queued(&db, 300, 1, JobKind::Survey, "normal", 0, 0);
	queued(&db, 301, 2, JobKind::Survey, "normal", 0, 0);
	mutate(&db,"UPDATE jobs SET scheduling_band=NULL,effective_priority='broken',recipe='broken JSON' WHERE id=300; UPDATE review_campaigns SET effective_policy='broken JSON' WHERE campaign_id=1");
	let rows = select(&db, ALL, &ClaimPolicy::default(), 10);
	assert_eq!(rows.len(), 2);
	let bad = rows.iter().find(|r| r.id == 300).unwrap();
	assert_eq!(bad.stored_band, None);
	assert_eq!(bad.stored_score, None);
	assert_eq!(bad.rank_band, Band::Background);
	assert_eq!(rows[0].id, 301);
	mutate(&db, "UPDATE jobs SET state='failed' WHERE id=300");
	assert_eq!(
		select(&db, ALL, &ClaimPolicy::default(), 10).len(),
		1,
		"quarantine exclusion follows durable job state"
	);
}

#[test]
fn legacy_verify_first_fifo_bypasses_campaign_caps_and_unknown_kinds() {
	let db = fixture();
	mutate(&db,"UPDATE jobs SET state='leased'; INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(300,1,'scan','queued',0),(301,1,'verify','queued',2),(302,1,'verify','queued',1)");
	let policy = ClaimPolicy { active_jobs_total: Some(1), ..ClaimPolicy::default() };
	let rows = select(&db, &[], &policy, 10);
	assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), vec![302, 301, 300]);
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let req = Request {
				worker_id: 1,
				legacy_kinds: &[JobKind::Unknown("verify".into())],
				phase_kinds: ALL,
				now: 10000,
				policy: &policy,
				limit: 1,
			};
			assert!(ranked(tx, &req)?.is_empty());
			Ok(())
		})
	})
	.unwrap();
}
