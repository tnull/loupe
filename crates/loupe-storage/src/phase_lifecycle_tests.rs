//! Regression guards for lifecycle consumers, independent of claim activation.
use loupe_core::text::BoundedText;
use rusqlite::{params, Connection};

use crate::{findings, jobs, review_intents, scheduler, transaction};

fn v1(conn: &Connection) -> crate::Result<()> {
	let policy = loupe_core::text::BoundedJson::<loupe_core::text::policy::Payload>::new(
		&serde_json::to_string(&scheduler::CampaignPolicy::default()).unwrap(),
	)?;
	conn.execute("UPDATE review_campaigns SET effective_policy=?1,effective_policy_digest=?2 WHERE campaign_id=1",params![policy.expose(),policy.digest().as_slice()])?;
	Ok(())
}
fn canonical_and_legacy(conn: &Connection) -> crate::Result<()> {
	conn.execute_batch("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,verification_required,validating_deadline,created_at) VALUES(1,1,101,'review','high','Phase','Canonical evidence','canonical','validating',1,1,0),(2,1,101,'legacy','high','Legacy','Legacy evidence','legacy','validating',1,1,0);
	INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(901,1,'scan','succeeded',0);
	UPDATE findings SET job_id=901 WHERE id=2;
	INSERT INTO finding_review_details(finding_id,repo_id,workflow_contract_version,profile_version,profile_digest,reviewed_commit_sha,identity_family,identity_anchor,identity_fingerprint,evidence_payload,submitted_rung,created_at) VALUES(1,1,1,1,zeroblob(32),'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','family','anchor',zeroblob(32),'{}','L2',0);")?;
	Ok(())
}
#[test]
fn v2_execution_retry_uses_frozen_policy_without_new_job() {
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let actual = scheduler::retry_or_fail(tx, 101, 100, &BoundedText::new("host crash")?);
			assert!(
				matches!(actual, Ok(scheduler::RetryOutcome::Requeued { eligible_at: 160 })),
				"version2 frozen retry must requeue the same logical job: {actual:?}"
			);
			assert_eq!(tx.query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get::<_, i64>(0))?, 3);
			Ok(())
		})
	})
	.unwrap();
}
#[test]
fn elapsed_campaign_deadline_never_requeues_execution_failure() {
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {
		v1(conn)?;
		conn.execute("UPDATE review_campaigns SET deadline_at=99 WHERE campaign_id=1", [])?;
		transaction::immediate(conn, |tx| {
			assert_eq!(
				scheduler::retry_or_fail(tx, 101, 100, &BoundedText::new("host crash")?)?,
				scheduler::RetryOutcome::Failed,
				"deadline-expired campaign work must fail, not requeue"
			);
			Ok(())
		})
	})
	.unwrap();
}
#[test]
fn retry_clears_attempt_preparation_with_capability_and_deadlines() {
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {v1(conn)?;conn.execute("UPDATE jobs SET prepared_attempt=1,prepared_capability_hash=zeroblob(32),prepared_at=1,hard_deadline_at=999,soft_deadline_at=900,submit_by=900 WHERE id=101",[])?;
		transaction::immediate(conn,|tx| {scheduler::retry_or_fail(tx,101,100,&BoundedText::new("host crash")?)?;Ok(())})?;
		let prepared:Option<i64>=conn.query_row("SELECT prepared_attempt FROM jobs WHERE id=101",[],|r|r.get(0))?;
		assert_eq!(prepared,None,"execution retry must revoke the prior attempt's preparation");Ok(())
	}).unwrap();
}
#[test]
fn reaper_propagates_database_failure_instead_of_quarantining_it() {
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {v1(conn)?;conn.execute("UPDATE jobs SET lease_expires_at=99 WHERE id=101",[])?;conn.execute_batch("CREATE TRIGGER fail_requeue BEFORE UPDATE OF state ON jobs WHEN NEW.state='queued' BEGIN SELECT RAISE(ABORT,'injected write failure'); END;")?;
		let actual=jobs::reap_stale_leases(conn,100);
		assert!(actual.is_err(),"unexpected write failure must propagate, never quarantine as permanent failure: {actual:?}");
		assert_eq!(conn.query_row("SELECT state FROM jobs WHERE id=101",[],|r|r.get::<_,String>(0))?,"leased");Ok(())
	}).unwrap();
}
#[test]
fn legacy_deadline_reaper_preserves_canonical_phase_findings() {
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {
		canonical_and_legacy(conn)?;
		assert_eq!(
			findings::reap_stale_validating(conn, 100)?,
			1,
			"only legacy validating findings may be dismissed by the deadline reaper"
		);
		assert_eq!(
			conn.query_row("SELECT state FROM findings WHERE id=1", [], |r| r.get::<_, String>(0))?,
			"validating"
		);
		assert_eq!(
			conn.query_row("SELECT state FROM findings WHERE id=2", [], |r| r.get::<_, String>(0))?,
			"dismissed"
		);
		Ok(())
	})
	.unwrap();
}
#[test]
fn admin_retry_cannot_reset_phase_attempt_budget_or_finding_state() {
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {canonical_and_legacy(conn)?;conn.execute("UPDATE jobs SET kind='verify',target_finding_id=1,state='failed',attempts=3 WHERE id=101",[])?;
		let actual=jobs::retry_failed(conn,101,100,200)?;
		assert!(matches!(actual,jobs::RetryOutcome::Conflict(_)),"phase work needs typed re-admission, never the legacy retry path");
		assert_eq!(conn.query_row("SELECT attempts FROM jobs WHERE id=101",[],|r|r.get::<_,i64>(0))?,3);Ok(())
	}).unwrap();
}

#[test]
fn exhausted_job_retains_hold_and_explicitly_defers_untouched_assignment() {
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {v1(conn)?;conn.execute_batch("UPDATE jobs SET attempts=3 WHERE id=101;
	INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,assignment_epoch,created_by_job_id,created_at) VALUES(1,11,'held','Held','Held work','[]',1,101,0),(2,11,'untouched','Untouched','Unfinished work','[]',1,101,0);
	INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(101,1,0,1),(101,2,1,1);
	INSERT INTO review_unit_results(review_unit_result_id,review_unit_id,produced_by_job_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at) VALUES(1,1,101,'old',1,'needs_follow_up','[]','{}',zeroblob(32),0);
	INSERT INTO review_unit_holds(review_unit_id,generation_id,producing_job_id,producing_result_id,source_assignment_epoch,continuation_class,created_at,updated_at) VALUES(1,11,101,1,1,'source_analysis_remaining',0,0);")?;
		transaction::immediate(conn,|tx| {assert_eq!(scheduler::retry_or_fail(tx,101,100,&BoundedText::new("host crash")?)?,scheduler::RetryOutcome::Failed);Ok(())})?;
		assert_eq!(conn.query_row("SELECT block_reason FROM review_unit_holds WHERE review_unit_id=1",[],|r|r.get::<_,Option<String>>(0))?,Some("execution_exhausted".into()),"exhaustion must preserve and block accepted held work");
		assert_eq!(conn.query_row("SELECT status FROM review_units WHERE review_unit_id=2",[],|r|r.get::<_,String>(0))?,"deferred");
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM review_unit_results",[],|r|r.get::<_,i64>(0))?,1,"never fabricate a result for untouched work");Ok(())
	}).unwrap();
}

#[test]
fn failed_producer_keeps_pending_handoff_but_failed_assignee_blocks_its_subject() {
	use review_intents::{BlockReason, State, Subject};
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			for id in [1, 2] {
				review_intents::tests::lead(tx, id)?;
				review_intents::ensure_drilldown_intent(
					tx,
					id,
					101,
					review_intents::tests::NORMAL,
					0,
				)?;
			}
			review_intents::tests::child(tx, 110, Some(Subject::Lead(2)), 101, false)?;
			review_intents::admit_subject(tx, Subject::Lead(2), 1, 110, 1)?;
			tx.execute("UPDATE jobs SET attempts=3 WHERE id IN(101,110)", [])?;
			assert_eq!(
				scheduler::retry_or_fail(tx, 101, 100, &BoundedText::new("producer crashed")?)?,
				scheduler::RetryOutcome::Failed
			);
			assert_eq!(
				review_intents::get_subject(tx, Subject::Lead(1))?.unwrap().state,
				State::Pending,
				"accepted handoff is independent progress, not an unfinished producer assignment"
			);
			assert_eq!(
				review_intents::get_subject(tx, Subject::Lead(2))?.unwrap().state,
				State::Admitted
			);
			assert_eq!(
				scheduler::retry_or_fail(tx, 110, 100, &BoundedText::new("assignee crashed")?)?,
				scheduler::RetryOutcome::Failed
			);
			let assigned = review_intents::get_subject(tx, Subject::Lead(2))?.unwrap();
			assert_eq!(assigned.state, State::Blocked);
			assert_eq!(assigned.block_reason, Some(BlockReason::ExecutionExhausted));
			assert_eq!(
				review_intents::get_subject(tx, Subject::Lead(1))?.unwrap().state,
				State::Pending
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn incompatible_payloads_fail_safely_and_missing_host_payloads_can_retry() {
	for mutation in [
		"UPDATE review_campaigns SET effective_policy_digest=zeroblob(32) WHERE campaign_id=1",
		"UPDATE review_campaigns SET effective_policy='malformed' WHERE campaign_id=1",
		"UPDATE review_campaigns SET effective_policy=zeroblob(8) WHERE campaign_id=1",
		"UPDATE jobs SET recipe='malformed' WHERE id=101",
		"UPDATE review_generations SET generated_profile='malformed' WHERE generation_id=11",
	] {
		let db = review_intents::tests::fixture();
		db.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				tx.execute(mutation, [])?;
				assert_eq!(
					scheduler::retry_or_fail(tx, 101, 100, &BoundedText::new("failed")?)?,
					scheduler::RetryOutcome::Failed,
					"{mutation}"
				);
				Ok(())
			})
		})
		.unwrap();
	}
	let db = review_intents::tests::fixture();
	db.with_conn(|conn|transaction::immediate(conn,|tx| {
		tx.execute("UPDATE jobs SET recipe=NULL,head_sha=NULL WHERE id=101",[])?;
		tx.execute("UPDATE review_generations SET generated_profile=NULL,generated_profile_digest=NULL WHERE generation_id=11",[])?;
		assert_eq!(scheduler::retry_or_fail(tx,101,100,&BoundedText::new("checkout failed")?)?,scheduler::RetryOutcome::Requeued{eligible_at:160});
		Ok(())
	})).unwrap();
}

#[test]
fn reaper_failure_does_not_rollback_other_jobs() {
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {
		conn.execute_batch("UPDATE jobs SET lease_expires_at=99 WHERE id=101; UPDATE jobs SET state='leased',lease_expires_at=99,attempts=1 WHERE id=102;
		INSERT INTO jobs(repo_id,kind,state,lease_expires_at,attempts,enqueued_at) VALUES(1,'scan','leased',99,3,0);
		CREATE TRIGGER fail_one_requeue BEFORE UPDATE OF state ON jobs WHEN NEW.id=101 AND NEW.state='queued' BEGIN SELECT RAISE(ABORT,'injected write failure'); END;")?;
		let legacy=conn.last_insert_rowid();
		assert!(jobs::reap_stale_leases(conn,100).is_err());
		for (job,expected) in [(101,"leased"),(102,"queued"),(legacy,"failed")] {
			assert_eq!(conn.query_row("SELECT state FROM jobs WHERE id=?1",[job],|r|r.get::<_,String>(0))?,expected);
		}
		Ok(())
	}).unwrap();
}

fn legacy_reaper_keeps_phase_finding_isolated(marker: &str) {
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {
			canonical_and_legacy(conn)?;
			match marker {
				"details"=>{conn.execute("UPDATE findings SET job_id=901 WHERE id=1",[])?;},
				"producer"=>{conn.execute("DELETE FROM finding_review_details WHERE finding_id=1",[])?;},
				"intent"=>{conn.execute_batch("DELETE FROM finding_review_details WHERE finding_id=1; UPDATE findings SET job_id=901 WHERE id=1;
				INSERT INTO finding_verification_intents(finding_id,repo_id,originating_job_id,originating_campaign_id,admission_campaign_id,source_commit_sha,profile_version,profile_digest,intent_revision,intent_kind,logical_sequence,state,accepted_band,accepted_score,priority_policy_version,created_at,updated_at) VALUES(1,1,101,1,1,'old',1,zeroblob(32),1,'initial_handoff',0,'pending','normal',0,1,0,0);")?;},
				_=>unreachable!(),
			}
			conn.execute_batch("INSERT INTO jobs(id,repo_id,kind,state,target_finding_id,attempts,worker_id,lease_expires_at,job_capability_hash,error,enqueued_at) VALUES
			(301,1,'verify','leased',1,1,1,99,NULL,'original failure',0),
			(302,1,'verify','leased',2,1,1,99,NULL,NULL,0),
			(303,1,'scan','leased',NULL,1,1,99,NULL,NULL,0),
			(305,1,'scan','leased',NULL,3,1,99,NULL,NULL,0);")?;
			for job in 301_i64..=305 {conn.execute("UPDATE jobs SET job_capability_hash=?2 WHERE id=?1",params![job,job.to_be_bytes().repeat(4)])?;}
			assert_eq!(jobs::reap_stale_leases(conn,100)?,4);
			assert_eq!(conn.query_row("SELECT state FROM jobs WHERE id=301",[],|r|r.get::<_,String>(0))?,"failed","phase marker {marker} must prevent legacy requeue");
			for (job,state) in [(302,"queued"),(303,"queued"),(305,"failed")] {
				assert_eq!(conn.query_row("SELECT state FROM jobs WHERE id=?1",[job],|r|r.get::<_,String>(0))?,state,"marker={marker},job={job}");
			}
			assert!(conn.query_row("SELECT worker_id IS NULL AND lease_expires_at IS NULL AND job_capability_hash IS NULL AND finished_at=100 FROM jobs WHERE id=301",[],|r|r.get::<_,bool>(0))?);
			assert_eq!(conn.query_row("SELECT error FROM jobs WHERE id=301",[],|r|r.get::<_,String>(0))?,"original failure");
			assert_eq!(conn.query_row("SELECT error FROM jobs WHERE id=305",[],|r|r.get::<_,String>(0))?,jobs::LEASE_EXPIRED_AFTER_MAX_ATTEMPTS_ERROR);
			assert_eq!(conn.query_row("SELECT COUNT(*) FROM findings WHERE state='validating'",[],|r|r.get::<_,i64>(0))?,2,"reaping execution must not mutate either finding");
			Ok(())
		}).unwrap();
}

#[test]
fn legacy_reaper_rejects_phase_details_target() {
	legacy_reaper_keeps_phase_finding_isolated("details");
}
#[test]
fn legacy_reaper_rejects_phase_producer_target() {
	legacy_reaper_keeps_phase_finding_isolated("producer");
}
#[test]
fn legacy_reaper_rejects_retained_phase_intent_target() {
	legacy_reaper_keeps_phase_finding_isolated("intent");
}

#[test]
fn heartbeat_rejects_overflow_or_exhausted_grace_without_mutating_expiry() {
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			for deadline in [i64::MAX, 60] {
				tx.execute("UPDATE jobs SET hard_deadline_at=?1 WHERE id=101", [deadline])?;
				assert!(crate::phase_lifecycle::heartbeat(tx, 101, 100, 200, 30).is_err());
				assert_eq!(
					tx.query_row("SELECT lease_expires_at FROM jobs WHERE id=101", [], |r| r
						.get::<_, i64>(0))?,
					10000
				);
			}
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn reaper_rechecks_expiration_after_earlier_job_transactions() {
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {
		conn.execute_batch("UPDATE jobs SET lease_expires_at=99 WHERE id=101;
		UPDATE jobs SET state='leased',lease_expires_at=99,attempts=1 WHERE id=102;
		CREATE TRIGGER renew_next_lease AFTER UPDATE OF state ON jobs WHEN NEW.id=101 AND NEW.state='queued' BEGIN UPDATE jobs SET lease_expires_at=1000 WHERE id=102; END;")?;
		assert_eq!(jobs::reap_stale_leases(conn,100)?,1,"a candidate renewed after collection must not be reaped");
		assert_eq!(conn.query_row("SELECT state FROM jobs WHERE id=102",[],|r|r.get::<_,String>(0))?,"leased");
		Ok(())
	}).unwrap();
}

#[test]
fn legacy_recovery_never_downgrades_missing_phase_details() {
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {
		canonical_and_legacy(conn)?;
		conn.execute("DELETE FROM finding_review_details WHERE finding_id=1", [])?;
		assert_eq!(
			findings::reap_stale_validating(conn, 100)?,
			1,
			"missing canonical details must fail closed, never become legacy"
		);
		assert_eq!(
			conn.query_row("SELECT state FROM findings WHERE id=1", [], |r| r.get::<_, String>(0))?,
			"validating"
		);
		assert_eq!(
			conn.query_row("SELECT state FROM findings WHERE id=2", [], |r| r.get::<_, String>(0))?,
			"dismissed"
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn legacy_job_retry_cannot_target_phase_finding_missing_details() {
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {
		canonical_and_legacy(conn)?;
		conn.execute("DELETE FROM finding_review_details WHERE finding_id=1",[])?;
		conn.execute_batch("INSERT INTO jobs(id,repo_id,kind,state,target_finding_id,attempts,enqueued_at) VALUES(301,1,'verify','failed',1,3,0);")?;
		assert!(matches!(jobs::retry_failed(conn,301,100,200)?,jobs::RetryOutcome::Conflict(_)),"a legacy row cannot revive incompatible canonical verification");
		Ok(())
	}).unwrap();
}

#[test]
fn retained_intent_alone_keeps_legacy_recovery_closed() {
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {
		canonical_and_legacy(conn)?;
		conn.execute_batch("DELETE FROM finding_review_details WHERE finding_id=1;
		UPDATE findings SET job_id=901 WHERE id=1;
		INSERT INTO finding_verification_intents(finding_id,repo_id,originating_job_id,originating_campaign_id,admission_campaign_id,source_commit_sha,profile_version,profile_digest,intent_revision,intent_kind,logical_sequence,state,accepted_band,accepted_score,priority_policy_version,created_at,updated_at) VALUES(1,1,101,1,1,'old',1,zeroblob(32),1,'initial_handoff',0,'pending','normal',0,1,0,0);
		INSERT INTO jobs(id,repo_id,kind,state,target_finding_id,attempts,enqueued_at) VALUES(301,1,'verify','failed',1,3,0);")?;
		assert_eq!(findings::reap_stale_validating(conn,100)?,1);
		assert_eq!(conn.query_row("SELECT state FROM findings WHERE id=1",[],|r|r.get::<_,String>(0))?,"validating");
		assert!(matches!(jobs::retry_failed(conn,301,100,200)?,jobs::RetryOutcome::Conflict(_)));
		Ok(())
	}).unwrap();
}
