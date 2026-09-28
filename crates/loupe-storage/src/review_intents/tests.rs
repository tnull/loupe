use super::*;
use crate::{review_tests, transaction, Db};

pub(crate) const SHA: &str = "0123456789012345678901234567890123456789";
pub(crate) const NORMAL: AcceptedPriority =
	AcceptedPriority { band: crate::scheduler::Band::Normal, score: 0 };
pub(crate) fn ready(db: &Db) {
	db.with_conn(|conn| {
		let profile=GeneratedProfile::new("{\"languages\":[\"rust\"]}").unwrap();
		let policy=CampaignPolicyV2::default().snapshot()?;
		conn.execute("UPDATE review_campaigns SET target_commit_sha=?1,effective_policy=?2,effective_policy_digest=?3,deadline_at=10000 WHERE campaign_id=1",params![SHA,policy.expose(),policy.digest().as_slice()])?;
		conn.execute("UPDATE review_generations SET generation_commit_sha=?1,profile_version=1,generated_profile=?2,generated_profile_digest=?3 WHERE generation_id=11",params![SHA,profile.expose(),profile.digest().as_slice()])?;
		let entry = loupe_core::inventory_manifest::ManifestEntry {
			raw_path: b"src.rs".to_vec(), git_mode: 0o100644, object_id: SHA.into(),
		};
		let mut manifest = loupe_core::inventory_manifest::ManifestHasher::new(SHA, 1).unwrap();
		manifest.push(&entry).unwrap();
		let digest = manifest.finish().unwrap();
		conn.execute("INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,received_entry_count,expected_digest,created_at,sealed_at) VALUES(11,1,101,1,1,?1,0,0)",[digest.as_slice()])?;
		conn.execute("INSERT INTO generation_inventory(generation_id,path,source_path,raw_path,blob_sha,entry_kind,git_mode,manifest_position,disposition,created_at) VALUES(11,'src.rs','src.rs',?1,?2,'tracked',33188,0,'context',0)",params![b"src.rs".as_slice(),SHA])?;
		conn.execute_batch("INSERT INTO workers(id,name,kind,cert_fingerprint,created_at) VALUES(1,'worker','worker',zeroblob(32),0);")?;
		conn.execute("UPDATE jobs SET state='leased',worker_id=1,attempts=1,lease_expires_at=10000,job_capability_hash=zeroblob(32),head_sha=?1,workflow_contract_version=1,scheduling_band='normal' WHERE id=101",[SHA])?;
		Ok(())
	}).unwrap();
}
pub(crate) fn fixture() -> Db {
	let db = review_tests::fixture();
	ready(&db);
	db
}
pub(crate) fn lead(tx: &Transaction<'_>, id: i64) -> Result<()> {
	tx.execute("INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_by_job_id,created_at) VALUES(?1,11,'family','anchor',?2,'{}',zeroblob(32),?3,101,0)",params![id,id.to_be_bytes().repeat(4),SHA])?;
	Ok(())
}
pub(crate) fn child(
	tx: &Transaction<'_>, id: i64, subject: Option<Subject>, parent: i64, logical: bool,
) -> Result<()> {
	let kind = subject.map_or(JobKind::Survey, Subject::phase);
	tx.execute("INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,head_sha,parent_job_id,continuation_of_job_id,assigned_lead_id,target_finding_id,worker_id,attempts,lease_expires_at,job_capability_hash,workflow_contract_version,scheduling_band,enqueued_at) VALUES(?1,1,?2,'leased',1,11,?3,?4,?5,?6,?7,1,1,10000,?8,1,'normal',0)",params![id,kind.as_str(),SHA,parent,logical.then_some(parent),match subject{Some(Subject::Lead(id))=>Some(id),_=>None},match subject{Some(Subject::Finding(id))=>Some(id),_=>None},id.to_be_bytes().repeat(4)])?;
	Ok(())
}
fn finding(tx: &Transaction<'_>, id: i64, lead_id: i64, job: i64) -> Result<()> {
	tx.execute("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,created_at) VALUES(?1,1,?2,'review','high','Finding','Evidence',?3,'validating',0)",params![id,job,format!("finding-{id}")])?;
	let profile = GeneratedProfile::new("{\"languages\":[\"rust\"]}").unwrap();
	tx.execute("INSERT INTO finding_review_details(finding_id,repo_id,workflow_contract_version,profile_version,profile_digest,reviewed_commit_sha,identity_family,identity_anchor,identity_fingerprint,evidence_payload,submitted_rung,origin_lead_id,created_at) VALUES(?1,1,1,1,?2,?3,'family','anchor',?4,'{}','L2',?5,0)",params![id,profile.digest().as_slice(),SHA,id.to_be_bytes().repeat(4),lead_id])?;
	tx.execute("UPDATE leads SET status='closed',disposition='promoted',promoted_finding_id=?2 WHERE lead_id=?1",params![lead_id,id])?;
	Ok(())
}

#[test]
fn subject_first_admission_precedes_checkout_but_production_does_not() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				lead(tx, 1)?;
				ensure_drilldown_intent(tx, 1, 101, NORMAL, 0)?;
				child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
				tx.execute("UPDATE jobs SET head_sha=?1 WHERE id=110", ["a".repeat(40)])?;
				assert!(
					admit_subject(tx, Subject::Lead(1), 1, 110, 1).is_err(),
					"known wrong checkout must not admit"
				);
				tx.execute("UPDATE jobs SET head_sha=NULL WHERE id=110", [])?;
				admit_subject(tx, Subject::Lead(1), 1, 110, 1)
					.expect("first subject admission must not require a completed child checkout");
				assert!(jobs::get(tx, 110)?.unwrap().head_sha.is_none());
				assert!(producer(tx, 110).is_err(), "admission is not checkout preparation");
				tx.execute("UPDATE jobs SET head_sha=?1 WHERE id=110", [SHA])?;
				assert!(producer(tx, 110).is_ok());
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn prepared_bootstrap_admits_subjects_before_survey_finalization() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				tx.execute(
					"UPDATE review_generations SET state='building' WHERE generation_id=11",
					[],
				)?;
				lead(tx, 1)?;
				ensure_drilldown_intent(tx, 1, 101, NORMAL, 0)?;
				child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
				admit_subject(tx, Subject::Lead(1), 1, 110, 1)
					.expect("prepared bootstrap lead must compete before survey finalize");
				finding(tx, 7, 1, 110)?;
				ensure_verification_intent(tx, 7, 110, NORMAL, 2)?;
				child(tx, 111, Some(Subject::Finding(7)), 110, false)?;
				admit_subject(tx, Subject::Finding(7), 1, 111, 3)
					.expect("mandatory verification may also run during prepared bootstrap");
				assert_eq!(jobs::get(tx, 101)?.unwrap().state, JobState::Leased);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn bootstrap_admission_rejects_missing_preparation_or_successor_context() {
	for mutation in [
		"UPDATE generation_manifests SET sealed_at=NULL WHERE generation_id=11",
		"UPDATE review_generations SET generated_profile=NULL,generated_profile_digest=NULL WHERE generation_id=11",
		"UPDATE review_generations SET predecessor_generation_id=12 WHERE generation_id=11",
		"UPDATE review_campaigns SET recipe='incremental' WHERE campaign_id=1",
	] {
		fixture().with_conn(|conn| transaction::immediate(conn,|tx| {
			tx.execute("UPDATE review_generations SET state='building' WHERE generation_id=11",[])?;
			lead(tx,1)?;
			ensure_drilldown_intent(tx,1,101,NORMAL,0)?;
			child(tx,110,Some(Subject::Lead(1)),101,false)?;
			tx.execute(mutation,[])?;
			assert!(admit_subject(tx,Subject::Lead(1),1,110,1).is_err(),"{mutation}");
			assert_eq!(get_subject(tx,Subject::Lead(1))?.unwrap().state,State::Pending);
			Ok(())
		})).unwrap();
	}
}

#[test]
fn repeated_observations_preserve_rank_owner_and_dependency_state() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			lead(tx, 1)?;
			let initial = ensure_drilldown_intent(tx, 1, 101, NORMAL, 10)?.unwrap();
			let urgent = AcceptedPriority { band: crate::scheduler::Band::Urgent, score: 550 };
			assert_eq!(ensure_drilldown_intent(tx, 1, 101, urgent, 11)?, Some(initial.clone()));
			child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
			let admitted = admit_subject(tx, Subject::Lead(1), 1, 110, 12)?;
			assert_eq!(ensure_drilldown_intent(tx, 1, 101, urgent, 13)?, Some(admitted));
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=110", [])?;
			let blocked = continue_subject(
				tx,
				Subject::Lead(1),
				110,
				ContinuationClass::ExternalDependency,
				14,
			)?;
			assert_eq!(blocked.state, State::Blocked);
			assert_eq!(blocked.not_before, None);
			assert_eq!(blocked.priority, NORMAL);
			assert_eq!(ensure_drilldown_intent(tx, 1, 101, urgent, 15)?, Some(blocked));
			assert_eq!(list_subjects(tx, Subject::Lead(0), 1, 0, 1)?.len(), 1);
			assert!(list_subjects(tx, Subject::Lead(0), 1, 0, 257).is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn logical_revision_tracks_finishing_producer_and_positive_frozen_backoff() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn,|tx| {
			lead(tx,1)?;
			ensure_drilldown_intent(tx,1,101,NORMAL,0)?;
			child(tx,110,Some(Subject::Lead(1)),101,false)?;
			admit_subject(tx,Subject::Lead(1),1,110,1)?;
			tx.execute("UPDATE jobs SET state='succeeded',attempts=3 WHERE id=110",[])?;
			tx.execute("UPDATE leads SET status='deferred',defer_reason='source work',retry_condition='source_analysis_remaining' WHERE lead_id=1",[])?;
			let next=continue_subject(tx,Subject::Lead(1),110,ContinuationClass::SourceAnalysisRemaining,10)?;
			assert_eq!((next.revision,next.logical_sequence,next.originating_job_id,next.admitted_job_id,next.not_before),(2,1,110,None,Some(70)));
			child(tx,111,Some(Subject::Lead(1)),110,true)?;
			assert!(admit_subject(tx,Subject::Lead(1),2,111,69).is_err());
			assert!(admit_subject(tx,Subject::Lead(1),1,111,70).is_err());
			admit_subject(tx,Subject::Lead(1),2,111,70)?;
			assert_eq!(tx.query_row("SELECT status FROM leads WHERE lead_id=1",[],|r|r.get::<_,String>(0))?,"open");
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=111",[])?;
			let next=continue_subject(tx,Subject::Lead(1),111,ContinuationClass::SourceAnalysisRemaining,80)?;
			assert_eq!((next.revision,next.logical_sequence,next.originating_job_id,next.not_before),(3,2,111,Some(200)));
			assert!(continue_subject(tx,Subject::Lead(1),110,ContinuationClass::SourceAnalysisRemaining,81).is_err());
			Ok(())
		})?;
		// A separate transaction recovers the same current revision, not the old child.
		assert_eq!(get_subject(conn,Subject::Lead(1))?.unwrap().originating_job_id,111);
		Ok(())
	}).unwrap();
}

#[test]
fn ownership_closed_subjects_and_first_live_lease_are_checked() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			lead(tx, 1)?;
			lead(tx, 2)?;
			tx.execute("UPDATE leads SET created_by_job_id=NULL WHERE lead_id=2", [])?;
			assert!(ensure_drilldown_intent(tx, 2, 101, NORMAL, 0).is_err());
			ensure_drilldown_intent(tx, 1, 101, NORMAL, 0)?;
			child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
			tx.execute(
				"UPDATE review_generations SET state='building' WHERE generation_id=11",
				[],
			)?;
			tx.execute(
				"UPDATE generation_manifests SET sealed_at=NULL WHERE generation_id=11",
				[],
			)?;
			assert!(
				admit_subject(tx, Subject::Lead(1), 1, 110, 1).is_err(),
				"bootstrap intent cannot dispatch before host preparation"
			);
			tx.execute("UPDATE generation_manifests SET sealed_at=0 WHERE generation_id=11", [])?;
			tx.execute("UPDATE review_generations SET state='active' WHERE generation_id=11", [])?;
			tx.execute("UPDATE jobs SET attempts=2 WHERE id=110", [])?;
			assert!(admit_subject(tx, Subject::Lead(1), 1, 110, 1).is_err());
			tx.execute("UPDATE jobs SET attempts=1,job_capability_hash=NULL WHERE id=110", [])?;
			assert!(admit_subject(tx, Subject::Lead(1), 1, 110, 1).is_err());
			tx.execute(
				"UPDATE jobs SET job_capability_hash=?1 WHERE id=110",
				[110_i64.to_be_bytes().repeat(4)],
			)?;
			tx.execute(
				"UPDATE leads SET status='closed',disposition='rejected' WHERE lead_id=1",
				[],
			)?;
			assert!(admit_subject(tx, Subject::Lead(1), 1, 110, 1).is_err());
			assert!(finish_subject_intent(tx, Subject::Lead(1), 101, 1).is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn canonical_verification_intent_survives_generation_purge_and_lifecycle_block() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			lead(tx, 1)?;
			child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
			finding(tx, 8, 1, 110)?;
			let initial = ensure_verification_intent(tx, 8, 110, NORMAL, 0)?.unwrap();
			assert_eq!(initial.generation_id, Some(11));
			child(tx, 111, Some(Subject::Finding(8)), 110, false)?;
			admit_subject(tx, Subject::Finding(8), 1, 111, 1)?;
			tx.execute("UPDATE jobs SET state='failed',job_capability_hash=NULL WHERE id=111", [])?;
			block_job_work(tx, 111, BlockReason::ExecutionExhausted, 2)?;
			let blocked = get_subject(tx, Subject::Finding(8))?.unwrap();
			assert_eq!(blocked.state, State::Blocked);
			assert_eq!(blocked.block_reason, Some(BlockReason::ExecutionExhausted));
			// Re-observing promotion cannot replace blocked canonical work.
			assert_eq!(ensure_verification_intent(tx, 8, 110, NORMAL, 3)?, Some(blocked));
			tx.execute("DELETE FROM review_generations WHERE generation_id=11", [])?;
			Ok(())
		})?;
		let retained = get_subject(conn, Subject::Finding(8))?.unwrap();
		assert_eq!(retained.generation_id, None);
		assert_eq!(retained.source_commit_sha, SHA);
		assert_eq!(retained.originating_job_id, 110);
		assert_eq!(retained.admitted_job_id, Some(111));
		assert!(crate::findings::get(conn, 8)?.is_some());
		Ok(())
	})
	.unwrap();
}

#[test]
fn finish_requires_matching_admitted_child_and_keeps_audit_identity() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			lead(tx, 1)?;
			ensure_drilldown_intent(tx, 1, 101, NORMAL, 0)?;
			child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
			admit_subject(tx, Subject::Lead(1), 1, 110, 1)?;
			assert!(finish_subject_intent(tx, Subject::Lead(1), 110, 2).is_err());
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=110", [])?;
			finish_subject_intent(tx, Subject::Lead(1), 110, 2)?;
			let done = get_subject(tx, Subject::Lead(1))?.unwrap();
			assert_eq!(done.state, State::Complete);
			assert_eq!(done.admitted_job_id, Some(110));
			assert!(continue_subject(
				tx,
				Subject::Lead(1),
				110,
				ContinuationClass::SourceAnalysisRemaining,
				3
			)
			.is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn lifecycle_block_does_not_decode_broken_recipe_or_policy_after_revocation() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			lead(tx, 1)?;
			ensure_drilldown_intent(tx, 1, 101, NORMAL, 0)?;
			child(tx, 110, Some(Subject::Lead(1)), 101, false)?;
			admit_subject(tx, Subject::Lead(1), 1, 110, 1)?;
			tx.execute(
				"UPDATE jobs SET state='failed',job_capability_hash=NULL,recipe='{' WHERE id=110",
				[],
			)?;
			tx.execute("UPDATE review_campaigns SET effective_policy='{' WHERE campaign_id=1", [])?;
			block_job_work(tx, 110, BlockReason::CompatibilityPolicy, 2)
				.expect("lifecycle blocking must survive malformed untrusted metadata");
			assert_eq!(
				get_subject(tx, Subject::Lead(1))?.unwrap().block_reason,
				Some(BlockReason::CompatibilityPolicy)
			);
			Ok(())
		})
	})
	.unwrap();
}
