//! New consumer feature tests use explicit phase kinds while public gates remain closed.
use loupe_core::review_payload::{GeneratedProfile, LeadEvidenceV1, UnitResultPayloadV1};
use loupe_storage::admission_policy::{AcceptedPriority, CampaignPolicyV2};
use loupe_storage::{admission, leads, review_intents, transaction, unit_holds, Db};
use rusqlite::params;
use serde_json::{json, Value};

use super::*;

const SHA: &str = "0123456789012345678901234567890123456789";
const NORMAL: AcceptedPriority = AcceptedPriority { band: scheduler::Band::Normal, score: 0 };

fn fixture() -> Db {
	let db = Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap();
	db.with_conn(|conn| {
  conn.execute_batch("INSERT INTO registered_repos(id,clone_url,host,owner,repo,default_branch,reporting,created_at) VALUES(1,'u','github.com','o','r','main','{\"kind\":\"manual\"}',0);
   INSERT INTO workers(id,name,kind,cert_fingerprint,created_at) VALUES(1,'worker','worker',zeroblob(32),0);
   INSERT INTO review_generations(generation_id,repo_id,generation_commit_sha,state,workflow_contract_version,created_at) VALUES(11,1,'placeholder','active',1,0);
   INSERT INTO review_campaigns(campaign_id,repo_id,recipe,trigger,target_commit_sha,generation_id,state,effective_policy,effective_policy_digest,deadline_at,created_at) VALUES(1,1,'bootstrap','manual','placeholder',11,'active','{}',zeroblob(32),10000,0);
   INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,enqueued_at,worker_id,attempts,lease_expires_at,job_capability_hash,workflow_contract_version,scheduling_band,effective_priority,recipe) VALUES(101,1,'survey','leased',1,11,0,1,1,10000,zeroblob(32),1,'normal',0,'{\"version\":1,\"phase\":\"survey\",\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}');
   INSERT INTO campaign_admission_spending(campaign_id,policy_version,general_spent) VALUES(1,2,1);
   INSERT INTO job_admission_charges(job_id,campaign_id,pool) VALUES(101,1,'general');")?;
  let policy=CampaignPolicyV2::default().snapshot()?;
  let profile=GeneratedProfile::new("{\"languages\":[\"rust\"]}")?;
  conn.execute("UPDATE review_campaigns SET target_commit_sha=?1,effective_policy=?2,effective_policy_digest=?3",params![SHA,policy.expose(),policy.digest().as_slice()])?;
  conn.execute("UPDATE review_generations SET generation_commit_sha=?1,profile_version=1,generated_profile=?2,generated_profile_digest=?3",params![SHA,profile.expose(),profile.digest().as_slice()])?;
  conn.execute("UPDATE jobs SET head_sha=?1",[SHA])?;
  conn.execute("INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,received_entry_count,expected_digest,created_at,sealed_at) VALUES(11,1,101,1,1,zeroblob(32),0,0)",[])?;
  conn.execute("INSERT INTO generation_inventory(generation_id,path,source_path,raw_path,blob_sha,entry_kind,git_mode,manifest_position,disposition,created_at) VALUES(11,'src.rs','src.rs',?1,?2,'tracked',33188,0,'context',0)",params![b"src.rs".as_slice(),SHA])?;
  Ok(())
 }).unwrap();
	db
}
fn scalar(tx: &Transaction<'_>, sql: &str) -> i64 {
	tx.query_row(sql, [], |r| r.get(0)).unwrap()
}
fn claim(tx: &Transaction<'_>, kinds: &[JobKind], limit: usize) -> Result<Option<Value>> {
	let policy = scheduler::ClaimPolicy::default();
	let req = candidates::Request {
		worker_id: 1,
		legacy_kinds: &[JobKind::Scan, JobKind::Verify],
		phase_kinds: kinds,
		now: 100,
		policy: &policy,
		limit: 1,
	};
	let (capability, hash) = crate::job_capability::issue();
	let mut repairs_left = MAX_REPAIRS;
	Ok(claim_in_transaction(tx, &req, &capability, &hash, limit, &mut repairs_left)?
		.map(|bytes| serde_json::from_slice(&bytes).unwrap()))
}
fn unit(tx: &Transaction<'_>, id: i64) -> Result<()> {
	tx.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,priority_band,created_by_job_id,created_at) VALUES(?1,11,?2,'boundary','inspect boundary','[{\"path\":\"src.rs\"}]','normal',101,0)",params![id,format!("unit-{id}")])?;
	Ok(())
}
fn lead(tx: &Transaction<'_>, anchor: &str) -> Result<i64> {
	let payload=LeadEvidenceV1::from_json(&json!({"format":"loupe.lead_evidence","version":1,"identity_family":"auth-bypass","identity_anchor":anchor,"review_unit_id":null,"assignment_epoch":null,"hypothesis":"wrapper bypass","invariant_or_boundary":"authentication","source_refs":[{"path":"src.rs"}],"next_proof_step":"trace wrapper","counterevidence":"guard exists","proof_gaps":"entry uncertain"}).to_string())?;
	let leads::Submitted::Created(id) = leads::submit_evidence(
		tx,
		&leads::NewLeadEvidence {
			generation_id: 11,
			created_by_job: 101,
			commit_sha: SHA,
			priority: loupe_storage::review_units::Priority::Normal,
			payload: &payload,
		},
		0,
	)?
	else {
		panic!("new lead")
	};
	review_intents::ensure_drilldown_intent(tx, id, 101, NORMAL, 0)?;
	Ok(id)
}
fn exact(tx: &Transaction<'_>) -> Result<i64> {
	unit(tx, 1)?;
	let payload=UnitResultPayloadV1::from_json(&json!({"format":"loupe.unit_result","version":1,"review_unit_id":1,"assignment_epoch":0,"disposition":"needs_follow_up","inspected_refs":[{"path":"src.rs"}],"created_lead_ids":[],"counterevidence":"guard exists","proof_gaps":"caller","follow_up":"inspect caller","continuation":"source_analysis_remaining"}).to_string())?;
	let result = loupe_storage::review_unit_results::insert_evidence(
		tx,
		&loupe_storage::review_unit_results::NewResultEvidence {
			generation_id: 11,
			produced_by_job: 101,
			commit_sha: SHA,
			profile_version: 1,
			payload: &payload,
		},
		0,
	)?;
	unit_holds::record_follow_up(
		tx,
		1,
		result,
		101,
		0,
		loupe_core::review_payload::ContinuationClass::SourceAnalysisRemaining,
		0,
	)?;
	tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
	Ok(unit_holds::freeze_survey_batches(tx, 101, 0)?.remove(0).batch_id)
}

#[test]
fn ordinary_delivery_and_retry_keep_snapshot_and_charge() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				unit(tx, 1)?;
				tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
				let first = claim(tx, &[JobKind::Survey], LEASE_BYTES)?.unwrap();
				let id = first["job_id"].as_i64().unwrap();
				assert_eq!(first["payload"]["kind"], "review_survey");
				assert!(first["github_pat"].is_null());
				assert_eq!(
					scalar(tx, "SELECT assignment_epoch FROM review_units WHERE review_unit_id=1"),
					1
				);
				let before = admission::get_spending(tx, 1)?.unwrap();
				tx.execute("UPDATE jobs SET state='queued' WHERE id=?1", [id])?;
				unit(tx, 2)?;
				let retry = claim(tx, &[JobKind::Survey], LEASE_BYTES)?.unwrap();
				assert_eq!(retry["job_id"], id);
				assert_eq!(
					scalar(tx, "SELECT assignment_epoch FROM review_units WHERE review_unit_id=2"),
					0
				);
				assert_eq!(admission::get_spending(tx, 1)?.unwrap(), before);
				assert_eq!(jobs::get(tx, id)?.unwrap().attempts, 2);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn localized_bad_unit_rolls_back_then_admits_healthy_member() {
	fixture().with_conn(|conn|transaction::immediate(conn,|tx| {
  unit(tx,1)?;unit(tx,2)?;
  tx.execute("UPDATE review_units SET closure_criteria=?1 WHERE review_unit_id=1",["x".repeat(8193)])?;
  tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101",[])?;
  let result=claim(tx,&[JobKind::Survey],LEASE_BYTES)?.expect("healthy ordinary unit survives");
  let id=result["job_id"].as_i64().unwrap();
  assert_eq!(scalar(tx,"SELECT assignment_epoch FROM review_units WHERE review_unit_id=1"),0);
  assert_eq!(scalar(tx,"SELECT COUNT(*) FROM review_units WHERE review_unit_id=1 AND status='deferred'"),1);
  assert_eq!(scalar(tx,"SELECT COUNT(*) FROM jobs"),2);
  assert_eq!(scalar(tx,"SELECT COUNT(*) FROM job_admission_charges"),2);
  assert_eq!(scalar(tx,"SELECT seq FROM scheduler_clock"),1);
  assert_eq!(scalar(tx,"SELECT review_unit_id FROM job_assigned_review_units"),2);
  assert_eq!(jobs::get(tx,id)?.unwrap().attempts,1);Ok(())
 })).unwrap();
}

#[test]
fn serialization_failure_preserves_accepted_lead_without_tentative_effects() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let id = lead(tx, "large-envelope")?;
				assert!(claim(tx, &[JobKind::Drilldown], 1)?.is_none());
				assert_eq!(scalar(tx, "SELECT COUNT(*) FROM jobs"), 1);
				assert_eq!(scalar(tx, "SELECT COUNT(*) FROM job_admission_charges"), 1);
				assert_eq!(scalar(tx, "SELECT seq FROM scheduler_clock"), 0);
				assert_eq!(admission::get_spending(tx, 1)?.unwrap().general, 1);
				let intent =
					review_intents::get_subject(tx, review_intents::Subject::Lead(id))?.unwrap();
				assert_eq!(intent.state, review_intents::State::Blocked);
				assert!(intent.admitted_job_id.is_none());
				assert!(matches!(
					leads::get_evidence(tx, id)?,
					loupe_storage::StoredEvidence::Recorded(_)
				));
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn drilldown_and_exact_continuation_deliver_accepted_sources() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let id = lead(tx, "accepted")?;
				let response = claim(tx, &[JobKind::Drilldown], LEASE_BYTES)?.unwrap();
				assert_eq!(
					jobs::get(tx, response["job_id"].as_i64().unwrap())?.unwrap().assigned_lead_id,
					Some(id)
				);
				Ok(())
			})
		})
		.unwrap();
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let batch = exact(tx)?;
				let response = claim(tx, &[JobKind::Survey], LEASE_BYTES)?.unwrap();
				let job = response["job_id"].as_i64().unwrap();
				assert_eq!(unit_holds::get_batch(tx, batch)?.unwrap().admitted_job_id, Some(job));
				tx.execute("UPDATE jobs SET state='queued' WHERE id=?1", [job])?;
				tx.execute(
					"UPDATE job_assigned_review_units SET completed=1 WHERE job_id=?1",
					[job],
				)?;
				unit(tx, 2)?;
				tx.execute(
					"UPDATE review_units SET priority_band='background' WHERE review_unit_id=2",
					[],
				)?;
				assert_eq!(claim(tx, &[JobKind::Survey], LEASE_BYTES)?.unwrap()["job_id"], job);
				assert_eq!(
					scalar(tx, "SELECT assignment_epoch FROM review_units WHERE review_unit_id=2"),
					0
				);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn retry_without_history_is_held_before_initializer_can_conceal_loss() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				unit(tx, 1)?;
				tx.execute("UPDATE jobs SET state='queued' WHERE id=101", [])?;
				let response = claim(tx, &[JobKind::Survey], LEASE_BYTES)?.unwrap();
				assert_ne!(response["job_id"], 101);
				assert_eq!(
					jobs::get(tx, 101)?.unwrap().error.as_deref(),
					Some("invalid_review_state")
				);
				assert_eq!(scalar(tx, "SELECT COUNT(*) FROM job_checkpoints WHERE job_id=101"), 0);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn all_bad_legacy_rows_make_bounded_durable_progress() {
	fixture().with_conn(|conn|transaction::immediate(conn,|tx| {
  for id in 200..240 {tx.execute("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(?1,1,'verify','queued',0)",[id])?;}
  assert!(claim(tx,&[],LEASE_BYTES)?.is_none());
  assert_eq!(scalar(tx,"SELECT COUNT(*) FROM jobs WHERE state='failed'"),32);
  assert_eq!(scalar(tx,"SELECT SUM(attempts) FROM jobs WHERE id>=200"),0);
  assert!(claim(tx,&[],LEASE_BYTES)?.is_none());
  assert_eq!(scalar(tx,"SELECT COUNT(*) FROM jobs WHERE state='failed'"),40);
  assert_eq!(scalar(tx,"SELECT seq FROM scheduler_clock"),0);Ok(())
 })).unwrap();
}

#[test]
fn unexpected_sql_error_rolls_back_without_quarantine() {
	let db = fixture();
	db.with_conn(|conn| {
  transaction::immediate(conn,|tx| {lead(tx,"trigger")?;Ok(())})?;
  conn.execute_batch("CREATE TRIGGER fail_charge BEFORE INSERT ON job_admission_charges BEGIN SELECT RAISE(ABORT,'injected unexpected SQL error'); END")?;
  let result=transaction::immediate(conn,|tx|claim(tx,&[JobKind::Drilldown],LEASE_BYTES));
  assert!(matches!(result,Err(loupe_storage::Error::Sqlite(_))));
  assert_eq!(conn.query_row("SELECT COUNT(*) FROM jobs",[],|r|r.get::<_,i64>(0))?,1);
  assert_eq!(conn.query_row("SELECT state FROM lead_drilldown_intents",[],|r|r.get::<_,String>(0))?,"pending");Ok(())
 }).unwrap();
}

#[test]
fn revoked_worker_cannot_trigger_quarantine() {
	let db = fixture();
	db.with_conn(|conn| {
		conn.execute(
			"INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(200,1,'verify','queued',0)",
			[],
		)?;
		conn.execute("UPDATE workers SET revoked_at=1 WHERE id=1", [])?;
		assert!(transaction::immediate(conn, |tx| claim(tx, &[], LEASE_BYTES)).is_err());
		assert_eq!(jobs::get(conn, 200)?.unwrap().state, loupe_core::JobState::Queued);
		Ok(())
	})
	.unwrap();
}

#[test]
fn cursor_maintenance_reaches_malformed_tail_without_a_worker() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				for i in 0..4 {
					lead(tx, &format!("healthy-{i}"))?;
				}
				tx.execute("UPDATE lead_drilldown_intents SET not_before=9999", [])?;
				let bad = lead(tx, "bad-tail")?;
				tx.execute("UPDATE leads SET anchored_payload='{}' WHERE lead_id=?1", [bad])?;
				let first = validation::maintain_campaign(tx, 1, 100, None, 2, 32)?;
				assert_eq!((first.inspected, first.repaired), (2, 0));
				let second = validation::maintain_campaign(tx, 1, 100, first.next, 2, 32)?;
				assert_eq!((second.inspected, second.repaired), (2, 0));
				let tail = validation::maintain_campaign(tx, 1, 100, second.next, 2, 32)?;
				assert_eq!((tail.inspected, tail.repaired), (1, 1));
				assert!(tail.next.is_none());
				assert!(tail.scan_complete);
				assert_eq!(
					scalar(tx, "SELECT COUNT(*) FROM lead_drilldown_intents WHERE state='pending'"),
					4
				);
				assert_eq!(scalar(tx, "SELECT seq FROM scheduler_clock"), 0);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn unresolved_preparation_delivers_campaign_branch_without_profile() {
	for recipe in ["bootstrap", "incremental"] {
		fixture().with_conn(|conn|transaction::immediate(conn,|tx| {
  tx.execute("DELETE FROM generation_manifests",[])?;
  tx.execute("UPDATE review_campaigns SET generation_id=NULL,target_commit_sha='feature/security',recipe=?1",[recipe])?;
  tx.execute("UPDATE jobs SET generation_id=NULL,head_sha=NULL,state='queued',attempts=0,recipe=?1",[format!(r#"{{"version":1,"phase":"survey","recipe":"{recipe}","assignment_key":"ordinary"}}"#)])?;
  let result=claim(tx,&[JobKind::Survey],LEASE_BYTES)?.unwrap();
  assert_eq!(result["repo"]["branch"],"feature/security");
  assert_eq!(result["head_branch"],"feature/security");
  assert_eq!(jobs::get(tx,101)?.unwrap().attempts,1);Ok(())
 })).unwrap();
	}
}

#[test]
fn exact_deferred_member_can_resume_its_own_hold() {
	fixture().with_conn(|conn|transaction::immediate(conn,|tx| {
  let batch=exact(tx)?;
  tx.execute("UPDATE review_units SET status='deferred',defer_reason='accepted follow up' WHERE review_unit_id=1",[])?;
  assert!(claim(tx,&[JobKind::Survey],LEASE_BYTES)?.is_some());
  assert_eq!(unit_holds::get_batch(tx,batch)?.unwrap().state,review_intents::State::Admitted);Ok(())
 })).unwrap();
}

#[test]
fn maintenance_distinguishes_unsupported_compatibility_and_malformed() {
	for (mutation,expected) in [
  ("UPDATE jobs SET recipe='{\"version\":1,\"phase\":\"survey\",\"recipe\":\"corroboration\",\"assignment_key\":\"ordinary\"}'","unsupported_recipe"),
  ("UPDATE jobs SET recipe='{\"version\":1,\"phase\":\"survey\",\"recipe\":\"reconciliation\",\"assignment_key\":\"ordinary\"}'","unsupported_recipe"),
  ("UPDATE jobs SET recipe='{\"version\":1,\"phase\":\"survey\",\"recipe\":\"coverage\",\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}'","invalid_review_state"),
  ("UPDATE review_generations SET generated_profile_digest=zeroblob(32)","invalid_review_state"),
  ("UPDATE generation_manifests SET sealed_at=NULL","invalid_review_state"),
  ("UPDATE jobs SET head_sha='ffffffffffffffffffffffffffffffffffffffff'","invalid_review_state"),
 ] {
 fixture().with_conn(|conn|transaction::immediate(conn,|tx| {
  tx.execute("UPDATE jobs SET state='queued',attempts=0",[])?;tx.execute(mutation,[])?;
  let out=validation::maintain_campaign(tx,1,100,None,256,32)?;
  assert_eq!(out.repaired,1,"{mutation}");
  assert_eq!(tx.query_row("SELECT error FROM jobs WHERE id=101",[],|r|r.get::<_,String>(0))?,expected);Ok(())
 })).unwrap();
 }
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let old = loupe_core::text::BoundedJson::<loupe_core::text::policy::Payload>::new(
					&serde_json::to_string(&scheduler::CampaignPolicy::default()).unwrap(),
				)?;
				tx.execute(
					"UPDATE review_campaigns SET effective_policy=?1,effective_policy_digest=?2",
					params![old.expose(), old.digest().as_slice()],
				)?;
				tx.execute("UPDATE jobs SET state='queued',attempts=0", [])?;
				assert_eq!(validation::maintain_campaign(tx, 1, 100, None, 256, 32)?.repaired, 1);
				assert_eq!(
					jobs::get(tx, 101)?.unwrap().error.as_deref(),
					Some("compatibility_policy")
				);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn queued_retry_epoch_mismatch_holds_job_without_reassigning() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				unit(tx, 1)?;
				tx.execute("UPDATE jobs SET state='succeeded'", [])?;
				let first = claim(tx, &[JobKind::Survey], LEASE_BYTES)?.unwrap();
				let id = first["job_id"].as_i64().unwrap();
				tx.execute("UPDATE jobs SET state='queued' WHERE id=?1", [id])?;
				tx.execute("UPDATE review_units SET assignment_epoch=assignment_epoch+1", [])?;
				assert_eq!(validation::maintain_campaign(tx, 1, 100, None, 256, 32)?.repaired, 1);
				assert_eq!(jobs::get(tx, id)?.unwrap().attempts, 1);
				assert_eq!(scalar(tx, "SELECT assignment_epoch FROM review_units"), 2);
				assert_eq!(scalar(tx, "SELECT assignment_epoch FROM job_assigned_review_units"), 1);
				Ok(())
			})
		})
		.unwrap();
}

fn finding(tx: &Transaction<'_>) -> Result<i64> {
	use loupe_core::text::{Anchor, Identifier};
	use loupe_storage::{finding_details, identity};
	let lead_id = lead(tx, "promoted")?;
	let response = claim(tx, &[JobKind::Drilldown], LEASE_BYTES)?.unwrap();
	let producer = response["job_id"].as_i64().unwrap();
	tx.execute(
		"UPDATE jobs SET state='succeeded',head_sha=?2 WHERE id=?1",
		params![producer, SHA],
	)?;
	tx.execute("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,created_at) VALUES(7,1,?1,'review','high','Finding','Evidence','canonical','validating',0)",[producer])?;
	let identity = identity::Identity {
		family: Identifier::new("auth-bypass")?,
		anchor: Anchor::new("boundary")?,
		instance: None,
	};
	let evidence:loupe_core::review_payload::FindingEvidenceV1=serde_json::from_value(json!({"version":1,"l2_argument":{"attacker_source":"Remote request","control":"Request length","sink":"Allocation","reachable_path":"Handler calls allocator","trust_boundary":"Request to memory"},"material_locations":[{"role":"sink","file":"src.rs","line_start":3,"line_end":4}],"counterevidence":"guard exists","assumptions_gaps":"caller","confidence":"medium"})).unwrap();
	let profile = GeneratedProfile::new("{\"languages\":[\"rust\"]}")?;
	finding_details::insert_review_evidence(
		tx,
		&finding_details::NewReviewEvidence {
			finding_id: 7,
			repo_id: 1,
			workflow_contract_version: 1,
			profile_version: 1,
			profile_digest: Some(profile.digest()),
			reviewed_commit_sha: SHA,
			identity: &identity,
			evidence: &evidence,
			origin_lead: Some(lead_id),
		},
		0,
	)?;
	tx.execute("UPDATE leads SET status='closed',disposition='promoted',promoted_finding_id=7 WHERE lead_id=?1",[lead_id])?;
	review_intents::ensure_verification_intent(tx, 7, producer, NORMAL, 0)?;
	Ok(7)
}

#[test]
fn verification_delivers_canonical_evidence_without_origin_lead() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let id = finding(tx)?;
				tx.execute(
					"UPDATE finding_review_details SET origin_lead_id=NULL WHERE finding_id=?1",
					[id],
				)?;
				let response = claim(tx, &[JobKind::Verify], LEASE_BYTES)?.unwrap();
				assert_eq!(response["payload"]["kind"], "review_verify");
				assert_eq!(
					jobs::get(tx, response["job_id"].as_i64().unwrap())?.unwrap().target_finding_id,
					Some(id)
				);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn malformed_nonadvertised_verification_releases_reserved_slot_without_verdict() {
	fixture().with_conn(|conn|transaction::immediate(conn,|tx| {
  let id=finding(tx)?;
  tx.execute("UPDATE finding_review_details SET evidence_payload='{}' WHERE finding_id=?1",[id])?;
  tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101",[])?;
  unit(tx,1)?;
  tx.execute("INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,enqueued_at,worker_id,attempts,lease_expires_at) VALUES(200,1,'drilldown','leased',1,11,0,1,1,10000)",[])?;
  let policy=scheduler::ClaimPolicy {active_jobs_per_repo:2,verify_reserved_slots:1,..Default::default()};
  let req=candidates::Request {worker_id:1,legacy_kinds:&[],phase_kinds:&[JobKind::Survey],now:100,policy:&policy,limit:1};
  assert!(candidates::ranked(tx,&req)?.is_empty(),"pending verify reserves capacity without a verify-capable worker");
  let progress=validation::maintain_campaign(tx,1,100,None,256,32)?;
  assert_eq!(progress.repaired,1);
  assert_eq!(candidates::ranked(tx,&req)?.len(),1,"held incompatible verification no longer reserves capacity");
  assert_eq!(loupe_storage::findings::get(tx,id)?.unwrap().state,loupe_core::FindingState::Validating);
  assert_eq!(review_intents::get_subject(tx,review_intents::Subject::Finding(id))?.unwrap().state,review_intents::State::Blocked);
  assert_eq!(scalar(tx,"SELECT COUNT(*) FROM finding_review_details"),1);Ok(())
 })).unwrap();
}

#[test]
fn pending_wrong_parent_profile_or_source_is_held_even_when_not_due() {
	for mutation in [
  "UPDATE lead_drilldown_intents SET profile_digest=zeroblob(32)",
  "UPDATE lead_drilldown_intents SET originating_job_id=200",
  "UPDATE generation_inventory SET path='foreign.rs',source_path='foreign.rs',raw_path=CAST('foreign.rs' AS BLOB)",
 ] {
 fixture().with_conn(|conn|transaction::immediate(conn,|tx| {
  lead(tx,"bad-context")?;
  tx.execute("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(200,1,'scan','succeeded',0)",[])?;
  tx.execute("UPDATE lead_drilldown_intents SET not_before=9999",[])?;tx.execute(mutation,[])?;
  assert_eq!(validation::maintain_campaign(tx,1,100,None,256,32)?.repaired,1,"{mutation}");Ok(())
 })).unwrap();
 }
}

#[test]
fn future_exact_batch_checks_retained_epoch_without_worker_or_due_time() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let batch = exact(tx)?;
				tx.execute("UPDATE survey_continuation_batches SET not_before=9999", [])?;
				tx.execute("UPDATE review_unit_holds SET source_assignment_epoch=4", [])?;
				let out = validation::maintain_campaign(tx, 1, 100, None, 256, 32)?;
				assert_eq!(
					out.repaired, 1,
					"future exact work must not conceal an invalid original epoch"
				);
				assert_eq!(
					unit_holds::get_batch(tx, batch)?.unwrap().state,
					review_intents::State::Blocked
				);
				assert_eq!(scalar(tx, "SELECT assignment_epoch FROM review_units"), 0);
				assert_eq!(scalar(tx, "SELECT COUNT(*) FROM review_unit_results"), 1);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn bootstrap_retry_before_publication_is_not_quarantined() {
	fixture().with_conn(|conn|transaction::immediate(conn, |tx| {
		tx.execute("UPDATE review_generations SET state='building',generated_profile=NULL,generated_profile_digest=NULL",[])?;
		tx.execute("UPDATE generation_manifests SET sealed_at=NULL",[])?;
		tx.execute("UPDATE jobs SET state='queued',recipe='{\"version\":1,\"phase\":\"survey\",\"recipe\":\"bootstrap\",\"assignment_key\":\"ordinary\"}'",[])?;
		assert_eq!(validation::maintain_campaign(tx,1,100,None,256,32)?.repaired,0);
		assert_eq!(claim(tx,&[JobKind::Survey],LEASE_BYTES)?.unwrap()["job_id"],101);
		assert_eq!(jobs::get(tx,101)?.unwrap().attempts,2);
		Ok(())
	})).unwrap();
}

#[test]
fn empty_ordinary_retry_marker_prevents_refilling_and_corrupt_markers_are_held() {
	for valid in [true, false] {
		fixture()
			.with_conn(|conn| {
				transaction::immediate(conn, |tx| {
					scheduler::initialize_ordinary_batch(tx, 101, 0)?;
					unit(tx, 1)?;
					tx.execute("UPDATE jobs SET state='queued' WHERE id=101", [])?;
					if !valid {
						tx.execute("UPDATE job_checkpoints SET payload_digest=zeroblob(32)", [])?;
					}
					let response = claim(tx, &[JobKind::Survey], LEASE_BYTES)?.unwrap();
					if valid {
						assert_eq!(response["job_id"], 101);
						assert_eq!(scalar(tx, "SELECT assignment_epoch FROM review_units"), 0);
						assert_eq!(scalar(tx, "SELECT COUNT(*) FROM job_assigned_review_units"), 0);
					} else {
						assert_ne!(response["job_id"], 101);
						assert_eq!(jobs::get(tx, 101)?.unwrap().attempts, 1);
						assert_eq!(
							jobs::get(tx, 101)?.unwrap().error.as_deref(),
							Some("invalid_review_state")
						);
					}
					Ok(())
				})
			})
			.unwrap();
	}
}

#[test]
fn maintenance_skips_dependency_blocked_work_and_rolls_back_on_sql_failure() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn,|tx| {
			let blocked=lead(tx,"dependency")?;
			tx.execute("UPDATE lead_drilldown_intents SET state='blocked',block_reason='external_dependency' WHERE lead_id=?1",[blocked])?;
			tx.execute("UPDATE leads SET anchored_payload='{}' WHERE lead_id=?1",[blocked])?;
			let bad=lead(tx,"malformed")?;
			tx.execute("UPDATE leads SET anchored_payload='{}' WHERE lead_id=?1",[bad])?;
			Ok(())
		})?;
		conn.execute_batch("CREATE TRIGGER fail_hold BEFORE UPDATE ON lead_drilldown_intents WHEN OLD.state='pending' BEGIN SELECT RAISE(ABORT,'hold failure'); END")?;
		assert!(matches!(transaction::immediate(conn,|tx|validation::maintain_campaign(tx,1,100,None,256,32)),Err(loupe_storage::Error::Sqlite(_))));
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM lead_drilldown_intents WHERE state='pending'",[],|r|r.get::<_,i64>(0))?,1);
		conn.execute("DROP TRIGGER fail_hold",[])?;
		let out=transaction::immediate(conn,|tx|validation::maintain_campaign(tx,1,100,None,256,32))?;
		assert_eq!((out.inspected,out.repaired),(1,1));
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM lead_drilldown_intents WHERE block_reason='external_dependency'",[],|r|r.get::<_,i64>(0))?,1);
		Ok(())
	}).unwrap();
}

fn subject_fixture(tx: &Transaction<'_>, verify: bool) -> Result<review_intents::Subject> {
	Ok(if verify {
		review_intents::Subject::Finding(finding(tx)?)
	} else {
		review_intents::Subject::Lead(lead(tx, "pending-eligibility")?)
	})
}

fn subject_table(subject: review_intents::Subject) -> &'static str {
	match subject {
		review_intents::Subject::Lead(_) => "lead_drilldown_intents",
		review_intents::Subject::Finding(_) => "finding_verification_intents",
	}
}

fn continue_test_subject(
	tx: &Transaction<'_>, subject: review_intents::Subject,
	class: loupe_core::review_payload::ContinuationClass,
) -> Result<review_intents::Intent> {
	let kind = match subject {
		review_intents::Subject::Lead(_) => JobKind::Drilldown,
		review_intents::Subject::Finding(_) => JobKind::Verify,
	};
	let job = claim(tx, &[kind], LEASE_BYTES)?.unwrap()["job_id"].as_i64().unwrap();
	tx.execute("UPDATE jobs SET state='succeeded',head_sha=?2 WHERE id=?1", params![job, SHA])?;
	if let review_intents::Subject::Lead(id) = subject {
		tx.execute("UPDATE leads SET status='deferred',defer_reason='remaining work',retry_condition='source_analysis_remaining' WHERE lead_id=?1",[id])?;
	}
	review_intents::continue_subject(tx, subject, job, class, 100)
}

fn evidence_bytes(tx: &Transaction<'_>, subject: review_intents::Subject) -> Result<String> {
	let (sql, id) = match subject {
		review_intents::Subject::Lead(id) => {
			("SELECT anchored_payload FROM leads WHERE lead_id=?1", id)
		},
		review_intents::Subject::Finding(id) => {
			("SELECT evidence_payload FROM finding_review_details WHERE finding_id=?1", id)
		},
	};
	Ok(tx.query_row(sql, [id], |r| r.get(0))?)
}

fn maintenance_holds_ineligible_subject(verify: bool, dependency: bool) {
	fixture().with_conn(|conn|transaction::immediate(conn,|tx| {
		let subject=subject_fixture(tx,verify)?;
		if dependency {
			continue_test_subject(tx,subject,loupe_core::review_payload::ContinuationClass::ExternalDependency)?;
			// Schema-valid corruption: this must stay dependency blocked, never
			// turn into a permanently pending obligation merely by setting a due time.
			tx.execute(&format!("UPDATE {} SET state='pending',block_reason=NULL,not_before=9999",subject_table(subject)),[])?;
		}else {
			match subject {
				review_intents::Subject::Lead(id)=>{tx.execute("UPDATE leads SET status='closed',disposition='rejected' WHERE lead_id=?1",[id])?;},
				review_intents::Subject::Finding(id)=>{tx.execute("UPDATE findings SET state='confirmed' WHERE id=?1",[id])?;},
			}
		}
		let before=review_intents::get_subject(tx,subject)?.unwrap();
		let evidence=evidence_bytes(tx,subject)?;
		let jobs=scalar(tx,"SELECT COUNT(*) FROM jobs");
		let spending=admission::get_spending(tx,1)?;
		let out=validation::maintain_campaign(tx,1,100,None,256,32)?;
		assert_eq!(out.repaired,1,"ineligible pending {subject:?}, dependency={dependency} must become an explicit hold");
		let after=review_intents::get_subject(tx,subject)?.unwrap();
		let mut expected=before;
		expected.state=review_intents::State::Blocked;
		expected.block_reason=Some(review_intents::BlockReason::CompatibilityPolicy);
		expected.not_before=None;
		expected.updated_at=100;
		assert_eq!(after,expected,"hold must retain accepted rank, revision, lineage and subject identity");
		assert_eq!(evidence_bytes(tx,subject)?,evidence,"accepted evidence must remain byte-identical");
		assert_eq!(scalar(tx,"SELECT COUNT(*) FROM jobs"),jobs);
		assert_eq!(admission::get_spending(tx,1)?,spending);
		if !dependency {
			match subject {
				review_intents::Subject::Lead(id)=>assert_eq!(loupe_storage::leads::get_metadata(tx,id)?.unwrap().status,loupe_storage::leads::Status::Closed),
				review_intents::Subject::Finding(id)=>assert_eq!(loupe_storage::findings::get(tx,id)?.unwrap().state,loupe_core::FindingState::Confirmed),
			}
		}
		Ok(())
	})).unwrap();
}

#[test]
fn maintenance_holds_pending_dependency_lead() {
	maintenance_holds_ineligible_subject(false, true);
}
#[test]
fn maintenance_holds_pending_dependency_finding() {
	maintenance_holds_ineligible_subject(true, true);
}
#[test]
fn maintenance_holds_pending_closed_lead() {
	maintenance_holds_ineligible_subject(false, false);
}
#[test]
fn maintenance_holds_pending_nonvalidating_finding() {
	maintenance_holds_ineligible_subject(true, false);
}

#[test]
fn maintenance_keeps_delayed_source_analysis_and_blocked_dependencies_unchanged() {
	for verify in [false, true] {
		for class in [
			loupe_core::review_payload::ContinuationClass::SourceAnalysisRemaining,
			loupe_core::review_payload::ContinuationClass::ExternalDependency,
		] {
			fixture().with_conn(|conn|transaction::immediate(conn,|tx| {
				let subject=subject_fixture(tx,verify)?;
				let before=continue_test_subject(tx,subject,class)?;
				let evidence=evidence_bytes(tx,subject)?;
				if class==loupe_core::review_payload::ContinuationClass::SourceAnalysisRemaining {assert!(before.not_before.unwrap()>100);}
				let out=validation::maintain_campaign(tx,1,100,None,256,32)?;
				assert_eq!(out.repaired,0);
				assert_eq!(out.inspected,if class==loupe_core::review_payload::ContinuationClass::SourceAnalysisRemaining {1}else{0});
				assert_eq!(review_intents::get_subject(tx,subject)?.unwrap(),before);
				assert_eq!(evidence_bytes(tx,subject)?,evidence);
				Ok(())
			})).unwrap();
		}
	}
}

#[test]
fn subject_admission_rejects_dependency_continuations_despite_a_due_time() {
	for verify in [false, true] {
		fixture().with_conn(|conn|transaction::immediate(conn,|tx| {
			let subject=subject_fixture(tx,verify)?;
			let intent=continue_test_subject(tx,subject,loupe_core::review_payload::ContinuationClass::ExternalDependency)?;
			tx.execute(&format!("UPDATE {} SET state='pending',block_reason=NULL,not_before=100",subject_table(subject)),[])?;
			let (kind,lead,finding)=match subject {review_intents::Subject::Lead(id)=>("drilldown",Some(id),None),review_intents::Subject::Finding(id)=>("verify",None,Some(id))};
			tx.execute("INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,head_sha,parent_job_id,continuation_of_job_id,assigned_lead_id,target_finding_id,worker_id,attempts,lease_expires_at,job_capability_hash,workflow_contract_version,scheduling_band,enqueued_at) VALUES(200,1,?1,'leased',1,11,?2,?3,?3,?4,?5,1,1,10000,?6,1,'normal',0)",params![kind,SHA,intent.originating_job_id,lead,finding,[200u8;32].as_slice()])?;
			assert!(review_intents::admit_subject(tx,subject,intent.revision,200,101).is_err(),"a due timestamp cannot authorize a dependency continuation");
			assert_eq!(review_intents::get_subject(tx,subject)?.unwrap().state,review_intents::State::Pending);
			Ok(())
		})).unwrap();
	}
}
