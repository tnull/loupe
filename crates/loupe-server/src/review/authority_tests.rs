//! These are direct leased authorization-boundary fixtures, not claims about
//! public phase lifecycle support. Public runtime gates remain closed.
use loupe_core::review_payload::{GeneratedProfile, SurveyTerminalV1};
use loupe_core::text::{BoundedJson, BoundedText, Identifier};
use loupe_storage::secrets::MasterKey;
use loupe_storage::{checkpoints, transaction, workers, Conflict, Db, Error};
use rusqlite::params;

use super::*;

const NOW: i64 = 100;
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
	db: Db,
	worker: AuthedWorker,
	headers: HeaderMap,
	hash: [u8; 32],
}

fn fixture() -> Fixture {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	let (capability, hash) = job_capability::issue();
	let mut headers = HeaderMap::new();
	headers.insert(loupe_proto::JOB_CAPABILITY_HEADER, capability.expose_secret().parse().unwrap());
	db.with_conn(|conn| {
		conn.execute_batch("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at)
		 VALUES(1,'u1','github.com','o','r1','{\"kind\":\"manual\"}',0),(2,'u2','github.com','o','r2','{\"kind\":\"manual\"}',0);
		 INSERT INTO workers VALUES(1,'worker','worker',x'01',0,0,NULL),(2,'other','worker',x'02',0,0,NULL),(3,'admin','admin',x'03',0,0,NULL);
		 INSERT INTO review_generations(generation_id,repo_id,generation_commit_sha,state,workflow_contract_version,created_at)
		 VALUES(11,1,'placeholder','active',1,0),(21,2,'foreign','active',1,0);
		 INSERT INTO review_campaigns(campaign_id,repo_id,recipe,trigger,target_commit_sha,generation_id,state,effective_policy,effective_policy_digest,deadline_at,created_at)
		 VALUES(1,1,'bootstrap','manual','placeholder',11,'active','{}',zeroblob(32),1000,0);
		 INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,worker_id,lease_expires_at,attempts,workflow_contract_version,recipe,hard_deadline_at,enqueued_at)
		 VALUES(101,1,'survey','leased',1,11,1,500,2,1,'{\"version\":1,\"phase\":\"survey\",\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}',1000,0),
		 (102,1,'survey','queued',1,11,NULL,NULL,0,1,NULL,NULL,0);
		 INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,expected_digest,created_at,sealed_at)
		 VALUES(11,1,101,0,zeroblob(32),0,1);")?;
		conn.execute("UPDATE jobs SET head_sha=?1,job_capability_hash=?2,prepared_attempt=2,prepared_capability_hash=?2,prepared_at=1 WHERE id=101", params![SHA, hash.as_slice()])?;
		conn.execute("UPDATE review_campaigns SET target_commit_sha=?1", [SHA])?;
		let profile = GeneratedProfile::new("{}").unwrap();
		conn.execute("UPDATE review_generations SET generation_commit_sha=?1,profile_version=1,generated_profile=?2,generated_profile_digest=?3 WHERE generation_id=11", params![SHA, profile.expose(), profile.digest().as_slice()])?;
		Ok(())
	}).unwrap();
	let worker =
		db.with_conn(|conn| Ok(workers::find_active_by_fingerprint(conn, &[1])?.unwrap())).unwrap();
	Fixture { db, worker: AuthedWorker { worker }, headers, hash }
}

fn mutate(f: &Fixture, sql: &str) {
	f.db.with_conn(|conn| {
		conn.execute_batch(sql)?;
		Ok(())
	})
	.unwrap();
}
fn allowed(f: &Fixture, phase: JobKind, access: Access) -> bool {
	f.db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			Ok(authorize(tx, &f.worker, &f.headers, 101, phase, access, NOW)?.is_some())
		})
	})
	.unwrap()
}

#[test]
fn profile_version_bounds_revoke_domain_not_lease_control() {
	let mut domain = Vec::new();
	for version in ["1", "4294967295", "4294967296", "1.5"] {
		let f = fixture();
		assert!(allowed(&f, JobKind::Survey, Access::Domain));
		mutate(
			&f,
			&format!(
				"UPDATE review_generations SET profile_version={version} WHERE generation_id=11"
			),
		);
		domain.push(allowed(&f, JobKind::Survey, Access::Domain));
		assert!(allowed(&f, JobKind::Survey, Access::LeaseControl), "control: {version}");
		finish(&f);
		f.db.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				assert!(
					matches!(
						replay_terminal(
							tx,
							&f.worker,
							&f.headers,
							101,
							JobKind::Survey,
							&terminal_payload()
						)?,
						terminal_receipt::Replayed::Receipt(_)
					),
					"receipt: {version}"
				);
				Ok(())
			})
		})
		.unwrap();
	}
	assert_eq!(
		domain,
		[true, true, false, false],
		"fresh domain authority requires an integer profile version in the lease range"
	);
}

#[test]
fn identity_and_transaction_time_revocation_are_uniformly_denied() {
	for sql in [
		"UPDATE workers SET revoked_at=1 WHERE id=1",
		"UPDATE workers SET kind='admin' WHERE id=1",
		"UPDATE jobs SET worker_id=2 WHERE id=101",
		"UPDATE jobs SET state='queued' WHERE id=101",
		"UPDATE jobs SET lease_expires_at=100 WHERE id=101",
		"UPDATE jobs SET attempts=0 WHERE id=101",
		"UPDATE jobs SET campaign_id=NULL WHERE id=101",
		"UPDATE jobs SET job_capability_hash=zeroblob(32) WHERE id=101",
	] {
		let f = fixture();
		assert!(allowed(&f, JobKind::Survey, Access::Domain), "positive precheck: {sql}");
		mutate(&f, sql);
		assert!(!allowed(&f, JobKind::Survey, Access::Domain), "transaction recheck: {sql}");
		assert!(!allowed(&f, JobKind::Survey, Access::LeaseControl));
	}
	let mut f = fixture();
	assert!(!allowed(&f, JobKind::Drilldown, Access::Domain));
	for job in [102, 999] {
		assert!(f
			.db
			.with_conn(|conn| transaction::immediate(conn, |tx| Ok(authorize(
				tx,
				&f.worker,
				&f.headers,
				job,
				JobKind::Survey,
				Access::Domain,
				NOW
			)?
			.is_none())))
			.unwrap());
	}
	f.headers.clear();
	assert!(!allowed(&f, JobKind::Survey, Access::LeaseControl));
	assert!(f
		.db
		.with_conn(|conn| transaction::immediate(conn, |tx| Ok(authorize(
			tx,
			&f.worker,
			&HeaderMap::new(),
			999,
			JobKind::Survey,
			Access::Domain,
			NOW
		)?
		.is_none())))
		.unwrap());
}

#[test]
fn preparation_and_readiness_matrix() {
	for (sql, checkout, host) in [
		("UPDATE jobs SET prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id=101", true, false),
		("UPDATE jobs SET prepared_attempt=1 WHERE id=101", true, false),
		("UPDATE jobs SET prepared_capability_hash=zeroblob(32) WHERE id=101", true, false),
		("UPDATE jobs SET prepared_at=101 WHERE id=101", true, false),
		("UPDATE jobs SET head_sha='old' WHERE id=101", true, false),
		("UPDATE review_campaigns SET target_commit_sha='different'", false, false),
		("UPDATE generation_manifests SET owner_job_id=NULL; UPDATE jobs SET generation_id=NULL WHERE id=101", false, false),
		("UPDATE jobs SET workflow_contract_version=2 WHERE id=101", false, false),
		("UPDATE review_generations SET workflow_contract_version=2 WHERE generation_id=11", false, false),
		("UPDATE generation_manifests SET sealed_at=NULL", true, true),
		("DELETE FROM generation_manifests", true, true),
		("UPDATE review_generations SET generated_profile=NULL WHERE generation_id=11", true, true),
		("UPDATE review_generations SET generated_profile='[]' WHERE generation_id=11", true, true),
		("UPDATE review_generations SET generated_profile_digest=zeroblob(32) WHERE generation_id=11", true, true),
	] {
		let f = fixture();
		assert!(allowed(&f, JobKind::Survey, Access::Domain));
		mutate(&f, sql);
		assert_eq!(allowed(&f, JobKind::Survey, Access::Checkout), checkout, "checkout: {sql}");
		assert_eq!(allowed(&f, JobKind::Survey, Access::PreparedHost), host, "prepared host: {sql}");
		assert!(!allowed(&f, JobKind::Survey, Access::Domain), "domain: {sql}");
	}
}

#[test]
fn lease_control_survives_deadlines_and_rebuildable_cleanup_only() {
	for sql in [
		"UPDATE review_campaigns SET state='cancelled'",
		"UPDATE review_campaigns SET deadline_at=100",
		"UPDATE jobs SET hard_deadline_at=100,submit_by=1000 WHERE id=101",
		"UPDATE jobs SET recipe='broken JSON' WHERE id=101",
		"DELETE FROM review_generations WHERE generation_id=11",
	] {
		let f = fixture();
		mutate(&f, sql);
		assert!(allowed(&f, JobKind::Survey, Access::LeaseControl), "control: {sql}");
		for access in [Access::Checkout, Access::PreparedHost, Access::Domain] {
			assert!(!allowed(&f, JobKind::Survey, access), "domain/host: {sql}");
		}
	}
}

#[test]
fn missing_phase_deadline_denies_analysis_not_failure_reports() {
	let f = fixture();
	assert!(allowed(&f, JobKind::Survey, Access::Domain));
	mutate(&f, "UPDATE jobs SET hard_deadline_at=NULL WHERE id=101");
	assert!(allowed(&f, JobKind::Survey, Access::LeaseControl));
	for access in [Access::Checkout, Access::PreparedHost, Access::Domain] {
		assert!(!allowed(&f, JobKind::Survey, access), "missing deadline must deny {access:?}");
	}
}

#[test]
fn lease_control_ignores_malformed_nonidentity_sql_values() {
	for column in ["recipe", "head_sha", "hard_deadline_at", "workflow_contract_version"] {
		let f = fixture();
		mutate(&f, &format!("UPDATE jobs SET {column}=x'ff' WHERE id=101"));
		let result = f.db.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				Ok(authorize(
					tx,
					&f.worker,
					&f.headers,
					101,
					JobKind::Survey,
					Access::LeaseControl,
					NOW,
				)?
				.is_some())
			})
		});
		assert!(
			matches!(result, Ok(true)),
			"nonidentity {column} must not block failure reporting: {result:?}"
		);
	}
}

#[test]
fn strict_recipe_decoder_rejects_unsupported_shapes() {
	for raw in [
		"{}",
		r#"{"version":2,"phase":"survey","recipe":"coverage","assignment_key":"ordinary"}"#,
		r#"{"version":1,"phase":"verify"}"#,
		r#"{"version":1,"phase":"survey","recipe":"coverage","assignment_key":"ordinary","extra":1}"#,
		r#"{"version":1,"version":1,"phase":"survey","recipe":"coverage","assignment_key":"ordinary"}"#,
		r#"{"version":1,"phase":"survey","phase":"survey","recipe":"coverage","assignment_key":"ordinary"}"#,
		r#"{"version":1,"phase":"survey","recipe":"coverage","assignment_key":"other"}"#,
		r#"{"version":1,"phase":"survey","recipe":"reconciliation","assignment_key":"ordinary"}"#,
		r#"{"version":1,"phase":"survey","recipe":"corroboration","assignment_key":"ordinary"}"#,
	] {
		let f = fixture();
		f.db.with_conn(|conn| {
			conn.execute("UPDATE jobs SET recipe=?1 WHERE id=101", [raw])?;
			Ok(())
		})
		.unwrap();
		assert!(!allowed(&f, JobKind::Survey, Access::Domain), "{raw}");
		assert!(!allowed(&f, JobKind::Survey, Access::Checkout), "{raw}");
		assert!(allowed(&f, JobKind::Survey, Access::LeaseControl));
	}
}

fn survey_recipe(f: &Fixture, recipe: &str) {
	f.db.with_conn(|conn| {
		conn.execute(
			"UPDATE jobs SET recipe=?1 WHERE id=101",
			[format!(
				r#"{{"version":1,"phase":"survey","recipe":"{recipe}","assignment_key":"ordinary"}}"#
			)],
		)?;
		Ok(())
	})
	.unwrap();
}

#[test]
fn bootstrap_incremental_and_coverage_have_distinct_eligibility() {
	let f = fixture();
	survey_recipe(&f, "bootstrap");
	assert!(
		!allowed(&f, JobKind::Survey, Access::Domain),
		"bootstrap cannot reactivate active baseline"
	);
	mutate(&f, "UPDATE review_generations SET state='building' WHERE generation_id=11");
	assert!(allowed(&f, JobKind::Survey, Access::Domain));
	mutate(&f, "UPDATE review_generations SET predecessor_generation_id=21 WHERE generation_id=11");
	assert!(!allowed(&f, JobKind::Survey, Access::Checkout), "successor needs B8");
	for recipe in ["bootstrap", "incremental"] {
		let f = fixture();
		survey_recipe(&f, recipe);
		f.db.with_conn(|conn| {
			conn.execute(
				"UPDATE review_campaigns SET recipe=?1,generation_id=NULL,target_commit_sha='main'",
				[recipe],
			)?;
			conn.execute("UPDATE generation_manifests SET owner_job_id=NULL", [])?;
			conn.execute("UPDATE jobs SET generation_id=NULL,head_sha=NULL WHERE id=101", [])?;
			Ok(())
		})
		.unwrap();
		assert!(allowed(&f, JobKind::Survey, Access::Checkout));
		assert!(!allowed(&f, JobKind::Survey, Access::PreparedHost));
		assert!(!allowed(&f, JobKind::Survey, Access::Domain));
	}
	let f = fixture();
	survey_recipe(&f, "incremental");
	mutate(&f, "UPDATE review_campaigns SET recipe='incremental'");
	assert!(allowed(&f, JobKind::Survey, Access::Domain));
	mutate(&f, "UPDATE review_generations SET state='building' WHERE generation_id=11");
	assert!(!allowed(&f, JobKind::Survey, Access::Checkout));
	for recipe in ["reconciliation", "corroboration"] {
		let f = fixture();
		f.db.with_conn(|conn| {
			conn.execute("UPDATE review_campaigns SET recipe=?1", [recipe])?;
			Ok(())
		})
		.unwrap();
		assert!(
			!allowed(&f, JobKind::Survey, Access::Domain),
			"campaign recipe cannot be bypassed by coverage"
		);
	}
}

fn units(f: &Fixture) {
	mutate(f, "INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,assignment_epoch,created_by_job_id,created_at)
	 VALUES(31,11,'owned','title','objective','[]',3,101,0),(32,11,'other','title','objective','bad JSON',3,102,0),(41,21,'foreign','title','objective','bad JSON',3,NULL,0);
	 INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(101,31,0,3);");
}

fn unit_allowed(f: &Fixture, id: i64, epoch: i64) -> bool {
	f.db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			authorize(tx, &f.worker, &f.headers, 101, JobKind::Survey, Access::Domain, NOW)?
				.unwrap()
				.survey_unit(id, epoch)
		})
	})
	.unwrap()
}

#[test]
fn exact_unit_membership_epoch_and_freshness_are_required() {
	let f = fixture();
	units(&f);
	assert!(unit_allowed(&f, 31, 3));
	for id in [32, 41, 999] {
		assert!(!unit_allowed(&f, id, 3), "uniform foreign/missing denial: {id}");
	}
	assert!(!unit_allowed(&f, 31, 2));
	for sql in [
		"UPDATE job_assigned_review_units SET assignment_epoch=NULL",
		"UPDATE job_assigned_review_units SET assignment_epoch=2",
		"UPDATE review_units SET assignment_epoch=4 WHERE review_unit_id=31",
		"UPDATE review_units SET stale=1 WHERE review_unit_id=31",
		"UPDATE review_units SET status='retired' WHERE review_unit_id=31",
	] {
		let f = fixture();
		units(&f);
		mutate(&f, sql);
		assert!(!unit_allowed(&f, 31, 3), "{sql}");
	}
	// The conclusive negative control must be Recorded current evidence, not a
	// historical payload that modern coverage deliberately leaves incomplete.
	let f = fixture();
	units(&f);
	assert!(unit_allowed(&f, 31, 3));
	f.db.with_conn(|conn|transaction::immediate(conn,|tx| {
		tx.execute("UPDATE generation_manifests SET expected_entry_count=1,received_entry_count=1 WHERE generation_id=11",[])?;
		tx.execute("INSERT INTO generation_inventory(generation_id,path,source_path,raw_path,blob_sha,entry_kind,git_mode,manifest_position,disposition,created_at) VALUES(11,'src.rs','src.rs',?1,?2,'tracked',33188,0,'context',0)",params![b"src.rs".as_slice(),SHA])?;
		let payload=loupe_core::review_payload::UnitResultPayloadV1::from_json(&serde_json::json!({"format":"loupe.unit_result","version":1,"review_unit_id":31,"assignment_epoch":3,"disposition":"no_lead_found","inspected_refs":[{"path":"src.rs"}],"created_lead_ids":[],"counterevidence":"Guard traced","proof_gaps":"None"}).to_string())?;
		loupe_storage::review_unit_results::insert_evidence(tx,&loupe_storage::review_unit_results::NewResultEvidence{generation_id:11,produced_by_job:101,commit_sha:SHA,profile_version:1,payload:&payload},NOW)?;
		Ok(())
	})).unwrap();
	assert!(!unit_allowed(&f, 31, 3), "current conclusive evidence excludes another fresh result");
	let f = fixture();
	units(&f);
	survey_recipe(&f, "bootstrap");
	mutate(&f,"UPDATE review_generations SET state='building' WHERE generation_id=11; DELETE FROM job_assigned_review_units;");
	assert!(unit_allowed(&f, 31, 3), "bootstrap uses creating-job provenance");
	assert!(!unit_allowed(&f, 32, 3));
}

#[test]
fn replay_lookup_precedes_fresh_checks_and_callback_failure_rolls_back() {
	let f = fixture();
	units(&f);
	let key = Identifier::new("result").unwrap();
	for expect_replay in [false, true] {
		f.db.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let auth = authorize(
					tx,
					&f.worker,
					&f.headers,
					101,
					JobKind::Survey,
					Access::Domain,
					NOW,
				)?
				.unwrap();
				let outcome = checkpoints::run(
					tx,
					auth.job().id,
					checkpoints::Operation::SubmitUnitResult,
					&key,
					&[7; 32],
					NOW,
					|tx| {
						assert!(!expect_replay, "fresh callback must not run on exact replay");
						assert!(auth.survey_unit(31, 3)?);
						tx.execute(
							"UPDATE review_units SET status='retired' WHERE review_unit_id=31",
							[],
						)?;
						Ok(BoundedJson::new("{\"unit_id\":31}")?)
					},
				)?;
				assert_eq!(matches!(outcome, checkpoints::Outcome::Replayed(_)), expect_replay);
				Ok(())
			})
		})
		.unwrap();
	}
	assert!(!unit_allowed(&f, 31, 3));
	mutate(&f, "UPDATE review_units SET status='open' WHERE review_unit_id=31");
	f.db.with_conn(|conn| {
		let failed = transaction::immediate(conn, |tx| {
			let auth =
				authorize(tx, &f.worker, &f.headers, 101, JobKind::Survey, Access::Domain, NOW)?
					.unwrap();
			checkpoints::run(
				tx,
				auth.job().id,
				checkpoints::Operation::SubmitUnitResult,
				&Identifier::new("rollback").unwrap(),
				&[8; 32],
				NOW,
				|tx| {
					assert!(auth.survey_unit(31, 3)?);
					tx.execute(
						"UPDATE review_units SET status='retired' WHERE review_unit_id=31",
						[],
					)?;
					Err(Error::Conflict(Conflict::UnitState))
				},
			)
		});
		assert!(matches!(failed, Err(Error::Conflict(Conflict::UnitState))));
		assert_eq!(
			conn.query_row("SELECT COUNT(*) FROM job_checkpoints", [], |row| row.get::<_, i64>(0))?,
			1
		);
		Ok(())
	})
	.unwrap();
	assert!(unit_allowed(&f, 31, 3), "failed callback domain write rolled back");
}

fn child(f: &Fixture, phase: JobKind) {
	mutate(f,"INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at)
	 VALUES(31,11,'family','anchor',zeroblob(32),'{}',zeroblob(32),'base',0),(41,21,'family','anchor',zeroblob(32),'broken',zeroblob(32),'foreign',0);
	 INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,created_at)
	 VALUES(51,1,101,'test','high','title','description','a',0),(61,2,101,'test','high','title','description','b',0);");
	f.db.with_conn(|conn| { conn.execute("UPDATE jobs SET kind=?1,recipe=?2,assigned_lead_id=?3,target_finding_id=?4 WHERE id=101", params![phase.as_str(),format!(r#"{{"version":1,"phase":"{}"}}"#,phase.as_str()), if phase==JobKind::Drilldown {Some(31)} else {None},if phase==JobKind::Verify {Some(51)} else {None}])?; Ok(()) }).unwrap();
}

#[test]
fn children_are_exact_subject_scoped_and_cannot_bypass_recipe_policy() {
	for phase in [JobKind::Drilldown, JobKind::Verify] {
		let f = fixture();
		child(&f, phase.clone());
		assert!(allowed(&f, phase.clone(), Access::Domain));
		f.db.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let auth =
					authorize(tx, &f.worker, &f.headers, 101, phase.clone(), Access::Domain, NOW)?
						.unwrap();
				assert_eq!(auth.assigned_lead(31)?, phase == JobKind::Drilldown);
				assert_eq!(auth.assigned_finding(51)?, phase == JobKind::Verify);
				for id in [41, 61, 999] {
					assert!(!auth.assigned_lead(id)?);
					assert!(!auth.assigned_finding(id)?);
				}
				assert!(!auth.survey_unit(31, 0)?);
				Ok(())
			})
		})
		.unwrap();
		mutate(&f, "UPDATE review_generations SET state='building' WHERE generation_id=11");
		assert!(
			allowed(&f, phase.clone(), Access::Domain),
			"ready initial bootstrap permits children"
		);
		mutate(&f, "UPDATE review_campaigns SET recipe='reconciliation'");
		assert!(!allowed(&f, phase.clone(), Access::Domain));
		assert!(!allowed(&f, phase.clone(), Access::Checkout));
		assert!(allowed(&f, phase, Access::LeaseControl));
	}
}

fn terminal_payload() -> TerminalPayload {
	TerminalPayload::Survey(
		SurveyTerminalV1::from_json(r#"{"version":1,"terminal_reason":"completed"}"#).unwrap(),
	)
}

fn finish(f: &Fixture) {
	f.db.with_conn(|conn| transaction::immediate(conn,|tx| {
		terminal_receipt::insert(tx,&terminal_receipt::NewReceipt {
			job_id:101,phase:JobKind::Survey,terminal_reason:&BoundedText::new("completed").unwrap(),subject_title:None,subject_digest:None,
			pinned_commit_sha:SHA,effective_recipe:&BoundedJson::new("{}").unwrap(),result_digest:&terminal_payload().digest().unwrap(),
			evidence_rung:None,result_counts:None,finishing_capability_hash:Some(&f.hash),
		},NOW)?;
		tx.execute("UPDATE jobs SET state='succeeded',job_capability_hash=NULL,lease_expires_at=NULL WHERE id=101",[])?;
		Ok(())
	})).unwrap();
}

#[test]
fn sealed_terminal_replay_survives_rebuildable_cleanup_not_identity_changes() {
	let f = fixture();
	finish(&f);
	mutate(&f,"DELETE FROM review_generations WHERE generation_id=11; UPDATE review_campaigns SET state='cancelled'; UPDATE jobs SET recipe='invalid',prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id=101;");
	f.db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			assert!(matches!(
				replay_terminal(
					tx,
					&f.worker,
					&f.headers,
					101,
					JobKind::Survey,
					&terminal_payload()
				)?,
				terminal_receipt::Replayed::Receipt(_)
			));
			let different = TerminalPayload::Survey(
				SurveyTerminalV1::from_json(
					r#"{"version":1,"terminal_reason":"completed","security_model_notes":"different"}"#,
				)
				.unwrap(),
			);
			assert!(matches!(
				replay_terminal(tx, &f.worker, &f.headers, 101, JobKind::Survey, &different)?,
				terminal_receipt::Replayed::Reject(terminal_receipt::Reject::WrongDigest)
			));
			Ok(())
		})
	})
	.unwrap();
	for sql in [
		"UPDATE workers SET revoked_at=1 WHERE id=1",
		"UPDATE workers SET kind='admin' WHERE id=1",
		"UPDATE jobs SET worker_id=2 WHERE id=101",
		"UPDATE jobs SET worker_id=NULL WHERE id=101",
		"UPDATE jobs SET campaign_id=NULL WHERE id=101",
		"UPDATE jobs SET state='queued' WHERE id=101",
	] {
		let f = fixture();
		finish(&f);
		mutate(&f, sql);
		f.db.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				assert!(
					matches!(
						replay_terminal(
							tx,
							&f.worker,
							&f.headers,
							101,
							JobKind::Survey,
							&terminal_payload()
						)?,
						terminal_receipt::Replayed::Reject(terminal_receipt::Reject::Denied)
					),
					"{sql}"
				);
				Ok(())
			})
		})
		.unwrap();
	}
	let mut f = fixture();
	finish(&f);
	let (old_cap, _) = job_capability::issue();
	f.headers.insert(loupe_proto::JOB_CAPABILITY_HEADER, old_cap.expose_secret().parse().unwrap());
	f.db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let wrong = TerminalPayload::Survey(
				SurveyTerminalV1::from_json(
					r#"{"version":1,"terminal_reason":"completed","security_model_notes":"different"}"#,
				)
				.unwrap(),
			);
			assert!(
				matches!(
					replay_terminal(tx, &f.worker, &f.headers, 101, JobKind::Survey, &wrong)?,
					terminal_receipt::Replayed::Reject(terminal_receipt::Reject::Denied)
				),
				"old capability cannot learn digest match"
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn terminal_binding_is_checked_before_receipt_decoding() {
	let f = fixture();
	finish(&f);
	mutate(&f, "UPDATE job_terminal_receipts SET effective_recipe='broken JSON' WHERE job_id=101");
	f.db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			for (job, worker, phase, cap) in [
				(999, 1, JobKind::Survey, f.hash),
				(101, 2, JobKind::Survey, f.hash),
				(101, 1, JobKind::Drilldown, f.hash),
				(101, 1, JobKind::Survey, [9; 32]),
			] {
				assert!(
					matches!(
						terminal_receipt::replay_terminal(
							tx,
							jobs::LeaseIdentity {
								job_id: job,
								worker_id: worker,
								capability_hash: &cap
							},
							phase,
							&[4; 32]
						)?,
						terminal_receipt::Replayed::Reject(terminal_receipt::Reject::Denied)
					),
					"unknown/wrong binding does not decode corrupt receipt"
				);
			}
			// The positive binding reaches decoding, proving the malformed receipt
			// is a real oracle hazard rather than an inert fixture.
			assert!(replay_terminal(
				tx,
				&f.worker,
				&f.headers,
				101,
				JobKind::Survey,
				&terminal_payload()
			)
			.is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn child_authority_requires_its_own_subject_and_ready_generation() {
	for phase in [JobKind::Drilldown, JobKind::Verify] {
		for sql in [
			"UPDATE generation_manifests SET sealed_at=NULL",
			"UPDATE jobs SET assigned_lead_id=NULL,target_finding_id=NULL WHERE id=101",
			"UPDATE jobs SET assigned_lead_id=41,target_finding_id=61 WHERE id=101",
			"UPDATE review_campaigns SET recipe='corroboration'",
		] {
			let f = fixture();
			child(&f, phase.clone());
			assert!(allowed(&f, phase.clone(), Access::Domain));
			mutate(&f, sql);
			assert!(!allowed(&f, phase.clone(), Access::Checkout), "{phase:?}: {sql}");
			assert!(!allowed(&f, phase.clone(), Access::Domain));
		}
	}
}
