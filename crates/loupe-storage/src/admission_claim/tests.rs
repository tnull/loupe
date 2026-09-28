use loupe_core::{JobKind, JobState};
use rusqlite::{params, Transaction};

use super::*;
use crate::review_intents::tests::{NORMAL, SHA};
use crate::review_intents::Subject;
use crate::{
	admission, admission_candidates, leads, review_intents, scheduler, transaction, unit_holds, Db,
	Result,
};

fn fixture() -> Db {
	let db = review_intents::tests::fixture();
	db.with_conn(|conn| {
		conn.execute("DELETE FROM jobs WHERE id IN(102,201)", [])?;
		conn.execute("INSERT INTO campaign_admission_spending(campaign_id,policy_version,general_spent) VALUES(1,2,1)", [])?;
		conn.execute("INSERT INTO job_admission_charges(job_id,campaign_id,pool) VALUES(101,1,'general')", [])?;
		conn.execute("UPDATE jobs SET recipe='{\"version\":1,\"phase\":\"survey\",\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}',effective_priority=0 WHERE id=101", [])?;
		Ok(())
	}).unwrap();
	db
}

fn request(policy: &scheduler::ClaimPolicy, now: i64) -> admission_candidates::Request<'_> {
	admission_candidates::Request {
		worker_id: 1,
		legacy_kinds: &[JobKind::Scan, JobKind::Verify],
		phase_kinds: &[JobKind::Survey, JobKind::Drilldown, JobKind::Verify],
		now,
		policy,
		limit: 1,
	}
}
fn claim(tx: &Transaction<'_>, now: i64) -> Result<scheduler::Claimed> {
	let policy = scheduler::ClaimPolicy::default();
	let req = request(&policy, now);
	let candidate = admission_candidates::ranked(tx, &req)?.remove(0);
	let hash: [u8; 32] = now.to_be_bytes().repeat(4).try_into().unwrap();
	let Outcome::Uncommitted(claimed) = materialize(tx, &candidate, &req, &hash, 600)? else {
		panic!("selected candidate must materialize")
	};
	Ok(*claimed)
}
fn lead(tx: &Transaction<'_>) -> Result<i64> {
	lead_with_priority(tx, NORMAL)
}
fn lead_with_priority(
	tx: &Transaction<'_>, priority: crate::admission_policy::AcceptedPriority,
) -> Result<i64> {
	let payload = loupe_core::review_payload::LeadEvidenceV1::from_json(
		&serde_json::json!({
			"format":"loupe.lead_evidence","version":1,"identity_family":"auth-bypass",
			"identity_anchor":"request guard","review_unit_id":null,"assignment_epoch":null,
			"hypothesis":"wrapper bypass","invariant_or_boundary":"authentication",
			"source_refs":[{"path":"src.rs"}],"next_proof_step":"trace wrapper",
			"counterevidence":"guard exists","proof_gaps":"entry uncertain"
		})
		.to_string(),
	)?;
	let leads::Submitted::Created(id) = leads::submit_evidence(
		tx,
		&leads::NewLeadEvidence {
			generation_id: 11,
			created_by_job: 101,
			commit_sha: SHA,
			priority: crate::review_units::Priority::Normal,
			payload: &payload,
		},
		0,
	)?
	else {
		panic!("new lead")
	};
	review_intents::ensure_drilldown_intent(tx, id, 101, priority, 0)?;
	Ok(id)
}

#[test]
fn initial_lead_and_logical_retry_join_lease_budget_parent_and_fairness() {
	fixture().with_conn(|conn| transaction::immediate(conn, |tx| {
		let lead = lead(tx)?;
		let first = claim(tx, 10)?;
		assert_eq!(first.job.kind, JobKind::Drilldown);
		assert_eq!(first.job.assigned_lead_id, Some(lead));
		assert_eq!(first.job.parent_job_id, Some(101));
		assert_eq!(first.job.continuation_of_job_id, None);
		assert_eq!(first.job.attempts, 1);
		assert!(first.job.head_sha.is_none());
		assert_eq!(admission::get_spending(tx, 1)?.unwrap().general, 2);
		tx.execute("UPDATE jobs SET state='queued',prepared_attempt=attempts,prepared_capability_hash=job_capability_hash,prepared_at=10 WHERE id=?1", [first.job.id])?;
		let retry = claim(tx, 11)?;
		assert_eq!(retry.job.id, first.job.id);
		assert_eq!(retry.job.attempts, 2);
		assert_eq!(admission::get_spending(tx, 1)?.unwrap().general, 2);
		assert!(tx.query_row("SELECT prepared_attempt IS NULL AND prepared_capability_hash IS NULL AND prepared_at IS NULL FROM jobs WHERE id=?1", [first.job.id], |r| r.get::<_,bool>(0))?);
		assert_eq!(tx.query_row("SELECT seq FROM scheduler_clock", [], |r| r.get::<_,i64>(0))?, 2);
		tx.execute("UPDATE jobs SET state='succeeded',head_sha=?2 WHERE id=?1", params![first.job.id,SHA])?;
		let pending=review_intents::continue_subject(tx, Subject::Lead(lead), first.job.id, loupe_core::review_payload::ContinuationClass::SourceAnalysisRemaining, 12)?;
		let next=claim(tx, pending.not_before.unwrap())?;
		assert_ne!(next.job.id, first.job.id);
		assert_eq!(next.job.parent_job_id, Some(first.job.id));
		assert_eq!(next.job.continuation_of_job_id, Some(first.job.id));
		assert_eq!(admission::get_spending(tx, 1)?.unwrap().general, 3);
		assert_eq!(review_intents::get_subject(tx,Subject::Lead(lead))?.unwrap().logical_sequence,1);
		Ok(())
	})).unwrap();
}

fn exact_batch(tx: &Transaction<'_>) -> Result<i64> {
	unit(tx, 1)?;
	let payload=loupe_core::review_payload::UnitResultPayloadV1::from_json(&serde_json::json!({"format":"loupe.unit_result","version":1,"review_unit_id":1,"assignment_epoch":0,"disposition":"needs_follow_up","inspected_refs":[{"path":"src.rs"}],"created_lead_ids":[],"counterevidence":"guard exists","proof_gaps":"caller analysis","follow_up":"inspect caller","continuation":"source_analysis_remaining"}).to_string())?;
	let result = crate::review_unit_results::insert_evidence(
		tx,
		&crate::review_unit_results::NewResultEvidence {
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
fn exact_admission_and_retry_preserve_identity_epochs_and_completed_members() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let batch = exact_batch(tx)?;
				let first = claim(tx, 60)?;
				assert_eq!(first.assigned_units, vec![1]);
				assert_eq!(first.job.parent_job_id, Some(101));
				assert_eq!(first.job.continuation_of_job_id, Some(101));
				assert_eq!(
					unit_holds::get_batch(tx, batch)?.unwrap().admitted_job_id,
					Some(first.job.id)
				);
				tx.execute("UPDATE jobs SET state='queued' WHERE id=?1", [first.job.id])?;
				let retry = claim(tx, 61)?;
				assert_eq!(retry.job.id, first.job.id);
				assert_eq!(retry.assigned_units, vec![1]);
				assert!(retry.resumed);
				assert_eq!(
					tx.query_row(
						"SELECT assignment_epoch FROM review_units WHERE review_unit_id=1",
						[],
						|r| r.get::<_, i64>(0)
					)?,
					1
				);
				assert_eq!(admission::get_spending(tx, 1)?.unwrap().general, 2);
				unit(tx, 2)?;
				tx.execute(
					"UPDATE job_assigned_review_units SET completed=1 WHERE job_id=?1",
					[first.job.id],
				)?;
				assert!(scheduler::initialize_ordinary_batch(tx, first.job.id, 62)?
					.units
					.is_empty());
				assert_eq!(
					tx.query_row(
						"SELECT assignment_epoch FROM review_units WHERE review_unit_id=2",
						[],
						|r| r.get::<_, i64>(0)
					)?,
					0
				);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn ordinary_admission_clamps_deadlines_and_retries_same_batch() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				unit(tx, 1)?;
				tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
				tx.execute("UPDATE review_campaigns SET deadline_at=150 WHERE campaign_id=1", [])?;
				let first = claim(tx, 100)?;
				assert_eq!(first.job.hard_deadline_at, Some(150));
				assert!(first.job.lease_expires_at.unwrap() <= 210);
				assert_eq!(first.assigned_units, vec![1]);
				assert_eq!(first.job.parent_job_id, Some(101));
				assert_eq!(first.job.continuation_of_job_id, None);
				unit(tx, 2)?;
				tx.execute("UPDATE jobs SET state='queued' WHERE id=?1", [first.job.id])?;
				let retry = claim(tx, 101)?;
				assert_eq!(retry.assigned_units, vec![1]);
				assert_eq!(admission::get_spending(tx, 1)?.unwrap().general, 2);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn legacy_verify_precedes_scan_without_campaign_budget_or_fairness() {
	fixture().with_conn(|conn| transaction::immediate(conn,|tx| {
		tx.execute("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(301,1,'scan','queued',0),(302,1,'verify','queued',1)",[])?;
		let first=claim(tx,100)?;
		assert_eq!(first.job.id,302);
		assert_eq!(first.job.lease_expires_at,Some(700));
		assert_eq!(claim(tx,101)?.job.id,301);
		assert_eq!(tx.query_row("SELECT seq FROM scheduler_clock",[],|r|r.get::<_,i64>(0))?,0);
		assert_eq!(admission::get_spending(tx,1)?.unwrap().general,1);
		Ok(())
	})).unwrap();
}

#[test]
fn serialization_failure_rolls_back_job_charge_intent_and_fairness() {
	let db = fixture();
	db.with_conn(|conn| {
		let lead = transaction::immediate(conn, lead)?;
		let result: Result<()> = transaction::immediate(conn, |tx| {
			claim(tx, 10)?;
			Err(crate::Error::Conflict(crate::Conflict::CheckpointEvidence))
		});
		assert!(result.is_err());
		assert_eq!(
			review_intents::get_subject(conn, Subject::Lead(lead))?.unwrap().state,
			review_intents::State::Pending
		);
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get::<_, i64>(0))?, 1);
		assert_eq!(
			conn.query_row("SELECT seq FROM scheduler_clock", [], |r| r.get::<_, i64>(0))?,
			0
		);
		transaction::immediate(conn, |tx| {
			assert_eq!(admission::get_spending(tx, 1)?.unwrap().general, 1);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn canonical_finding_intent_creates_only_selected_verification() {
	fixture().with_conn(|conn| transaction::immediate(conn,|tx| {
		let lead=lead(tx)?;
		let drill=claim(tx,1)?.job.id;
		tx.execute("UPDATE jobs SET head_sha=?2 WHERE id=?1",params![drill,SHA])?;
		let promotion=loupe_core::review_payload::PromotionV1::from_json(&serde_json::json!({
			"version":1,"severity":"high","title":"Remote allocation","description":"Length reaches allocator",
			"identity_family":"allocation","identity_anchor":"request allocator",
			"evidence":{"version":1,"l2_argument":{"attacker_source":"remote request","control":"length","sink":"allocator","reachable_path":"handler to allocator","trust_boundary":"network to memory"},
			"material_locations":[{"role":"sink","file":"src.rs"}],"counterevidence":"guard exists","assumptions_gaps":"caller identity","confidence":"medium"}
		}).to_string())?;
		let profile=loupe_core::review_payload::GeneratedProfile::new("{\"languages\":[\"rust\"]}")?;
		let finding=crate::review_findings::insert(tx,&crate::review_findings::NewFinding {
			repo_id:1,job_id:drill,origin_lead_id:lead,profile_version:1,profile_digest:profile.digest(),reviewed_commit_sha:SHA,promotion:&promotion,
		},2)?;
		leads::close(tx,lead,&leads::Closure::Promoted { finding },2)?;
		review_intents::ensure_verification_intent(tx,finding,drill,NORMAL,2)?;
		let verify=claim(tx,3)?;
		assert_eq!(verify.job.kind,JobKind::Verify);
		assert_eq!(verify.job.parent_job_id,Some(drill));
		assert_eq!(verify.job.continuation_of_job_id,None);
		assert_eq!(verify.job.target_finding_id,Some(finding));
		assert_eq!(review_intents::get_subject(tx,Subject::Finding(finding))?.unwrap().admitted_job_id,Some(verify.job.id));
		assert_eq!(admission::get_spending(tx,1)?.unwrap().general,3);
		Ok(())
	})).unwrap();
}

#[test]
fn preparation_is_only_speculative_job_and_is_charged_once() {
	for recipe in ["bootstrap", "incremental"] {
		fixture().with_conn(|conn| transaction::immediate(conn,|tx| {
			tx.execute("DELETE FROM job_admission_charges",[])?;
			tx.execute("DELETE FROM campaign_admission_spending",[])?;
			tx.execute("DELETE FROM generation_manifests",[])?;
			tx.execute("DELETE FROM jobs",[])?;
			tx.execute("UPDATE review_campaigns SET generation_id=NULL,recipe=?1 WHERE campaign_id=1",[recipe])?;
			let id=create_preparation(tx,1,5)?;
			assert_eq!(get_job(tx,id)?.state,JobState::Queued);
			assert_eq!(admission::get_spending(tx,1)?.unwrap().general,1);
			let first=claim(tx,10)?;
			assert_eq!(first.job.id,id);
			assert_eq!(first.job.attempts,1);
			assert!(first.assigned_units.is_empty());
			assert_eq!(admission::get_spending(tx,1)?.unwrap().general,1);
			Ok(())
		})).unwrap();
	}
}

#[test]
fn branch_named_preparation_can_reach_first_checkout_lease() {
	for recipe in [campaigns::Recipe::Bootstrap, campaigns::Recipe::Incremental] {
		fixture()
			.with_conn(|conn| {
				transaction::immediate(conn, |tx| {
					tx.execute("UPDATE review_campaigns SET state='finished'", [])?;
					tx.execute(
						"UPDATE jobs SET state='succeeded' WHERE state IN('queued','leased')",
						[],
					)?;
					let snapshot = CampaignPolicyV2::default().snapshot()?;
					let campaign = campaigns::create(
						tx,
						&campaigns::NewCampaign {
							repo_id: 1,
							recipe,
							trigger: campaigns::Trigger::Manual,
							requested_base_sha: None,
							target_commit_sha: "main",
							generation_id: None,
							effective_policy: &snapshot,
							deadline_at: Some(10000),
							root_campaign_id: None,
							continuation_of_campaign_id: None,
						},
						1,
					)?;
					let result = create_preparation(tx, campaign, 5);
					assert!(
						result.is_ok(),
						"Unpinned {recipe:?} branch must reach checkout: {result:?}"
					);
					let job = result?;
					let first = claim(tx, 10)?;
					assert_eq!(first.job.id, job);
					assert!(first.job.head_sha.is_none() && first.job.generation_id.is_none());
					assert_eq!(first.job.attempts, 1);
					assert_eq!(admission::get_spending(tx, campaign)?.unwrap().general, 1);
					assert_eq!(campaigns::get(tx, campaign)?.unwrap().target_commit_sha, "main");
					Ok(())
				})
			})
			.unwrap();
	}
}

#[test]
fn stale_rank_and_revoked_worker_cannot_mutate() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				lead(tx)?;
				let policy = scheduler::ClaimPolicy::default();
				let req = request(&policy, 10);
				let mut candidate = admission_candidates::ranked(tx, &req)?.remove(0);
				candidate.stored_score = Some(550);
				assert!(matches!(materialize(tx, &candidate, &req, &[8; 32], 60)?, Outcome::Stale));
				let candidate = admission_candidates::ranked(tx, &req)?.remove(0);
				tx.execute("UPDATE workers SET revoked_at=5 WHERE id=1", [])?;
				assert!(materialize(tx, &candidate, &req, &[8; 32], 60).is_err());
				assert_eq!(
					tx.query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get::<_, i64>(0))?,
					1
				);
				assert_eq!(admission::get_spending(tx, 1)?.unwrap().general, 1);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn malformed_frozen_policy_and_foreign_parent_roll_back() {
	for mutation in [
		"UPDATE review_campaigns SET effective_policy_digest=zeroblob(32) WHERE campaign_id=1",
		"INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,enqueued_at) VALUES(102,1,'survey','succeeded',1,12,0); UPDATE lead_drilldown_intents SET originating_job_id=102",
	] {
		let db = fixture();
		db.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				lead(tx)?;
				tx.execute_batch(mutation)?;
				Ok(())
			})?;
			let before=conn.query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get::<_,i64>(0))?;
			let result = transaction::immediate(conn, |tx| claim(tx, 10));
			assert!(result.is_err(), "{mutation}");
			assert_eq!(conn.query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get::<_, i64>(0))?, before);
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn protected_capacity_preserves_pending_work_and_urgent_retry_costs_nothing() {
	for urgent in [false, true] {
		fixture().with_conn(|conn| transaction::immediate(conn,|tx| {
			let priority=if urgent {crate::admission_policy::AcceptedPriority {band:scheduler::Band::Urgent,score:550}} else {NORMAL};
			let id=lead_with_priority(tx,priority)?;
			tx.execute("UPDATE campaign_admission_spending SET general_spent=56 WHERE campaign_id=1",[])?;
			let policy=scheduler::ClaimPolicy::default();
			let req=request(&policy,10);
			if !urgent {
				assert!(admission_candidates::ranked(tx,&req)?.is_empty());
				assert_eq!(review_intents::get_subject(tx,Subject::Lead(id))?.unwrap().state,review_intents::State::Pending);
				assert!(matches!(leads::get_evidence(tx,id)?,crate::StoredEvidence::Recorded(_)));
			} else {
				let first=claim(tx,10)?;
				assert_eq!(first.job.scheduling_band,Some(scheduler::Band::Urgent));
				assert_eq!(first.job.effective_priority,Some(550));
				assert_eq!(admission::get_spending(tx,1)?.unwrap().urgent,1);
				tx.execute("UPDATE campaign_admission_spending SET urgent_spent=4,verification_spent=4 WHERE campaign_id=1",[])?;
				tx.execute("UPDATE jobs SET state='queued' WHERE id=?1",[first.job.id])?;
				assert_eq!(claim(tx,11)?.job.id,first.job.id);
				assert_eq!(admission::get_spending(tx,1)?.unwrap().total()?,64);
			}
			Ok(())
		})).unwrap();
	}
}

#[test]
fn exact_caller_failure_restores_epoch_hold_charge_and_fairness() {
	let db = fixture();
	db.with_conn(|conn| {
		let batch = transaction::immediate(conn, exact_batch)?;
		let failure: Result<()> = transaction::immediate(conn, |tx| {
			assert_eq!(claim(tx, 60)?.assigned_units, vec![1]);
			Err(Error::Conflict(Conflict::CheckpointEvidence))
		});
		assert!(failure.is_err());
		assert_eq!(
			unit_holds::get_batch(conn, batch)?.unwrap().state,
			review_intents::State::Pending
		);
		assert_eq!(
			conn.query_row(
				"SELECT assignment_epoch FROM review_units WHERE review_unit_id=1",
				[],
				|r| r.get::<_, i64>(0)
			)?,
			0
		);
		assert_eq!(
			conn.query_row("SELECT COUNT(*) FROM job_assigned_review_units", [], |r| r
				.get::<_, i64>(0))?,
			0
		);
		assert_eq!(
			conn.query_row("SELECT seq FROM scheduler_clock", [], |r| r.get::<_, i64>(0))?,
			0
		);
		transaction::immediate(conn, |tx| {
			assert_eq!(admission::get_spending(tx, 1)?.unwrap().general, 1);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn historical_policy_is_not_reinterpreted_for_claim_or_preparation() {
	fixture().with_conn(|conn| transaction::immediate(conn,|tx| {
		let v1=BoundedJson::<loupe_core::text::policy::Payload>::new(&serde_json::to_string(&scheduler::CampaignPolicy::default()).unwrap())?;
		tx.execute("UPDATE review_campaigns SET effective_policy=?1,effective_policy_digest=?2 WHERE campaign_id=1",params![v1.expose(),v1.digest().as_slice()])?;
		tx.execute("UPDATE jobs SET state='queued' WHERE id=101",[])?;
		assert!(matches!(claim(tx,10),Err(Error::Conflict(Conflict::CampaignPolicy))));
		assert!(matches!(create_preparation(tx,1,10),Err(Error::Conflict(Conflict::CampaignPolicy))));
		assert_eq!(get_job(tx,101)?.state,JobState::Queued);
		assert_eq!(admission::get_spending(tx,1)?.unwrap().general,1);
		Ok(())
	})).unwrap();
}

#[test]
fn retry_cannot_change_frozen_token_budget() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				lead(tx)?;
				let job = claim(tx, 10)?.job.id;
				tx.execute("UPDATE jobs SET state='queued',token_budget=42 WHERE id=?1", [job])?;
				Ok(())
			})?;
			let result = transaction::immediate(conn, |tx| claim(tx, 11));
			assert!(result.is_err(), "Execution retry must retain the exact frozen token budget");
			Ok(())
		})
		.unwrap();
}

#[test]
fn pinned_preparation_reuses_profile_and_rejects_incremental_building() {
	for (campaign_recipe, generation_state, expected_recipe) in [
		(campaigns::Recipe::Bootstrap, "active", Some("coverage")),
		(campaigns::Recipe::Incremental, "active", Some("incremental")),
		(campaigns::Recipe::Bootstrap, "building", Some("bootstrap")),
		(campaigns::Recipe::Incremental, "building", None),
	] {
		fixture().with_conn(|conn| transaction::immediate(conn,|tx| {
			tx.execute("UPDATE review_campaigns SET state='finished' WHERE campaign_id=1",[])?;
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101",[])?;
			tx.execute("UPDATE review_generations SET state=?1 WHERE generation_id=11",[generation_state])?;
			let profile_before:Vec<u8>=tx.query_row("SELECT generated_profile_digest FROM review_generations WHERE generation_id=11",[],|r|r.get(0))?;
			let snapshot=CampaignPolicyV2::default().snapshot()?;
			let campaign=campaigns::create(tx,&campaigns::NewCampaign {
				repo_id:1,recipe:campaign_recipe,trigger:campaigns::Trigger::Manual,requested_base_sha:None,target_commit_sha:SHA,generation_id:Some(11),effective_policy:&snapshot,deadline_at:Some(10000),root_campaign_id:None,continuation_of_campaign_id:None,
			},1)?;
			let result=create_preparation(tx,campaign,1);
			if let Some(expected_recipe)=expected_recipe {
				let id=result?;
				let job=get_job(tx,id)?;
				let recipe:serde_json::Value=serde_json::from_str(job.recipe.as_ref().unwrap().expose()).unwrap();
				assert_eq!(recipe["recipe"],expected_recipe);
				assert_eq!(claim(tx,2)?.job.id,id);
				assert_eq!(admission::get_spending(tx,campaign)?.unwrap().general,1);
			} else {
				assert!(result.is_err());
				assert!(admission::get_spending(tx,campaign)?.is_none());
			}
			assert_eq!(tx.query_row("SELECT generated_profile_digest FROM review_generations WHERE generation_id=11",[],|r|r.get::<_,Vec<u8>>(0))?,profile_before);
			Ok(())
		})).unwrap();
	}
}

fn unit(tx: &Transaction<'_>, id: i64) -> Result<()> {
	tx.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_by_job_id,created_at) VALUES(?1,11,?2,'Title','Objective','[{\"path\":\"src.rs\"}]',101,0)", params![id,format!("unit-{id}")])?;
	Ok(())
}

#[test]
fn v2_ordinary_initializer_selects_once_and_retains_empty_marker() {
	review_intents::tests::fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				unit(tx, 1)?;
				let first = scheduler::initialize_ordinary_batch(tx, 101, 1);
				assert!(
					first.is_ok(),
					"V2 ordinary selection must accept frozen V2 sizing: {first:?}"
				);
				assert_eq!(first?.units, vec![1]);
				unit(tx, 2)?;
				assert_eq!(scheduler::initialize_ordinary_batch(tx, 101, 2)?.units, vec![1]);
				tx.execute(
					"UPDATE job_assigned_review_units SET completed=1 WHERE job_id=101",
					[],
				)?;
				let completed = scheduler::initialize_ordinary_batch(tx, 101, 3)?;
				assert!(completed.units.is_empty());
				assert!(completed.resumed);
				Ok(())
			})
		})
		.unwrap();
	review_intents::tests::fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				assert!(scheduler::initialize_ordinary_batch(tx, 101, 1)?.units.is_empty());
				unit(tx, 1)?;
				let retry = scheduler::initialize_ordinary_batch(tx, 101, 2)?;
				assert!(retry.units.is_empty(), "An empty logical batch must not refill on retry");
				assert!(retry.resumed);
				Ok(())
			})
		})
		.unwrap();
}
