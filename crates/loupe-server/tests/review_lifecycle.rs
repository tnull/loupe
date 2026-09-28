//! Server orchestration with explicit worker-state fixtures. Storage tests
//! exercise actual bootstrap/coverage/incremental claims without a reverse dependency.
use loupe_core::text::policy::Payload;
use loupe_core::text::BoundedJson;
use loupe_core::{JobKind, JobState};
use loupe_server::review::campaign;
use loupe_server::review::policy::ReviewPolicy;
use loupe_storage::{
	admission_candidates, admission_claim, campaigns, generations, jobs, review_unit_results,
	transaction,
};
use rusqlite::{params, Transaction};

// Pinning only accepts complete object ids.
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// B3 intentionally cannot lease phase jobs through the public runtime path.
// Once B4 enables it, the combined lifecycle test should use that path.
fn lease_fixture(
	tx: &Transaction<'_>, job_id: i64, worker: i64,
) -> loupe_storage::Result<jobs::JobRow> {
	assert_eq!(
		tx.execute(
			"UPDATE jobs SET state='leased',worker_id=?2,attempts=1,head_sha='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE id=?1 AND state='queued'",
			params![job_id, worker],
		)?,
		1
	);
	Ok(jobs::get(tx, job_id)?.unwrap())
}

#[test]
fn bootstrap_to_coverage_preserves_the_profile_and_activation() {
	let db =
		loupe_storage::Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap();
	db.with_conn(|c| transaction::immediate(c, |tx| {
		tx.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(1,'u','github.com','o','r','{\"kind\":\"manual\"}',0)",[])?;
		let worker=loupe_storage::workers::insert(tx,"lifecycle",loupe_storage::workers::WorkerKind::Worker,&[7;32],0)?;
		let opened=campaign::open(tx,&campaign::OpenCampaign{repo_id:1,trigger:"manual".parse().unwrap(),requested_ref:campaign::RequestedRef::Branch("main"),base_sha:None,kind_hint:campaign::KindHint::Incremental},&ReviewPolicy::default(),0).unwrap();
		let campaign::Opened::Created{campaign_id,job_id}=opened else {panic!("new campaign")};
		let generation=campaign::pin(tx,campaign_id,job_id,SHA,1).unwrap();
		let bootstrap=lease_fixture(tx,job_id,worker)?;
		assert_eq!(bootstrap.kind,JobKind::Survey);
		assert_eq!(bootstrap.generation_id,Some(generation));
		let recipe:serde_json::Value=serde_json::from_str(bootstrap.recipe.as_ref().unwrap().expose()).unwrap();
		assert_eq!(recipe["recipe"],"bootstrap");
		let payload=BoundedJson::<Payload>::new("{}")?;
		generations::set_profile(tx,generation,1,&payload)?;
		tx.execute("UPDATE review_generations SET inventory_digest=zeroblob(32) WHERE generation_id=?1",[generation])?;
		tx.execute("INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,received_entry_count,expected_digest,created_at,sealed_at) VALUES(?1,1,?2,1,1,zeroblob(32),0,0)",params![generation,job_id])?;
		tx.execute("INSERT INTO generation_inventory(generation_id,path,source_path,raw_path,manifest_position,git_mode,blob_sha,entry_kind,disposition,disposition_reason,created_at) VALUES(?1,'src.rs','src.rs',?2,0,33188,?3,'tracked','context','fixture source',0)",params![generation,b"src.rs".as_slice(),SHA])?;
		for (i,band) in ["background","normal","urgent","high","normal","urgent"].iter().enumerate() {
			tx.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,priority_band,created_by_job_id,created_at) VALUES(?1,?2,?3,'t','o','[{\"path\":\"src.rs\"}]',?4,?5,?1)",params![i as i64+1,generation,format!("unit-{i}"),band,job_id])?;
		}
		let record=|unit,job|->loupe_storage::Result<()> {
			let epoch:i64=tx.query_row("SELECT assignment_epoch FROM review_units WHERE review_unit_id=?1",[unit],|r|r.get(0))?;
			let evidence=loupe_core::review_payload::UnitResultPayloadV1::from_json(&serde_json::json!({"format":"loupe.unit_result","version":1,"review_unit_id":unit,"assignment_epoch":epoch,"disposition":"no_lead_found","inspected_refs":[{"path":"src.rs"}],"created_lead_ids":[],"counterevidence":"Source guard is present","proof_gaps":"No remaining gap"}).to_string())?;
			let result=review_unit_results::insert_evidence(tx,&review_unit_results::NewResultEvidence{generation_id:generation,produced_by_job:job,commit_sha:SHA,profile_version:1,payload:&evidence},3)?;
			loupe_storage::unit_holds::release_conclusive(tx,unit,result,job,epoch,3)
		};
		for unit in [1,2] {record(unit,job_id)?;}
		assert_eq!(campaign::replenish(tx,campaign_id,3).unwrap(),None);
		// B5's finalize supplies the terminal transition and checkpoint envelope.
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=3 WHERE id=?1",[job_id])?;
		campaign::activate_generation(tx,campaign_id,3).unwrap();
		assert_eq!(campaign::replenish(tx,campaign_id,3)?,None);
		let policy=ReviewPolicy::default().claim_policy();
		let req=admission_candidates::Request{worker_id:worker,legacy_kinds:&[],phase_kinds:&[JobKind::Survey],now:3,policy:&policy,limit:1};
		let candidates=admission_candidates::ranked(tx,&req)?;
		assert_eq!(candidates.len(),1);
		let admission_claim::Outcome::Uncommitted(claimed)=admission_claim::materialize(tx,&candidates[0],&req,&[5;32],900)? else {panic!("winning coverage candidate")};
		assert_eq!(claimed.assigned_units,vec![3,6,4,5]);
		let batch=claimed.job;
		let coverage=batch.id;
		tx.execute("UPDATE jobs SET head_sha=?2 WHERE id=?1",params![coverage,SHA])?;
		assert_eq!(batch.kind,JobKind::Survey);
		assert_eq!(batch.generation_id,Some(generation));
		assert_eq!(batch.continuation_of_job_id,None,"ordinary work is not a logical continuation");
		let recipe:serde_json::Value=serde_json::from_str(batch.recipe.as_ref().unwrap().expose()).unwrap();
		assert_eq!(recipe["recipe"],"coverage");
		// Typed accepted results close exactly the real admission's four members.
		for unit in [3,6,4,5] {record(unit,coverage)?;}
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=5 WHERE id=?1",[coverage])?;
		assert_eq!(campaign::replenish(tx,campaign_id,5).unwrap(),None);
		assert!(generations::coverage_rollup(tx,generation)?.complete());
		let after=generations::get(tx,generation)?.unwrap();
		assert_eq!(after.profile_version,1);
		assert_eq!(after.activated_at,Some(3));
		assert_eq!(campaign::try_finish(tx,campaign_id,5).unwrap(),Some(campaign::Finish::Completed));
		let row=campaigns::get(tx,campaign_id)?.unwrap();
		assert_eq!(row.state,campaigns::State::Finished);
		assert!(row.terminal_counts.is_some());

		// The activated baseline survives campaign boundaries. The next
		// incremental survey reuses it, including profile and activation time.
		let opened=campaign::open(tx,&campaign::OpenCampaign{repo_id:1,trigger:"manual".parse().unwrap(),requested_ref:campaign::RequestedRef::Pinned(SHA),base_sha:Some(SHA),kind_hint:campaign::KindHint::Incremental},&ReviewPolicy::default(),6).unwrap();
		let campaign::Opened::Created{campaign_id:second,job_id:initial}=opened else {panic!("second campaign")};
		let row=campaigns::get(tx,second)?.unwrap();
		assert_eq!(row.recipe,campaigns::Recipe::Incremental);
		assert_eq!(row.generation_id,Some(generation));
		let incremental=lease_fixture(tx,initial,worker)?;
		assert_eq!(incremental.kind,JobKind::Survey);
		assert_eq!(incremental.generation_id,Some(generation));
		let recipe:serde_json::Value=serde_json::from_str(incremental.recipe.as_ref().unwrap().expose()).unwrap();
		assert_eq!(recipe["recipe"],"incremental");
		// Storage's companion claim test checks that this baseline yields
		// an empty incremental batch after all units have been completed.
		// Explicit queued retry fixture exercises campaign deadline cleanup;
		// production never speculatively queues a second preparation job.
		tx.execute("INSERT INTO jobs(repo_id,kind,state,campaign_id,generation_id,enqueued_at) VALUES(1,'survey','queued',?1,?2,7)",params![second,generation])?;
		let queued=tx.last_insert_rowid();
		let deadline=row.deadline_at.unwrap();
		assert_eq!(campaign::try_finish(tx,second,deadline).unwrap(),None);
		assert_eq!(jobs::get(tx,queued)?.unwrap().state,JobState::Cancelled);
		assert_eq!(jobs::get(tx,initial)?.unwrap().state,JobState::Leased);
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=?2 WHERE id=?1",params![initial,deadline+1])?;
		assert_eq!(campaign::try_finish(tx,second,deadline+1).unwrap(),Some(campaign::Finish::DeadlineReached));
		let after=generations::get(tx,generation)?.unwrap();
		assert_eq!(after.profile_version,1);
		assert_eq!(after.generated_profile.as_ref(),Some(&payload));
		assert_eq!(after.activated_at,Some(3));
		Ok(())
	})).unwrap();
}
