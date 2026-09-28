//! Private production transaction seam: do not expose a second mutation API.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::StatusCode;
use loupe_core::inventory_manifest::{ManifestEntry, ManifestHasher};
use loupe_core::review_payload::{GeneratedProfile, PromotionV1};
use loupe_storage::admission_policy::{AcceptedPriority, CampaignPolicyV2};
use loupe_storage::{review_findings, scheduler, terminal_payloads, transaction, workers, Db};
use serde_json::json;
use tower::Service;

use super::*;
use crate as server;
#[path = "reporter.rs"]
mod reporter;

#[tokio::test]
async fn committed_verification_without_dispatch_is_recovered_only_by_admin_retry() {
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
	let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	let ca = Arc::new(loupe_tls::Ca::new("gap").unwrap());
	let certificate = ca.mint_client("gap-worker").unwrap();
	let peer = crate::PeerCert(
		rustls_pemfile::certs(&mut certificate.cert_pem.as_bytes()).next().unwrap().unwrap(),
	);
	let fingerprint = loupe_tls::cert_fingerprint(peer.0.as_ref());
	let db = Arc::new(Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap());
	let token = "g".repeat(43);
	let hash = *blake3::hash(token.as_bytes()).as_bytes();
	let evidence = json!({"version":1,"l2_argument":{"attacker_source":"request","control":"length","sink":"allocator","reachable_path":"producer path","trust_boundary":"network to process"},"material_locations":[{"role":"sink","file":"src.rs"}],"counterevidence":"none known","assumptions_gaps":"source contract","confidence":"high"});
	let promotion=PromotionV1::from_json(&json!({"version":1,"severity":"high","title":"Allocation boundary","description":"Source finding","identity_family":"allocation","identity_anchor":"allocator","evidence":evidence}).to_string()).unwrap();
	let (finding,worker)=db.with_conn(|conn| transaction::immediate(conn,|tx| {
		tx.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(1,'u','github.com','owner','repo','{\"kind\":\"manual\"}',0)",[])?;
		let worker=workers::insert(tx,"gap-worker",workers::WorkerKind::Worker,&fingerprint,now)?;
		let profile=GeneratedProfile::new("{}").unwrap();
		let policy=CampaignPolicyV2::default().snapshot()?;
		tx.execute("INSERT INTO review_generations(generation_id,repo_id,generation_commit_sha,state,workflow_contract_version,profile_version,generated_profile,generated_profile_digest,created_at) VALUES(1,1,?1,'active',1,1,?2,?3,0)",params![sha,profile.expose(),profile.digest().as_slice()])?;
		tx.execute("INSERT INTO review_campaigns(campaign_id,repo_id,recipe,trigger,target_commit_sha,generation_id,state,effective_policy,effective_policy_digest,deadline_at,created_at) VALUES(1,1,'bootstrap','manual',?1,1,'active',?2,?3,?4,0)",params![sha,policy.expose(),policy.digest().as_slice(),now+3600])?;
		tx.execute("INSERT INTO campaign_admission_spending(campaign_id,policy_version,general_spent) VALUES(1,2,1)",[])?;
		tx.execute("INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES(1,1,'allocation','origin',zeroblob(32),'{}',zeroblob(32),?1,0)",[sha])?;
		tx.execute("INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,assigned_lead_id,head_sha,workflow_contract_version,recipe,enqueued_at) VALUES(1,1,'drilldown','succeeded',1,1,1,?1,1,'{\"version\":1,\"phase\":\"drilldown\"}',0)",[sha])?;
		let mut manifest=ManifestHasher::new(sha,1).unwrap();
		manifest.push(&ManifestEntry{raw_path:b"src.rs".to_vec(),git_mode:0o100644,object_id:sha.into()}).unwrap();
		let digest=manifest.finish().unwrap();
		tx.execute("INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,received_entry_count,expected_digest,created_at,sealed_at) VALUES(1,1,1,1,1,?1,0,1)",[digest.as_slice()])?;
		tx.execute("INSERT INTO generation_inventory(generation_id,path,source_path,raw_path,blob_sha,entry_kind,git_mode,manifest_position,disposition,created_at) VALUES(1,'src.rs','src.rs',?1,?2,'tracked',33188,0,'context',0)",params![b"src.rs".as_slice(),sha])?;
		let finding=review_findings::insert(tx,&review_findings::NewFinding{repo_id:1,job_id:1,origin_lead_id:1,profile_version:1,profile_digest:profile.digest(),reviewed_commit_sha:sha,promotion:&promotion},now)?;
		loupe_storage::leads::close(tx,1,&loupe_storage::leads::Closure::Promoted{finding},now)?;
		let intent=review_intents::ensure_verification_intent(tx,finding,1,AcceptedPriority{band:scheduler::Band::Normal,score:0},now)?.unwrap();
		tx.execute("INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,parent_job_id,target_finding_id,worker_id,attempts,lease_expires_at,hard_deadline_at,head_sha,job_capability_hash,prepared_attempt,prepared_capability_hash,prepared_at,workflow_contract_version,scheduling_band,recipe,enqueued_at) VALUES(2,1,'verify','leased',1,1,1,?1,?2,1,?3,?3,?4,?5,1,?5,?6,1,'normal','{\"version\":1,\"phase\":\"verify\"}',?6)",params![finding,worker,now+3600,sha,hash.as_slice(),now])?;
		review_intents::admit_subject(tx,Subject::Finding(finding),intent.revision,2,now)?;
		Ok((finding,workers::find_active_by_fingerprint(tx,&fingerprint)?.unwrap()))
	})).unwrap();
	let mut state =
		AppState::new(db, ca, Arc::new(crate::reporters::GithubReporter::new().unwrap()));
	let stub = reporter::configure(&mut state, finding).await;
	let mut independent = evidence;
	independent["l2_argument"]["reachable_path"] = json!("Independent verifier trace");
	let input=VerificationTerminalV1::from_json(&json!({"version":1,"verdict":"verified","established_rung":"L2","e2e_applicability":"not_applicable","e2e_rationale":"Source-only contract defect","evidence":independent}).to_string()).unwrap();
	let mut headers = HeaderMap::new();
	headers.insert(loupe_proto::JOB_CAPABILITY_HEADER, token.parse().unwrap());
	let (response, dispatch) =
		finish(&state, &AuthedWorker { worker }, &headers, 2, input.clone()).unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(dispatch.map(|(id, _)| id), Some(finding));
	// Deliberately stop before executing the returned delivery action: this is
	// the actual production transaction, not a manually seeded confirmed row.
	assert!(stub.capture.calls.lock().unwrap().is_empty());
	state
		.db
		.with_conn(|conn| {
			assert_eq!(findings::get(conn, finding)?.unwrap().state, FindingState::Confirmed);
			assert!(matches!(terminal_payloads::get(conn, 2)?, StoredEvidence::Recorded(_)));
			Ok(())
		})
		.unwrap();
	let mut replay = axum::http::Request::post("/v1/jobs/2/finalize-verification")
		.header(loupe_proto::PROTOCOL_VERSION_HEADER, "3")
		.header(loupe_proto::JOB_CAPABILITY_HEADER, token)
		.header("content-type", "application/json")
		.body(Body::from(json!({"protocol_version":3,"payload":input}).to_string()))
		.unwrap();
	replay.extensions_mut().insert(peer);
	assert_eq!(crate::router(state.clone()).call(replay).await.unwrap().status(), StatusCode::OK);
	assert!(
		stub.capture.calls.lock().unwrap().is_empty(),
		"receipt replay must not fill the dispatch gap"
	);
	assert_eq!(reporter::admin(&state, finding, "retry-report").await, StatusCode::NO_CONTENT);
	assert_eq!(stub.capture.calls.lock().unwrap().len(), 1);
	state
		.db
		.with_conn(|conn| {
			assert_eq!(findings::get(conn, finding)?.unwrap().state, FindingState::Reported);
			Ok(())
		})
		.unwrap();
}
