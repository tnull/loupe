//! Shares the real router/mTLS host fixture, not a bypass around phase authority.
use loupe_core::review_candidates::CandidateKind;
use loupe_core::text::{Anchor, BoundedJson, Identifier};
use loupe_storage::identity::Identity;
use loupe_storage::{checkpoints, duplicate_candidates, generations, leads};

use super::*;

async fn ready() -> (Fixture, i64) {
	let f = fixture();
	let generation = prepare(&f).await;
	f.state.db.with_conn(|conn| {
		let policy=ReviewPolicy::default().snapshot_v2().unwrap();
		conn.execute("UPDATE review_campaigns SET effective_policy=?2,effective_policy_digest=?3 WHERE campaign_id=?1",params![f.campaign,policy.expose(),policy.digest().as_slice()])?;
		conn.execute("INSERT INTO campaign_admission_spending(campaign_id,policy_version,general_spent) VALUES(?1,2,1)",[f.campaign])?;
		conn.execute("UPDATE jobs SET soft_deadline_at=?2,submit_by=?2,token_budget=123 WHERE id=?1",params![f.job,now()+3000])?;
		Ok(())
	}).unwrap();
	(f, generation)
}

async fn get(f: &Fixture, route: &str) -> (StatusCode, Value) {
	let mut req = Request::get(format!("/v1/jobs/{}/{route}", f.job))
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header(JOB_CAPABILITY_HEADER, &f.token)
		.body(Body::empty())
		.unwrap();
	req.extensions_mut().insert(f.peer.clone());
	response(f, req).await
}

fn lead(
	tx: &rusqlite::Transaction<'_>, generation: i64, job: i64, anchor: &str,
) -> loupe_storage::Result<i64> {
	let identity = Identity {
		family: Identifier::new("auth-bypass")?,
		anchor: Anchor::new(anchor)?,
		instance: None,
	};
	let result = leads::submit(
		tx,
		&leads::NewLead {
			generation_id: generation,
			unit_id: None,
			identity: &identity,
			payload: &BoundedJson::new(r#"{"secret":"do not disclose evidence body"}"#)?,
			commit_sha: SHA,
			priority: loupe_storage::review_units::Priority::Normal,
			priority_proposal: None,
			supersedes: None,
			created_by_job: Some(job),
		},
		now(),
	)?;
	let leads::Submitted::Created(id) = result else { panic!("new lead") };
	Ok(id)
}

fn issued_count(f: &Fixture) -> i64 {
	f.state
		.db
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				checkpoints::accepted_count(
					tx,
					f.job,
					checkpoints::Operation::IssueDuplicateCandidates,
				)
			})
		})
		.unwrap()
}

#[tokio::test]
async fn limits_use_frozen_quota_and_do_not_guess_host_spending() {
	let (mut f, _) = ready().await;
	Arc::make_mut(&mut f.state.review_policy).max_leads_per_survey = 99;
	let (status, value) = get(&f, "limits").await;
	assert_eq!(status, StatusCode::OK, "{value}");
	assert_eq!(value["new_units"], json!({"limit":32,"remaining":32}));
	assert_eq!(value["leads"], json!({"limit":16,"remaining":16}));
	assert_eq!(value["siblings"], json!({"limit":0,"remaining":0}));
	assert_eq!(value["campaign_jobs_admitted"], 1);
	assert_eq!(value["campaign_general_remaining"], 55);
	assert_eq!(value["tokens"], json!({"status":"host_enforced","limit":123,"spent":"unknown"}));
	assert_eq!(value["proof_capacity"], "unavailable");
	assert_eq!(value["artifact_capacity"], "unavailable");
	assert_eq!(value["output_capacity"], "unavailable");
	f.state
		.db
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				checkpoints::run(
					tx,
					f.job,
					checkpoints::Operation::SubmitLead,
					&Identifier::new("counted")?,
					&[9; 32],
					now(),
					|_| Ok(BoundedJson::new("{}")?),
				)?;
				tx.execute(
					"UPDATE jobs SET attempts=attempts+1,prepared_attempt=attempts+1 WHERE id=?1",
					[f.job],
				)?;
				Ok(())
			})
		})
		.unwrap();
	let (_, after) = get(&f, "limits").await;
	assert_eq!(after["leads"], json!({"limit":16,"remaining":15}));
	assert_eq!(after["campaign_jobs_admitted"], 1);
}

#[tokio::test]
async fn candidates_are_minimal_same_project_and_exact_query_replays_are_frozen() {
	let (f, generation) = ready().await;
	let first=f.state.db.with_conn(|conn|transaction::immediate(conn,|tx| {
		let first=lead(tx,generation,f.job,"public handler")?;
		tx.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(2,'other-url','github.com','private','repo','{\"kind\":\"manual\"}',0)",[])?;
		let other=generations::create(tx,&generations::NewGeneration {repo_id:2,predecessor_generation_id:None,commit_sha:SHA,workflow_contract_version:1},now())?;
		tx.execute("INSERT INTO jobs(id,repo_id,kind,state,generation_id,enqueued_at) VALUES(1000,2,'scan','succeeded',?1,0)",[other])?;
		lead(tx,other,1000,"private handler")?;
		Ok(first)
	})).unwrap();
	let (status, value) = get(&f, "lead-candidates?query=auth&limit=20").await;
	assert_eq!(status, StatusCode::OK, "{value}");
	assert_eq!(value["candidates"].as_array().unwrap().len(), 1);
	assert_eq!(value["candidates"][0]["id"], first);
	assert!(!value.to_string().contains("secret") && !value.to_string().contains("private"));
	f.state
		.db
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				lead(tx, generation, f.job, "later handler")?;
				assert!(duplicate_candidates::issued_target(
					tx,
					f.job,
					1,
					CandidateKind::Lead,
					first
				)?);
				assert!(!duplicate_candidates::issued_target(
					tx,
					1000,
					1,
					CandidateKind::Lead,
					first
				)?);
				assert!(!duplicate_candidates::issued_target(
					tx,
					f.job,
					2,
					CandidateKind::Lead,
					first
				)?);
				Ok(())
			})
		})
		.unwrap();
	assert_eq!(get(&f, "lead-candidates?limit=20&query=auth").await.1, value);
	assert_eq!(issued_count(&f), 1);
	let (_, new) = get(&f, "lead-candidates?query=handler&limit=20").await;
	assert_eq!(new["candidates"].as_array().unwrap().len(), 2);
	f.state
		.db
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				tx.execute(
					"UPDATE leads SET commit_sha=?2 WHERE lead_id=?1",
					params![first, NEXT_SHA],
				)?;
				assert!(!duplicate_candidates::issued_target(
					tx,
					f.job,
					1,
					CandidateKind::Lead,
					first
				)?);
				Ok(())
			})
		})
		.unwrap();
}

#[tokio::test]
async fn candidate_query_quota_is_durable_across_attempts_and_replay_is_free() {
	let (f, _) = ready().await;
	for index in 0..32 {
		let (status, value) = get(&f, &format!("lead-candidates?query=empty{index}")).await;
		assert_eq!(status, StatusCode::OK, "{value}");
	}
	assert_eq!(issued_count(&f), 32);
	f.state
		.db
		.with_conn(|conn| {
			conn.execute(
				"UPDATE jobs SET attempts=attempts+1,prepared_attempt=attempts+1 WHERE id=?1",
				[f.job],
			)?;
			Ok(())
		})
		.unwrap();
	assert_eq!(get(&f, "lead-candidates?query=empty0&limit=10").await.0, StatusCode::OK);
	let (status, error) = get(&f, "lead-candidates?query=empty33").await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(error["error"]["code"], "checkpoint_limit");
	assert_eq!(issued_count(&f), 32);
	assert_eq!(get(&f, "limits").await.1["candidate_queries"]["remaining"], 0);
}

#[tokio::test]
async fn context_transport_rejects_unknown_duplicate_oversized_and_encoded_input() {
	let (f, _) = ready().await;
	for route in [
		"limits?invented=1".to_string(),
		"lead-candidates?query=auth&limit=0".into(),
		"lead-candidates?query=auth&limit=21".into(),
		"lead-candidates?query=auth&limit=1&limit=2".into(),
		"lead-candidates?query=auth&query=other".into(),
		"lead-candidates?query=auth&unknown=x".into(),
		format!("lead-candidates?query={}", "a".repeat(501)),
		format!("lead-candidates?query={}", "%F0%9F%98%80".repeat(251)),
		format!("lead-candidates?query={}", "a".repeat(8193)),
	] {
		let (status, error) = get(&f, &route).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{route}: {error}");
		assert!(error["error"]["code"].is_string());
	}
	for route in ["limits", "lead-candidates?query=auth"] {
		for (body, encoding) in [("x", None), ("", Some("gzip"))] {
			let mut req = Request::get(format!("/v1/jobs/{}/{route}", f.job))
				.header(PROTOCOL_VERSION_HEADER, "3")
				.header(JOB_CAPABILITY_HEADER, &f.token);
			if let Some(encoding) = encoding {
				req = req.header("content-encoding", encoding);
			}
			let mut req = req.body(Body::from(body)).unwrap();
			req.extensions_mut().insert(f.peer.clone());
			let (status, error) = response(&f, req).await;
			assert!(status.is_client_error(), "{status}: {error}");
			assert!(error["error"]["code"].is_string());
		}
	}
	assert_eq!(issued_count(&f), 0);
}

#[tokio::test]
async fn context_denials_do_not_issue_candidates_or_disclose_limits() {
	for defect in
		["wrong_worker", "wrong_capability", "expired", "cancelled", "unprepared", "legacy_verify"]
	{
		let (mut f, _) = ready().await;
		match defect {
			"wrong_worker"=>f.peer=f.other_peer.clone(),
			"wrong_capability"=>f.token="b".repeat(43),
			_=>f.state.db.with_conn(|conn| {
				let sql=match defect {"expired"=>"UPDATE jobs SET lease_expires_at=0 WHERE id=?1",
					"cancelled"=>"UPDATE jobs SET state='cancelled',job_capability_hash=NULL WHERE id=?1",
					"unprepared"=>"UPDATE jobs SET prepared_attempt=NULL,prepared_at=NULL,prepared_capability_hash=NULL WHERE id=?1",
					_=>"UPDATE jobs SET kind='verify',campaign_id=NULL WHERE id=?1"};
				conn.execute(sql,[f.job])?;Ok(())
			}).unwrap(),
		}
		for route in ["limits", "lead-candidates?query=auth"] {
			let (status, error) = get(&f, route).await;
			if defect == "unprepared" && route == "limits" {
				assert_eq!(status, StatusCode::OK, "limits do not issue source authority");
			} else {
				assert_eq!(status, StatusCode::FORBIDDEN, "{defect} {route}: {error}");
				assert_eq!(error["error"]["code"], "denied");
			}
		}
		assert_eq!(issued_count(&f), 0);
	}
}

#[tokio::test]
async fn phase_verification_has_limits_but_no_candidate_search() {
	let (f, _) = ready().await;
	f.state.db.with_conn(|conn| {
		conn.execute("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,created_at) VALUES(1,1,?1,'review','high','title','body','phase',0)",[f.job])?;
		conn.execute("UPDATE jobs SET kind='verify',target_finding_id=1,recipe='{\"version\":1,\"phase\":\"verify\"}' WHERE id=?1",[f.job])?;
		Ok(())
	}).unwrap();
	let (status, value) = get(&f, "limits").await;
	assert_eq!(status, StatusCode::OK, "{value}");
	for field in ["new_units", "leads", "siblings", "candidate_queries"] {
		assert_eq!(value[field], json!({"limit":0,"remaining":0}));
	}
	assert_eq!(get(&f, "lead-candidates?query=auth").await.0, StatusCode::FORBIDDEN);
	assert_eq!(issued_count(&f), 0);
}

#[tokio::test]
async fn candidate_limit_and_response_boundary_apply_to_complete_projection() {
	let (f, generation) = ready().await;
	f.state
		.db
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				for index in 0..24 {
					lead(tx, generation, f.job, &format!("entry boundary {index}"))?;
				}
				Ok(())
			})
		})
		.unwrap();
	let mut req = Request::get(format!("/v1/jobs/{}/lead-candidates?query=auth&limit=20", f.job))
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header(JOB_CAPABILITY_HEADER, &f.token)
		.body(Body::empty())
		.unwrap();
	req.extensions_mut().insert(f.peer.clone());
	let response = router(f.state.clone()).call(req).await.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(response.headers()["cache-control"], "no-store");
	let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
	let value: Value = serde_json::from_slice(&bytes).unwrap();
	assert_eq!(value["candidates"].as_array().unwrap().len(), 20);
	assert_eq!(issued_count(&f), 1);
}

#[tokio::test]
async fn limits_stop_at_the_earlier_campaign_deadline() {
	let (f, _) = ready().await;
	let cutoff = now() + 10;
	f.state
		.db
		.with_conn(|conn| {
			conn.execute(
				"UPDATE review_campaigns SET deadline_at=?2 WHERE campaign_id=?1",
				params![f.campaign, cutoff],
			)?;
			Ok(())
		})
		.unwrap();
	let (status, value) = get(&f, "limits").await;
	assert_eq!(status, StatusCode::OK, "{value}");
	assert_eq!(
		value["hard_deadline_at"], cutoff,
		"analysis cutoff must include the campaign deadline"
	);
	assert!(value["soft_deadline_at"].as_i64().unwrap() <= cutoff);
	assert!(value["submit_by"].as_i64().unwrap() <= cutoff);
	assert!(value["remaining_seconds"].as_u64().unwrap() <= 10);
}
