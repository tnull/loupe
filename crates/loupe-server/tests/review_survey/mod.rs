//! Public router tests; only accepted checkpoints are seeded while their HTTP
//! producer is developed independently. No lease/terminal authorization bypass.
use loupe_core::review_payload::{ContinuationClass, UnitResultPayloadV1};
use loupe_core::text::{BoundedText, Identifier, RepoPath, SourceRef};
use loupe_storage::{
	generations, review_unit_results, review_units, terminal_payloads, unit_holds, StoredEvidence,
};

use super::*;

fn payload(reason: &str) -> Value {
	json!({"protocol_version":3,"payload":{"version":1,"terminal_reason":reason,
		"continuation":"Keep the remaining source work", "security_model_notes":"<script>literal</script>\n```notes```"}})
}

async fn ready() -> (Fixture, i64) {
	let f = fixture();
	let generation = prepare(&f).await;
	f.state.db.with_conn(|conn| {
		let policy = ReviewPolicy::default().snapshot_v2().unwrap();
		conn.execute("UPDATE review_campaigns SET effective_policy=?2,effective_policy_digest=?3 WHERE campaign_id=?1",params![f.campaign,policy.expose(),policy.digest().as_slice()])?;
		conn.execute("INSERT INTO campaign_admission_spending(campaign_id,policy_version,general_spent) VALUES(?1,2,1)",[f.campaign])?;
		Ok(())
	}).unwrap();
	(f, generation)
}

fn source() -> SourceRef {
	SourceRef { path: RepoPath::new("z.rs").unwrap(), symbol: None }
}

fn unit(f: &Fixture, generation: i64, key: &str, disposition: Option<&str>) -> (i64, Option<i64>) {
	f.state.db.with_conn(|conn|transaction::immediate(conn, |tx| {
		let unit = review_units::create(tx, &review_units::NewUnit {
			generation_id:generation,client_key:&Identifier::new(key)?,title:&BoundedText::new("review")?,
			objective:&BoundedText::new("inspect boundary")?,priority:review_units::Priority::Normal,
			priority_proposal:None,source_refs:&loupe_storage::source_refs::UnitRefs::new(vec![source()])?,
			depends_on:None,closure_criteria:None,semantic_context:None,carried_from:None,created_by_job:Some(f.job),
		}, now())?;
		let result = if let Some(disposition) = disposition {
			let mut value = json!({"format":"loupe.unit_result","version":1,"review_unit_id":unit,
				"assignment_epoch":0,"disposition":disposition,"inspected_refs":[source()],"created_lead_ids":[],
				"counterevidence":"none","proof_gaps":"none","notes":"accepted notes"});
			if disposition == "needs_follow_up" {
				value["follow_up"] = json!("remaining source work");
				value["continuation"] = json!("source_analysis_remaining");
			}
			let payload = UnitResultPayloadV1::from_json(&value.to_string())?;
			let result = review_unit_results::insert_evidence(tx, &review_unit_results::NewResultEvidence {
				generation_id:generation,produced_by_job:f.job,commit_sha:SHA,profile_version:1,payload:&payload,
			}, now())?;
			if disposition == "needs_follow_up" {
				unit_holds::record_follow_up(tx,unit,result,f.job,0,ContinuationClass::SourceAnalysisRemaining,now())?;
			}
			Some(result)
		} else { None };
		Ok((unit,result))
	})).unwrap()
}

fn scalar(f: &Fixture, sql: &str) -> i64 {
	f.state.db.with_conn(|conn| Ok(conn.query_row(sql, [], |r| r.get(0))?)).unwrap()
}

#[tokio::test]
async fn prepared_bootstrap_seals_partial_coverage_and_replays_the_exact_receipt() {
	let (f, generation) = ready().await;
	unit(&f, generation, "unassessed", None);
	let before = scalar(&f, "SELECT COUNT(*) FROM jobs");
	let request_body = payload("completed");
	let (status, first) = request(&f, f.job, "finalize-survey", request_body.clone()).await;
	assert_eq!(status, StatusCode::OK, "{first}");
	assert_eq!(first["receipt"]["summary"]["coverage"], "partial");
	assert_eq!(first["receipt"]["summary"]["missing_results"], 1);
	// The non-UTF-8 entry is explicitly excluded by host sealing; the two
	// addressable entries still need dispositions.
	assert_eq!(first["receipt"]["summary"]["unresolved_inventory"], 2);
	assert_eq!(scalar(&f,"SELECT COUNT(*) FROM review_generations WHERE state='active' AND corroboration_state='pending'"),1);
	assert_eq!(scalar(&f,"SELECT COUNT(*) FROM jobs WHERE state='succeeded' AND worker_id IS NOT NULL AND job_capability_hash IS NULL AND prepared_attempt IS NULL"),1);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM jobs"), before, "no speculative child jobs");
	f.state.db.with_conn(|conn| {
		let StoredEvidence::Recorded(terminal_payloads::TerminalPayload::Survey(stored)) = terminal_payloads::get(conn,f.job)? else { panic!("typed terminal evidence") };
		assert_eq!(serde_json::to_value(stored).unwrap(),request_body["payload"]);
		conn.execute("UPDATE review_campaigns SET state='cancelled'",[])?;
		conn.execute("UPDATE review_generations SET generated_profile='{}',generated_profile_digest=zeroblob(32)",[])?;
		Ok(())
	}).unwrap();
	assert_eq!(
		request(&f, f.job, "finalize-survey", request_body.clone()).await,
		(StatusCode::OK, first.clone())
	);
	f.state
		.db
		.with_conn(|conn| {
			conn.execute("DELETE FROM review_generations", [])?;
			let StoredEvidence::Recorded(terminal_payloads::TerminalPayload::Survey(stored)) =
				terminal_payloads::get(conn, f.job)?
			else {
				panic!("full survey notes must survive generation purge")
			};
			assert_eq!(serde_json::to_value(stored).unwrap(), request_body["payload"]);
			Ok(())
		})
		.unwrap();
	assert_eq!(request(&f, f.job, "finalize-survey", request_body).await, (StatusCode::OK, first));
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 1);
	assert_eq!(
		request(&f, f.job, "finalize-survey", payload("partial")).await.0,
		StatusCode::CONFLICT
	);
}

#[tokio::test]
async fn receipt_and_payload_failures_roll_back_activation_and_success() {
	for table in ["job_terminal_receipts", "job_terminal_payloads"] {
		let (f, generation) = ready().await;
		unit(&f, generation, "held", Some("needs_follow_up"));
		f.state.db.with_conn(|conn| {
			conn.execute_batch(&format!("CREATE TRIGGER fail_terminal BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'injected terminal failure'); END"))?;
			Ok(())
		}).unwrap();
		assert_eq!(
			request(&f, f.job, "finalize-survey", payload("partial")).await.0,
			StatusCode::INTERNAL_SERVER_ERROR
		);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM review_generations WHERE state='building'"), 1);
		assert_eq!(scalar(&f,"SELECT COUNT(*) FROM jobs WHERE state='leased' AND job_capability_hash IS NOT NULL"),1);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 0);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_payloads"), 0);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM survey_continuation_batches"), 0);
	}
}

#[tokio::test]
async fn follow_up_batches_split_overflow_and_keep_exact_members_without_spend() {
	let (f, generation) = ready().await;
	f.state.db.with_conn(|conn| {
		let policy = loupe_storage::admission_policy::CampaignPolicyV2 {survey_units_per_job:2,..Default::default()}.snapshot()?;
		conn.execute("UPDATE review_campaigns SET effective_policy=?2,effective_policy_digest=?3 WHERE campaign_id=?1",params![f.campaign,policy.expose(),policy.digest().as_slice()])?;
		Ok(())
	}).unwrap();
	let expected: Vec<i64> = (0..5)
		.map(|i| unit(&f, generation, &format!("held-{i}"), Some("needs_follow_up")).0)
		.collect();
	let unheld = unit(&f, generation, "ordinary", None).0;
	let before = scalar(&f, "SELECT general_spent FROM campaign_admission_spending");
	let result = post(&f, "finalize-survey", payload("partial")).await;
	assert_eq!(result["receipt"]["summary"]["follow_up_batches"], 3);
	assert_eq!(result["receipt"]["summary"]["follow_up_units"], 5);
	assert_eq!(result["receipt"]["summary"]["missing_results"], 6);
	f.state
		.db
		.with_conn(|conn| {
			let batches = unit_holds::list_batches(conn, f.campaign, 0, 256)?;
			assert_eq!(
				batches.iter().map(|b| b.expected_unit_count).collect::<Vec<_>>(),
				vec![2, 2, 1]
			);
			let mut actual = Vec::new();
			for batch in batches {
				assert_eq!(batch.logical_sequence, 1);
				assert!(batch.not_before.unwrap() > now());
				assert!(batch.admitted_job_id.is_none());
				for hold in unit_holds::batch_holds(conn, batch.batch_id)? {
					actual.push(hold.unit_id);
				}
			}
			assert_eq!(actual, expected);
			assert!(unit_holds::get_hold(conn, unheld)?.is_none());
			Ok(())
		})
		.unwrap();
	assert_eq!(scalar(&f, "SELECT general_spent FROM campaign_admission_spending"), before);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM jobs"), 1);
	assert_eq!(post(&f, "finalize-survey", payload("partial")).await, result);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM survey_continuation_batches"), 3);
}

#[tokio::test]
async fn modern_conclusive_evidence_and_real_corroboration_are_both_required() {
	for historical in [false, true] {
		for corroborated in [false, true] {
			let (f, generation) = ready().await;
			let (_, result) = unit(&f, generation, "done", Some("no_lead_found"));
			f.state.db.with_conn(|conn| {
				conn.execute("UPDATE generation_inventory SET disposition='context'",[])?;
				if corroborated {conn.execute("UPDATE review_generations SET corroboration_state='satisfied'",[])?;}
				if historical {let raw="{}"; conn.execute("UPDATE review_unit_results SET result_payload=?2,result_digest=?3 WHERE review_unit_result_id=?1",params![result,raw,loupe_core::canonical::digest(raw.as_bytes()).as_slice()])?;}
				Ok(())
			}).unwrap();
			let value = post(&f, "finalize-survey", payload("deferred")).await;
			assert_eq!(
				value["receipt"]["summary"]["coverage"],
				if corroborated && !historical { "complete" } else { "partial" }
			);
			assert_eq!(value["receipt"]["summary"]["missing_results"], i64::from(historical));
		}
	}
}

#[tokio::test]
async fn missing_preparation_and_wrong_authority_never_seal() {
	for damage in [
		"unprepared",
		"expired",
		"deadline",
		"old_attempt",
		"wrong_token",
		"wrong_worker",
		"unsupported",
		"owner",
		"profile",
		"unsealed",
	] {
		let (mut f, _) = ready().await;
		match damage {
			"wrong_token" => f.token = "b".repeat(43),
			"wrong_worker" => f.peer = f.other_peer.clone(),
			_ => {
				f.state.db.with_conn(|conn| {
				let sql=match damage {
					"unprepared" => "UPDATE jobs SET prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL",
					"expired" => "UPDATE jobs SET lease_expires_at=0",
					"deadline" => "UPDATE jobs SET hard_deadline_at=0",
					"old_attempt" => "UPDATE jobs SET attempts=attempts+1",
					"unsupported" => "UPDATE jobs SET recipe='{\"phase\":\"survey\",\"version\":1,\"recipe\":\"reconciliation\",\"assignment_key\":\"ordinary\"}'",
					"owner" => "UPDATE generation_manifests SET owner_job_id=NULL",
					"profile" => "UPDATE review_generations SET generated_profile=NULL,generated_profile_digest=NULL",
					"unsealed" => "UPDATE generation_manifests SET sealed_at=NULL",
					_=>unreachable!()
				}; conn.execute(sql,[])?; Ok(())
			}).unwrap();
			},
		}
		let (status, value) = request(&f, f.job, "finalize-survey", payload("partial")).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{damage}: {value}");
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 0);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM review_generations WHERE state='building'"), 1);
	}
}

#[tokio::test]
async fn malformed_or_stale_modern_evidence_rolls_back_without_losing_checkpoint_data() {
	for damage in ["digest", "projection", "epoch", "missing_hold"] {
		let (f, generation) = ready().await;
		unit(&f, generation, "damaged", Some("needs_follow_up"));
		f.state
			.db
			.with_conn(|conn| {
				conn.execute(
					match damage {
						"digest" => "UPDATE review_unit_results SET result_digest=zeroblob(32)",
						"projection" => {
							"UPDATE review_unit_results SET disposition='no_lead_found'"
						},
						"epoch" => "UPDATE review_units SET assignment_epoch=1",
						"missing_hold" => "DELETE FROM review_unit_holds",
						_ => unreachable!(),
					},
					[],
				)?;
				Ok(())
			})
			.unwrap();
		let (status, value) = request(&f, f.job, "finalize-survey", payload("partial")).await;
		assert_eq!(status, StatusCode::CONFLICT, "{damage}: {value}");
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM review_unit_results"), 1);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 0);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM jobs WHERE state='leased'"), 1);
	}
}

#[tokio::test]
async fn ordinary_partial_survey_never_reactivates_or_replaces_the_profile() {
	let (f, generation) = ready().await;
	unit(&f, generation, "unfinished", None);
	f.state.db.with_conn(|conn|transaction::immediate(conn,|tx| {
		generations::activate(tx,generation,42)?;
		tx.execute("UPDATE jobs SET recipe='{\"phase\":\"survey\",\"version\":1,\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}' WHERE id=?1",[f.job])?;
		Ok(())
	})).unwrap();
	let value = post(&f, "finalize-survey", payload("partial")).await;
	assert_eq!(value["receipt"]["summary"]["coverage"], "partial");
	assert_eq!(scalar(&f, "SELECT activated_at FROM review_generations"), 42);
	f.state
		.db
		.with_conn(|conn| {
			let profile: String =
				conn.query_row("SELECT generated_profile FROM review_generations", [], |r| {
					r.get(0)
				})?;
			assert_eq!(profile, "{\"scope\":\"crate\"}");
			let receipt = loupe_storage::terminal_receipt::get(conn, f.job)?.unwrap();
			let audit: Value = serde_json::from_str(receipt.effective_recipe.expose()).unwrap();
			assert_eq!(audit["commit_sha"], SHA);
			assert_eq!(audit["policy"]["version"], 2);
			assert_eq!(audit["profile_version"], 1);
			assert_eq!(audit["manifest_entries"], 3);
			assert_eq!(audit["profile_digest"].as_str().unwrap().len(), 64);
			assert_eq!(audit["manifest_digest"].as_str().unwrap().len(), 64);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn transport_is_strict_bounded_and_no_store_including_rejections() {
	let (f, _) = ready().await;
	let valid = payload("partial").to_string();
	let cases = [
		(
			valid.replace("\"protocol_version\":3", "\"protocol_version\":2"),
			"3",
			"identity",
			StatusCode::BAD_REQUEST,
		),
		(
			valid.replace("\"version\":1", "\"version\":1,\"version\":1"),
			"3",
			"identity",
			StatusCode::BAD_REQUEST,
		),
		(
			valid.replace("\"payload\":{", "\"payload\":{\"inventory_dispositions\":[],"),
			"3",
			"identity",
			StatusCode::BAD_REQUEST,
		),
		(
			valid.replace("\"payload\":{", "\"owner\":1,\"payload\":{"),
			"3",
			"identity",
			StatusCode::BAD_REQUEST,
		),
		(valid.clone(), "2", "identity", StatusCode::BAD_REQUEST),
		(valid.clone(), "3", "gzip", StatusCode::UNSUPPORTED_MEDIA_TYPE),
		(" ".repeat(128 * 1024) + &valid, "3", "identity", StatusCode::PAYLOAD_TOO_LARGE),
	];
	for (body, version, encoding, expected) in cases {
		let mut req = Request::post(format!("/v1/jobs/{}/finalize-survey", f.job))
			.header(PROTOCOL_VERSION_HEADER, version)
			.header(JOB_CAPABILITY_HEADER, &f.token)
			.header("Content-Type", "application/json")
			.header("Content-Encoding", encoding)
			.body(Body::from(body))
			.unwrap();
		req.extensions_mut().insert(f.peer.clone());
		let response = router(f.state.clone()).call(req).await.unwrap();
		assert_eq!(response.status(), expected);
		assert_eq!(response.headers()["cache-control"], "no-store");
		let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
		assert!(serde_json::from_slice::<Value>(&bytes).unwrap()["error"].is_object());
	}
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 0);
	let mut req = Request::post(format!("/v1/jobs/{}/finalize-survey", f.job))
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header(JOB_CAPABILITY_HEADER, &f.token)
		.header("Content-Type", "application/json")
		.body(Body::from(valid))
		.unwrap();
	req.extensions_mut().insert(f.peer.clone());
	let response = router(f.state.clone()).call(req).await.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(response.headers()["cache-control"], "no-store");
	let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
	assert!(
		!String::from_utf8_lossy(&bytes).contains("script"),
		"accepted notes are retained, not reflected in bounded receipt"
	);
}

#[tokio::test]
async fn replay_does_not_disclose_existence_to_the_wrong_identity() {
	let (mut f, _) = ready().await;
	post(&f, "finalize-survey", payload("partial")).await;
	let correct_token = f.token.clone();
	f.token = "b".repeat(43);
	let wrong_token = request(&f, f.job, "finalize-survey", payload("deferred")).await;
	f.token = correct_token;
	f.peer = f.other_peer.clone();
	let wrong_worker = request(&f, f.job, "finalize-survey", payload("deferred")).await;
	let missing = request(&f, 999999, "finalize-survey", payload("deferred")).await;
	assert_eq!(wrong_token, wrong_worker);
	assert_eq!(wrong_worker, missing);
	assert_eq!(missing.0, StatusCode::FORBIDDEN);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 1);
}

async fn exact_continuation(f: &mut Fixture) -> i64 {
	post(f, "finalize-survey", payload("partial")).await;
	let job=f.state.db.with_conn(|conn|transaction::immediate(conn,|tx| {
		let batch=unit_holds::list_batches(tx,f.campaign,0,256)?.remove(0);
		// Scheduling itself is tested at the unified selector integration. This
		// fixture only makes an exact, due admission for the HTTP consumer.
		tx.execute("UPDATE survey_continuation_batches SET not_before=?2 WHERE batch_id=?1",params![batch.batch_id,now()-1])?;
		tx.execute("INSERT INTO jobs(repo_id,kind,state,campaign_id,generation_id,parent_job_id,continuation_of_job_id,worker_id,attempts,lease_expires_at,hard_deadline_at,job_capability_hash,workflow_contract_version,scheduling_band,recipe,enqueued_at)
		SELECT repo_id,'survey','leased',campaign_id,generation_id,id,id,worker_id,1,?2,?2,?3,1,'normal','{\"version\":1,\"phase\":\"survey\",\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}',?4 FROM jobs WHERE id=?1",params![f.job,now()+3600,blake3::hash(f.token.as_bytes()).as_bytes().as_slice(),now()])?;
		let job=tx.last_insert_rowid();
		unit_holds::admit_exact_batch(tx,batch.batch_id,job,now())?;
		// The Q integration replaces pin-target's legacy V1 initializer. Seed
		// only its trusted host confirmation here, not survey domain authority.
		let hash=*blake3::hash(f.token.as_bytes()).as_bytes();
		loupe_storage::host_preparation::confirm(tx,loupe_storage::jobs::ActiveLease {
			identity:loupe_storage::jobs::LeaseIdentity {job_id:job,worker_id:f.worker,capability_hash:&hash},now:now()
		},loupe_core::JobKind::Survey,SHA)?;
		Ok(job)
	})).unwrap();
	f.job = job;
	job
}

#[tokio::test]
async fn zero_progress_continuation_transfers_holds_atomically_with_receipt() {
	for inject in [true, false] {
		let (mut f, generation) = ready().await;
		let (unit, _) = unit(&f, generation, "held", Some("needs_follow_up"));
		let original_job = f.job;
		exact_continuation(&mut f).await;
		if inject {
			f.state.db.with_conn(|conn| {
			conn.execute_batch("CREATE TRIGGER fail_payload BEFORE INSERT ON job_terminal_payloads BEGIN SELECT RAISE(ABORT,'fail after hold movement'); END")?;
			Ok(())
		}).unwrap();
		}
		let (status, value) = request(&f, f.job, "finalize-survey", payload("partial")).await;
		assert_eq!(
			status,
			if inject { StatusCode::INTERNAL_SERVER_ERROR } else { StatusCode::OK },
			"{value}"
		);
		f.state
			.db
			.with_conn(|conn| {
				let holds = unit_holds::get_hold(conn, unit)?.unwrap();
				assert_eq!(holds.producing_job_id, original_job);
				assert_eq!(holds.source_assignment_epoch, 0);
				assert_eq!(review_units::get(conn, unit)?.unwrap().assignment_epoch, 1);
				let batches = unit_holds::list_batches(conn, f.campaign, 0, 256)?;
				assert_eq!(batches.len(), if inject { 1 } else { 2 });
				assert_eq!(
					batches[0].state,
					if inject {
						loupe_storage::review_intents::State::Admitted
					} else {
						loupe_storage::review_intents::State::Complete
					}
				);
				assert_eq!(holds.pending_batch_id, Some(batches.last().unwrap().batch_id));
				assert!(!conn.query_row(
					"SELECT completed FROM job_assigned_review_units WHERE job_id=?1",
					[f.job],
					|r| r.get::<_, bool>(0)
				)?);
				Ok(())
			})
			.unwrap();
		if !inject {
			assert_eq!(value["receipt"]["summary"]["coverage"], "partial");
			assert_eq!(value["receipt"]["summary"]["follow_up_units"], 1);
			assert_eq!(post(&f, "finalize-survey", payload("partial")).await, value);
		}
	}
}

#[tokio::test]
async fn ordinary_conclusive_results_need_exact_assignments_not_creator_identity() {
	let (f, generation) = ready().await;
	unit(&f, generation, "not-assigned", Some("no_lead_found"));
	f.state.db.with_conn(|conn|transaction::immediate(conn,|tx| {
		generations::activate(tx,generation,now())?;
		tx.execute("UPDATE jobs SET recipe='{\"phase\":\"survey\",\"version\":1,\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}' WHERE id=?1",[f.job])?;
		Ok(())
	})).unwrap();
	let (status, value) = request(&f, f.job, "finalize-survey", payload("completed")).await;
	assert_eq!(
		status,
		StatusCode::CONFLICT,
		"ordinary survey creation is not exact assignment authority: {value}"
	);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 0);
}
