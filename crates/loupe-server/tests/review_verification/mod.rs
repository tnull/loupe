//! Authenticated router tests. Promotion uses its real endpoint; verification
//! admission is explicit setup while public phase claims remain closed.
use loupe_core::review_payload::VerificationTerminalV1;
use loupe_server as server;
use loupe_storage::{finding_details, findings, review_intents, terminal_payloads, StoredEvidence};

use super::*;
mod reporter;

fn body(payload: Value) -> Value {
	json!({"protocol_version":3,"payload":payload})
}
fn verified() -> Value {
	let mut evidence = drilldown_terminal::promote()["payload"]["promotion"]["evidence"].clone();
	evidence["l2_argument"]["reachable_path"]=json!("Independent verifier: the accepted length reaches allocation through parse_packet.\nAll intermediate checks were traced.");
	body(
		json!({"version":1,"verdict":"verified","established_rung":"L2","e2e_applicability":"not_applicable",
		"e2e_rationale":"A source-level contract violation with no observable execution target.","evidence":evidence,"notes":"Independent notes\nretained in full."}),
	)
}
fn rejected() -> Value {
	body(
		json!({"version":1,"verdict":"rejected","counterargument":{"argument":"The verifier independently established a dominating guard.\nThe proposed path is unreachable.","source_refs":[{"path":"z.rs"}]},"notes":"Rejection notes"}),
	)
}
fn inconclusive(class: &str) -> Value {
	body(
		json!({"version":1,"verdict":"inconclusive","blocker":if class=="awaiting_proof_infrastructure" {"awaiting proof infrastructure"}else{"Unresolved source work\nrequires further inspection"},
		"continuation":class,"partial_evidence":{"argument":"The first caller is understood.\nThe second remains untraced.","source_refs":[{"path":"cafe\u{301}.rs"}]},
		"retry_explanation":"Revisit the untraced caller\nafter the frozen delay","notes":"No security verdict inferred."}),
	)
}
async fn ready() -> (Fixture, i64, i64) {
	ready_fixture(fixture()).await
}
async fn ready_fixture(f: Fixture) -> (Fixture, i64, i64) {
	let (f, generation, _) = drilldown_terminal::ready_fixture(f).await;
	let finding = post(&f, "finalize-drilldown", drilldown_terminal::promote()).await["receipt"]
		["summary"]["promoted_finding_id"]
		.as_i64()
		.unwrap();
	let token = "v".repeat(43);
	let job=f.state.db.with_conn(|conn| transaction::immediate(conn,|tx| {
		let intent=review_intents::get_subject(tx,review_intents::Subject::Finding(finding))?.unwrap();
		tx.execute("INSERT INTO jobs(repo_id,kind,state,campaign_id,generation_id,parent_job_id,target_finding_id,worker_id,attempts,lease_expires_at,hard_deadline_at,job_capability_hash,workflow_contract_version,scheduling_band,recipe,enqueued_at)
			VALUES(1,'verify','leased',?1,?2,?3,?4,?5,1,?6,?6,?7,1,'urgent','{\"version\":1,\"phase\":\"verify\"}',?8)",params![f.campaign,generation,f.job,finding,f.worker,now()+3600,blake3::hash(token.as_bytes()).as_bytes().as_slice(),now()])?;
		let job=tx.last_insert_rowid();
		review_intents::admit_subject(tx,review_intents::Subject::Finding(finding),intent.revision,job,now())?;
		Ok(job)
	})).unwrap();
	let f = Fixture {
		state: f.state,
		peer: f.peer,
		other_peer: f.other_peer,
		worker: f.worker,
		campaign: f.campaign,
		job,
		token,
	};
	post(&f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await;
	(f, generation, finding)
}
fn scalar(f: &Fixture, sql: &str) -> i64 {
	f.state.db.with_conn(|conn| Ok(conn.query_row(sql, [], |row| row.get(0))?)).unwrap()
}
fn execute(f: &Fixture, sql: &str) {
	f.state
		.db
		.with_conn(|conn| {
			conn.execute_batch(sql)?;
			Ok(())
		})
		.unwrap()
}

#[tokio::test]
async fn verified_retains_an_independent_argument_and_seals_a_constant_receipt() {
	let (f, _, finding) = ready().await;
	let input = verified();
	let (status, reply) = request(&f, f.job, "finalize-verification", input.clone()).await;
	assert_eq!(status, StatusCode::OK, "new verification endpoint must finalize: {reply}");
	assert_eq!(reply["receipt"]["summary"]["finding_id"], finding);
	assert_eq!(reply["receipt"]["summary"]["finding_state"], "confirmed");
	let attempt = reply["receipt"]["summary"]["verification_id"].as_i64().unwrap();
	f.state
		.db
		.with_conn(|conn| {
			let StoredEvidence::Recorded(stored) =
				finding_details::get_attempt_evidence(conn, attempt)?
			else {
				panic!("canonical attempt")
			};
			assert_eq!(
				stored.evidence,
				VerificationTerminalV1::from_json(&input["payload"].to_string()).unwrap()
			);
			assert_eq!(
				findings::get(conn, finding)?.unwrap().state,
				loupe_core::FindingState::Confirmed
			);
			assert_eq!(
				review_intents::get_subject(conn, review_intents::Subject::Finding(finding))?
					.unwrap()
					.state,
				review_intents::State::Complete
			);
			Ok(())
		})
		.unwrap();
	assert!(!reply.to_string().contains("Independent verifier"));
	assert_eq!(post(&f, "finalize-verification", input).await, reply);
}

#[tokio::test]
async fn inconclusive_at_exhaustion_preserves_validating_and_records_only_delayed_intent() {
	let (f, _, finding) = ready().await;
	execute(&f,"UPDATE campaign_admission_spending SET general_spent=56,urgent_spent=4,verification_spent=4; UPDATE findings SET validating_deadline=0");
	execute(
		&f,
		&format!("UPDATE jobs SET attempts=3,soft_deadline_at=0,submit_by=0 WHERE id={}", f.job),
	);
	post(&f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await;
	let started = now();
	let before = scalar(&f, "SELECT COUNT(*) FROM jobs");
	let (status, reply) =
		request(&f, f.job, "finalize-verification", inconclusive("source_analysis_remaining"))
			.await;
	assert_eq!(status, StatusCode::OK, "new inconclusive verification must finalize: {reply}");
	assert_eq!(reply["receipt"]["summary"]["finding_state"], "validating");
	assert_eq!(reply["receipt"]["summary"]["continuation"]["state"], "pending");
	f.state
		.db
		.with_conn(|conn| {
			assert_eq!(
				findings::get(conn, finding)?.unwrap().state,
				loupe_core::FindingState::Validating
			);
			let intent =
				review_intents::get_subject(conn, review_intents::Subject::Finding(finding))?
					.unwrap();
			assert_eq!((intent.revision, intent.logical_sequence), (2, 1));
			assert!(
				intent.not_before.unwrap() >= started + 60
					&& intent.not_before.unwrap() <= now() + 60,
				"first logical delay does not use execution attempt 3"
			);
			Ok(())
		})
		.unwrap();
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM jobs"), before);
	assert_eq!(
		scalar(
			&f,
			"SELECT general_spent+urgent_spent+verification_spent FROM campaign_admission_spending"
		),
		64
	);
}

#[tokio::test]
async fn normal_reporting_is_after_commit_and_receipt_replay_never_redelivers() {
	let (mut f, _, finding) = ready().await;
	let stub = reporter::configure(&mut f.state, finding).await;
	let reply = post(&f, "finalize-verification", verified()).await;
	assert_eq!(
		reply["receipt"]["summary"]["finding_state"], "confirmed",
		"sealed state precedes reporting"
	);
	assert_eq!(stub.capture.calls.lock().unwrap().len(), 1);
	f.state
		.db
		.with_conn(|conn| {
			assert_eq!(
				findings::get(conn, finding)?.unwrap().state,
				loupe_core::FindingState::Reported
			);
			Ok(())
		})
		.unwrap();
	assert_eq!(post(&f, "finalize-verification", verified()).await, reply);
	assert_eq!(stub.capture.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn approval_policy_respects_inheritance_overrides_and_manual_destinations() {
	for (server_default, override_value, expected_hold, manual) in [
		(true, None, true, false),
		(false, Some(true), true, false),
		(true, Some(false), false, false),
		(false, None, false, false),
		(true, None, true, true),
		(false, None, false, true),
	] {
		let (mut f, _, finding) = ready().await;
		let stub = reporter::configure(&mut f.state, finding).await;
		f.state.require_approval_default = server_default;
		f.state
			.db
			.with_conn(|conn| {
				conn.execute("UPDATE registered_repos SET require_approval=?1", [override_value])?;
				Ok(())
			})
			.unwrap();
		if manual {
			execute(&f, "UPDATE registered_repos SET reporting='{\"kind\":\"manual\"}'");
		}
		let reply = post(&f, "finalize-verification", verified()).await;
		assert_eq!(
			reply["receipt"]["summary"]["finding_state"],
			if expected_hold { "awaiting_approval" } else { "confirmed" }
		);
		assert_eq!(
			stub.capture.calls.lock().unwrap().len(),
			usize::from(!expected_hold && !manual)
		);
		if expected_hold {
			assert_eq!(reporter::admin(&f.state, finding, "approve").await, StatusCode::NO_CONTENT);
		}
		assert_eq!(stub.capture.calls.lock().unwrap().len(), usize::from(!manual));
		f.state
			.db
			.with_conn(|conn| {
				assert_eq!(
					findings::get(conn, finding)?.unwrap().state,
					if manual {
						loupe_core::FindingState::Confirmed
					} else {
						loupe_core::FindingState::Reported
					}
				);
				Ok(())
			})
			.unwrap();
		assert_eq!(post(&f, "finalize-verification", verified()).await, reply);
		assert_eq!(stub.capture.calls.lock().unwrap().len(), usize::from(!manual));
	}
}

#[tokio::test]
async fn failed_delivery_is_retryable_without_reopening_the_verdict_or_dispatching_on_replay() {
	let (mut f, _, finding) = ready().await;
	let stub = reporter::configure(&mut f.state, finding).await;
	stub.capture.fail.store(true, std::sync::atomic::Ordering::SeqCst);
	let reply = post(&f, "finalize-verification", verified()).await;
	assert_eq!(stub.capture.calls.lock().unwrap().len(), 1);
	f.state
		.db
		.with_conn(|conn| {
			assert_eq!(
				findings::get(conn, finding)?.unwrap().state,
				loupe_core::FindingState::Confirmed
			);
			Ok(())
		})
		.unwrap();
	stub.capture.fail.store(false, std::sync::atomic::Ordering::SeqCst);
	assert_eq!(post(&f, "finalize-verification", verified()).await, reply);
	assert_eq!(stub.capture.calls.lock().unwrap().len(), 1);
	assert_eq!(reporter::admin(&f.state, finding, "retry-report").await, StatusCode::NO_CONTENT);
	assert_eq!(stub.capture.calls.lock().unwrap().len(), 2);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM finding_verifications"), 1);
	f.state
		.db
		.with_conn(|conn| {
			assert_eq!(
				findings::get(conn, finding)?.unwrap().state,
				loupe_core::FindingState::Reported
			);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn source_rejection_and_dependency_blockers_remain_honest_and_canonical() {
	let (mut f, _, finding) = ready().await;
	let stub = reporter::configure(&mut f.state, finding).await;
	let rejection = rejected();
	let reply = post(&f, "finalize-verification", rejection.clone()).await;
	assert_eq!(reply["receipt"]["summary"]["finding_state"], "dismissed");
	assert_eq!(
		scalar(&f, "SELECT COUNT(*) FROM finding_verifications WHERE verdict='dismissed'"),
		1
	);
	assert!(stub.capture.calls.lock().unwrap().is_empty());
	let attempt = reply["receipt"]["summary"]["verification_id"].as_i64().unwrap();
	f.state
		.db
		.with_conn(|conn| {
			let StoredEvidence::Recorded(stored) =
				finding_details::get_attempt_evidence(conn, attempt)?
			else {
				panic!("canonical rejection")
			};
			assert_eq!(
				stored.evidence,
				VerificationTerminalV1::from_json(&rejection["payload"].to_string()).unwrap()
			);
			Ok(())
		})
		.unwrap();
	for class in ["awaiting_proof_infrastructure", "external_dependency", "requires_successor"] {
		let (f, _, finding) = ready().await;
		let mut input = inconclusive(class);
		if class == "awaiting_proof_infrastructure" {
			input["payload"].as_object_mut().unwrap().remove("partial_evidence");
		}
		let reply = post(&f, "finalize-verification", input.clone()).await;
		assert_eq!(reply["receipt"]["summary"]["finding_state"], "validating");
		assert_eq!(reply["receipt"]["summary"]["continuation"]["state"], "blocked");
		assert_eq!(reply["receipt"]["summary"]["continuation"]["reason"], class);
		let attempt = reply["receipt"]["summary"]["verification_id"].as_i64().unwrap();
		f.state
			.db
			.with_conn(|conn| {
				let intent =
					review_intents::get_subject(conn, review_intents::Subject::Finding(finding))?
						.unwrap();
				assert_eq!(intent.state, review_intents::State::Blocked);
				assert!(intent.not_before.is_none());
				let StoredEvidence::Recorded(attempt) =
					finding_details::get_attempt_evidence(conn, attempt)?
				else {
					panic!("canonical inconclusive")
				};
				assert_eq!(
					attempt.evidence,
					VerificationTerminalV1::from_json(&input["payload"].to_string()).unwrap()
				);
				let StoredEvidence::Recorded(terminal_payloads::TerminalPayload::Verification(
					stored,
				)) = terminal_payloads::get(conn, f.job)?
				else {
					panic!("typed terminal")
				};
				assert_eq!(
					stored,
					VerificationTerminalV1::from_json(&input["payload"].to_string()).unwrap()
				);
				Ok(())
			})
			.unwrap();
		assert_eq!(post(&f, "finalize-verification", input).await, reply);
	}
}

#[tokio::test]
async fn every_transaction_stage_rolls_back_without_delivering_or_losing_authority() {
	for (table, operation) in [
		("finding_verifications", "INSERT"),
		("verification_attempt_details", "INSERT"),
		("findings", "UPDATE"),
		("jobs", "UPDATE"),
		("finding_verification_intents", "UPDATE"),
		("job_terminal_receipts", "INSERT"),
		("job_terminal_payloads", "INSERT"),
	] {
		let (mut f, _, finding) = ready().await;
		let stub = reporter::configure(&mut f.state, finding).await;
		execute(&f,&format!("CREATE TRIGGER fail_verification BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'injected failure'); END"));
		assert_eq!(
			request(&f, f.job, "finalize-verification", verified()).await.0,
			StatusCode::INTERNAL_SERVER_ERROR,
			"{table}"
		);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM finding_verifications"), 0);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM verification_attempt_details"), 0);
		assert_eq!(
			scalar(
				&f,
				&format!("SELECT COUNT(*) FROM job_terminal_receipts WHERE job_id={}", f.job)
			),
			0
		);
		assert_eq!(
			scalar(
				&f,
				&format!("SELECT COUNT(*) FROM job_terminal_payloads WHERE job_id={}", f.job)
			),
			0
		);
		assert_eq!(scalar(&f,&format!("SELECT COUNT(*) FROM jobs WHERE id={} AND state='leased' AND job_capability_hash IS NOT NULL AND prepared_attempt=attempts",f.job)),1);
		f.state
			.db
			.with_conn(|conn| {
				assert_eq!(
					findings::get(conn, finding)?.unwrap().state,
					loupe_core::FindingState::Validating
				);
				assert_eq!(
					review_intents::get_subject(conn, review_intents::Subject::Finding(finding))?
						.unwrap()
						.state,
					review_intents::State::Admitted
				);
				Ok(())
			})
			.unwrap();
		assert!(stub.capture.calls.lock().unwrap().is_empty());
	}
}

#[tokio::test]
async fn preproof_matrix_rejects_missing_independent_evidence_and_unsupported_claims() {
	let (f, _, _) = ready().await;
	let mut cases = Vec::new();
	for field in ["evidence", "e2e_rationale", "established_rung", "e2e_applicability", "version"] {
		let mut input = verified();
		input["payload"].as_object_mut().unwrap().remove(field);
		cases.push(input);
	}
	for rung in ["L1", "L3", "L4"] {
		let mut input = verified();
		input["payload"]["established_rung"] = json!(rung);
		cases.push(input);
	}
	let mut input = verified();
	input["payload"]["e2e_applicability"] = json!("applicable");
	cases.push(input);
	for mut input in [verified(), rejected(), inconclusive("source_analysis_remaining")] {
		for field in [
			"proof",
			"artifact_id",
			"execution_id",
			"patch_unified",
			"poc_unified",
			"terminal_inconclusive",
			"finding_id",
		] {
			let mut invalid = input.clone();
			invalid["payload"][field] = json!(1);
			cases.push(invalid);
		}
		input["payload"]["revalidation"] = json!({"rationale":"checked","current_source_refs":[]});
		cases.push(input);
	}
	for field in ["attacker_source", "control", "sink", "reachable_path", "trust_boundary"] {
		let mut input = verified();
		input["payload"]["evidence"]["l2_argument"].as_object_mut().unwrap().remove(field);
		cases.push(input);
	}
	for count in [0, 17] {
		let mut input = verified();
		input["payload"]["evidence"]["material_locations"] =
			json!(vec![json!({"role":"sink","file":"z.rs"}); count]);
		cases.push(input);
		let mut input = rejected();
		input["payload"]["counterargument"]["source_refs"] =
			json!(vec![json!({"path":"z.rs"}); count]);
		cases.push(input);
	}
	let mut input = rejected();
	input["payload"].as_object_mut().unwrap().remove("counterargument");
	cases.push(input);
	let mut input = rejected();
	input["payload"]["counterargument"]["argument"] = json!("a".repeat(8001));
	cases.push(input);
	let mut input = inconclusive("source_analysis_remaining");
	input["payload"].as_object_mut().unwrap().remove("blocker");
	cases.push(input);
	let mut input = inconclusive("source_analysis_remaining");
	input["payload"].as_object_mut().unwrap().remove("continuation");
	cases.push(input);
	let mut input = inconclusive("awaiting_proof_infrastructure");
	input["payload"]["blocker"] = json!("anything else");
	cases.push(input);
	for input in cases {
		assert_eq!(
			request(&f, f.job, "finalize-verification", input.clone()).await.0,
			StatusCode::BAD_REQUEST,
			"{input}"
		);
	}
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM finding_verifications"), 0);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM verification_attempt_details"), 0);
	assert_eq!(
		scalar(&f, &format!("SELECT COUNT(*) FROM job_terminal_receipts WHERE job_id={}", f.job)),
		0
	);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM findings WHERE state='validating'"), 1);
}

#[tokio::test]
async fn current_manifest_checks_cover_all_nested_evidence_and_optional_revalidation() {
	for (variant, mut input) in [
		("verified", verified()),
		("rejected", rejected()),
		("inconclusive", inconclusive("source_analysis_remaining")),
	] {
		let (f, _, _) = ready().await;
		input["payload"]["revalidation"] = json!({"rationale":"same checkout still requires valid refs","current_source_refs":[{"path":"unknown.rs"}]});
		assert_eq!(
			request(&f, f.job, "finalize-verification", input.clone()).await.0,
			StatusCode::BAD_REQUEST,
			"{variant} optional revalidation"
		);
		input["payload"].as_object_mut().unwrap().remove("revalidation");
		match variant {
			"verified" => {
				input["payload"]["evidence"]["material_locations"][2]["file"] = json!("unknown.rs")
			},
			"rejected" => {
				input["payload"]["counterargument"]["source_refs"][0]["path"] = json!("unknown.rs")
			},
			_ => {
				input["payload"]["partial_evidence"]["source_refs"][0]["path"] = json!("unknown.rs")
			},
		}
		assert_eq!(
			request(&f, f.job, "finalize-verification", input).await.0,
			StatusCode::BAD_REQUEST,
			"{variant} evidence"
		);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM finding_verifications"), 0);
	}
}

#[tokio::test]
async fn changed_checkout_requires_revalidation_without_rewriting_original_provenance() {
	for mut input in [verified(), rejected(), inconclusive("source_analysis_remaining")] {
		let (f, _, finding) = ready().await;
		execute(&f,&format!("UPDATE finding_review_details SET reviewed_commit_sha='{NEXT_SHA}',profile_version=9,profile_digest=zeroblob(32); UPDATE jobs SET head_sha='{NEXT_SHA}' WHERE kind='drilldown'; DELETE FROM leads"));
		let (status, error) = request(&f, f.job, "finalize-verification", input.clone()).await;
		assert_eq!(status, StatusCode::CONFLICT);
		assert_eq!(error["error"]["code"], "revalidation_required");
		input["payload"]["revalidation"] = json!({"rationale":"Independently established on the current checkout.\nOld evidence stays historical.","current_source_refs":[{"path":"cafe\u{301}.rs"}]});
		let reply = post(&f, "finalize-verification", input).await;
		let attempt = reply["receipt"]["summary"]["verification_id"].as_i64().unwrap();
		f.state
			.db
			.with_conn(|conn| {
				let StoredEvidence::Recorded(original) =
					finding_details::get_review_evidence(conn, finding)?
				else {
					panic!("original")
				};
				assert_eq!(original.reviewed_commit_sha, NEXT_SHA);
				assert_eq!(original.profile_version, 9);
				assert_eq!(original.profile_digest, Some([0; 32]));
				assert!(original.origin_lead.is_none());
				let StoredEvidence::Recorded(current) =
					finding_details::get_attempt_evidence(conn, attempt)?
				else {
					panic!("current attempt")
				};
				assert_eq!(current.checkout_commit_sha, SHA);
				Ok(())
			})
			.unwrap();
	}
}

#[tokio::test]
async fn original_evidence_and_current_intent_fail_closed_when_incompatible() {
	for damage in [
		"DELETE FROM finding_review_details",
		"UPDATE finding_review_details SET evidence_payload='{\"version\":99}'",
		"UPDATE finding_review_details SET evidence_payload=NULL,l2_argument='{}',counterevidence='retained legacy',assumptions_gaps='historical',confidence='high'",
		"UPDATE finding_review_details SET profile_digest=NULL",
		"UPDATE finding_review_details SET workflow_contract_version=2",
		"UPDATE jobs SET head_sha=NULL WHERE kind='drilldown'",
		"UPDATE jobs SET workflow_contract_version=NULL WHERE kind='drilldown'",
		"DELETE FROM finding_verification_intents",
		"UPDATE finding_verification_intents SET state='pending',admitted_job_id=NULL",
		"UPDATE finding_verification_intents SET profile_digest=zeroblob(32)",
		"UPDATE finding_verification_intents SET originating_job_id=admitted_job_id",
		"UPDATE findings SET verification_required=0",
	] {
		let (f, _, _) = ready().await;
		execute(&f, damage);
		let (status, _) = request(&f, f.job, "finalize-verification", verified()).await;
		assert!(status.is_client_error(), "{damage}: {status}");
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM finding_verifications"), 0);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM findings WHERE state='validating'"), 1);
	}
}

#[tokio::test]
async fn continuation_failure_rolls_back_attempt_and_success_then_replay_is_frozen() {
	let (f, _, _) = ready().await;
	let input = inconclusive("source_analysis_remaining");
	execute(&f,"CREATE TRIGGER fail_continuation BEFORE UPDATE ON finding_verification_intents WHEN NEW.intent_revision>OLD.intent_revision BEGIN SELECT RAISE(ABORT,'injected continuation failure'); END");
	assert_eq!(
		request(&f, f.job, "finalize-verification", input.clone()).await.0,
		StatusCode::INTERNAL_SERVER_ERROR
	);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM finding_verifications"), 0);
	assert_eq!(scalar(&f, "SELECT intent_revision FROM finding_verification_intents"), 1);
	assert_eq!(scalar(&f,&format!("SELECT COUNT(*) FROM jobs WHERE id={} AND state='leased' AND job_capability_hash IS NOT NULL",f.job)),1);
	execute(&f, "DROP TRIGGER fail_continuation");
	let reply = post(&f, "finalize-verification", input.clone()).await;
	let due = reply["receipt"]["summary"]["continuation"]["not_before"].as_i64().unwrap();
	execute(&f, &format!("UPDATE finding_verification_intents SET not_before={}", due + 3600));
	assert_eq!(post(&f, "finalize-verification", input).await, reply);
	assert_eq!(scalar(&f, "SELECT not_before FROM finding_verification_intents"), due + 3600);
	assert_eq!(scalar(&f, "SELECT intent_revision FROM finding_verification_intents"), 2);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM finding_verifications"), 1);
}

#[tokio::test]
async fn authority_matrix_denies_before_decoding_unrelated_or_malformed_evidence() {
	for damage in [
		"worker",
		"token",
		"attempt",
		"unprepared",
		"expired",
		"deadline",
		"unsupported",
		"assignment",
		"phase",
		"cancelled",
	] {
		let (mut f, _, _) = ready().await;
		match damage {
			"worker"=>f.peer=f.other_peer.clone(),"token"=>f.token="x".repeat(43),
			"attempt"=>execute(&f,&format!("UPDATE jobs SET attempts=attempts+1 WHERE id={}",f.job)),
			"unprepared"=>execute(&f,&format!("UPDATE jobs SET prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id={}",f.job)),
			"expired"=>execute(&f,&format!("UPDATE jobs SET lease_expires_at=0 WHERE id={}",f.job)),
			"deadline"=>execute(&f,&format!("UPDATE jobs SET hard_deadline_at=0 WHERE id={}",f.job)),
			"unsupported"=>execute(&f,&format!("UPDATE jobs SET recipe='{{\"version\":2,\"phase\":\"verify\"}}' WHERE id={}",f.job)),
			"assignment"=>execute(&f,&format!("UPDATE jobs SET target_finding_id=NULL WHERE id={}",f.job)),
			"cancelled"=>execute(&f,"UPDATE review_campaigns SET state='cancelled'"),
			_=>execute(&f,&format!("UPDATE jobs SET kind='drilldown' WHERE id={}",f.job)),
		}
		execute(&f, "UPDATE finding_review_details SET evidence_payload=x'80'");
		let denied = request(&f, f.job, "finalize-verification", verified()).await;
		let missing = request(&f, 999999, "finalize-verification", verified()).await;
		assert_eq!(denied, missing, "{damage}");
		assert_eq!(denied.0, StatusCode::FORBIDDEN);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM finding_verifications"), 0);
	}
}

#[tokio::test]
async fn terminal_replay_uses_only_finishing_identity_even_after_restart_and_generation_purge() {
	for input in [verified(), rejected(), inconclusive("source_analysis_remaining")] {
		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("verification.db");
		let key = loupe_storage::secrets::MasterKey::for_tests();
		let (mut f, _, finding) =
			ready_fixture(fixture_with_db(Arc::new(Db::open(&path, &key).unwrap()))).await;
		let old = f.token.clone();
		f.token = "r".repeat(43);
		f.state
			.db
			.with_conn(|conn| {
				conn.execute(
					"UPDATE jobs SET attempts=attempts+1,job_capability_hash=?2 WHERE id=?1",
					params![f.job, blake3::hash(f.token.as_bytes()).as_bytes().as_slice()],
				)?;
				Ok(())
			})
			.unwrap();
		post(&f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await;
		let first = post(&f, "finalize-verification", input.clone()).await;
		let attempt = first["receipt"]["summary"]["verification_id"].as_i64().unwrap();
		let original = f
			.state
			.db
			.with_conn(|conn| finding_details::get_review_evidence(conn, finding))
			.unwrap();
		drop(std::mem::replace(&mut f.state.db, Arc::new(Db::open_in_memory(&key).unwrap())));
		f.state.db = Arc::new(Db::open(&path, &key).unwrap());
		execute(&f,"UPDATE review_generations SET generated_profile='{}',generated_profile_digest=zeroblob(32);UPDATE review_campaigns SET state='cancelled';DELETE FROM review_generations");
		assert_eq!(post(&f, "finalize-verification", input.clone()).await, first);
		f.state
			.db
			.with_conn(|conn| {
				let StoredEvidence::Recorded(attempt) =
					finding_details::get_attempt_evidence(conn, attempt)?
				else {
					panic!("canonical attempt")
				};
				let expected =
					VerificationTerminalV1::from_json(&input["payload"].to_string()).unwrap();
				assert_eq!(
					attempt.evidence.canonical_bytes().unwrap(),
					expected.canonical_bytes().unwrap()
				);
				let StoredEvidence::Recorded(current) =
					finding_details::get_review_evidence(conn, finding)?
				else {
					panic!("canonical finding")
				};
				let StoredEvidence::Recorded(original) = &original else { panic!("original") };
				assert_eq!(current.evidence, original.evidence);
				assert_eq!(current.profile_digest, original.profile_digest);
				let StoredEvidence::Recorded(terminal_payloads::TerminalPayload::Verification(
					terminal,
				)) = terminal_payloads::get(conn, f.job)?
				else {
					panic!("terminal")
				};
				assert_eq!(terminal, expected);
				Ok(())
			})
			.unwrap();
		let current = f.token.clone();
		f.token = old;
		assert_eq!(
			request(&f, f.job, "finalize-verification", input.clone()).await.0,
			StatusCode::FORBIDDEN
		);
		f.token = current;
		let peer = f.peer.clone();
		f.peer = f.other_peer.clone();
		assert_eq!(
			request(&f, f.job, "finalize-verification", input.clone()).await.0,
			StatusCode::FORBIDDEN
		);
		f.peer = peer;
		let divergent =
			if input["payload"]["verdict"] == "rejected" { verified() } else { rejected() };
		let (status, error) = request(&f, f.job, "finalize-verification", divergent).await;
		assert_eq!(status, StatusCode::CONFLICT);
		assert_eq!(error["error"]["code"], "terminal_conflict");
		assert_eq!(post(&f, "finalize-verification", input).await, first);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM finding_verifications"), 1);
	}
}

#[tokio::test]
async fn strict_transport_is_bounded_noncacheable_and_rejects_unknown_or_encoded_payloads() {
	let (f, _, _) = ready().await;
	let valid = verified().to_string();
	for (raw, version, encoding, status) in [
		(
			valid.replace("\"version\":1", "\"version\":1,\"version\":1"),
			"3",
			"identity",
			StatusCode::BAD_REQUEST,
		),
		(
			valid.replace("\"payload\":{", "\"finding_id\":1,\"payload\":{"),
			"3",
			"identity",
			StatusCode::BAD_REQUEST,
		),
		(
			valid.replace("\"protocol_version\":3", "\"protocol_version\":2"),
			"3",
			"identity",
			StatusCode::BAD_REQUEST,
		),
		(valid.clone(), "2", "identity", StatusCode::BAD_REQUEST),
		(valid.clone(), "3", "gzip", StatusCode::UNSUPPORTED_MEDIA_TYPE),
		(" ".repeat(512 * 1024) + &valid, "3", "identity", StatusCode::PAYLOAD_TOO_LARGE),
	] {
		let mut req = Request::post(format!("/v1/jobs/{}/finalize-verification", f.job))
			.header(PROTOCOL_VERSION_HEADER, version)
			.header(JOB_CAPABILITY_HEADER, &f.token)
			.header("content-type", "application/json")
			.header("content-encoding", encoding)
			.body(Body::from(raw))
			.unwrap();
		req.extensions_mut().insert(f.peer.clone());
		let response = router(f.state.clone()).call(req).await.unwrap();
		assert_eq!(response.status(), status);
		assert_eq!(response.headers()["cache-control"], "no-store");
		let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
		assert!(serde_json::from_slice::<Value>(&bytes).unwrap()["error"].is_object());
	}
	let mut req = Request::post(format!("/v1/jobs/{}/finalize-verification", f.job))
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header(JOB_CAPABILITY_HEADER, &f.token)
		.header("content-type", "application/json")
		.body(Body::from(valid))
		.unwrap();
	req.extensions_mut().insert(f.peer.clone());
	let response = router(f.state.clone()).call(req).await.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(response.headers()["cache-control"], "no-store");
	let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
	assert!(!String::from_utf8_lossy(&bytes).contains("Independent notes"));
}
