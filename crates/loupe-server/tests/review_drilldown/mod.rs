//! Real authenticated router coverage. Explicit admission fixtures keep the
//! phase claim gate closed until the final public lifecycle integration.
use loupe_core::review_payload::{DrilldownTerminalV1, LeadEvidenceV1};
use loupe_storage::admission_policy::AcceptedPriority;
use loupe_storage::{
	leads, review_intents, review_units, scheduler, terminal_payloads, StoredEvidence,
};

use super::*;

fn body(payload: Value) -> Value {
	json!({"protocol_version":3,"payload":payload})
}
fn reject() -> Value {
	body(json!({"version":1,"disposition":"reject","counterargument":{
		"argument":"The bound is checked before allocation.\nAll callers enforce it.",
		"source_refs":[{"path":"z.rs"}]}}))
}

async fn ready() -> (Fixture, i64, i64) {
	ready_fixture(fixture()).await
}

pub(super) async fn ready_fixture(f: Fixture) -> (Fixture, i64, i64) {
	let pin = post(&f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await;
	let generation = pin["generation"]["generation_id"].as_i64().unwrap();
	let entries = vec!["a%FF", "cafe\u{301}.rs", "café.rs", "z.rs"]
		.into_iter()
		.map(|path| ManifestEntry {
			raw_path: path.as_bytes().to_vec(),
			git_mode: 0o100644,
			object_id: SHA.into(),
		})
		.collect::<Vec<_>>();
	post(&f, "inventory-batches", chunk(&entries, 0, entries.len())).await;
	post(&f, "seal-inventory", json!({"protocol_version":3})).await;
	post(&f, "publish-profile", json!({"protocol_version":3,"profile":{"scope":"crate"}})).await;
	f.state.db.with_conn(|conn| {
		let policy = ReviewPolicy::default().snapshot_v2().unwrap();
		conn.execute("UPDATE review_campaigns SET effective_policy=?2,effective_policy_digest=?3 WHERE campaign_id=?1",params![f.campaign,policy.expose(),policy.digest().as_slice()])?;
		conn.execute("INSERT INTO campaign_admission_spending(campaign_id,policy_version,general_spent) VALUES(?1,2,1)",[f.campaign])?;
		Ok(())
	}).unwrap();
	let (f, lead) = child(&f, generation, f.job, "allocation boundary").await;
	(f, generation, lead)
}

async fn child(f: &Fixture, generation: i64, producer: i64, anchor: &str) -> (Fixture, i64) {
	let token = hex(blake3::hash(anchor.as_bytes()).as_bytes())[..43].to_string();
	let (lead,job) = f.state.db.with_conn(|conn| transaction::immediate(conn,|tx| {
		let payload = LeadEvidenceV1::from_json(&json!({"format":"loupe.lead_evidence","version":1,
			"identity_family":"allocation","identity_anchor":anchor,
			"hypothesis":"Attacker controlled length exceeds the allocation bound.",
			"source_refs":[{"path":"z.rs"}],"next_proof_step":"Inspect the bound",
			"counterevidence":"Caller validation","proof_gaps":"Check all callers"}).to_string())?;
		let leads::Submitted::Created(lead) = leads::submit_evidence(tx,&leads::NewLeadEvidence {
			generation_id:generation,created_by_job:producer,commit_sha:SHA,priority:review_units::Priority::High,payload:&payload,
		},now())? else { panic!("new lead") };
		let priority = AcceptedPriority {band:scheduler::Band::Urgent,score:500};
		let intent = review_intents::ensure_drilldown_intent(tx,lead,producer,priority,now())?.unwrap();
		tx.execute("INSERT INTO jobs(repo_id,kind,state,campaign_id,generation_id,parent_job_id,assigned_lead_id,worker_id,attempts,lease_expires_at,hard_deadline_at,job_capability_hash,workflow_contract_version,scheduling_band,recipe,enqueued_at)
			VALUES(1,'drilldown','leased',?1,?2,?3,?4,?5,1,?6,?6,?7,1,'urgent','{\"version\":1,\"phase\":\"drilldown\"}',?8)",params![f.campaign,generation,producer,lead,f.worker,now()+3600,blake3::hash(token.as_bytes()).as_bytes().as_slice(),now()])?;
		let job=tx.last_insert_rowid();
		review_intents::admit_subject(tx,review_intents::Subject::Lead(lead),intent.revision,job,now())?;
		Ok((lead,job))
	})).unwrap();
	let f = Fixture {
		state: f.state.clone(),
		peer: f.peer.clone(),
		other_peer: f.other_peer.clone(),
		worker: f.worker,
		campaign: f.campaign,
		job,
		token,
	};
	post(&f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await;
	(f, lead)
}

fn scalar(f: &Fixture, sql: &str) -> i64 {
	f.state.db.with_conn(|conn| Ok(conn.query_row(sql, [], |r| r.get(0))?)).unwrap()
}

#[tokio::test]
async fn reject_seals_the_assigned_lead_and_replays_after_generation_purge() {
	let (f, _, lead) = ready().await;
	let input = reject();
	let (status, first) = request(&f, f.job, "finalize-drilldown", input.clone()).await;
	assert_eq!(status, StatusCode::OK, "new drilldown endpoint must finalize: {first}");
	assert_eq!(first["receipt"]["summary"]["lead_id"], lead);
	assert_eq!(first["receipt"]["summary"]["disposition"], "rejected");
	f.state
		.db
		.with_conn(|conn| {
			assert_eq!(
				leads::get_metadata(conn, lead)?.unwrap().disposition,
				Some(leads::Disposition::Rejected)
			);
			assert_eq!(
				review_intents::get_subject(conn, review_intents::Subject::Lead(lead))?
					.unwrap()
					.state,
				review_intents::State::Complete
			);
			let StoredEvidence::Recorded(terminal_payloads::TerminalPayload::Drilldown(stored)) =
				terminal_payloads::get(conn, f.job)?
			else {
				panic!("typed evidence")
			};
			assert_eq!(
				stored,
				DrilldownTerminalV1::from_json(&input["payload"].to_string()).unwrap()
			);
			conn.execute("UPDATE review_campaigns SET state='cancelled'", [])?;
			conn.execute("DELETE FROM review_generations", [])?;
			Ok(())
		})
		.unwrap();
	assert_eq!(request(&f, f.job, "finalize-drilldown", input).await, (StatusCode::OK, first));
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 1);
}

#[tokio::test]
async fn defer_preserves_multiline_prose_and_creates_only_a_typed_pending_intent() {
	let (f, _, lead) = ready().await;
	let input = body(
		json!({"version":1,"disposition":"defer","reason":"More work\nwith exact evidence",
		"continuation":"source_analysis_remaining","retry_explanation":"Inspect next caller\nwithout losing notes"}),
	);
	let before = scalar(&f, "SELECT COUNT(*) FROM jobs");
	let (status, reply) = request(&f, f.job, "finalize-drilldown", input.clone()).await;
	assert_eq!(status, StatusCode::OK, "new drilldown defer must finalize: {reply}");
	assert_eq!(reply["receipt"]["summary"]["continuation"]["state"], "pending");
	f.state
		.db
		.with_conn(|conn| {
			assert_eq!(leads::get_metadata(conn, lead)?.unwrap().status, leads::Status::Deferred);
			let intent =
				review_intents::get_subject(conn, review_intents::Subject::Lead(lead))?.unwrap();
			assert_eq!(
				(intent.revision, intent.logical_sequence, intent.state),
				(2, 1, review_intents::State::Pending)
			);
			assert!(intent.not_before.unwrap() > now());
			let StoredEvidence::Recorded(terminal_payloads::TerminalPayload::Drilldown(stored)) =
				terminal_payloads::get(conn, f.job)?
			else {
				panic!("typed evidence")
			};
			assert_eq!(
				stored,
				DrilldownTerminalV1::from_json(&input["payload"].to_string()).unwrap()
			);
			Ok(())
		})
		.unwrap();
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM jobs"), before);
	assert_eq!(scalar(&f, "SELECT general_spent FROM campaign_admission_spending"), 1);
}

pub(super) fn promote() -> Value {
	body(json!({"version":1,"disposition":"promote","promotion":{
		"version":1,"severity":"high","title":"Untrusted allocation control",
		"description":"Attacker-controlled length reaches the allocator.\nCanonical details remain literal.",
		"identity_family":"allocation","identity_anchor":"request allocator","identity_instance_key":"public endpoint","cwe":"CWE-789",
		"evidence":{"version":1,"l2_argument":{"attacker_source":"remote request","control":"request length",
			"sink":"allocator","reachable_path":"handler to allocator","trust_boundary":"network to process memory"},
			"material_locations":[{"role":"entry_point","file":"cafe\u{301}.rs","symbol":"entry","line_start":3,"line_end":8},
				{"role":"sink","file":"café.rs","symbol":"allocate","line_start":12},{"role":"wrapper","file":"z.rs"}],
			"counterevidence":"authentication precedes allocation","assumptions_gaps":"authenticated remote attacker","confidence":"medium"}}}))
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
async fn promotion_is_canonical_l2_with_mandatory_ranked_verification_even_without_capacity() {
	let (f, _, lead) = ready().await;
	execute(&f,"UPDATE registered_repos SET verification_enabled=0; UPDATE campaign_admission_spending SET general_spent=56,urgent_spent=4,verification_spent=4");
	let input = promote();
	let before = scalar(&f, "SELECT COUNT(*) FROM jobs");
	let reply = post(&f, "finalize-drilldown", input.clone()).await;
	let finding = reply["receipt"]["summary"]["promoted_finding_id"].as_i64().unwrap();
	assert!(reply.to_string().len() < 16384 && !reply.to_string().contains("Attacker-controlled"));
	f.state
		.db
		.with_conn(|conn| {
			let finding_row = loupe_storage::findings::get(conn, finding)?.unwrap();
			assert_eq!(finding_row.state, loupe_core::FindingState::Validating);
			assert!(
				finding_row.verification_required
					&& finding_row.poc_unified.is_none()
					&& finding_row.patch_unified.is_none()
			);
			let StoredEvidence::Recorded(details) =
				loupe_storage::finding_details::get_review_evidence(conn, finding)?
			else {
				panic!("typed finding")
			};
			assert_eq!(
				details
					.evidence
					.material_locations
					.iter()
					.map(|l| l.file.expose())
					.collect::<Vec<_>>(),
				vec!["cafe\u{301}.rs", "café.rs", "z.rs"]
			);
			assert_eq!(details.origin_lead, Some(lead));
			assert_eq!(details.reviewed_commit_sha, SHA);
			let intent =
				review_intents::get_subject(conn, review_intents::Subject::Finding(finding))?
					.unwrap();
			assert_eq!(intent.state, review_intents::State::Pending);
			assert_eq!(
				intent.priority,
				AcceptedPriority { band: scheduler::Band::Urgent, score: 500 }
			);
			assert_eq!(intent.originating_job_id, f.job);
			assert_eq!(leads::get_metadata(conn, lead)?.unwrap().promoted_finding, Some(finding));
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
	assert_eq!(post(&f, "finalize-drilldown", input).await, reply);
}

#[tokio::test]
async fn every_variant_checks_current_source_refs_and_optional_revalidation() {
	for variant in ["promote", "reject", "hardening", "duplicate", "defer"] {
		let (f, _, _) = ready().await;
		let mut input = match variant {
			"promote" => promote(),
			"reject" => reject(),
			"hardening" => body(
				json!({"version":1,"disposition":"hardening","explanation":{"argument":"A defense in depth check","source_refs":[{"path":"z.rs"}]}}),
			),
			"duplicate" => body(
				json!({"version":1,"disposition":"duplicate","target":{"kind":"lead","id":99999},"rationale":"same cause"}),
			),
			_ => body(
				json!({"version":1,"disposition":"defer","reason":"remaining","continuation":"source_analysis_remaining"}),
			),
		};
		input["payload"]["revalidation"] = json!({"current_source_refs":[{"path":"unknown.rs"}],"rationale":"checked current checkout"});
		assert_eq!(
			request(&f, f.job, "finalize-drilldown", input.clone()).await.0,
			StatusCode::BAD_REQUEST,
			"{variant}"
		);
		input["payload"].as_object_mut().unwrap().remove("revalidation");
		match variant {
			"promote" => {
				input["payload"]["promotion"]["evidence"]["material_locations"][2]["file"] =
					json!("unknown.rs")
			},
			"reject" => {
				input["payload"]["counterargument"]["source_refs"][0]["path"] = json!("unknown.rs")
			},
			"hardening" => {
				input["payload"]["explanation"]["source_refs"][0]["path"] = json!("unknown.rs")
			},
			_ => continue,
		}
		assert_eq!(
			request(&f, f.job, "finalize-drilldown", input).await.0,
			StatusCode::BAD_REQUEST,
			"{variant} refs"
		);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 0);
	}
}

#[tokio::test]
async fn revalidation_is_required_for_flagged_or_carried_old_commit_evidence() {
	for mismatch in [false, true] {
		let (f, _, _) = ready().await;
		if mismatch {
			execute(&f,&format!("UPDATE leads SET commit_sha='{NEXT_SHA}';UPDATE jobs SET head_sha='{NEXT_SHA}' WHERE kind='survey'"));
		} else {
			execute(&f, "UPDATE leads SET needs_revalidation=1");
		}
		let (status, reply) = request(&f, f.job, "finalize-drilldown", reject()).await;
		assert_eq!(status, StatusCode::CONFLICT);
		assert_eq!(reply["error"]["code"], "revalidation_required");
		let mut input = reject();
		input["payload"]["revalidation"] = json!({"current_source_refs":[{"path":"cafe\u{301}.rs"}],"rationale":"The current checkout preserves the same bound.\nThe original checkout is not relabeled."});
		let reply = post(&f, "finalize-drilldown", input).await;
		assert_eq!(reply["receipt"]["commit_sha"], SHA);
	}
}

#[tokio::test]
async fn incomplete_original_evidence_or_provenance_and_nonowned_intents_fail_closed() {
	for damage in [
		"DELETE FROM lead_drilldown_intents",
		"UPDATE lead_drilldown_intents SET state='pending',admitted_job_id=NULL",
		"UPDATE lead_drilldown_intents SET profile_digest=zeroblob(32)",
		"UPDATE lead_drilldown_intents SET originating_job_id=admitted_job_id",
		"UPDATE leads SET created_by_job_id=NULL",
		"UPDATE jobs SET head_sha=NULL WHERE kind='survey'",
		"UPDATE jobs SET workflow_contract_version=2 WHERE kind='survey'",
		"UPDATE leads SET anchored_payload='{}',anchored_digest=zeroblob(32)",
		"UPDATE leads SET anchored_payload='{\"format\":\"loupe.lead_evidence\",\"version\":99}',anchored_digest=zeroblob(32)",
	] {
		let (f,_,_)=ready().await;
		execute(&f,damage);
		let (status,value)=request(&f,f.job,"finalize-drilldown",reject()).await;
		assert_ne!(status,StatusCode::OK,"{damage}: {value}");
		assert_eq!(scalar(&f,"SELECT COUNT(*) FROM leads WHERE status='open'"),1);
		assert_eq!(scalar(&f,"SELECT COUNT(*) FROM job_terminal_receipts"),0);
	}
}

#[tokio::test]
async fn all_finalization_writes_roll_back_on_intent_receipt_or_payload_failure() {
	for table in ["finding_verification_intents", "job_terminal_receipts", "job_terminal_payloads"]
	{
		let (f, _, lead) = ready().await;
		execute(&f,&format!("CREATE TRIGGER fail_insert BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'injected failure'); END"));
		assert_eq!(
			request(&f, f.job, "finalize-drilldown", promote()).await.0,
			StatusCode::INTERNAL_SERVER_ERROR,
			"{table}"
		);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM findings"), 0);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM finding_review_details"), 0);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM finding_verification_intents"), 0);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 0);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_payloads"), 0);
		assert_eq!(scalar(&f,&format!("SELECT COUNT(*) FROM jobs WHERE id={} AND state='leased' AND job_capability_hash IS NOT NULL AND prepared_attempt=attempts",f.job)),1);
		f.state
			.db
			.with_conn(|conn| {
				assert_eq!(leads::get_metadata(conn, lead)?.unwrap().status, leads::Status::Open);
				assert_eq!(
					review_intents::get_subject(conn, review_intents::Subject::Lead(lead))?
						.unwrap()
						.state,
					review_intents::State::Admitted
				);
				Ok(())
			})
			.unwrap();
	}
}

#[tokio::test]
async fn hardening_and_dependency_defer_seal_distinct_honest_states() {
	let (f, _, lead) = ready().await;
	let input = body(
		json!({"version":1,"disposition":"hardening","explanation":{"argument":"No exploit path.\nAdd defense in depth.","source_refs":[{"path":"z.rs"}]}}),
	);
	post(&f, "finalize-drilldown", input).await;
	f.state
		.db
		.with_conn(|conn| {
			assert_eq!(
				leads::get_metadata(conn, lead)?.unwrap().disposition,
				Some(leads::Disposition::Hardening)
			);
			Ok(())
		})
		.unwrap();
	for class in ["awaiting_proof_infrastructure", "external_dependency", "requires_successor"] {
		let (f, _, _) = ready().await;
		let input = body(
			json!({"version":1,"disposition":"defer","reason":"Dependency\nnot resolved","continuation":class,"retry_explanation":"Do not retry\nuntil unblocked"}),
		);
		let reply = post(&f, "finalize-drilldown", input.clone()).await;
		let continuation = &reply["receipt"]["summary"]["continuation"];
		assert_eq!(continuation["state"], "blocked");
		assert_eq!(continuation["class"], class);
		assert_eq!(continuation["reason"], class);
		assert!(continuation.get("not_before").is_none());
		assert_eq!(post(&f, "finalize-drilldown", input).await, reply);
	}
}

async fn candidates(f: &Fixture) -> Value {
	let mut req =
		Request::get(format!("/v1/jobs/{}/lead-candidates?query=allocation&limit=20", f.job))
			.header(PROTOCOL_VERSION_HEADER, "3")
			.header(JOB_CAPABILITY_HEADER, &f.token)
			.body(Body::empty())
			.unwrap();
	req.extensions_mut().insert(f.peer.clone());
	let (status, value) = response(f, req).await;
	assert_eq!(status, StatusCode::OK, "{value}");
	value
}
fn duplicate(kind: &str, id: i64) -> Value {
	body(
		json!({"version":1,"disposition":"duplicate","target":{"kind":kind,"id":id},"rationale":"Same source-controlled cause.\nRetain this explanation."}),
	)
}

#[tokio::test]
async fn duplicate_requires_job_issued_typed_target_and_never_decodes_unissued_objects() {
	let (f, generation, lead) = ready().await;
	let producer = scalar(&f, "SELECT id FROM jobs WHERE kind='survey'");
	let (other, other_lead) = child(&f, generation, producer, "other allocation").await;
	for id in [lead, other_lead, 999999] {
		let (status, value) = request(&f, f.job, "finalize-drilldown", duplicate("lead", id)).await;
		assert_eq!(status, StatusCode::FORBIDDEN);
		assert_eq!(value["error"]["code"], "denied");
	}
	execute(&f, &format!("UPDATE leads SET identity_anchor=x'80' WHERE lead_id={other_lead}"));
	assert_eq!(
		request(&f, f.job, "finalize-drilldown", duplicate("lead", other_lead)).await.0,
		StatusCode::FORBIDDEN
	);
	execute(
		&f,
		&format!("UPDATE leads SET identity_anchor='other allocation' WHERE lead_id={other_lead}"),
	);
	candidates(&f).await;
	assert_eq!(
		request(&f, f.job, "finalize-drilldown", duplicate("lead", lead)).await.0,
		StatusCode::FORBIDDEN,
		"self remains forbidden even if issued"
	);
	post(&f, "finalize-drilldown", duplicate("lead", other_lead)).await;
	assert_eq!(
		scalar(&f, &format!("SELECT duplicate_of_lead_id FROM leads WHERE lead_id={lead}")),
		other_lead
	);
	// The other job did not receive this job's candidate authority.
	assert_eq!(
		request(&other, other.job, "finalize-drilldown", duplicate("lead", lead)).await.0,
		StatusCode::FORBIDDEN
	);
}

#[tokio::test]
async fn duplicate_can_target_an_issued_canonical_finding_but_revalidates_issued_identity() {
	for mutate in [false, true] {
		let (f, generation, _) = ready().await;
		let producer = scalar(&f, "SELECT id FROM jobs WHERE kind='survey'");
		let finding = post(&f, "finalize-drilldown", promote()).await["receipt"]["summary"]
			["promoted_finding_id"]
			.as_i64()
			.unwrap();
		let (other, lead) = child(&f, generation, producer, "other allocation").await;
		candidates(&other).await;
		if mutate {
			execute(&other,&format!("UPDATE finding_review_details SET identity_anchor='changed' WHERE finding_id={finding}"));
		}
		let (status, _) =
			request(&other, other.job, "finalize-drilldown", duplicate("finding", finding)).await;
		if mutate {
			assert_eq!(status, StatusCode::CONFLICT);
			assert_eq!(
				scalar(
					&other,
					&format!("SELECT COUNT(*) FROM leads WHERE lead_id={lead} AND status='open'")
				),
				1
			);
		} else {
			assert_eq!(status, StatusCode::OK);
			assert_eq!(
				scalar(
					&other,
					&format!("SELECT duplicate_of_finding_id FROM leads WHERE lead_id={lead}")
				),
				finding
			);
		}
	}
}

#[tokio::test]
async fn promotion_conflict_codes_distinguish_semantic_and_compatibility_ownership() {
	for collision in ["modern", "details_unique", "legacy", "malformed", "mismatched"] {
		let (f, generation, _) = ready().await;
		let producer = scalar(&f, "SELECT id FROM jobs WHERE kind='survey'");
		let finding = post(&f, "finalize-drilldown", promote()).await["receipt"]["summary"]
			["promoted_finding_id"]
			.as_i64()
			.unwrap();
		let (other, lead) = child(&f, generation, producer, "other allocation").await;
		match collision {
			"details_unique"=>execute(&f,&format!("UPDATE findings SET fingerprint='prior-compatible-key' WHERE id={finding}")),
			"legacy"=>execute(&f,&format!("DELETE FROM finding_review_details WHERE finding_id={finding}")),
			"malformed"=>execute(&f,&format!("UPDATE finding_review_details SET evidence_payload='{{\"version\":99}}' WHERE finding_id={finding}")),
			"mismatched"=>execute(&f,&format!("UPDATE finding_review_details SET identity_anchor='different identity' WHERE finding_id={finding}")),
			_=>{},
		}
		let before = f
			.state
			.db
			.with_conn(|conn| Ok(loupe_storage::findings::get(conn, finding)?.unwrap()))
			.unwrap();
		let (status, value) = request(&other, other.job, "finalize-drilldown", promote()).await;
		assert_eq!(status, StatusCode::CONFLICT, "{collision}: {value}");
		assert_eq!(
			value["error"]["code"],
			if matches!(collision, "modern" | "details_unique") {
				"finding_identity_conflict"
			} else {
				"compatibility_key_conflict"
			}
		);
		assert!(value["error"]["detail"].is_null(), "no arbitrary retained finding details");
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM findings"), 1);
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 1);
		assert_eq!(
			scalar(
				&f,
				&format!("SELECT COUNT(*) FROM leads WHERE lead_id={lead} AND status='open'")
			),
			1
		);
		f.state
			.db
			.with_conn(|conn| {
				assert_eq!(loupe_storage::findings::get(conn, finding)?.unwrap(), before);
				Ok(())
			})
			.unwrap();
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_normalized_duplicate_promotions_have_one_winner_and_instances_remain_distinct()
{
	let (f, generation, _) = ready().await;
	let producer = scalar(&f, "SELECT id FROM jobs WHERE kind='survey'");
	let (other, _) = child(&f, generation, producer, "second allocation").await;
	let db = f.state.db.clone();
	let barrier = Arc::new(tokio::sync::Barrier::new(2));
	let b = barrier.clone();
	let mut input = promote();
	input["payload"]["promotion"]["identity_anchor"] = json!("request café allocator");
	let mut equivalent = input.clone();
	equivalent["payload"]["promotion"]["identity_anchor"] = json!("request cafe\u{301} allocator");
	let first = tokio::spawn(async move {
		b.wait().await;
		let reply = request(&f, f.job, "finalize-drilldown", input).await;
		(f, reply)
	});
	let second = tokio::spawn(async move {
		barrier.wait().await;
		request(&other, other.job, "finalize-drilldown", equivalent).await
	});
	let (f, a) = first.await.unwrap();
	let b = second.await.unwrap();
	let mut statuses = [a.0, b.0];
	statuses.sort();
	assert_eq!(statuses, [StatusCode::OK, StatusCode::CONFLICT]);
	let loser = if a.0 == StatusCode::CONFLICT { a.1 } else { b.1 };
	assert_eq!(loser["error"]["code"], "finding_identity_conflict");
	db.with_conn(|conn| {
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get::<_, i64>(0))?, 1);
		Ok(())
	})
	.unwrap();
	let (third, _) = child(&f, generation, producer, "third allocation").await;
	let mut distinct = promote();
	distinct["payload"]["promotion"]["identity_anchor"] = json!("request café allocator");
	distinct["payload"]["promotion"]["identity_instance_key"] = json!("separate endpoint");
	post(&third, "finalize-drilldown", distinct).await;
	assert_eq!(scalar(&third, "SELECT COUNT(*) FROM findings"), 2);
}

#[tokio::test]
async fn canonical_evidence_and_receipt_survive_restart_purge_and_profile_replacement() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("terminal.db");
	let key = loupe_storage::secrets::MasterKey::for_tests();
	let (mut f, _, _) =
		ready_fixture(fixture_with_db(Arc::new(Db::open(&path, &key).unwrap()))).await;
	let input = promote();
	let first = post(&f, "finalize-drilldown", input.clone()).await;
	let finding = first["receipt"]["summary"]["promoted_finding_id"].as_i64().unwrap();
	let original = f
		.state
		.db
		.with_conn(|conn| {
			let StoredEvidence::Recorded(value) =
				loupe_storage::finding_details::get_review_evidence(conn, finding)?
			else {
				panic!("recorded")
			};
			Ok(value)
		})
		.unwrap();
	// Drop the last handle to the file-backed connection before reopening it.
	drop(std::mem::replace(&mut f.state.db, Arc::new(Db::open_in_memory(&key).unwrap())));
	f.state.db = Arc::new(Db::open(&path, &key).unwrap());
	execute(&f,"UPDATE review_generations SET generated_profile='{}',generated_profile_digest=zeroblob(32); UPDATE review_campaigns SET state='cancelled'");
	assert_eq!(post(&f, "finalize-drilldown", input.clone()).await, first);
	execute(&f, "DELETE FROM review_generations");
	f.state
		.db
		.with_conn(|conn| {
			let StoredEvidence::Recorded(details) =
				loupe_storage::finding_details::get_review_evidence(conn, finding)?
			else {
				panic!("retained finding")
			};
			assert_eq!(details.evidence, original.evidence);
			assert_eq!(details.profile_digest, original.profile_digest);
			assert_eq!(details.reviewed_commit_sha, original.reviewed_commit_sha);
			assert!(details.origin_lead.is_none());
			let StoredEvidence::Recorded(terminal_payloads::TerminalPayload::Drilldown(stored)) =
				terminal_payloads::get(conn, f.job)?
			else {
				panic!("retained terminal")
			};
			assert_eq!(
				stored.canonical_bytes().unwrap(),
				DrilldownTerminalV1::from_json(&input["payload"].to_string())
					.unwrap()
					.canonical_bytes()
					.unwrap()
			);
			Ok(())
		})
		.unwrap();
	assert_eq!(post(&f, "finalize-drilldown", input.clone()).await, first);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM findings"), 1);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 1);
}

#[tokio::test]
async fn wrong_identity_old_attempt_and_unprepared_or_expired_jobs_cannot_finalize() {
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
	] {
		let (mut f, _, _) = ready().await;
		match damage {
			"worker"=>f.peer=f.other_peer.clone(),"token"=>f.token="x".repeat(43),
			"attempt"=>execute(&f,&format!("UPDATE jobs SET attempts=attempts+1 WHERE id={}",f.job)),
			"unprepared"=>execute(&f,&format!("UPDATE jobs SET prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id={}",f.job)),
			"expired"=>execute(&f,&format!("UPDATE jobs SET lease_expires_at=0 WHERE id={}",f.job)),
			"deadline"=>execute(&f,&format!("UPDATE jobs SET hard_deadline_at=0 WHERE id={}",f.job)),
			"unsupported"=>execute(&f,&format!("UPDATE jobs SET recipe='{{\"version\":2,\"phase\":\"drilldown\"}}' WHERE id={}",f.job)),
			"assignment"=>execute(&f,&format!("UPDATE jobs SET assigned_lead_id=NULL WHERE id={}",f.job)),
			_=>execute(&f,&format!("UPDATE jobs SET kind='verify' WHERE id={}",f.job)),
		}
		let (status, value) = request(&f, f.job, "finalize-drilldown", reject()).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{damage}: {value}");
		assert_eq!(value["error"]["code"], "denied");
		assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 0);
	}
}

#[tokio::test]
async fn receipt_replay_authenticates_finishing_worker_and_capability_before_digest_conflict() {
	let (mut f, _, _) = ready().await;
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
	let accepted = post(&f, "finalize-drilldown", reject()).await;
	let new = f.token.clone();
	f.token = old;
	assert_eq!(request(&f, f.job, "finalize-drilldown", reject()).await.0, StatusCode::FORBIDDEN);
	f.token = new;
	let originalpeer = f.peer.clone();
	f.peer = f.other_peer.clone();
	assert_eq!(request(&f, f.job, "finalize-drilldown", reject()).await.0, StatusCode::FORBIDDEN);
	f.peer = originalpeer;
	let mut divergent = reject();
	divergent["payload"]["counterargument"]["argument"] = json!("Changed evidence");
	let (status, value) = request(&f, f.job, "finalize-drilldown", divergent).await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(value["error"]["code"], "terminal_conflict");
	assert_eq!(post(&f, "finalize-drilldown", reject()).await, accepted);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 1);
}

#[tokio::test]
async fn strict_transport_rejects_unknown_duplicate_oversized_and_encoded_payloads() {
	let (f, _, _) = ready().await;
	let valid = reject().to_string();
	let cases = [
		(
			valid.replace("\"version\":1", "\"version\":1,\"version\":1"),
			"3",
			"identity",
			StatusCode::BAD_REQUEST,
		),
		(
			valid.replace("\"payload\":{", "\"payload\":{\"owner\":1,"),
			"3",
			"identity",
			StatusCode::BAD_REQUEST,
		),
		(
			valid.replace("\"payload\":{", "\"lead_id\":1,\"payload\":{"),
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
	];
	for (body, version, encoding, expected) in cases {
		let mut req = Request::post(format!("/v1/jobs/{}/finalize-drilldown", f.job))
			.header(PROTOCOL_VERSION_HEADER, version)
			.header(JOB_CAPABILITY_HEADER, &f.token)
			.header("content-type", "application/json")
			.header("content-encoding", encoding)
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
	let mut req = Request::post(format!("/v1/jobs/{}/finalize-drilldown", f.job))
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
	assert!(!String::from_utf8_lossy(&bytes).contains("All callers enforce"));
}

#[tokio::test]
async fn continuation_failure_rolls_back_success_and_replay_keeps_the_sealed_decision() {
	let (f, _, lead) = ready().await;
	let input = body(json!({"version":1,"disposition":"defer","reason":"More work\nkept intact",
		"continuation":"source_analysis_remaining","retry_explanation":"Retry\nafter the frozen delay"}));
	execute(&f,"CREATE TRIGGER fail_continuation BEFORE UPDATE ON lead_drilldown_intents BEGIN SELECT RAISE(ABORT,'injected continuation failure'); END");
	assert_eq!(
		request(&f, f.job, "finalize-drilldown", input.clone()).await.0,
		StatusCode::INTERNAL_SERVER_ERROR
	);
	assert_eq!(scalar(&f,&format!("SELECT COUNT(*) FROM jobs WHERE id={} AND state='leased' AND job_capability_hash IS NOT NULL",f.job)),1);
	assert_eq!(scalar(&f,&format!("SELECT COUNT(*) FROM leads WHERE lead_id={lead} AND status='open' AND defer_reason IS NULL")),1);
	assert_eq!(scalar(&f, "SELECT intent_revision FROM lead_drilldown_intents"), 1);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 0);
	execute(&f, "DROP TRIGGER fail_continuation");
	let reply = post(&f, "finalize-drilldown", input.clone()).await;
	let due = reply["receipt"]["summary"]["continuation"]["not_before"].as_i64().unwrap();
	assert_eq!(scalar(&f, "SELECT intent_revision FROM lead_drilldown_intents"), 2);
	// A later administrative change to derived work must not rewrite what the
	// terminal receipt says was accepted, nor cause replay to repair that state.
	execute(&f, &format!("UPDATE lead_drilldown_intents SET not_before={}", due + 3600));
	assert_eq!(post(&f, "finalize-drilldown", input).await, reply);
	assert_eq!(scalar(&f, "SELECT not_before FROM lead_drilldown_intents"), due + 3600);
	assert_eq!(scalar(&f, "SELECT intent_revision FROM lead_drilldown_intents"), 2);
}

#[tokio::test]
async fn structural_bounds_reject_missing_evidence_and_excess_nested_refs_before_mutation() {
	let (f, _, _) = ready().await;
	let mut cases = Vec::new();
	for count in [0, 17] {
		let mut input = reject();
		input["payload"]["counterargument"]["source_refs"] =
			json!(vec![json!({"path":"z.rs"}); count]);
		cases.push(input);
		let mut input = promote();
		input["payload"]["promotion"]["evidence"]["material_locations"] =
			json!(vec![json!({"role":"sink","file":"z.rs"}); count]);
		cases.push(input);
		let mut input = reject();
		input["payload"]["revalidation"] = json!({"rationale":"reviewed","current_source_refs":vec![json!({"path":"z.rs"});count]});
		cases.push(input);
	}
	let mut input = reject();
	input["payload"]["counterargument"]["argument"] = json!("a".repeat(8001));
	cases.push(input);
	let mut input = reject();
	input["payload"]["counterargument"]["source_refs"][0]["path"] = json!("../escape.rs");
	cases.push(input);
	let mut input = duplicate("lead", 1);
	input["payload"]["target"]["finding_id"] = json!(1);
	cases.push(input);
	let mut input = promote();
	input["payload"]["promotion"]["evidence"]["established_rung"] = json!("L3");
	cases.push(input);
	for input in cases {
		assert_eq!(
			request(&f, f.job, "finalize-drilldown", input).await.0,
			StatusCode::BAD_REQUEST
		);
	}
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 0);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM findings"), 0);
}

#[tokio::test]
async fn carried_evidence_keeps_old_producer_provenance_without_requiring_its_generation() {
	let (f, _, lead) = ready().await;
	f.state.db.with_conn(|conn| transaction::immediate(conn,|tx| {
		tx.execute("INSERT INTO review_generations(repo_id,generation_commit_sha,state,workflow_contract_version,created_at) VALUES(1,?1,'retired',1,0)",[NEXT_SHA])?;
		let old_generation=tx.last_insert_rowid();
		tx.execute("INSERT INTO jobs(repo_id,kind,state,campaign_id,generation_id,head_sha,workflow_contract_version,enqueued_at) VALUES(1,'survey','succeeded',?1,?2,?3,1,0)",params![f.campaign,old_generation,NEXT_SHA])?;
		let producer=tx.last_insert_rowid();
		tx.execute("UPDATE leads SET created_by_job_id=?2,commit_sha=?3,needs_revalidation=1 WHERE lead_id=?1",params![lead,producer,NEXT_SHA])?;
		tx.execute("DELETE FROM review_generations WHERE generation_id=?1",[old_generation])?;
		Ok(())
	})).unwrap();
	assert_eq!(request(&f, f.job, "finalize-drilldown", promote()).await.0, StatusCode::CONFLICT);
	let mut input = promote();
	input["payload"]["revalidation"] = json!({"current_source_refs":[{"path":"z.rs"}],"rationale":"Re-established the source argument at the pinned current checkout."});
	post(&f, "finalize-drilldown", input).await;
	f.state
		.db
		.with_conn(|conn| {
			assert_eq!(leads::get_metadata(conn, lead)?.unwrap().commit_sha, NEXT_SHA);
			Ok(())
		})
		.unwrap();
}
