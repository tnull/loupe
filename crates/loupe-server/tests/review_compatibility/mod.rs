//! Explicit operator reset is the only early-purge boundary. Canonical evidence
//! and receipts survive; a later ordinary open must choose a fresh bootstrap.
use super::*;

fn admin(f: &Fixture) -> PeerCert {
	let bundle = f.state.ca.mint_client("reset-admin").unwrap();
	let peer =
		PeerCert(rustls_pemfile::certs(&mut bundle.cert_pem.as_bytes()).next().unwrap().unwrap());
	f.state
		.db
		.with_conn(|conn| {
			workers::insert(
				conn,
				"reset-admin",
				workers::WorkerKind::Admin,
				&loupe_tls::cert_fingerprint(peer.0.as_ref()),
				now(),
			)?;
			Ok(())
		})
		.unwrap();
	peer
}

async fn reset(f: &Fixture, generation: i64, peer: &PeerCert) -> (StatusCode, Value) {
	let mut req = Request::post(format!("/v1/review-generations/{generation}/reset"))
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header("content-type", "application/json")
		.body(Body::from(r#"{"protocol_version":3}"#))
		.unwrap();
	req.extensions_mut().insert(peer.clone());
	let response = router(f.state.clone()).call(req).await.unwrap();
	let status = response.status();
	assert_ne!(status, StatusCode::NOT_FOUND, "operator reset route must exist");
	assert_eq!(
		response.headers().get("cache-control").and_then(|v| v.to_str().ok()),
		Some("no-store")
	);
	let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
	(status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn quiescent_reset_purges_derived_state_and_next_open_bootstraps() {
	let f = fixture();
	let generation = prepare(&f).await;
	let peer = admin(&f);
	f.state
		.db
		.with_conn(|conn| {
			conn.execute("UPDATE jobs SET state='cancelled' WHERE id=?1", [f.job])?;
			conn.execute(
				"UPDATE review_campaigns SET state='cancelled' WHERE campaign_id=?1",
				[f.campaign],
			)?;
			Ok(())
		})
		.unwrap();
	let (status, reply) = reset(&f, generation, &peer).await;
	assert_eq!(status, StatusCode::OK, "quiescent reset endpoint: {reply}");
	assert_eq!(reply["inventory_entries_removed"], 3);
	assert_eq!(reply["verification_intents_blocked"], 0);
	let replacement = f
		.state
		.db
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let retired = loupe_storage::generations::get(tx, generation)?.unwrap();
				assert_eq!(retired.state, loupe_storage::generations::State::Retired);
				assert!(
					retired.generated_profile.is_none()
						&& retired.inventory_digest.is_none()
						&& retired.pending_follow_up.is_none()
				);
				assert_eq!(
					tx.query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get::<_, i64>(0))?,
					1
				);
				let campaign::Opened::Created { campaign_id, job_id } = campaign::open(
					tx,
					&campaign::OpenCampaign {
						repo_id: 1,
						trigger: loupe_storage::campaigns::Trigger::Manual,
						requested_ref: campaign::RequestedRef::Pinned(SHA),
						base_sha: None,
						kind_hint: campaign::KindHint::Incremental,
					},
					&ReviewPolicy::default(),
					now(),
				)?
				else {
					panic!("fresh campaign")
				};
				let campaign = loupe_storage::campaigns::get(tx, campaign_id)?.unwrap();
				assert_eq!(campaign.recipe, loupe_storage::campaigns::Recipe::Bootstrap);
				let fresh =
					loupe_storage::generations::get(tx, campaign.generation_id.unwrap())?.unwrap();
				assert_ne!(
					fresh.generation_id, generation,
					"A reset generation ID must never name its replacement"
				);
				assert_eq!(fresh.state, loupe_storage::generations::State::Building);
				assert_eq!(fresh.coverage, loupe_storage::generations::Coverage::Unknown);
				assert!(fresh.generated_profile.is_none());
				assert!(fresh.predecessor_generation_id.is_none());
				assert_eq!(
					loupe_storage::jobs::get(tx, job_id)?.unwrap().kind,
					loupe_core::JobKind::Survey
				);
				Ok(fresh.generation_id)
			})
		})
		.unwrap();
	f.state
		.db
		.with_conn(|conn| {
			conn.execute(
				"UPDATE jobs SET state='cancelled' WHERE state IN('queued','leased')",
				[],
			)?;
			conn.execute("UPDATE review_campaigns SET state='cancelled' WHERE state='active'", [])?;
			Ok(())
		})
		.unwrap();
	assert_eq!(
		reset(&f, generation, &peer).await.0,
		StatusCode::CONFLICT,
		"An old request cannot reset its quiescent replacement"
	);
	f.state
		.db
		.with_conn(|conn| {
			let fresh = loupe_storage::generations::get(conn, replacement)?.unwrap();
			assert_eq!(fresh.state, loupe_storage::generations::State::Building);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn reset_preserves_promotion_evidence_receipts_and_pending_verification_on_disk() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("reset.sqlite");
	let key = loupe_storage::secrets::MasterKey::for_tests();
	let db = Arc::new(Db::open(&path, &key).unwrap());
	let (f, generation, _) = drilldown_terminal::ready_fixture(fixture_with_db(db)).await;
	let input = drilldown_terminal::promote();
	let receipt = post(&f, "finalize-drilldown", input.clone()).await;
	let peer = admin(&f);
	let before = f.state.db.with_conn(|conn| {
		conn.execute("UPDATE jobs SET state='cancelled' WHERE state IN('queued','leased')", [])?;
		conn.execute("UPDATE review_campaigns SET state='cancelled'", [])?;
		// Oversized derived closure criteria motivate rebuilding, not truncation.
		conn.execute("INSERT INTO review_units(generation_id,client_review_unit_key,title,objective,source_refs,closure_criteria,created_at) VALUES(?1,'historical','unit','objective','[]',?2,0)",params![generation,"x".repeat(3000)])?;
		Ok((snapshot(conn,"SELECT * FROM findings"), snapshot(conn,"SELECT evidence_payload,reviewed_commit_sha,profile_version,profile_digest FROM finding_review_details"), snapshot(conn,"SELECT originating_job_id,originating_campaign_id,admission_campaign_id,source_commit_sha,profile_version,profile_digest,intent_revision,intent_kind,continuation_class,logical_sequence,accepted_band,accepted_score,priority_policy_version,created_at FROM finding_verification_intents")))
	}).unwrap();
	let (status, reply) = reset(&f, generation, &peer).await;
	assert_eq!(status, StatusCode::OK, "{reply}");
	assert_eq!(reply["verification_intents_blocked"], 1);
	assert_eq!(reply["review_units_removed"], 1);
	assert_eq!(
		request(&f, f.job, "finalize-drilldown", input.clone()).await,
		(StatusCode::OK, receipt.clone())
	);
	let Fixture { state, peer: worker_peer, other_peer, worker, job, campaign, token } = f;
	drop(state);
	let db = Arc::new(Db::open(&path, &key).unwrap());
	db.with_conn(|conn| {
		assert_eq!(snapshot(conn,"SELECT * FROM findings"),before.0);
		assert_eq!(snapshot(conn,"SELECT evidence_payload,reviewed_commit_sha,profile_version,profile_digest FROM finding_review_details"),before.1);
		assert_eq!(snapshot(conn,"SELECT originating_job_id,originating_campaign_id,admission_campaign_id,source_commit_sha,profile_version,profile_digest,intent_revision,intent_kind,continuation_class,logical_sequence,accepted_band,accepted_score,priority_policy_version,created_at FROM finding_verification_intents"),before.2);
		assert_eq!(conn.query_row("SELECT state,block_reason,generation_id FROM finding_verification_intents",[],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<i64>>(2)?)))?,("blocked".into(),"requires_successor".into(),None));
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM review_units",[],|r|r.get::<_,i64>(0))?,0);
		assert!(snapshot(conn,"PRAGMA foreign_key_check").is_empty());
		Ok(())
	}).unwrap();
	let f = Fixture {
		state: AppState::new(
			db,
			Arc::new(Ca::new("restart").unwrap()),
			Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()),
		),
		peer: worker_peer,
		other_peer,
		worker,
		job,
		campaign,
		token,
	};
	assert_eq!(request(&f, job, "finalize-drilldown", input).await, (StatusCode::OK, receipt));
}

fn snapshot(conn: &rusqlite::Connection, sql: &str) -> Vec<Vec<rusqlite::types::Value>> {
	let mut statement = conn.prepare(sql).unwrap();
	let count = statement.column_count();
	statement
		.query_map([], |row| (0..count).map(|i| row.get(i)).collect())
		.unwrap()
		.collect::<rusqlite::Result<_>>()
		.unwrap()
}

#[tokio::test]
async fn reset_refuses_busy_generation_and_worker_authority_without_mutation() {
	let f = fixture();
	let generation = prepare(&f).await;
	let peer = admin(&f);
	assert_eq!(reset(&f, generation, &f.peer).await.0, StatusCode::FORBIDDEN);
	for queued in [false, true] {
		f.state
			.db
			.with_conn(|conn| {
				conn.execute(
					"UPDATE jobs SET state=?1 WHERE id=?2",
					params![if queued { "queued" } else { "leased" }, f.job],
				)?;
				Ok(())
			})
			.unwrap();
		assert_eq!(reset(&f, generation, &peer).await.0, StatusCode::CONFLICT);
	}
	f.state
		.db
		.with_conn(|conn| {
			conn.execute("UPDATE jobs SET state='cancelled' WHERE id=?1", [f.job])?;
			Ok(())
		})
		.unwrap();
	assert_eq!(
		reset(&f, generation, &peer).await.0,
		StatusCode::CONFLICT,
		"active campaign remains busy"
	);
	f.state
		.db
		.with_conn(|conn| {
			assert_eq!(
				conn.query_row("SELECT COUNT(*) FROM generation_inventory", [], |r| r
					.get::<_, i64>(0))?,
				3
			);
			assert_eq!(
				conn.query_row("SELECT state FROM review_generations", [], |r| r
					.get::<_, String>(0))?,
				"building"
			);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn reset_requires_strict_bounded_protocol_and_active_admin() {
	let f = fixture();
	let generation = prepare(&f).await;
	let peer = admin(&f);
	for (raw, version, authenticated, expected) in [
		(r#"{"protocol_version":3,"extra":true}"#.to_string(), "3", true, 400),
		(r#"{"protocol_version":3,"protocol_version":3}"#.to_string(), "3", true, 400),
		(r#"{"protocol_version":2}"#.to_string(), "3", true, 400),
		(r#"{"protocol_version":3}"#.to_string(), "2", true, 400),
		(" ".repeat(8193), "3", true, 413),
		(r#"{"protocol_version":3}"#.to_string(), "3", false, 401),
	] {
		let mut req = Request::post(format!("/v1/review-generations/{generation}/reset"))
			.header(PROTOCOL_VERSION_HEADER, version)
			.header("content-type", "application/json")
			.body(Body::from(raw))
			.unwrap();
		if authenticated {
			req.extensions_mut().insert(peer.clone());
		}
		let reply = router(f.state.clone()).call(req).await.unwrap();
		assert_eq!(reply.status().as_u16(), expected);
		assert_eq!(reply.headers()["cache-control"], "no-store");
		let bytes = to_bytes(reply.into_body(), 4096).await.unwrap();
		assert!(serde_json::from_slice::<Value>(&bytes).unwrap()["error"]["code"].is_string());
	}
	f.state
		.db
		.with_conn(|conn| {
			conn.execute("UPDATE workers SET revoked_at=?1 WHERE name='reset-admin'", [now()])?;
			Ok(())
		})
		.unwrap();
	assert_eq!(reset(&f, generation, &peer).await.0, StatusCode::UNAUTHORIZED);
}
