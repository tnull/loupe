//! Campaign completion must inspect durable work, not just materialized jobs.
use rusqlite::params;

use super::*;

fn pending_lead(
	tx: &rusqlite::Transaction<'_>, campaign: i64, generation: i64, job: i64, due: Option<i64>,
) -> loupe_storage::Result<()> {
	let (kind, class, sequence) = if due.is_some() {
		("logical_continuation", Some("source_analysis_remaining"), 1)
	} else {
		("initial_handoff", None, 0)
	};
	tx.execute("INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_by_job_id,created_at) VALUES(1,?1,'family','anchor',zeroblob(32),'{}',zeroblob(32),?2,?3,0)",params![generation,SHA,job])?;
	tx.execute("INSERT INTO lead_drilldown_intents(lead_id,repo_id,generation_id,originating_job_id,originating_campaign_id,admission_campaign_id,source_commit_sha,profile_version,profile_digest,intent_revision,intent_kind,continuation_class,logical_sequence,state,not_before,accepted_band,accepted_score,priority_policy_version,created_at,updated_at) VALUES(1,1,?1,?2,?3,?3,?4,1,zeroblob(32),1,?5,?6,?7,'pending',?8,'normal',0,1,0,0)",params![generation,job,campaign,SHA,kind,class,sequence,due])?;
	Ok(())
}

#[test]
fn campaign_creation_freezes_v2_and_charges_only_preparation_once() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let (campaign, job) = created(campaign::open(
				tx,
				&request(RequestedRef::Branch("main")),
				&ReviewPolicy::default(),
				0,
			)?);
			let stored = campaigns::get(tx, campaign)?.unwrap();
			let snapshot: serde_json::Value =
				serde_json::from_str(stored.effective_policy.expose()).unwrap();
			assert_eq!(snapshot["version"], 2, "new campaign must freeze V2 admission policy");
			assert_eq!(loupe_storage::admission::get_spending(tx, campaign)?.unwrap().general, 1);
			assert_eq!(
				tx.query_row(
					"SELECT COUNT(*) FROM job_admission_charges WHERE job_id=?1",
					[job],
					|r| r.get::<_, i64>(0)
				)?,
				1
			);
			assert_eq!(
				campaign::open(
					tx,
					&request(RequestedRef::Branch("main")),
					&ReviewPolicy::default(),
					1
				)?,
				Opened::Pending { campaign_id: campaign }
			);
			assert_eq!(
				tx.query_row("SELECT COUNT(*) FROM jobs WHERE campaign_id=?1", [campaign], |r| {
					r.get::<_, i64>(0)
				})?,
				1
			);
			assert_eq!(loupe_storage::admission::get_spending(tx, campaign)?.unwrap().total()?, 1);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn coverage_replenishment_never_allocates_a_speculative_child() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let (campaign, _) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, true)?;
			assert_eq!(
				campaign::replenish(tx, campaign, 1)?,
				None,
				"coverage work must compete at first claim, not consume a queued child"
			);
			assert_eq!(
				tx.query_row("SELECT COUNT(*) FROM jobs WHERE campaign_id=?1", [campaign], |r| {
					r.get::<_, i64>(0)
				})?,
				1
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn pending_handoff_without_workers_prevents_premature_completion() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let (campaign, generation) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, false)?;
			let job =
				tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1", [campaign], |r| r.get(0))?;
			pending_lead(tx, campaign, generation, job, None)?;
			assert_eq!(
				campaign::try_finish(tx, campaign, 1)?,
				None,
				"accepted pending lead must remain schedulable without a connected worker"
			);
			assert_eq!(campaigns::get(tx, campaign)?.unwrap().state, campaigns::State::Active);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn delayed_pending_work_due_before_deadline_keeps_campaign_active() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let (campaign, generation) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, false)?;
			let job =
				tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1", [campaign], |r| r.get(0))?;
			pending_lead(tx, campaign, generation, job, Some(100))?;
			assert_eq!(
				campaign::try_finish(tx, campaign, 1)?,
				None,
				"a delayed continuation must not need a speculative child to survive"
			);
			Ok(())
		})
	})
	.unwrap();
}

fn pending_finding(
	tx: &rusqlite::Transaction<'_>, campaign: i64, generation: i64, job: i64,
) -> loupe_storage::Result<()> {
	tx.execute("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,created_at) VALUES(1,1,?1,'review','high','Canonical finding','Complete original evidence','finding','validating',0)",[job])?;
	tx.execute("INSERT INTO finding_verification_intents(finding_id,repo_id,generation_id,originating_job_id,originating_campaign_id,admission_campaign_id,source_commit_sha,profile_version,profile_digest,intent_revision,intent_kind,logical_sequence,state,accepted_band,accepted_score,priority_policy_version,created_at,updated_at) VALUES(1,1,?1,?2,?3,?3,?4,1,zeroblob(32),1,'initial_handoff',0,'pending','normal',0,1,0,0)",params![generation,job,campaign,SHA])?;
	Ok(())
}

#[test]
fn protected_capacity_blocks_normal_lead_but_keeps_verification_pending() {
	let db = fixture();
	db.with_conn(|conn|transaction::immediate(conn,|tx| {
		let (campaign,generation)=idle_campaign(tx,1,&ReviewPolicy::default(),0,true)?;
		let job=tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1",[campaign],|r|r.get(0))?;
		pending_lead(tx,campaign,generation,job,None)?;
		pending_finding(tx,campaign,generation,job)?;
		tx.execute("UPDATE campaign_admission_spending SET general_spent=56 WHERE campaign_id=?1",[campaign])?;
		assert_eq!(campaign::try_finish(tx,campaign,1)?,None);
		assert_eq!(tx.query_row("SELECT block_reason FROM lead_drilldown_intents",[],|r|r.get::<_,String>(0))?,"protected_capacity");
		assert_eq!(tx.query_row("SELECT state FROM finding_verification_intents",[],|r|r.get::<_,String>(0))?,"pending");
		assert_eq!(tx.query_row("SELECT defer_reason FROM review_units",[],|r|r.get::<_,String>(0))?,"protected_capacity");
		assert_eq!(tx.query_row("SELECT COUNT(*) FROM jobs",[],|r|r.get::<_,i64>(0))?,1,"no speculative verification child");
		tx.execute("UPDATE campaign_admission_spending SET urgent_spent=4,verification_spent=4 WHERE campaign_id=?1",[campaign])?;
		assert_eq!(campaign::try_finish(tx,campaign,2)?,Some(campaign::Finish::Completed));
		assert_eq!(tx.query_row("SELECT block_reason FROM finding_verification_intents",[],|r|r.get::<_,String>(0))?,"campaign_budget");
		assert_eq!(tx.query_row("SELECT state,description FROM findings",[],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?,("validating".into(),"Complete original evidence".into()));
		let saved=campaigns::get(tx,campaign)?.unwrap();
		assert_eq!(saved.terminal_reason.unwrap().expose(),"campaign_budget");
		let summary:serde_json::Value=serde_json::from_str(saved.terminal_counts.unwrap().expose()).unwrap();
		assert_eq!(summary["pending_work"]["findings"][0]["count"],1);
		assert_eq!(summary["pending_work"]["findings"][0]["reason"],"campaign_budget");
		Ok(())
	})).unwrap();
}

#[test]
fn due_at_or_beyond_deadline_is_retained_as_blocked_not_polled() {
	for due in [21600, 21601] {
		let db = fixture();
		db.with_conn(|conn|transaction::immediate(conn,|tx| {
			let (campaign,generation)=idle_campaign(tx,1,&ReviewPolicy::default(),0,false)?;
			let job=tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1",[campaign],|r|r.get(0))?;
			pending_lead(tx,campaign,generation,job,Some(due))?;
			assert_eq!(campaign::try_finish(tx,campaign,1)?,Some(campaign::Finish::Completed));
			assert_eq!(tx.query_row("SELECT state,block_reason,intent_revision,logical_sequence FROM lead_drilldown_intents",[],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?)))?,("blocked".into(),"campaign_deadline".into(),1,1));
			Ok(())
		})).unwrap();
	}
}

fn held_batch(
	tx: &rusqlite::Transaction<'_>, campaign: i64, generation: i64, job: i64,
) -> loupe_storage::Result<()> {
	tx.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES(1,?1,'held','unit','unfinished','[]',0)",[generation])?;
	tx.execute("INSERT INTO review_unit_results(review_unit_result_id,review_unit_id,produced_by_job_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at) VALUES(1,1,?1,?2,1,'needs_follow_up','[]','{}',zeroblob(32),0)",params![job,SHA])?;
	tx.execute("INSERT INTO survey_continuation_batches(batch_id,repo_id,generation_id,campaign_id,producer_job_id,batch_ordinal,logical_sequence,continuation_class,state,not_before,expected_unit_count,accepted_band,accepted_score,priority_policy_version,created_at) VALUES(1,1,?1,?2,?3,0,1,'source_analysis_remaining','pending',100,1,'normal',0,1,0)",params![generation,campaign,job])?;
	tx.execute("INSERT INTO review_unit_holds(review_unit_id,generation_id,producing_job_id,producing_result_id,source_assignment_epoch,continuation_class,pending_batch_id,batch_position,created_at,updated_at) VALUES(1,?1,?2,1,0,'source_analysis_remaining',1,0,0,0)",params![generation,job])?;
	Ok(())
}

#[test]
fn cancellation_and_deadline_preserve_exact_holds_and_live_control_identity() {
	for cancel in [true, false] {
		let db = fixture();
		db.with_conn(|conn|transaction::immediate(conn,|tx| {
			let (campaign,generation)=idle_campaign(tx,1,&ReviewPolicy::default(),0,false)?;
			let job=tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1",[campaign],|r|r.get(0))?;
			pending_lead(tx,campaign,generation,job,None)?;
			pending_finding(tx,campaign,generation,job)?;
			held_batch(tx,campaign,generation,job)?;
			assert_eq!(campaign::try_finish(tx,campaign,1)?,None,"future exact batch is pending work");
			tx.execute("UPDATE jobs SET state='leased',job_capability_hash=zeroblob(32),lease_expires_at=22000 WHERE id=?1",[job])?;
			let reason=if cancel {
				campaign::cancel(tx,campaign,&BoundedText::new("operator")?,2)?;
				"campaign_cancelled"
			} else {
				assert_eq!(campaign::try_finish(tx,campaign,21600)?,None);
				"campaign_deadline"
			};
			for table in ["lead_drilldown_intents","finding_verification_intents","survey_continuation_batches","review_unit_holds"] {
				assert_eq!(tx.query_row(&format!("SELECT block_reason FROM {table}"),[],|r|r.get::<_,String>(0))?,reason);
			}
			assert_eq!(tx.query_row("SELECT producing_job_id,producing_result_id,source_assignment_epoch,pending_batch_id,batch_position FROM review_unit_holds",[],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?)))?,(job,1,0,1,0));
			assert_eq!(tx.query_row("SELECT state,length(job_capability_hash),lease_expires_at FROM jobs WHERE id=?1",[job],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?)))?,("leased".into(),32,22000));
			assert_eq!(tx.query_row("SELECT state FROM findings",[],|r|r.get::<_,String>(0))?,"validating");
			assert_eq!(tx.query_row("SELECT defer_reason FROM review_units",[],|r|r.get::<_,String>(0))?,reason);
			Ok(())
		})).unwrap();
	}
}

#[test]
fn historical_and_malformed_policies_are_held_without_fabricated_accounting() {
	for raw in [ReviewPolicy::default().snapshot().unwrap().expose().to_owned(), "not json".into()]
	{
		let db = fixture();
		db.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let (campaign, generation) =
					idle_campaign(tx, 1, &ReviewPolicy::default(), 0, false)?;
				let job =
					tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1", [campaign], |r| {
						r.get(0)
					})?;
				pending_finding(tx, campaign, generation, job)?;
				tx.execute(
					"UPDATE review_campaigns SET effective_policy=?2 WHERE campaign_id=?1",
					params![campaign, raw],
				)?;
				assert_eq!(
					campaign::try_finish(tx, campaign, 1)?,
					Some(campaign::Finish::Completed)
				);
				assert_eq!(
					tx.query_row("SELECT terminal_reason FROM review_campaigns", [], |r| r
						.get::<_, String>(0))?,
					"compatibility_policy"
				);
				assert_eq!(
					tx.query_row("SELECT state FROM findings", [], |r| r.get::<_, String>(0))?,
					"validating"
				);
				assert_eq!(
					loupe_storage::admission::get_spending(tx, campaign)?.unwrap().total()?,
					1
				);
				Ok(())
			})
		})
		.unwrap();
	}
}

#[test]
fn b8_reconciliation_is_explicitly_deferred_without_a_preparation_charge() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let (previous, _) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, false)?;
			campaign::try_finish(tx, previous, 1)?;
			let mut new = request(RequestedRef::Branch("main"));
			new.kind_hint = KindHint::FullReview;
			let Opened::Deferred { campaign_id } =
				campaign::open(tx, &new, &ReviewPolicy::default(), 2)?
			else {
				panic!("B8 reconciliation must be deferred")
			};
			let row = campaigns::get(tx, campaign_id)?.unwrap();
			assert_eq!(row.target_commit_sha, "main");
			assert_eq!(row.recipe, campaigns::Recipe::Reconciliation);
			assert_eq!(row.terminal_reason.unwrap().expose(), "unsupported_recipe");
			assert_eq!(row.state, campaigns::State::Finished);
			assert_eq!(
				tx.query_row(
					"SELECT COUNT(*) FROM jobs WHERE campaign_id=?1",
					[campaign_id],
					|r| r.get::<_, i64>(0)
				)?,
				0
			);
			assert!(loupe_storage::admission::get_spending(tx, campaign_id)?.is_none());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn terminal_summary_downgrades_stale_complete_coverage_and_preserves_unknown() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let (campaign, generation) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, true)?;
			tx.execute(
				"UPDATE review_generations SET coverage='complete' WHERE generation_id=?1",
				[generation],
			)?;
			assert_eq!(
				campaigns::summarize(tx, campaign)?.coverage,
				generations::Coverage::Partial,
				"terminal summary cannot preserve stale complete coverage with uncovered units"
			);
			tx.execute(
				"UPDATE review_generations SET coverage='unknown' WHERE generation_id=?1",
				[generation],
			)?;
			assert_eq!(
				campaigns::summarize(tx, campaign)?.coverage,
				generations::Coverage::Unknown,
				"summary does not promote historical coverage"
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn known_changed_target_is_deferred_without_a_preparation_job_or_charge() {
	for reference in
		[RequestedRef::Pinned(DIFFERENT), RequestedRef::Pinned(SHA), RequestedRef::Branch("main")]
	{
		fixture()
			.with_conn(|conn| {
				transaction::immediate(conn, |tx| {
					let (previous, baseline) =
						idle_campaign(tx, 1, &ReviewPolicy::default(), 0, false)?;
					campaign::try_finish(tx, previous, 1)?;
					let opened =
						campaign::open(tx, &request(reference), &ReviewPolicy::default(), 2)?;
					if matches!(reference, RequestedRef::Pinned(DIFFERENT)) {
						assert!(
							matches!(opened, Opened::Deferred { .. }),
							"known B8 target must not allocate preparation: {opened:?}"
						);
						let Opened::Deferred { campaign_id } = opened else { unreachable!() };
						let row = campaigns::get(tx, campaign_id)?.unwrap();
						assert_eq!(row.recipe, campaigns::Recipe::Incremental);
						assert_eq!(row.target_commit_sha, DIFFERENT);
						assert_eq!(row.state, campaigns::State::Finished);
						assert_eq!(row.terminal_reason.unwrap().expose(), "unsupported_recipe");
						assert_eq!(
							tx.query_row(
								"SELECT COUNT(*) FROM jobs WHERE campaign_id=?1",
								[campaign_id],
								|r| r.get::<_, i64>(0)
							)?,
							0
						);
						assert_eq!(
							tx.query_row(
								"SELECT COUNT(*) FROM job_admission_charges WHERE campaign_id=?1",
								[campaign_id],
								|r| r.get::<_, i64>(0)
							)?,
							0
						);
						assert!(loupe_storage::admission::get_spending(tx, campaign_id)?.is_none());
						assert_eq!(
							generations::get(tx, baseline)?.unwrap().state,
							generations::State::Active
						);
					} else {
						let (campaign, job) = created(opened);
						assert_eq!(jobs::get(tx, job)?.unwrap().state, JobState::Queued);
						assert_eq!(
							loupe_storage::admission::get_spending(tx, campaign)?
								.unwrap()
								.total()?,
							1
						);
					}
					Ok(())
				})
			})
			.unwrap();
	}
}

#[test]
fn exact_batch_alone_waits_then_preserves_members_on_protected_refusal() {
	let db = fixture();
	db.with_conn(|conn|transaction::immediate(conn,|tx| {
		let (campaign,generation)=idle_campaign(tx,1,&ReviewPolicy::default(),0,false)?;
		let job=tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1",[campaign],|r|r.get(0))?;
		held_batch(tx,campaign,generation,job)?;
		assert_eq!(campaign::try_finish(tx,campaign,1)?,None);
		tx.execute("UPDATE campaign_admission_spending SET general_spent=56 WHERE campaign_id=?1",[campaign])?;
		assert_eq!(campaign::try_finish(tx,campaign,2)?,Some(campaign::Finish::Completed));
		assert_eq!(tx.query_row("SELECT state,block_reason,expected_unit_count FROM survey_continuation_batches",[],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?)))?,("blocked".into(),"protected_capacity".into(),1));
		assert_eq!(tx.query_row("SELECT block_reason FROM review_unit_holds",[],|r|r.get::<_,String>(0))?,"protected_capacity");
		assert_eq!(tx.query_row("SELECT COUNT(*) FROM review_unit_results",[],|r|r.get::<_,i64>(0))?,1);
		assert_eq!(tx.query_row("SELECT defer_reason FROM review_units",[],|r|r.get::<_,String>(0))?,"protected_capacity");
		Ok(())
	})).unwrap();
}

#[test]
fn queued_execution_retry_remains_active_without_spending_again() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let (campaign, _) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, false)?;
			tx.execute(
				"UPDATE jobs SET state='queued',eligible_at=100,attempts=1 WHERE campaign_id=?1",
				[campaign],
			)?;
			assert_eq!(campaign::try_finish(tx, campaign, 1)?, None);
			assert_eq!(loupe_storage::admission::get_spending(tx, campaign)?.unwrap().total()?, 1);
			assert_eq!(tx.query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get::<_, i64>(0))?, 1);
			Ok(())
		})
	})
	.unwrap();
}
