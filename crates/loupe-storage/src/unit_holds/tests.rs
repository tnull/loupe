use super::*;
use crate::review_intents::tests::{child, fixture, SHA};
use crate::{generations, review_tests, review_units, transaction, Db};

fn units(tx: &Transaction<'_>, count: i64) -> Result<()> {
	for id in 1..=count {
		tx.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_by_job_id,created_at) VALUES(?1,11,?2,'Unit','Review source','[]',101,0)",params![id,format!("unit-{id}")])?;
	}
	Ok(())
}
fn result(tx: &Transaction<'_>, unit: i64, job: i64, follow_up: bool) -> Result<i64> {
	result_with_class(
		tx,
		unit,
		job,
		follow_up.then_some(ContinuationClass::SourceAnalysisRemaining),
	)
}
fn result_with_class(
	tx: &Transaction<'_>, unit: i64, job: i64, class: Option<ContinuationClass>,
) -> Result<i64> {
	let epoch: i64 = tx.query_row(
		"SELECT assignment_epoch FROM review_units WHERE review_unit_id=?1",
		[unit],
		|r| r.get(0),
	)?;
	let payload = loupe_core::review_payload::UnitResultPayloadV1::from_json(
		&serde_json::json!({
			"format":"loupe.unit_result","version":1,"review_unit_id":unit,"assignment_epoch":epoch,
			"disposition":if class.is_some(){"needs_follow_up"}else{"no_lead_found"},
			"inspected_refs":[{"path":"src.rs"}],"created_lead_ids":[],
			"counterevidence":"Existing guard","proof_gaps":"Caller analysis incomplete",
			"follow_up":class.map(|_|"Inspect callers"),"continuation":class
		})
		.to_string(),
	)?;
	crate::review_unit_results::insert_evidence(
		tx,
		&crate::review_unit_results::NewResultEvidence {
			generation_id: 11,
			produced_by_job: job,
			commit_sha: SHA,
			profile_version: 1,
			payload: &payload,
		},
		0,
	)
}
fn hold_units(tx: &Transaction<'_>, count: i64) -> Result<()> {
	units(tx, count)?;
	for unit in 1..=count {
		let r = result(tx, unit, 101, true)?;
		record_follow_up(tx, unit, r, 101, 0, ContinuationClass::SourceAnalysisRemaining, 1)?;
	}
	Ok(())
}

#[test]
fn partial_continuation_carries_untouched_members_across_two_handoffs() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				hold_units(tx, 3)?;
				tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
				let first = freeze_survey_batches(tx, 101, 0)?.remove(0);
				child(tx, 110, None, 101, true)?;
				let original_assignment = admit_exact_batch(tx, first.batch_id, 110, 60)?;
				let original_hold = get_hold(tx, 3)?.unwrap();
				let closed = result(tx, 1, 110, false)?;
				release_conclusive(tx, 1, closed, 110, 1, 61)?;
				let renewed = result(tx, 2, 110, true)?;
				record_follow_up(
					tx,
					2,
					renewed,
					110,
					1,
					ContinuationClass::SourceAnalysisRemaining,
					61,
				)?;
				tx.execute("UPDATE jobs SET state='succeeded' WHERE id=110", [])?;
				let second = freeze_survey_batches(tx, 110, 62)?;
				assert_eq!(second.len(), 1);
				let members = batch_holds(tx, second[0].batch_id)?;
				assert_eq!(
					members.iter().map(|h| h.unit_id).collect::<Vec<_>>(),
					vec![2, 3],
					"partial finalization must retain the untouched held member"
				);
				assert_eq!(members[1].producing_job_id, original_hold.producing_job_id);
				assert_eq!(members[1].producing_result_id, original_hold.producing_result_id);
				assert_eq!(members[1].source_assignment_epoch, 0);
				assert_eq!(get_batch(tx, first.batch_id)?.unwrap().state, State::Complete);
				assert_eq!(
					assigned_units(tx, 110)?[2],
					original_assignment[2],
					"carrying must not invent completion or change the original assignment"
				);
				assert_eq!(
					freeze_survey_batches(tx, 110, 1000)?,
					second,
					"replay freezes the original handoff"
				);
				child(tx, 111, None, 110, true)?;
				let assigned =
					admit_exact_batch(tx, second[0].batch_id, 111, second[0].not_before.unwrap())?;
				assert_eq!(
					assigned.iter().map(|a| (a.unit_id, a.assignment_epoch)).collect::<Vec<_>>(),
					vec![(2, 2), (3, 2)]
				);
				assert_eq!(
					admit_exact_batch(tx, second[0].batch_id, 111, 999)?,
					assigned,
					"execution retry must not increment epochs"
				);
				tx.execute("UPDATE jobs SET state='succeeded' WHERE id=111", [])?;
				let third = freeze_survey_batches(tx, 111, 200)?;
				assert_eq!(third.len(), 1, "zero-progress terminalization still needs a handoff");
				assert_eq!(third[0].logical_sequence, 3);
				child(tx, 112, None, 111, true)?;
				let assigned =
					admit_exact_batch(tx, third[0].batch_id, 112, third[0].not_before.unwrap())?;
				assert_eq!(
					assigned.iter().map(|a| (a.unit_id, a.assignment_epoch)).collect::<Vec<_>>(),
					vec![(2, 3), (3, 3)]
				);
				assert_eq!(
					get_hold(tx, 3)?.unwrap().producing_result_id,
					original_hold.producing_result_id
				);
				Ok(())
			})
		})
		.unwrap();
}

#[test]
fn carry_handoff_rejects_broken_original_evidence_or_reservation_and_rolls_back() {
	for damage in [
		"epoch",
		"missing_assignment",
		"missing_hold",
		"position",
		"completed",
		"digest",
		"historical",
		"conflicting_owner",
	] {
		let db = fixture();
		db.with_conn(|conn| {
			let first=transaction::immediate(conn,|tx| {
				hold_units(tx,2)?;
				tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101",[])?;
				let first=freeze_survey_batches(tx,101,0)?.remove(0);
				child(tx,110,None,101,true)?;
				admit_exact_batch(tx,first.batch_id,110,60)?;
				match damage {
					"epoch"=>{tx.execute("UPDATE review_units SET assignment_epoch=99 WHERE review_unit_id=2",[])?;},
					"missing_assignment"=>{tx.execute("DELETE FROM job_assigned_review_units WHERE job_id=110 AND review_unit_id=2",[])?;},
					"missing_hold"=>{tx.execute("DELETE FROM review_unit_holds WHERE review_unit_id=2",[])?;},
					"position"=>{tx.execute("UPDATE review_unit_holds SET batch_position=9 WHERE review_unit_id=2",[])?;},
					"completed"=>{tx.execute("UPDATE job_assigned_review_units SET completed=1 WHERE job_id=110 AND review_unit_id=2",[])?;},
					"digest"|"historical"=>damage_result(tx,get_hold(tx,2)?.unwrap().producing_result_id,damage)?,
					"conflicting_owner"=>{child(tx,111,None,101,true)?;tx.execute("INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(111,2,0,1)",[])?;},
					_=>unreachable!()
				}
				Ok(first)
			})?;
			let outcome=transaction::immediate(conn,|tx| {
				tx.execute("UPDATE jobs SET state='succeeded' WHERE id=110",[])?;
				freeze_survey_batches(tx,110,61)
			});
			assert!(outcome.is_err(),"carry handoff accepted damaged {damage}");
			assert_eq!(crate::jobs::get(conn,110)?.unwrap().state,JobState::Leased);
			assert_eq!(get_batch(conn,first.batch_id)?.unwrap().state,State::Admitted);
			assert_eq!(get_hold(conn,1)?.unwrap().pending_batch_id,Some(first.batch_id),"earlier movements roll back with later validation failure");
			assert_eq!(list_batches(conn,1,0,256)?.len(),1);
			Ok(())
		}).unwrap();
	}
}

#[test]
fn carried_handoff_survives_restart_and_failure_after_movement() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("carried.db");
	let key = crate::secrets::MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	review_tests::seed(&db);
	crate::review_intents::tests::ready(&db);
	let first = db
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				hold_units(tx, 1)?;
				tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
				let first = freeze_survey_batches(tx, 101, 0)?.remove(0);
				child(tx, 110, None, 101, true)?;
				admit_exact_batch(tx, first.batch_id, 110, 60)?;
				Ok(first)
			})
		})
		.unwrap();
	db.with_conn(|conn| {
		let failed: Result<()> = transaction::immediate(conn, |tx| {
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=110", [])?;
			let next = freeze_survey_batches(tx, 110, 61)?;
			assert_eq!(next.len(), 1);
			assert_eq!(get_hold(tx, 1)?.unwrap().pending_batch_id, Some(next[0].batch_id));
			Err(Error::Conflict(Conflict::TerminalReceipt))
		});
		assert!(failed.is_err());
		assert_eq!(get_hold(conn, 1)?.unwrap().pending_batch_id, Some(first.batch_id));
		assert_eq!(get_batch(conn, first.batch_id)?.unwrap().state, State::Admitted);
		assert_eq!(crate::jobs::get(conn, 110)?.unwrap().state, JobState::Leased);
		Ok(())
	})
	.unwrap();
	let second = db
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				tx.execute("UPDATE jobs SET state='succeeded' WHERE id=110", [])?;
				Ok(freeze_survey_batches(tx, 110, 61)?.remove(0))
			})
		})
		.unwrap();
	drop(db);
	let db = Db::open(&path, &key).unwrap();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			assert_eq!(freeze_survey_batches(tx, 110, 1000)?, vec![second.clone()]);
			assert_eq!(get_hold(tx, 1)?.unwrap().producing_job_id, 101);
			assert_eq!(get_hold(tx, 1)?.unwrap().source_assignment_epoch, 0);
			child(tx, 111, None, 110, true)?;
			let assignment =
				admit_exact_batch(tx, second.batch_id, 111, second.not_before.unwrap())?;
			assert_eq!(assignment[0].assignment_epoch, 2);
			assert_eq!(assignment[0].unit_id, 1);
			assert_eq!(admit_exact_batch(tx, second.batch_id, 111, 1000)?, assignment);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn carried_batch_admission_rechecks_original_evidence_and_exact_handoff_epoch() {
	for damage in [
		"historical",
		"digest",
		"epoch",
		"missing_assignment",
		"completed_assignment",
		"unit_epoch",
	] {
		fixture()
			.with_conn(|conn| {
				let batch =
					transaction::immediate(conn, |tx| {
						hold_units(tx, 1)?;
						tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
						let first = freeze_survey_batches(tx, 101, 0)?.remove(0);
						child(tx, 110, None, 101, true)?;
						admit_exact_batch(tx, first.batch_id, 110, 60)?;
						tx.execute("UPDATE jobs SET state='succeeded' WHERE id=110", [])?;
						let second = freeze_survey_batches(tx, 110, 61)?.remove(0);
						child(tx, 111, None, 110, true)?;
						match damage {
							"missing_assignment" => {
								tx.execute(
									"DELETE FROM job_assigned_review_units WHERE job_id=110",
									[],
								)?;
							},
							"completed_assignment" => {
								tx.execute("UPDATE job_assigned_review_units SET completed=1 WHERE job_id=110",[])?;
							},
							"unit_epoch" => {
								tx.execute("UPDATE review_units SET assignment_epoch=9 WHERE review_unit_id=1",[])?;
							},
							_ => damage_result(
								tx,
								get_hold(tx, 1)?.unwrap().producing_result_id,
								damage,
							)?,
						}
						Ok(second)
					})?;
				assert!(
					transaction::immediate(conn, |tx| admit_exact_batch(
						tx,
						batch.batch_id,
						111,
						batch.not_before.unwrap()
					))
					.is_err(),
					"admission accepted {damage}"
				);
				assert_eq!(get_batch(conn, batch.batch_id)?.unwrap().state, State::Pending);
				assert_eq!(get_hold(conn, 1)?.unwrap().pending_batch_id, Some(batch.batch_id));
				assert!(assigned_units(&conn.transaction()?, 111)?.is_empty());
				Ok(())
			})
			.unwrap();
	}
}

fn damage_result(tx: &Transaction<'_>, id: i64, kind: &str) -> Result<()> {
	use crate::StoredEvidence;
	let StoredEvidence::Recorded(mut evidence) = crate::review_unit_results::get_evidence(tx, id)?
	else {
		panic!("typed fixture")
	};
	if kind == "digest" {
		tx.execute("UPDATE review_unit_results SET result_digest=zeroblob(32) WHERE review_unit_result_id=?1",[id])?;
		return Ok(());
	}
	match kind {
		"epoch" => evidence.assignment_epoch += 1,
		"class" => evidence.continuation = Some(ContinuationClass::ExternalDependency),
		"historical" => {},
		_ => panic!("unknown mutation"),
	}
	let bytes = if kind == "historical" { b"{}".to_vec() } else { evidence.canonical_bytes()? };
	tx.execute("UPDATE review_unit_results SET result_payload=?2,result_digest=?3 WHERE review_unit_result_id=?1",params![id,std::str::from_utf8(&bytes).unwrap(),crate::canonical::digest(&bytes).as_slice()])?;
	Ok(())
}

#[test]
fn hold_transitions_require_matching_recorded_evidence() {
	let mut accepted = Vec::new();
	for follow_up in [true, false] {
		for kind in ["historical", "digest", "epoch", "class"] {
			if !follow_up && kind == "class" {
				continue;
			}
			fixture()
				.with_conn(|conn| {
					transaction::immediate(conn, |tx| {
						units(tx, 1)?;
						let id = result(tx, 1, 101, follow_up)?;
						damage_result(tx, id, kind)?;
						let outcome = if follow_up {
							record_follow_up(
								tx,
								1,
								id,
								101,
								0,
								ContinuationClass::SourceAnalysisRemaining,
								1,
							)
						} else {
							release_conclusive(tx, 1, id, 101, 0, 1)
						};
						if outcome.is_ok() {
							accepted.push((follow_up, kind));
						}
						Ok(())
					})
				})
				.unwrap();
		}
	}
	assert!(
		accepted.is_empty(),
		"hold transitions accepted mismatched or historical evidence: {accepted:?}"
	);
}

#[test]
fn fresh_batch_admission_rechecks_canonical_producing_evidence() {
	let mut accepted = Vec::new();
	for kind in ["historical", "digest", "epoch", "class"] {
		fixture()
			.with_conn(|conn| {
				let batch = transaction::immediate(conn, |tx| {
					hold_units(tx, 1)?;
					tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
					let batch = freeze_survey_batches(tx, 101, 0)?.remove(0);
					child(tx, 110, None, 101, true)?;
					damage_result(tx, get_hold(tx, 1)?.unwrap().producing_result_id, kind)?;
					Ok(batch)
				})?;
				if transaction::immediate(conn, |tx| admit_exact_batch(tx, batch.batch_id, 110, 60))
					.is_ok()
				{
					accepted.push(kind);
				} else {
					assert_eq!(get_batch(conn, batch.batch_id)?.unwrap().state, State::Pending);
					assert_eq!(review_units::get(conn, 1)?.unwrap().assignment_epoch, 0);
				}
				Ok(())
			})
			.unwrap();
	}
	assert!(
		accepted.is_empty(),
		"fresh admission accepted mismatched or historical evidence: {accepted:?}"
	);
}

#[test]
fn exact_batch_first_admission_precedes_child_checkout() {
	fixture()
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				hold_units(tx, 1)?;
				tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
				let batch = freeze_survey_batches(tx, 101, 0)?.remove(0);
				child(tx, 110, None, 101, true)?;
				tx.execute("UPDATE jobs SET head_sha=NULL WHERE id=110", [])?;
				tx.execute(
					"UPDATE review_generations SET state='building' WHERE generation_id=11",
					[],
				)?;
				assert!(
					admit_exact_batch(tx, batch.batch_id, 110, 60).is_err(),
					"exact survey continuation still requires activation"
				);
				tx.execute(
					"UPDATE review_generations SET state='active' WHERE generation_id=11",
					[],
				)?;
				let assigned = admit_exact_batch(tx, batch.batch_id, 110, 60)
					.expect("first batch admission must not require a completed child checkout");
				assert_eq!(assigned.len(), 1);
				assert!(crate::jobs::get(tx, 110)?.unwrap().head_sha.is_none());
				Ok(())
			})
		})
		.unwrap();
}

fn held_fixture() -> Db {
	let db = review_tests::fixture();
	db.with_conn(|conn| {
		conn.execute_batch("UPDATE jobs SET state='succeeded' WHERE id=101;
		INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at)
		VALUES(1,11,'held','Held','Finish source review','[]',0),(2,11,'ordinary','Ordinary','Review other source','[]',0);
		INSERT INTO review_unit_results(review_unit_result_id,review_unit_id,produced_by_job_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at)
		VALUES(1,1,101,'base',1,'needs_follow_up','[]','{}',zeroblob(32),0);
		INSERT INTO review_unit_holds(review_unit_id,generation_id,producing_job_id,producing_result_id,source_assignment_epoch,continuation_class,created_at,updated_at)
		VALUES(1,11,101,1,0,'source_analysis_remaining',0,0);")?;
		Ok(())
	}).unwrap();
	db
}

#[test]
fn ordinary_selection_excludes_every_hold_but_keeps_other_work() {
	let db = held_fixture();
	db.with_conn(|conn| {
		let eligible: Vec<i64> = conn.prepare(&format!("SELECT u.review_unit_id FROM review_units u JOIN review_generations g USING(generation_id) WHERE {} ORDER BY u.review_unit_id", *review_units::UNIT_NEEDS_WORK))?
		.query_map([], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
		assert_eq!(eligible, vec![2], "held work must not return to ordinary selection");
		Ok(())
	}).unwrap();
}

#[test]
fn deferred_and_held_work_remains_incomplete_coverage() {
	let db = held_fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			tx.execute("UPDATE review_units SET status='deferred'", [])?;
			let rollup = generations::coverage_rollup(tx, 11)?;
			assert_eq!(rollup.missing_results, 2, "deferral must not silently complete coverage");
			assert_eq!(rollup.needs_follow_up, 1);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn ordinary_assignment_cannot_steal_held_work() {
	let db = held_fixture();
	db.with_conn(|conn| {
		conn.execute("UPDATE jobs SET generation_id=11 WHERE id=102", [])?;
		assert!(
			transaction::immediate(conn, |tx| review_units::assign(
				tx,
				102,
				&[review_units::Assignment { unit_id: 1, expected_epoch: 0 }]
			))
			.is_err(),
			"ordinary assignment must reject a held unit"
		);
		transaction::immediate(conn, |tx| {
			review_units::assign(
				tx,
				102,
				&[review_units::Assignment { unit_id: 2, expected_epoch: 0 }],
			)
		})?;
		Ok(())
	})
	.unwrap();
}

#[test]
fn freeze_groups_classes_and_bounded_exact_batches_without_dropping_overflow() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			units(tx, 10)?;
			for unit in 1..=10 {
				let class = if unit == 10 {
					ContinuationClass::ExternalDependency
				} else {
					ContinuationClass::SourceAnalysisRemaining
				};
				let r = result_with_class(tx, unit, 101, Some(class))?;
				record_follow_up(tx, unit, r, 101, 0, class, 1)?;
			}
			assert!(
				freeze_survey_batches(tx, 101, 10).is_err(),
				"live producer cannot freeze mutable membership"
			);
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
			let batches = freeze_survey_batches(tx, 101, 10)?;
			assert_eq!(
				batches.iter().map(|b| b.expected_unit_count).collect::<Vec<_>>(),
				vec![4, 4, 1, 1]
			);
			for batch in &batches[..3] {
				assert_eq!(batch.state, State::Pending);
				assert_eq!(batch.not_before, Some(70));
				assert_eq!(batch.logical_sequence, 1);
			}
			assert_eq!(batches[3].state, State::Blocked);
			assert_eq!(batches[3].not_before, None);
			assert_eq!(batches[3].block_reason, Some(BlockReason::ExternalDependency));
			assert_eq!(
				freeze_survey_batches(tx, 101, 500)?,
				batches,
				"replay never changes due time/membership"
			);
			let held: Vec<i64> = batches
				.iter()
				.map(|b| batch_holds(tx, b.batch_id))
				.collect::<Result<Vec<_>>>()?
				.into_iter()
				.flatten()
				.map(|h| h.unit_id)
				.collect();
			assert_eq!(held, (1..=10).collect::<Vec<_>>());
			assert_eq!(list_batches(tx, 1, 0, 2)?.len(), 2);
			assert!(list_batches(tx, 1, 0, 257).is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn exact_admission_retains_holds_and_retry_reuses_completed_original_members() {
	let db = fixture();
	db.with_conn(|conn| {
		let batch = transaction::immediate(conn, |tx| {
			hold_units(tx, 2)?;
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
			let batch = freeze_survey_batches(tx, 101, 10)?.remove(0);
			child(tx, 110, None, 101, true)?;
			assert!(admit_exact_batch(tx, batch.batch_id, 110, 69).is_err());
			let assigned = admit_exact_batch(tx, batch.batch_id, 110, 70)?;
			assert_eq!(
				assigned
					.iter()
					.map(|a| (a.unit_id, a.position, a.assignment_epoch))
					.collect::<Vec<_>>(),
				vec![(1, 0, 1), (2, 1, 1)]
			);
			assert_eq!(batch_holds(tx, batch.batch_id)?.len(), 2);
			assert_eq!(get_hold(tx, 1)?.unwrap().source_assignment_epoch, 0);
			let r = result(tx, 1, 110, false)?;
			release_conclusive(tx, 1, r, 110, 1, 71)?;
			assert!(get_hold(tx, 1)?.is_none());
			assert_eq!(get_batch(tx, batch.batch_id)?.unwrap().state, State::Admitted);
			Ok(batch)
		})?;
		transaction::immediate(conn, |tx| {
			tx.execute("UPDATE jobs SET attempts=2 WHERE id=110", [])?;
			let replay = admit_exact_batch(tx, batch.batch_id, 110, 80)?;
			assert_eq!(replay.len(), 2, "completed units stay in the original batch");
			assert!(replay[0].completed);
			assert_eq!(replay[0].assignment_epoch, 1, "execution retry never changes epoch");
			let r = result(tx, 2, 110, false)?;
			release_conclusive(tx, 2, r, 110, 1, 81)?;
			assert_eq!(get_batch(tx, batch.batch_id)?.unwrap().state, State::Complete);
			assert!(generations::coverage_rollup(tx, 11)?.complete());
			Ok(())
		})?;
		Ok(())
	})
	.unwrap();
}

#[test]
fn held_authority_binds_exact_admitted_job_and_persisted_epoch() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			hold_units(tx, 1)?;
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
			let batch = freeze_survey_batches(tx, 101, 0)?.remove(0);
			child(tx, 110, None, 101, true)?;
			child(tx, 111, None, 101, true)?;
			admit_exact_batch(tx, batch.batch_id, 110, 60)?;
			let hash = 110_i64.to_be_bytes().repeat(4);
			let owner = crate::review_authority::authorize(
				tx,
				crate::jobs::ActiveLease {
					identity: crate::jobs::LeaseIdentity {
						job_id: 110,
						worker_id: 1,
						capability_hash: &hash,
					},
					now: 61,
				},
				JobKind::Survey,
			)?
			.unwrap();
			assert!(
				owner.survey_unit(1, 1, false)?,
				"admitted exact owner can act while hold persists"
			);
			assert!(!owner.survey_unit(1, 0, false)?);
			let other_hash = 111_i64.to_be_bytes().repeat(4);
			let other = crate::review_authority::authorize(
				tx,
				crate::jobs::ActiveLease {
					identity: crate::jobs::LeaseIdentity {
						job_id: 111,
						worker_id: 1,
						capability_hash: &other_hash,
					},
					now: 61,
				},
				JobKind::Survey,
			)?
			.unwrap();
			assert!(!other.survey_unit(1, 1, false)?);
			let r = result(tx, 1, 111, false)?;
			assert!(release_conclusive(tx, 1, r, 111, 1, 61).is_err());
			let own = result(tx, 1, 110, false)?;
			assert!(release_conclusive(tx, 1, own, 110, 0, 61).is_err());
			tx.execute(
				"UPDATE job_assigned_review_units SET assignment_epoch=NULL WHERE job_id=110",
				[],
			)?;
			assert!(
				!owner.survey_unit(1, 1, false)?,
				"historical missing epochs grant no authority"
			);
			assert!(release_conclusive(tx, 1, own, 110, 1, 61).is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn stale_missing_or_foreign_batch_members_fail_without_filtering_or_refill() {
	for mutation in [
		"UPDATE review_units SET stale=1 WHERE review_unit_id=2",
		"UPDATE review_units SET assignment_epoch=9 WHERE review_unit_id=2",
		"UPDATE review_unit_results SET invalidated=1 WHERE review_unit_id=2",
		"DELETE FROM review_unit_holds WHERE review_unit_id=2",
		"UPDATE review_unit_holds SET batch_position=9 WHERE review_unit_id=2",
	] {
		let db = fixture();
		db.with_conn(|conn| {
			let batch = transaction::immediate(conn, |tx| {
				hold_units(tx, 2)?;
				tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
				let b = freeze_survey_batches(tx, 101, 0)?.remove(0);
				child(tx, 110, None, 101, true)?;
				Ok(b.batch_id)
			})?;
			conn.execute(mutation, [])?;
			assert!(
				transaction::immediate(conn, |tx| admit_exact_batch(tx, batch, 110, 60)).is_err(),
				"{mutation}"
			);
			assert_eq!(get_batch(conn, batch)?.unwrap().state, State::Pending);
			assert_eq!(review_units::get(conn, 1)?.unwrap().assignment_epoch, 0);
			assert_eq!(
				conn.query_row(
					"SELECT COUNT(*) FROM job_assigned_review_units WHERE job_id=110",
					[],
					|r| r.get::<_, i64>(0)
				)?,
				0
			);
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn further_follow_up_replaces_hold_and_advances_logical_parent_without_polling_dependencies() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			hold_units(tx, 2)?;
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
			let original = freeze_survey_batches(tx, 101, 0)?.remove(0);
			child(tx, 110, None, 101, true)?;
			admit_exact_batch(tx, original.batch_id, 110, 60)?;
			for (unit, class) in [
				(1, ContinuationClass::SourceAnalysisRemaining),
				(2, ContinuationClass::AwaitingProofInfrastructure),
			] {
				let r = result_with_class(tx, unit, 110, Some(class))?;
				record_follow_up(tx, unit, r, 110, 1, class, 70)?;
				let held = get_hold(tx, unit)?.unwrap();
				assert_eq!(
					(
						held.producing_job_id,
						held.producing_result_id,
						held.source_assignment_epoch,
						held.pending_batch_id
					),
					(110, r, 1, None)
				);
			}
			assert_eq!(get_batch(tx, original.batch_id)?.unwrap().state, State::Complete);
			tx.execute("UPDATE jobs SET state='succeeded',attempts=3 WHERE id=110", [])?;
			let next = freeze_survey_batches(tx, 110, 80)?;
			assert_eq!(next.len(), 2);
			assert_eq!(next[0].logical_sequence, 2);
			assert_eq!(next[0].producer_job_id, 110);
			assert_eq!(next[0].not_before, Some(200));
			assert_eq!(next[1].state, State::Blocked);
			assert_eq!(next[1].not_before, None);
			child(tx, 111, None, 110, true)?;
			assert!(admit_exact_batch(tx, next[1].batch_id, 111, 500).is_err());
			assert_eq!(admit_exact_batch(tx, next[0].batch_id, 111, 200)?[0].assignment_epoch, 2);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn lifecycle_block_preserves_holds_and_defers_unassessed_assignments_without_fake_results() {
	let db = fixture();
	db.with_conn(|conn| transaction::immediate(conn,|tx| {
		hold_units(tx,1)?;
		tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101",[])?;
		let batch=freeze_survey_batches(tx,101,0)?.remove(0);
		child(tx,110,None,101,true)?;
		admit_exact_batch(tx,batch.batch_id,110,60)?;
		tx.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES(2,11,'untouched','Untouched','Review source','[]',0)",[])?;
		child(tx,111,None,101,false)?;
		review_units::assign(tx,111,&[review_units::Assignment{unit_id:2,expected_epoch:0}])?;
		for job in [110,111] {
			tx.execute("UPDATE jobs SET state='failed',job_capability_hash=NULL WHERE id=?1",[job])?;
			review_intents::block_job_work(tx,job,BlockReason::ExecutionExhausted,70)?;
		}
		assert_eq!(get_hold(tx,1)?.unwrap().block_reason,Some(BlockReason::ExecutionExhausted));
		assert_eq!(get_batch(tx,batch.batch_id)?.unwrap().state,State::Blocked);
		let untouched=review_units::get(tx,2)?.unwrap();
		assert_eq!(untouched.status,review_units::Status::Deferred);
		assert_eq!(untouched.defer_reason.unwrap().expose(),"execution_exhausted");
		assert!(get_hold(tx,2)?.is_none(),"no evidence is invented to fill the hold FK");
		assert_eq!(tx.query_row("SELECT COUNT(*) FROM review_unit_results WHERE review_unit_id=2",[],|r|r.get::<_,i64>(0))?,0);
		assert_eq!(generations::coverage_rollup(tx,11)?.missing_results,2);
		let eligible:i64=tx.query_row(&format!("SELECT COUNT(*) FROM review_units u JOIN review_generations g USING(generation_id) WHERE {}",*review_units::UNIT_NEEDS_WORK),[],|r|r.get(0))?;
		assert_eq!(eligible,0);
		Ok(())
	})).unwrap();
}

#[test]
fn admitted_exact_batch_cannot_be_extended_by_ordinary_assignment() {
	let db = fixture();
	db.with_conn(|conn| transaction::immediate(conn,|tx| {
		hold_units(tx,1)?;
		tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101",[])?;
		let batch=freeze_survey_batches(tx,101,0)?.remove(0);
		child(tx,110,None,101,true)?;
		admit_exact_batch(tx,batch.batch_id,110,60)?;
		tx.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES(2,11,'unrelated','Unrelated','Review source','[]',0)",[])?;
		assert!(review_units::assign(tx,110,&[review_units::Assignment{unit_id:2,expected_epoch:0}]).is_err(),"an exact continuation batch must never append or refill");
		Ok(())
	})).unwrap();
}

#[test]
fn completed_exact_batch_retries_without_refilling() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			hold_units(tx, 1)?;
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
			let batch = freeze_survey_batches(tx, 101, 0)?.remove(0);
			child(tx, 110, None, 101, true)?;
			admit_exact_batch(tx, batch.batch_id, 110, 60)?;
			let r = result(tx, 1, 110, false)?;
			release_conclusive(tx, 1, r, 110, 1, 61)?;
			tx.execute("UPDATE jobs SET attempts=2 WHERE id=110", [])?;
			let original = admit_exact_batch(tx, batch.batch_id, 110, 70)
				.expect("completed exact batch remains replayable on an execution retry");
			assert_eq!(original.len(), 1);
			assert!(original[0].completed);
			assert_eq!(original[0].assignment_epoch, 1);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn reopened_database_retains_intent_and_exact_membership_and_serializes_admission() {
	use std::sync::{Arc, Barrier};

	use crate::review_intents::tests::{lead, ready, NORMAL};
	use crate::review_intents::{self, Subject};
	use crate::secrets::MasterKey;
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("pending.db");
	let key = MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	review_tests::seed(&db);
	ready(&db);
	let batch = db
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				lead(tx, 1)?;
				review_intents::ensure_drilldown_intent(tx, 1, 101, NORMAL, 0)?;
				hold_units(tx, 2)?;
				tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
				let batch = freeze_survey_batches(tx, 101, 0)?.remove(0);
				child(tx, 110, None, 101, true)?;
				child(tx, 111, None, 101, true)?;
				Ok(batch.batch_id)
			})
		})
		.unwrap();
	drop(db);
	let db = Db::open(&path, &key).unwrap();
	db.with_conn(|conn| {
		assert_eq!(
			review_intents::get_subject(conn, Subject::Lead(1))?.unwrap().originating_job_id,
			101
		);
		assert_eq!(
			batch_holds(conn, batch)?.iter().map(|h| h.unit_id).collect::<Vec<_>>(),
			vec![1, 2]
		);
		Ok(())
	})
	.unwrap();
	drop(db);
	let barrier = Arc::new(Barrier::new(2));
	let handles: Vec<_> = [110, 111]
		.into_iter()
		.map(|job| {
			let db = Db::open(&path, &key).unwrap();
			let barrier = Arc::clone(&barrier);
			std::thread::spawn(move || {
				barrier.wait();
				db.with_conn(|conn| {
					transaction::immediate(conn, |tx| admit_exact_batch(tx, batch, job, 60))
				})
				.is_ok()
			})
		})
		.collect();
	assert_eq!(handles.into_iter().map(|h| h.join().unwrap() as usize).sum::<usize>(), 1);
	let db = Db::open(&path, &key).unwrap();
	db.with_conn(|conn| {
		assert_eq!(get_batch(conn, batch)?.unwrap().state, State::Admitted);
		assert_eq!(review_units::get(conn, 1)?.unwrap().assignment_epoch, 1);
		assert_eq!(review_units::get(conn, 2)?.unwrap().assignment_epoch, 1);
		assert_eq!(
			conn.query_row("SELECT COUNT(*) FROM job_assigned_review_units", [], |r| r
				.get::<_, i64>(0))?,
			2
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn holds_reject_wrong_result_job_epoch_profile_and_generation() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			units(tx, 2)?;
			let r = result(tx, 1, 101, true)?;
			assert!(record_follow_up(
				tx,
				2,
				r,
				101,
				0,
				ContinuationClass::SourceAnalysisRemaining,
				1
			)
			.is_err());
			assert!(record_follow_up(
				tx,
				1,
				r,
				101,
				1,
				ContinuationClass::SourceAnalysisRemaining,
				1
			)
			.is_err());
			tx.execute(
				"UPDATE review_unit_results SET profile_version=2 WHERE review_unit_result_id=?1",
				[r],
			)?;
			assert!(record_follow_up(
				tx,
				1,
				r,
				101,
				0,
				ContinuationClass::SourceAnalysisRemaining,
				1
			)
			.is_err());
			tx.execute(
				"UPDATE review_unit_results SET profile_version=1 WHERE review_unit_result_id=?1",
				[r],
			)?;
			child(tx, 110, None, 101, false)?;
			assert!(record_follow_up(
				tx,
				1,
				r,
				110,
				0,
				ContinuationClass::SourceAnalysisRemaining,
				1
			)
			.is_err());
			tx.execute("UPDATE jobs SET head_sha='wrong' WHERE id=101", [])?;
			assert!(record_follow_up(
				tx,
				1,
				r,
				101,
				0,
				ContinuationClass::SourceAnalysisRemaining,
				1
			)
			.is_err());
			tx.execute("UPDATE jobs SET head_sha=?1 WHERE id=101", [SHA])?;
			record_follow_up(tx, 1, r, 101, 0, ContinuationClass::SourceAnalysisRemaining, 1)?;
			let before = get_hold(tx, 1)?;
			record_follow_up(tx, 1, r, 101, 0, ContinuationClass::SourceAnalysisRemaining, 2)?;
			assert_eq!(get_hold(tx, 1)?, before);
			assert!(
				record_follow_up(tx, 1, r, 101, 0, ContinuationClass::ExternalDependency, 2)
					.is_err(),
				"an old producer cannot rewrite its accepted typed hold"
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn obsolete_successful_producer_cannot_block_a_later_admitted_owner() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			hold_units(tx, 1)?;
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
			let batch = freeze_survey_batches(tx, 101, 0)?.remove(0);
			child(tx, 110, None, 101, true)?;
			admit_exact_batch(tx, batch.batch_id, 110, 60)?;
			assert!(
				review_intents::block_job_work(tx, 101, BlockReason::ExecutionExhausted, 61)
					.is_err(),
				"an obsolete successful producer no longer owns the admitted hold"
			);
			assert_eq!(get_hold(tx, 1)?.unwrap().block_reason, None);
			assert_eq!(get_batch(tx, batch.batch_id)?.unwrap().state, State::Admitted);
			Ok(())
		})
	})
	.unwrap();
}
