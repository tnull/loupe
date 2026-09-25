//! Typed evidence has canonical owners independent of rebuildable generations.
use loupe_core::review_payload::{FindingEvidenceV1, VerificationTerminalV1};
use loupe_core::text::{Anchor, BoundedJson, BoundedText, Identifier};
use loupe_core::JobKind;
use serde_json::{json, Value};

use crate::finding_details::{self, NewAttemptEvidence, NewReviewEvidence};
use crate::identity::Identity;
use crate::secrets::MasterKey;
use crate::terminal_payloads::{self, TerminalPayload};
use crate::{terminal_receipt, transaction, Db, StoredEvidence};

fn evidence() -> FindingEvidenceV1 {
	serde_json::from_value(json!({
		"version": 1,
		"l2_argument": {
			"attacker_source": "Remote request", "control": "Request length",
			"sink": "Allocation", "reachable_path": "Handler calls allocator",
			"trust_boundary": "Request to process memory"
		},
		"material_locations": [
			{"role": "sink", "file": "src/cafe\u{301}.rs", "line_start": 3, "line_end": 4},
			{"role": "wrapper", "file": "src/café.rs"}
		],
		"counterevidence": "é".repeat(4000),
		"assumptions_gaps": "é".repeat(4000), "confidence": "medium"
	}))
	.unwrap()
}

fn revalidation() -> Value {
	json!({"current_source_refs": [{"path":"src/cafe\u{301}.rs"}], "rationale": "é".repeat(2000)})
}

fn terminals() -> Vec<TerminalPayload> {
	let mut values = Vec::new();
	let mut independent = evidence();
	independent.l2_argument.attacker_source =
		BoundedText::new("Verifier independently traced remote input").unwrap();
	for reason in ["completed", "partial", "deferred"] {
		values.push(TerminalPayload::Survey(
			serde_json::from_value(json!({
				"version": 1, "terminal_reason": reason,
				"continuation": "é".repeat(4000), "security_model_notes": "é".repeat(8000)
			}))
			.unwrap(),
		));
	}
	for raw in [
		json!({"version":1,"disposition":"promote","promotion":{
			"version":1,"severity":"high","title":"Allocation control",
			"description":"é".repeat(16384),"identity_family":"allocation",
			"identity_anchor":"request allocator","evidence":evidence()}}),
		json!({"version":1,"disposition":"reject","counterargument":{
			"argument":"é".repeat(8000),"source_refs":[{"path":"src/cafe\u{301}.rs"}]}}),
		json!({"version":1,"disposition":"duplicate","target":{"kind":"lead","id":1},"rationale":"Same identity"}),
		json!({"version":1,"disposition":"duplicate","target":{"kind":"finding","id":1},"rationale":"Same identity"}),
		json!({"version":1,"disposition":"hardening","explanation":{
			"argument":"é".repeat(8000),"source_refs":[{"path":"src/café.rs"}]}}),
		json!({"version":1,"disposition":"defer","reason":"More source work",
			"continuation":"source_analysis_remaining","retry_explanation":"Inspect caller"}),
	] {
		let mut raw = raw;
		raw["revalidation"] = revalidation();
		values.push(TerminalPayload::Drilldown(serde_json::from_value(raw).unwrap()));
	}
	for raw in [
		json!({"version":1,"verdict":"verified","established_rung":"L2",
			"e2e_applicability":"not_applicable","e2e_rationale":"é".repeat(2000),"evidence":independent}),
		json!({"version":1,"verdict":"rejected","counterargument":{
			"argument":"é".repeat(8000),"source_refs":[{"path":"src/cafe\u{301}.rs"}]}}),
		json!({"version":1,"verdict":"inconclusive","blocker":"é".repeat(2000),
			"continuation":"source_analysis_remaining","retry_explanation":"Inspect another caller",
			"partial_evidence":{"argument":"Partial argument","source_refs":[{"path":"src/cafe\u{301}.rs"}]}}),
		json!({"version":1,"verdict":"inconclusive","blocker":"awaiting proof infrastructure",
			"continuation":"awaiting_proof_infrastructure"}),
		json!({"version":1,"verdict":"inconclusive","blocker":"Dependency unavailable","continuation":"external_dependency"}),
		json!({"version":1,"verdict":"inconclusive","blocker":"Target changed","continuation":"requires_successor"}),
	] {
		let mut raw = raw;
		raw["revalidation"] = revalidation();
		raw["notes"] = json!("é".repeat(4000));
		values.push(TerminalPayload::Verification(serde_json::from_value(raw).unwrap()));
	}
	values
}

fn seed(db: &Db) {
	crate::review_tests::seed(db);
	db.with_conn(|c| {
		c.execute_batch("INSERT INTO jobs (id,repo_id,kind,state,campaign_id,generation_id,head_sha,workflow_contract_version,enqueued_at)
		VALUES (301,1,'drilldown','succeeded',1,11,'base',1,0);
		INSERT INTO findings (id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,created_at)
		VALUES (401,1,301,'review','high','title','description','review-test','validating',0);")?;
		c.execute("INSERT INTO leads (lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at)
		VALUES (501,11,'allocation','request allocator',?1,'{}',zeroblob(32),'base',0),(521,21,'allocation','request allocator',?1,'{}',zeroblob(32),'foreign',0)",[identity().fingerprint().as_slice()])?;
		c.execute("UPDATE jobs SET assigned_lead_id=501 WHERE id=301",[])?;
		Ok(())
	}).unwrap();
}

fn fixture() -> Db {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	seed(&db);
	db
}

fn insert_verification(
	conn: &rusqlite::Connection, evidence: &VerificationTerminalV1,
) -> crate::Result<()> {
	conn.execute_batch("INSERT INTO jobs (id,repo_id,kind,state,campaign_id,generation_id,head_sha,target_finding_id,workflow_contract_version,enqueued_at)
		VALUES (601,1,'verify','succeeded',1,11,'base',401,1,0);")?;
	conn.execute("INSERT INTO finding_verifications(id,finding_id,job_id,verdict,created_at) VALUES (601,401,601,?1,0)",[verdict(evidence)])?;
	Ok(())
}

fn inconclusive() -> VerificationTerminalV1 {
	VerificationTerminalV1::from_json(r#"{"version":1,"verdict":"inconclusive","blocker":"awaiting proof infrastructure","continuation":"awaiting_proof_infrastructure"}"#).unwrap()
}

fn attempt(evidence: &VerificationTerminalV1) -> NewAttemptEvidence<'_> {
	NewAttemptEvidence {
		verification_id: 601,
		repo_id: 1,
		workflow_contract_version: 1,
		checkout_commit_sha: "base",
		evidence,
	}
}

fn identity() -> Identity {
	Identity {
		family: Identifier::new("allocation").unwrap(),
		anchor: Anchor::new("request allocator").unwrap(),
		instance: None,
	}
}

fn review<'a>(evidence: &'a FindingEvidenceV1, identity: &'a Identity) -> NewReviewEvidence<'a> {
	NewReviewEvidence {
		finding_id: 401,
		repo_id: 1,
		workflow_contract_version: 1,
		profile_version: 1,
		profile_digest: Some(&[3; 32]),
		reviewed_commit_sha: "base",
		identity,
		evidence,
		origin_lead: Some(501),
	}
}

fn verdict(evidence: &VerificationTerminalV1) -> &'static str {
	match evidence {
		VerificationTerminalV1::Verified { .. } => "confirmed",
		VerificationTerminalV1::Rejected { .. } => "dismissed",
		VerificationTerminalV1::Inconclusive { .. } => "inconclusive",
	}
}

fn insert_receipt(
	tx: &rusqlite::Transaction<'_>, job: i64, value: &TerminalPayload,
) -> crate::Result<()> {
	terminal_receipt::insert(
		tx,
		&terminal_receipt::NewReceipt {
			job_id: job,
			phase: value.phase(),
			terminal_reason: &BoundedText::new("completed")?,
			subject_title: None,
			subject_digest: None,
			pinned_commit_sha: "base",
			effective_recipe: &BoundedJson::new("{}")?,
			result_digest: &value.digest()?,
			evidence_rung: None,
			result_counts: None,
			finishing_capability_hash: None,
		},
		1,
	)?;
	Ok(())
}

#[test]
fn every_terminal_and_independent_attempt_survives_reopen_and_generation_purge() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("evidence.db");
	let key = MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	seed(&db);
	let values = terminals();
	db.with_conn(|c| transaction::immediate(c, |tx| {
		finding_details::insert_review_evidence(tx, &review(&evidence(), &identity()), 1)?;
		for (index, value) in values.iter().enumerate() {
			let job = 1000 + index as i64;
			tx.execute("INSERT INTO jobs (id,repo_id,kind,state,campaign_id,generation_id,head_sha,target_finding_id,workflow_contract_version,enqueued_at)
			VALUES (?1,1,?2,'succeeded',1,11,'base',?3,1,0)", rusqlite::params![job,value.phase().as_str(),(value.phase()==JobKind::Verify).then_some(401)])?;
			insert_receipt(tx, job, value)?;
			terminal_payloads::insert(tx, job, value)?;
			if let TerminalPayload::Verification(evidence) = value {
				tx.execute("INSERT INTO finding_verifications (id,finding_id,job_id,verdict,created_at) VALUES (?1,401,?1,?2,0)",rusqlite::params![job,verdict(evidence)])?;
				finding_details::insert_attempt_evidence(tx, &NewAttemptEvidence {
					verification_id: job, repo_id: 1, workflow_contract_version: 1,
					checkout_commit_sha: "base", evidence,
				},1)?;
			}
		}
		Ok(())
	})).unwrap();
	drop(db);
	let db = Db::open(&path, &key).unwrap();
	db.with_conn(|c| {
		c.execute("DELETE FROM review_generations WHERE generation_id=11",[])?;
		let StoredEvidence::Recorded(review) = finding_details::get_review_evidence(c, 401)? else { panic!("typed finding evidence must survive") };
		assert_eq!(review.evidence, evidence());
		assert_eq!(review.identity, identity());
		assert_eq!(review.reviewed_commit_sha, "base");
		assert_eq!(review.profile_digest, Some([3;32]));
		assert_eq!(review.origin_lead,None,"only rebuildable provenance is cleared by generation purge");
		for (index, value) in values.iter().enumerate() {
			let job = 1000 + index as i64;
			assert_eq!(terminal_payloads::get(c, job)?, StoredEvidence::Recorded(value.clone()));
			if let TerminalPayload::Verification(evidence) = value {
				let StoredEvidence::Recorded(attempt) = finding_details::get_attempt_evidence(c, job)? else { panic!("independent attempt evidence must survive") };
				assert_eq!(&attempt.evidence,evidence);
				assert_eq!(attempt.checkout_commit_sha,"base");
				let projections:bool=c.query_row("SELECT established_rung IS NULL AND e2e_applicability IS NULL AND e2e_rationale IS NULL AND blocker IS NULL AND retry_condition IS NULL AND verification_proof_id IS NULL FROM verification_attempt_details WHERE verification_id=?1",[job],|r|r.get(0))?;
				assert!(projections,"typed attempts must not invent applicability or duplicate evidence");
			}
		}
		c.execute("DELETE FROM job_terminal_payloads",[])?;
		c.execute("DELETE FROM job_terminal_receipts",[])?;
		assert!(matches!(finding_details::get_review_evidence(c,401)?,StoredEvidence::Recorded(_)));
		for (index,value) in values.iter().enumerate() {
			if matches!(value,TerminalPayload::Verification(_)) {
				assert!(matches!(finding_details::get_attempt_evidence(c,1000+index as i64)?,StoredEvidence::Recorded(_)),"canonical attempt does not depend on terminal audit storage");
			}
		}
		Ok(())
	}).unwrap();
}

#[test]
fn historical_rows_stay_distinct_from_missing_and_typed_evidence() {
	let db = fixture();
	db.with_conn(|c| {
		assert_eq!(finding_details::get_review_evidence(c,401)?,StoredEvidence::Missing);
		assert_eq!(finding_details::get_attempt_evidence(c,601)?,StoredEvidence::Missing);
		assert_eq!(terminal_payloads::get(c,301)?,StoredEvidence::Missing);
		insert_verification(c,&inconclusive())?;
		transaction::immediate(c,|tx| {
			finding_details::insert_review_details(tx,&finding_details::NewReview {
				finding_id:401,repo_id:1,workflow_contract_version:1,profile_version:1,
				profile_digest:None,reviewed_commit_sha:"base",identity:&identity(),
				l2_argument:&BoundedJson::new(r#"{"historical":"argument"}"#)?,
				counterevidence:&BoundedText::new("Old counterevidence")?,
				assumptions_gaps:&BoundedText::new("Old assumptions")?,
				confidence:finding_details::Confidence::Low,submitted_rung:finding_details::SubmittedRung::L3,
				origin_lead:None,
			},1)?;
			finding_details::insert_attempt_details(tx,&finding_details::NewAttempt {
				verification_id:601,repo_id:1,workflow_contract_version:1,checkout_commit_sha:"base",
				established_rung:Some(finding_details::EstablishedRung::L3),
				e2e_applicability:finding_details::Applicability::Applicable,e2e_rationale:None,
				blocker:Some(&BoundedText::new("Historical blocker")?),retry_condition:None,
				verification_proof:None,terminal_digest:&[8;32],
			},1)?;
			let payload=terminals().into_iter().find(|p|p.phase()==JobKind::Drilldown).unwrap();
			insert_receipt(tx,301,&payload)
		})?;
		assert_eq!(finding_details::get_review_evidence(c,401)?,StoredEvidence::Historical);
		assert_eq!(finding_details::get_attempt_evidence(c,601)?,StoredEvidence::Historical);
		assert_eq!(terminal_payloads::get(c,301)?,StoredEvidence::Historical);
		let historical:(String,String,String,String)=c.query_row("SELECT l2_argument,counterevidence,assumptions_gaps,confidence FROM finding_review_details WHERE finding_id=401",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
		assert_eq!(historical,(r#"{"historical":"argument"}"#.into(),"Old counterevidence".into(),"Old assumptions".into(),"low".into()));
		let applicability:String=c.query_row("SELECT e2e_applicability FROM verification_attempt_details WHERE verification_id=601",[],|r|r.get(0))?;
		assert_eq!(applicability,"applicable");
		assert!(c.execute("UPDATE finding_review_details SET evidence_payload=?1 WHERE finding_id=401",[String::from_utf8(evidence().canonical_bytes()?).unwrap()]).is_err(),"historical and modern representations cannot coexist");
		assert!(c.execute("UPDATE verification_attempt_details SET evidence_payload=?1 WHERE verification_id=601",[String::from_utf8(inconclusive().canonical_bytes()?).unwrap()]).is_err());
		Ok(())
	}).unwrap();
}

#[test]
fn rejected_typed_writes_roll_back_prior_changes_and_preserve_identity_conflicts() {
	let db = fixture();
	db.with_conn(|c| {
		let mut invalid=evidence();
		invalid.material_locations.clear();
		let error=transaction::immediate(c,|tx| {
			tx.execute("UPDATE findings SET title='tentative' WHERE id=401",[])?;
			finding_details::insert_review_evidence(tx,&review(&invalid,&identity()),1)
		}).unwrap_err();
		assert!(matches!(error,crate::Error::ReviewPayload(_)));
		assert_eq!(c.query_row("SELECT title FROM findings WHERE id=401",[],|r|r.get::<_,String>(0))?,"title");
		let value=evidence();
		let identity=identity();
		for (repo,commit,workflow) in [(2,"base",1),(1,"wrong",1),(1,"base",2)] {
			let mut request=review(&value,&identity);
			request.repo_id=repo;
			request.reviewed_commit_sha=commit;
			request.workflow_contract_version=workflow;
			assert!(matches!(transaction::immediate(c,|tx|finding_details::insert_review_evidence(tx,&request,1)),Err(crate::Error::Ownership(crate::Ownership::Finding))));
		}
		let mut foreign_origin=review(&value,&identity);
		foreign_origin.origin_lead=Some(521);
		assert!(matches!(transaction::immediate(c,|tx|finding_details::insert_review_evidence(tx,&foreign_origin,1)),Err(crate::Error::Ownership(crate::Ownership::FindingLead))));
		transaction::immediate(c,|tx|finding_details::insert_review_evidence(tx,&review(&value,&identity),1))?;
		c.execute("INSERT INTO findings (id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,created_at) VALUES (402,1,301,'review','high','second','description','second-key','validating',0)",[])?;
		let mut request=review(&value,&identity);
		request.finding_id=402;
		assert!(matches!(transaction::immediate(c,|tx|finding_details::insert_review_evidence(tx,&request,1)),Err(crate::Error::Conflict(crate::Conflict::FindingIdentity(401)))));
		assert_eq!(finding_details::get_review_evidence(c,402)?,StoredEvidence::Missing);
		Ok(())
	}).unwrap();
}

#[test]
fn terminal_payload_requires_receipt_phase_job_and_canonical_digest() {
	let db = fixture();
	let value = terminals().into_iter().find(|p| p.phase() == JobKind::Drilldown).unwrap();
	db.with_conn(|c| {
		assert!(transaction::immediate(c, |tx| terminal_payloads::insert(tx, 301, &value)).is_err());
		transaction::immediate(c, |tx| insert_receipt(tx, 301, &value))?;
		for mutation in [
			"UPDATE job_terminal_receipts SET result_digest=zeroblob(32) WHERE job_id=301",
			"UPDATE job_terminal_receipts SET phase='survey' WHERE job_id=301",
			"UPDATE jobs SET kind='survey' WHERE id=301",
		] {
			assert!(transaction::immediate(c, |tx| {
				tx.execute(mutation, [])?;
				terminal_payloads::insert(tx, 301, &value)
			})
			.is_err());
			assert_eq!(terminal_payloads::get(c, 301)?, StoredEvidence::Historical);
		}
		transaction::immediate(c, |tx| terminal_payloads::insert(tx, 301, &value))?;
		assert!(transaction::immediate(c, |tx| terminal_payloads::insert(tx, 301, &value)).is_err());
		assert!(
			c.execute("UPDATE job_terminal_payloads SET phase='survey' WHERE job_id=301", [])
				.is_err(),
			"the receipt phase foreign key rejects disagreement before a read"
		);
		for mutation in [
			"UPDATE job_terminal_payloads SET payload=' '||payload WHERE job_id=301",
			"UPDATE job_terminal_payloads SET payload='{}' WHERE job_id=301",
			"UPDATE job_terminal_receipts SET result_digest=zeroblob(32) WHERE job_id=301",
			"UPDATE jobs SET kind='survey' WHERE id=301",
		] {
			let tx = c.transaction()?;
			tx.execute(mutation, [])?;
			assert!(
				terminal_payloads::get(&tx, 301).is_err(),
				"corrupt terminal audit must not downgrade: {mutation}"
			);
			tx.rollback()?;
		}
		// Simulate corruption that bypassed SQLite's receipt FK and cascade.
		c.pragma_update(None, "foreign_keys", false)?;
		let tx = c.transaction()?;
		tx.execute("DELETE FROM job_terminal_receipts WHERE job_id=301", [])?;
		assert!(
			terminal_payloads::get(&tx, 301).is_err(),
			"a surviving payload without its receipt is corrupt"
		);
		tx.rollback()?;
		c.pragma_update(None, "foreign_keys", true)?;
		assert_eq!(terminal_payloads::get(c, 301)?, StoredEvidence::Recorded(value.clone()));
		Ok(())
	})
	.unwrap();
}

#[test]
fn attempt_provenance_and_read_validation_fail_closed() {
	let db = fixture();
	let value = inconclusive();
	db.with_conn(|c| {
		insert_verification(c,&value)?;
		for (repo,commit,workflow) in [(2,"base",1),(1,"wrong",1),(1,"base",2)] {
			let mut request=attempt(&value);
			request.repo_id=repo;
			request.checkout_commit_sha=commit;
			request.workflow_contract_version=workflow;
			assert!(transaction::immediate(c,|tx|finding_details::insert_attempt_evidence(tx,&request,1)).is_err());
		}
		for mutation in [
			"UPDATE finding_verifications SET verdict='confirmed' WHERE id=601",
			"UPDATE jobs SET target_finding_id=999 WHERE id=601",
			"UPDATE jobs SET kind='drilldown' WHERE id=601",
			"UPDATE finding_verifications SET job_id=NULL WHERE id=601",
		] {
			assert!(transaction::immediate(c,|tx| {
				tx.execute(mutation,[])?;
				finding_details::insert_attempt_evidence(tx,&attempt(&value),1)
			}).is_err());
		}
		assert_eq!(finding_details::get_attempt_evidence(c,601)?,StoredEvidence::Missing);
		transaction::immediate(c,|tx|finding_details::insert_attempt_evidence(tx,&attempt(&value),1))?;
		for mutation in [
			"UPDATE verification_attempt_details SET evidence_payload=' '||evidence_payload WHERE verification_id=601",
			"UPDATE verification_attempt_details SET evidence_payload='{}' WHERE verification_id=601",
			"UPDATE verification_attempt_details SET terminal_digest=zeroblob(32) WHERE verification_id=601",
			"UPDATE finding_verifications SET verdict='confirmed' WHERE id=601",
			"UPDATE jobs SET head_sha='wrong' WHERE id=601",
		] {
			let tx=c.transaction()?;
			tx.execute(mutation,[])?;
			assert!(finding_details::get_attempt_evidence(&tx,601).is_err(),"corrupt attempt must not downgrade: {mutation}");
			tx.rollback()?;
		}
		assert!(c.execute("UPDATE verification_attempt_details SET e2e_applicability='not_applicable' WHERE verification_id=601",[]).is_err());
		Ok(())
	}).unwrap();
}

#[test]
fn finding_reads_validate_canonical_evidence_identity_and_provenance() {
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c,|tx|finding_details::insert_review_evidence(tx,&review(&evidence(),&identity()),1))?;
		for mutation in [
			"UPDATE finding_review_details SET evidence_payload=' '||evidence_payload WHERE finding_id=401",
			"UPDATE finding_review_details SET evidence_payload='{}' WHERE finding_id=401",
			"UPDATE finding_review_details SET identity_fingerprint=zeroblob(32) WHERE finding_id=401",
			"UPDATE finding_review_details SET reviewed_commit_sha='wrong' WHERE finding_id=401",
		] {
			let tx=c.transaction()?;
			tx.execute(mutation,[])?;
			assert!(finding_details::get_review_evidence(&tx,401).is_err(),"corrupt finding must not downgrade: {mutation}");
			tx.rollback()?;
			}
			assert!(c.execute("UPDATE finding_review_details SET submitted_rung='L3' WHERE finding_id=401",[]).is_err(),"modern finding evidence is L2 even before the read guard");
		assert!(c.execute("UPDATE finding_review_details SET counterevidence='duplicate projection' WHERE finding_id=401",[]).is_err());
		Ok(())
	}).unwrap();
}

#[test]
fn erased_modern_payload_is_not_mistaken_for_historical_evidence() {
	let db = fixture();
	db.with_conn(|c| {
		let value=inconclusive();
		insert_verification(c,&value)?;
		transaction::immediate(c,|tx| {
			finding_details::insert_review_evidence(tx,&review(&evidence(),&identity()),1)?;
			finding_details::insert_attempt_evidence(tx,&attempt(&value),1)
		})?;
		// Simulate a damaged file; normal writers cannot violate this constraint.
		c.pragma_update(None,"ignore_check_constraints",true)?;
		c.execute("UPDATE finding_review_details SET evidence_payload=NULL WHERE finding_id=401",[])?;
		c.execute("UPDATE verification_attempt_details SET evidence_payload=NULL WHERE verification_id=601",[])?;
		c.pragma_update(None,"ignore_check_constraints",false)?;
		assert!(finding_details::get_review_evidence(c,401).is_err());
		assert!(finding_details::get_attempt_evidence(c,601).is_err());
		Ok(())
	}).unwrap();
}
