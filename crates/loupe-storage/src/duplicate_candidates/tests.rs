use super::*;
use crate::secrets::MasterKey;
use crate::{review_tests, transaction, Db};

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn seed(db: &Db) {
	review_tests::seed(db);
	db.with_conn(|conn|transaction::immediate(conn,|tx| {
		let identity=Identity {family:Identifier::new("auth-bypass")?,anchor:loupe_core::text::Anchor::new("entry boundary")?,instance:None};
		tx.execute("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,created_at) VALUES(1,1,101,'review','high','title','private body','test',0)",[])?;
		tx.execute("INSERT INTO finding_review_details(finding_id,repo_id,workflow_contract_version,profile_version,reviewed_commit_sha,identity_family,identity_anchor,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,created_at) VALUES(1,1,1,1,?1,?2,?3,?4,'{}','counter','gaps','high','L2',0)",params![SHA,identity.family.expose(),identity.anchor.expose(),identity.fingerprint().as_slice()])?;
		Ok(())
	})).unwrap();
}

#[test]
fn issuance_and_immutable_finding_identity_survive_reopening() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("candidates.db");
	let key = MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	seed(&db);
	let query = CandidateQuery {
		query: loupe_core::review_candidates::QueryText::new("auth").unwrap(),
		limit: 20,
	};
	let initial = db
		.with_conn(|conn| transaction::immediate(conn, |tx| issue(tx, 101, 1, &query, 1)))
		.unwrap();
	assert_eq!(initial.len(), 1);
	assert_eq!(initial[0].kind, CandidateKind::Finding);
	assert!(!serde_json::to_string(&initial).unwrap().contains("private"));
	drop(db);
	let db = Db::open(&path, &key).unwrap();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			assert_eq!(issue(tx, 101, 1, &query, 2)?, initial);
			assert_eq!(
				checkpoints::accepted_count(tx, 101, Operation::IssueDuplicateCandidates)?,
				1
			);
			assert!(issued_target(tx, 101, 1, CandidateKind::Finding, 1)?);
			assert!(!issued_target(tx, 102, 1, CandidateKind::Finding, 1)?);
			assert!(!issued_target(tx, 101, 2, CandidateKind::Finding, 1)?);
			assert!(!issued_target(tx, 101, 1, CandidateKind::Finding, 999)?);
			tx.execute(
				"UPDATE findings SET description='changed body',state='dismissed' WHERE id=1",
				[],
			)?;
			assert!(
				issued_target(tx, 101, 1, CandidateKind::Finding, 1)?,
				"mutable status/body do not replace immutable identity"
			);
			tx.execute(
				"UPDATE finding_review_details SET reviewed_commit_sha=?1 WHERE finding_id=1",
				["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
			)?;
			assert!(
				!issued_target(tx, 101, 1, CandidateKind::Finding, 1)?,
				"retargeting provenance revokes issued authority"
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn refused_bad_or_rolled_back_queries_do_not_consume_issuance() {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	seed(&db);
	let query = CandidateQuery {
		query: loupe_core::review_candidates::QueryText::new("auth").unwrap(),
		limit: 20,
	};
	db.with_conn(|conn| {
		let result:Result<()>=transaction::immediate(conn,|tx| {
			assert_eq!(issue(tx,101,1,&query,0)?.len(),1);
			Err(Error::Conflict(Conflict::Candidate))
		});
		assert!(result.is_err());
		transaction::immediate(conn,|tx| {
			assert_eq!(checkpoints::accepted_count(tx,101,Operation::IssueDuplicateCandidates)?,0);
			assert!(issue(tx,101,2,&query,0).is_err());
			tx.execute("UPDATE finding_review_details SET identity_fingerprint=zeroblob(32) WHERE finding_id=1",[])?;
			assert!(issue(tx,101,1,&query,0).is_err());
			assert_eq!(checkpoints::accepted_count(tx,101,Operation::IssueDuplicateCandidates)?,0);
			Ok(())
		})
	}).unwrap();
}

#[test]
fn unissued_targets_are_denied_before_decoding_their_contents() {
	let mut leaks = Vec::new();
	for mutation in
		["identity_fingerprint=zeroblob(32)", "identity_anchor=x'00'", "reviewed_commit_sha='bad'"]
	{
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		seed(&db);
		db.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let query = CandidateQuery {
					query: loupe_core::review_candidates::QueryText::new("auth")?,
					limit: 20,
				};
				assert_eq!(issue(tx, 101, 1, &query, 0)?.len(), 1);
				assert!(!issued_target(tx, 102, 1, CandidateKind::Finding, 1)?);
				tx.execute(
					&format!("UPDATE finding_review_details SET {mutation} WHERE finding_id=1"),
					[],
				)?;
				let result = issued_target(tx, 102, 1, CandidateKind::Finding, 1);
				if !matches!(result, Ok(false)) {
					leaks.push(format!("{mutation}: {result:?}"));
				}
				assert!(!issued_target(tx, 102, 1, CandidateKind::Finding, 999)?);
				assert!(!issued_target(tx, 102, 2, CandidateKind::Finding, 1)?);
				assert!(
					issued_target(tx, 101, 1, CandidateKind::Finding, 1).is_err(),
					"issued corrupted evidence must still fail closed"
				);
				Ok(())
			})
		})
		.unwrap();
	}
	assert!(leaks.is_empty(), "unissued targets must never be decoded: {leaks:?}");
}
