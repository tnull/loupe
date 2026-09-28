use super::*;
use crate::{review_tests, transaction, Db};

fn fixture() -> Db {
	let db = review_tests::fixture();
	db.with_conn(|conn| {
		conn.execute_batch("INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,received_entry_count,expected_digest,created_at,sealed_at) VALUES(11,1,101,2,2,zeroblob(32),0,1);
		INSERT INTO generation_inventory(inventory_entry_id,generation_id,path,raw_path,source_path,manifest_position,git_mode,blob_sha,entry_kind,created_at) VALUES(1,11,'a.rs',CAST('a.rs' AS BLOB),'a.rs',0,33188,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','tracked',0),(2,11,'b.rs',CAST('b.rs' AS BLOB),'b.rs',1,33188,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','tracked',0);
		INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,assignment_epoch,created_at) VALUES(1,11,'a','A','Review A','[{\"path\":\"a.rs\"}]',1,0),(2,11,'b','B','Review B','[{\"path\":\"b.rs\"}]',1,0),(3,21,'foreign','Foreign','Review A','[{\"path\":\"a.rs\"}]',1,0);
		INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(101,1,0,1);")?;
		Ok(())
	}).unwrap();
	db
}

#[test]
fn resolution_scopes_exact_identity_before_exposing_revision() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let a = RepoPath::new("a.rs")?;
			let b = RepoPath::new("b.rs")?;
			assert!(resolve(tx, 101, 11, false, &a)?.is_some());
			assert!(resolve(tx, 101, 11, false, &b)?.is_none());
			assert!(resolve(tx, 101, 11, true, &b)?.is_some());
			assert!(resolve(tx, 201, 11, true, &a)?.is_none());
			tx.execute(
				"UPDATE generation_inventory SET manifest_position=NULL WHERE inventory_entry_id=2",
				[],
			)?;
			assert!(resolve(tx, 101, 11, true, &b)?.is_none());
			tx.execute(
				"UPDATE generation_manifests SET sealed_at=NULL WHERE generation_id=11",
				[],
			)?;
			assert!(resolve(tx, 101, 11, true, &a)?.is_none());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn replacement_validates_all_paths_epochs_generation_and_cas_without_partial_updates() {
	let db = fixture();
	db.with_conn(|conn| {
		let entry=transaction::immediate(conn,|tx|resolve(tx,101,11,false,&RepoPath::new("a.rs")?))?.unwrap();
		for mappings in [
			vec![Mapping{unit_id:1,assignment_epoch:1},Mapping{unit_id:2,assignment_epoch:1}],
			vec![Mapping{unit_id:1,assignment_epoch:0}],
			vec![Mapping{unit_id:3,assignment_epoch:1}],
			vec![Mapping{unit_id:1,assignment_epoch:1};2],
		] {
			assert!(transaction::immediate(conn,|tx|replace(tx,&entry,&Update{expected_revision:0,disposition:Disposition::Mapped,reason:None,mappings:&mappings})).is_err());
			assert_eq!(conn.query_row("SELECT disposition_revision FROM generation_inventory WHERE inventory_entry_id=1",[],|r|r.get::<_,i64>(0))?,0);
		}
		let mappings=[Mapping{unit_id:1,assignment_epoch:1}];
		transaction::immediate(conn,|tx| {
			assert_eq!(replace(tx,&entry,&Update{expected_revision:0,disposition:Disposition::Mapped,reason:None,mappings:&mappings})?,1);
			Ok(())
		})?;
		assert!(transaction::immediate(conn,|tx|replace(tx,&entry,&Update{expected_revision:0,disposition:Disposition::Unresolved,reason:None,mappings:&[]})).is_err());
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM generation_inventory_units WHERE inventory_entry_id=1",[],|r|r.get::<_,i64>(0))?,1);
		Ok(())
	}).unwrap();
}
