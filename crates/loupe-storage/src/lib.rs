//! SQLite storage layer for loupe.
//!
//! The schema is defined as an ordered list of migrations in `migrations`.
//! `Db::open` runs any unapplied migrations inside a transaction and
//! advances `schema_meta.version`. Tests are encouraged to use
//! `Db::open_in_memory` so the migration code path is exercised on every
//! run.

pub mod admission;
pub mod admission_candidates;
pub mod admission_claim;
pub mod admission_policy;
pub mod admission_quarantine;
pub mod campaign_work;
pub mod campaigns;
pub mod checkpoints;
mod db;
pub mod duplicate_candidates;
pub mod finding_details;
pub mod findings;
pub mod generations;
pub mod host_preparation;
pub mod identity;
pub mod inventory;
pub mod inventory_disposition;
pub mod jobs;
pub mod lead_observations;
pub mod leads;
pub mod migrations;
pub mod ownership;
pub mod phase_lifecycle;
pub mod proofs;
pub mod repos;
mod review;
pub mod review_authority;
pub mod review_compatibility;
pub mod review_coverage;
pub mod review_findings;
pub mod review_intents;
pub mod review_unit_results;
pub mod review_units;
pub mod scheduler;
pub mod secrets;
pub mod source_refs;
pub mod terminal_payloads;
pub mod terminal_receipt;
pub mod transaction;
pub mod unit_holds;
pub mod workers;

#[cfg(test)]
mod checkpoint_evidence_feature_tests;
#[cfg(test)]
mod checkpoint_evidence_tests;
#[cfg(test)]
mod evidence_tests;
#[cfg(test)]
mod proof_tests;
#[cfg(test)]
mod replay_tests;
#[cfg(test)]
mod review_coverage_tests;
#[cfg(test)]
mod review_tests;
#[cfg(test)]
mod scope_tests;

/// Missing rows and historical rows without canonical evidence are distinct.
/// A malformed modern payload is an error, never historical evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredEvidence<T> {
	Missing,
	Historical,
	Recorded(T),
}

pub use db::{Db, Error, Result};
pub use loupe_core::canonical;
pub use review::{Conflict, Entity, Ownership};
