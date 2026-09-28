//! Independent, byte-exact inventory disposition checkpoints.
use loupe_core::canonical;
use loupe_core::text::policy::ClientKey;
use loupe_core::text::{BoundedText, Identifier, RepoPath, TextPolicy};
use serde::{Deserialize, Serialize};

use crate::review_api::ReviewProtocol;
use crate::review_lease::{LeaseList, ReviewId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryReason;
impl TextPolicy for InventoryReason {
	const FIELD: &'static str = "reason";
	const MAX_CHARS: usize = 500;
	const MAX_BYTES: usize = 1000;
	const MULTILINE: bool = false;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
	Mapped,
	Context,
	Excluded,
	Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitMapping {
	pub review_unit_id: ReviewId,
	pub assignment_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Wire")]
pub struct InventoryDispositionRequest {
	pub protocol_version: ReviewProtocol,
	pub client_inventory_disposition_key: Identifier<ClientKey>,
	pub source_path: RepoPath,
	pub expected_revision: i64,
	pub disposition: Disposition,
	pub reason: Option<BoundedText<InventoryReason>>,
	pub mappings: LeaseList<UnitMapping, 8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
	protocol_version: ReviewProtocol,
	client_inventory_disposition_key: Identifier<ClientKey>,
	source_path: RepoPath,
	expected_revision: i64,
	disposition: Disposition,
	reason: Option<BoundedText<InventoryReason>>,
	#[serde(default)]
	mappings: LeaseList<UnitMapping, 8>,
}
impl TryFrom<Wire> for InventoryDispositionRequest {
	type Error = &'static str;
	fn try_from(w: Wire) -> Result<Self, Self::Error> {
		let value = Self {
			protocol_version: w.protocol_version,
			client_inventory_disposition_key: w.client_inventory_disposition_key,
			source_path: w.source_path,
			expected_revision: w.expected_revision,
			disposition: w.disposition,
			reason: w.reason,
			mappings: w.mappings,
		};
		value.validate()?;
		Ok(value)
	}
}
impl InventoryDispositionRequest {
	pub fn validate(&self) -> Result<(), &'static str> {
		if self.expected_revision < 0 {
			return Err("expected_revision must be nonnegative");
		}
		if (self.disposition == Disposition::Mapped) == self.mappings.as_slice().is_empty() {
			return Err("mapped requires mappings; other dispositions forbid them");
		}
		if matches!(self.disposition, Disposition::Context | Disposition::Excluded)
			&& self.reason.is_none()
		{
			return Err("context and excluded require reason");
		}
		let mut ids = std::collections::HashSet::new();
		for mapping in self.mappings.as_slice() {
			if mapping.assignment_epoch > i64::MAX as u64
				|| !ids.insert(i64::from(mapping.review_unit_id))
			{
				return Err("mappings require distinct units and SQLite-range epochs");
			}
		}
		Ok(())
	}
	/// Canonicalize the complete typed request, never generic JSON prose leaves:
	/// RepoPath deliberately preserves NFC-distinct Git identities.
	pub fn digest(&self) -> Result<[u8; 32], serde_json::Error> {
		Ok(canonical::digest(&canonical::canonical_bytes(&serde_json::to_value(self)?)))
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryDispositionResponse {
	pub protocol_version: ReviewProtocol,
	pub inventory_entry_id: ReviewId,
	pub revision: u64,
}

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;
	fn request() -> serde_json::Value {
		json!({"protocol_version":3,"client_inventory_disposition_key":"entry-a","source_path":"a.rs","expected_revision":0,"disposition":"mapped","mappings":[{"review_unit_id":1,"assignment_epoch":0}]})
	}
	#[test]
	fn strict_bounds_and_variant_requirements() {
		let valid = request();
		assert!(serde_json::from_value::<InventoryDispositionRequest>(valid.clone()).is_ok());
		for (field, value) in [
			("unexpected", json!(1)),
			("protocol_version", json!(2)),
			("expected_revision", json!(-1)),
			("source_path", json!("../a")),
			("mappings", json!([])),
			(
				"mappings",
				json!([{"review_unit_id":1,"assignment_epoch":0},{"review_unit_id":1,"assignment_epoch":1}]),
			),
		] {
			let mut invalid = valid.clone();
			invalid[field] = value;
			assert!(
				serde_json::from_value::<InventoryDispositionRequest>(invalid).is_err(),
				"{field}"
			);
		}
		for disposition in ["context", "excluded", "unresolved"] {
			let mut value = valid.clone();
			value["disposition"] = json!(disposition);
			assert!(serde_json::from_value::<InventoryDispositionRequest>(value.clone()).is_err());
			value["mappings"] = json!([]);
			assert_eq!(
				serde_json::from_value::<InventoryDispositionRequest>(value.clone()).is_ok(),
				disposition == "unresolved"
			);
			value["reason"] = json!("intentional scope");
			assert!(serde_json::from_value::<InventoryDispositionRequest>(value).is_ok());
		}
		let mut oversized = valid.clone();
		oversized["reason"] = json!("a".repeat(501));
		assert!(serde_json::from_value::<InventoryDispositionRequest>(oversized).is_err());
		assert!(BoundedText::<InventoryReason>::new(&"a".repeat(500)).is_ok());
		assert!(BoundedText::<InventoryReason>::new(&"界".repeat(333)).is_ok());
		assert!(BoundedText::<InventoryReason>::new(&"界".repeat(334)).is_err());
		let mut maximum = valid.clone();
		maximum["mappings"] = json!((1..=8)
			.map(|id| json!({"review_unit_id":id,"assignment_epoch":0}))
			.collect::<Vec<_>>());
		assert!(serde_json::from_value::<InventoryDispositionRequest>(maximum).is_ok());
		let mut excess = valid.clone();
		excess["mappings"] = json!((1..=9)
			.map(|id| json!({"review_unit_id":id,"assignment_epoch":0}))
			.collect::<Vec<_>>());
		assert!(serde_json::from_value::<InventoryDispositionRequest>(excess).is_err());
		for raw in [
			valid.to_string().replace(
				"\"expected_revision\":0",
				"\"expected_revision\":0,\"expected_revision\":0",
			),
			valid
				.to_string()
				.replace("\"assignment_epoch\":0", "\"assignment_epoch\":0,\"assignment_epoch\":0"),
			valid
				.to_string()
				.replace("\"assignment_epoch\":0", "\"assignment_epoch\":9223372036854775808"),
		] {
			assert!(serde_json::from_str::<InventoryDispositionRequest>(&raw).is_err());
		}
	}
	#[test]
	fn digest_covers_every_field_and_preserves_exact_path_identity() {
		let original: InventoryDispositionRequest = serde_json::from_value(request()).unwrap();
		for (field, value) in [
			("client_inventory_disposition_key", json!("entry-b")),
			("source_path", json!("b.rs")),
			("expected_revision", json!(1)),
			("reason", json!("why")),
			("mappings", json!([{"review_unit_id":1,"assignment_epoch":1}])),
		] {
			let mut changed = request();
			changed[field] = value;
			let changed: InventoryDispositionRequest = serde_json::from_value(changed).unwrap();
			assert_ne!(original.digest().unwrap(), changed.digest().unwrap(), "{field}");
		}
		let mut nfc = original.clone();
		nfc.source_path = RepoPath::new("é.rs").unwrap();
		let mut nfd = original.clone();
		nfd.source_path = RepoPath::new("e\u{301}.rs").unwrap();
		assert_ne!(nfc.digest().unwrap(), nfd.digest().unwrap());
	}
}
