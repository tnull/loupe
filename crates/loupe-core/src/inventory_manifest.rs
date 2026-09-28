//! Lossless, streaming format-1 inventory identity shared by host and server.

pub const MAX_ENTRIES: u64 = 1_000_000;
pub const MAX_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_CHUNK_ENTRIES: usize = 4096;
pub const MAX_CHUNK_BYTES: u64 = 1024 * 1024;
pub const MAX_PATH_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
	pub raw_path: Vec<u8>,
	pub git_mode: u32,
	pub object_id: String,
}

pub fn is_git_oid(value: &str) -> bool {
	matches!(value.len(), 40 | 64)
		&& value.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Gitlink entries name commits; every other supported mode names a blob.
pub fn is_submodule_mode(mode: u32) -> Result<bool, &'static str> {
	match mode {
		0o100644 | 0o100755 | 0o120000 => Ok(false),
		0o160000 => Ok(true),
		_ => Err("unsupported inventory mode"),
	}
}

fn oid_bytes(value: &str) -> Result<Vec<u8>, &'static str> {
	if !is_git_oid(value) {
		return Err("invalid inventory object id");
	}
	fn digit(byte: u8) -> u8 {
		if byte <= b'9' {
			byte - b'0'
		} else {
			byte - b'a' + 10
		}
	}
	Ok(value
		.as_bytes()
		.as_chunks::<2>()
		.0
		.iter()
		.map(|pair| digit(pair[0]) * 16 + digit(pair[1]))
		.collect())
}

impl ManifestEntry {
	pub fn canonical_len(&self) -> Result<u64, &'static str> {
		if self.raw_path.is_empty()
			|| self.raw_path.len() > MAX_PATH_BYTES
			|| self.raw_path.contains(&0)
			|| self
				.raw_path
				.split(|byte| *byte == b'/')
				.any(|part| part.is_empty() || part == b"." || part == b"..")
		{
			return Err("invalid raw inventory path");
		}
		is_submodule_mode(self.git_mode)?;
		if !is_git_oid(&self.object_id) {
			return Err("invalid inventory object id");
		}
		Ok(4 + self.raw_path.len() as u64 + 4 + 1 + self.object_id.len() as u64 / 2)
	}
}

pub struct ManifestHasher {
	hasher: blake3::Hasher,
	expected: u64,
	received: u64,
	bytes: u64,
	previous: Option<Vec<u8>>,
}

impl ManifestHasher {
	pub fn new(commit: &str, expected: u64) -> Result<Self, &'static str> {
		if expected > MAX_ENTRIES {
			return Err("inventory entry limit exceeded");
		}
		let commit = oid_bytes(commit)?;
		let mut hasher = blake3::Hasher::new();
		hasher.update(b"loupe.inventory.v1\0");
		hasher.update(&[commit.len() as u8]);
		hasher.update(&commit);
		hasher.update(&expected.to_be_bytes());
		Ok(Self { hasher, expected, received: 0, bytes: 0, previous: None })
	}

	pub fn push(&mut self, entry: &ManifestEntry) -> Result<(), &'static str> {
		let len = entry.canonical_len()?;
		if self.received >= self.expected
			|| self.previous.as_ref().is_some_and(|previous| previous >= &entry.raw_path)
		{
			return Err("inventory is not an ordered complete set");
		}
		let bytes = self
			.bytes
			.checked_add(len)
			.filter(|bytes| *bytes <= MAX_BYTES)
			.ok_or("inventory byte limit exceeded")?;
		let oid = oid_bytes(&entry.object_id)?;
		self.hasher.update(&(entry.raw_path.len() as u32).to_be_bytes());
		self.hasher.update(&entry.raw_path);
		self.hasher.update(&entry.git_mode.to_be_bytes());
		self.hasher.update(&[oid.len() as u8]);
		self.hasher.update(&oid);
		self.received += 1;
		self.bytes = bytes;
		self.previous = Some(entry.raw_path.clone());
		Ok(())
	}

	pub fn bytes(&self) -> u64 {
		self.bytes
	}

	pub fn finish(self) -> Result<[u8; 32], &'static str> {
		if self.received != self.expected {
			return Err("incomplete inventory");
		}
		Ok(*self.hasher.finalize().as_bytes())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn format_is_exact_and_lossless() {
		let entry = ManifestEntry {
			raw_path: vec![b'a', 0xff],
			git_mode: 0o100644,
			object_id: "22".repeat(20),
		};
		let mut hasher = ManifestHasher::new(&"11".repeat(20), 1).unwrap();
		hasher.push(&entry).unwrap();
		assert_eq!(hasher.bytes(), 31);
		let mut exact = b"loupe.inventory.v1\0".to_vec();
		exact.push(20);
		exact.extend([0x11; 20]);
		exact.extend(1u64.to_be_bytes());
		exact.extend(2u32.to_be_bytes());
		exact.extend([b'a', 0xff]);
		exact.extend(0o100644u32.to_be_bytes());
		exact.push(20);
		exact.extend([0x22; 20]);
		assert_eq!(hasher.finish().unwrap(), *blake3::hash(&exact).as_bytes());
	}

	#[test]
	fn refuses_invalid_paths_modes_oids_and_incomplete_or_unordered_sets() {
		let entry = ManifestEntry {
			raw_path: b"a".to_vec(),
			git_mode: 0o100644,
			object_id: "22".repeat(32),
		};
		for path in [b"".as_slice(), b"/a", b"a/", b"a//b", b"a/../b", b"a/./b", b"a\0"] {
			assert!(ManifestEntry { raw_path: path.to_vec(), ..entry.clone() }
				.canonical_len()
				.is_err());
		}
		assert!(ManifestEntry { git_mode: 0o040000, ..entry.clone() }.canonical_len().is_err());
		assert!(ManifestEntry { object_id: "AB".repeat(20), ..entry.clone() }
			.canonical_len()
			.is_err());
		let mut hasher = ManifestHasher::new(&"11".repeat(32), 2).unwrap();
		hasher.push(&entry).unwrap();
		assert!(hasher.push(&entry).is_err());
		assert!(hasher.finish().is_err());
		assert!(ManifestHasher::new(&"11".repeat(20), 0).unwrap().finish().is_ok());
	}
}
