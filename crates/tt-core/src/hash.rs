//! SHA-256 digests and bounded streaming file hashing.
//!
//! The hash buffer is fixed and small so that hashing a multi-gigabyte checkpoint
//! never grows scanner memory, and so that cancellation is responsive: the caller
//! is consulted once per buffer.

use crate::error::{TtError, TtResult};
use crate::hex;
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Bytes read per hashing iteration. Also the cancellation granularity.
pub const HASH_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn to_hex(self) -> String {
        hex::encode(&self.0)
    }
    pub fn from_hex(s: &str) -> TtResult<Self> {
        Ok(Digest(hex::decode_fixed::<32>(s)?))
    }
    /// Digest of a byte slice.
    pub fn of(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(bytes);
        let out = h.finalize();
        let mut d = [0u8; 32];
        d.copy_from_slice(&out);
        Digest(d)
    }
    /// First `n` hex characters, for human-facing short forms.
    pub fn short(self, n: usize) -> String {
        let s = self.to_hex();
        s[..n.min(s.len())].to_string()
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Incremental hasher.
#[derive(Clone)]
pub struct Hasher(Sha256);

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    pub fn new() -> Self {
        Hasher(Sha256::new())
    }
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    pub fn finish(self) -> Digest {
        let out = self.0.finalize();
        let mut d = [0u8; 32];
        d.copy_from_slice(&out);
        Digest(d)
    }
}

/// How much of a file was hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashScope {
    /// Every byte was hashed.
    Full,
    /// Only the first `bytes` were hashed, because the file exceeded the budget.
    HeadOnly { bytes: u64 },
    /// Nothing was hashed.
    None,
}

impl HashScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            HashScope::Full => "full",
            HashScope::HeadOnly { .. } => "head_only",
            HashScope::None => "none",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileHash {
    pub digest: Digest,
    pub bytes_hashed: u64,
    pub scope: HashScope,
}

/// Hash a file with a bounded buffer and a byte budget.
///
/// `cancel` is polled once per buffer; returning `true` aborts with
/// [`TtError::Io`] carrying `cancelled`, so a long hash never blocks the UI.
pub fn hash_file(
    path: &Path,
    budget_bytes: u64,
    cancel: &dyn Fn() -> bool,
) -> TtResult<FileHash> {
    let mut f = File::open(path)?;
    let mut hasher = Hasher::new();
    let mut buf = vec![0u8; HASH_BUFFER_BYTES];
    let mut total: u64 = 0;
    let mut truncated = false;

    loop {
        if cancel() {
            return Err(TtError::io("cancelled"));
        }
        let remaining = budget_bytes.saturating_sub(total);
        if remaining == 0 {
            // Probe whether anything is left, to distinguish exactly-at-budget
            // from truncated.
            let mut probe = [0u8; 1];
            if f.read(&mut probe)? > 0 {
                truncated = true;
            }
            break;
        }
        let want = buf.len().min(remaining as usize);
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }

    Ok(FileHash {
        digest: hasher.finish(),
        bytes_hashed: total,
        scope: if truncated { HashScope::HeadOnly { bytes: total } } else { HashScope::Full },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector_empty() {
        assert_eq!(
            Digest::of(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn known_vector_abc() {
        assert_eq!(
            Digest::of(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn incremental_matches_oneshot() {
        let mut h = Hasher::new();
        h.update(b"hello ");
        h.update(b"world");
        assert_eq!(h.finish(), Digest::of(b"hello world"));
    }

    #[test]
    fn hex_round_trip() {
        let d = Digest::of(b"traintrace");
        assert_eq!(Digest::from_hex(&d.to_hex()).unwrap(), d);
    }
}
