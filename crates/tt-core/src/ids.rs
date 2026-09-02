//! Identifiers with fixed shapes, so that a malformed one is a parse error rather
//! than a value that flows silently into a report.

use crate::error::{TtError, TtResult};
use crate::hex;

/// `TT-<4 digit year>-<6 uppercase hex>`
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CaseId(String);

impl CaseId {
    pub fn new(year: i64, suffix: &str) -> TtResult<Self> {
        let s = format!("TT-{year:04}-{suffix}");
        Self::parse(&s)
    }

    pub fn parse(s: &str) -> TtResult<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        let bad = |d: &str| TtError::malformed("case_id", 0, d.to_string());
        if parts.len() != 3 || parts[0] != "TT" {
            return Err(bad("expected TT-<year>-<suffix>"));
        }
        if parts[1].len() != 4 || !parts[1].bytes().all(|c| c.is_ascii_digit()) {
            return Err(bad("year must be four digits"));
        }
        if parts[2].len() != 6
            || !parts[2].bytes().all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c))
        {
            return Err(bad("suffix must be six uppercase hex characters"));
        }
        Ok(CaseId(s.to_string()))
    }

    /// Derive a case id from random bytes.
    pub fn from_entropy(year: i64, bytes: &[u8; 3]) -> CaseId {
        CaseId(format!("TT-{year:04}-{}", hex::encode(bytes).to_uppercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Safe as a file-name component by construction.
    pub fn as_filename_part(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CaseId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<CaseId> for crate::canon::CanonValue {
    fn from(c: CaseId) -> Self {
        crate::canon::CanonValue::Str(c.0)
    }
}

impl From<&CaseId> for crate::canon::CanonValue {
    fn from(c: &CaseId) -> Self {
        crate::canon::CanonValue::Str(c.0.clone())
    }
}

/// A 16-byte random value, rendered as 32 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce(String);

impl Nonce {
    pub fn from_bytes(b: &[u8; 16]) -> Nonce {
        Nonce(hex::encode(b))
    }
    pub fn parse(s: &str) -> TtResult<Nonce> {
        if s.len() != 32 {
            return Err(TtError::malformed("nonce", s.len(), "expected 32 hex characters"));
        }
        hex::decode(s)?;
        Ok(Nonce(s.to_string()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&Nonce> for crate::canon::CanonValue {
    fn from(n: &Nonce) -> Self {
        crate::canon::CanonValue::Str(n.0.clone())
    }
}

/// Sequential ids that are stable within one report.
#[derive(Debug, Default)]
pub struct IdAllocator {
    next_fact: u32,
    next_artifact: u32,
}

impl IdAllocator {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn fact(&mut self) -> String {
        self.next_fact += 1;
        format!("F-{:04}", self.next_fact)
    }
    pub fn artifact(&mut self) -> String {
        self.next_artifact += 1;
        format!("A-{:04}", self.next_artifact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_id_shape() {
        assert!(CaseId::parse("TT-2026-0F3A9C").is_ok());
        assert!(CaseId::parse("TT-2026-0f3a9c").is_err(), "lowercase rejected");
        assert!(CaseId::parse("TT-26-0F3A9C").is_err());
        assert!(CaseId::parse("XX-2026-0F3A9C").is_err());
        assert!(CaseId::parse("TT-2026-0F3A9").is_err());
        assert!(CaseId::parse("TT-2026-0F3A9C-1").is_err());
        assert!(CaseId::parse("../etc").is_err());
    }

    #[test]
    fn case_id_from_entropy_is_valid() {
        let c = CaseId::from_entropy(2026, &[0x0f, 0x3a, 0x9c]);
        assert_eq!(c.as_str(), "TT-2026-0F3A9C");
        assert!(CaseId::parse(c.as_str()).is_ok());
    }

    #[test]
    fn nonce_shape() {
        assert!(Nonce::parse(&"a".repeat(32)).is_ok());
        assert!(Nonce::parse(&"A".repeat(32)).is_err());
        assert!(Nonce::parse(&"a".repeat(31)).is_err());
    }

    #[test]
    fn allocator_is_sequential_and_padded() {
        let mut a = IdAllocator::new();
        assert_eq!(a.fact(), "F-0001");
        assert_eq!(a.fact(), "F-0002");
        assert_eq!(a.artifact(), "A-0001");
    }
}
