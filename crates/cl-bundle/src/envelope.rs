//! The integrity envelope.
//!
//! ## What this proves, and what it does not
//!
//! The envelope lists every payload with its SHA-256 and binds them into one root
//! digest that the verifier recomputes. That detects a bundle edited after export:
//! change one word of the PDF and the root digest moves.
//!
//! It does **not** prove the bundle is genuine. The scanner runs on the vendor's
//! machine, offline, under the vendor's control. Anyone who can edit the report can
//! also recompute the envelope. This is *self-consistency*, not independent
//! cryptographic proof, and the report says so in those words. Independent proof
//! needs either the buyer's signed challenge (`cl-case`) or the optional Stage-1.5
//! server-held seal, both of which involve a key the vendor never holds.

use crate::Payload;
use cl_core::canon::{arr, CanonValue, Obj};
use cl_core::error::{ClError, ClResult};
use cl_core::hash::Digest;

/// Root digest over `[name, sha256]` pairs sorted by name.
///
/// Sorting rather than using bundle order means the digest is a property of the
/// *contents*, so reordering entries in the archive cannot change it — which is
/// exactly the substitution a repacking attack would try.
pub fn root_digest(payloads: &[Payload]) -> Digest {
    let mut rows: Vec<(String, String)> =
        payloads.iter().map(|p| (p.name.clone(), p.digest().to_hex())).collect();
    rows.sort();
    let value = CanonValue::Arr(
        rows.into_iter()
            .map(|(n, d)| arr(vec![n, d]))
            .collect(),
    );
    value.digest()
}

pub fn build_envelope(payloads: &[Payload]) -> CanonValue {
    let mut rows: Vec<&Payload> = payloads.iter().collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    let entries: Vec<CanonValue> = rows
        .iter()
        .map(|p| {
            CanonValue::Obj(
                Obj::new()
                    .with("name", p.name.as_str())
                    .with("sha256", p.digest())
                    .with("size_bytes", p.bytes.len()),
            )
        })
        .collect();
    CanonValue::Obj(
        Obj::new()
            .with("schema_version", cl_core::SCHEMA_VERSION)
            .with("bundle_format", cl_core::BUNDLE_FORMAT)
            .with("payloads", CanonValue::Arr(entries))
            .with("root_digest", root_digest(payloads))
            .with(
                "note",
                "Self-consistency of this bundle's own bytes. Not independent proof of origin.",
            ),
    )
}

/// The outcome of checking a bundle against its envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeCheck {
    pub root_matches: bool,
    /// Names present in the envelope but absent from the archive.
    pub missing: Vec<String>,
    /// Names present in the archive but absent from the envelope.
    pub unexpected: Vec<String>,
    /// Names present in both whose bytes hash differently.
    pub altered: Vec<String>,
}

impl EnvelopeCheck {
    pub fn is_intact(&self) -> bool {
        self.root_matches
            && self.missing.is_empty()
            && self.unexpected.is_empty()
            && self.altered.is_empty()
    }
}

/// Check the archive's payloads against a parsed `integrity-envelope.json`.
///
/// The envelope entry itself is excluded from the comparison: a document cannot
/// contain its own digest.
pub fn verify_envelope(envelope: &CanonValue, payloads: &[Payload]) -> ClResult<EnvelopeCheck> {
    let declared = envelope
        .get("payloads")
        .and_then(|p| p.as_arr())
        .ok_or_else(|| ClError::malformed("integrity_envelope", 0, "missing payloads array"))?;

    let mut missing = Vec::new();
    let mut altered = Vec::new();
    let mut declared_names: Vec<String> = Vec::new();

    for entry in declared {
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ClError::malformed("integrity_envelope", 0, "payload without a name"))?;
        let want = entry
            .get("sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ClError::malformed("integrity_envelope", 0, "payload without a digest"))?;
        declared_names.push(name.to_string());
        match payloads.iter().find(|p| p.name == name) {
            None => missing.push(name.to_string()),
            Some(p) => {
                if p.digest().to_hex() != want {
                    altered.push(name.to_string());
                }
            }
        }
    }

    let mut unexpected: Vec<String> = payloads
        .iter()
        .map(|p| p.name.clone())
        .filter(|n| n != crate::INTEGRITY_ENVELOPE_JSON && !declared_names.contains(n))
        .collect();
    unexpected.sort();
    missing.sort();
    altered.sort();

    let compared: Vec<Payload> = payloads
        .iter()
        .filter(|p| p.name != crate::INTEGRITY_ENVELOPE_JSON)
        .cloned()
        .collect();
    let declared_root = envelope.get("root_digest").and_then(|v| v.as_str()).unwrap_or("");
    let root_matches = declared_root == root_digest(&compared).to_hex();

    Ok(EnvelopeCheck { root_matches, missing, unexpected, altered })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Payload> {
        vec![
            Payload::new(crate::REPORT_JSON, b"{\"a\":1}".to_vec()),
            Payload::new(crate::VERIFY_TXT, b"read me".to_vec()),
        ]
    }

    #[test]
    fn intact_bundle_verifies() {
        let p = sample();
        let env = build_envelope(&p);
        let check = verify_envelope(&env, &p).unwrap();
        assert!(check.is_intact(), "{check:?}");
    }

    #[test]
    fn root_digest_ignores_entry_order() {
        let a = sample();
        let mut b = sample();
        b.reverse();
        assert_eq!(root_digest(&a), root_digest(&b));
    }

    #[test]
    fn one_changed_byte_is_detected() {
        let p = sample();
        let env = build_envelope(&p);
        let mut tampered = p.clone();
        tampered[0].bytes = b"{\"a\":2}".to_vec();
        let check = verify_envelope(&env, &tampered).unwrap();
        assert!(!check.is_intact());
        assert_eq!(check.altered, vec![crate::REPORT_JSON.to_string()]);
        assert!(!check.root_matches);
    }

    #[test]
    fn a_removed_payload_is_reported_as_missing_not_as_intact() {
        let p = sample();
        let env = build_envelope(&p);
        let check = verify_envelope(&env, &p[..1]).unwrap();
        assert_eq!(check.missing, vec![crate::VERIFY_TXT.to_string()]);
        assert!(!check.is_intact());
    }

    #[test]
    fn an_added_payload_is_reported_as_unexpected() {
        let p = sample();
        let env = build_envelope(&p);
        let mut more = p.clone();
        more.push(Payload::new(crate::REPORT_PDF, b"%PDF-1.7".to_vec()));
        let check = verify_envelope(&env, &more).unwrap();
        assert_eq!(check.unexpected, vec![crate::REPORT_PDF.to_string()]);
        assert!(!check.is_intact());
    }

    #[test]
    fn envelope_is_canonical_and_stable() {
        let a = build_envelope(&sample());
        let mut rev = sample();
        rev.reverse();
        let b = build_envelope(&rev);
        assert_eq!(a.digest(), b.digest());
    }
}
