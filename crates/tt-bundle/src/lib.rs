//! # tt-bundle
//!
//! The `.ttscan` container: a hand-written, STORED-ONLY ZIP writer and a
//! deliberately hostile reader.
//!
//! ## Why stored-only
//!
//! Refusing compressed entries outright makes decompression bombs *structurally*
//! impossible rather than merely bounded. A compressed entry is rejected, never
//! decompressed-and-then-checked. The cost is a larger attachment; the benefit is
//! that an entire class of attack cannot be expressed in the format.
//!
//! ## Why the name set is closed
//!
//! A bundle may contain only the eight names in [`ENTRY_ORDER`]. Anything else is
//! refused before a single byte is read out. Path traversal, absolute paths, drive
//! letters and `..` are not *filtered* — they simply cannot appear in a name drawn
//! from a fixed list.

#![forbid(unsafe_code)]

pub mod crc32;
pub mod envelope;
pub mod zip;

pub use crc32::crc32;
pub use envelope::{build_envelope, root_digest, verify_envelope, EnvelopeCheck};
pub use zip::{read_archive, write_archive};

use tt_core::error::{TtError, TtResult};
use tt_core::limits::BundleLimits;

pub const CHALLENGE_JSON: &str = "challenge.json";
pub const CHALLENGE_SIG: &str = "challenge.sig";
pub const REPORT_JSON: &str = "report.json";
pub const ARTIFACT_MANIFEST_JSON: &str = "artifact-manifest.json";
pub const FORENSIC_MARKERS_JSON: &str = "forensic-markers.json";
pub const INTEGRITY_ENVELOPE_JSON: &str = "integrity-envelope.json";
pub const REPORT_PDF: &str = "report.pdf";
pub const VERIFY_TXT: &str = "VERIFY.txt";

/// The only names a `.ttscan` may contain, in the only order they may appear.
///
/// Fixing the order is what makes the container byte-reproducible: two runs over
/// the same payloads produce identical archives, so a differing byte is a real
/// difference rather than an artefact of map iteration order.
pub const ENTRY_ORDER: &[&str] = &[
    CHALLENGE_JSON,
    CHALLENGE_SIG,
    REPORT_JSON,
    ARTIFACT_MANIFEST_JSON,
    FORENSIC_MARKERS_JSON,
    INTEGRITY_ENVELOPE_JSON,
    REPORT_PDF,
    VERIFY_TXT,
];

/// One entry of the bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub name: String,
    pub bytes: Vec<u8>,
}

impl Payload {
    pub fn new(name: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Payload {
        Payload { name: name.into(), bytes: bytes.into() }
    }
    pub fn digest(&self) -> tt_core::hash::Digest {
        tt_core::hash::Digest::of(&self.bytes)
    }
}

/// Reject any name that is not one of the eight known entries.
///
/// The checks below the membership test are redundant while the list stays closed,
/// and they are kept deliberately: if a future version widens the set, the traversal
/// defences must not have to be remembered and re-added.
pub fn validate_entry_name(name: &str, limits: &BundleLimits) -> TtResult<()> {
    if name.is_empty() {
        return Err(TtError::malformed("bundle_entry_name", 0, "empty name"));
    }
    if name.len() > limits.max_name_bytes {
        return Err(TtError::LimitExceeded {
            limit: "bundle_max_name_bytes",
            value: name.len() as u64,
            max: limits.max_name_bytes as u64,
        });
    }
    if !name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-')) {
        return Err(TtError::malformed(
            "bundle_entry_name",
            0,
            "name contains a byte outside [A-Za-z0-9._-]",
        ));
    }
    if name.contains("..") {
        return Err(TtError::malformed("bundle_entry_name", 0, "name contains .."));
    }
    if !ENTRY_ORDER.contains(&name) {
        return Err(TtError::malformed(
            "bundle_entry_name",
            0,
            format!("`{name}` is not a known bundle entry"),
        ));
    }
    Ok(())
}

/// Build the `.ttscan` file name for a case.
pub fn bundle_file_name(case_id: &str, root_digest_hex: &str) -> String {
    let short: String = root_digest_hex.chars().take(12).collect();
    format!("{case_id}-{short}.ttscan")
}

/// Write a bundle atomically, verifying it from disk before it gets its final name.
///
/// The reopen-and-verify step is the point: a bundle that was corrupted between
/// memory and disk must never acquire the `.ttscan` extension, because that
/// extension is what tells a buyer the file is the authoritative artefact.
pub fn write_bundle_atomically(
    dir: &std::path::Path,
    file_stem: &str,
    payloads: &[Payload],
) -> TtResult<std::path::PathBuf> {
    use std::io::Write;

    let archive = write_archive(payloads)?;
    let tmp = dir.join(format!(".{file_stem}.partial"));
    let final_path = dir.join(format!("{file_stem}.ttscan"));

    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&archive)?;
        f.flush()?;
        f.sync_all()?;
    }

    // Reopen from disk and re-verify every payload, not the in-memory copy.
    let from_disk = std::fs::read(&tmp)?;
    let parsed = read_archive(&from_disk, &BundleLimits::default()).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e
    })?;
    for want in payloads {
        let got = parsed.iter().find(|p| p.name == want.name);
        let ok = got.map(|g| g.bytes == want.bytes).unwrap_or(false);
        if !ok {
            let _ = std::fs::remove_file(&tmp);
            return Err(TtError::integrity(format!(
                "payload `{}` did not survive the write to disk",
                want.name
            )));
        }
    }

    std::fs::rename(&tmp, &final_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        TtError::from(e)
    })?;
    Ok(final_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_order_has_no_duplicates() {
        let mut seen = Vec::new();
        for n in ENTRY_ORDER {
            assert!(!seen.contains(n), "duplicate entry {n}");
            seen.push(n);
        }
    }

    #[test]
    fn known_names_are_accepted() {
        let l = BundleLimits::default();
        for n in ENTRY_ORDER {
            validate_entry_name(n, &l).unwrap_or_else(|e| panic!("{n} rejected: {e}"));
        }
    }

    #[test]
    fn traversal_and_unknown_names_are_refused() {
        let l = BundleLimits::default();
        for bad in [
            "",
            "../report.json",
            "/report.json",
            "C:\\report.json",
            "sub/report.json",
            "sub\\report.json",
            "report.json.exe",
            "evil.sh",
            "..",
            "report json",
        ] {
            assert!(validate_entry_name(bad, &l).is_err(), "`{bad}` should be refused");
        }
    }

    #[test]
    fn overlong_name_is_refused() {
        let l = BundleLimits::default();
        let long = "a".repeat(l.max_name_bytes + 1);
        assert!(validate_entry_name(&long, &l).is_err());
    }

    #[test]
    fn bundle_file_name_takes_twelve_digest_characters() {
        let n = bundle_file_name("TT-2026-0F3A9C", &"ab".repeat(32));
        assert_eq!(n, "TT-2026-0F3A9C-abababababab.ttscan");
    }
}
