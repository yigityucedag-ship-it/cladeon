//! Turning a completed scan into a sealed `.clade` bundle.
//!
//! This lives in the library rather than in a CLI's `main` because two very
//! different front ends need identical behaviour: the command line, and the
//! double-clickable window a vendor is actually going to use. If the sealing logic
//! sat in one of them, the other would grow a second copy, and the two would drift
//! in exactly the place where drift is least acceptable — what goes into the
//! evidence bundle.

use crate::scan::{self, ScanRequest, ScanResult};
use cl_bundle::Payload;
use cl_core::canon::{CanonValue, Obj};
use cl_core::error::{ClError, ClResult};
use cl_core::hash::Digest;
use cl_core::ids::CaseId;
use std::path::{Path, PathBuf};

/// A bundle that has been written to disk and verified from disk.
pub struct SealedBundle {
    pub path: PathBuf,
    /// SHA-256 of the finished file, for the vendor to quote in their e-mail.
    pub sha256: String,
    pub result: ScanResult,
}

/// Scan the selected roots and seal the result.
///
/// `nonce` comes from the buyer's challenge when there is one. Without it the
/// markers are derived from the case id alone, which is weaker and is why an
/// unchallenged scan reports `challenge_status = absent` rather than pretending.
#[allow(clippy::too_many_arguments)]
pub fn scan_and_seal(
    req: &ScanRequest,
    out_dir: &Path,
    nonce: &str,
    challenge_sig: Option<Vec<u8>>,
    cancel: &dyn Fn() -> bool,
    progress: &mut dyn FnMut(scan::Progress),
) -> ClResult<SealedBundle> {
    let result = scan::run(req, cancel, progress)?;
    let case_id = req.case_id.clone();

    // ---- markers ----
    let ed = result.report.evidence_digest;
    let canary = cl_markers::derive_canary(
        &ed,
        case_id.as_str(),
        nonce,
        cl_markers::canary::DEFAULT_CANARY_DIGITS,
    );
    let tag = cl_markers::tint_tag(&ed, case_id.as_str(), nonce);
    let carrier = cl_markers::build_carrier(&tag, 240, 40, cl_markers::tint::RECOMMENDED_BASE);
    let markers = markers_document(&canary, &tag, &carrier);

    // ---- render ----
    let pdf = cl_report::render(&result.report, &result.rules, &result.facts, Some(carrier));

    // ---- assemble ----
    let mut payloads: Vec<Payload> = Vec::new();
    if let Some(b) = &req.challenge_bytes {
        payloads.push(Payload::new(cl_bundle::CHALLENGE_JSON, b.clone()));
    }
    if let Some(sig) = challenge_sig {
        payloads.push(Payload::new(cl_bundle::CHALLENGE_SIG, sig));
    }
    payloads.push(Payload::new(cl_bundle::REPORT_JSON, result.report.to_canonical_bytes()));
    payloads.push(Payload::new(
        cl_bundle::ARTIFACT_MANIFEST_JSON,
        result.report.artifact_manifest.to_canonical_bytes(),
    ));
    payloads.push(Payload::new(cl_bundle::FORENSIC_MARKERS_JSON, markers.to_canonical_bytes()));
    payloads.push(Payload::new(cl_bundle::REPORT_PDF, pdf));
    payloads.push(Payload::new(cl_bundle::VERIFY_TXT, verify_txt(&case_id).into_bytes()));

    let envelope = cl_bundle::build_envelope(&payloads);
    let root = cl_bundle::root_digest(&payloads);
    payloads.push(Payload::new(cl_bundle::INTEGRITY_ENVELOPE_JSON, envelope.to_canonical_bytes()));

    std::fs::create_dir_all(out_dir)?;
    let stem = cl_bundle::bundle_file_name(case_id.as_str(), &root.to_hex())
        .trim_end_matches(".clade")
        .to_string();
    let path = cl_bundle::write_bundle_atomically(out_dir, &stem, &payloads)?;
    let sha256 = std::fs::read(&path)
        .map(|b| Digest::of(&b).to_hex())
        .map_err(|e| ClError::io(format!("the bundle could not be re-read: {e:?}")))?;

    Ok(SealedBundle { path, sha256, result })
}

pub fn markers_document(
    canary: &cl_markers::Canary,
    tag: &[u8; 16],
    carrier: &cl_core::raster::Raster,
) -> CanonValue {
    let digits: String = canary.digits.iter().map(|d| char::from(b'0' + d.min(&9))).collect();
    CanonValue::Obj(
        Obj::new()
            .with("schema_version", cl_core::SCHEMA_VERSION)
            .with("marker_version", cl_core::MARKER_VERSION)
            .with(
                "numeric_canary",
                CanonValue::Obj(
                    Obj::new()
                        .with("expected_digit_sequence", digits)
                        .with("derivation", canary.derivation)
                        .with(
                            "note",
                            "Non-analytical rendering-integrity digits. They never affect \
                             a threshold or a conclusion.",
                        ),
                ),
            )
            .with(
                "tint_marker",
                CanonValue::Obj(
                    Obj::new()
                        .with("carrier", "footer_raster")
                        .with("carrier_pages", "all")
                        .with("carrier_width", carrier.width)
                        .with("carrier_height", carrier.height)
                        .with("expected_tag", cl_core::hex::encode(tag))
                        .with("expected_carrier_sha256", carrier.digest())
                        .with("ecc", "repetition_x7_majority")
                        .with("detector", "normalised_correlation")
                        .with("detector_threshold_percent", cl_markers::DETECTOR_THRESHOLD_PERCENT),
                ),
            ),
    )
}

pub fn verify_txt(case: &CaseId) -> String {
    format!(
        "Cladeon evidence bundle\n\
         case: {case}\n\
         \n\
         report.json is the authoritative document. report.pdf is a rendering of it.\n\
         A screenshot, a Word conversion or a re-exported PDF is not this report.\n\
         \n\
         To check this bundle:\n\
         \n\
             cladeon-verify check <this file>\n\
         \n\
         or open it with the Cladeon desktop application.\n\
         \n\
         The verifier reports file integrity, challenge binding, marker status,\n\
         coverage and evidence strength separately. A bundle can be intact and still\n\
         inconclusive; those are different statements and it will make both.\n\
         \n\
         {}\n",
        cl_core::REQUIRED_STATEMENT
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_txt_names_the_authoritative_document_and_carries_the_statement() {
        let t = verify_txt(&CaseId::parse("CL-2026-0F3A9C").unwrap());
        assert!(t.contains("report.json is the authoritative document"));
        assert!(t.contains("CL-2026-0F3A9C"));
        assert!(t.contains("does not establish intent"));
        assert!(t.is_ascii(), "VERIFY.txt must be plain ASCII with no active content");
    }

    #[test]
    fn the_markers_document_records_what_a_verifier_needs() {
        let ed = Digest::of(b"evidence");
        let canary = cl_markers::derive_canary(&ed, "CL-2026-0F3A9C", "abcd", 6);
        let tag = cl_markers::tint_tag(&ed, "CL-2026-0F3A9C", "abcd");
        let carrier = cl_markers::build_carrier(&tag, 240, 40, cl_markers::tint::RECOMMENDED_BASE);
        let doc = markers_document(&canary, &tag, &carrier);
        assert_eq!(
            doc.get("tint_marker").and_then(|t| t.get("expected_tag")).and_then(|t| t.as_str()),
            Some(cl_core::hex::encode(&tag).as_str())
        );
        let note = doc
            .get("numeric_canary")
            .and_then(|c| c.get("note"))
            .and_then(|n| n.as_str())
            .unwrap();
        assert!(note.contains("never affect"));
    }
}
