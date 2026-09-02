//! TrainTrace Screen — the vendor-side portable scanner.
//!
//! Reads only the folders it is pointed at, never executes what it finds, opens no
//! network socket, and writes one `.ttscan` bundle that the vendor emails back.
//!
//! The `preflight` command exists because the vendor is entitled to see exactly what
//! would leave their machine *before* anything does. A scanner that showed its
//! output only after producing it would be asking for trust it has not earned.

#![forbid(unsafe_code)]

mod scan;

#[cfg(test)]
mod corpus;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use tt_bundle::Payload;
use tt_core::canon::{CanonValue, Obj};
use tt_core::ids::CaseId;
use tt_core::limits::Limits;
use tt_core::redact::Redactor;
use tt_core::vocab::{
    InferenceAugmentation, ParameterUpdate, TrainingStage, WeightOrigin,
};
use tt_facts::DeclaredFacets;

#[derive(Parser)]
#[command(
    name = "tt-screen",
    about = "TrainTrace Screen - scan supplied artifacts and produce a .ttscan bundle",
    long_about = "Reads only the folders you select. Never executes or deserialises what \
                  it finds. Opens no network connection. Produces one .ttscan file that \
                  you send back to whoever asked for it."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show what would be read and what would leave this machine.
    Preflight {
        #[arg(long = "root", required = true)]
        roots: Vec<PathBuf>,
        #[arg(long = "exclude")]
        excluded: Vec<PathBuf>,
    },
    /// Scan the selected folders and write a .ttscan bundle.
    Scan {
        #[arg(long = "root", required = true)]
        roots: Vec<PathBuf>,
        #[arg(long = "exclude")]
        excluded: Vec<PathBuf>,
        /// Directory the bundle is written to.
        #[arg(long)]
        out: PathBuf,
        /// A challenge.json issued by the buyer.
        #[arg(long)]
        challenge: Option<PathBuf>,
        /// Detached signature for the challenge.
        #[arg(long)]
        challenge_sig: Option<PathBuf>,
        /// Case id, when no challenge file is supplied.
        #[arg(long)]
        case_id: Option<String>,
        #[arg(long, default_value = "")]
        vendor: String,
        /// The exact claim being tested, quoted verbatim into the report.
        #[arg(long, default_value = "")]
        claim: String,
        #[arg(long)]
        weight_origin: Option<String>,
        #[arg(long)]
        parameter_update: Option<String>,
        #[arg(long)]
        training_stage: Option<String>,
        #[arg(long = "augmentation")]
        augmentation: Vec<String>,
        /// Record sizes and types without hashing file contents.
        #[arg(long)]
        no_hash: bool,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Preflight { roots, excluded } => preflight(&roots, &excluded),
        Command::Scan {
            roots,
            excluded,
            out,
            challenge,
            challenge_sig,
            case_id,
            vendor,
            claim,
            weight_origin,
            parameter_update,
            training_stage,
            augmentation,
            no_hash,
        } => {
            let facets = match declared_facets(
                weight_origin.as_deref(),
                parameter_update.as_deref(),
                training_stage.as_deref(),
                &augmentation,
            ) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };
            run_scan(RunArgs {
                roots,
                excluded,
                out,
                challenge,
                challenge_sig,
                case_id,
                vendor,
                claim,
                facets,
                hash_files: !no_hash,
            })
        }
    }
}

fn parse_enum<T>(
    value: Option<&str>,
    parse: fn(&str) -> Option<T>,
    all: &[&str],
    what: &str,
) -> Result<Option<T>, String> {
    match value {
        None => Ok(None),
        Some(v) => parse(v).map(Some).ok_or_else(|| {
            format!("`{v}` is not a valid {what}. Expected one of: {}", all.join(", "))
        }),
    }
}

fn declared_facets(
    origin: Option<&str>,
    update: Option<&str>,
    stage: Option<&str>,
    augmentation: &[String],
) -> Result<DeclaredFacets, String> {
    let mut d = DeclaredFacets::default();
    d.weight_origin = parse_enum(
        origin,
        WeightOrigin::parse,
        &WeightOrigin::ALL.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
        "weight origin",
    )?;
    d.parameter_update = parse_enum(
        update,
        ParameterUpdate::parse,
        &ParameterUpdate::ALL.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
        "parameter update",
    )?;
    d.training_stage = parse_enum(
        stage,
        TrainingStage::parse,
        &TrainingStage::ALL.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
        "training stage",
    )?;
    for a in augmentation {
        match InferenceAugmentation::parse(a) {
            Some(v) => d.inference_augmentation.push(v),
            None => {
                return Err(format!(
                    "`{a}` is not a valid inference augmentation. Expected one of: {}",
                    InferenceAugmentation::ALL
                        .iter()
                        .map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            }
        }
    }
    Ok(d)
}

/// Show the vendor what a scan would touch, before it touches anything.
fn preflight(roots: &[PathBuf], excluded: &[PathBuf]) -> ExitCode {
    let mut redactor = Redactor::new();
    let opts = tt_inventory::ScanOptions {
        limits: Limits::default(),
        // Preflight never hashes: it is a look, not a read.
        hash_files: false,
        excluded: excluded.to_vec(),
        head_bytes: tt_formats::detect::CLASSIFY_HEAD_BYTES,
    };
    let inv = match tt_inventory::scan(
        roots,
        &mut redactor,
        &opts,
        &|p, h| tt_formats::detect::classify(p, h),
        &|| false,
        &mut |_| {},
    ) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("preflight failed: {e}");
            return ExitCode::from(2);
        }
    };

    println!("TrainTrace Screen {} - preflight", tt_core::PRODUCT_VERSION);
    println!("No file has been hashed and nothing has been written.\n");
    println!("Selected roots:");
    for (i, r) in roots.iter().enumerate() {
        println!("  ROOT{} = {}", i + 1, r.display());
    }
    if !excluded.is_empty() {
        println!("\nExcluded by you (recorded in the report as excluded, not hidden):");
        for e in excluded {
            println!("  {}", e.display());
        }
    }

    let mut by_type: std::collections::BTreeMap<&str, (u64, u64)> = Default::default();
    for a in &inv.artifacts {
        let e = by_type.entry(a.artifact_type.as_str()).or_insert((0, 0));
        e.0 += 1;
        e.1 = e.1.saturating_add(a.size_bytes);
    }
    println!("\nWhat is in scope:");
    println!("  {:<26} {:>8} {:>14}", "type", "files", "bytes");
    for (t, (n, b)) in &by_type {
        println!("  {t:<26} {n:>8} {b:>14}");
    }
    println!("  {:<26} {:>8} {:>14}", "TOTAL", inv.files_enumerated, inv.bytes_enumerated);

    let opaque = inv
        .artifacts
        .iter()
        .filter(|a| a.artifact_type == tt_facts::ArtifactType::OpaqueSerialization)
        .count();
    if opaque > 0 {
        println!(
            "\n{opaque} file(s) use a format that executes code when loaded. They will be \
             hashed and counted; their contents will never be opened."
        );
    }

    println!("\nWhat leaves this machine:");
    println!("  - file names as scoped aliases (ROOT1/...), never absolute paths");
    println!("  - sizes, types and SHA-256 digests");
    println!("  - metadata fields read from configs and container headers");
    println!("  - the rule outcomes derived from them");
    println!("\nWhat never leaves this machine:");
    println!("  - model weights, datasets, source code and prompts");
    println!("  - credentials: values under key names like api_key, token or password");
    println!("    are replaced before they enter the report");
    println!("  - your Windows user name and any absolute path");

    if !inv.coverage.is_empty() {
        println!("\nThings this scan would not be able to see:");
        for c in inv.coverage.iter().take(20) {
            println!("  [{}] {} - {}", c.rule_id, c.path_alias, c.detail);
        }
        if inv.coverage.len() > 20 {
            println!("  ... and {} more", inv.coverage.len() - 20);
        }
    }
    println!("\nRun the same command with `scan --out <dir>` to produce a bundle.");
    ExitCode::SUCCESS
}

struct RunArgs {
    roots: Vec<PathBuf>,
    excluded: Vec<PathBuf>,
    out: PathBuf,
    challenge: Option<PathBuf>,
    challenge_sig: Option<PathBuf>,
    case_id: Option<String>,
    vendor: String,
    claim: String,
    facets: DeclaredFacets,
    hash_files: bool,
}

fn run_scan(a: RunArgs) -> ExitCode {
    // A challenge, when supplied, is the source of truth for the case identity and
    // the claim. Command-line values only fill in when there is no challenge, so a
    // vendor cannot answer a different question from the one that was asked.
    let challenge_bytes = match &a.challenge {
        Some(p) => match std::fs::read(p) {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("cannot read challenge {}: {e}", p.display());
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let parsed = challenge_bytes.as_ref().map(|b| tt_case::Challenge::parse(b));
    let challenge = match parsed {
        Some(Ok(c)) => Some(c),
        Some(Err(e)) => {
            eprintln!("the challenge could not be read: {e}");
            return ExitCode::from(2);
        }
        None => None,
    };

    let case_id = match (&challenge, &a.case_id) {
        (Some(c), _) => c.case_id.clone(),
        (None, Some(s)) => match CaseId::parse(s) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("--case-id is malformed: {e}");
                return ExitCode::from(2);
            }
        },
        (None, None) => {
            eprintln!("supply either --challenge or --case-id");
            return ExitCode::from(2);
        }
    };
    let vendor = challenge.as_ref().map(|c| c.vendor_label.clone()).unwrap_or(a.vendor);
    let claim = challenge.as_ref().map(|c| c.exact_claim_text.clone()).unwrap_or(a.claim);
    let nonce = challenge.as_ref().map(|c| c.nonce.as_str().to_string()).unwrap_or_default();

    let req = scan::ScanRequest {
        roots: a.roots,
        excluded: a.excluded,
        case_id: case_id.clone(),
        vendor_label: vendor,
        exact_claim_text: claim,
        declared: a.facets,
        hash_files: a.hash_files,
        limits: Limits::default(),
        challenge_bytes: challenge_bytes.clone(),
    };

    let result = match scan::run(&req, &|| false) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("scan failed: {e}");
            return ExitCode::from(2);
        }
    };

    // ---- markers --------------------------------------------------------
    let ed = result.report.evidence_digest;
    let canary = tt_markers::derive_canary(
        &ed,
        case_id.as_str(),
        &nonce,
        tt_markers::canary::DEFAULT_CANARY_DIGITS,
    );
    let tag = tt_markers::tint_tag(&ed, case_id.as_str(), &nonce);
    let carrier = tt_markers::build_carrier(&tag, 240, 40, tt_markers::tint::RECOMMENDED_BASE);
    let markers = markers_document(&canary, &tag, &carrier);

    // ---- render ---------------------------------------------------------
    let pdf = tt_report::render(&result.report, &result.rules, &result.facts, Some(carrier));

    // ---- bundle ---------------------------------------------------------
    let mut payloads: Vec<Payload> = Vec::new();
    if let Some(b) = &challenge_bytes {
        payloads.push(Payload::new(tt_bundle::CHALLENGE_JSON, b.clone()));
    }
    if let Some(p) = &a.challenge_sig {
        match std::fs::read(p) {
            Ok(b) => payloads.push(Payload::new(tt_bundle::CHALLENGE_SIG, b)),
            Err(e) => eprintln!("warning: challenge signature not included: {e}"),
        }
    }
    payloads.push(Payload::new(tt_bundle::REPORT_JSON, result.report.to_canonical_bytes()));
    payloads.push(Payload::new(
        tt_bundle::ARTIFACT_MANIFEST_JSON,
        result.report.artifact_manifest.to_canonical_bytes(),
    ));
    payloads.push(Payload::new(
        tt_bundle::FORENSIC_MARKERS_JSON,
        markers.to_canonical_bytes(),
    ));
    payloads.push(Payload::new(tt_bundle::REPORT_PDF, pdf));
    payloads.push(Payload::new(
        tt_bundle::VERIFY_TXT,
        verify_txt(&case_id).into_bytes(),
    ));

    let envelope = tt_bundle::build_envelope(&payloads);
    let root = tt_bundle::root_digest(&payloads);
    payloads.push(Payload::new(
        tt_bundle::INTEGRITY_ENVELOPE_JSON,
        envelope.to_canonical_bytes(),
    ));

    if let Err(e) = std::fs::create_dir_all(&a.out) {
        eprintln!("cannot create output directory {}: {e}", a.out.display());
        return ExitCode::from(2);
    }
    let stem = tt_bundle::bundle_file_name(case_id.as_str(), &root.to_hex())
        .trim_end_matches(".ttscan")
        .to_string();
    let path = match tt_bundle::write_bundle_atomically(&a.out, &stem, &payloads) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("the bundle could not be written: {e}");
            return ExitCode::from(2);
        }
    };

    let bundle_digest = std::fs::read(&path)
        .map(|b| tt_core::hash::Digest::of(&b).to_hex())
        .unwrap_or_else(|_| "(unreadable)".into());

    // ---- summary --------------------------------------------------------
    println!("TrainTrace Screen {}", tt_core::PRODUCT_VERSION);
    println!("case:     {case_id}");
    println!("scanned:  {} files, {} bytes", result.inventory.files_enumerated, result.inventory.bytes_enumerated);
    println!("coverage: {}", result.inventory.coverage_status);
    if result.redaction_ledger.is_empty() {
        println!("redacted: nothing");
    } else {
        let total: u64 = result.redaction_ledger.iter().map(|e| e.count).sum();
        println!("redacted: {total} value(s) removed before anything left this machine");
        for e in &result.redaction_ledger {
            println!("            {:<28} {}", e.kind, e.count);
        }
    }
    println!();
    for f in tt_core::vocab::Facet::ALL {
        if let Some(c) = result.rules.conclusion(*f) {
            println!("  {:<24} {}", f.as_str(), c.band.render());
        }
    }
    println!();
    println!("bundle:   {}", path.display());
    println!("sha256:   {bundle_digest}");
    println!();
    println!("Send that file unchanged. A screenshot, a Word conversion or a re-exported");
    println!("PDF is not the report: report.json inside the bundle is authoritative.");
    ExitCode::SUCCESS
}

fn markers_document(
    canary: &tt_markers::Canary,
    tag: &[u8; 16],
    carrier: &tt_core::raster::Raster,
) -> CanonValue {
    let digits: String = canary.digits.iter().map(|d| char::from(b'0' + d.min(&9))).collect();
    CanonValue::Obj(
        Obj::new()
            .with("schema_version", tt_core::SCHEMA_VERSION)
            .with("marker_version", tt_core::MARKER_VERSION)
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
                        .with("expected_tag", tt_core::hex::encode(tag))
                        .with("expected_carrier_sha256", carrier.digest())
                        .with("ecc", "repetition_x7_majority")
                        .with("detector", "normalised_correlation")
                        .with(
                            "detector_threshold_percent",
                            tt_markers::DETECTOR_THRESHOLD_PERCENT,
                        ),
                ),
            ),
    )
}

fn verify_txt(case: &CaseId) -> String {
    format!(
        "TrainTrace evidence bundle\n\
         case: {case}\n\
         \n\
         report.json is the authoritative document. report.pdf is a rendering of it.\n\
         A screenshot, a Word conversion or a re-exported PDF is not this report.\n\
         \n\
         To check this bundle:\n\
         \n\
             tt-verify check <this file>\n\
         \n\
         The verifier reports file integrity, challenge binding, marker status,\n\
         coverage and evidence strength separately. A bundle can be intact and still\n\
         inconclusive; those are different statements and it will make both.\n\
         \n\
         {}\n",
        tt_core::REQUIRED_STATEMENT
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facet_flags_parse_and_reject_clearly() {
        let ok = declared_facets(
            Some("derivative_of_disclosed_base"),
            Some("unmerged_peft_observed"),
            Some("supervised_instruction_tuning"),
            &["rag".to_string(), "external_api_router".to_string()],
        )
        .unwrap();
        assert_eq!(ok.weight_origin, Some(WeightOrigin::DerivativeOfDisclosedBase));
        assert_eq!(ok.inference_augmentation.len(), 2);

        let err = declared_facets(Some("nonsense"), None, None, &[]).unwrap_err();
        assert!(err.contains("nonsense"), "{err}");
        assert!(err.contains("derivative_of_disclosed_base"), "the error must list the options");
    }

    #[test]
    fn no_facets_declared_is_valid() {
        let d = declared_facets(None, None, None, &[]).unwrap();
        assert!(d.weight_origin.is_none());
        assert!(d.inference_augmentation.is_empty());
    }

    #[test]
    fn verify_txt_names_the_authoritative_document_and_carries_the_statement() {
        let t = verify_txt(&CaseId::parse("TT-2026-0F3A9C").unwrap());
        assert!(t.contains("report.json is the authoritative document"));
        assert!(t.contains("TT-2026-0F3A9C"));
        assert!(t.contains("does not establish intent"));
        assert!(t.is_ascii(), "VERIFY.txt must be plain ASCII with no active content");
    }

    #[test]
    fn the_markers_document_records_what_a_verifier_needs() {
        let ed = tt_core::hash::Digest::of(b"evidence");
        let canary = tt_markers::derive_canary(&ed, "TT-2026-0F3A9C", "abcd", 6);
        let tag = tt_markers::tint_tag(&ed, "TT-2026-0F3A9C", "abcd");
        let carrier =
            tt_markers::build_carrier(&tag, 240, 40, tt_markers::tint::RECOMMENDED_BASE);
        let doc = markers_document(&canary, &tag, &carrier);
        assert_eq!(
            doc.get("tint_marker").and_then(|t| t.get("expected_tag")).and_then(|t| t.as_str()),
            Some(tt_core::hex::encode(&tag).as_str())
        );
        // The note must say plainly that the digits are not analytical, so the
        // report cannot be read as claiming false precision.
        let note = doc
            .get("numeric_canary")
            .and_then(|c| c.get("note"))
            .and_then(|n| n.as_str())
            .unwrap();
        assert!(note.contains("never affect"));
    }
}
