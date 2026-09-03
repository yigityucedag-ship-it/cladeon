//! Cladeon Screen — the vendor-side portable scanner.
//!
//! Reads only the folders it is pointed at, never executes what it finds, opens no
//! network socket, and writes one `.clade` bundle that the vendor emails back.
//!
//! The `preflight` command exists because the vendor is entitled to see exactly what
//! would leave their machine *before* anything does. A scanner that showed its
//! output only after producing it would be asking for trust it has not earned.

#![forbid(unsafe_code)]

use cl_screen::{scan, seal};

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use cl_core::ids::CaseId;
use cl_core::limits::Limits;
use cl_core::redact::Redactor;
use cl_core::vocab::{
    InferenceAugmentation, ParameterUpdate, TrainingStage, WeightOrigin,
};
use cl_facts::DeclaredFacets;

#[derive(Parser)]
#[command(
    name = "cl-screen",
    about = "Cladeon Screen - scan supplied artifacts and produce a .clade bundle",
    long_about = "Reads only the folders you select. Never executes or deserialises what \
                  it finds. Opens no network connection. Produces one .clade file that \
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
    /// Scan the selected folders and write a .clade bundle.
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
    let opts = cl_inventory::ScanOptions {
        limits: Limits::default(),
        // Preflight never hashes: it is a look, not a read.
        hash_files: false,
        excluded: excluded.to_vec(),
        head_bytes: cl_formats::detect::CLASSIFY_HEAD_BYTES,
    };
    let inv = match cl_inventory::scan(
        roots,
        &mut redactor,
        &opts,
        &|p, h| cl_formats::detect::classify(p, h),
        &|| false,
        &mut |_| {},
    ) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("preflight failed: {e}");
            return ExitCode::from(2);
        }
    };

    println!("Cladeon Screen {} - preflight", cl_core::PRODUCT_VERSION);
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
        .filter(|a| a.artifact_type == cl_facts::ArtifactType::OpaqueSerialization)
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
    let challenge = match challenge_bytes.as_ref().map(|b| cl_case::Challenge::parse(b)) {
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

    let sig = a.challenge_sig.as_ref().and_then(|p| match std::fs::read(p) {
        Ok(b) => Some(b),
        Err(e) => {
            eprintln!("warning: challenge signature not included: {e}");
            None
        }
    });

    let req = scan::ScanRequest {
        roots: a.roots,
        excluded: a.excluded,
        case_id: case_id.clone(),
        vendor_label: vendor,
        exact_claim_text: claim,
        declared: a.facets,
        hash_files: a.hash_files,
        limits: Limits::default(),
        challenge_bytes,
    };

    let sealed = match seal::scan_and_seal(&req, &a.out, &nonce, sig, &|| false, &mut |_| {}) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("scan failed: {e}");
            return ExitCode::from(2);
        }
    };
    let result = &sealed.result;

    println!("Cladeon Screen {}", cl_core::PRODUCT_VERSION);
    println!("case:     {case_id}");
    println!(
        "scanned:  {} files, {} bytes",
        result.inventory.files_enumerated, result.inventory.bytes_enumerated
    );
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
    for f in cl_core::vocab::Facet::ALL {
        if let Some(c) = result.rules.conclusion(*f) {
            println!("  {:<24} {}", f.as_str(), c.band.render());
        }
    }
    println!();
    println!("bundle:   {}", sealed.path.display());
    println!("sha256:   {}", sealed.sha256);
    println!();
    println!("Send that file unchanged. A screenshot, a Word conversion or a re-exported");
    println!("PDF is not the report: report.json inside the bundle is authoritative.");
    ExitCode::SUCCESS
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


}
