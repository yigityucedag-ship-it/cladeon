//! TrainTrace Verify — the buyer-side verifier.
//!
//! Reads a `.ttscan`, treats it as hostile, and reports five independent statuses
//! without collapsing them into a verdict. See [`verify`] for why that matters.

#![forbid(unsafe_code)]

mod verify;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use tt_core::ids::CaseId;
use tt_core::time::Timestamp;
use tt_core::vocab::{ChallengeStatus, IntegrityStatus};
use verify::Recomputation;

#[derive(Parser)]
#[command(
    name = "tt-verify",
    about = "TrainTrace Verify - check a .ttscan evidence bundle",
    long_about = "Reports file integrity, challenge binding, marker status, coverage and \
                  evidence strength as five separate answers. An intact bundle whose \
                  evidence is thin is both intact and inconclusive; neither cancels the \
                  other."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a bundle and print a report.
    Check {
        /// Path to the .ttscan file.
        bundle: PathBuf,
        /// Case id this bundle is expected to answer.
        #[arg(long)]
        case_id: Option<String>,
        /// Emit canonical JSON instead of text.
        #[arg(long)]
        json: bool,
        /// Verify as at this RFC 3339 UTC instant instead of now, for reproducibility.
        #[arg(long)]
        as_of: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Check { bundle, case_id, json, as_of } => {
            let bytes = match std::fs::read(&bundle) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("cannot read {}: {}", bundle.display(), e);
                    return ExitCode::from(2);
                }
            };
            let now = match as_of {
                Some(s) => match Timestamp::parse_rfc3339(&s) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("--as-of is not an RFC 3339 UTC instant: {e}");
                        return ExitCode::from(2);
                    }
                },
                None => Timestamp::now(),
            };
            let expected = match case_id.as_deref().map(CaseId::parse) {
                Some(Ok(c)) => Some(c),
                Some(Err(e)) => {
                    eprintln!("--case-id is malformed: {e}");
                    return ExitCode::from(2);
                }
                None => None,
            };

            let v = verify::verify_bundle(&bytes, now, expected.as_ref());

            if json {
                println!("{}", v.to_canon().to_pretty_string());
            } else {
                print_text(&v, &bundle);
            }

            // Exit codes are for scripts: 0 clear, 1 something needs a human.
            if v.all_clear() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
    }
}

fn print_text(v: &verify::Verification, path: &std::path::Path) {
    println!("TrainTrace Verify {}", tt_core::PRODUCT_VERSION);
    println!("bundle: {}", path.display());
    if let Some(c) = &v.case_id {
        println!("case:   {c}");
    }
    if let Some(l) = &v.vendor_label {
        println!("vendor: {l}");
    }
    if let Some(c) = &v.exact_claim_text {
        println!("claim:  {c}");
    }
    println!();
    println!("  integrity   {}", v.integrity);
    println!("  challenge   {}", v.challenge);
    println!("  markers     {}", v.marker);
    println!("  coverage    {}", v.coverage);
    println!("  evidence    {}  ({})", v.evidence, v.evidence.render());
    println!(
        "  recomputed  {}",
        match &v.recomputation {
            Recomputation::Matches => "matches the report's own observations".to_string(),
            Recomputation::Diverges { .. } => "DIVERGES from the report's own observations".into(),
            Recomputation::NotPossible { .. } => "not possible".into(),
        }
    );

    if !v.facet_bands.is_empty() {
        println!("\nper facet:");
        for (f, b) in &v.facet_bands {
            println!("  {f:<24} {b}");
        }
    }

    if !v.findings.is_empty() {
        println!("\nnotes:");
        for f in &v.findings {
            println!("  - {f}");
        }
    }

    println!("\nThis is a Stage-1 vendor self-scan. {}", tt_core::REQUIRED_STATEMENT);

    if v.integrity != IntegrityStatus::Intact
        || matches!(v.recomputation, Recomputation::Diverges { .. })
    {
        println!("\nThe bundle does not verify. Treat report.json, not the PDF, as the");
        println!("authoritative document, and ask the vendor to re-run the scanner.");
    } else if v.challenge == ChallengeStatus::Unsigned {
        println!("\nThe bundle verifies against itself. It is not bound to a signed challenge.");
    }
}
