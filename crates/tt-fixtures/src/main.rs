//! Generate the golden fixture corpus.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "tt-fixtures", about = "Generate the TrainTrace golden fixture corpus")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List every case with its kind and what it tests.
    List,
    /// Write cases into a directory.
    Generate {
        #[arg(long, default_value = "fixtures/generated")]
        out: PathBuf,
        /// Generate one case instead of all of them.
        #[arg(long)]
        case: Option<String>,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::List => {
            for c in tt_fixtures::cases() {
                println!("{:<36} {:<14} {}", c.name, c.kind.as_str(), c.claim);
                if !c.expect.must_not_name.is_empty() {
                    let f: Vec<&str> =
                        c.expect.must_not_name.iter().map(|x| x.as_str()).collect();
                    println!("{:<36} {:<14} must abstain on: {}", "", "", f.join(", "));
                }
            }
            println!("\n{} cases", tt_fixtures::cases().len());
            ExitCode::SUCCESS
        }
        Command::Generate { out, case } => {
            let r = match case {
                Some(name) => match tt_fixtures::case(&name) {
                    Some(c) => tt_fixtures::generate(c, &out).map(|_| ()),
                    None => {
                        eprintln!("no case named `{name}`. Run `tt-fixtures list`.");
                        return ExitCode::from(2);
                    }
                },
                None => tt_fixtures::generate_all(&out),
            };
            match r {
                Ok(()) => {
                    println!("wrote fixtures to {}", out.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("could not write fixtures: {e}");
                    ExitCode::from(2)
                }
            }
        }
    }
}
