//! Building the folder a buyer sends to a vendor.
//!
//! The vendor's whole experience is decided here. They receive one folder, open it,
//! and double-click one thing. If they have to find a file, read an argument, or
//! understand what a "challenge" is, the audit stalls on the least motivated person
//! in the chain — so the kit is assembled to make that impossible:
//!
//! * the scanner sits at the top level, named so it is obvious what to run;
//! * the case file sits beside it, where the scanner finds it without being told;
//! * the instructions are plain text, short, and say what the program will not do
//!   before they say what it will.
//!
//! The issuer's **private key never enters the kit**. Only the public half travels,
//! inside the signed challenge, which is what makes a returned bundle checkable at
//! all — and what would be destroyed by shipping the secret alongside it.

use cl_core::error::{ClError, ClResult};
use std::path::{Path, PathBuf};

/// Where the scanner executable is expected to live, relative to this program.
///
/// The buyer downloads one archive containing both applications, so the scanner is
/// normally a sibling. Returning the path rather than embedding the binary keeps
/// this program small and lets the pair be updated independently.
pub fn scanner_beside_us() -> Option<PathBuf> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    for name in ["cladeon-screen.exe", "cladeon-screen"] {
        let p = dir.join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

pub struct Kit {
    pub dir: PathBuf,
    pub scanner_included: bool,
}

/// Write the vendor kit into `parent/<case-id>/`.
pub fn build(
    parent: &Path,
    challenge: &cl_case::Challenge,
    challenge_bytes: &[u8],
    signature: Option<&str>,
) -> ClResult<Kit> {
    let dir = parent.join(challenge.case_id.as_str());
    std::fs::create_dir_all(&dir)?;

    std::fs::write(dir.join("challenge.json"), challenge_bytes)?;
    if let Some(sig) = signature {
        std::fs::write(dir.join("challenge.sig"), sig.as_bytes())?;
    }

    let scanner_included = match scanner_beside_us() {
        Some(src) => {
            let name = src.file_name().map(|n| n.to_owned()).ok_or_else(|| {
                ClError::io("the scanner executable has no file name".to_string())
            })?;
            std::fs::copy(&src, dir.join(name))?;
            true
        }
        None => false,
    };

    std::fs::write(dir.join("READ ME FIRST.txt"), instructions(challenge, scanner_included))?;
    Ok(Kit { dir, scanner_included })
}

/// The one page the vendor reads.
///
/// Deliberately plain ASCII with no formatting: it has to survive being pasted into
/// an e-mail body, opened in Notepad, or printed. It leads with what the program
/// will not do, because that is the vendor's actual first question.
pub fn instructions(challenge: &cl_case::Challenge, scanner_included: bool) -> String {
    // The buyer is no longer asked to type the supplier's name, so the opening line
    // addresses the reader directly when there is none to use.
    let opening = if challenge.vendor_label.trim().is_empty() {
        "You have been asked to show how one of your AI systems was built.".to_string()
    } else {
        format!(
            "{} has been asked to show how one of its AI systems was built.",
            challenge.vendor_label
        )
    };
    let run_line = if scanner_included {
        "2. Double-click  cladeon-screen.exe  in this folder."
    } else {
        "2. Double-click the Cladeon Screen program you were sent."
    };
    format!(
        "WHAT THIS IS\n\
         ============\n\
         \n\
         {opening}\n\
         This folder contains a small program that looks at folders you choose and\n\
         writes a single summary file. You send that file back. Nothing is uploaded.\n\
         \n\
         The statement being checked:\n\
         \n\
             \"{claim}\"\n\
         \n\
         Case reference: {case}\n\
         Please reply by:  {expires}\n\
         \n\
         \n\
         WHAT THE PROGRAM WILL NOT DO\n\
         ============================\n\
         \n\
         - It does not connect to the internet. Nothing is uploaded, ever.\n\
         - It does not open, load or run your model files.\n\
         - It does not copy your model weights, training data, source code or prompts.\n\
         - It does not need an administrator, and it installs nothing.\n\
         - It removes passwords, API keys and your Windows user name automatically,\n\
           and shows you a list of everything removed.\n\
         \n\
         Before it reads anything, it shows you exactly what would be sent. You can\n\
         stop at that point.\n\
         \n\
         \n\
         WHAT TO DO\n\
         ==========\n\
         \n\
         1. Keep everything in this folder together.\n\
         {run_line}\n\
         3. Follow the six steps on screen. Choose the folders holding the model and\n\
            its training records.\n\
         4. It saves one file ending in .clade\n\
         5. Reply to the e-mail and attach that file, unchanged.\n\
         \n\
         Do not rename it, do not open and re-save it, and do not send a screenshot\n\
         or a printout instead. The file carries checks that those would break.\n\
         \n\
         \n\
         IF YOU CANNOT SHOW SOMETHING\n\
         ============================\n\
         \n\
         Leave it out. The program lets you exclude folders, and records only that\n\
         something was excluded, never what was in it. A report that says \"not enough\n\
         evidence\" is a normal result and is not treated as a finding against you.\n\
         \n\
         \n\
         {statement}\n",
        opening = opening,
        claim = challenge.exact_claim_text,
        case = challenge.case_id,
        expires = challenge.expires_at.to_rfc3339(),
        run_line = run_line,
        statement = cl_core::REQUIRED_STATEMENT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl_core::ids::{CaseId, Nonce};
    use cl_core::time::Timestamp;

    fn sample() -> cl_case::Challenge {
        cl_case::Challenge::new(
            CaseId::parse("CL-2026-0F3A9C").unwrap(),
            Nonce::parse(&"a1".repeat(16)).unwrap(),
            "Acme Analytics Ltd",
            "We trained our own large language model from scratch.",
            Timestamp::parse_rfc3339("2026-09-02T13:00:00Z").unwrap(),
            14,
            vec!["adapter_config".into()],
            None,
            Some(cl_core::vocab::WeightOrigin::RandomInitializationClaimed),
        )
    }

    #[test]
    fn instructions_lead_with_what_the_program_will_not_do() {
        let t = instructions(&sample(), true);
        let will_not = t.find("WILL NOT DO").expect("section present");
        let what_to_do = t.find("WHAT TO DO").expect("section present");
        assert!(will_not < what_to_do, "reassurance must come before instruction");
    }

    #[test]
    fn instructions_are_plain_ascii() {
        // They have to survive being pasted into an e-mail or opened in Notepad.
        let t = instructions(&sample(), true);
        assert!(t.is_ascii(), "instructions must be plain ASCII");
    }

    #[test]
    fn instructions_quote_the_claim_and_the_deadline() {
        let t = instructions(&sample(), true);
        assert!(t.contains("We trained our own large language model from scratch."));
        assert!(t.contains("CL-2026-0F3A9C"));
        assert!(t.contains("2026-09-16"), "the reply-by date must be visible");
    }

    #[test]
    fn instructions_say_that_withholding_is_allowed() {
        // A vendor who feels cornered will not run it at all.
        let t = instructions(&sample(), true);
        assert!(t.contains("CANNOT SHOW SOMETHING"));
        assert!(t.contains("not treated as a finding against you"));
    }

    #[test]
    fn instructions_adapt_when_the_scanner_is_not_bundled() {
        let with = instructions(&sample(), true);
        let without = instructions(&sample(), false);
        assert!(with.contains("cladeon-screen.exe"));
        // "Keep everything in this folder together" appears either way, so assert on
        // the executable name rather than on a phrase both versions share.
        assert!(!without.contains("cladeon-screen.exe"));
        assert!(without.contains("the Cladeon Screen program you were sent"));
    }

    #[test]
    fn instructions_carry_the_required_statement() {
        assert!(instructions(&sample(), true).contains("does not establish intent"));
    }

    #[test]
    fn instructions_use_no_forbidden_language() {
        assert_eq!(
            cl_core::vocab::forbidden_language(&instructions(&sample(), true)),
            None
        );
    }
}
