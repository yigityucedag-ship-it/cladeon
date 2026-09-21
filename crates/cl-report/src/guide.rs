//! The printed instructions that travel with the software.
//!
//! This is rendered with the same PDF writer as the report itself rather than being a
//! hand-made file dropped into the folder, for one reason: a PDF nobody can regenerate
//! goes stale the first time a screen changes, and stale instructions are worse than
//! none. It is a function, so it moves when the product moves.
//!
//! It is written for someone who has never audited anything, has been handed a zip
//! file, and wants to know what to double-click.

use crate::pdf::PdfBuilder;

/// The name the guide is saved under.
pub const GUIDE_FILE_NAME: &str = "How to use Cladeon.pdf";

/// Render the instruction booklet.
///
/// Deterministic: the same build produces the same bytes, so a copy sitting in a
/// distributed folder can be checked against a fresh render.
pub fn render() -> Vec<u8> {
    let mut b = PdfBuilder::new(
        "Cladeon - how to use it",
        "Cladeon checks whether a supplier's files fit what they told you.",
    );

    // ---- what it is ---------------------------------------------------------
    b.heading(1, "What this is for");
    b.paragraph(
        "Someone tells you they built their own AI. You would like to know whether that \
         is what the files actually show. Cladeon asks them for a small amount of \
         evidence, checks it, and gives you a report you can keep.",
    );
    b.paragraph(
        "It never sees their model, their data or their code. It reads file names, \
         sizes, checksums and settings from configuration files. Nothing else leaves \
         their machine.",
    );

    b.heading(2, "The two programs");
    b.paragraph(
        "Cladeon.exe is yours. It opens a case and reads the file that comes back. It is \
         the only thing in this folder you need to double-click.",
    );
    b.paragraph(
        "cladeon-screen.exe, in the Scanner folder, is theirs. You never run it. Cladeon \
         puts a copy of it into the folder you send them.",
    );

    b.rule();

    // ---- the warning they will hit before anything else ---------------------
    //
    // This section exists because the first thing a new user sees is a full-screen
    // blue warning, and a manual that does not mention it reads as either careless
    // or evasive. Saying it plainly, and giving them a way to check the file
    // themselves, is worth more than pretending the warning is not there.
    b.heading(1, "Before you run it: the Windows warning");
    b.paragraph(
        "Windows will show a blue box saying \"Windows protected your PC\" the first time \
         you open Cladeon. Choose \"More info\", then \"Run anyway\".",
    );
    b.paragraph(
        "This is not a virus warning and nothing has been detected. Windows shows it for \
         any program that has not been signed with a paid certificate, which this one has \
         not. It is free software given away rather than sold, and a certificate costs \
         money every year.",
    );
    b.paragraph(
        "You do not have to take that on trust. The folder holds a file called \
         Checksums.txt with a fingerprint of each program. If someone tampered with a copy \
         on its way to you, the fingerprint would not match. To check one, open PowerShell \
         and run:",
    );
    b.paragraph(r"    Get-FileHash .\Cladeon.exe");

    b.rule();

    // ---- the walkthrough ----------------------------------------------------
    b.heading(1, "Doing a check, start to finish");

    b.heading(2, "1. Open a case");
    b.bullet("Double-click Cladeon.exe.");
    b.bullet("Choose \"Start a new check\".");
    b.bullet("Answer the one question: what are they saying they built?");
    b.bullet("Choose how long they have to reply.");
    b.bullet("Press \"Create the folder to send\" and pick somewhere to put it.");
    b.paragraph(
        "You get a folder named after the case, for example CL-2026-0F3A9C. It holds the \
         request, its signature, the scanner, and a plain-text page of instructions for \
         them.",
    );

    b.heading(2, "2. Send it");
    b.bullet("Right-click the folder, choose Send to, then Compressed (zipped) folder.");
    b.bullet("Attach the zip to an e-mail and ask them to keep the files together.");
    b.paragraph(
        "They do not need Cladeon, an account, an internet connection or an \
         administrator. They open one program and follow five screens.",
    );

    b.heading(2, "3. Read what comes back");
    b.bullet("They reply with one file ending in .clade");
    b.bullet("Save it somewhere you can find it.");
    b.bullet("Open Cladeon.exe and choose \"Open a file a vendor sent back\".");

    b.page_break();

    // ---- reading the result -------------------------------------------------
    b.heading(1, "Reading the report");
    b.paragraph(
        "There is no single score, and that is deliberate. A file can be perfectly intact \
         and still not tell you much. Five separate questions are answered, and a good \
         answer to one is never allowed to speak for the others.",
    );
    b.table(
        &["The question", "What it tells you"],
        &[
            vec![
                "Has the file been altered?".to_string(),
                "Whether anything was edited after they made it.".to_string(),
            ],
            vec![
                "Does it answer your request?".to_string(),
                "Whether it is tied to the case you opened, not another one.".to_string(),
            ],
            vec![
                "Is the report as printed?".to_string(),
                "Whether the PDF was rebuilt or re-exported.".to_string(),
            ],
            vec![
                "How much did they show?".to_string(),
                "Whether parts were left out. Leaving things out is allowed.".to_string(),
            ],
            vec![
                "Do the files fit the claim?".to_string(),
                "The actual finding. See below.".to_string(),
            ],
        ],
    );

    b.heading(2, "What the last line can say");
    b.key_value("Corroborated", "Several separate things agree with the claim.");
    b.key_value("Strongly consistent", "The evidence fits the claim well.");
    b.key_value("Weakly consistent", "It fits, but there is not much of it.");
    b.key_value("Partially supported", "Real support, but not enough to name the method.");
    b.key_value("Not enough evidence", "The files that would answer it were not sent.");
    b.key_value("Contradicted", "A file that was examined does not fit the claim.");

    b.heading(2, "Two things worth knowing");
    b.paragraph(
        "\"Not enough evidence\" is the most common answer, and it is a real answer rather \
         than a failure. Cladeon abstains instead of guessing, and something left out \
         never counts against anyone.",
    );
    b.paragraph(
        "\"Contradicted\" means the files disagree with the claim, within what was shown. \
         It is a reason to ask a follow-up question. It is not a statement about anyone's \
         honesty, and Cladeon does not make one.",
    );

    b.rule();

    // ---- the questions everyone asks ---------------------------------------
    b.heading(1, "Questions people ask");
    b.key_value("Does it upload anything?", "No. Neither program opens a network connection.");
    b.key_value(
        "Will it slow their machine down?",
        "It reads file headers and checksums. A model folder takes minutes. A folder with \
         hundreds of thousands of small files takes much longer, because Windows checks \
         each file as it is opened.",
    );
    b.key_value(
        "What if they will not show something?",
        "They can exclude it. The report records that a folder was excluded, never what \
         was in it.",
    );
    b.key_value(
        "Can they edit the report?",
        "They can edit the file, but the checks stop matching and Cladeon says so.",
    );
    b.key_value("Is a screenshot enough?", "No. Send the .clade file itself, unchanged.");
    b.key_value(
        "Does it settle whether they trained a model?",
        "No, and it does not claim to. Read the line at the foot of every report.",
    );

    b.paragraph("");
    b.paragraph(cl_core::REQUIRED_STATEMENT);

    b.build(&cl_core::hash::Digest::of(
        format!("cladeon-guide-{}", cl_core::PRODUCT_VERSION).as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The extracted text with every run of whitespace collapsed to one space.
    ///
    /// The renderer wraps lines, so a sentence that reads as one phrase on the page
    /// arrives here split by a newline. Without this, these assertions would silently
    /// depend on where the wrap happens to fall.
    fn text() -> String {
        let raw = crate::pdf::extract_text(&render()).expect("the guide must be readable");
        raw.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn the_guide_renders_and_reads_back() {
        let t = text();
        assert!(t.contains("What this is for"));
        assert!(t.contains("Not enough evidence"));
        assert!(t.contains("Reading the report"));
    }

    #[test]
    fn the_guide_says_which_program_the_buyer_runs() {
        // The single question someone opening the zip actually has.
        let t = text();
        assert!(t.contains("only thing in this folder you need to double-click"));
        assert!(t.contains("You never run it"), "the scanner is not the buyer's to run");
    }

    #[test]
    fn the_guide_carries_the_required_statement() {
        assert!(text().contains("does not establish intent"));
    }

    #[test]
    fn the_guide_uses_no_forbidden_language() {
        assert_eq!(cl_core::vocab::forbidden_language(&text()), None);
    }

    #[test]
    fn the_guide_is_deterministic() {
        // A copy shipped in a folder has to be checkable against a fresh render.
        assert_eq!(render(), render());
    }

    #[test]
    fn the_guide_does_not_promise_a_verdict() {
        // An instruction booklet is exactly where over-claiming creeps in: nobody
        // reviews the manual as carefully as they review the report.
        let t = text().to_lowercase();
        for bad in ["proves that", "detects fake", "tells you if they", "will show you whether they"]
        {
            assert!(!t.contains(bad), "the guide over-claims: `{bad}`");
        }
    }

    #[test]
    fn the_guide_explains_the_windows_warning_without_dismissing_it() {
        // A manual that stays silent about a full-screen security warning reads as
        // careless or evasive, and it is the first thing a new user meets.
        let t = text();
        assert!(t.contains("Windows protected your PC"), "the warning is not quoted");
        assert!(t.contains("Run anyway"), "the way past it is not given");
        assert!(t.contains("has not been signed"), "the reason is not stated");
        assert!(t.contains("Checksums.txt"), "no way to check the file independently");
        // It must not tell the reader the warning is meaningless or safe to ignore.
        let lower = t.to_lowercase();
        for bad in ["ignore this", "perfectly safe", "false positive", "harmless warning"] {
            assert!(!lower.contains(bad), "the guide waves away a security warning: `{bad}`");
        }
    }

    #[test]
    fn the_guide_names_itself_as_a_pdf() {
        assert!(GUIDE_FILE_NAME.ends_with(".pdf"));
    }
}
