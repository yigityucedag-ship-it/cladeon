//! The "How to use this" screen.
//!
//! It was a button that saved a PDF, which asked the user to leave the application,
//! find a file, and open a second program before they could read a page of
//! instructions. Someone who is unsure enough to press "How to use this" is the last
//! person who should be handed a file-save dialog. It is a screen now.
//!
//! The printed guide still exists and still ships in the folder, for anyone who
//! wants it on paper. Nothing here duplicates it by hand: this screen is the same
//! material, written for a screen, and both are checked against the same promises.

use eframe::egui;

/// Draw the help page. Returns true if the user asked to go back.
pub fn draw(ui: &mut egui::Ui) -> bool {
    cl_ui::h1(ui, "How to use Cladeon");
    ui.add_space(6.0);
    cl_ui::body(
        ui,
        "Someone tells you they built their own AI. You would like to know whether that is what their files actually show.",
    );

    ui.add_space(18.0);
    cl_ui::h2(ui, "1.  Open a case");
    cl_ui::body(ui, "Press \"Start a new check\" and answer the one question: what are they saying they built?");
    cl_ui::body(ui, "Cladeon makes a folder named after the case. It holds the request and the small program they run.");

    ui.add_space(12.0);
    cl_ui::h2(ui, "2.  Send it to them");
    cl_ui::body(ui, "Right-click the folder, choose Send to, then Compressed (zipped) folder. Attach that to an e-mail.");
    cl_ui::body(ui, "They need no account, no internet connection and no administrator. They open one program and follow five screens.");

    ui.add_space(12.0);
    cl_ui::h2(ui, "3.  Read what comes back");
    cl_ui::body(ui, "They reply with one file ending in .clade  Press \"Open a file a vendor sent back\" and choose it.");

    ui.add_space(22.0);
    cl_ui::h2(ui, "What the report tells you");
    cl_ui::body(
        ui,
        "There is no single score. Five separate questions are answered, and a good answer to one is never allowed to speak for the others.",
    );
    ui.add_space(8.0);
    for (q, a) in [
        ("Has the file been altered?", "Whether anything was edited after they made it."),
        ("Does it answer your request?", "Whether it is tied to the case you opened, not another one."),
        ("Was the PDF rebuilt?", "Whether the printed report was re-exported or copied."),
        ("How much did they show?", "Whether parts were left out. Leaving things out is allowed."),
        ("Do the files fit the claim?", "The actual finding."),
    ] {
        cl_ui::field(ui, q, a);
    }

    ui.add_space(18.0);
    cl_ui::h2(ui, "What the finding can say");
    // Driven off the enum, so a band that a report can print cannot be one this
    // screen has never heard of.
    for b in cl_core::vocab::SupportBand::ALL {
        cl_ui::field(ui, cl_ui::band_short_name(*b), cl_ui::band_plain_english(*b));
    }

    ui.add_space(16.0);
    cl_ui::callout(
        ui,
        cl_ui::colour::NEUTRAL,
        "Two things worth knowing",
        "\"Not enough evidence\" is the most common answer, and it is a real answer rather than a failure. Cladeon abstains instead of guessing, and something left out never counts against anyone.",
    );
    ui.add_space(8.0);
    cl_ui::callout(
        ui,
        cl_ui::colour::NEUTRAL,
        "If it says the files do not fit",
        "It means the files disagree with the claim, within what was shown. It is a reason to ask a follow-up question. It is not a statement about anyone's honesty, and Cladeon does not make one.",
    );

    ui.add_space(22.0);
    cl_ui::h2(ui, "Questions people ask");
    for (q, a) in [
        ("Does it upload anything?", "No. Neither program opens a network connection."),
        ("Will it slow their machine down?", "It reads file headers and checksums. Minutes, not hours."),
        (
            "What if they will not show something?",
            "They can exclude it. The report records that a folder was excluded, never what was in it.",
        ),
        (
            "Can they edit the report?",
            "They can edit the file, but the checks stop matching and Cladeon says so.",
        ),
        ("Is a screenshot enough?", "No. It must be the .clade file itself, unchanged."),
        (
            "Does it settle whether they trained a model?",
            "No, and it does not claim to. Read the line at the foot of every screen.",
        ),
    ] {
        cl_ui::field(ui, q, a);
    }

    ui.add_space(24.0);
    cl_ui::secondary_button(ui, "Back")
}

#[cfg(test)]
mod tests {
    /// Every sentence this screen shows, in one place, so the tests below can read
    /// them without a running interface.
    fn screen_text() -> String {
        // Cut before the tests: this module's own `bad` list contains the very
        // phrases the over-claiming check looks for, and reading past here made that
        // test fail against itself.
        let src = include_str!("help.rs");
        let src = &src[..src.find("mod tests").unwrap_or(src.len())];
        src.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_screen_covers_what_the_printed_guide_covers() {
        // The two are written separately, so the risk is that one gains a section and
        // the other silently does not. These are the headings a reader needs either
        // way; if one is dropped here it was dropped by accident.
        let t = screen_text();
        for section in [
            "Open a case",
            "Send it to them",
            "Read what comes back",
            "What the report tells you",
            "Questions people ask",
        ] {
            assert!(t.contains(section), "the screen no longer covers `{section}`");
        }
    }

    #[test]
    fn every_band_a_report_can_show_has_a_name_and_a_meaning() {
        // The screen loops over the enum, so coverage is structural rather than a
        // hand-copied list. What is still worth checking is that a new band cannot
        // be added with a placeholder for either half.
        for b in cl_core::vocab::SupportBand::ALL {
            let name = cl_ui::band_short_name(*b);
            let meaning = cl_ui::band_plain_english(*b);
            assert!(name.len() > 4, "{b} has no readable name");
            assert!(meaning.len() > 20 && meaning.ends_with('.'), "{b} has a thin meaning");
            assert_ne!(name, meaning);
        }
    }

    #[test]
    fn the_help_screen_uses_no_forbidden_language() {
        assert_eq!(cl_core::vocab::forbidden_language(&screen_text()), None);
    }

    #[test]
    fn it_does_not_promise_a_verdict() {
        let t = screen_text().to_lowercase();
        for bad in ["proves that", "detects fake", "tells you if they"] {
            assert!(!t.contains(bad), "the help screen over-claims: `{bad}`");
        }
    }
}
