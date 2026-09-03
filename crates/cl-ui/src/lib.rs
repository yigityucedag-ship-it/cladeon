//! Shared presentation for both Cladeon applications.
//!
//! ## Why this crate exists apart from the apps
//!
//! The auditor and the vendor see the same vocabulary — the same seven support
//! bands, the same five verification statuses — and they must see them *rendered the
//! same way*. If "Weakly consistent" is amber in one window and grey in the other,
//! the colour has stopped being information. So the mapping from a conclusion to a
//! colour and a phrase lives here, once, next to the vocabulary it renders.
//!
//! ## The one rule this layer obeys
//!
//! **It never parses anything.** No artifact byte and no bundle byte is read here;
//! the UI calls the library API and displays what comes back. A contract test
//! (`gui_crates_do_not_parse_anything`) enforces it, because a parser written for
//! display convenience is exactly how hostile input ends up somewhere unbounded.

#![forbid(unsafe_code)]

use egui::{Color32, RichText, Ui};
use cl_core::vocab::{
    ChallengeStatus, CoverageStatus, IntegrityStatus, MarkerStatus, SupportBand,
};

/// Ink and paper. Deliberately sober: this is a document people forward to their
/// legal team, not a dashboard.
pub mod colour {
    use egui::Color32;

    pub const INK: Color32 = Color32::from_rgb(0x1b, 0x1d, 0x22);
    pub const MUTED: Color32 = Color32::from_rgb(0x6b, 0x71, 0x7d);
    pub const RULE: Color32 = Color32::from_rgb(0xd8, 0xdb, 0xe0);
    pub const PAPER: Color32 = Color32::from_rgb(0xfa, 0xfa, 0xfb);

    /// Good, but never triumphant — the strongest thing this product says is
    /// "corroborated within supplied evidence", which is not a clean bill of health.
    pub const AFFIRM: Color32 = Color32::from_rgb(0x1f, 0x7a, 0x4d);
    /// Neither good nor bad. Most conclusions land here and that is correct.
    pub const NEUTRAL: Color32 = Color32::from_rgb(0x5a, 0x63, 0x72);
    /// Something needs a human.
    pub const ATTENTION: Color32 = Color32::from_rgb(0xb4, 0x6a, 0x0a);
    /// A conflict between an exact claim and an observed artifact.
    pub const CONFLICT: Color32 = Color32::from_rgb(0xa8, 0x2f, 0x2f);
    pub const ACCENT: Color32 = Color32::from_rgb(0x2b, 0x4f, 0x8e);
}

/// Apply the shared look. Called once at startup by each app.
pub fn apply_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.visuals = egui::Visuals::light();
    style.visuals.panel_fill = colour::PAPER;
    style.visuals.window_fill = colour::PAPER;
    style.visuals.override_text_color = Some(colour::INK);
    ctx.set_style(style);
}

/// Colour for a support band.
///
/// Note what is *not* colour-coded as bad: `InsufficientEvidence` and `NotSupplied`
/// are neutral, because abstaining is the tool working correctly, not a finding
/// against anyone. Only a contradiction earns red.
pub fn band_colour(b: SupportBand) -> Color32 {
    match b {
        SupportBand::Corroborated | SupportBand::StronglyConsistent => colour::AFFIRM,
        SupportBand::WeaklyConsistent | SupportBand::PartiallySupported => colour::ATTENTION,
        SupportBand::InsufficientEvidence | SupportBand::NotSupplied => colour::NEUTRAL,
        SupportBand::Contradicted => colour::CONFLICT,
    }
}

pub fn integrity_colour(s: IntegrityStatus) -> Color32 {
    match s {
        IntegrityStatus::Intact => colour::AFFIRM,
        IntegrityStatus::Modified | IntegrityStatus::Unreadable => colour::CONFLICT,
        IntegrityStatus::Incomplete => colour::ATTENTION,
    }
}

pub fn challenge_colour(s: ChallengeStatus) -> Color32 {
    match s {
        ChallengeStatus::Bound => colour::AFFIRM,
        ChallengeStatus::Unsigned | ChallengeStatus::Absent => colour::NEUTRAL,
        _ => colour::CONFLICT,
    }
}

pub fn marker_colour(s: MarkerStatus) -> Color32 {
    match s {
        MarkerStatus::PresentConsistent => colour::AFFIRM,
        MarkerStatus::PresentInconsistent => colour::CONFLICT,
        _ => colour::NEUTRAL,
    }
}

pub fn coverage_colour(s: CoverageStatus) -> Color32 {
    match s {
        CoverageStatus::Complete => colour::AFFIRM,
        CoverageStatus::Partial => colour::ATTENTION,
        CoverageStatus::Minimal => colour::NEUTRAL,
    }
}

/// A plain-language gloss for a support band.
///
/// The enum names are precise and unreadable. Somebody in procurement needs a
/// sentence, and it has to carry the same caution as the term it explains.
pub fn band_plain_english(b: SupportBand) -> &'static str {
    match b {
        SupportBand::Corroborated => {
            "Several independent pieces of evidence agree with this part of the claim."
        }
        SupportBand::StronglyConsistent => {
            "The evidence supplied fits this part of the claim well."
        }
        SupportBand::WeaklyConsistent => {
            "The evidence fits, but there is not much of it."
        }
        SupportBand::PartiallySupported => {
            "There is real supporting evidence, but not enough to name the method used."
        }
        SupportBand::InsufficientEvidence => {
            "Not enough was supplied to reach a conclusion. This is not a finding against the vendor."
        }
        SupportBand::Contradicted => {
            "Something the vendor stated conflicts with a file that was examined."
        }
        SupportBand::NotSupplied => {
            "The kind of file needed to answer this was not in the folders that were scanned."
        }
    }
}

pub fn facet_title(f: cl_core::vocab::Facet) -> &'static str {
    use cl_core::vocab::Facet;
    match f {
        Facet::WeightOrigin => "Where the weights came from",
        Facet::ParameterUpdate => "How the weights were changed",
        Facet::TrainingStage => "What kind of training",
        Facet::InferenceAugmentation => "What else runs at answer time",
    }
}

// ---------------------------------------------------------------------------
// Widgets
// ---------------------------------------------------------------------------

pub fn h1(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(26.0).strong().color(colour::INK));
}

pub fn h2(ui: &mut Ui, text: &str) {
    ui.add_space(6.0);
    ui.label(RichText::new(text).size(17.0).strong().color(colour::INK));
    ui.add_space(2.0);
}

pub fn muted(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(13.0).color(colour::MUTED));
}

pub fn body(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(14.5).color(colour::INK));
}

/// A coloured status chip.
pub fn badge(ui: &mut Ui, text: &str, fill: Color32) {
    egui::Frame::NONE
        .fill(fill)
        .corner_radius(4.0)
        .inner_margin(egui::Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(12.5).strong().color(Color32::WHITE));
        });
}

/// A bordered callout. `tone` picks the left rule colour.
pub fn callout(ui: &mut Ui, tone: Color32, title: &str, text: &str) {
    egui::Frame::NONE
        .fill(Color32::from_rgb(0xf2, 0xf3, 0xf5))
        .corner_radius(4.0)
        .inner_margin(egui::Margin::symmetric(12, 10))
        .stroke(egui::Stroke::new(1.0_f32, colour::RULE))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(3.0, 16.0), egui::Sense::hover());
                ui.painter().rect_filled(rect, 1.0, tone);
                ui.label(RichText::new(title).size(13.5).strong().color(tone));
            });
            ui.add_space(3.0);
            ui.label(RichText::new(text).size(13.0).color(colour::INK));
        });
}

/// A labelled row, aligned so a column of them reads as a table.
pub fn field(ui: &mut Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            egui::vec2(190.0, 18.0),
            egui::Layout::left_to_right(egui::Align::Min),
            |ui| {
                ui.label(RichText::new(label).size(13.0).color(colour::MUTED));
            },
        );
        ui.label(RichText::new(value).size(13.5).color(colour::INK));
    });
}

/// The step rail shown down the side of a wizard.
pub fn step_rail(ui: &mut Ui, steps: &[&str], current: usize) {
    ui.vertical(|ui| {
        for (i, s) in steps.iter().enumerate() {
            let (dot, text) = if i < current {
                (colour::AFFIRM, colour::MUTED)
            } else if i == current {
                (colour::ACCENT, colour::INK)
            } else {
                (colour::RULE, colour::MUTED)
            };
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(9.0, 9.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 4.5, dot);
                ui.label(RichText::new(*s).size(13.0).color(text));
            });
            ui.add_space(6.0);
        }
    });
}

/// The sentence the product is legally and ethically obliged to show.
pub fn required_statement(ui: &mut Ui) {
    ui.add_space(4.0);
    ui.label(
        RichText::new(cl_core::REQUIRED_STATEMENT)
            .size(11.5)
            .italics()
            .color(colour::MUTED),
    );
}

/// A primary action button, sized so it reads as the obvious next step.
pub fn primary_button(ui: &mut Ui, text: &str, enabled: bool) -> bool {
    ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(text).size(14.5).strong().color(Color32::WHITE))
            .fill(if enabled { colour::ACCENT } else { colour::RULE })
            .corner_radius(4.0),
    )
    .clicked()
}

pub fn secondary_button(ui: &mut Ui, text: &str) -> bool {
    ui.add(egui::Button::new(RichText::new(text).size(14.0).color(colour::INK)))
        .clicked()
}

/// Human-readable byte count.
pub fn bytes_human(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// A score in tenths, rendered for a reader rather than a machine.
pub fn score_human(tenths: i64) -> String {
    format!("{}.{} out of 100", tenths / 10, tenths % 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abstention_is_never_coloured_as_a_finding() {
        // Abstaining is the tool working correctly. Only a genuine conflict is red.
        assert_eq!(band_colour(SupportBand::InsufficientEvidence), colour::NEUTRAL);
        assert_eq!(band_colour(SupportBand::NotSupplied), colour::NEUTRAL);
        assert_eq!(band_colour(SupportBand::Contradicted), colour::CONFLICT);
    }

    #[test]
    fn every_band_has_a_plain_english_gloss_and_a_colour() {
        for b in SupportBand::ALL {
            let g = band_plain_english(*b);
            assert!(g.len() > 20, "{b} has a thin gloss");
            assert!(g.ends_with('.'), "{b} gloss is not a sentence");
            let _ = band_colour(*b);
        }
    }

    #[test]
    fn plain_english_uses_no_forbidden_language() {
        let mut all = String::new();
        for b in SupportBand::ALL {
            all.push_str(band_plain_english(*b));
            all.push('\n');
        }
        for f in cl_core::vocab::Facet::ALL {
            all.push_str(facet_title(*f));
            all.push('\n');
        }
        assert_eq!(cl_core::vocab::forbidden_language(&all), None);
    }

    #[test]
    fn insufficient_evidence_says_it_is_not_an_accusation() {
        // The single most important sentence in the whole interface.
        let g = band_plain_english(SupportBand::InsufficientEvidence);
        assert!(g.contains("not a finding against"), "{g}");
    }

    #[test]
    fn byte_formatting_is_readable() {
        assert_eq!(bytes_human(0), "0 B");
        assert_eq!(bytes_human(999), "999 B");
        assert_eq!(bytes_human(1024), "1.0 KB");
        assert_eq!(bytes_human(3_672_806), "3.5 MB");
    }

    #[test]
    fn score_reads_as_a_number_out_of_a_hundred() {
        assert_eq!(score_human(0), "0.0 out of 100");
        assert_eq!(score_human(620), "62.0 out of 100");
        assert_eq!(score_human(1000), "100.0 out of 100");
    }
}
