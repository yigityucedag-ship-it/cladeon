//! Cladeon — the auditor's desktop application.
//!
//! Two jobs, and they are the two halves of a diligence conversation:
//!
//! 1. **Open a case.** Record who is being asked and the exact sentence being
//!    tested, then produce a folder to e-mail them.
//! 2. **Read what comes back.** Open the returned file and see five separate
//!    answers, in language a procurement officer can act on.
//!
//! ## What this window refuses to do
//!
//! It never reduces a bundle to a single verdict, however much easier that would be
//! to read. A bundle can be byte-perfect and evidentially worthless at the same
//! time, and collapsing those into one word is precisely the misreading this whole
//! product exists to prevent. So integrity, binding, markers, coverage and evidence
//! each get their own line, and the strongest one is never allowed to speak for the
//! others.

#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod help;
mod instructions_tr;
mod kit;

use cl_core::ids::{CaseId, Nonce};
use cl_core::time::Timestamp;
use cl_core::vocab::{ChallengeStatus, IntegrityStatus, MarkerStatus, SupportBand, WeightOrigin};
use cl_verify::{verify_bundle, Recomputation, Verification};
use eframe::egui;
use std::path::PathBuf;

#[derive(PartialEq, Eq, Clone, Copy)]
enum Page {
    Home,
    NewCase,
    KitReady,
    Report,
    Help,
}

struct App {
    page: Page,
    // new case
    claimed_origin: Option<WeightOrigin>,
    valid_days: i64,
    // issued
    kit_dir: Option<PathBuf>,
    kit_case: Option<String>,
    kit_scanner_included: bool,
    // report
    bundle_path: Option<PathBuf>,
    verification: Option<Verification>,
    error: Option<String>,
    notice: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        App {
            page: Page::Home,
            // The claim this product exists to test. Pre-selected because it is why a
            // buyer opens a case at all, and because leaving it unset silently
            // disables the rule family that tests it.
            claimed_origin: Some(WeightOrigin::RandomInitializationClaimed),
            valid_days: 21,
            kit_dir: None,
            kit_case: None,
            kit_scanner_included: false,
            bundle_path: None,
            verification: None,
            error: None,
            notice: None,
        }
    }
}

/// Where the issuer's signing key lives.
///
/// Beside the executable, because the product installs nothing and a buyer may run
/// it from a shared drive. It is the buyer's private half: it never enters a kit,
/// and losing it only means future cases cannot be signed — past bundles stay
/// checkable, because the public half travels inside each challenge.
/// The sentence quoted into the report, derived from the single question the buyer
/// answers when opening a case.
///
/// This used to be free text the buyer pasted from a pitch. Verbatim quotation reads
/// better in a report, but it cost two typed fields on the one screen that has to be
/// usable by someone who does not want to be doing this, and a claim can be softened
/// or sharpened in the retyping. A fixed sentence per option cannot be, and it is the
/// same sentence the supplier sees, so neither side is reading a private version.
fn claim_text(origin: Option<WeightOrigin>) -> &'static str {
    match origin {
        Some(WeightOrigin::RandomInitializationClaimed) => "We trained our own model.",
        Some(WeightOrigin::DerivativeOfDisclosedBase) => {
            "We built our system on an existing model from someone else."
        }
        Some(WeightOrigin::DistilledFromTeacher) => {
            "We copied the behaviour of a larger model into our own."
        }
        Some(WeightOrigin::Unknown) | None => {
            "No claim about how this model was built has been recorded."
        }
    }
}

const KEY_FILE: &str = "cladeon-issuer.key";

/// A key already sitting beside the executable, if there is one.
///
/// This is where the key used to live unconditionally, and portable copies on a
/// shared drive still keep it there. It is checked first so that upgrading does not
/// silently start issuing cases under a new identity.
fn portable_key() -> Option<PathBuf> {
    let p = std::env::current_exe().ok()?.parent()?.join(KEY_FILE);
    p.is_file().then_some(p)
}

/// Where a new key is created.
///
/// Not beside the executable. That worked while the product was only ever unzipped
/// into a writable folder, but an installed copy lives somewhere read-only - Program
/// Files, or the sealed package directory the Microsoft Store installs into - and the
/// write fails at the exact moment the user is trying to open their first case.
///
/// Per-user rather than machine-wide, because it is a private key: two people sharing
/// a computer should not be issuing cases under one another's identity.
fn key_home() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).or_else(|| {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share"))
    })?;
    Some(base.join("Cladeon"))
}

fn key_path() -> Option<PathBuf> {
    if let Some(p) = portable_key() {
        return Some(p);
    }
    Some(key_home()?.join(KEY_FILE))
}

fn load_or_create_key() -> Result<cl_case::IssuerKey, String> {
    let path = key_path().ok_or("cannot determine where to keep the signing key")?;
    if path.is_file() {
        let hex = std::fs::read_to_string(&path).map_err(|e| format!("{e}"))?;
        return cl_case::IssuerKey::from_secret_hex(hex.trim()).map_err(|e| format!("{e}"));
    }
    let key = cl_case::IssuerKey::generate().map_err(|e| format!("{e}"))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("the folder for the signing key could not be made: {e}"))?;
    }
    std::fs::write(&path, key.to_secret_hex())
        .map_err(|e| format!("the signing key could not be written to {}: {e}", path.display()))?;
    Ok(key)
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cl_ui::apply_theme(&cc.egui_ctx);
        cl_ui::set_language(cl_i18n::load());
        App::default()
    }

    fn create_case(&mut self) {
        self.error = None;
        let parent = match rfd::FileDialog::new().set_title(cl_ui::tr("Where should the vendor folder go?")).pick_folder() {
            Some(p) => p,
            None => return,
        };

        let mut seed = [0u8; 3];
        if getrandom::getrandom(&mut seed).is_err() {
            self.error = Some("could not generate a case identifier".into());
            return;
        }
        let mut nonce_bytes = [0u8; 16];
        if getrandom::getrandom(&mut nonce_bytes).is_err() {
            self.error = Some("could not generate a case nonce".into());
            return;
        }
        let now = Timestamp::now();
        let year = {
            let (y, _, _) = cl_core::time::civil_from_days(now.0.div_euclid(86_400));
            y
        };
        let case_id = CaseId::from_entropy(year, &seed);
        let nonce = Nonce::from_bytes(&nonce_bytes);

        // Always signed. It was a checkbox marked "recommended", which is a decision
        // dressed up as a choice: an unsigned request cannot be tied to the reply it
        // produces, and nobody opening this screen wants that.
        let key = match load_or_create_key() {
            Ok(k) => Some(k),
            Err(e) => {
                self.error = Some(format!("the signing key could not be prepared: {e}"));
                return;
            }
        };

        let challenge = cl_case::Challenge::new(
            case_id.clone(),
            nonce,
            // Not asked for. An empty label is displayed as "not recorded" rather
            // than printed as a blank field.
            "",
            claim_text(self.claimed_origin),
            now,
            self.valid_days,
            vec![
                "base_identity".into(),
                "adapter_config".into(),
                "training_logs".into(),
                "serving_config".into(),
            ],
            key.as_ref().map(|k| k.public_hex()),
            self.claimed_origin,
        );

        let bytes = match challenge.to_canonical_bytes() {
            Ok(b) => b,
            Err(e) => {
                self.error = Some(format!("the case could not be written: {e}"));
                return;
            }
        };
        let sig = match &key {
            Some(k) => match k.sign(&challenge) {
                Ok(s) => Some(s),
                Err(e) => {
                    self.error = Some(format!("the case could not be signed: {e}"));
                    return;
                }
            },
            None => None,
        };

        match kit::build(&parent, &challenge, &bytes, sig.as_deref(), cl_ui::language()) {
            Ok(k) => {
                self.kit_dir = Some(k.dir);
                self.kit_scanner_included = k.scanner_included;
                self.kit_case = Some(case_id.as_str().to_string());
                self.page = Page::KitReady;
            }
            Err(e) => self.error = Some(format!("the vendor folder could not be written: {e}")),
        }
    }

    fn help(&mut self, ui: &mut egui::Ui) {
        if help::draw(ui) {
            self.page = Page::Home;
        }
    }

    fn open_bundle(&mut self) {
        self.error = None;
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Cladeon evidence bundle", &["clade"])
            .set_title(cl_ui::tr("Open the file the vendor sent back"))
            .pick_file()
        else {
            return;
        };
        match std::fs::read(&path) {
            Err(e) => self.error = Some(format!("that file could not be read: {e}")),
            Ok(bytes) => {
                let v = verify_bundle(&bytes, Timestamp::now(), None);
                self.bundle_path = Some(path);
                self.verification = Some(v);
                self.page = Page::Report;
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Cladeon").size(19.0).strong());
                ui.label(
                    egui::RichText::new(cl_core::PRODUCT_VERSION)
                        .size(12.0)
                        .color(cl_ui::colour::MUTED),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    cl_ui::language_picker(ui);
                    ui.add_space(10.0);
                    if self.page != Page::Home && cl_ui::secondary_button(ui, "Home") {
                        self.page = Page::Home;
                    }
                });
            });
            ui.add_space(8.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(12.0);
                if let Some(e) = self.error.clone() {
                    cl_ui::callout(ui, cl_ui::colour::CONFLICT, "Something went wrong", &e);
                    ui.add_space(6.0);
                    if cl_ui::secondary_button(ui, "Dismiss") {
                        self.error = None;
                    }
                    ui.add_space(10.0);
                }
                if let Some(n) = self.notice.clone() {
                    cl_ui::callout(ui, cl_ui::colour::ACCENT, "Copied", &n);
                    ui.add_space(10.0);
                    self.notice = None;
                }
                match self.page {
                    Page::Home => self.home(ui),
                    Page::NewCase => self.new_case(ui),
                    Page::KitReady => self.kit_ready(ui),
                    Page::Report => self.report(ui),
                    Page::Help => self.help(ui),
                }
                ui.add_space(18.0);
                cl_ui::required_statement(ui);
            });
        });
    }
}

impl App {
    fn home(&mut self, ui: &mut egui::Ui) {
        cl_ui::h1(ui, "Check how a vendor built their AI");
        ui.add_space(8.0);
        cl_ui::body(
            ui,
            "You write down what a supplier told you. They run a small program over their own files. Cladeon tells you how well the two fit.",
        );

        ui.add_space(20.0);

        ui.horizontal(|ui| {
            if cl_ui::primary_button(ui, "Start a new check", true) {
                self.page = Page::NewCase;
            }
            ui.add_space(8.0);
            if cl_ui::secondary_button(ui, "Open a file a vendor sent back") {
                self.open_bundle();
            }
            ui.add_space(8.0);
            if cl_ui::secondary_button(ui, "How to use this") {
                self.page = Page::Help;
            }
        });

        ui.add_space(24.0);
        cl_ui::h2(ui, "How it works");
        cl_ui::body(ui, "1.  You write down who you are asking and what they told you.");
        cl_ui::body(ui, "2.  Cladeon makes a folder. You e-mail it to them.");
        cl_ui::body(ui, "3.  They double-click one program and send back one file.");
        cl_ui::body(ui, "4.  You open that file here and read the report.");

        ui.add_space(18.0);
        cl_ui::callout(
            ui,
            cl_ui::colour::NEUTRAL,
            "What this can and cannot tell you",
            "It reports whether the files fit the claim. It cannot see what was not sent, and it does not decide what anyone intended. Its most common answer is that there was not enough evidence to tell, which is a real answer.",
        );
    }

    fn new_case(&mut self, ui: &mut egui::Ui) {
        cl_ui::h1(ui, "Start a new check");
        ui.add_space(10.0);

        cl_ui::h2(ui, "What are they saying they built?");
        cl_ui::muted(ui, "Pick whichever is closest to what you were told.");
        ui.add_space(8.0);
        for (opt, label) in [
            (Some(WeightOrigin::RandomInitializationClaimed), "They trained their own model"),
            (Some(WeightOrigin::DerivativeOfDisclosedBase), "They built on someone else's model"),
            (Some(WeightOrigin::DistilledFromTeacher), "They copied a bigger model's behaviour"),
            (None, "They did not say"),
        ] {
            ui.radio_value(&mut self.claimed_origin, opt, cl_ui::tr(label));
        }

        ui.add_space(12.0);
        cl_ui::callout(
            ui,
            cl_ui::colour::NEUTRAL,
            "The statement that gets tested",
            claim_text(self.claimed_origin),
        );

        ui.add_space(14.0);
        ui.horizontal(|ui| {
            ui.label(cl_ui::tr("Ask them to reply within"));
            ui.add(egui::DragValue::new(&mut self.valid_days).range(1..=90).suffix(cl_ui::tr(" days")));
        });

        ui.add_space(20.0);
        ui.horizontal(|ui| {
            if cl_ui::secondary_button(ui, "Back") {
                self.page = Page::Home;
            }
            if cl_ui::primary_button(ui, "Create the folder to send", true) {
                self.create_case();
            }
        });
    }

    fn kit_ready(&mut self, ui: &mut egui::Ui) {
        cl_ui::h1(ui, "Ready to send");
        ui.add_space(10.0);

        if let Some(c) = &self.kit_case {
            cl_ui::field(ui, "Case reference", c);
        }
        if let Some(d) = &self.kit_dir {
            cl_ui::callout(ui, cl_ui::colour::ACCENT, "Folder created", &d.display().to_string());
            ui.add_space(6.0);
            if cl_ui::secondary_button(ui, "Copy location") {
                ui.ctx().copy_text(d.display().to_string());
                self.notice = Some("The folder location is on your clipboard.".into());
            }
        }

        ui.add_space(14.0);
        cl_ui::h2(ui, "What to do now");
        cl_ui::body(ui, "1.  Zip that folder.");
        cl_ui::body(ui, "2.  E-mail it to your contact at the vendor.");
        cl_ui::body(ui, "3.  Tell them to open it and read \"READ ME FIRST\".");
        cl_ui::body(ui, "4.  They send back one file ending in .clade");

        if !self.kit_scanner_included {
            ui.add_space(12.0);
            cl_ui::callout(
                ui,
                cl_ui::colour::ATTENTION,
                "The scanner program was not included",
                "cladeon-screen.exe was not found next to this application, so the folder \
                 contains only the request. Copy the scanner in beside it before sending, \
                 or the vendor will have nothing to run.",
            );
        }

        ui.add_space(18.0);
        ui.horizontal(|ui| {
            if cl_ui::secondary_button(ui, "Start another check") {
                self.page = Page::NewCase;
            }
            if cl_ui::secondary_button(ui, "Open a returned file") {
                self.open_bundle();
            }
        });
    }

    fn report(&mut self, ui: &mut egui::Ui) {
        let Some(v) = self.verification.clone() else { return };

        cl_ui::h1(ui, "What the vendor sent back");
        ui.add_space(8.0);
        match v.vendor_label.as_deref() {
            Some(l) if !l.trim().is_empty() => cl_ui::field(ui, "Supplier", l),
            _ => cl_ui::field(ui, "Supplier", "not recorded"),
        }
        if let Some(c) = &v.case_id {
            cl_ui::field(ui, "Case", c);
        }
        if let Some(p) = &self.bundle_path {
            cl_ui::field(ui, "File", &p.display().to_string());
        }

        if let Some(claim) = &v.exact_claim_text {
            ui.add_space(10.0);
            cl_ui::h2(ui, "The claim being tested");
            egui::Frame::NONE
                .fill(egui::Color32::from_rgb(0xf2, 0xf3, 0xf5))
                .inner_margin(egui::Margin::same(12))
                .corner_radius(4.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(claim).size(15.0).italics());
                });
        }

        // ---- the five axes, never merged ----
        ui.add_space(16.0);
        cl_ui::h2(ui, "Five separate checks");
        cl_ui::muted(
            ui,
            "These answer different questions. A file can be perfectly intact and still not \
             prove much; both of those are shown, and neither cancels the other.",
        );
        ui.add_space(8.0);

        status_row(
            ui,
            "Has the file been altered?",
            v.integrity.as_str(),
            cl_ui::integrity_colour(v.integrity),
            match v.integrity {
                IntegrityStatus::Intact => "Unchanged since the vendor created it.",
                IntegrityStatus::Modified => "Something was edited after it was created.",
                IntegrityStatus::Incomplete => "Part of the bundle is missing.",
                IntegrityStatus::Unreadable => "The file could not be read at all.",
            },
        );
        status_row(
            ui,
            "Does it answer your request?",
            v.challenge.as_str(),
            cl_ui::challenge_colour(v.challenge),
            match v.challenge {
                ChallengeStatus::Bound => "It is signed and tied to the request you issued.",
                ChallengeStatus::Unsigned => "It names a request, but nothing proves it was yours.",
                ChallengeStatus::Absent => "It answers no recorded request.",
                ChallengeStatus::Expired => "The request had expired when this was checked.",
                ChallengeStatus::SignatureInvalid => "The signature does not check out.",
                ChallengeStatus::CaseMismatch => "This answers a different case.",
            },
        );
        status_row(
            ui,
            "Was the PDF rebuilt?",
            v.marker.as_str(),
            cl_ui::marker_colour(v.marker),
            match v.marker {
                MarkerStatus::PresentConsistent => "The PDF still carries its original markings.",
                MarkerStatus::PresentInconsistent => {
                    "The PDF claims markings it does not carry. It has been rebuilt or copied."
                }
                _ => "No markings to check.",
            },
        );
        status_row(
            ui,
            "How much did they show?",
            v.coverage.as_str(),
            cl_ui::coverage_colour(v.coverage),
            "How much of the selected folders the scan managed to read.",
        );
        status_row(
            ui,
            "Do the conclusions follow?",
            match &v.recomputation {
                Recomputation::Matches => "checked and consistent",
                Recomputation::Diverges { .. } => "DOES NOT FOLLOW",
                Recomputation::NotPossible { .. } => "could not be re-checked",
            },
            match &v.recomputation {
                Recomputation::Matches => cl_ui::colour::AFFIRM,
                Recomputation::Diverges { .. } => cl_ui::colour::CONFLICT,
                Recomputation::NotPossible { .. } => cl_ui::colour::NEUTRAL,
            },
            "Cladeon re-derives the findings from the evidence in the file and compares them \
             with what the file claims.",
        );

        if let Recomputation::Diverges { detail } = &v.recomputation {
            ui.add_space(10.0);
            cl_ui::callout(
                ui,
                cl_ui::colour::CONFLICT,
                "The stated findings do not follow from the evidence in this file",
                detail,
            );
            ui.add_space(4.0);
            cl_ui::body(
                ui,
                "This is what an edited report looks like even when every checksum matches. \
                 Ask the vendor to run the scan again and send the untouched result.",
            );
        }

        // ---- per facet ----
        ui.add_space(18.0);
        cl_ui::h2(ui, "What the evidence supports");
        if v.facet_bands.is_empty() {
            cl_ui::muted(ui, "No conclusions were recorded.");
        }
        for (facet, band) in &v.facet_bands {
            let b = SupportBand::parse(band).unwrap_or(SupportBand::InsufficientEvidence);
            let f = cl_core::vocab::Facet::parse(facet);
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                cl_ui::badge(ui, b.render(), cl_ui::band_colour(b));
                ui.label(
                    egui::RichText::new(f.map(cl_ui::facet_title).unwrap_or(facet.as_str()))
                        .size(14.5),
                );
            });
            cl_ui::muted(ui, cl_ui::band_plain_english(b));
        }

        // ---- notes ----
        if !v.findings.is_empty() {
            ui.add_space(18.0);
            cl_ui::h2(ui, "Notes");
            for f in &v.findings {
                cl_ui::body(ui, &format!("• {f}"));
            }
        }

        ui.add_space(18.0);
        cl_ui::callout(
            ui,
            cl_ui::colour::NEUTRAL,
            "Before you act on this",
            "This is a self-scan: the vendor chose which folders to show, on a machine you do \
             not control. It cannot establish that the folders scanned are the system actually \
             in production. Treat it as a screen that tells you what to ask next, not as an \
             audit.",
        );

        ui.add_space(14.0);
        ui.horizontal(|ui| {
            if cl_ui::secondary_button(ui, "Open another file") {
                self.open_bundle();
            }
            if let Some(p) = &self.bundle_path {
                if cl_ui::secondary_button(ui, "Copy file location") {
                    ui.ctx().copy_text(p.display().to_string());
                    self.notice = Some("The file location is on your clipboard.".into());
                }
            }
            if let Some(d) = &v.evidence_digest {
                let d = d.clone();
                if cl_ui::secondary_button(ui, "Copy evidence fingerprint") {
                    ui.ctx().copy_text(d);
                    self.notice = Some(
                        "The evidence fingerprint is on your clipboard. Two scans of unchanged \
                         evidence share it."
                            .into(),
                    );
                }
            }
        });
    }
}

fn status_row(ui: &mut egui::Ui, question: &str, value: &str, colour: egui::Color32, gloss: &str) {
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            egui::vec2(250.0, 20.0),
            egui::Layout::left_to_right(egui::Align::Min),
            |ui| {
                ui.label(egui::RichText::new(question).size(14.0).strong());
            },
        );
        cl_ui::badge(ui, value, colour);
    });
    ui.horizontal(|ui| {
        ui.add_space(250.0);
        ui.label(egui::RichText::new(gloss).size(12.5).color(cl_ui::colour::MUTED));
    });
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 800.0])
            .with_min_inner_size([840.0, 620.0])
            .with_title("Cladeon"),
        ..Default::default()
    };
    eframe::run_native("Cladeon", options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_option_yields_its_own_sentence_and_the_silent_one_asserts_nothing() {
        // The buyer types nothing, so these four sentences are the entire vocabulary
        // of claims the product can test. They must be distinct, they must read as
        // sentences in a report, and the one that means "they did not say" must not
        // quietly assert a training claim on the supplier's behalf.
        let opts = [
            Some(WeightOrigin::RandomInitializationClaimed),
            Some(WeightOrigin::DerivativeOfDisclosedBase),
            Some(WeightOrigin::DistilledFromTeacher),
            None,
        ];
        let mut seen: Vec<&str> = Vec::new();
        for o in opts {
            let t = claim_text(o);
            assert!(t.ends_with('.'), "`{t}` is not a sentence");
            assert!(t.len() > 20, "`{t}` is too thin to quote in a report");
            assert!(!seen.contains(&t), "`{t}` is used for two different answers");
            seen.push(t);
        }
        let silent = claim_text(None);
        assert!(silent.contains("No claim"), "{silent}");
        assert_eq!(claim_text(Some(WeightOrigin::Unknown)), silent);
    }

    #[test]
    fn the_buyer_is_asked_one_question_and_types_nothing() {
        // The screen carried two text fields and a checkbox. If any of them come
        // back, the case-opening screen has stopped being a single choice.
        let src = include_str!("main.rs");
        let body = &src[..src.find("mod tests").unwrap_or(src.len())];
        let screen = &body[body.find("fn new_case").unwrap()..body.find("fn kit_ready").unwrap()];
        for probe in ["text_edit_singleline", "text_edit_multiline", "TextEdit", "checkbox"] {
            assert!(!screen.contains(probe), "`{probe}` is back on the case-opening screen");
        }
        assert_eq!(screen.matches("radio_value").count(), 1, "one question, one control");
    }


    #[test]
    fn a_new_key_is_never_created_inside_the_install_directory() {
        // An installed copy - Program Files, or the sealed directory the Microsoft
        // Store installs into - is read-only. Creating the key there fails at the
        // moment the user opens their first case, which is the worst possible time.
        let exe_dir = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
        let fresh = key_home().expect("a per-user home must resolve").join(KEY_FILE);
        assert_ne!(
            fresh.parent(),
            Some(exe_dir.as_path()),
            "a new key would be written next to the executable"
        );
        assert!(fresh.is_absolute(), "the key home must be absolute: {}", fresh.display());
    }

    #[test]
    fn an_existing_portable_key_still_wins() {
        // Upgrading a copy that already has a key beside it must not silently start
        // issuing cases under a new identity.
        match portable_key() {
            Some(p) => assert_eq!(key_path().as_deref(), Some(p.as_path())),
            None => assert_eq!(key_path(), key_home().map(|h| h.join(KEY_FILE))),
        }
    }

    #[test]
    fn the_signing_key_is_never_part_of_the_kit() {
        // The kit writes challenge.json, challenge.sig, the scanner and instructions.
        // The secret half must not appear in that list at any point.
        let src = include_str!("kit.rs");
        assert!(!src.contains("to_secret_hex"), "the kit builder must never touch the secret key");
    }

    #[test]
    fn every_status_has_a_plain_english_gloss() {
        // Each arm of the five status rows must produce a sentence, not an enum name.
        for s in IntegrityStatus::ALL {
            let g = match s {
                IntegrityStatus::Intact => "Unchanged since the vendor created it.",
                IntegrityStatus::Modified => "Something was edited after it was created.",
                IntegrityStatus::Incomplete => "Part of the bundle is missing.",
                IntegrityStatus::Unreadable => "The file could not be read at all.",
            };
            assert!(g.ends_with('.') && g.len() > 15, "{s} has a thin gloss");
        }
        for s in ChallengeStatus::ALL {
            let g = match s {
                ChallengeStatus::Bound => "It is signed and tied to the request you issued.",
                ChallengeStatus::Unsigned => "It names a request, but nothing proves it was yours.",
                ChallengeStatus::Absent => "It answers no recorded request.",
                ChallengeStatus::Expired => "The request had expired when this was checked.",
                ChallengeStatus::SignatureInvalid => "The signature does not check out.",
                ChallengeStatus::CaseMismatch => "This answers a different case.",
            };
            assert!(g.ends_with('.'), "{s} has no sentence");
        }
    }

    #[test]
    fn no_forbidden_language_in_the_auditor_interface() {
        let src = include_str!("main.rs");
        // Only the display strings matter, but scanning the whole file is the strict
        // reading and it passes, so keep it strict.
        for line in src.lines() {
            let t = line.trim();
            if !t.starts_with("//") && !t.starts_with("///") && !t.starts_with("//!") {
                if let Some(bad) = cl_core::vocab::forbidden_language(t) {
                    // `lie detector` appears in no display string; catch real leaks.
                    panic!("forbidden language `{bad}` in: {t}");
                }
            }
        }
    }

    #[test]
    fn an_evidence_fingerprint_is_a_sha256_hex_string() {
        // What the "Copy evidence fingerprint" button puts on the clipboard.
        let d = cl_core::hash::Digest::of(b"x").to_hex();
        assert_eq!(d.len(), 64);
        assert!(cl_core::hex::is_sha256_hex(&d));
    }
}
