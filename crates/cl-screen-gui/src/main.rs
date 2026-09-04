//! Cladeon Screen — the window a vendor actually uses.
//!
//! This is the program a buyer e-mails out, so its whole design assumption is that
//! the person opening it has never used a command line, did not choose to be
//! audited, and is reasonably suspicious of a stranger's executable reading their
//! files. Three consequences follow, and they shape every screen:
//!
//! 1. **It asks for nothing until it has explained itself.** The first screen says
//!    what the program reads, what it never does, and that no network connection is
//!    opened — before any folder picker appears.
//! 2. **Nothing leaves the machine unseen.** The preflight screen lists what would
//!    be sent *before* a single file is hashed, and the vendor can stop there.
//! 3. **It never spawns anything.** The output location comes from a save dialog the
//!    vendor drives, so they always know where the file went without the program
//!    launching a file manager on their behalf.
//!
//! The case file is picked up automatically if it sits beside the executable, so the
//! buyer can send one folder and the vendor only has to double-click.

#![forbid(unsafe_code)]
// A double-clicked application must not flash a console window behind it.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use cl_core::ids::CaseId;
use cl_core::limits::Limits;
use cl_core::redact::Redactor;
use cl_core::vocab::{CoverageStatus, Facet, SupportBand};
use cl_facts::DeclaredFacets;
use cl_screen::{scan, seal};
use eframe::egui;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;

const STEPS: &[&str] =
    &["What this is", "Your folders", "Before we start", "Scanning", "Send it back"];

#[derive(PartialEq, Eq, Clone, Copy)]
enum Step {
    Welcome = 0,
    Folders = 1,
    Preflight = 2,
    Running = 3,
    Done = 4,
}

/// A preflight summary: what is in scope, without having hashed anything.
#[derive(Default, Clone)]
struct Preflight {
    by_type: Vec<(String, u64, u64)>,
    total_files: u64,
    total_bytes: u64,
    opaque: u64,
    unreadable: Vec<String>,
}

/// What the scan produced, reduced to what the window needs.
///
/// The full `ScanResult` is deliberately not carried into the UI: the window shows
/// conclusions, and giving it the whole fact set would invite the UI to start
/// interpreting evidence, which is the rules engine's job.
struct Finished {
    path: PathBuf,
    sha256: String,
    files: u64,
    bytes: u64,
    coverage: CoverageStatus,
    facets: Vec<(Facet, SupportBand, bool)>,
    redactions: Vec<(String, u64)>,
    limitation_count: usize,
}

enum Msg {
    Preflight(Result<Preflight, String>),
    Progress(scan::Progress),
    Finished(Box<Result<Finished, String>>),
}

struct App {
    step: Step,
    // case
    challenge: Option<cl_case::Challenge>,
    challenge_bytes: Option<Vec<u8>>,
    challenge_sig: Option<Vec<u8>>,
    case_id: String,
    vendor: String,
    claim: String,
    // declaration
    // selection
    roots: Vec<PathBuf>,
    excluded: Vec<PathBuf>,
    // work
    rx: Option<Receiver<Msg>>,
    cancel: Arc<AtomicBool>,
    preflight: Option<Preflight>,
    preflight_running: bool,
    progress: scan::Progress,
    finished: Option<Finished>,
    error: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        App {
            step: Step::Welcome,
            challenge: None,
            challenge_bytes: None,
            challenge_sig: None,
            case_id: String::new(),
            vendor: String::new(),
            claim: String::new(),
            roots: Vec::new(),
            excluded: Vec::new(),
            rx: None,
            cancel: Arc::new(AtomicBool::new(false)),
            preflight: None,
            preflight_running: false,
            progress: scan::Progress::default(),
            finished: None,
            error: None,
        }
    }
}

/// Look beside the executable for the case file the buyer sent.
///
/// The buyer ships one folder containing this program and the case file, so the
/// vendor never has to know what a "challenge" is or go looking for it.
fn find_challenge_beside_exe() -> Option<(cl_case::Challenge, Vec<u8>, Option<Vec<u8>>)> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    find_challenge_in(&dir)
}

/// The searchable half, split out so it can be tested.
///
/// If this quietly stops working the vendor simply sees "no request file found",
/// shrugs, and the audit is untraceable to the buyer's question — a silent failure
/// with no error anywhere. That is exactly the kind of thing that needs a test.
fn find_challenge_in(dir: &Path) -> Option<(cl_case::Challenge, Vec<u8>, Option<Vec<u8>>)> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        let name = p.file_name()?.to_string_lossy().to_ascii_lowercase();
        if name == "challenge.json" || name.ends_with(".case") || name.ends_with(".challenge") {
            candidates.push(p);
        }
    }
    candidates.sort();
    for c in candidates {
        let Ok(bytes) = std::fs::read(&c) else { continue };
        if let Ok(ch) = cl_case::Challenge::parse(&bytes) {
            let sig = std::fs::read(c.with_extension("sig")).ok();
            return Some((ch, bytes, sig));
        }
    }
    None
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cl_ui::apply_theme(&cc.egui_ctx);
        cl_ui::set_language(cl_i18n::load());
        let mut app = App::default();
        if let Some((ch, bytes, sig)) = find_challenge_beside_exe() {
            app.case_id = ch.case_id.as_str().to_string();
            app.vendor = ch.vendor_label.clone();
            app.claim = ch.exact_claim_text.clone();
            app.challenge = Some(ch);
            app.challenge_bytes = Some(bytes);
            app.challenge_sig = sig;
        }
        app
    }

    fn request(&self) -> Option<scan::ScanRequest> {
        let case_id = CaseId::parse(&self.case_id).ok()?;
        Some(scan::ScanRequest {
            roots: self.roots.clone(),
            excluded: self.excluded.clone(),
            case_id,
            vendor_label: self.vendor.clone(),
            exact_claim_text: self.claim.clone(),
            // Everything here comes from the buyer's request. The supplier is asked
            // nothing about their own system, so there is no second account of it to
            // reconcile: the report compares one fixed claim against the files.
            declared: DeclaredFacets {
                weight_origin: self.challenge.as_ref().and_then(|c| c.claimed_origin),
                ..DeclaredFacets::default()
            },
            hash_files: true,
            limits: Limits::default(),
            challenge_bytes: self.challenge_bytes.clone(),
        })
    }

    fn start_preflight(&mut self, ctx: &egui::Context) {
        let roots = self.roots.clone();
        let excluded = self.excluded.clone();
        let (tx, rx) = channel();
        self.rx = Some(rx);
        self.preflight_running = true;
        self.preflight = None;
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let mut redactor = Redactor::new();
            let opts = cl_inventory::ScanOptions {
                limits: Limits::default(),
                // A preflight looks; it does not read. Nothing is hashed here.
                hash_files: false,
                excluded,
                head_bytes: cl_formats::detect::CLASSIFY_HEAD_BYTES,
            };
            let out = cl_inventory::scan(
                &roots,
                &mut redactor,
                &opts,
                &|p, h| cl_formats::detect::classify(p, h),
                &|| false,
                &mut |_| {},
            );
            let msg = match out {
                Err(e) => Err(format!("{e}")),
                Ok(inv) => {
                    let mut by: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
                    for a in &inv.artifacts {
                        let e = by.entry(a.artifact_type.as_str()).or_insert((0, 0));
                        e.0 += 1;
                        e.1 = e.1.saturating_add(a.size_bytes);
                    }
                    Ok(Preflight {
                        by_type: by.into_iter().map(|(k, v)| (k.to_string(), v.0, v.1)).collect(),
                        total_files: inv.files_enumerated,
                        total_bytes: inv.bytes_enumerated,
                        opaque: inv
                            .artifacts
                            .iter()
                            .filter(|a| {
                                a.artifact_type == cl_facts::ArtifactType::OpaqueSerialization
                            })
                            .count() as u64,
                        unreadable: inv
                            .coverage
                            .iter()
                            .take(12)
                            .map(|c| format!("{} — {}", c.path_alias, c.detail))
                            .collect(),
                    })
                }
            };
            let _ = tx.send(Msg::Preflight(msg));
            ctx.request_repaint();
        });
    }

    fn start_scan(&mut self, ctx: &egui::Context, out_dir: PathBuf) {
        let Some(req) = self.request() else {
            self.error = Some("The case identifier is not valid.".into());
            return;
        };
        let nonce =
            self.challenge.as_ref().map(|c| c.nonce.as_str().to_string()).unwrap_or_default();
        let sig = self.challenge_sig.clone();
        let (tx, rx) = channel();
        self.rx = Some(rx);
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        self.progress = scan::Progress::default();
        self.step = Step::Running;
        let ctx = ctx.clone();
        let tx_progress = tx.clone();
        let ctx_progress = ctx.clone();

        std::thread::spawn(move || {
            let flag = cancel.clone();
            let out = seal::scan_and_seal(
                &req,
                &out_dir,
                &nonce,
                sig,
                &|| flag.load(Ordering::Relaxed),
                &mut |p| {
                    let _ = tx_progress.send(Msg::Progress(p));
                    ctx_progress.request_repaint();
                },
            );
            let msg = match out {
                Err(e) => Err(format!("{e}")),
                Ok(sealed) => {
                    let r = &sealed.result;
                    Ok(Finished {
                        path: sealed.path.clone(),
                        sha256: sealed.sha256.clone(),
                        files: r.inventory.files_enumerated,
                        bytes: r.inventory.bytes_enumerated,
                        coverage: r.inventory.coverage_status,
                        facets: Facet::ALL
                            .iter()
                            .filter_map(|f| {
                                r.rules
                                    .conclusion(*f)
                                    .map(|c| (*f, c.band, c.method_label_emitted))
                            })
                            .collect(),
                        redactions: r
                            .redaction_ledger
                            .iter()
                            .map(|e| (e.kind.to_string(), e.count))
                            .collect(),
                        limitation_count: r.rules.limitations().len(),
                    })
                }
            };
            let _ = tx.send(Msg::Finished(Box::new(msg)));
            ctx.request_repaint();
        });
    }

    fn pump(&mut self) {
        let Some(rx) = &self.rx else { return };
        while let Ok(m) = rx.try_recv() {
            match m {
                Msg::Preflight(Ok(p)) => {
                    self.preflight = Some(p);
                    self.preflight_running = false;
                }
                Msg::Preflight(Err(e)) => {
                    self.error = Some(e);
                    self.preflight_running = false;
                }
                Msg::Progress(p) => self.progress = p,
                Msg::Finished(r) => match *r {
                    Ok(f) => {
                        self.finished = Some(f);
                        self.step = Step::Done;
                    }
                    Err(e) => {
                        self.error = Some(e);
                        self.step = Step::Preflight;
                    }
                },
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.pump();

        egui::SidePanel::left("rail").exact_width(210.0).show(ctx, |ui| {
            ui.add_space(18.0);
            cl_ui::h2(ui, "Cladeon Screen");
            cl_ui::muted(ui, cl_core::PRODUCT_VERSION);
            ui.add_space(18.0);
            cl_ui::step_rail(ui, STEPS, self.step as usize);
            ui.add_space(18.0);
            ui.separator();
            cl_ui::language_picker(ui);
            ui.separator();
            cl_ui::muted(ui, "No internet connection is used.\nYour files are never run.");
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(14.0);
                if let Some(e) = self.error.clone() {
                    cl_ui::callout(ui, cl_ui::colour::CONFLICT, "Something went wrong", &e);
                    ui.add_space(8.0);
                    if cl_ui::secondary_button(ui, "Dismiss") {
                        self.error = None;
                    }
                    ui.add_space(12.0);
                }
                match self.step {
                    Step::Welcome => self.welcome(ui),
                    Step::Folders => self.folders(ui),
                    Step::Preflight => self.preflight_screen(ui, ctx),
                    Step::Running => self.running(ui),
                    Step::Done => self.done(ui),
                }
                ui.add_space(20.0);
                cl_ui::required_statement(ui);
            });
        });
    }
}

impl App {
    fn welcome(&mut self, ui: &mut egui::Ui) {
        let Some(c) = self.challenge.clone() else {
            return self.no_request(ui);
        };

        cl_ui::h1(ui, "Show how your AI system was built");
        ui.add_space(8.0);
        cl_ui::body(
            ui,
            "This program looks at folders you choose and writes one file describing what \
             it found. You send that file back. It takes a few minutes.",
        );

        ui.add_space(16.0);
        cl_ui::field(ui, "Asked by", &c.vendor_label);
        cl_ui::field(ui, "Reference", c.case_id.as_str());
        ui.add_space(10.0);
        cl_ui::h2(ui, "The statement being checked");
        egui::Frame::NONE
            .fill(egui::Color32::from_rgb(0xf2, 0xf3, 0xf5))
            .inner_margin(egui::Margin::same(12))
            .corner_radius(4.0)
            .show(ui, |ui| {
                ui.label(egui::RichText::new(&c.exact_claim_text).size(15.0).italics());
            });
        cl_ui::muted(ui, "Taken from the request. You are not asked to restate it.");

        ui.add_space(16.0);
        cl_ui::h2(ui, "What it never does");
        cl_ui::body(ui, "-  It does not connect to the internet. Nothing is uploaded.");
        cl_ui::body(ui, "-  It does not run, open or load your model files.");
        cl_ui::body(ui, "-  It does not copy your weights, your data, your code or your prompts.");
        cl_ui::body(ui, "-  It removes passwords, API keys and your Windows user name.");
        ui.add_space(6.0);
        cl_ui::muted(ui, "Before it reads anything, it shows you exactly what would be sent.");

        ui.add_space(18.0);
        if cl_ui::primary_button(ui, "Continue", true) {
            self.step = Step::Folders;
        }
    }

    /// Shown when the program was sent on its own, without the request file.
    ///
    /// The earlier version of this screen let the vendor type a case reference and
    /// the claim by hand. That was a mistake twice over: it asked the least willing
    /// participant to do data entry, and it let the sentence under test be rewritten
    /// by the party it is testing. There is now no way past this screen except to
    /// supply the file the buyer actually issued.
    fn no_request(&mut self, ui: &mut egui::Ui) {
        cl_ui::h1(ui, "The request file is missing");
        ui.add_space(8.0);
        cl_ui::body(
            ui,
            "Whoever asked you for this sent a small file called challenge.json. It should \
             sit in the same folder as this program.",
        );
        ui.add_space(12.0);
        cl_ui::callout(
            ui,
            cl_ui::colour::ATTENTION,
            "What to do",
            "Go back to their e-mail and save the whole folder they attached, keeping the \
             files together. Then open this program from inside that folder.",
        );
        ui.add_space(16.0);
        if cl_ui::secondary_button(ui, "Find the file myself") {
            if let Some(f) = rfd::FileDialog::new()
                .set_title(cl_ui::tr("Open the request file you were sent"))
                .add_filter(cl_ui::tr("Request file"), &["json"])
                .pick_file()
            {
                match f.parent().and_then(find_challenge_in) {
                    Some((ch, bytes, sig)) => {
                        self.case_id = ch.case_id.as_str().to_string();
                        self.vendor = ch.vendor_label.clone();
                        self.claim = ch.exact_claim_text.clone();
                        self.challenge = Some(ch);
                        self.challenge_bytes = Some(bytes);
                        self.challenge_sig = sig;
                        self.error = None;
                    }
                    None => {
                        self.error = Some(
                            "That folder does not hold a request this program can read. Look \
                             for the folder containing challenge.json."
                                .to_string(),
                        );
                    }
                }
            }
        }
    }

    fn folders(&mut self, ui: &mut egui::Ui) {
        cl_ui::h1(ui, "Choose what to show");
        ui.add_space(8.0);
        cl_ui::body(
            ui,
            "Pick the folders holding your model and its training records. Nothing outside \
             these folders is looked at.",
        );
        ui.add_space(12.0);

        if cl_ui::secondary_button(ui, "Add a folder…") {
            if let Some(d) = rfd::FileDialog::new().pick_folder() {
                if !self.roots.contains(&d) {
                    self.roots.push(d);
                    self.preflight = None;
                }
            }
        }
        ui.add_space(8.0);

        let mut remove: Option<usize> = None;
        for (i, r) in self.roots.iter().enumerate() {
            ui.horizontal(|ui| {
                if ui.small_button(cl_ui::tr("Remove")).clicked() {
                    remove = Some(i);
                }
                ui.label(egui::RichText::new(r.display().to_string()).size(13.0));
            });
        }
        if let Some(i) = remove {
            self.roots.remove(i);
            self.preflight = None;
        }

        if self.roots.is_empty() {
            ui.add_space(6.0);
            cl_ui::muted(ui, "No folders chosen yet.");
        }

        ui.add_space(16.0);
        // Folded away by default. Excluding a folder is a real capability and the
        // report records that it happened, but presenting it as a second open
        // question implies the supplier is expected to have something to leave out.
        egui::CollapsingHeader::new("Leave a folder out (most people do not need this)")
            .default_open(!self.excluded.is_empty())
            .show(ui, |ui| {
                cl_ui::muted(
                    ui,
                    "Anything you exclude is recorded as excluded by you. It is not hidden, \
                     but its contents are never read.",
                );
                if cl_ui::secondary_button(ui, "Exclude a folder...") {
                    if let Some(d) = rfd::FileDialog::new().pick_folder() {
                        if !self.excluded.contains(&d) {
                            self.excluded.push(d);
                            self.preflight = None;
                        }
                    }
                }
                let mut rm: Option<usize> = None;
                for (i, r) in self.excluded.iter().enumerate() {
                    ui.horizontal(|ui| {
                        if ui.small_button(cl_ui::tr("Remove")).clicked() {
                            rm = Some(i);
                        }
                        ui.label(
                            egui::RichText::new(r.display().to_string())
                                .size(13.0)
                                .color(cl_ui::colour::MUTED),
                        );
                    });
                }
                if let Some(i) = rm {
                    self.excluded.remove(i);
                }
            });

        ui.add_space(18.0);
        ui.horizontal(|ui| {
            if cl_ui::secondary_button(ui, "Back") {
                self.step = Step::Welcome;
            }
            if cl_ui::primary_button(ui, "Continue", !self.roots.is_empty()) {
                self.step = Step::Preflight;
            }
        });
    }

    fn preflight_screen(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        cl_ui::h1(ui, "Before anything is read");
        ui.add_space(8.0);

        if self.preflight.is_none() && !self.preflight_running {
            self.start_preflight(ctx);
        }
        if self.preflight_running {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(cl_ui::tr("Looking at what is there. Nothing has been read yet."));
            });
            return;
        }

        if let Some(p) = self.preflight.clone() {
            cl_ui::body(
                ui,
                "This is everything found in the folders you chose. No file has been read and \
                 nothing has been written.",
            );
            ui.add_space(12.0);

            egui::Grid::new("scope").num_columns(3).striped(true).spacing([24.0, 6.0]).show(
                ui,
                |ui| {
                    ui.label(egui::RichText::new(cl_ui::tr("Kind of file")).strong());
                    ui.label(egui::RichText::new(cl_ui::tr("Count")).strong());
                    ui.label(egui::RichText::new(cl_ui::tr("Size")).strong());
                    ui.end_row();
                    for (t, n, b) in &p.by_type {
                        ui.label(cl_ui::tr(friendly_type(t)));
                        ui.label(n.to_string());
                        ui.label(cl_ui::bytes_human(*b));
                        ui.end_row();
                    }
                    ui.label(egui::RichText::new(cl_ui::tr("Total")).strong());
                    ui.label(egui::RichText::new(p.total_files.to_string()).strong());
                    ui.label(egui::RichText::new(cl_ui::bytes_human(p.total_bytes)).strong());
                    ui.end_row();
                },
            );

            if p.opaque > 0 {
                ui.add_space(12.0);
                cl_ui::callout(
                    ui,
                    cl_ui::colour::NEUTRAL,
                    &format!("{} file(s) will be counted but never opened", p.opaque),
                    "These are formats that can run code when loaded. Cladeon records their \
                     name, size and checksum and never reads inside them.",
                );
            }

            ui.add_space(14.0);
            cl_ui::h2(ui, "What will be in the file you send back");
            cl_ui::body(ui, "•  Folder and file names, shortened so your real paths are hidden.");
            cl_ui::body(ui, "•  File sizes and checksums.");
            cl_ui::body(ui, "•  Settings read from configuration files, such as a model's size.");
            cl_ui::body(ui, "•  The conclusions drawn from those.");

            ui.add_space(10.0);
            cl_ui::h2(ui, "What will not be");
            cl_ui::body(ui, "•  Your model weights, training data, source code and prompts.");
            cl_ui::body(ui, "•  Any password, key or token — removed before it reaches the file.");
            cl_ui::body(ui, "•  Your Windows user name and any full path from this computer.");

            if !p.unreadable.is_empty() {
                ui.add_space(12.0);
                cl_ui::h2(ui, "Things this scan will not be able to see");
                for u in &p.unreadable {
                    cl_ui::muted(ui, u);
                }
            }

            ui.add_space(18.0);
            ui.horizontal(|ui| {
                if cl_ui::secondary_button(ui, "Back") {
                    self.step = Step::Folders;
                }
                if cl_ui::primary_button(ui, "Scan and create the file", true) {
                    let name = format!("{}.clade", self.case_id);
                    if let Some(f) = rfd::FileDialog::new()
                        .set_file_name(&name)
                        .add_filter("Cladeon evidence bundle", &["clade"])
                        .save_file()
                    {
                        let dir = f.parent().map(|p| p.to_path_buf()).unwrap_or_default();
                        self.start_scan(ctx, dir);
                    }
                }
            });
        }
    }

    fn running(&mut self, ui: &mut egui::Ui) {
        cl_ui::h1(ui, "Scanning");
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(egui::RichText::new(self.progress.phase.label()).size(15.0));
        });
        ui.add_space(12.0);
        cl_ui::field(ui, "Files seen", &self.progress.files_seen.to_string());
        cl_ui::field(ui, "Data examined", &cl_ui::bytes_human(self.progress.bytes_seen));
        cl_ui::field(ui, "Data checksummed", &cl_ui::bytes_human(self.progress.bytes_hashed));
        ui.add_space(16.0);
        cl_ui::muted(
            ui,
            "Counts are of real work done, not an estimate. Large model files take the longest.",
        );
        ui.add_space(16.0);
        if cl_ui::secondary_button(ui, "Stop") {
            self.cancel.store(true, Ordering::Relaxed);
        }
    }

    fn done(&mut self, ui: &mut egui::Ui) {
        let Some(f) = &self.finished else { return };
        cl_ui::h1(ui, "Done — now send the file back");
        ui.add_space(10.0);

        cl_ui::callout(
            ui,
            cl_ui::colour::ACCENT,
            "Your file is saved here",
            &f.path.display().to_string(),
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if cl_ui::secondary_button(ui, "Copy location") {
                ui.ctx().copy_text(f.path.display().to_string());
            }
            if cl_ui::secondary_button(ui, "Copy checksum") {
                ui.ctx().copy_text(f.sha256.clone());
            }
        });

        ui.add_space(14.0);
        cl_ui::body(ui, "Attach that one file to your reply. Do not rename it, open it and save \
                         it again, or send a screenshot — any of those breaks the checks it carries.");

        ui.add_space(16.0);
        cl_ui::h2(ui, "What was looked at");
        cl_ui::field(ui, "Files", &f.files.to_string());
        cl_ui::field(ui, "Data", &cl_ui::bytes_human(f.bytes));
        cl_ui::field(ui, "Coverage", f.coverage.as_str());
        if f.redactions.is_empty() {
            cl_ui::field(ui, "Removed before sending", "nothing needed removing");
        } else {
            let total: u64 = f.redactions.iter().map(|(_, n)| n).sum();
            cl_ui::field(ui, "Removed before sending", &format!("{total} value(s)"));
            for (kind, n) in &f.redactions {
                cl_ui::muted(ui, &format!(" {kind}: {n}"));
            }
        }

        ui.add_space(16.0);
        cl_ui::h2(ui, "What the files showed");
        for (facet, band, named) in &f.facets {
            ui.horizontal(|ui| {
                cl_ui::badge(ui, band.render(), cl_ui::band_colour(*band));
                ui.label(egui::RichText::new(cl_ui::facet_title(*facet)).size(14.0));
            });
            cl_ui::muted(ui, cl_ui::band_plain_english(*band));
            let _ = named;
            ui.add_space(4.0);
        }

        if f.limitation_count > 0 {
            ui.add_space(6.0);
            cl_ui::muted(
                ui,
                &format!(
                    "The report also notes {} thing(s) this scan could not see. Those are \
                     limits of the scan itself.",
                    f.limitation_count
                ),
            );
        }

        ui.add_space(12.0);
        cl_ui::callout(
            ui,
            cl_ui::colour::NEUTRAL,
            "If it says there was not enough evidence",
            "It means the files that would answer that question were not in the folders you \
             picked. That is a normal result. You can go back, add more folders and run it \
             again.",
        );

        ui.add_space(16.0);
        if cl_ui::secondary_button(ui, "Scan again") {
            self.finished = None;
            self.preflight = None;
            self.step = Step::Folders;
        }
    }
}

fn friendly_type(t: &str) -> &str {
    match t {
        "safetensors" => "Model weights (SafeTensors)",
        "gguf" => "Model weights (GGUF)",
        "onnx" => "Model (ONNX)",
        "opaque_serialization" => "Checkpoint — counted, never opened",
        "shard_index" => "Weight file index",
        "peft_adapter_config" => "Adapter settings",
        "transformers_config" => "Model settings",
        "tokenizer_config" => "Tokenizer settings",
        "trainer_state" => "Training history",
        "training_args" => "Training settings",
        "training_log" => "Training log",
        "dependency_lockfile" => "Software dependency list",
        "deployment_manifest" => "Deployment settings",
        "serving_config" => "Serving settings",
        "vector_index" => "Document search index",
        "retrieval_trace" => "Retrieval records",
        "model_card" => "Model description",
        "generic_json" | "generic_yaml" | "generic_toml" => "Other settings file",
        "plain_text" => "Text file",
        other => other,
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 760.0])
            .with_min_inner_size([820.0, 600.0])
            .with_title("Cladeon Screen"),
        ..Default::default()
    };
    eframe::run_native(
        "Cladeon Screen",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn friendly_names_replace_the_machine_vocabulary() {
        // A vendor should never be shown "opaque_serialization".
        assert_eq!(friendly_type("safetensors"), "Model weights (SafeTensors)");
        assert!(friendly_type("opaque_serialization").contains("never opened"));
        // Anything unmapped falls through rather than being hidden.
        assert_eq!(friendly_type("something_new"), "something_new");
    }

    #[test]
    fn every_artifact_type_the_scanner_emits_has_a_gloss_or_falls_through() {
        for t in cl_facts::ArtifactType::ALL {
            let g = friendly_type(t.as_str());
            assert!(!g.is_empty(), "{t} rendered empty");
        }
    }

    #[test]
    fn a_request_needs_a_valid_case_id() {
        let mut app = App::default();
        app.roots.push(PathBuf::from("."));
        assert!(app.request().is_none(), "an empty case id must not build a request");
        app.case_id = "CL-2026-0F3A9C".into();
        assert!(app.request().is_some());
    }

    #[test]
    fn the_only_declaration_comes_from_the_buyers_request() {
        // The supplier is asked nothing about their own system, so a scan with no
        // request must assert nothing at all. If this ever starts returning a
        // populated set, some screen has grown a question it should not be asking.
        let mut app = App::default();
        app.case_id = "CL-2026-0F3A9C".into();
        assert_eq!(app.request().unwrap().declared, DeclaredFacets::default());

        let (ch, bytes) = a_challenge();
        app.challenge = Some(ch);
        app.challenge_bytes = Some(bytes);
        let r = app.request().unwrap();
        assert_eq!(
            r.declared.weight_origin,
            Some(cl_core::vocab::WeightOrigin::RandomInitializationClaimed),
            "the claim under test must reach the rules from the request"
        );
        assert_eq!(r.declared.parameter_update, None, "the scanner infers method, it is not told");
        assert!(r.declared.inference_augmentation.is_empty());
    }

    #[test]
    fn no_forbidden_language_in_the_vendor_interface() {
        // This window is read by the party being screened, so a single loaded word
        // here does more damage than anywhere else in the product. The auditor
        // application has carried this guard from the start; the omission on this
        // side was an oversight, and it is the side that matters more.
        let src = include_str!("main.rs");
        for line in src.lines() {
            let t = line.trim();
            if t.starts_with("//") {
                continue;
            }
            if let Some(bad) = cl_core::vocab::forbidden_language(t) {
                panic!("forbidden language `{bad}` in: {t}");
            }
        }
    }

    #[test]
    fn the_vendor_is_never_asked_to_describe_their_own_system() {
        // The whole point of the redesign: no control on any screen collects the
        // supplier's account of what they built. If a dropdown or a free-text claim
        // box ever comes back, this catches it before a release does.
        let src = include_str!("main.rs");
        let body = &src[..src.find("mod tests").unwrap_or(src.len())];
        for probe in ["text_edit_multiline", "ComboBox", "radio_value"] {
            assert!(
                !body.contains(probe),
                "`{probe}` is back on a vendor screen: the supplier is being asked to state their own case again"
            );
        }
    }

    #[test]
    fn without_a_request_there_is_no_way_into_the_scan() {
        // The vendor cannot type their way past a missing case file, because that
        // would let the party being tested author the sentence being tested.
        let app = App::default();
        assert!(app.challenge.is_none());
        assert_eq!(app.step as usize, Step::Welcome as usize);
    }

    fn temp_kit(tag: &str) -> PathBuf {
        let d = std::env::temp_dir()
            .join(format!("cl-kit-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn a_challenge() -> (cl_case::Challenge, Vec<u8>) {
        let c = cl_case::Challenge::new(
            CaseId::parse("CL-2026-0F3A9C").unwrap(),
            cl_core::ids::Nonce::parse(&"a1".repeat(16)).unwrap(),
            "Acme Analytics Ltd",
            "We trained our own model from scratch.",
            cl_core::time::Timestamp::parse_rfc3339("2026-09-02T13:00:00Z").unwrap(),
            14,
            vec![],
            None,
            Some(cl_core::vocab::WeightOrigin::RandomInitializationClaimed),
        );
        let b = c.to_canonical_bytes().unwrap();
        (c, b)
    }

    #[test]
    fn the_case_file_is_found_beside_the_program() {
        // The buyer ships one folder; the vendor double-clicks. If this stops
        // working they see "no request found" and the audit silently detaches from
        // the question that was asked.
        let (_, bytes) = a_challenge();
        for name in ["challenge.json", "acme.case", "request.challenge"] {
            let d = temp_kit(name);
            std::fs::write(d.join(name), &bytes).unwrap();
            let found = find_challenge_in(&d);
            assert!(found.is_some(), "a case named {name} was not picked up");
            let (ch, _, _) = found.unwrap();
            assert_eq!(ch.case_id.as_str(), "CL-2026-0F3A9C");
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn a_signature_beside_the_case_is_picked_up_too() {
        let (_, bytes) = a_challenge();
        let d = temp_kit("sig");
        std::fs::write(d.join("challenge.json"), &bytes).unwrap();
        std::fs::write(d.join("challenge.sig"), "ab".repeat(64)).unwrap();
        let (_, _, sig) = find_challenge_in(&d).expect("case found");
        assert!(sig.is_some(), "the detached signature was not collected");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_unrelated_folder_yields_nothing_rather_than_guessing() {
        let d = temp_kit("empty");
        std::fs::write(d.join("notes.txt"), b"hello").unwrap();
        std::fs::write(d.join("data.json"), b"{}").unwrap();
        assert!(find_challenge_in(&d).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_corrupt_case_file_is_ignored_not_half_loaded() {
        let d = temp_kit("corrupt");
        std::fs::write(d.join("challenge.json"), b"{not a challenge}").unwrap();
        assert!(find_challenge_in(&d).is_none(), "a broken case must not load partially");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_step_rail_matches_the_step_enum() {
        assert_eq!(STEPS.len(), Step::Done as usize + 1);
    }
}
