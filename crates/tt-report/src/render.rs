//! Rendering the report as a PDF.
//!
//! The PDF is a *view*. `report.json` is the authoritative document, and every page
//! here says so, because the failure mode this product most needs to survive is a
//! buyer being sent a screenshot or a re-exported PDF and treating it as the record.
//!
//! ## What the layout is arguing
//!
//! The order of sections is deliberate. A reader who stops after page one should
//! come away with the right impression, so page one carries the assurance level and
//! the unavoidable limitation *before* it carries any conclusion. A reader who goes
//! further finds declared facts and observed facts kept visibly apart, then the
//! inferences drawn from them, then — at equal prominence — what was missing, what
//! was ambiguous, and what the scanner could not see.
//!
//! Negative space is given the same typographic weight as findings. A section headed
//! "Missing evidence" that is as long and as prominent as the conclusions is the
//! honest shape for a screen whose most common correct answer is "not enough here".

use crate::pdf::PdfBuilder;
use crate::Report;
use tt_core::canon::CanonValue;
use tt_core::hash::Digest;
use tt_core::raster::Raster;
use tt_core::vocab::{Facet, OutcomeKind, SupportBand};
use tt_facts::FactSet;
use tt_rules::RuleReport;

/// Rows of a facet summary table, in a fixed order so two reports compare by eye.
const FACET_ORDER: &[Facet] = &[
    Facet::WeightOrigin,
    Facet::ParameterUpdate,
    Facet::TrainingStage,
    Facet::InferenceAugmentation,
];

fn facet_title(f: Facet) -> &'static str {
    match f {
        Facet::WeightOrigin => "Weight origin",
        Facet::ParameterUpdate => "Parameter update",
        Facet::TrainingStage => "Training stage",
        Facet::InferenceAugmentation => "Inference augmentation",
    }
}

fn str_field(v: &CanonValue, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

/// Render the report to PDF bytes.
///
/// `carrier` is the tint-marker raster, drawn in the footer of every page. It is
/// optional: a report with no marker is a perfectly valid report, and the verifier
/// reports `marker_status = absent` rather than treating it as a fault.
pub fn render(
    report: &Report,
    rules: &RuleReport,
    facts: &FactSet,
    carrier: Option<Raster>,
) -> Vec<u8> {
    let v = &report.value;
    let mut b = PdfBuilder::new(
        "Model Provenance Screening Report",
        "report.json is authoritative. This PDF is a rendering of it.",
    );
    if let Some(c) = carrier {
        b.set_footer_raster(c);
    }

    // ---- page 1 ----------------------------------------------------------
    b.heading(1, "Model Provenance Screening Report");
    b.key_value("Case", &str_field(v, "case_id"));
    b.key_value("Vendor", &str_field(v, "vendor_label"));
    b.key_value("Scanner", &format!("{} {}", tt_core::SCANNER_NAME, tt_core::PRODUCT_VERSION));
    b.key_value(
        "Ruleset",
        &format!(
            "ruleset {} / vocabulary {} / schema {}",
            tt_core::RULESET_VERSION,
            tt_core::VOCABULARY_VERSION,
            tt_core::SCHEMA_VERSION
        ),
    );
    b.key_value("Assurance level", "Vendor self-scan");
    b.rule();

    b.heading(2, "The claim under test");
    b.paragraph(&str_field(v, "exact_claim_text"));
    b.rule();

    b.heading(2, "What this report is");
    b.paragraph(tt_core::REQUIRED_STATEMENT);
    b.paragraph(
        "It is a consistency screen. It reports how well the artifacts the vendor \
         chose to supply fit the way they say the system was built. Where the \
         evidence does not settle a question, it says so rather than guessing.",
    );
    b.rule();

    b.heading(2, "Lineage summary");
    let mut rows: Vec<Vec<String>> = Vec::new();
    for f in FACET_ORDER {
        let c = rules.conclusion(*f);
        let band = c.map(|c| c.band).unwrap_or(SupportBand::InsufficientEvidence);
        let claim = c
            .and_then(|c| c.claim)
            .filter(|_| c.map(|c| c.method_label_emitted).unwrap_or(false))
            .map(|c| c.render().to_string())
            .unwrap_or_else(|| "not named".to_string());
        let score = c.map(|c| c.score_tenths).unwrap_or(0);
        rows.push(vec![
            facet_title(*f).to_string(),
            claim,
            band.render().to_string(),
            format!("{}.{}", score / 10, score % 10),
        ]);
    }
    b.table(&["Facet", "Method named", "Support", "Score"], &rows);
    b.paragraph(
        "The score is a rubric-based support score out of 100. It is not a \
         probability that the claim is true, and it is not calibrated confidence. A \
         method is named only when the evidence clears every gate in the ruleset; \
         \"not named\" means the report declines to name one, not that the vendor \
         did something else.",
    );

    b.page_break();

    // ---- declared versus observed ---------------------------------------
    b.heading(1, "Evidence");
    b.heading(2, "What the vendor declared");
    let d = &facts.declared;
    b.key_value(
        "Weight origin",
        d.weight_origin.map(|x| x.as_str()).unwrap_or("not declared"),
    );
    b.key_value(
        "Parameter update",
        d.parameter_update.map(|x| x.as_str()).unwrap_or("not declared"),
    );
    b.key_value(
        "Training stage",
        d.training_stage.map(|x| x.as_str()).unwrap_or("not declared"),
    );
    let aug = if d.inference_augmentation.is_empty() {
        "not declared".to_string()
    } else {
        d.inference_augmentation.iter().map(|a| a.as_str()).collect::<Vec<_>>().join(", ")
    };
    b.key_value("Inference augmentation", &aug);

    b.heading(2, "What was observed");
    b.key_value("Artifacts inspected", &facts.artifacts.len().to_string());
    b.key_value("Normalised observations", &facts.facts.len().to_string());
    if let Some(scope) = v.get("scope") {
        for (label, key) in [
            ("Files enumerated", "files_enumerated"),
            ("Files hashed", "files_hashed"),
            ("Bytes enumerated", "bytes_enumerated"),
            ("Bytes hashed", "bytes_hashed"),
        ] {
            if let Some(n) = scope.get(key).and_then(|x| x.as_int()) {
                b.key_value(label, &n.to_string());
            }
        }
        if let Some(c) = scope.get("coverage_status").and_then(|x| x.as_str()) {
            b.key_value("Coverage", c);
        }
    }

    let supporting: Vec<&tt_rules::RuleOutcome> =
        rules.outcomes.iter().filter(|o| o.kind == OutcomeKind::SupportingEvidence).collect();
    if !supporting.is_empty() {
        b.heading(2, "Supporting evidence");
        for o in &supporting {
            b.bullet(&format!("[{}] {}", o.rule_id, o.text));
        }
    }

    // ---- negative space, at equal weight --------------------------------
    section(&mut b, rules, OutcomeKind::Contradiction, "Contradictions",
        "A contradiction is a conflict between an exact claim and an observed \
         artifact. It is not a finding about intent.");
    section(&mut b, rules, OutcomeKind::MissingAnchor, "Missing evidence",
        "Missing evidence is not a contradiction. Each item below caps how far the \
         supporting score can rise; none of them counts against the vendor.");
    section(&mut b, rules, OutcomeKind::Ambiguity, "Ambiguities",
        "Each observation below is compatible with more than one explanation.");
    section(&mut b, rules, OutcomeKind::CoverageLimitation, "What this scan could not see",
        "These are limitations of the scanner and of the selected scope.");
    section(&mut b, rules, OutcomeKind::NextEvidenceRequest, "Evidence that would resolve this",
        "Supplying the following would let a later scan reach a firmer conclusion.");

    b.page_break();

    // ---- per-facet detail ------------------------------------------------
    b.heading(1, "Facet detail");
    for f in FACET_ORDER {
        let Some(c) = rules.conclusion(*f) else { continue };
        b.heading(2, facet_title(*f));
        b.key_value("Support", c.band.render());
        b.key_value("Score", &format!("{}.{} of 100", c.score_tenths / 10, c.score_tenths % 10));
        b.key_value("Method named", if c.method_label_emitted { "yes" } else { "no" });
        if let Some(t) = c.best_tier {
            b.key_value("Best evidence tier", &format!("{} - {}", t.as_str(), t.describe()));
        }
        if !c.anchors.is_empty() {
            let rows: Vec<Vec<String>> = c
                .anchors
                .iter()
                .map(|a| {
                    vec![
                        a.anchor.to_string(),
                        a.weight.to_string(),
                        a.achievement.to_string(),
                        a.witness_rule.unwrap_or("-").to_string(),
                    ]
                })
                .collect();
            b.table(&["Anchor", "Weight", "Achieved", "By rule"], &rows);
        }
        for cap in &c.caps {
            b.bullet(&format!(
                "Capped at {}.{} by {}: {}",
                cap.max_tenths / 10,
                cap.max_tenths % 10,
                cap.cap_id.as_str(),
                cap.cap_id.render()
            ));
        }
        for a in &c.abstentions {
            b.bullet(&format!("Abstained ({}): {}", a.as_str(), a.render()));
        }
        if !c.alternatives.is_empty() {
            b.paragraph("Alternatives considered and their scores:");
            for (claim, score) in &c.alternatives {
                b.bullet(&format!("{} - {}.{}", claim.render(), score / 10, score % 10));
            }
        }
    }

    b.page_break();

    // ---- privacy ---------------------------------------------------------
    b.heading(1, "Privacy and redaction");
    b.paragraph(
        "Absolute paths were replaced by scoped aliases and candidate credentials \
         were removed before anything entered this report. The vendor may hide a \
         value; the fact that something was hidden is recorded and is not \
         removable.",
    );
    if let Some(ledger) = v.get("redaction_ledger").and_then(|l| l.as_arr()) {
        if ledger.is_empty() {
            b.paragraph("No redactions were applied.");
        } else {
            let rows: Vec<Vec<String>> = ledger
                .iter()
                .map(|e| {
                    vec![
                        str_field(e, "rule"),
                        str_field(e, "kind"),
                        e.get("count").and_then(|c| c.as_int()).unwrap_or(0).to_string(),
                    ]
                })
                .collect();
            b.table(&["Rule", "Kind", "Count"], &rows);
        }
    }

    b.heading(1, "Integrity");
    b.key_value("Evidence digest", &str_field(v, "evidence_digest"));
    b.key_value("Artifact manifest", &str_field(v, "artifact_manifest_sha256"));
    b.paragraph(
        "These digests bind this report to the bytes observed during the scan. They \
         are self-consistency, not independent proof of origin: the scanner ran \
         offline on a machine the vendor controls. Verify the bundle with TrainTrace \
         Verify, which re-derives the conclusions from the report's own observations \
         rather than trusting the numbers printed here.",
    );

    b.build(&doc_id(report))
}

/// One outcome section, emitted only when it has content.
fn section(
    b: &mut PdfBuilder,
    rules: &RuleReport,
    kind: OutcomeKind,
    title: &str,
    preamble: &str,
) {
    let items: Vec<&tt_rules::RuleOutcome> =
        rules.outcomes.iter().filter(|o| o.kind == kind).collect();
    b.heading(2, title);
    if items.is_empty() {
        b.paragraph("None.");
        return;
    }
    b.paragraph(preamble);
    for o in items {
        b.bullet(&format!("[{}] {}", o.rule_id, o.text));
        for d in &o.artifact_sha256 {
            b.bullet(&format!("    artifact {d}"));
        }
    }
}

/// A deterministic document id derived from the report itself.
fn doc_id(report: &Report) -> Digest {
    report.digest()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::extract_text;
    use crate::{HostInfo, ReportInput, ScopeInfo};
    use tt_core::hash::HashScope;
    use tt_core::ids::CaseId;
    use tt_core::time::Timestamp;
    use tt_core::vocab::CoverageStatus;
    use tt_facts::{ArtifactRecord, ArtifactType, Fact, FactKind, ReadStatus};

    fn ts(s: &str) -> Timestamp {
        Timestamp::parse_rfc3339(s).unwrap()
    }

    fn facts() -> FactSet {
        let mut f = FactSet::new();
        f.declared.parameter_update = Some(tt_core::vocab::ParameterUpdate::UnmergedPeftObserved);
        f.push_artifact(ArtifactRecord {
            artifact_id: "A-0001".into(),
            path_alias: "ROOT1/adapter/adapter_model.safetensors".into(),
            artifact_type: ArtifactType::SafeTensors,
            size_bytes: 4096,
            sha256: Some(Digest::of(b"adapter")),
            hash_scope: HashScope::Full,
            parser: Some("safetensors_header"),
            parser_version: 1,
            read_status: ReadStatus::Ok,
            changed_during_scan: false,
            mtime: None,
        });
        f.push_fact(
            Fact::new("F-0001", FactKind::AdapterConfig, "dir::ROOT1/adapter")
                .with_artifact("A-0001")
                .with("peft_type", "LORA")
                .with("r", 16i64),
        );
        f
    }

    fn built() -> (Report, RuleReport, FactSet) {
        let f = facts();
        let rules = tt_rules::evaluate(&f);
        let case = CaseId::parse("TT-2026-0F3A9C").unwrap();
        let r = crate::build(ReportInput {
            case_id: &case,
            challenge_sha256: None,
            vendor_label: "Acme Analytics Ltd",
            exact_claim_text: "We fine-tuned an open base model with LoRA.",
            scanner_build_sha256: None,
            host: HostInfo {
                os: "Windows 11".into(),
                os_build: "26200".into(),
                arch: "x86_64".into(),
                started_at: ts("2026-09-02T13:14:00Z"),
                finished_at: ts("2026-09-02T13:16:42Z"),
            },
            facts: &f,
            rules: &rules,
            scope: ScopeInfo {
                selected_roots: vec!["ROOT1".into()],
                coverage_status: CoverageStatus::Complete,
                ..Default::default()
            },
            redaction_ledger: Vec::new(),
        })
        .unwrap();
        (r, rules, f)
    }

    #[test]
    fn the_rendered_document_carries_the_required_statement() {
        let (r, rules, f) = built();
        let pdf = render(&r, &rules, &f, None);
        let text = extract_text(&pdf).unwrap();
        // The statement wraps across lines, so check a distinctive phrase from it.
        assert!(text.contains("consistency within"), "{text}");
        assert!(text.contains("Vendor self-scan"));
    }

    #[test]
    fn every_facet_appears_in_the_summary() {
        let (r, rules, f) = built();
        let text = extract_text(&render(&r, &rules, &f, None)).unwrap();
        for facet in FACET_ORDER {
            assert!(text.contains(facet_title(*facet)), "missing {}", facet_title(*facet));
        }
    }

    #[test]
    fn negative_space_is_rendered_even_when_empty() {
        // "None." under a heading is the point: a reader must see that the question
        // was asked, not be left to infer it from a missing section.
        let (r, rules, f) = built();
        let text = extract_text(&render(&r, &rules, &f, None)).unwrap();
        for heading in [
            "Contradictions",
            "Missing evidence",
            "Ambiguities",
            "What this scan could not see",
        ] {
            assert!(text.contains(heading), "missing section {heading}");
        }
    }

    #[test]
    fn the_rendering_says_it_is_not_authoritative() {
        let (r, rules, f) = built();
        let text = extract_text(&render(&r, &rules, &f, None)).unwrap();
        assert!(text.contains("report.json"), "the PDF must name the authoritative document");
    }

    #[test]
    fn rendered_text_uses_no_forbidden_language() {
        let (r, rules, f) = built();
        let text = extract_text(&render(&r, &rules, &f, None)).unwrap();
        assert_eq!(tt_core::vocab::forbidden_language(&text), None);
    }

    #[test]
    fn rendering_is_deterministic() {
        let (r, rules, f) = built();
        assert_eq!(render(&r, &rules, &f, None), render(&r, &rules, &f, None));
    }

    #[test]
    fn a_footer_carrier_survives_the_round_trip() {
        let (r, rules, f) = built();
        let carrier = tt_markers::build_carrier(
            &[7u8; 16],
            240,
            40,
            tt_markers::tint::RECOMMENDED_BASE,
        );
        let pdf = render(&r, &rules, &f, Some(carrier.clone()));
        let back = crate::pdf::extract_footer_raster(&pdf).unwrap().expect("carrier present");
        assert_eq!(back, carrier);
        let d = tt_markers::detect(&back, &[7u8; 16]);
        assert!(d.matched, "marker must survive being written into and read out of the PDF");
    }

    #[test]
    fn an_empty_scan_still_renders_a_complete_document() {
        let f = FactSet::new();
        let rules = tt_rules::evaluate(&f);
        let case = CaseId::parse("TT-2026-000000").unwrap();
        let r = crate::build(ReportInput {
            case_id: &case,
            challenge_sha256: None,
            vendor_label: "Nobody Ltd",
            exact_claim_text: "We trained it ourselves.",
            scanner_build_sha256: None,
            host: HostInfo {
                os: "Windows 11".into(),
                os_build: "26200".into(),
                arch: "x86_64".into(),
                started_at: ts("2026-09-02T13:14:00Z"),
                finished_at: ts("2026-09-02T13:14:01Z"),
            },
            facts: &f,
            rules: &rules,
            scope: ScopeInfo::default(),
            redaction_ledger: Vec::new(),
        })
        .unwrap();
        let text = extract_text(&render(&r, &rules, &f, None)).unwrap();
        assert!(text.contains("Lineage summary"));
        assert!(text.contains("We trained it ourselves"));
    }
}
