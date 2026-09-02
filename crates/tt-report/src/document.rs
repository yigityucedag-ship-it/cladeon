//! Assembly of `report.json`, the authoritative document.
//!
//! The PDF is a rendering; this is the thing that is hashed, cited and verified.
//!
//! ## The reproducibility split
//!
//! The plan requires that two scans of unchanged evidence agree. That cannot mean
//! "the whole report is identical" — a report contains the time the scan started and
//! the nonce of the case, and both must differ. So the document is deliberately
//! divided:
//!
//! * **Analytical fields** — declared facets, observations, rule outcomes,
//!   conclusions, and the artifact manifest digest. These are covered by
//!   [`Report::evidence_digest`] and must be byte-identical across runs.
//! * **Situational fields** — host, timestamps, case identity, redaction counts.
//!   These live in the report but outside the evidence digest.
//!
//! A verifier can therefore say "this is the same finding as last week" without
//! being confused by the clock, and equally cannot be fooled by a report that kept
//! the timestamps and changed the conclusions.

use tt_core::canon::{arr, CanonValue, Obj};
use tt_core::error::{TtError, TtResult};
use tt_core::hash::Digest;
use tt_core::ids::CaseId;
use tt_core::redact::RedactionEvent;
use tt_core::time::Timestamp;
use tt_core::vocab::{self, CoverageStatus};
use tt_facts::FactSet;
use tt_rules::RuleReport;

#[derive(Debug, Clone)]
pub struct HostInfo {
    pub os: String,
    pub os_build: String,
    pub arch: String,
    pub started_at: Timestamp,
    pub finished_at: Timestamp,
}

impl HostInfo {
    fn to_canon(&self) -> CanonValue {
        CanonValue::Obj(
            Obj::new()
                .with("os", self.os.as_str())
                .with("os_build", self.os_build.as_str())
                .with("arch", self.arch.as_str())
                .with("scanner_started_at", self.started_at.to_rfc3339())
                .with("scanner_finished_at", self.finished_at.to_rfc3339()),
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScopeInfo {
    pub selected_roots: Vec<String>,
    pub excluded_paths: Vec<String>,
    pub bytes_enumerated: u64,
    pub bytes_hashed: u64,
    pub files_enumerated: u64,
    pub files_hashed: u64,
    pub coverage_status: CoverageStatus,
}

impl ScopeInfo {
    fn to_canon(&self) -> CanonValue {
        let roots: Vec<CanonValue> = self
            .selected_roots
            .iter()
            .map(|a| CanonValue::Obj(Obj::new().with("alias", a.as_str())))
            .collect();
        let excluded: Vec<CanonValue> = self
            .excluded_paths
            .iter()
            .map(|a| {
                CanonValue::Obj(
                    Obj::new().with("alias", a.as_str()).with("reason", "excluded_by_submitter"),
                )
            })
            .collect();
        CanonValue::Obj(
            Obj::new()
                .with("selected_roots", CanonValue::Arr(roots))
                .with("excluded_paths", CanonValue::Arr(excluded))
                .with("bytes_enumerated", self.bytes_enumerated)
                .with("bytes_hashed", self.bytes_hashed)
                .with("files_enumerated", self.files_enumerated)
                .with("files_hashed", self.files_hashed)
                .with("coverage_status", self.coverage_status),
        )
    }
}

pub struct ReportInput<'a> {
    pub case_id: &'a CaseId,
    pub challenge_sha256: Option<Digest>,
    pub vendor_label: &'a str,
    pub exact_claim_text: &'a str,
    pub scanner_build_sha256: Option<Digest>,
    pub host: HostInfo,
    pub facts: &'a FactSet,
    pub rules: &'a RuleReport,
    pub scope: ScopeInfo,
    pub redaction_ledger: Vec<RedactionEvent>,
}

#[derive(Debug, Clone)]
pub struct Report {
    /// The authoritative document.
    pub value: CanonValue,
    /// `artifact-manifest.json`, hashed into the report.
    pub artifact_manifest: CanonValue,
    /// Digest over the analytical subset only. Stable across scans.
    pub evidence_digest: Digest,
}

impl Report {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.value.to_canonical_bytes()
    }
    pub fn digest(&self) -> Digest {
        self.value.digest()
    }
}

fn ledger_canon(events: &[RedactionEvent]) -> CanonValue {
    let mut rows: Vec<&RedactionEvent> = events.iter().collect();
    rows.sort_by(|a, b| a.rule.cmp(b.rule).then(a.kind.cmp(b.kind)));
    CanonValue::Arr(
        rows.iter()
            .map(|e| {
                CanonValue::Obj(
                    Obj::new().with("rule", e.rule).with("kind", e.kind).with("count", e.count),
                )
            })
            .collect(),
    )
}

/// The subset of the report that must be identical for identical evidence.
fn evidence_subset(
    facts: &FactSet,
    rules: &RuleReport,
    artifact_manifest_sha256: Digest,
) -> CanonValue {
    CanonValue::Obj(
        Obj::new()
            .with("declared_facets", facts.declared.to_canon())
            .with("observations", facts.observations_canon())
            .with("rule_outcomes", rules.outcomes_canon())
            .with("claim_scores", rules.claim_scores_canon())
            .with("conclusions", rules.conclusions_canon())
            .with("artifact_manifest_sha256", artifact_manifest_sha256),
    )
}

/// Build the authoritative report.
///
/// Fails if any rendered string contains language the product is not permitted to
/// use. That check runs over the assembled document rather than at each call site,
/// because a guard you have to remember to call is not a guard.
pub fn build(input: ReportInput<'_>) -> TtResult<Report> {
    let artifact_manifest = input.facts.artifact_manifest_canon();
    let manifest_digest = artifact_manifest.digest();

    let subset = evidence_subset(input.facts, input.rules, manifest_digest);
    let evidence_digest = subset.digest();

    let coverage: Vec<CanonValue> =
        input.facts.coverage.iter().map(|c| c.to_canon()).collect();

    let mut o = Obj::new()
        .with("schema_version", tt_core::SCHEMA_VERSION)
        .with("vocabulary_version", tt_core::VOCABULARY_VERSION)
        .with("ruleset_version", tt_core::RULESET_VERSION)
        .with("rubric_version", tt_core::RUBRIC_VERSION)
        .with("scanner_name", tt_core::SCANNER_NAME)
        .with("scanner_version", tt_core::PRODUCT_VERSION)
        .with("case_id", input.case_id)
        .with("vendor_label", input.vendor_label)
        .with("exact_claim_text", input.exact_claim_text)
        .with("assurance_level", vocab::ASSURANCE_LEVEL)
        .with("scan_mode", "offline_default")
        // Stage 1 opens no socket. This is a statement about the build, not a
        // runtime observation, and it is asserted by a test over the dependency set.
        .with("network_enabled", false)
        .with("host", input.host.to_canon())
        .with("declared_facets", input.facts.declared.to_canon())
        .with("scope", input.scope.to_canon())
        .with("redaction_ledger", ledger_canon(&input.redaction_ledger))
        .with("observations", input.facts.observations_canon())
        .with("coverage_notes", CanonValue::Arr(coverage))
        .with("rule_outcomes", input.rules.outcomes_canon())
        .with("claim_scores", input.rules.claim_scores_canon())
        .with("conclusions", input.rules.conclusions_canon())
        .with(
            "contradictions",
            arr(input.rules.contradictions().into_iter().map(|s| s.to_string()).collect::<Vec<_>>()),
        )
        .with(
            "ambiguities",
            arr(input.rules.ambiguities().into_iter().map(|s| s.to_string()).collect::<Vec<_>>()),
        )
        .with(
            "limitations",
            arr(input.rules.limitations().into_iter().map(|s| s.to_string()).collect::<Vec<_>>()),
        )
        .with(
            "next_evidence_requests",
            arr(input
                .rules
                .next_evidence_requests()
                .into_iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()),
        )
        .with("required_statement", tt_core::REQUIRED_STATEMENT)
        .with("artifact_manifest_sha256", manifest_digest)
        .with("evidence_digest", evidence_digest);

    if let Some(d) = input.challenge_sha256 {
        o.set("challenge_sha256", d);
    }
    if let Some(d) = input.scanner_build_sha256 {
        o.set("scanner_build_sha256", d);
    }

    let value = CanonValue::Obj(o);

    // The language guard, applied to text TrainTrace *wrote*.
    //
    // It deliberately does not run over the whole document. `vendor_label`,
    // `exact_claim_text` and every observed field value are verbatim vendor input,
    // and the report is obliged to reproduce them unchanged. A company legitimately
    // named "Certified Systems Ltd", or a vendor whose own claim says "we guarantee
    // this model is original", must not make the scanner refuse to produce a report
    // — and quoting them is not the tool adopting their words. The rule is about
    // TrainTrace's stance, so it binds TrainTrace's own sentences.
    let mut authored = input.rules.all_text();
    authored.push_str(tt_core::REQUIRED_STATEMENT);
    authored.push('\n');
    for c in &input.facts.coverage {
        authored.push_str(&c.detail);
        authored.push('\n');
    }
    if let Some(bad) = vocab::forbidden_language(&authored) {
        return Err(TtError::contract(format!(
            "report contains prohibited language `{bad}` in authored text"
        )));
    }

    Ok(Report { value, artifact_manifest, evidence_digest })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tt_facts::{ArtifactRecord, ArtifactType, Fact, FactKind, ReadStatus};
    use tt_core::hash::HashScope;

    fn ts(s: &str) -> Timestamp {
        Timestamp::parse_rfc3339(s).unwrap()
    }

    fn host(started: &str) -> HostInfo {
        HostInfo {
            os: "Windows 11".into(),
            os_build: "26200".into(),
            arch: "x86_64".into(),
            started_at: ts(started),
            finished_at: ts("2026-09-02T13:16:42Z"),
        }
    }

    fn facts() -> FactSet {
        let mut f = FactSet::new();
        f.exact_claim_text = "We fine-tuned an open base model with LoRA.".into();
        f.push_artifact(ArtifactRecord {
            artifact_id: "A-0001".into(),
            path_alias: "ROOT1/adapter/adapter_model.safetensors".into(),
            artifact_type: ArtifactType::SafeTensors,
            size_bytes: 1024,
            sha256: Some(Digest::of(b"tensors")),
            hash_scope: HashScope::Full,
            parser: Some("safetensors_header"),
            parser_version: 1,
            read_status: ReadStatus::Ok,
            changed_during_scan: false,
            mtime: Some(ts("2026-08-01T00:00:00Z")),
        });
        f.push_fact(
            Fact::new("F-0001", FactKind::AdapterConfig, "dir::ROOT1/adapter")
                .with_artifact("A-0001")
                .with("peft_type", "LORA")
                .with("r", 16i64),
        );
        f
    }

    fn input<'a>(
        case: &'a CaseId,
        f: &'a FactSet,
        r: &'a RuleReport,
        started: &str,
    ) -> ReportInput<'a> {
        ReportInput {
            case_id: case,
            challenge_sha256: None,
            vendor_label: "Acme Analytics Ltd",
            exact_claim_text: "We fine-tuned an open base model with LoRA.",
            scanner_build_sha256: None,
            host: host(started),
            facts: f,
            rules: r,
            scope: ScopeInfo {
                selected_roots: vec!["ROOT1".into()],
                coverage_status: CoverageStatus::Complete,
                ..Default::default()
            },
            redaction_ledger: vec![RedactionEvent {
                rule: "TT-PRIV-002",
                kind: "windows_username",
                count: 3,
            }],
        }
    }

    #[test]
    fn report_builds_and_is_canonical() {
        let case = CaseId::parse("TT-2026-0F3A9C").unwrap();
        let f = facts();
        let r = tt_rules::evaluate(&f);
        let rep = build(input(&case, &f, &r, "2026-09-02T13:14:00Z")).unwrap();
        let bytes = rep.to_canonical_bytes();
        // Round-trips through the strict canonical reader.
        tt_core::canon::parse_canonical(&bytes, &tt_core::limits::Limits::default()).unwrap();
    }

    #[test]
    fn evidence_digest_ignores_the_clock() {
        let case = CaseId::parse("TT-2026-0F3A9C").unwrap();
        let f = facts();
        let r = tt_rules::evaluate(&f);
        let a = build(input(&case, &f, &r, "2026-09-02T13:14:00Z")).unwrap();
        let b = build(input(&case, &f, &r, "2027-01-01T00:00:00Z")).unwrap();
        assert_eq!(a.evidence_digest, b.evidence_digest, "same evidence, same digest");
        assert_ne!(a.digest(), b.digest(), "but the documents do differ");
    }

    #[test]
    fn evidence_digest_moves_when_a_conclusion_moves() {
        let case = CaseId::parse("TT-2026-0F3A9C").unwrap();
        let f = facts();
        let r = tt_rules::evaluate(&f);
        let a = build(input(&case, &f, &r, "2026-09-02T13:14:00Z")).unwrap();

        let mut f2 = facts();
        f2.push_fact(
            Fact::new("F-0002", FactKind::AdapterTensorSet, "artifact::A-0001")
                .with_artifact("A-0001")
                .with("lora_pair_count", 224i64)
                .with("inferred_ranks", vec!["16".to_string()]),
        );
        let r2 = tt_rules::evaluate(&f2);
        let b = build(input(&case, &f2, &r2, "2026-09-02T13:14:00Z")).unwrap();
        assert_ne!(a.evidence_digest, b.evidence_digest);
    }

    #[test]
    fn every_facet_appears_in_the_conclusions() {
        let case = CaseId::parse("TT-2026-0F3A9C").unwrap();
        let f = facts();
        let r = tt_rules::evaluate(&f);
        let rep = build(input(&case, &f, &r, "2026-09-02T13:14:00Z")).unwrap();
        let concl = rep.value.get("conclusions").and_then(|c| c.as_arr()).unwrap();
        assert_eq!(concl.len(), vocab::Facet::ALL.len());
    }

    #[test]
    fn the_required_statement_is_present_verbatim() {
        let case = CaseId::parse("TT-2026-0F3A9C").unwrap();
        let f = facts();
        let r = tt_rules::evaluate(&f);
        let rep = build(input(&case, &f, &r, "2026-09-02T13:14:00Z")).unwrap();
        assert_eq!(
            rep.value.get("required_statement").and_then(|v| v.as_str()),
            Some(tt_core::REQUIRED_STATEMENT)
        );
    }

    #[test]
    fn assurance_level_is_always_vendor_self_scan() {
        let case = CaseId::parse("TT-2026-0F3A9C").unwrap();
        let f = facts();
        let r = tt_rules::evaluate(&f);
        let rep = build(input(&case, &f, &r, "2026-09-02T13:14:00Z")).unwrap();
        assert_eq!(
            rep.value.get("assurance_level").and_then(|v| v.as_str()),
            Some("vendor_self_scan")
        );
        assert_eq!(rep.value.get("network_enabled").and_then(|v| v.as_bool()), Some(false));
    }

    #[test]
    fn quoting_the_vendor_is_not_the_tool_adopting_their_words() {
        // A real company may be called this, and a real claim may overstate. The
        // report must reproduce both verbatim; the language rule governs what
        // TrainTrace itself asserts, not what it quotes.
        let case = CaseId::parse("TT-2026-0F3A9C").unwrap();
        let f = facts();
        let r = tt_rules::evaluate(&f);
        let mut inp = input(&case, &f, &r, "2026-09-02T13:14:00Z");
        inp.vendor_label = "Certified Systems Ltd";
        inp.exact_claim_text = "We guarantee this model is 100% accurate and authentic.";
        let rep = build(inp).expect("quoted vendor text must not fail the build");
        assert_eq!(
            rep.value.get("exact_claim_text").and_then(|v| v.as_str()),
            Some("We guarantee this model is 100% accurate and authentic."),
            "the claim under test must be reproduced exactly"
        );
        assert_eq!(
            rep.value.get("vendor_label").and_then(|v| v.as_str()),
            Some("Certified Systems Ltd")
        );
    }

    #[test]
    fn prohibited_language_in_authored_text_fails_the_build() {
        use tt_rules::RuleOutcome;
        let case = CaseId::parse("TT-2026-0F3A9C").unwrap();
        let f = facts();
        let mut r = tt_rules::evaluate(&f);
        // A rule that editorialises is a bug, and the build refuses it.
        r.outcomes.push(RuleOutcome::limitation(
            "TT-INV-002",
            "The vendor lied about the adapter.",
        ));
        let err = build(input(&case, &f, &r, "2026-09-02T13:14:00Z")).unwrap_err();
        assert!(matches!(err, TtError::ContractViolation { .. }), "{err:?}");
    }

    #[test]
    fn a_scan_that_found_nothing_still_produces_a_complete_report() {
        let case = CaseId::parse("TT-2026-0F3A9C").unwrap();
        let f = FactSet::new();
        let r = tt_rules::evaluate(&f);
        let rep = build(input(&case, &f, &r, "2026-09-02T13:14:00Z")).unwrap();
        let concl = rep.value.get("conclusions").and_then(|c| c.as_arr()).unwrap();
        assert_eq!(concl.len(), vocab::Facet::ALL.len());
        // Nothing in scope must read as "not supplied", never as a negative finding.
        for c in concl {
            let band = c.get("band").and_then(|b| b.as_str()).unwrap();
            assert!(
                band == "artifact_not_supplied_or_out_of_scope"
                    || band == "insufficient_evidence_abstained",
                "empty scan produced band {band}"
            );
        }
    }
}
