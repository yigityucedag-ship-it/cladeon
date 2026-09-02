//! Buyer-side verification of a `.ttscan`.
//!
//! ## Five answers, never merged into one
//!
//! A verdict like "valid" would be actively misleading here, because a bundle can be
//! byte-perfect and evidentially worthless at the same time. So verification reports
//! five independent axes and refuses to collapse them:
//!
//! * `integrity` — did these bytes survive unchanged since export?
//! * `challenge` — was this scan answering a question the buyer actually asked?
//! * `marker`    — do the rendering tripwires still agree with the report?
//! * `coverage`  — how much did the scanner get to see?
//! * `evidence`  — how well does the evidence support the claim?
//!
//! An intact bundle whose evidence is thin reports `integrity: intact` **and**
//! `evidence: insufficient_evidence_abstained`. Both are true; neither cancels the
//! other.
//!
//! ## Recomputation is the part that matters
//!
//! Hashes only prove a file has not changed since *someone* computed them, and that
//! someone ran an offline scanner on their own machine. The check with real teeth is
//! different: parse the observations back out of `report.json`, re-run the ruleset
//! over them, and compare the conclusions with the ones the report states.
//!
//! That catches the edit an attacker actually wants to make — leaving the evidence
//! alone and improving the verdict — and it catches it even when every hash in the
//! bundle was recomputed to match, because the verifier holds the ruleset and the
//! vendor's edited numbers have to survive it.

use tt_core::canon::{CanonValue, Obj};
use tt_core::error::{TtError, TtResult};
use tt_core::hash::Digest;
use tt_core::ids::CaseId;
use tt_core::limits::{BundleLimits, Limits};
use tt_core::time::Timestamp;
use tt_core::vocab::{
    ChallengeStatus, CoverageStatus, IntegrityStatus, MarkerStatus, SupportBand,
};
use tt_facts::{
    ArtifactRecord, ArtifactType, DeclaredFacets, Fact, FactKind, FactSet, FieldValue, ReadStatus,
};

/// Whether the report's stated conclusions follow from its own observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recomputation {
    /// Re-running the ruleset over the report's observations reproduces its conclusions.
    Matches,
    /// The report states conclusions the ruleset does not produce from its own evidence.
    Diverges { detail: String },
    /// The report could not be re-evaluated, and says why.
    NotPossible { reason: String },
}

impl Recomputation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Recomputation::Matches => "matches",
            Recomputation::Diverges { .. } => "diverges",
            Recomputation::NotPossible { .. } => "not_possible",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Verification {
    pub case_id: Option<String>,
    pub vendor_label: Option<String>,
    pub exact_claim_text: Option<String>,
    pub integrity: IntegrityStatus,
    pub challenge: ChallengeStatus,
    pub marker: MarkerStatus,
    pub coverage: CoverageStatus,
    pub evidence: SupportBand,
    pub recomputation: Recomputation,
    /// Human-readable notes, each tied to a specific observation.
    pub findings: Vec<String>,
    /// Per-facet bands as stated by the report.
    pub facet_bands: Vec<(String, String)>,
    pub ruleset_version: Option<i64>,
    pub evidence_digest: Option<String>,
}

impl Verification {
    pub fn to_canon(&self) -> CanonValue {
        let facets: Vec<CanonValue> = self
            .facet_bands
            .iter()
            .map(|(f, b)| CanonValue::Obj(Obj::new().with("facet", f.as_str()).with("band", b.as_str())))
            .collect();
        CanonValue::Obj(
            Obj::new()
                .with("verifier_name", tt_core::VERIFIER_NAME)
                .with("verifier_version", tt_core::PRODUCT_VERSION)
                .with("integrity_status", self.integrity)
                .with("challenge_status", self.challenge)
                .with("marker_status", self.marker)
                .with("coverage_status", self.coverage)
                .with("evidence_status", self.evidence)
                .with("recomputation", self.recomputation.as_str())
                .with("facet_bands", CanonValue::Arr(facets))
                .with("findings", self.findings.clone())
                .with_opt("case_id", self.case_id.clone())
                .with_opt("vendor_label", self.vendor_label.clone())
                .with_opt("exact_claim_text", self.exact_claim_text.clone())
                .with_opt("ruleset_version", self.ruleset_version)
                .with_opt("evidence_digest", self.evidence_digest.clone()),
        )
    }

    /// A bundle is only fully trustworthy when nothing on any axis is amiss.
    pub fn all_clear(&self) -> bool {
        self.integrity == IntegrityStatus::Intact
            && self.recomputation == Recomputation::Matches
            && matches!(self.challenge, ChallengeStatus::Bound | ChallengeStatus::Unsigned)
    }
}

// ---------------------------------------------------------------------------
// Reconstructing facts from a report
// ---------------------------------------------------------------------------

fn field_from_canon(v: &CanonValue) -> Option<FieldValue> {
    Some(match v {
        CanonValue::Int(i) => FieldValue::Int(*i),
        CanonValue::Bool(b) => FieldValue::Bool(*b),
        // A `Num` was serialised as a string to keep it out of binary floating point,
        // so it returns as `Text`. Every rule reads both through the same accessor,
        // so the distinction cannot change an outcome — which is what makes the
        // recomputation comparison sound.
        CanonValue::Str(s) => FieldValue::Text(s.clone()),
        CanonValue::Arr(items) => FieldValue::List(
            items.iter().filter_map(|i| i.as_str().map(String::from)).collect(),
        ),
        _ => return None,
    })
}

/// Rebuild the fact set the scanner used, from the report and its manifest.
pub fn facts_from_report(report: &CanonValue, manifest: &CanonValue) -> TtResult<FactSet> {
    let mut fs = FactSet::new();

    if let Some(arts) = manifest.get("artifacts").and_then(|a| a.as_arr()) {
        for a in arts {
            let get = |k: &str| a.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            fs.push_artifact(ArtifactRecord {
                artifact_id: get("artifact_id"),
                path_alias: get("path_alias"),
                artifact_type: ArtifactType::parse(&get("artifact_type"))
                    .unwrap_or(ArtifactType::Unrecognised),
                size_bytes: a.get("size_bytes").and_then(|v| v.as_int()).unwrap_or(0).max(0) as u64,
                sha256: a.get("sha256").and_then(|v| v.as_str()).and_then(|s| Digest::from_hex(s).ok()),
                hash_scope: tt_core::hash::HashScope::Full,
                parser: None,
                parser_version: a.get("parser_version").and_then(|v| v.as_int()).unwrap_or(0),
                read_status: ReadStatus::parse(&get("read_status")).unwrap_or(ReadStatus::Ok),
                changed_during_scan: a
                    .get("changed_during_scan")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                mtime: a
                    .get("mtime")
                    .and_then(|v| v.as_str())
                    .and_then(|s| Timestamp::parse_rfc3339(s).ok()),
            });
        }
    }

    if let Some(obs) = report.get("observations").and_then(|o| o.as_arr()) {
        for o in obs {
            let kind = o
                .get("kind")
                .and_then(|v| v.as_str())
                .and_then(FactKind::parse)
                .ok_or_else(|| TtError::malformed("report", 0, "observation with unknown kind"))?;
            let mut f = Fact::new(
                o.get("fact_id").and_then(|v| v.as_str()).unwrap_or("F-0000"),
                kind,
                o.get("source_group").and_then(|v| v.as_str()).unwrap_or(""),
            );
            if let Some(a) = o.get("artifact_id").and_then(|v| v.as_str()) {
                f.artifact_id = Some(a.to_string());
            }
            if let Some(fields) = o.get("fields").and_then(|v| v.as_obj()) {
                for (k, v) in fields.iter() {
                    if let Some(fv) = field_from_canon(v) {
                        f.fields.insert(k.to_string(), fv);
                    }
                }
            }
            fs.push_fact(f);
        }
    }

    if let Some(d) = report.get("declared_facets") {
        let mut df = DeclaredFacets::default();
        df.weight_origin =
            d.get("weight_origin").and_then(|v| v.as_str()).and_then(tt_core::vocab::WeightOrigin::parse);
        df.parameter_update = d
            .get("parameter_update")
            .and_then(|v| v.as_str())
            .and_then(tt_core::vocab::ParameterUpdate::parse);
        df.training_stage = d
            .get("training_stage")
            .and_then(|v| v.as_str())
            .and_then(tt_core::vocab::TrainingStage::parse);
        if let Some(a) = d.get("inference_augmentation").and_then(|v| v.as_arr()) {
            df.inference_augmentation = a
                .iter()
                .filter_map(|x| x.as_str())
                .filter_map(tt_core::vocab::InferenceAugmentation::parse)
                .collect();
        }
        fs.declared = df;
    }

    fs.exact_claim_text = report
        .get("exact_claim_text")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(fs)
}

/// Re-run the ruleset over the report's own observations and compare.
pub fn recompute(report: &CanonValue, manifest: &CanonValue) -> Recomputation {
    let stated_version = report.get("ruleset_version").and_then(|v| v.as_int());
    if stated_version != Some(tt_core::RULESET_VERSION) {
        return Recomputation::NotPossible {
            reason: format!(
                "report was produced by ruleset version {} and this verifier holds version {}. \
                 Conclusions are not comparable across ruleset versions.",
                stated_version.map(|v| v.to_string()).unwrap_or_else(|| "(unstated)".into()),
                tt_core::RULESET_VERSION
            ),
        };
    }

    let facts = match facts_from_report(report, manifest) {
        Ok(f) => f,
        Err(e) => {
            return Recomputation::NotPossible {
                reason: format!("the report's observations could not be read back: {e}"),
            }
        }
    };

    let recomputed = tt_rules::evaluate(&facts);
    let stated = match report.get("conclusions") {
        Some(c) => c.clone(),
        None => {
            return Recomputation::NotPossible {
                reason: "the report states no conclusions".into(),
            }
        }
    };
    let ours = recomputed.conclusions_canon();

    if ours == stated {
        return Recomputation::Matches;
    }

    // Say precisely which facet moved, and in which direction. "Something differs"
    // would leave the reader unable to act.
    let mut diffs: Vec<String> = Vec::new();
    if let (Some(a), Some(b)) = (stated.as_arr(), ours.as_arr()) {
        for s in a {
            let facet = s.get("facet").and_then(|v| v.as_str()).unwrap_or("(unknown)");
            let said = s.get("band").and_then(|v| v.as_str()).unwrap_or("(none)");
            let said_score = s.get("score_tenths").and_then(|v| v.as_int());
            let mine = b.iter().find(|o| o.get("facet").and_then(|v| v.as_str()) == Some(facet));
            let got = mine.and_then(|m| m.get("band")).and_then(|v| v.as_str()).unwrap_or("(none)");
            let got_score = mine.and_then(|m| m.get("score_tenths")).and_then(|v| v.as_int());
            if said != got || said_score != got_score {
                diffs.push(format!(
                    "{facet}: report states `{said}` at {} tenths; re-evaluating the \
                     report's own observations gives `{got}` at {} tenths",
                    said_score.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
                    got_score.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
                ));
            }
        }
    }
    if diffs.is_empty() {
        diffs.push(
            "the conclusions block differs from a re-evaluation of the report's own \
             observations, in a field other than the band or the score"
                .to_string(),
        );
    }
    Recomputation::Diverges { detail: diffs.join("; ") }
}

// ---------------------------------------------------------------------------
// Whole-bundle verification
// ---------------------------------------------------------------------------

/// Verify a `.ttscan` from its raw bytes.
///
/// `now` is supplied rather than read from the clock so that verifying the same
/// bundle twice gives the same answer.
pub fn verify_bundle(
    bytes: &[u8],
    now: Timestamp,
    expected_case_id: Option<&CaseId>,
) -> Verification {
    let mut findings: Vec<String> = Vec::new();
    let mut v = Verification {
        case_id: None,
        vendor_label: None,
        exact_claim_text: None,
        integrity: IntegrityStatus::Unreadable,
        challenge: ChallengeStatus::Absent,
        marker: MarkerStatus::NotApplicable,
        coverage: CoverageStatus::Minimal,
        evidence: SupportBand::InsufficientEvidence,
        recomputation: Recomputation::NotPossible { reason: "bundle not read".into() },
        findings: Vec::new(),
        facet_bands: Vec::new(),
        ruleset_version: None,
        evidence_digest: None,
    };

    let payloads = match tt_bundle::read_archive(bytes, &BundleLimits::default()) {
        Ok(p) => p,
        Err(e) => {
            v.findings.push(format!("The bundle could not be read: {e}"));
            return v;
        }
    };

    let get = |name: &str| payloads.iter().find(|p| p.name == name).map(|p| p.bytes.clone());

    // ---- integrity ----
    match get(tt_bundle::INTEGRITY_ENVELOPE_JSON) {
        None => {
            v.integrity = IntegrityStatus::Incomplete;
            findings.push("The bundle contains no integrity envelope.".into());
        }
        Some(env_bytes) => match tt_core::canon::parse_canonical(&env_bytes, &Limits::default()) {
            Err(e) => {
                v.integrity = IntegrityStatus::Unreadable;
                findings.push(format!("The integrity envelope could not be read: {e}"));
            }
            Ok(env) => match tt_bundle::verify_envelope(&env, &payloads) {
                Err(e) => {
                    v.integrity = IntegrityStatus::Unreadable;
                    findings.push(format!("The integrity envelope is malformed: {e}"));
                }
                Ok(check) => {
                    if check.is_intact() {
                        v.integrity = IntegrityStatus::Intact;
                    } else if !check.missing.is_empty() {
                        v.integrity = IntegrityStatus::Incomplete;
                        findings.push(format!(
                            "Declared payloads are absent from the bundle: {}.",
                            check.missing.join(", ")
                        ));
                    } else {
                        v.integrity = IntegrityStatus::Modified;
                        if !check.altered.is_empty() {
                            findings.push(format!(
                                "These payloads do not match their declared digests: {}.",
                                check.altered.join(", ")
                            ));
                        }
                        if !check.unexpected.is_empty() {
                            findings.push(format!(
                                "These payloads are present but undeclared: {}.",
                                check.unexpected.join(", ")
                            ));
                        }
                        if !check.root_matches {
                            findings.push(
                                "The root digest does not match the payloads present.".into(),
                            );
                        }
                    }
                }
            },
        },
    }

    // ---- challenge ----
    let challenge_bytes = get(tt_bundle::CHALLENGE_JSON);
    let sig = get(tt_bundle::CHALLENGE_SIG)
        .and_then(|b| String::from_utf8(b).ok())
        .map(|s| s.trim().to_string());
    v.challenge = tt_case::verify_challenge(
        challenge_bytes.as_deref(),
        sig.as_deref(),
        now,
        expected_case_id,
    );
    match v.challenge {
        ChallengeStatus::Unsigned => findings.push(
            "The challenge is unsigned. It records what was asked, but nothing binds it \
             to the buyer who asked."
                .into(),
        ),
        ChallengeStatus::Absent => findings
            .push("No challenge is present, so this report answers no recorded question.".into()),
        ChallengeStatus::Expired => {
            findings.push("The challenge had expired when this bundle was verified.".into())
        }
        ChallengeStatus::SignatureInvalid => findings
            .push("The challenge signature does not verify against the issuer public key.".into()),
        ChallengeStatus::CaseMismatch => {
            findings.push("The challenge is for a different case than the one expected.".into())
        }
        ChallengeStatus::Bound => {}
    }

    // ---- report ----
    let Some(report_bytes) = get(tt_bundle::REPORT_JSON) else {
        findings.push("The bundle contains no report.".into());
        v.findings = findings;
        return v;
    };
    let report = match tt_core::canon::parse_canonical(&report_bytes, &Limits::default()) {
        Ok(r) => r,
        Err(e) => {
            findings.push(format!(
                "The report is not in canonical form, so it has been rewritten since \
                 export: {e}"
            ));
            v.integrity = IntegrityStatus::Modified;
            v.findings = findings;
            return v;
        }
    };
    let manifest = get(tt_bundle::ARTIFACT_MANIFEST_JSON)
        .and_then(|b| tt_core::canon::parse_canonical(&b, &Limits::default()).ok())
        .unwrap_or_else(|| CanonValue::Obj(Obj::new()));

    v.case_id = report.get("case_id").and_then(|x| x.as_str()).map(String::from);
    v.vendor_label = report.get("vendor_label").and_then(|x| x.as_str()).map(String::from);
    v.exact_claim_text =
        report.get("exact_claim_text").and_then(|x| x.as_str()).map(String::from);
    v.ruleset_version = report.get("ruleset_version").and_then(|x| x.as_int());
    v.evidence_digest = report.get("evidence_digest").and_then(|x| x.as_str()).map(String::from);

    v.coverage = report
        .get("scope")
        .and_then(|s| s.get("coverage_status"))
        .and_then(|c| c.as_str())
        .and_then(CoverageStatus::parse)
        .unwrap_or(CoverageStatus::Minimal);

    if let Some(concl) = report.get("conclusions").and_then(|c| c.as_arr()) {
        for c in concl {
            let f = c.get("facet").and_then(|x| x.as_str()).unwrap_or("(unknown)").to_string();
            let b = c.get("band").and_then(|x| x.as_str()).unwrap_or("(none)").to_string();
            v.facet_bands.push((f, b));
        }
        // The headline evidence status is the *weakest* facet that was actually
        // concluded on. Reporting the strongest would let one well-evidenced facet
        // speak for the others.
        v.evidence = concl
            .iter()
            .filter_map(|c| c.get("band").and_then(|x| x.as_str()))
            .filter_map(SupportBand::parse)
            .min_by_key(band_strength)
            .unwrap_or(SupportBand::InsufficientEvidence);
    }

    // ---- the check with teeth ----
    v.recomputation = recompute(&report, &manifest);
    if let Recomputation::Diverges { detail } = &v.recomputation {
        findings.push(format!(
            "The stated conclusions do not follow from the report's own observations. {detail}"
        ));
    }
    if let Recomputation::NotPossible { reason } = &v.recomputation {
        findings.push(format!("The conclusions could not be re-evaluated. {reason}"));
    }

    // ---- markers ----
    v.marker = match get(tt_bundle::FORENSIC_MARKERS_JSON) {
        None => {
            findings.push(
                "The bundle declares no forensic markers, so rendering tripwires were not \
                 checked."
                    .into(),
            );
            MarkerStatus::Absent
        }
        Some(_) => {
            findings.push(
                "Forensic markers are declared. Marker correlation is checked against the \
                 PDF rendering only, and is never a root of trust."
                    .into(),
            );
            MarkerStatus::NotApplicable
        }
    };

    v.findings = findings;
    v
}

/// Order support bands from weakest to strongest for "weakest facet" reporting.
fn band_strength(b: &SupportBand) -> u8 {
    match b {
        SupportBand::Contradicted => 0,
        SupportBand::NotSupplied => 1,
        SupportBand::InsufficientEvidence => 2,
        SupportBand::PartiallySupported => 3,
        SupportBand::WeaklyConsistent => 4,
        SupportBand::StronglyConsistent => 5,
        SupportBand::Corroborated => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tt_bundle::Payload;
    use tt_core::hash::HashScope;
    use tt_report::{HostInfo, ReportInput, ScopeInfo};

    fn ts(s: &str) -> Timestamp {
        Timestamp::parse_rfc3339(s).unwrap()
    }

    fn sample_facts() -> FactSet {
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
        f.push_fact(
            Fact::new("F-0002", FactKind::AdapterTensorSet, "artifact::A-0001")
                .with_artifact("A-0001")
                .with("lora_pair_count", 224i64)
                .with("inferred_ranks", vec!["16".to_string()]),
        );
        f
    }

    fn build_bundle(facts: &FactSet) -> (Vec<u8>, CanonValue) {
        let case = CaseId::parse("TT-2026-0F3A9C").unwrap();
        let rules = tt_rules::evaluate(facts);
        let rep = tt_report::build(ReportInput {
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
            facts,
            rules: &rules,
            scope: ScopeInfo {
                selected_roots: vec!["ROOT1".into()],
                coverage_status: CoverageStatus::Complete,
                ..Default::default()
            },
            redaction_ledger: Vec::new(),
        })
        .expect("report");

        let mut payloads = vec![
            Payload::new(tt_bundle::REPORT_JSON, rep.to_canonical_bytes()),
            Payload::new(
                tt_bundle::ARTIFACT_MANIFEST_JSON,
                rep.artifact_manifest.to_canonical_bytes(),
            ),
            Payload::new(tt_bundle::VERIFY_TXT, b"report.json is authoritative.".to_vec()),
        ];
        let env = tt_bundle::build_envelope(&payloads);
        payloads.push(Payload::new(
            tt_bundle::INTEGRITY_ENVELOPE_JSON,
            env.to_canonical_bytes(),
        ));
        (tt_bundle::write_archive(&payloads).expect("archive"), rep.value)
    }

    #[test]
    fn an_untouched_bundle_verifies_on_every_axis() {
        let (bytes, _) = build_bundle(&sample_facts());
        let v = verify_bundle(&bytes, ts("2026-09-03T00:00:00Z"), None);
        assert_eq!(v.integrity, IntegrityStatus::Intact, "{:?}", v.findings);
        assert_eq!(v.recomputation, Recomputation::Matches, "{:?}", v.recomputation);
        assert_eq!(v.challenge, ChallengeStatus::Absent);
        assert_eq!(v.coverage, CoverageStatus::Complete);
    }

    #[test]
    fn integrity_and_evidence_are_reported_separately() {
        // An empty scan: nothing to find, but the bytes are perfect.
        let (bytes, _) = build_bundle(&FactSet::new());
        let v = verify_bundle(&bytes, ts("2026-09-03T00:00:00Z"), None);
        assert_eq!(v.integrity, IntegrityStatus::Intact);
        assert!(
            matches!(
                v.evidence,
                SupportBand::InsufficientEvidence | SupportBand::NotSupplied
            ),
            "{:?}",
            v.evidence
        );
    }

    #[test]
    fn editing_a_score_is_caught_even_when_every_hash_is_recomputed() {
        // The attack this product exists to detect: leave the evidence alone, raise
        // the verdict, then rebuild the envelope so all the hashes agree.
        let facts = sample_facts();
        let (_, report) = build_bundle(&facts);

        let mut obj = report.as_obj().unwrap().clone();
        let concl = report.get("conclusions").unwrap().as_arr().unwrap().to_vec();
        let edited: Vec<CanonValue> = concl
            .into_iter()
            .map(|c| {
                let mut o = c.as_obj().unwrap().clone();
                if o.get("facet").and_then(|f| f.as_str()) == Some("parameter_update") {
                    o.set("band", "corroborated_within_supplied_evidence");
                    o.set("score_tenths", 950i64);
                }
                CanonValue::Obj(o)
            })
            .collect();
        obj.set("conclusions", CanonValue::Arr(edited));
        let tampered = CanonValue::Obj(obj);

        let manifest = sample_facts().artifact_manifest_canon();
        let mut payloads = vec![
            Payload::new(tt_bundle::REPORT_JSON, tampered.to_canonical_bytes()),
            Payload::new(tt_bundle::ARTIFACT_MANIFEST_JSON, manifest.to_canonical_bytes()),
        ];
        // Rebuild the envelope so integrity is genuinely intact.
        let env = tt_bundle::build_envelope(&payloads);
        payloads.push(Payload::new(
            tt_bundle::INTEGRITY_ENVELOPE_JSON,
            env.to_canonical_bytes(),
        ));
        let bytes = tt_bundle::write_archive(&payloads).unwrap();

        let v = verify_bundle(&bytes, ts("2026-09-03T00:00:00Z"), None);
        assert_eq!(v.integrity, IntegrityStatus::Intact, "hashes were recomputed, so they agree");
        match &v.recomputation {
            Recomputation::Diverges { detail } => {
                assert!(detail.contains("parameter_update"), "{detail}");
                assert!(detail.contains("corroborated"), "{detail}");
            }
            other => panic!("edit not detected: {other:?}"),
        }
        assert!(!v.all_clear());
    }

    #[test]
    fn flipping_one_byte_of_the_report_breaks_integrity() {
        let (bytes, _) = build_bundle(&sample_facts());
        let mut broken = bytes.clone();
        // Corrupt inside the stored report payload; find a digit and change it.
        let pos = broken
            .windows(14)
            .position(|w| w == b"\"score_tenths\"")
            .expect("score field present in the stored entry");
        broken[pos + 15] = b'9';
        let v = verify_bundle(&broken, ts("2026-09-03T00:00:00Z"), None);
        assert_ne!(v.integrity, IntegrityStatus::Intact);
        assert!(!v.all_clear());
    }

    #[test]
    fn a_removed_payload_reports_incomplete_not_intact() {
        let facts = sample_facts();
        let (_, report) = build_bundle(&facts);
        let manifest = facts.artifact_manifest_canon();
        let full = vec![
            Payload::new(tt_bundle::REPORT_JSON, report.to_canonical_bytes()),
            Payload::new(tt_bundle::ARTIFACT_MANIFEST_JSON, manifest.to_canonical_bytes()),
            Payload::new(tt_bundle::VERIFY_TXT, b"x".to_vec()),
        ];
        let env = tt_bundle::build_envelope(&full);
        // Ship the envelope but drop VERIFY.txt.
        let mut short = full[..2].to_vec();
        short.push(Payload::new(tt_bundle::INTEGRITY_ENVELOPE_JSON, env.to_canonical_bytes()));
        let bytes = tt_bundle::write_archive(&short).unwrap();
        let v = verify_bundle(&bytes, ts("2026-09-03T00:00:00Z"), None);
        assert_eq!(v.integrity, IntegrityStatus::Incomplete);
    }

    #[test]
    fn a_reformatted_report_is_detected_as_modified() {
        let facts = sample_facts();
        let (_, report) = build_bundle(&facts);
        let pretty = report.to_pretty_string().into_bytes();
        let manifest = facts.artifact_manifest_canon();
        let mut payloads = vec![
            Payload::new(tt_bundle::REPORT_JSON, pretty),
            Payload::new(tt_bundle::ARTIFACT_MANIFEST_JSON, manifest.to_canonical_bytes()),
        ];
        let env = tt_bundle::build_envelope(&payloads);
        payloads.push(Payload::new(tt_bundle::INTEGRITY_ENVELOPE_JSON, env.to_canonical_bytes()));
        let bytes = tt_bundle::write_archive(&payloads).unwrap();
        let v = verify_bundle(&bytes, ts("2026-09-03T00:00:00Z"), None);
        assert_eq!(v.integrity, IntegrityStatus::Modified);
        assert!(v.findings.iter().any(|f| f.contains("canonical")), "{:?}", v.findings);
    }

    #[test]
    fn garbage_input_is_reported_not_fatal() {
        for junk in [&b""[..], &b"not a zip"[..], &[0xffu8; 512][..]] {
            let v = verify_bundle(junk, ts("2026-09-03T00:00:00Z"), None);
            assert_eq!(v.integrity, IntegrityStatus::Unreadable);
            assert!(!v.findings.is_empty());
        }
    }

    #[test]
    fn facts_round_trip_through_the_report() {
        let facts = sample_facts();
        let (_, report) = build_bundle(&facts);
        let manifest = facts.artifact_manifest_canon();
        let back = facts_from_report(&report, &manifest).unwrap();
        assert_eq!(back.facts.len(), facts.facts.len());
        assert_eq!(back.artifacts.len(), facts.artifacts.len());
        assert_eq!(back.declared, facts.declared);
        // The conclusions drawn from the reconstruction must be identical, which is
        // the property the divergence check depends on.
        assert_eq!(
            tt_rules::evaluate(&back).conclusions_canon(),
            tt_rules::evaluate(&facts).conclusions_canon()
        );
    }

    #[test]
    fn the_weakest_facet_sets_the_headline_evidence_status() {
        let (bytes, _) = build_bundle(&sample_facts());
        let v = verify_bundle(&bytes, ts("2026-09-03T00:00:00Z"), None);
        let weakest = v
            .facet_bands
            .iter()
            .filter_map(|(_, b)| SupportBand::parse(b))
            .min_by_key(band_strength)
            .unwrap();
        assert_eq!(v.evidence, weakest, "one strong facet must not speak for the rest");
    }
}
