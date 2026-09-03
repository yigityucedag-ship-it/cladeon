//! The golden corpus, run end to end.
//!
//! Every case in `cl-fixtures` is generated to a temporary tree, scanned by the real
//! pipeline, and checked against the expectations its own `MANIFEST.md` states. This
//! is the suite that judges the product rather than any one component of it.
//!
//! The cases that matter most carry `must_not_name`. A scanner that became confident
//! enough to name a merged adapter, or to name continued pretraining from final
//! weights alone, would fail here rather than ship.

use crate::scan::{run, ScanRequest, ScanResult};
use std::sync::atomic::{AtomicU32, Ordering};
use cl_core::ids::CaseId;
use cl_core::limits::Limits;
use cl_core::vocab::{Facet, OutcomeKind, SupportBand};
use cl_facts::DeclaredFacets;

static SEQ: AtomicU32 = AtomicU32::new(0);

fn declared_from(d: &cl_fixtures::Declared) -> DeclaredFacets {
    use cl_core::vocab::{
        InferenceAugmentation as I, ParameterUpdate as P, TrainingStage as T, WeightOrigin as W,
    };
    DeclaredFacets {
        weight_origin: d.weight_origin.and_then(W::parse),
        parameter_update: d.parameter_update.and_then(P::parse),
        training_stage: d.training_stage.and_then(T::parse),
        inference_augmentation: d.augmentation.iter().filter_map(|a| I::parse(a)).collect(),
    }
}

fn scan_case(c: &cl_fixtures::Case) -> ScanResult {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let root =
        std::env::temp_dir().join(format!("cl-corpus-{}-{}-{}", std::process::id(), c.name, n));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let dir = cl_fixtures::generate(c, &root).expect("generate case");

    let req = ScanRequest {
        roots: vec![dir],
        excluded: Vec::new(),
        case_id: CaseId::parse("CL-2026-0F3A9C").unwrap(),
        vendor_label: "Corpus Vendor".into(),
        exact_claim_text: c.claim.to_string(),
        declared: declared_from(&c.declared),
        hash_files: true,
        limits: Limits::default(),
        challenge_bytes: None,
    };
    let r =
        run(&req, &|| false, &mut |_| {}).unwrap_or_else(|e| panic!("case `{}` failed to scan: {e}", c.name));
    let _ = std::fs::remove_dir_all(&root);
    r
}

#[test]
fn every_case_scans_without_error() {
    for c in cl_fixtures::cases() {
        let r = scan_case(c);
        assert!(
            r.report.value.get("conclusions").is_some(),
            "case `{}` produced no conclusions",
            c.name
        );
    }
}

#[test]
fn cases_that_must_abstain_do_abstain() {
    for c in cl_fixtures::cases() {
        if c.expect.must_not_name.is_empty() {
            continue;
        }
        let r = scan_case(c);
        for facet in c.expect.must_not_name {
            let concl = r.rules.conclusion(*facet).expect("a conclusion for every facet");
            assert!(
                !concl.method_label_emitted,
                "case `{}` named a method on {} at {} tenths, but its ground truth says \
                 Stage 1 cannot establish that.\nGround truth: {}",
                c.name,
                facet.as_str(),
                concl.score_tenths,
                c.truth
            );
        }
    }
}

#[test]
fn pinned_bands_are_reported_exactly() {
    for c in cl_fixtures::cases() {
        if c.expect.band.is_empty() {
            continue;
        }
        let r = scan_case(c);
        for (facet, want) in c.expect.band {
            let got = r.rules.conclusion(*facet).map(|x| x.band);
            assert_eq!(
                got,
                Some(*want),
                "case `{}` reported {got:?} on {}, expected {want:?}",
                c.name,
                facet.as_str()
            );
        }
    }
}

#[test]
fn required_abstentions_are_recorded() {
    for c in cl_fixtures::cases() {
        if c.expect.abstentions.is_empty() {
            continue;
        }
        let r = scan_case(c);
        for (facet, id) in c.expect.abstentions {
            let concl = r.rules.conclusion(*facet).expect("conclusion");
            assert!(
                concl.abstentions.contains(id),
                "case `{}` did not record {} on {}. Recorded: {:?}",
                c.name,
                id.as_str(),
                facet.as_str(),
                concl.abstentions
            );
        }
    }
}

/// The failure mode that matters most: accusing an honest vendor.
#[test]
fn no_case_that_should_be_quiet_raises_a_contradiction() {
    for c in cl_fixtures::cases() {
        if !c.expect.no_contradictions {
            continue;
        }
        let r = scan_case(c);
        let found: Vec<(&str, &str)> = r
            .rules
            .outcomes
            .iter()
            .filter(|o| o.kind == OutcomeKind::Contradiction)
            .map(|o| (o.rule_id, o.text.as_str()))
            .collect();
        assert!(
            found.is_empty(),
            "case `{}` raised a contradiction against evidence that does not support one: \
             {found:?}\nGround truth: {}",
            c.name,
            c.truth
        );
    }
}

/// Abstention is the default, not a refusal to ever speak. A genuine conflict
/// between an exact claim and an observed artifact must still be reported.
#[test]
fn a_real_conflict_is_still_reported_as_a_contradiction() {
    let c = cl_fixtures::case("malformed_adapter_config_mismatch").expect("case exists");
    let r = scan_case(c);
    let contradictions: Vec<&str> = r
        .rules
        .outcomes
        .iter()
        .filter(|o| o.kind == OutcomeKind::Contradiction)
        .map(|o| o.rule_id)
        .collect();
    assert!(
        contradictions.contains(&"CL-LORA-006"),
        "a declared rank of 32 against tensors implying rank 8 must be a contradiction, got \
         {contradictions:?}"
    );
}

#[test]
fn nothing_from_the_privacy_bait_reaches_the_report() {
    for c in cl_fixtures::cases() {
        if c.expect.must_not_leak.is_empty() {
            continue;
        }
        let r = scan_case(c);
        let json = String::from_utf8_lossy(&r.report.to_canonical_bytes()).to_string();
        let manifest = r.report.artifact_manifest.to_canonical_string();
        for secret in c.expect.must_not_leak {
            assert!(!json.contains(secret), "case `{}` leaked `{secret}` into report.json", c.name);
            assert!(
                !manifest.contains(secret),
                "case `{}` leaked `{secret}` into the artifact manifest",
                c.name
            );
        }
        // The account name embedded in the absolute path must not survive either.
        assert!(!json.contains("alice"), "case `{}` leaked a user name", c.name);
    }
}

#[test]
fn hostile_files_produce_coverage_notes_rather_than_silence() {
    let c = cl_fixtures::case("parser_abuse").expect("case exists");
    let r = scan_case(c);
    assert!(
        !r.facts.coverage.is_empty(),
        "malformed files must be recorded as things the scan could not read"
    );
    // And the scan still produced a complete report.
    assert_eq!(
        r.report.value.get("conclusions").and_then(|x| x.as_arr()).map(|a| a.len()),
        Some(Facet::ALL.len())
    );
}

/// Corroboration requires independent sources and a deployment binding a folder
/// self-scan does not have. If any case reached it, either the corpus has drifted
/// into unrealism or a cap has stopped binding.
#[test]
fn the_corpus_never_reaches_corroborated_on_a_stage_one_self_scan() {
    for c in cl_fixtures::cases() {
        let r = scan_case(c);
        for f in Facet::ALL {
            if let Some(concl) = r.rules.conclusion(*f) {
                assert_ne!(
                    concl.band,
                    SupportBand::Corroborated,
                    "case `{}` reached `corroborated` on {} at {} tenths",
                    c.name,
                    f.as_str(),
                    concl.score_tenths
                );
            }
        }
    }
}

/// Two scans of one *unchanged tree* must agree, across the whole corpus.
///
/// The tree is generated once and scanned twice, which is what "unchanged evidence"
/// means. Regenerating between scans would give the files new modification times,
/// and those are part of the evidence: the manifest records them and the `CL-CHRONO`
/// rules read them, so a touched file moving the digest is correct behaviour rather
/// than a reproducibility failure.
#[test]
fn the_whole_corpus_is_reproducible() {
    for c in cl_fixtures::cases() {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir()
            .join(format!("cl-repro-{}-{}-{}", std::process::id(), c.name, n));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let dir = cl_fixtures::generate(c, &root).expect("generate case");

        let req = || ScanRequest {
            roots: vec![dir.clone()],
            excluded: Vec::new(),
            case_id: CaseId::parse("CL-2026-0F3A9C").unwrap(),
            vendor_label: "Corpus Vendor".into(),
            exact_claim_text: c.claim.to_string(),
            declared: declared_from(&c.declared),
            hash_files: true,
            limits: Limits::default(),
            challenge_bytes: None,
        };
        let a = run(&req(), &|| false, &mut |_| {}).expect("first scan");
        let b = run(&req(), &|| false, &mut |_| {}).expect("second scan");
        assert_eq!(
            a.report.evidence_digest, b.report.evidence_digest,
            "case `{}` produced a different evidence digest on a second scan of the same tree",
            c.name
        );
        // Note what is deliberately NOT asserted here: that the two full documents
        // differ. Two scans a few milliseconds apart share a whole-second timestamp,
        // so they are usually byte-identical - which is a good property, not a bug.
        // That the evidence digest ignores the clock is tested directly, with
        // explicit differing timestamps, in `cl_report::document`.
        let _ = std::fs::remove_dir_all(&root);
    }
}
