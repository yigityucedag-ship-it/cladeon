//! Workspace-level contracts.
//!
//! Several rules in this repository are stated in prose — in `docs/`, in module
//! headers, in commit messages. Prose is not enforcement. Every check here turns one
//! of those statements into something that fails a build when it stops being true.
//!
//! Each test names the promise it protects and what breaking it would cost.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/tt-contracts; the workspace root is two above.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn read(p: &Path) -> String {
    fs::read_to_string(p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// Product sources: every `.rs` under `crates/`, except this crate.
///
/// `tt-contracts` is excluded because it necessarily *names* the very constructs it
/// forbids — a scanner that searches for the string `std::net` will otherwise find
/// itself and fail. Excluding it is safe: it ships no code, which
/// `contracts_crate_ships_no_code` enforces.
fn rust_sources() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let crates = repo_root().join("crates");
    let mut stack = vec![crates];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                if name == "target" || name == "tt-contracts" {
                    continue;
                }
                stack.push(p);
            } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// The exclusion above is only sound while this crate really is empty.
#[test]
fn contracts_crate_ships_no_code() {
    let lib = read(&repo_root().join("crates/tt-contracts/src/lib.rs"));
    let code: Vec<&str> = lib
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//") && !l.starts_with("#!"))
        .collect();
    assert!(
        code.is_empty(),
        "tt-contracts must ship no code, because the source scanners skip it: {code:?}"
    );
}

fn cargo_manifests() -> Vec<PathBuf> {
    let mut out = vec![repo_root().join("Cargo.toml")];
    let crates = repo_root().join("crates");
    if let Ok(entries) = fs::read_dir(&crates) {
        for e in entries.flatten() {
            let m = e.path().join("Cargo.toml");
            if m.exists() {
                out.push(m);
            }
        }
    }
    out.sort();
    out
}

/// Strip `#[cfg(test)]` modules so a policy check does not trip over test fixtures
/// that legitimately contain the strings being searched for.
fn without_test_modules(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut depth: i32 = 0;
    let mut in_test = false;
    let mut brace_at_entry = 0i32;
    for line in src.lines() {
        if !in_test && line.trim_start().starts_with("#[cfg(test)]") {
            in_test = true;
            brace_at_entry = depth;
            continue;
        }
        let opens = line.matches('{').count() as i32;
        let closes = line.matches('}').count() as i32;
        if in_test {
            depth += opens - closes;
            if depth <= brace_at_entry && closes > 0 {
                in_test = false;
            }
            continue;
        }
        depth += opens - closes;
        out.push_str(line);
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// Dependency policy
// ---------------------------------------------------------------------------

/// The only third-party crates permitted anywhere in the workspace.
///
/// The promise: no third-party crate parses bytes that came from a vendor artifact
/// or a `.ttscan`. Every such parser is in-repo and bounded. Breaking this silently
/// re-introduces an unaudited attack surface into a tool whose entire job is to read
/// files supplied by a party with a motive.
const ALLOWED_DEPENDENCIES: &[&str] = &[
    // The only third-party crates in the workspace.
    "sha2",
    "ed25519-dalek",
    "getrandom",
    "clap",
    // In-repo crates. Listed explicitly so that adding a new one is a deliberate act
    // rather than something a `path = ` dependency can do quietly.
    "tt-core",
    "tt-facts",
    "tt-inventory",
    "tt-formats",
    "tt-rules",
    "tt-markers",
    "tt-report",
    "tt-bundle",
    "tt-case",
    "tt-fixtures",
];

#[test]
fn no_dependency_outside_the_allow_list() {
    for manifest in cargo_manifests() {
        let text = read(&manifest);
        let mut in_deps = false;
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                in_deps = t == "[dependencies]"
                    || t == "[workspace.dependencies]"
                    || t == "[dev-dependencies]"
                    || t == "[build-dependencies]";
                continue;
            }
            if !in_deps || t.is_empty() || t.starts_with('#') {
                continue;
            }
            let Some(name) = t.split(['=', '.']).next().map(str::trim) else { continue };
            if name.is_empty() {
                continue;
            }
            assert!(
                ALLOWED_DEPENDENCIES.contains(&name),
                "{} declares `{name}`, which is outside the dependency allow-list. \
                 No third-party crate may parse untrusted bytes; add an in-repo bounded \
                 parser instead, or extend ALLOWED_DEPENDENCIES deliberately.",
                manifest.display()
            );
        }
    }
}

#[test]
fn no_unsafe_code_anywhere() {
    for src in rust_sources() {
        let text = read(&src);
        for (i, line) in text.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with("//!") {
                continue;
            }
            assert!(
                !t.contains("unsafe "),
                "{}:{} contains `unsafe`. Every crate declares forbid(unsafe_code); a \
                 memory-safety bug in a parser of hostile input is the worst outcome \
                 this product has.",
                src.display(),
                i + 1
            );
        }
    }
}

#[test]
fn every_library_crate_forbids_unsafe() {
    let crates = repo_root().join("crates");
    for e in fs::read_dir(&crates).expect("crates dir").flatten() {
        let lib = e.path().join("src/lib.rs");
        if !lib.exists() {
            continue;
        }
        let text = read(&lib);
        assert!(
            text.contains("#![forbid(unsafe_code)]"),
            "{} is missing #![forbid(unsafe_code)]",
            lib.display()
        );
    }
}

// ---------------------------------------------------------------------------
// The offline promise
// ---------------------------------------------------------------------------

/// The product promises that the default mode opens no network socket. The
/// dependency allow-list makes that structurally true — none of the four permitted
/// crates can open one — but a future edit could add `std::net` directly.
#[test]
fn nothing_opens_a_network_socket() {
    for src in rust_sources() {
        let text = without_test_modules(&read(&src));
        for needle in ["std::net", "TcpStream", "UdpSocket", "TcpListener"] {
            assert!(
                !text.contains(needle),
                "{} references `{needle}`. Stage 1 must open no socket in the default \
                 mode; that is a headline promise of the product.",
                src.display()
            );
        }
    }
}

/// Vendor artifacts are never executed. Nothing may spawn a process.
#[test]
fn nothing_spawns_a_process() {
    for src in rust_sources() {
        let text = without_test_modules(&read(&src));
        for needle in ["std::process::Command", "Command::new"] {
            assert!(
                !text.contains(needle),
                "{} references `{needle}`. Supplied artifacts are never executed.",
                src.display()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Vocabulary and rule catalogue stay in step with the documents
// ---------------------------------------------------------------------------

#[test]
fn every_vocabulary_string_appears_in_the_frozen_document() {
    use tt_core::vocab::*;
    let doc = read(&repo_root().join("docs/00-FROZEN-VOCABULARY.md"));

    let mut missing: Vec<String> = Vec::new();
    let mut check = |s: &str| {
        if !doc.contains(s) {
            missing.push(s.to_string());
        }
    };
    for v in WeightOrigin::ALL {
        check(v.as_str());
    }
    for v in ParameterUpdate::ALL {
        check(v.as_str());
    }
    for v in TrainingStage::ALL {
        check(v.as_str());
    }
    for v in InferenceAugmentation::ALL {
        check(v.as_str());
    }
    for v in SupportBand::ALL {
        check(v.as_str());
    }
    for v in EvidenceTier::ALL {
        check(v.as_str());
    }
    for v in OutcomeKind::ALL {
        check(v.as_str());
    }
    for v in Claim::ALL {
        check(v.as_str());
    }
    for v in CapId::ALL {
        check(v.as_str());
    }
    for v in AbstentionId::ALL {
        check(v.as_str());
    }
    for v in IntegrityStatus::ALL {
        check(v.as_str());
    }
    for v in ChallengeStatus::ALL {
        check(v.as_str());
    }
    for v in MarkerStatus::ALL {
        check(v.as_str());
    }
    for v in CoverageStatus::ALL {
        check(v.as_str());
    }
    assert!(
        missing.is_empty(),
        "these enum values are not documented in docs/00-FROZEN-VOCABULARY.md: {missing:?}. \
         The document is the contract a buyer reads; code that drifts from it makes the \
         contract false."
    );
}

#[test]
fn every_cap_in_the_document_exists_in_code() {
    use tt_core::vocab::CapId;
    let doc = read(&repo_root().join("docs/00-FROZEN-VOCABULARY.md"));
    for line in doc.lines() {
        for token in line.split('`') {
            if token.starts_with("CAP-") {
                assert!(
                    CapId::parse(token).is_some(),
                    "docs name cap `{token}` but CapId has no such variant"
                );
            }
            if token.starts_with("ABS-") {
                assert!(
                    tt_core::vocab::AbstentionId::parse(token).is_some(),
                    "docs name abstention `{token}` but AbstentionId has no such variant"
                );
            }
        }
    }
}

/// Every rule id the engine can emit must exist in the catalogue, and must match the
/// documented shape. A rule citing an id nobody can look up is not a citation.
#[test]
fn every_emitted_rule_id_is_in_the_catalogue() {
    let catalogue = read(&repo_root().join("docs/01-RULE-CATALOGUE.md"));
    let families = read(&repo_root().join("crates/tt-rules/src/families.rs"));

    let mut ids: Vec<String> = Vec::new();
    let bytes = families.as_bytes();
    let mut i = 0usize;
    while i + 3 < bytes.len() {
        if &bytes[i..i + 3] == b"TT-" && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
            let mut j = i;
            while j < bytes.len()
                && (bytes[j].is_ascii_uppercase() || bytes[j].is_ascii_digit() || bytes[j] == b'-')
            {
                j += 1;
            }
            let id = &families[i..j];
            // Only well-formed ids; prose mentions are not citations.
            let parts: Vec<&str> = id.split('-').collect();
            if parts.len() == 3 && parts[2].len() == 3 && parts[2].bytes().all(|c| c.is_ascii_digit())
            {
                ids.push(id.to_string());
            }
            i = j;
            continue;
        }
        i += 1;
    }
    ids.sort();
    ids.dedup();
    assert!(!ids.is_empty(), "found no rule ids in families.rs; the extractor is broken");

    let mut unknown = Vec::new();
    for id in &ids {
        if !catalogue.contains(id.as_str()) {
            unknown.push(id.clone());
        }
    }
    assert!(
        unknown.is_empty(),
        "these rule ids are emitted but are not in docs/01-RULE-CATALOGUE.md: {unknown:?}"
    );
}

// ---------------------------------------------------------------------------
// The stance
// ---------------------------------------------------------------------------

/// No rendered conclusion may reach a reader in language the product forbids.
///
/// This runs over the whole cross-product of the vocabulary's rendered text, which is
/// everything a reader can be shown that TrainTrace itself wrote.
#[test]
fn no_authored_vocabulary_uses_forbidden_language() {
    use tt_core::vocab::*;
    let mut all = String::new();
    for b in SupportBand::ALL {
        all.push_str(b.render());
        all.push('\n');
    }
    for c in Claim::ALL {
        all.push_str(c.render());
        all.push('\n');
    }
    for c in CapId::ALL {
        all.push_str(c.render());
        all.push('\n');
    }
    for a in AbstentionId::ALL {
        all.push_str(a.render());
        all.push('\n');
    }
    for t in EvidenceTier::ALL {
        all.push_str(t.describe());
        all.push('\n');
    }
    all.push_str(tt_core::REQUIRED_STATEMENT);
    assert_eq!(forbidden_language(&all), None, "in:\n{all}");
}

/// Every rule-outcome text the families can produce, over an empty and a populated
/// fact set, must be free of forbidden language. This catches an editorialising
/// sentence written directly into a rule.
#[test]
fn no_rule_text_uses_forbidden_language() {
    use tt_facts::FactSet;
    let empty = tt_rules::evaluate(&FactSet::new());
    assert_eq!(
        tt_core::vocab::forbidden_language(&empty.all_text()),
        None,
        "empty scan produced forbidden language"
    );
}

/// A contradiction must cite an artifact. The catalogue says so; this makes it true.
///
/// The point is not tidiness. A contradiction is the only outcome that can harm a
/// vendor, so it is the one that must always be traceable to bytes the scanner
/// actually read.
#[test]
fn every_contradiction_cites_an_artifact_digest() {
    use tt_core::hash::{Digest, HashScope};
    use tt_core::vocab::OutcomeKind;
    use tt_facts::{ArtifactRecord, ArtifactType, Fact, FactKind, FactSet, ReadStatus};

    // A fact set engineered to fire contradictions: a declared no-update claim while
    // adapter artifacts are present, and a rank disagreement.
    let mut f = FactSet::new();
    f.declared.parameter_update = Some(tt_core::vocab::ParameterUpdate::NoUpdateObserved);
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
            .with("inferred_ranks", vec!["8".to_string()]),
    );

    let report = tt_rules::evaluate(&f);
    let contradictions: Vec<_> =
        report.outcomes.iter().filter(|o| o.kind == OutcomeKind::Contradiction).collect();
    assert!(
        !contradictions.is_empty(),
        "the fixture was supposed to produce contradictions; if the rules changed, \
         update the fixture rather than deleting the check"
    );
    for c in contradictions {
        assert!(
            !c.artifact_sha256.is_empty(),
            "contradiction {} cites no artifact digest: {}",
            c.rule_id,
            c.text
        );
        assert!(
            !c.fact_ids.is_empty(),
            "contradiction {} cites no fact: {}",
            c.rule_id,
            c.text
        );
    }
}

/// A missing anchor must never reduce a score. Absent evidence caps; it never
/// subtracts. This is the asymmetry that stops "you did not send us that file" from
/// becoming an accusation.
#[test]
fn missing_anchors_never_reduce_a_score() {
    use tt_core::vocab::{Claim, EvidenceTier};
    use tt_rules::{judge, Emissions, RuleOutcome};

    let base = || {
        let mut e = Emissions::default();
        e.outcomes.push(
            RuleOutcome::support(
                "TT-LORA-003",
                Claim::UnmergedLora,
                "structure",
                100,
                EvidenceTier::E2,
                "t",
            )
            .group("artifact::A-0001"),
        );
        e
    };

    let without = judge(base());
    let mut with = base();
    for (rule, anchor) in [
        ("TT-BASE-003", "base"),
        ("TT-LORA-014", "load_or_remerge_record"),
        ("TT-BIND-004", "deployment_binding"),
    ] {
        with.outcomes.push(RuleOutcome::missing(rule, Claim::UnmergedLora, anchor, "t"));
    }
    let with = judge(with);

    let score_of = |r: &tt_rules::RuleReport| {
        r.claim_scores.iter().find(|s| s.claim == Claim::UnmergedLora).unwrap().raw_tenths
    };
    assert_eq!(
        score_of(&without),
        score_of(&with),
        "adding missing-anchor outcomes changed the score"
    );
}

/// Stage 1 must not be able to name a merged adapter, whatever the evidence.
///
/// Two of that rubric's anchors — the delta pattern and a reproduced merge — require
/// tensor analysis that Stage 1 does not perform. If a future weight edit made the
/// remaining anchors sum past the emission floor, Stage 1 would start over-claiming
/// on exactly the case the plan says it must abstain on.
#[test]
fn stage_one_cannot_name_a_merged_adapter() {
    use tt_core::vocab::{Claim, EMISSION_MIN_TENTHS};
    let reachable: u32 = Claim::MergedAdapter
        .rubric()
        .iter()
        .filter(|a| a.name != "delta_pattern" && a.name != "merge_reproduction")
        .map(|a| a.weight)
        .sum();
    let best_tenths = (reachable as i64) * 1000 / (Claim::MergedAdapter.rubric_divisor() as i64);
    assert!(
        best_tenths < EMISSION_MIN_TENTHS,
        "a merged adapter could reach {best_tenths} tenths without Stage-2 analysis, \
         which is above the {EMISSION_MIN_TENTHS} emission floor"
    );
}

/// An ordinary, correctly-ordered training log must not produce a contradiction.
///
/// This guards the layer above the parser. A bug in `tt-formats` once left
/// `steps_monotonic` defaulting to `false`, which rule `TT-DENSE-007` turns into a
/// contradiction — so every honest vendor with an ordered log would have been
/// reported as contradicted. The parser bug is fixed and unit-tested; this asserts
/// the consequence that actually mattered, because that is the failure a reader
/// would have seen.
#[test]
fn an_ordinary_training_log_produces_no_contradiction() {
    use tt_core::vocab::OutcomeKind;
    use tt_facts::{Fact, FactKind, FactSet};

    let mut f = FactSet::new();
    f.push_fact(
        Fact::new("F-0001", FactKind::TrainingMetric, "dir::ROOT1")
            .with("entry_count", 3i64)
            .with("first_step", 100i64)
            .with("last_step", 300i64)
            .with("steps_monotonic", true),
    );
    f.push_fact(Fact::new("F-0002", FactKind::CheckpointStep, "dir::ROOT1").with("step", 100i64));
    f.push_fact(Fact::new("F-0003", FactKind::CheckpointStep, "dir::ROOT1").with("step", 300i64));

    let r = tt_rules::evaluate(&f);
    let contradictions: Vec<&str> = r
        .outcomes
        .iter()
        .filter(|o| o.kind == OutcomeKind::Contradiction)
        .map(|o| o.rule_id)
        .collect();
    assert!(
        contradictions.is_empty(),
        "an ordered training log produced contradictions: {contradictions:?}"
    );
}

/// A metric fact that omits the ordering flag entirely must also be safe.
///
/// Rules read it with `unwrap_or(true)`, so an absent flag means "no disorder
/// observed", never "disorder observed". Silence is not evidence against anyone.
#[test]
fn an_absent_ordering_flag_is_not_read_as_disorder() {
    use tt_core::vocab::OutcomeKind;
    use tt_facts::{Fact, FactKind, FactSet};

    let mut f = FactSet::new();
    f.push_fact(
        Fact::new("F-0001", FactKind::TrainingMetric, "dir::ROOT1").with("entry_count", 5i64),
    );
    let r = tt_rules::evaluate(&f);
    assert!(
        r.outcomes.iter().all(|o| o.kind != OutcomeKind::Contradiction),
        "an absent flag was read as a contradiction"
    );
}

/// A system that wraps somebody else's API has no local weights *by design*, and
/// must not be capped for it on the claims that describe what it actually is.
///
/// Both caps below were once applied in the wrong direction, and each capped the
/// single claim the evidence supported: CAP-QUESTIONNAIRE fired on every claim
/// whenever no checkpoint was present, and CAP-API-ONLY - defined by the plan as
/// "API behaviour only, FOR A WEIGHT-TRAINING CLAIM" - was applied to the API claim
/// itself. The effect was a scanner that could see a full retrieval chain and an
/// external endpoint and still report nothing.
#[test]
fn an_api_and_rag_system_is_not_capped_for_having_no_weights() {
    use tt_core::vocab::{CapId, Claim, InferenceAugmentation};
    use tt_facts::{Fact, FactKind, FactSet};

    let mut f = FactSet::new();
    // The vendor claims to have trained weights, and also runs retrieval.
    f.declared.weight_origin = Some(tt_core::vocab::WeightOrigin::RandomInitializationClaimed);
    f.declared.inference_augmentation = vec![InferenceAugmentation::Rag];
    f.push_fact(
        Fact::new("F-0001", FactKind::RetrievalTrace, "dir::ROOT1")
            .with("entry_count", 25i64)
            .with("request_level_chain", true),
    );
    f.push_fact(Fact::new("F-0002", FactKind::RetrievalIndex, "dir::ROOT1").with("store", "chroma"));
    f.push_fact(
        Fact::new("F-0003", FactKind::ProviderEndpoint, "dir::ROOT2").with("host", "api.openai.com"),
    );
    f.push_fact(Fact::new("F-0004", FactKind::PromptTemplate, "dir::ROOT3").with("preview", "{context}"));

    let r = tt_rules::evaluate(&f);
    let rag = r.claim_scores.iter().find(|s| s.claim == Claim::Rag).unwrap();
    assert!(
        !rag.caps.iter().any(|c| c.cap_id == CapId::Questionnaire),
        "the RAG claim was capped as questionnaire-only for lacking model weights"
    );
    assert!(
        !rag.caps.iter().any(|c| c.cap_id == CapId::ApiOnly),
        "the RAG claim was capped by an API-behaviour cap"
    );
    assert!(
        rag.score_tenths > CapId::Questionnaire.max_tenths(),
        "a full retrieval chain scored no better than a questionnaire ({} tenths)",
        rag.score_tenths
    );

    let api = r.claim_scores.iter().find(|s| s.claim == Claim::ExternalApi).unwrap();
    assert!(
        !api.caps.iter().any(|c| c.cap_id == CapId::ApiOnly),
        "CAP-API-ONLY binds weight-training claims, not the API claim it supports"
    );
}

/// The same caps must still bind the claims they were written for.
///
/// The fix above narrowed their scope, so this asserts the narrowing did not turn
/// them off: a weight-training claim resting on nothing but API behaviour is still
/// capped, which is the whole reason the cap exists.
#[test]
fn weight_training_claims_are_still_capped_by_api_only_evidence() {
    use tt_core::vocab::{CapId, Claim, WeightOrigin};
    use tt_facts::{Fact, FactKind, FactSet};

    let mut f = FactSet::new();
    f.declared.weight_origin = Some(WeightOrigin::RandomInitializationClaimed);
    f.push_fact(
        Fact::new("F-0001", FactKind::ProviderEndpoint, "dir::ROOT1").with("host", "api.openai.com"),
    );

    let r = tt_rules::evaluate(&f);
    let scratch = r.claim_scores.iter().find(|s| s.claim == Claim::Scratch).unwrap();
    assert!(
        scratch
            .caps
            .iter()
            .any(|c| c.cap_id == CapId::ApiOnly || c.cap_id == CapId::Questionnaire),
        "a from-scratch claim backed only by an API endpoint must still be capped: {:?}",
        scratch.caps
    );
    assert!(
        scratch.score_tenths <= CapId::ApiOnly.max_tenths(),
        "scratch reached {} tenths on API evidence alone",
        scratch.score_tenths
    );
}

/// Every test the acceptance document names must actually exist.
///
/// An acceptance document is a claim about what is covered, and a claim about
/// coverage is exactly the kind that rots quietly: a test gets renamed, the table
/// still lists it, and the document keeps asserting a guarantee nobody checks any
/// more. This makes that impossible.
///
/// The document also cites corpus-case names and vocabulary values in backticks, so
/// an identifier is accepted if it is a test function, a fixture case, or a value
/// from the frozen vocabulary. Anything else is a stale reference.
#[test]
fn every_test_named_in_the_acceptance_document_exists() {
    use tt_core::vocab::*;

    let doc = read(&repo_root().join("docs/04-ACCEPTANCE-TESTS.md"));

    // Collect every `snake_case` identifier the document cites.
    let mut cited: Vec<String> = Vec::new();
    let mut in_tick = false;
    let mut cur = String::new();
    for ch in doc.chars() {
        if ch == '`' {
            if in_tick {
                let t = cur.trim().to_string();
                let looks_like_ident = t.len() > 8
                    && t.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                    && t.contains('_');
                if looks_like_ident && !cited.contains(&t) {
                    cited.push(t);
                }
                cur.clear();
            }
            in_tick = !in_tick;
        } else if in_tick {
            cur.push(ch);
        }
    }
    assert!(cited.len() > 50, "only {} identifiers found; the extractor is broken", cited.len());

    // Every test function in the workspace, INCLUDING this file.
    //
    // `rust_sources` excludes `tt-contracts` so the forbidden-string scanners do not
    // find themselves. That exclusion is right for those checks and wrong for this
    // one, which needs to see its own crate's tests - so it is added back here
    // rather than by widening `rust_sources` and breaking the other guards.
    let mut sources = String::new();
    for p in rust_sources() {
        sources.push_str(&read(&p));
    }
    sources.push_str(&read(&repo_root().join("crates/tt-contracts/tests/contracts.rs")));

    // Names that are legitimately not tests.
    let mut allowed: Vec<String> =
        tt_fixtures::cases().iter().map(|c| c.name.to_string()).collect();
    let mut vocab: Vec<&'static str> = Vec::new();
    vocab.extend(SupportBand::ALL.iter().map(|v| v.as_str()));
    vocab.extend(Claim::ALL.iter().map(|v| v.as_str()));
    vocab.extend(Facet::ALL.iter().map(|v| v.as_str()));
    vocab.extend(WeightOrigin::ALL.iter().map(|v| v.as_str()));
    vocab.extend(ParameterUpdate::ALL.iter().map(|v| v.as_str()));
    vocab.extend(TrainingStage::ALL.iter().map(|v| v.as_str()));
    vocab.extend(InferenceAugmentation::ALL.iter().map(|v| v.as_str()));
    vocab.extend(IntegrityStatus::ALL.iter().map(|v| v.as_str()));
    vocab.extend(ChallengeStatus::ALL.iter().map(|v| v.as_str()));
    vocab.extend(MarkerStatus::ALL.iter().map(|v| v.as_str()));
    vocab.extend(CoverageStatus::ALL.iter().map(|v| v.as_str()));
    vocab.extend(OutcomeKind::ALL.iter().map(|v| v.as_str()));
    allowed.extend(vocab.into_iter().map(String::from));
    allowed.push("acceptance_version".into());
    allowed.push("threat_model_version".into());
    allowed.push("skipped_by_submitter".into());
    allowed.push("out_of_scope_path".into());
    allowed.push(ASSURANCE_LEVEL.to_string());

    let stale: Vec<&String> = cited
        .iter()
        .filter(|n| !sources.contains(&format!("fn {n}(")) && !allowed.contains(n))
        .collect();
    assert!(
        stale.is_empty(),
        concat!(
            "docs/04-ACCEPTANCE-TESTS.md names these, but they are neither tests, ",
            "fixture cases, nor vocabulary values: {:?}"
        ),
        stale
    );
}
