//! The frozen vocabulary from `docs/00-FROZEN-VOCABULARY.md`.
//!
//! Every string in this module is part of the wire format. Changing one is a
//! breaking schema change. The `vocabulary_matches_document` test in
//! `tests/vocabulary_contract.rs` reads the markdown and fails if the two drift.

use std::fmt;

macro_rules! str_enum {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $variant:ident => $s:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name { $($(#[$vm])* $variant),+ }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];
            pub fn as_str(self) -> &'static str {
                match self { $($name::$variant => $s),+ }
            }
            pub fn parse(s: &str) -> Option<Self> {
                match s { $($s => Some($name::$variant),)+ _ => None }
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.as_str()) }
        }
        impl From<$name> for crate::canon::CanonValue {
            fn from(v: $name) -> Self { crate::canon::CanonValue::Str(v.as_str().to_string()) }
        }
    };
}

// ---------------------------------------------------------------------------
// Facets
// ---------------------------------------------------------------------------

str_enum! {
    /// Which of the four independent lineage facets a statement is about.
    Facet {
        WeightOrigin => "weight_origin",
        ParameterUpdate => "parameter_update",
        TrainingStage => "training_stage",
        InferenceAugmentation => "inference_augmentation",
    }
}

str_enum! {
    WeightOrigin {
        RandomInitializationClaimed => "random_initialization_claimed",
        DerivativeOfDisclosedBase => "derivative_of_disclosed_base",
        DistilledFromTeacher => "distilled_from_teacher",
        Unknown => "unknown",
    }
}

str_enum! {
    ParameterUpdate {
        NoUpdateObserved => "no_update_observed",
        UnmergedPeftObserved => "unmerged_peft_observed",
        MergedAdapterConsistent => "merged_adapter_consistent",
        PartialOrDenseUpdate => "partial_or_dense_update",
        Unknown => "unknown",
    }
}

str_enum! {
    TrainingStage {
        ContinuedPretraining => "continued_pretraining",
        SupervisedInstructionTuning => "supervised_instruction_tuning",
        PreferenceTuning => "preference_tuning",
        Distillation => "distillation",
        OtherOrUnknown => "other_or_unknown",
    }
}

str_enum! {
    InferenceAugmentation {
        Rag => "rag",
        ExternalApiRouter => "external_api_router",
        ToolsPromptOrchestration => "tools_prompt_orchestration",
        LocalDirectInference => "local_direct_inference",
        NoneObservedOrUnknown => "none_observed_or_unknown",
    }
}

// ---------------------------------------------------------------------------
// Conclusions
// ---------------------------------------------------------------------------

str_enum! {
    /// The only permitted conclusion wordings. There is deliberately no variant
    /// that asserts anything about the vendor's intent.
    SupportBand {
        Corroborated => "corroborated_within_supplied_evidence",
        StronglyConsistent => "strongly_consistent",
        WeaklyConsistent => "weakly_consistent",
        PartiallySupported => "partially_supported",
        InsufficientEvidence => "insufficient_evidence_abstained",
        Contradicted => "contradicted_within_observed_scope",
        NotSupplied => "artifact_not_supplied_or_out_of_scope",
    }
}

impl SupportBand {
    /// Text rendered in the PDF.
    pub fn render(self) -> &'static str {
        match self {
            SupportBand::Corroborated => "Corroborated within vendor-supplied evidence",
            SupportBand::StronglyConsistent => "Strongly consistent",
            SupportBand::WeaklyConsistent => "Weakly consistent",
            SupportBand::PartiallySupported => "Partially supported",
            SupportBand::InsufficientEvidence => "Insufficient evidence / abstained",
            SupportBand::Contradicted => "Contradicted within the observed scope",
            SupportBand::NotSupplied => "Artifact not supplied or outside scan scope",
        }
    }

    /// Band implied by a score alone. `PartiallySupported` and `Contradicted` are
    /// assigned by rule outcome and override this.
    pub fn from_tenths(t: i64) -> SupportBand {
        match t {
            850..=1000 => SupportBand::Corroborated,
            700..=849 => SupportBand::StronglyConsistent,
            500..=699 => SupportBand::WeaklyConsistent,
            _ => SupportBand::InsufficientEvidence,
        }
    }
}

str_enum! {
    EvidenceTier {
        E0 => "E0",
        E1 => "E1",
        E2 => "E2",
        E3 => "E3",
        E4 => "E4",
    }
}

impl EvidenceTier {
    pub fn rank(self) -> u8 {
        match self {
            EvidenceTier::E0 => 0,
            EvidenceTier::E1 => 1,
            EvidenceTier::E2 => 2,
            EvidenceTier::E3 => 3,
            EvidenceTier::E4 => 4,
        }
    }
    pub fn describe(self) -> &'static str {
        match self {
            EvidenceTier::E0 => "Claim only",
            EvidenceTier::E1 => "Mutable supporting record",
            EvidenceTier::E2 => "Direct structural artifact",
            EvidenceTier::E3 => "Cross-corroborated technical trail",
            EvidenceTier::E4 => "Independently supervised evidence",
        }
    }
}

str_enum! {
    OutcomeKind {
        SupportingEvidence => "supporting_evidence",
        MissingAnchor => "missing_anchor",
        Contradiction => "contradiction",
        Ambiguity => "ambiguity",
        CoverageLimitation => "coverage_limitation",
        NextEvidenceRequest => "next_evidence_request",
    }
}

// ---------------------------------------------------------------------------
// Claims and rubrics
// ---------------------------------------------------------------------------

str_enum! {
    /// A scored hypothesis. Several claims may be scored against one facet; the
    /// facet's conclusion is the best-supported claim that also clears the
    /// emission gate.
    Claim {
        UnmergedLora => "unmerged_lora",
        MergedAdapter => "merged_adapter",
        DenseFinetune => "dense_finetune",
        ContinuedPretraining => "continued_pretraining",
        Distillation => "distillation",
        Rag => "rag",
        ExternalApi => "external_api",
        Scratch => "scratch",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorSpec {
    pub name: &'static str,
    pub weight: u32,
}

const fn a(name: &'static str, weight: u32) -> AnchorSpec {
    AnchorSpec { name, weight }
}

const RUBRIC_UNMERGED_LORA: &[AnchorSpec] = &[
    a("structure", 30),
    a("base", 20),
    a("base_consistency", 20),
    a("load_or_remerge_record", 20),
    a("deployment_binding", 10),
];
const RUBRIC_MERGED_ADAPTER: &[AnchorSpec] = &[
    a("exact_base", 15),
    a("delta_pattern", 25),
    a("pre_merge_adapter", 20),
    a("merge_reproduction", 30),
    a("binding", 10),
];
const RUBRIC_DENSE_FINETUNE: &[AnchorSpec] = &[
    a("pre_post", 15),
    a("broad_deltas", 20),
    a("optimizer_trainability", 20),
    a("progression", 20),
    a("replay", 15),
    a("binding", 10),
];
const RUBRIC_CPT: &[AnchorSpec] = &[
    a("base", 10),
    a("trajectory", 15),
    a("objective_data_tokens", 25),
    a("optimizer", 20),
    a("replay", 20),
    a("binding", 10),
];
const RUBRIC_DISTILLATION: &[AnchorSpec] = &[
    a("teacher", 15),
    a("teacher_outputs", 25),
    a("objective", 20),
    a("trajectory", 15),
    a("replay", 15),
    a("binding", 10),
];
const RUBRIC_RAG: &[AnchorSpec] = &[
    a("index", 20),
    a("retrieval_trace", 25),
    a("prompt_assembly", 25),
    a("replay", 15),
    a("binding", 15),
];
const RUBRIC_EXTERNAL_API: &[AnchorSpec] = &[
    a("binding", 20),
    a("config", 20),
    a("observed_egress", 35),
    a("upstream_correlation", 20),
    a("other", 5),
];
const RUBRIC_SCRATCH: &[AnchorSpec] = &[
    a("identity", 5),
    a("step_zero", 20),
    a("trajectory", 20),
    a("optimizer_data_order", 15),
    a("data_tokenizer", 10),
    a("compute_jobs", 15),
    a("replay", 10),
    a("candidate_exclusion", 5),
];

impl Claim {
    pub fn rubric(self) -> &'static [AnchorSpec] {
        match self {
            Claim::UnmergedLora => RUBRIC_UNMERGED_LORA,
            Claim::MergedAdapter => RUBRIC_MERGED_ADAPTER,
            Claim::DenseFinetune => RUBRIC_DENSE_FINETUNE,
            Claim::ContinuedPretraining => RUBRIC_CPT,
            Claim::Distillation => RUBRIC_DISTILLATION,
            Claim::Rag => RUBRIC_RAG,
            Claim::ExternalApi => RUBRIC_EXTERNAL_API,
            Claim::Scratch => RUBRIC_SCRATCH,
        }
    }

    /// Sum of the rubric weights. Written into the report so a verifier can
    /// recompute the arithmetic without holding the table.
    pub fn rubric_divisor(self) -> u32 {
        self.rubric().iter().map(|x| x.weight).sum()
    }

    /// The facet whose conclusion this claim competes for.
    pub fn facet(self) -> Facet {
        match self {
            Claim::UnmergedLora | Claim::MergedAdapter | Claim::DenseFinetune => {
                Facet::ParameterUpdate
            }
            Claim::Scratch => Facet::WeightOrigin,
            Claim::ContinuedPretraining | Claim::Distillation => Facet::TrainingStage,
            Claim::Rag | Claim::ExternalApi => Facet::InferenceAugmentation,
        }
    }

    /// Claims that cannot both be the answer for the same artifact set. Used by
    /// the separation part of the emission gate and by `ABS-HYBRID-TOO-CLOSE`.
    ///
    /// Note what is **not** here: `Rag` and `ExternalApi` are not mutually
    /// exclusive with anything, because a system may legitimately do both while
    /// also having trained weights.
    pub fn mutually_exclusive_with(self) -> &'static [Claim] {
        match self {
            Claim::UnmergedLora => &[Claim::MergedAdapter, Claim::DenseFinetune],
            Claim::MergedAdapter => &[Claim::UnmergedLora, Claim::DenseFinetune],
            Claim::DenseFinetune => &[Claim::UnmergedLora, Claim::MergedAdapter],
            Claim::ContinuedPretraining => &[Claim::Distillation],
            Claim::Distillation => &[Claim::ContinuedPretraining],
            Claim::Scratch => &[],
            Claim::Rag => &[],
            Claim::ExternalApi => &[],
        }
    }

    pub fn render(self) -> &'static str {
        match self {
            Claim::UnmergedLora => "unmerged PEFT/LoRA adapter",
            Claim::MergedAdapter => "adapter merged into dense weights",
            Claim::DenseFinetune => "partial or dense fine-tuning",
            Claim::ContinuedPretraining => "continued pretraining",
            Claim::Distillation => "distillation from a teacher model",
            Claim::Rag => "retrieval-augmented generation",
            Claim::ExternalApi => "external inference endpoint",
            Claim::Scratch => "training from random initialisation",
        }
    }
}

// ---------------------------------------------------------------------------
// Caps and abstentions
// ---------------------------------------------------------------------------

str_enum! {
    CapId {
        Questionnaire => "CAP-QUESTIONNAIRE",
        ApiOnly => "CAP-API-ONLY",
        NoBase => "CAP-NO-BASE",
        MergeUnreproducible => "CAP-MERGE-UNREPRO",
        CptNoObjective => "CAP-CPT-NO-OBJ",
        ScratchNoStepZero => "CAP-SCRATCH-NO-ZERO",
        /// Added during implementation, not present in the original plan.
        ///
        /// The plan requires that correlated evidence not be counted repeatedly - a
        /// README, a config and a generated model card from one directory are one
        /// source, not three confirmations. Taking the maximum per anchor removes
        /// double-counting *within* an anchor but not *across* anchors: a single
        /// chatty config could otherwise fill several anchors on its own and reach
        /// "corroborated". This cap makes the requirement explicit - corroboration
        /// needs more than one independent source.
        SingleSource => "CAP-SINGLE-SOURCE",
    }
}

impl CapId {
    /// Maximum `score_tenths` this cap permits.
    pub fn max_tenths(self) -> i64 {
        match self {
            CapId::Questionnaire => 250,
            CapId::ApiOnly => 350,
            CapId::NoBase => 550,
            CapId::MergeUnreproducible => 600,
            CapId::CptNoObjective => 400,
            CapId::ScratchNoStepZero => 450,
            CapId::SingleSource => 849,
        }
    }
    pub fn render(self) -> &'static str {
        match self {
            CapId::Questionnaire => "Questionnaire or configuration text only",
            CapId::ApiOnly => "API behaviour only, for a weight-training claim",
            CapId::NoBase => "Final weights without an exact base or trajectory",
            CapId::MergeUnreproducible => {
                "Merged adapter without an exact base or a reproducible adapter"
            }
            CapId::CptNoObjective => {
                "Continued pretraining or distillation without objective or teacher trajectory"
            }
            CapId::ScratchNoStepZero => {
                "Random-initialisation claim without step-zero and intermediate checkpoints"
            }
            CapId::SingleSource => {
                "All achieved anchors trace back to a single source, so the evidence corroborates itself rather than being corroborated"
            }
        }
    }
}

str_enum! {
    AbstentionId {
        BaseUnknown => "ABS-BASE-UNKNOWN",
        QuantizedOnly => "ABS-QUANTIZED-ONLY",
        HashConflict => "ABS-HASH-CONFLICT",
        NoBinding => "ABS-NO-BINDING",
        CptFinalOnly => "ABS-CPT-FINAL-ONLY",
        DistillStyleOnly => "ABS-DISTILL-STYLE-ONLY",
        ScratchNoMatchOnly => "ABS-SCRATCH-NOMATCH-ONLY",
        HybridTooClose => "ABS-HYBRID-TOO-CLOSE",
        EvidenceMutable => "ABS-EVIDENCE-MUTABLE",
    }
}

impl AbstentionId {
    pub fn render(self) -> &'static str {
        match self {
            AbstentionId::BaseUnknown => "The exact base model identity is not established.",
            AbstentionId::QuantizedOnly => {
                "Only quantised or dtype-converted weights are available for comparison."
            }
            AbstentionId::HashConflict => "Hashes that should agree do not agree.",
            AbstentionId::NoBinding => {
                "Nothing in scope binds the observed artifacts to the claimed deployment."
            }
            AbstentionId::CptFinalOnly => {
                "Final weights alone cannot distinguish continued pretraining from supervised fine-tuning."
            }
            AbstentionId::DistillStyleOnly => {
                "Size or behavioural similarity alone does not establish distillation."
            }
            AbstentionId::ScratchNoMatchOnly => {
                "Failure to match a known base does not establish random initialisation."
            }
            AbstentionId::HybridTooClose => {
                "Two mutually exclusive explanations score too closely to separate."
            }
            AbstentionId::EvidenceMutable => {
                "All contributing evidence is mutable supporting record or weaker."
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

/// Minimum score for a positive method label.
pub const EMISSION_MIN_TENTHS: i64 = 800;
/// Minimum separation from the best mutually exclusive alternative.
pub const EMISSION_MIN_SEPARATION_TENTHS: i64 = 150;
/// Minimum evidence tier for a positive method label.
pub const EMISSION_MIN_TIER: EvidenceTier = EvidenceTier::E2;

// ---------------------------------------------------------------------------
// Language guard
// ---------------------------------------------------------------------------

/// Words that must never appear in rendered output, matched **as whole words**.
///
/// The list is about *stance*, not politeness: a screening tool that says "fraud"
/// has stopped screening and started accusing.
///
/// Whole-word matching is not a nicety. The product's own required statement
/// contains "vendor-supplied", which contains "lied"; a naive substring check
/// rejects the very sentence the report is obliged to print. Equally,
/// "authentication" is an ordinary technical word while "authentic" is a claim we
/// must never make.
pub const FORBIDDEN_WORDS: &[&str] = &[
    "lied",
    "lying",
    "liar",
    "fraud",
    "fraudulent",
    "dishonest",
    "deceptive",
    "deceit",
    "faked",
    "scam",
    "certified",
    "certification",
    "guarantee",
    "guaranteed",
    "authentic",
    // Screening is not accusation, and the interface must never use the word - not
    // even to deny it. Saying "this is not an accusation" plants the idea it was
    // one. This is a checked rule rather than a style note because it came back
    // once already after being removed by hand.
    "accuse",
    "accuses",
    "accused",
    "accusing",
    "accusation",
    "accusations",
    "accusatory",
];

/// Multi-word or symbol-bearing forms, matched as substrings because they cannot
/// be confused with a longer innocent word.
pub const FORBIDDEN_PHRASES: &[&str] =
    &["proof that", "verified true", "lie detector", "99%", "100% accurate"];

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// True when `needle` occurs in `hay` (already lowercased) delimited by non-word
/// bytes on both sides. A hyphen counts as a delimiter, so "vendor-supplied" does
/// not contain the word "supplied"'s tail as a separate word, but "supplied" would
/// match if it were listed.
fn contains_word(hay: &str, needle: &str) -> bool {
    let hb = hay.as_bytes();
    let mut from = 0usize;
    while let Some(pos) = hay[from..].find(needle) {
        let start = from + pos;
        let end = start + needle.len();
        let before_ok = start == 0 || !is_word_byte(hb[start - 1]);
        let after_ok = end >= hb.len() || !is_word_byte(hb[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// Returns the first forbidden word or phrase found in `text`, if any.
pub fn forbidden_language(text: &str) -> Option<&'static str> {
    let lower = text.to_lowercase();
    if let Some(w) = FORBIDDEN_WORDS.iter().copied().find(|w| contains_word(&lower, w)) {
        return Some(w);
    }
    FORBIDDEN_PHRASES.iter().copied().find(|p| lower.contains(p))
}

/// Assurance level. Stage 1 has exactly one.
pub const ASSURANCE_LEVEL: &str = "vendor_self_scan";

// ---------------------------------------------------------------------------
// Verify status axes
// ---------------------------------------------------------------------------

str_enum! {
    IntegrityStatus {
        Intact => "intact",
        Modified => "modified",
        Incomplete => "incomplete",
        Unreadable => "unreadable",
    }
}

str_enum! {
    ChallengeStatus {
        Bound => "bound",
        Unsigned => "unsigned",
        SignatureInvalid => "signature_invalid",
        Expired => "expired",
        CaseMismatch => "case_mismatch",
        Absent => "absent",
    }
}

str_enum! {
    MarkerStatus {
        PresentConsistent => "present_consistent",
        PresentInconsistent => "present_inconsistent",
        Absent => "absent",
        NotApplicable => "not_applicable",
    }
}

str_enum! {
    CoverageStatus {
        Complete => "complete",
        Partial => "partial",
        Minimal => "minimal",
    }
}

/// Absence of information is *minimal* coverage, never complete.
///
/// A default of `Complete` would mean a struct that was built but never populated
/// claimed full coverage of a scan that never happened.
impl Default for CoverageStatus {
    fn default() -> Self {
        CoverageStatus::Minimal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_strings_round_trip() {
        for v in SupportBand::ALL {
            assert_eq!(SupportBand::parse(v.as_str()), Some(*v));
        }
        for v in Claim::ALL {
            assert_eq!(Claim::parse(v.as_str()), Some(*v));
        }
        for v in AbstentionId::ALL {
            assert_eq!(AbstentionId::parse(v.as_str()), Some(*v));
        }
    }

    #[test]
    fn band_thresholds_match_the_frozen_table() {
        assert_eq!(SupportBand::from_tenths(0), SupportBand::InsufficientEvidence);
        assert_eq!(SupportBand::from_tenths(499), SupportBand::InsufficientEvidence);
        assert_eq!(SupportBand::from_tenths(500), SupportBand::WeaklyConsistent);
        assert_eq!(SupportBand::from_tenths(699), SupportBand::WeaklyConsistent);
        assert_eq!(SupportBand::from_tenths(700), SupportBand::StronglyConsistent);
        assert_eq!(SupportBand::from_tenths(849), SupportBand::StronglyConsistent);
        assert_eq!(SupportBand::from_tenths(850), SupportBand::Corroborated);
        assert_eq!(SupportBand::from_tenths(1000), SupportBand::Corroborated);
    }

    #[test]
    fn every_rubric_sums_to_its_divisor_and_is_nonzero() {
        for c in Claim::ALL {
            let d = c.rubric_divisor();
            assert!(d > 0, "{c} has an empty rubric");
            assert_eq!(d, c.rubric().iter().map(|a| a.weight).sum::<u32>());
        }
    }

    #[test]
    fn rubric_anchor_names_are_unique_within_a_claim() {
        for c in Claim::ALL {
            let mut seen = Vec::new();
            for a in c.rubric() {
                assert!(!seen.contains(&a.name), "{c} repeats anchor {}", a.name);
                seen.push(a.name);
            }
        }
    }

    #[test]
    fn mutual_exclusion_is_symmetric() {
        for c in Claim::ALL {
            for other in c.mutually_exclusive_with() {
                assert!(
                    other.mutually_exclusive_with().contains(c),
                    "{c} excludes {other} but not the reverse"
                );
            }
        }
    }

    #[test]
    fn rag_and_api_exclude_nothing() {
        assert!(Claim::Rag.mutually_exclusive_with().is_empty());
        assert!(Claim::ExternalApi.mutually_exclusive_with().is_empty());
    }

    #[test]
    fn merged_adapter_cannot_reach_the_emission_gate_in_stage_one() {
        // delta_pattern (25) and merge_reproduction (30) are unreachable without
        // Stage 2, so the best achievable score is 45/100 -> 450 tenths, which is
        // below EMISSION_MIN_TENTHS. This is a property of the rubric, asserted
        // here so a future weight edit cannot quietly make Stage 1 over-claim.
        let reachable: u32 = Claim::MergedAdapter
            .rubric()
            .iter()
            .filter(|a| a.name != "delta_pattern" && a.name != "merge_reproduction")
            .map(|a| a.weight)
            .sum();
        let best_tenths = (reachable as i64) * 10;
        assert!(
            best_tenths < EMISSION_MIN_TENTHS,
            "merged adapter could reach {best_tenths} tenths without Stage 2"
        );
    }

    #[test]
    fn all_rendered_text_is_free_of_forbidden_language() {
        let mut all = String::new();
        for b in SupportBand::ALL {
            all.push_str(b.render());
            all.push(' ');
        }
        for c in Claim::ALL {
            all.push_str(c.render());
            all.push(' ');
        }
        for c in CapId::ALL {
            all.push_str(c.render());
            all.push(' ');
        }
        for x in AbstentionId::ALL {
            all.push_str(x.render());
            all.push(' ');
        }
        for t in EvidenceTier::ALL {
            all.push_str(t.describe());
            all.push(' ');
        }
        assert_eq!(forbidden_language(&all), None, "in: {all}");
    }

    #[test]
    fn forbidden_language_is_case_insensitive() {
        assert_eq!(forbidden_language("The vendor LIED here"), Some("lied"));
        assert_eq!(forbidden_language("nothing to see"), None);
    }

    #[test]
    fn whole_word_matching_does_not_fire_on_innocent_longer_words() {
        // The regression that caught this: "vendor-supplied" ends in "lied".
        assert_eq!(forbidden_language("consistency within vendor-supplied evidence"), None);
        assert_eq!(forbidden_language("the artifact was supplied"), None);
        assert_eq!(forbidden_language("token authentication succeeded"), None);
        assert_eq!(forbidden_language("a certificate was present"), None);
        // ...but the words themselves are still caught.
        assert_eq!(forbidden_language("this is authentic"), Some("authentic"));
        assert_eq!(forbidden_language("a certified result"), Some("certified"));
        assert_eq!(forbidden_language("we guarantee it"), Some("guarantee"));
    }

    #[test]
    fn phrases_are_matched_as_substrings() {
        assert_eq!(forbidden_language("this is proof that it happened"), Some("proof that"));
        assert_eq!(forbidden_language("detects 99% of cases"), Some("99%"));
        assert_eq!(forbidden_language("a lie detector"), Some("lie detector"));
        // "prove" on its own is permitted: the required statement uses it.
        assert_eq!(forbidden_language("cannot prove historical training events"), None);
    }

    #[test]
    fn required_statement_is_clean() {
        assert_eq!(forbidden_language(crate::REQUIRED_STATEMENT), None);
    }
}
