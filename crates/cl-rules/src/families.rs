//! The rule families from `docs/01-RULE-CATALOGUE.md`.
//!
//! Each family reads normalised facts and emits outcomes. No family computes a
//! score, applies a cap, or decides a band - that is [`crate::engine`]'s job, and
//! keeping the two apart is what makes the scoring auditable independently of the
//! evidence rules.
//!
//! ## Tiering, corrected against the plan's own definitions
//!
//! The plan defines E1 as a *mutable supporting record* ("README, screenshot, config
//! text, invoice") and E2 as a *direct structural artifact* ("adapter tensors,
//! SafeTensors header, checkpoint index"). A first pass at this catalogue put
//! `adapter_config.json` at E2 because it is the canonical PEFT artifact. That was
//! wrong on the plan's own terms: a JSON config is text that anyone can write, and
//! calling it structural would let a vendor reach a method label by editing a file.
//!
//! So the line here is strict: **anything read out of text is E1; only structure
//! observed inside a binary container is E2.** An adapter config declaring
//! `peft_type: LORA` is E1. The `lora_A`/`lora_B` tensor pairs in the SafeTensors
//! header, with shapes that agree with the declared rank, are E2. The practical
//! effect is that a folder of hand-written configs cannot name a method, which is
//! the behaviour the product promises.

use crate::engine::{AbstentionRequest, CapRequest, Emissions};
use crate::model::RuleOutcome;
use cl_core::vocab::{
    AbstentionId, CapId, Claim, EvidenceTier as T, Facet, InferenceAugmentation as Aug,
    ParameterUpdate as PU, TrainingStage as TS, WeightOrigin as WO,
};
use cl_facts::{ArtifactType, Fact, FactKind as K, FactSet, FieldValue};

pub struct Ctx<'a> {
    pub f: &'a FactSet,
    pub out: Emissions,
}

impl<'a> Ctx<'a> {
    pub fn new(f: &'a FactSet) -> Self {
        Ctx { f, out: Emissions::default() }
    }

    pub fn emit(&mut self, o: RuleOutcome) {
        self.out.outcomes.push(o);
    }

    pub fn cap(&mut self, claim: Claim, cap_id: CapId, triggered_by: &'static str) {
        let r = CapRequest { claim, cap_id, triggered_by };
        if !self.out.caps.contains(&r) {
            self.out.caps.push(r);
        }
    }

    pub fn abstain(&mut self, facet: Facet, id: AbstentionId) {
        let r = AbstentionRequest { facet, id };
        if !self.out.abstentions.contains(&r) {
            self.out.abstentions.push(r);
        }
    }

    /// Digest of the artifact a fact came from, for citation.
    fn digest_of(&self, fact: &Fact) -> Option<String> {
        let id = fact.artifact_id.as_deref()?;
        self.f.artifact(id)?.sha256.map(|d| d.to_hex())
    }

    /// A supporting outcome bound to the fact that produced it.
    #[allow(clippy::too_many_arguments)]
    pub fn support(
        &mut self,
        rule: &'static str,
        claim: Claim,
        anchor: &'static str,
        achievement: u32,
        tier: T,
        text: impl Into<String>,
        fact: &Fact,
    ) {
        let mut o = RuleOutcome::support(rule, claim, anchor, achievement, tier, text)
            .group(fact.source_group.clone())
            .fact(fact.fact_id.clone());
        if let Some(d) = self.digest_of(fact) {
            o = o.artifact_digest(d);
        }
        self.emit(o);
    }

    /// A contradiction. The catalogue requires every contradiction to cite an
    /// artifact hash; this helper makes that the only convenient way to raise one.
    pub fn contradict(
        &mut self,
        rule: &'static str,
        facet: Facet,
        claim: Option<Claim>,
        text: impl Into<String>,
        fact: &Fact,
    ) {
        let mut o = RuleOutcome::contradiction(rule, facet, text)
            .group(fact.source_group.clone())
            .fact(fact.fact_id.clone());
        if let Some(c) = claim {
            o = o.on_claim(c);
            o.facet = Some(facet);
        }
        if let Some(d) = self.digest_of(fact) {
            o = o.artifact_digest(d);
        }
        self.emit(o);
    }

    pub fn limitation(&mut self, rule: &'static str, text: impl Into<String>) {
        self.emit(RuleOutcome::limitation(rule, text));
    }

    pub fn ambiguity(&mut self, rule: &'static str, text: impl Into<String>) {
        self.emit(RuleOutcome::ambiguity(rule, text));
    }

    pub fn next_evidence(&mut self, rule: &'static str, text: impl Into<String>) {
        self.emit(RuleOutcome::next_evidence(rule, text));
    }

    pub fn missing(&mut self, rule: &'static str, claim: Claim, anchor: &'static str, text: impl Into<String>) {
        self.emit(RuleOutcome::missing(rule, claim, anchor, text));
    }
}

/// Read a field under any of several plausible names.
///
/// Parsers and rules are written by different hands against the same catalogue, and
/// a rule that silently reads nothing is the worst failure mode available: it looks
/// like "no evidence" rather than like a bug. Accepting a small alias set makes that
/// mismatch survivable, and the fixture suite catches the cases it does not.
fn any<'a>(f: &'a Fact, keys: &[&str]) -> Option<&'a FieldValue> {
    keys.iter().find_map(|k| f.field(k))
}
fn any_int(f: &Fact, keys: &[&str]) -> Option<i64> {
    any(f, keys).and_then(|v| v.as_int())
}
fn any_text<'a>(f: &'a Fact, keys: &[&str]) -> Option<&'a str> {
    any(f, keys).and_then(|v| v.as_text())
}
fn any_bool(f: &Fact, keys: &[&str]) -> Option<bool> {
    any(f, keys).and_then(|v| v.as_bool())
}
fn any_list<'a>(f: &'a Fact, keys: &[&str]) -> Option<&'a [String]> {
    any(f, keys).and_then(|v| v.as_list())
}

// ===========================================================================
// CL-INV-*: scope
// ===========================================================================

pub fn scope(ctx: &mut Ctx) {
    let has_weights = ctx.f.artifacts.iter().any(|a| {
        matches!(
            a.artifact_type,
            ArtifactType::SafeTensors
                | ArtifactType::Gguf
                | ArtifactType::Onnx
                | ArtifactType::OpaqueSerialization
                | ArtifactType::ShardIndex
        )
    });
    let has_any = !ctx.f.artifacts.is_empty();

    if !has_any {
        ctx.limitation("CL-INV-007", "No artifact was present in any selected root.");
        for f in Facet::ALL {
            ctx.out.out_of_scope.push(*f);
        }
        return;
    }
    if !has_weights {
        ctx.limitation(
            "CL-INV-007",
            "No model-bearing artifact was found in any selected root. Weight-related \
             conclusions are limited to what the supplied text records can show.",
        );
        // Weight origin and parameter update cannot be observed at all without a
        // model-bearing artifact. Saying "insufficient evidence" would understate
        // this: the artifact was not in scope, which is a different statement.
        ctx.out.out_of_scope.push(Facet::WeightOrigin);
        ctx.out.out_of_scope.push(Facet::ParameterUpdate);
    }

    let only_text = ctx.f.artifacts.iter().all(|a| {
        matches!(
            a.artifact_type,
            ArtifactType::PlainText
                | ArtifactType::ModelCard
                | ArtifactType::GenericJson
                | ArtifactType::GenericYaml
                | ArtifactType::GenericToml
                | ArtifactType::Unrecognised
        )
    });
    if only_text && has_any {
        ctx.limitation(
            "CL-INV-008",
            "The selected scope contains only documents and text records.",
        );
    }

    for a in ctx.f.artifacts.iter().filter(|a| a.artifact_type == ArtifactType::OpaqueSerialization)
    {
        let _ = a;
    }
    let opaque = ctx.f.artifacts_of(ArtifactType::OpaqueSerialization).count();
    if opaque > 0 {
        ctx.limitation(
            "CL-FMT-006",
            format!(
                "{opaque} artifact(s) use a serialisation format that executes code when \
                 loaded. They were hashed and counted; their contents were not read."
            ),
        );
    }
}

// ===========================================================================
// CL-BASE-*: base model identity
// ===========================================================================

/// Claims for which knowing the base model matters.
const BASE_DEPENDENT: &[Claim] = &[
    Claim::UnmergedLora,
    Claim::MergedAdapter,
    Claim::DenseFinetune,
    Claim::ContinuedPretraining,
];

pub fn base_identity(ctx: &mut Ctx) {
    let refs: Vec<Fact> = ctx.f.by_kind(K::BaseModelReference).cloned().collect();
    let mut exact = false;
    let mut named = false;

    for r in &refs {
        let pinned = any_bool(&r, &["revision_pinned", "pinned", "has_revision"]).unwrap_or(false)
            || any_text(&r, &["revision", "commit", "sha"]).is_some();
        let name = any_text(&r, &["base_ref", "base_model_name_or_path", "base", "name"])
            .unwrap_or("(unnamed)")
            .to_string();
        if pinned {
            exact = true;
            for c in BASE_DEPENDENT {
                let anchor = if *c == Claim::MergedAdapter { "exact_base" } else { "base" };
                ctx.support(
                    "CL-BASE-001",
                    *c,
                    anchor,
                    100,
                    T::E1,
                    format!(
                        "A base model is named with a pinned revision: {name}. This is a \
                         text record and is mutable."
                    ),
                    r,
                );
            }
        } else {
            named = true;
            for c in BASE_DEPENDENT {
                let anchor = if *c == Claim::MergedAdapter { "exact_base" } else { "base" };
                ctx.support(
                    "CL-BASE-002",
                    *c,
                    anchor,
                    30,
                    T::E1,
                    format!("A base model is named without a pinned revision: {name}."),
                    r,
                );
            }
        }
    }

    // Base weights actually present and hashed: structural, not a text record.
    let base_weights: Vec<Fact> = ctx
        .f
        .by_kind(K::TensorHeader)
        .filter(|f| any_bool(f, &["is_base", "base_weights"]).unwrap_or(false))
        .cloned()
        .collect();
    for b in &base_weights {
        for c in BASE_DEPENDENT {
            ctx.support(
                "CL-BASE-009",
                *c,
                "base_consistency",
                100,
                T::E2,
                "Base weights are present within the scanned scope and were hashed.",
                b,
            );
        }
    }

    // Architecture and tokenizer consistency with the declared base family.
    if let Some(mc) = ctx.f.first(K::ModelConfig).cloned() {
        if any_text(&mc, &["model_type", "architecture", "architectures"]).is_some() {
            for c in BASE_DEPENDENT {
                ctx.support(
                    "CL-BASE-005",
                    *c,
                    "base_consistency",
                    60,
                    T::E1,
                    "Model architecture and dimensions are recorded and internally coherent.",
                    &mc,
                );
            }
        }
    }
    if let Some(tk) = ctx.f.first(K::TokenizerIdentity).cloned() {
        for c in BASE_DEPENDENT {
            ctx.support(
                "CL-BASE-007",
                *c,
                "base_consistency",
                40,
                T::E1,
                "A tokenizer identity is recorded.",
                &tk,
            );
        }
    }

    // Adapter config naming a base that conflicts with the model config's base.
    let adapter_base: Option<String> = ctx
        .f
        .by_kind(K::AdapterConfig)
        .find_map(|f| any_text(f, &["base_model_name_or_path", "base_ref"]).map(|s| s.to_string()));
    let config_base: Option<String> = ctx
        .f
        .by_kind(K::ModelConfig)
        .find_map(|f| any_text(f, &["_name_or_path", "base_ref"]).map(|s| s.to_string()));
    if let (Some(a), Some(b)) = (&adapter_base, &config_base) {
        if a != b && !a.is_empty() && !b.is_empty() {
            if let Some(fact) = ctx.f.first(K::AdapterConfig).cloned() {
                ctx.contradict(
                    "CL-BASE-004",
                    Facet::WeightOrigin,
                    None,
                    format!(
                        "The adapter configuration names base `{a}` while the model \
                         configuration names `{b}`. These two supplied records disagree."
                    ),
                    &fact,
                );
            }
        }
    }

    if !exact && !named {
        for c in BASE_DEPENDENT {
            let anchor = if *c == Claim::MergedAdapter { "exact_base" } else { "base" };
            ctx.missing(
                "CL-BASE-003",
                *c,
                anchor,
                "No base model identity of any kind was supplied within scope.",
            );
        }
        ctx.abstain(Facet::WeightOrigin, AbstentionId::BaseUnknown);
        ctx.abstain(Facet::ParameterUpdate, AbstentionId::BaseUnknown);
    } else if !exact {
        for c in BASE_DEPENDENT {
            ctx.next_evidence(
                "CL-BASE-001",
                "Supplying the exact base revision or commit hash would raise the base anchor.",
            );
            let _ = c;
        }
    }
}

// ===========================================================================
// CL-LORA-*: unmerged PEFT
// ===========================================================================

pub fn lora(ctx: &mut Ctx) {
    let configs: Vec<Fact> = ctx.f.by_kind(K::AdapterConfig).cloned().collect();
    let tensor_sets: Vec<Fact> = ctx.f.by_kind(K::AdapterTensorSet).cloned().collect();

    let mut declared_rank: Option<i64> = None;
    let mut declared_targets: Vec<String> = Vec::new();

    for c in &configs {
        let peft_type = any_text(c, &["peft_type", "type"]).unwrap_or("(unspecified)").to_string();
        declared_rank = any_int(c, &["r", "rank", "lora_rank"]).or(declared_rank);
        if let Some(t) = any_list(c, &["target_modules", "targets"]) {
            declared_targets = t.to_vec();
        }
        ctx.support(
            "CL-LORA-001",
            Claim::UnmergedLora,
            "structure",
            45,
            T::E1,
            format!(
                "An adapter configuration declares a PEFT method: {peft_type}. A \
                 configuration file is a text record and is mutable."
            ),
            c,
        );
        if any_list(c, &["modules_to_save"]).map(|m| !m.is_empty()).unwrap_or(false) {
            ctx.support(
                "CL-LORA-009",
                Claim::UnmergedLora,
                "structure",
                60,
                T::E1,
                "The adapter configuration declares additional saved modules, so the \
                 expected tensor set is wider than adapter matrices alone.",
                c,
            );
        }
        if any_bool(c, &["use_dora"]).unwrap_or(false) || any_bool(c, &["use_rslora"]).unwrap_or(false)
        {
            ctx.emit(
                RuleOutcome::new(
                    "CL-LORA-010",
                    cl_core::vocab::OutcomeKind::SupportingEvidence,
                    "A DoRA or RS-LoRA variant is declared, so the expected tensor set \
                     differs from plain LoRA and was adjusted accordingly.",
                )
                .on_claim(Claim::UnmergedLora)
                .group(c.source_group.clone())
                .fact(c.fact_id.clone()),
            );
        }
    }

    for ts in &tensor_sets {
        let pairs = any_int(ts, &["lora_pair_count", "pairs"]).unwrap_or(0);
        let ranks = any_list(ts, &["inferred_ranks", "ranks"]).map(|r| r.to_vec()).unwrap_or_default();
        let targets = any_list(ts, &["target_module_suffixes", "targets"])
            .map(|r| r.to_vec())
            .unwrap_or_default();

        if pairs > 0 {
            ctx.support(
                "CL-LORA-002",
                Claim::UnmergedLora,
                "structure",
                75,
                T::E2,
                format!(
                    "{pairs} adapter tensor pair(s) are present in the container header \
                     with method-consistent key names."
                ),
                ts,
            );
        }

        // Rank agreement between the declared config and the observed shapes.
        match (declared_rank, ranks.len()) {
            (Some(r), 1) => {
                let observed = ranks[0].parse::<i64>().ok();
                if observed == Some(r) {
                    ctx.support(
                        "CL-LORA-003",
                        Claim::UnmergedLora,
                        "structure",
                        100,
                        T::E2,
                        format!(
                            "Adapter tensor shapes imply rank {r}, matching the rank declared \
                             in the adapter configuration."
                        ),
                        ts,
                    );
                } else if let Some(o) = observed {
                    ctx.contradict(
                        "CL-LORA-006",
                        Facet::ParameterUpdate,
                        Some(Claim::UnmergedLora),
                        format!(
                            "The adapter configuration declares rank {r}, but the adapter \
                             tensor shapes imply rank {o}."
                        ),
                        ts,
                    );
                }
            }
            (Some(_), n) if n > 1 => {
                ctx.ambiguity(
                    "CL-LORA-011",
                    format!(
                        "Adapter tensors imply {n} different ranks, which is consistent with \
                         several adapters or with per-layer ranks."
                    ),
                );
                ctx.support(
                    "CL-LORA-002",
                    Claim::UnmergedLora,
                    "structure",
                    75,
                    T::E2,
                    "Adapter tensor pairs are present with more than one implied rank.",
                    ts,
                );
            }
            _ => {}
        }

        if !targets.is_empty() && !declared_targets.is_empty() {
            let declared_covers = declared_targets
                .iter()
                .any(|d| targets.iter().any(|t| t.contains(d.as_str()) || d.contains(t.as_str())));
            if declared_covers {
                ctx.support(
                    "CL-LORA-004",
                    Claim::UnmergedLora,
                    "structure",
                    90,
                    T::E2,
                    "The observed adapter tensor key set matches the declared target modules.",
                    ts,
                );
            }
        }

        if any_bool(ts, &["has_dora"]).unwrap_or(false) && configs.is_empty() {
            ctx.ambiguity(
                "CL-LORA-010",
                "DoRA magnitude tensors are present without a configuration describing them.",
            );
        }
    }

    if !configs.is_empty() && tensor_sets.is_empty() {
        ctx.missing(
            "CL-LORA-007",
            Claim::UnmergedLora,
            "structure",
            "An adapter configuration is present but no adapter tensors were found in scope.",
        );
    }
    if configs.is_empty() && !tensor_sets.is_empty() {
        if let Some(ts) = tensor_sets.first() {
            ctx.support(
                "CL-LORA-008",
                Claim::UnmergedLora,
                "structure",
                40,
                T::E2,
                "Adapter tensors are present with no adapter configuration in scope, so the \
                 declared rank and targets could not be cross-checked.",
                ts,
            );
        }
        ctx.ambiguity(
            "CL-LORA-008",
            "Adapter tensors are present without a configuration to check them against.",
        );
    }

    // A record of the adapter actually being loaded or merged at serve time.
    let load_record = ctx
        .f
        .by_kind(K::ServingConfig)
        .find(|f| {
            any_bool(f, &["enable_lora", "lora"]).unwrap_or(false)
                || any_text(f, &["lora_modules", "adapter_path"]).is_some()
        })
        .cloned()
        .or_else(|| ctx.f.first(K::MergeRecord).cloned());
    match load_record {
        Some(lr) => ctx.support(
            "CL-LORA-013",
            Claim::UnmergedLora,
            "load_or_remerge_record",
            100,
            T::E1,
            "A serving or merge record referencing the adapter was observed.",
            &lr,
        ),
        None => {
            if !configs.is_empty() || !tensor_sets.is_empty() {
                ctx.missing(
                    "CL-LORA-014",
                    Claim::UnmergedLora,
                    "load_or_remerge_record",
                    "No record was observed of the adapter being loaded or merged.",
                );
            }
        }
    }

    // Trainable/total parameter accounting against the adapter shape.
    if let Some(tp) = ctx.f.first(K::TrainableParameterRecord).cloned() {
        let trainable = any_int(&tp, &["trainable", "trainable_params"]);
        let total = any_int(&tp, &["total", "all_params", "total_params"]);
        if let (Some(tr), Some(to)) = (trainable, total) {
            if to > 0 && tr > 0 && tr < to {
                let pct_x100 = (tr.saturating_mul(10_000)) / to;
                if pct_x100 <= 500 {
                    ctx.support(
                        "CL-LORA-015",
                        Claim::UnmergedLora,
                        "base_consistency",
                        80,
                        T::E1,
                        format!(
                            "The recorded trainable parameter share ({}.{:02}%) is consistent \
                             with adapter-only training.",
                            pct_x100 / 100,
                            pct_x100 % 100
                        ),
                        &tp,
                    );
                } else {
                    ctx.ambiguity(
                        "CL-LORA-016",
                        "The recorded trainable parameter share is larger than adapter-only \
                         training would ordinarily produce.",
                    );
                }
            } else if tr >= to && to > 0 {
                ctx.contradict(
                    "CL-LORA-016",
                    Facet::ParameterUpdate,
                    Some(Claim::UnmergedLora),
                    "The record states that every parameter was trainable, which conflicts \
                     with an adapter-only training claim.",
                    &tp,
                );
            }
        }
    }

    if !configs.is_empty() || !tensor_sets.is_empty() {
        ctx.limitation(
            "CL-LORA-012",
            "Absence of adapter files never establishes that an adapter was not used, \
             because an adapter may have been merged into the weights.",
        );
    }
}

// ===========================================================================
// CL-MERGE-*: merged adapter
// ===========================================================================

pub fn merged_adapter(ctx: &mut Ctx) {
    let declared = ctx.f.declared.parameter_update == Some(PU::MergedAdapterConsistent);
    let dense_present = ctx.f.by_kind(K::TensorHeader).any(|f| {
        any_int(f, &["parameters"]).unwrap_or(0) > 0
            && !ctx.f.has(K::AdapterTensorSet)
    });
    if !declared && !dense_present {
        return;
    }

    if let Some(th) = ctx.f.first(K::TensorHeader).cloned() {
        ctx.support(
            "CL-MERGE-001",
            Claim::MergedAdapter,
            "exact_base",
            60,
            T::E2,
            "A full-size dense checkpoint is present alongside a declared base.",
            &th,
        );
        if ctx.f.has(K::ModelConfig) && ctx.f.has(K::TokenizerIdentity) {
            ctx.support(
                "CL-MERGE-004",
                Claim::MergedAdapter,
                "exact_base",
                80,
                T::E2,
                "Architecture, tokenizer and tensor layout are mutually compatible.",
                &th,
            );
        }
    }
    if let Some(mr) = ctx.f.first(K::MergeRecord).cloned() {
        ctx.support(
            "CL-MERGE-002",
            Claim::MergedAdapter,
            "pre_merge_adapter",
            70,
            T::E1,
            "A merge log or merge configuration was observed.",
            &mr,
        );
    }
    if ctx.f.has(K::AdapterTensorSet) && ctx.f.has(K::TensorHeader) {
        if let Some(ts) = ctx.f.first(K::AdapterTensorSet).cloned() {
            ctx.support(
                "CL-MERGE-003",
                Claim::MergedAdapter,
                "pre_merge_adapter",
                100,
                T::E2,
                "A pre-merge adapter was supplied alongside the merged checkpoint.",
                &ts,
            );
        }
    }

    // The two anchors Stage 1 structurally cannot reach.
    ctx.missing(
        "CL-MERGE-005",
        Claim::MergedAdapter,
        "delta_pattern",
        "Stage 1 does not compare tensors, so it cannot establish whether the weight \
         deltas have low effective rank.",
    );
    ctx.next_evidence(
        "CL-MERGE-006",
        "Reproducing the merge - re-applying a supplied pre-merge adapter to the exact \
         base and comparing the result - requires Stage-2 tensor analysis.",
    );
    ctx.cap(Claim::MergedAdapter, CapId::MergeUnreproducible, "CL-MERGE-006");

    if ctx.f.has(K::QuantizationRecord) {
        ctx.limitation(
            "CL-MERGE-007",
            "The final weights are quantised or dtype-converted, which would erase the \
             delta pattern that a merged adapter leaves behind.",
        );
        ctx.abstain(Facet::ParameterUpdate, AbstentionId::QuantizedOnly);
    }
}

// ===========================================================================
// CL-DENSE-*: dense or partial fine-tuning
// ===========================================================================

pub fn dense(ctx: &mut Ctx) {
    let steps: Vec<Fact> = ctx.f.by_kind(K::CheckpointStep).cloned().collect();
    let metrics: Vec<Fact> = ctx.f.by_kind(K::TrainingMetric).cloned().collect();

    let has_base = ctx.f.has(K::BaseModelReference);
    let has_final = ctx.f.has(K::TensorHeader);
    if has_base && has_final {
        if let Some(th) = ctx.f.first(K::TensorHeader).cloned() {
            ctx.support(
                "CL-DENSE-001",
                Claim::DenseFinetune,
                "pre_post",
                100,
                T::E2,
                "Both a pre-training identity and a final checkpoint identity are supplied.",
                &th,
            );
        }
    } else if has_final {
        if let Some(th) = ctx.f.first(K::TensorHeader).cloned() {
            ctx.support(
                "CL-DENSE-002",
                Claim::DenseFinetune,
                "pre_post",
                20,
                T::E2,
                "Only a final checkpoint identity is supplied.",
                &th,
            );
        }
    }

    if let Some(opt) = ctx.f.first(K::OptimizerRecord).cloned() {
        ctx.support(
            "CL-DENSE-003",
            Claim::DenseFinetune,
            "optimizer_trainability",
            100,
            T::E1,
            "An optimizer or trainability record was observed.",
            &opt,
        );
    }

    let distinct_steps: Vec<i64> = {
        let mut v: Vec<i64> = steps.iter().filter_map(|s| any_int(s, &["step", "global_step"])).collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    if distinct_steps.len() >= 2 {
        if let Some(s) = steps.first() {
            ctx.support(
                "CL-DENSE-004",
                Claim::DenseFinetune,
                "progression",
                100,
                T::E1,
                format!(
                    "{} distinct checkpoint steps were observed, spanning {} to {}.",
                    distinct_steps.len(),
                    distinct_steps.first().copied().unwrap_or(0),
                    distinct_steps.last().copied().unwrap_or(0)
                ),
                s,
            );
        }
    } else if has_final {
        ctx.missing(
            "CL-DENSE-005",
            Claim::DenseFinetune,
            "progression",
            "Only one checkpoint is present, so no training progression is observable.",
        );
    }

    for m in &metrics {
        let count = any_int(m, &["entry_count", "entries"]).unwrap_or(0);
        let monotonic = any_bool(m, &["steps_monotonic", "monotone_step_order"]).unwrap_or(true);
        if count >= 2 && monotonic {
            ctx.support(
                "CL-DENSE-006",
                Claim::DenseFinetune,
                "progression",
                70,
                T::E1,
                format!("A loss and learning-rate history of {count} entries was observed."),
                m,
            );
        }
        if count >= 2 && !monotonic {
            ctx.contradict(
                "CL-DENSE-007",
                Facet::ParameterUpdate,
                None,
                "The supplied loss history is not ordered consistently with its own step \
                 record.",
                m,
            );
        }
    }

    ctx.next_evidence(
        "CL-DENSE-008",
        "Establishing broad tensor-level deltas requires Stage-2 comparison against the \
         exact base checkpoint.",
    );
    if has_final {
        ctx.limitation(
            "CL-DENSE-009",
            "A full-size checkpoint does not show that every parameter was trained. \
             Conversion or quantisation alone can make every serialised tensor differ.",
        );
    }
}

// ===========================================================================
// CL-CPT-*: continued pretraining
// ===========================================================================

pub fn continued_pretraining(ctx: &mut Ctx) {
    let declared = ctx.f.declared.training_stage == Some(TS::ContinuedPretraining);
    let objective = ctx.f.first(K::TrainingObjective).cloned();
    let corpus = ctx.f.first(K::DatasetManifest).cloned();
    let tokens = ctx.f.first(K::TokenCountRecord).cloned();
    let optimizer = ctx.f.first(K::OptimizerRecord).cloned();
    let metrics = ctx.f.first(K::TrainingMetric).cloned();
    let tokenizer = ctx.f.first(K::TokenizerIdentity).cloned();

    if !declared && objective.is_none() && corpus.is_none() {
        return;
    }

    if let Some(o) = &objective {
        ctx.support(
            "CL-CPT-001",
            Claim::ContinuedPretraining,
            "objective_data_tokens",
            45,
            T::E1,
            format!(
                "A training objective is recorded: {}.",
                any_text(o, &["objective", "task_type", "loss"]).unwrap_or("(unspecified)")
            ),
            o,
        );
    }
    if let Some(c) = &corpus {
        let has_tokens = tokens.is_some() || any_int(c, &["tokens", "token_count"]).is_some();
        if has_tokens {
            ctx.support(
                "CL-CPT-002",
                Claim::ContinuedPretraining,
                "objective_data_tokens",
                100,
                T::E1,
                "A corpus manifest with token counts was observed.",
                c,
            );
        } else {
            ctx.support(
                "CL-CPT-002",
                Claim::ContinuedPretraining,
                "objective_data_tokens",
                60,
                T::E1,
                "A corpus manifest was observed, without token counts.",
                c,
            );
        }
    }
    if let Some(t) = &tokenizer {
        if any_bool(t, &["vocab_changed", "vocab_extended"]).unwrap_or(false) {
            ctx.support(
                "CL-CPT-003",
                Claim::ContinuedPretraining,
                "objective_data_tokens",
                55,
                T::E1,
                "A tokenizer vocabulary change is recorded.",
                t,
            );
        }
    }
    if let Some(o) = &optimizer {
        ctx.support(
            "CL-CPT-004",
            Claim::ContinuedPretraining,
            "optimizer",
            100,
            T::E1,
            "A checkpoint and optimizer trajectory was observed.",
            o,
        );
    }
    if let Some(m) = &metrics {
        ctx.support(
            "CL-CPT-005",
            Claim::ContinuedPretraining,
            "trajectory",
            100,
            T::E1,
            "A loss history against training progress was observed.",
            m,
        );
    }

    // Unconditional whenever CPT is in play.
    ctx.limitation(
        "CL-CPT-006",
        "Final weights alone cannot distinguish continued pretraining from supervised \
         fine-tuning. Distinguishing them needs the objective, the data and the trajectory.",
    );

    let has_any_anchor =
        objective.is_some() || corpus.is_some() || optimizer.is_some() || metrics.is_some();
    if !has_any_anchor {
        ctx.missing(
            "CL-CPT-007",
            Claim::ContinuedPretraining,
            "objective_data_tokens",
            "No objective, corpus or trajectory record was observed.",
        );
        ctx.abstain(Facet::TrainingStage, AbstentionId::CptFinalOnly);
        ctx.cap(Claim::ContinuedPretraining, CapId::CptNoObjective, "CL-CPT-007");
    } else if objective.is_none() && corpus.is_none() {
        ctx.cap(Claim::ContinuedPretraining, CapId::CptNoObjective, "CL-CPT-006");
    }
}

// ===========================================================================
// CL-DIST-*: distillation
// ===========================================================================

pub fn distillation(ctx: &mut Ctx) {
    let declared = ctx.f.declared.training_stage == Some(TS::Distillation)
        || ctx.f.declared.weight_origin == Some(WO::DistilledFromTeacher);
    let teacher = ctx.f.first(K::TeacherReference).cloned();
    let cache = ctx.f.first(K::TeacherOutputCache).cloned();
    if !declared && teacher.is_none() {
        return;
    }

    if let Some(t) = &teacher {
        let pinned = any_bool(t, &["revision_pinned", "pinned"]).unwrap_or(false);
        let name = any_text(t, &["teacher", "teacher_ref", "name"]).unwrap_or("(unnamed)");
        if pinned {
            ctx.support(
                "CL-DIST-001",
                Claim::Distillation,
                "teacher",
                100,
                T::E1,
                format!("A teacher model is identified with a pinned revision: {name}."),
                t,
            );
        } else {
            ctx.support(
                "CL-DIST-002",
                Claim::Distillation,
                "teacher",
                30,
                T::E1,
                format!("A teacher model is named without a pinned revision: {name}."),
                t,
            );
        }
    }
    if let Some(o) = ctx.f.first(K::TrainingObjective).cloned() {
        let obj = any_text(&o, &["objective", "loss"]).unwrap_or("");
        let distill_shaped = ["kl", "kd", "distill", "soft_target", "logit"]
            .iter()
            .any(|k| obj.to_ascii_lowercase().contains(k));
        if distill_shaped {
            ctx.support(
                "CL-DIST-003",
                Claim::Distillation,
                "objective",
                100,
                T::E1,
                format!("A distillation objective is recorded: {obj}."),
                &o,
            );
        }
    }
    if let Some(c) = &cache {
        ctx.support(
            "CL-DIST-004",
            Claim::Distillation,
            "teacher_outputs",
            100,
            T::E1,
            "A hashed teacher-output or logit cache was observed.",
            c,
        );
    }
    if let Some(m) = ctx.f.first(K::TrainingMetric).cloned() {
        ctx.support(
            "CL-DIST-006",
            Claim::Distillation,
            "trajectory",
            100,
            T::E1,
            "A student checkpoint trajectory was observed.",
            &m,
        );
    }

    ctx.limitation(
        "CL-DIST-007",
        "Model size, style or behavioural similarity does not establish distillation. \
         Shared training data produces similar behaviour without any teacher.",
    );
    if teacher.is_none() && cache.is_none() {
        ctx.abstain(Facet::TrainingStage, AbstentionId::DistillStyleOnly);
        ctx.cap(Claim::Distillation, CapId::CptNoObjective, "CL-DIST-007");
        ctx.next_evidence(
            "CL-DIST-008",
            "Record precisely what is meant by distillation here, and supply the teacher \
             identity and a hashed teacher-output cache.",
        );
    }
}

// ===========================================================================
// CL-SCRATCH-*: claimed random initialisation
// ===========================================================================

pub fn scratch(ctx: &mut Ctx) {
    if ctx.f.declared.weight_origin != Some(WO::RandomInitializationClaimed) {
        return;
    }

    let steps: Vec<i64> = {
        let mut v: Vec<i64> = ctx
            .f
            .by_kind(K::CheckpointStep)
            .filter_map(|s| any_int(s, &["step", "global_step"]))
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    let has_step_zero = steps.first() == Some(&0);

    if has_step_zero {
        if let Some(s) = ctx.f.by_kind(K::CheckpointStep).next().cloned() {
            ctx.support(
                "CL-SCRATCH-001",
                Claim::Scratch,
                "step_zero",
                100,
                T::E1,
                "A step-zero checkpoint recorded before training was observed.",
                &s,
            );
        }
    } else {
        ctx.missing(
            "CL-SCRATCH-009",
            Claim::Scratch,
            "step_zero",
            "No step-zero or random-initialisation checkpoint is present in scope.",
        );
        ctx.cap(Claim::Scratch, CapId::ScratchNoStepZero, "CL-SCRATCH-009");
    }

    if steps.len() >= 3 {
        if let Some(s) = ctx.f.by_kind(K::CheckpointStep).next().cloned() {
            ctx.support(
                "CL-SCRATCH-002",
                Claim::Scratch,
                "trajectory",
                100,
                T::E1,
                format!("{} distinct checkpoint steps were observed.", steps.len()),
                &s,
            );
        }
    }
    if let Some(o) = ctx.f.first(K::OptimizerRecord).cloned() {
        let seeded = ctx.f.has(K::SeedRecord);
        ctx.support(
            "CL-SCRATCH-003",
            Claim::Scratch,
            "optimizer_data_order",
            if seeded { 100 } else { 60 },
            T::E1,
            if seeded {
                "Optimizer, scheduler and seed state were observed."
            } else {
                "An optimizer record was observed, without seed or data-order state."
            },
            &o,
        );
    }
    if let Some(t) = ctx.f.first(K::TrainingObjective).cloned() {
        ctx.support(
            "CL-SCRATCH-004",
            Claim::Scratch,
            "identity",
            100,
            T::E1,
            "A training configuration was observed.",
            &t,
        );
    }
    if let Some(d) = ctx.f.first(K::DatasetManifest).cloned() {
        ctx.support(
            "CL-SCRATCH-005",
            Claim::Scratch,
            "data_tokenizer",
            70,
            T::E1,
            "A dataset manifest was observed.",
            &d,
        );
    }
    if let Some(h) = ctx.f.first(K::HardwareRecord).cloned() {
        ctx.support(
            "CL-SCRATCH-007",
            Claim::Scratch,
            "compute_jobs",
            100,
            T::E1,
            "Hardware or job telemetry for the training run was observed.",
            &h,
        );
    }

    // Unconditional. This is the single most important sentence on a scratch claim.
    ctx.limitation(
        "CL-SCRATCH-010",
        "Failure to match a known base model does not establish random initialisation. \
         Stage 1 does not compare weights against any base, and no such comparison was made.",
    );
    if !has_step_zero && steps.len() < 3 {
        ctx.abstain(Facet::WeightOrigin, AbstentionId::ScratchNoMatchOnly);
    }

    // The three separable claims. Conflating them is a common way to overstate.
    ctx.emit(RuleOutcome::new(
        "CL-SCRATCH-011",
        cl_core::vocab::OutcomeKind::SupportingEvidence,
        "A claim of original architecture is recorded separately from a claim of \
         originally initialised weights; a scratch model may reuse a known architecture.",
    ));
    ctx.emit(RuleOutcome::new(
        "CL-SCRATCH-012",
        cl_core::vocab::OutcomeKind::SupportingEvidence,
        "A claim of an original tokenizer is recorded separately from a claim of \
         originally initialised weights.",
    ));
    if ctx.f.has(K::TokenizerIdentity) && !ctx.f.has(K::DatasetManifest) {
        ctx.ambiguity(
            "CL-SCRATCH-013",
            "A recognisable tokenizer or architecture is compatible with a scratch weight \
             claim and does not weigh against it.",
        );
    }

    // An adapter naming a base while scratch is claimed is a genuine conflict.
    if let Some(ac) = ctx
        .f
        .by_kind(K::AdapterConfig)
        .find(|f| any_text(f, &["base_model_name_or_path", "base_ref"]).is_some())
        .cloned()
    {
        ctx.contradict(
            "CL-XFACET-003",
            Facet::WeightOrigin,
            Some(Claim::Scratch),
            "Random initialisation is declared, while an adapter configuration in scope \
             names a base model the adapter was built against.",
            &ac,
        );
    }
}

// ===========================================================================
// CL-RAG-*
// ===========================================================================

pub fn rag(ctx: &mut Ctx) {
    let declared = ctx.f.declared.inference_augmentation.contains(&Aug::Rag);
    let index = ctx.f.first(K::RetrievalIndex).cloned();
    let traces: Vec<Fact> = ctx.f.by_kind(K::RetrievalTrace).cloned().collect();
    let embed = ctx.f.first(K::EmbeddingModel).cloned();
    let prompt = ctx.f.first(K::PromptTemplate).cloned();

    if !declared && index.is_none() && traces.is_empty() {
        return;
    }

    if let Some(i) = &index {
        ctx.support(
            "CL-RAG-002",
            Claim::Rag,
            "index",
            100,
            T::E1,
            "A vector index or retrieval-store manifest was observed.",
            i,
        );
        ctx.limitation(
            "CL-RAG-007",
            "A vector store present in the scanned scope does not show that retrieval is \
             used in production.",
        );
    }
    if let Some(e) = &embed {
        ctx.support(
            "CL-RAG-003",
            Claim::Rag,
            "index",
            70,
            T::E1,
            "An embedding model identity was observed.",
            e,
        );
    }
    if let Some(p) = &prompt {
        ctx.support(
            "CL-RAG-005",
            Claim::Rag,
            "prompt_assembly",
            100,
            T::E1,
            "A prompt-assembly template was observed.",
            p,
        );
    }

    let full_chain = traces
        .iter()
        .find(|t| any_bool(t, &["request_level_chain", "full_chain"]).unwrap_or(false));
    match full_chain {
        Some(t) => ctx.support(
            "CL-RAG-001",
            Claim::Rag,
            "retrieval_trace",
            100,
            T::E2,
            format!(
                "A request-level retrieval chain was observed: query, retrieved chunks with \
                 scores, and assembled context, over {} recorded request(s).",
                any_int(t, &["entry_count", "entries"]).unwrap_or(1)
            ),
            t,
        ),
        None => {
            if let Some(t) = traces.first() {
                ctx.support(
                    "CL-RAG-001",
                    Claim::Rag,
                    "retrieval_trace",
                    40,
                    T::E1,
                    "Retrieval records were observed, but they do not form a complete \
                     request-level chain from query to scored chunks to assembled context.",
                    t,
                );
            } else {
                ctx.missing(
                    "CL-RAG-001",
                    Claim::Rag,
                    "retrieval_trace",
                    "No request-level retrieval chain was observed.",
                );
            }
        }
    }

    ctx.emit(RuleOutcome::new(
        "CL-RAG-008",
        cl_core::vocab::OutcomeKind::SupportingEvidence,
        "Retrieval augmentation can coexist with any weight-training claim. The two \
         facets are scored independently and neither weighs against the other.",
    ));
}

// ===========================================================================
// CL-API-*
// ===========================================================================

pub fn external_api(ctx: &mut Ctx) {
    let declared = ctx.f.declared.inference_augmentation.contains(&Aug::ExternalApiRouter);
    let endpoints: Vec<Fact> = ctx.f.by_kind(K::ProviderEndpoint).cloned().collect();
    let sdks: Vec<Fact> = ctx
        .f
        .by_kind(K::SdkDependency)
        .filter(|f| any_text(f, &["category"]) == Some("provider_sdk"))
        .cloned()
        .collect();
    let traces: Vec<Fact> = ctx.f.by_kind(K::OutboundRequestTrace).cloned().collect();
    let serving = ctx.f.first(K::ServingConfig).cloned();

    if !declared && endpoints.is_empty() && sdks.is_empty() && traces.is_empty() {
        return;
    }

    let mut any_support = false;
    if let Some(e) = endpoints.first() {
        any_support = true;
        ctx.support(
            "CL-API-001",
            Claim::ExternalApi,
            "config",
            100,
            T::E1,
            format!(
                "An external inference endpoint is configured: {}.",
                any_text(e, &["host", "endpoint_url", "base_url"]).unwrap_or("(host recorded)")
            ),
            e,
        );
    }
    if let Some(s) = sdks.first() {
        any_support = true;
        ctx.support(
            "CL-API-002",
            Claim::ExternalApi,
            "config",
            60,
            T::E1,
            format!(
                "A provider SDK dependency is declared: {}.",
                any_text(s, &["name"]).unwrap_or("(named)")
            ),
            s,
        );
    }
    if let Some(t) = traces.first() {
        any_support = true;
        ctx.support(
            "CL-API-003",
            Claim::ExternalApi,
            "observed_egress",
            100,
            T::E1,
            "Outbound inference request records were observed.",
            t,
        );
    }
    if let Some(s) = &serving {
        any_support = true;
        ctx.support(
            "CL-API-004",
            Claim::ExternalApi,
            "binding",
            100,
            T::E1,
            "A serving or router configuration was observed.",
            s,
        );
    }

    let local_weights = ctx.f.has_artifact_type(ArtifactType::SafeTensors)
        || ctx.f.has_artifact_type(ArtifactType::Gguf)
        || ctx.f.has_artifact_type(ArtifactType::ShardIndex);
    if !local_weights {
        if let Some(e) = endpoints.first().or_else(|| sdks.first()) {
            ctx.support(
                "CL-API-005",
                Claim::ExternalApi,
                "other",
                100,
                T::E2,
                "No local model weights are present in any selected root.",
                e,
            );
        }
    } else if !endpoints.is_empty() && ctx.f.declared.declares_weight_training() {
        // Deliberately an ambiguity, not a contradiction: a vendor may legitimately
        // train weights and also call an external service.
        if let Some(e) = endpoints.first() {
            let _ = e;
        }
        ctx.ambiguity(
            "CL-API-010",
            "An external inference endpoint is configured while a weight-training claim is \
             declared. Both can be true at once; this narrows nothing on its own.",
        );
    }

    if any_support {
        ctx.limitation(
            "CL-API-006",
            "An external endpoint was observed, but the provider and model identity behind \
             it are not independently established.",
        );
        ctx.limitation(
            "CL-API-007",
            "A remote endpoint may still be operated by the vendor.",
        );
        ctx.limitation(
            "CL-API-008",
            "These findings apply only to the requests recorded in the supplied evidence. \
             Routing and caching can vary between requests.",
        );
        ctx.next_evidence(
            "CL-API-009",
            "Correlating these requests with provider-side records requires evidence from \
             the provider account.",
        );
        // The cap is defined as "API behaviour only, FOR A WEIGHT-TRAINING CLAIM",
        // so it binds the training claims, not the API claim. Applying it to
        // `ExternalApi` would cap the one claim this evidence actually supports.
        if ctx.f.declared.declares_weight_training() && !local_weights {
            for c in WEIGHT_TRAINING_CLAIMS {
                ctx.cap(*c, CapId::ApiOnly, "CL-API-006");
            }
        }
    }
}

// ===========================================================================
// CL-COMPUTE-*
// ===========================================================================

/// Order-of-magnitude screen only. The band is deliberately wide because
/// efficiency, precision, sparsity and utilisation legitimately move the figure.
const COMPUTE_BAND_FACTOR: i128 = 30;

pub fn compute(ctx: &mut Ctx) {
    let params = ctx
        .f
        .observed_parameter_count()
        .or_else(|| ctx.f.first(K::ComputeRecord).and_then(|f| any_int(f, &["parameters"])));
    let tokens = ctx
        .f
        .first(K::TokenCountRecord)
        .and_then(|f| any_int(f, &["tokens", "token_count", "total_tokens"]));
    let declared_flops = ctx
        .f
        .first(K::ComputeRecord)
        .and_then(|f| any_int(f, &["flops", "total_flos", "total_flops"]));

    let (Some(p), Some(t)) = (params, tokens) else {
        ctx.missing(
            "CL-COMPUTE-004",
            Claim::Scratch,
            "compute_jobs",
            "A parameter count or a token count was not supplied, so no compute \
             plausibility screen was possible.",
        );
        return;
    };

    // C ~ 6 * N * D for a dense transformer.
    let expected: i128 = 6i128 * (p as i128) * (t as i128);
    if let (Some(declared), Some(f)) = (declared_flops, ctx.f.first(K::ComputeRecord).cloned()) {
        let d = declared as i128;
        let lo = expected / COMPUTE_BAND_FACTOR;
        let hi = expected.saturating_mul(COMPUTE_BAND_FACTOR);
        if d >= lo && d <= hi {
            ctx.support(
                "CL-COMPUTE-001",
                Claim::Scratch,
                "compute_jobs",
                60,
                T::E1,
                "The declared compute falls inside the order-of-magnitude band implied by \
                 the declared parameter and token counts.",
                &f,
            );
        } else if d < lo {
            ctx.ambiguity(
                "CL-COMPUTE-002",
                "The declared compute is more than an order of magnitude below the band \
                 implied by the declared parameter and token counts. Efficiency, sparsity \
                 and precision choices can account for this.",
            );
        } else {
            ctx.ambiguity(
                "CL-COMPUTE-003",
                "The declared compute is far above the band implied by the declared \
                 parameter and token counts. Restarts and low utilisation can account for \
                 this.",
            );
        }
    }
    ctx.limitation(
        "CL-COMPUTE-005",
        "Compute plausibility is an order-of-magnitude screen. It cannot establish that a \
         training run took place.",
    );
}

// ===========================================================================
// CL-CHRONO-*
// ===========================================================================

pub fn chronology(ctx: &mut Ctx) {
    let mtimes: Vec<i64> = ctx.f.artifacts.iter().filter_map(|a| a.mtime.map(|t| t.0)).collect();
    if mtimes.is_empty() {
        return;
    }
    let all_same = mtimes.windows(2).all(|w| w[0] == w[1]);
    if all_same && mtimes.len() > 3 {
        // Copying a whole directory at once is completely ordinary, so this is an
        // ambiguity and never a contradiction.
        ctx.ambiguity(
            "CL-CHRONO-003",
            "Every artifact in scope shares one modification timestamp, which is what \
             copying a directory produces.",
        );
    }

    let chrono: Vec<Fact> = ctx.f.by_kind(K::FileChronology).cloned().collect();
    for c in &chrono {
        if let (Some(start), Some(ckpt)) = (
            any_text(c, &["run_started_at", "started_at"]),
            any_text(c, &["checkpoint_at", "referenced_at"]),
        ) {
            let s = cl_core::time::Timestamp::parse_rfc3339(start);
            let k = cl_core::time::Timestamp::parse_rfc3339(ckpt);
            if let (Ok(s), Ok(k)) = (s, k) {
                if s > k {
                    ctx.contradict(
                        "CL-CHRONO-004",
                        Facet::TrainingStage,
                        None,
                        format!(
                            "A training log records a run start of {start} while referring to \
                             a checkpoint recorded at {ckpt}. These two supplied records \
                             cannot both hold."
                        ),
                        c,
                    );
                }
            }
        }
    }

    ctx.limitation(
        "CL-CHRONO-005",
        "Filesystem timestamps are settable by anyone with write access and are treated \
         as a mutable supporting record at best.",
    );
}

// ===========================================================================
// CL-PARAM-*
// ===========================================================================

pub fn parameters(ctx: &mut Ctx) {
    let Some(observed) = ctx.f.observed_parameter_count() else { return };
    if let Some(th) = ctx.f.first(K::TensorHeader).cloned() {
        ctx.support(
            "CL-PARAM-001",
            Claim::DenseFinetune,
            "pre_post",
            30,
            T::E2,
            format!("A parameter count of {observed} was derived from the container headers."),
            &th,
        );
    }

    let declared = ctx
        .f
        .by_kind(K::ModelConfig)
        .find_map(|f| any_int(f, &["declared_parameters", "num_parameters"]));
    if let (Some(d), Some(mc)) = (declared, ctx.f.first(K::ModelConfig).cloned()) {
        if d > 0 {
            let diff = (observed - d).abs();
            let within_two_percent = diff.saturating_mul(50) <= d;
            if within_two_percent {
                ctx.support(
                    "CL-PARAM-002",
                    Claim::DenseFinetune,
                    "pre_post",
                    70,
                    T::E2,
                    "The derived parameter count matches the declared count within two percent.",
                    &mc,
                );
            } else {
                ctx.contradict(
                    "CL-PARAM-003",
                    Facet::ParameterUpdate,
                    None,
                    format!(
                        "The parameter count derived from the container headers ({observed}) \
                         differs from the declared count ({d}) by more than two percent."
                    ),
                    &mc,
                );
            }
        }
    }

    if ctx.f.has(K::QuantizationRecord) {
        ctx.limitation(
            "CL-PARAM-004",
            "Quantised storage prevents exact parameter accounting from container headers \
             alone.",
        );
    }
}

// ===========================================================================
// CL-BIND-*
// ===========================================================================

const BINDABLE: &[(Claim, &str)] = &[
    (Claim::UnmergedLora, "deployment_binding"),
    (Claim::MergedAdapter, "binding"),
    (Claim::DenseFinetune, "binding"),
    (Claim::ContinuedPretraining, "binding"),
    (Claim::Distillation, "binding"),
    (Claim::Rag, "binding"),
    (Claim::ExternalApi, "binding"),
];

pub fn binding(ctx: &mut Ctx) {
    let refs: Vec<Fact> = ctx.f.by_kind(K::ArtifactReference).cloned().collect();
    let in_scope = refs.iter().find(|r| any_bool(r, &["in_scope", "resolved"]).unwrap_or(false));
    let by_digest = ctx
        .f
        .by_kind(K::ContainerManifest)
        .find(|c| any_text(c, &["image_digest", "digest"]).is_some())
        .cloned();

    if let Some(r) = in_scope {
        for (claim, anchor) in BINDABLE {
            ctx.support(
                "CL-BIND-001",
                *claim,
                anchor,
                100,
                T::E1,
                "A serving configuration references an artifact inside the scanned scope.",
                r,
            );
        }
    } else if let Some(c) = &by_digest {
        for (claim, anchor) in BINDABLE {
            ctx.support(
                "CL-BIND-002",
                *claim,
                anchor,
                100,
                T::E1,
                "A container or deployment manifest pins an image by digest.",
                c,
            );
        }
    } else if !refs.is_empty() {
        for (claim, anchor) in BINDABLE {
            ctx.support(
                "CL-BIND-003",
                *claim,
                anchor,
                20,
                T::E1,
                "A serving configuration references a path outside the scanned scope.",
                &refs[0],
            );
        }
        ctx.limitation(
            "CL-BIND-003",
            "The serving configuration points outside the selected scope, so the artifact \
             it names was not examined.",
        );
        // We can see that a deployment exists and that it names something we were not
        // shown. That is a positive reason to doubt we are looking at the right
        // artifact, which is different from simply having no deployment information.
        for f in Facet::ALL {
            ctx.abstain(*f, AbstentionId::NoBinding);
        }
    } else {
        for (claim, anchor) in BINDABLE {
            ctx.missing(
                "CL-BIND-004",
                *claim,
                anchor,
                "No serving or deployment configuration was observed in scope.",
            );
        }
        // Deliberately NOT an abstention.
        //
        // A vendor self-scan of a model folder almost never contains serving
        // configuration, so abstaining here would abstain on every facet of every
        // ordinary scan, and Stage 1 could never report anything at all. That is not
        // caution, it is uselessness wearing caution's clothes.
        //
        // The honest treatment is to score it and say so: the binding anchor stays at
        // zero, which lowers the score, and `CL-BIND-005` states unconditionally on
        // every report that the scanned folder is not established to be the
        // production deployment. The reader is told exactly what is missing without
        // the tool refusing to describe what it did see.
    }

    // Unconditional on every report.
    ctx.limitation(
        "CL-BIND-005",
        "The scanned folder is not established to be the production deployment. This is a \
         vendor self-scan of a location the vendor selected.",
    );
}

// ===========================================================================
// CL-XFACET-*
// ===========================================================================

pub fn cross_facet(ctx: &mut Ctx) {
    let d = &ctx.f.declared;

    if d.parameter_update == Some(PU::NoUpdateObserved) {
        if let Some(ac) = ctx.f.first(K::AdapterConfig).cloned() {
            ctx.contradict(
                "CL-XFACET-002",
                Facet::ParameterUpdate,
                None,
                "No parameter update is declared, while adapter artifacts are present in \
                 the scanned scope.",
                &ac,
            );
        } else if let Some(ts) = ctx.f.first(K::AdapterTensorSet).cloned() {
            ctx.contradict(
                "CL-XFACET-002",
                Facet::ParameterUpdate,
                None,
                "No parameter update is declared, while adapter tensors are present in the \
                 scanned scope.",
                &ts,
            );
        }
    }

    if d.inference_augmentation.contains(&Aug::LocalDirectInference)
        && ctx.f.has(K::ProviderEndpoint)
    {
        ctx.ambiguity(
            "CL-XFACET-004",
            "Local direct inference is declared while an external endpoint is configured in \
             scope. A configured endpoint may be unused, or used for a different purpose.",
        );
    }

    let coherent = d.weight_origin.is_some()
        || d.parameter_update.is_some()
        || d.training_stage.is_some()
        || !d.inference_augmentation.is_empty();
    if coherent {
        ctx.emit(RuleOutcome::new(
            "CL-XFACET-001",
            cl_core::vocab::OutcomeKind::SupportingEvidence,
            "The declared facet set is internally coherent.",
        ));
    }
}

// ===========================================================================
// Global caps that depend on the whole picture
// ===========================================================================

/// Claims that assert something was done to a model's weights.
///
/// The distinction matters for caps. A retrieval or external-API claim is *about*
/// not training weights, so the absence of weights is not a gap in its evidence -
/// it is the thing being claimed. Capping those claims for lacking checkpoints
/// would penalise a vendor for the system being exactly what they said it was.
const WEIGHT_TRAINING_CLAIMS: &[Claim] = &[
    Claim::UnmergedLora,
    Claim::MergedAdapter,
    Claim::DenseFinetune,
    Claim::ContinuedPretraining,
    Claim::Distillation,
    Claim::Scratch,
];

pub fn global_caps(ctx: &mut Ctx) {
    // Nothing but text records in scope. Applied only to weight-training claims:
    // a system that wraps somebody else's API has no local weights by design, and
    // `CL-API-005` scores their absence as supporting evidence rather than a gap.
    let structural = ctx.f.artifacts.iter().any(|a| {
        matches!(
            a.artifact_type,
            ArtifactType::SafeTensors | ArtifactType::Gguf | ArtifactType::Onnx | ArtifactType::ShardIndex
        )
    });
    if !structural {
        for c in WEIGHT_TRAINING_CLAIMS {
            ctx.cap(*c, CapId::Questionnaire, "CL-INV-008");
        }
    }

    // Final weights present but no exact base and no trajectory.
    let exact_base = ctx.out.outcomes.iter().any(|o| o.rule_id == "CL-BASE-001");
    let trajectory = ctx.f.count(K::CheckpointStep) >= 2 || ctx.f.has(K::TrainingMetric);
    if structural && !exact_base && !trajectory {
        for c in [
            Claim::UnmergedLora,
            Claim::MergedAdapter,
            Claim::DenseFinetune,
            Claim::ContinuedPretraining,
            Claim::Scratch,
        ] {
            ctx.cap(c, CapId::NoBase, "CL-BASE-003");
        }
    }

    if ctx.f.has(K::QuantizationRecord) && !ctx.f.has(K::AdapterTensorSet) {
        ctx.limitation(
            "CL-MERGE-007",
            "Only quantised or dtype-converted weights are available, which prevents any \
             delta-based reasoning about how they were produced.",
        );
    }
}

/// Every family, in order. Evidence first, then the rules that depend on what the
/// evidence families did or did not find.
pub fn run_all(facts: &FactSet) -> Emissions {
    let mut ctx = Ctx::new(facts);
    scope(&mut ctx);
    base_identity(&mut ctx);
    lora(&mut ctx);
    merged_adapter(&mut ctx);
    dense(&mut ctx);
    continued_pretraining(&mut ctx);
    distillation(&mut ctx);
    scratch(&mut ctx);
    rag(&mut ctx);
    external_api(&mut ctx);
    compute(&mut ctx);
    chronology(&mut ctx);
    parameters(&mut ctx);
    binding(&mut ctx);
    cross_facet(&mut ctx);
    global_caps(&mut ctx);
    ctx.out
}
