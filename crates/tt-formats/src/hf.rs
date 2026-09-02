//! Hugging Face ecosystem configuration files.
//!
//! These are the files a fine-tuning run leaves behind: `config.json`,
//! `adapter_config.json`, a shard index, a tokenizer, `trainer_state.json`. They are
//! also the files it is easiest to write by hand, which is why everything this
//! module emits is tier **E1** at the rules layer. A config declaring
//! `peft_type: LORA` is a text record; the `lora_A`/`lora_B` tensor pairs in a
//! SafeTensors header are the structural evidence.
//!
//! ## Pinned revisions
//!
//! The single most consequential field here is whether a base model reference names
//! an immutable revision. Rule `TT-BASE-001` (an exact base) and `TT-BASE-002` (a
//! base named without one) differ by a factor of three in achievement, so
//! `revision_pinned` has to mean something precise.
//!
//! It means a commit hash. `"main"` is not a pin — it is a branch that moves, and a
//! model card that says `revision: main` records no more than the model's name does.
//! Treating a branch as a pin would let a vendor claim an exact base by typing a word.

use crate::{ParseOutput, PendingFact};
use std::collections::BTreeMap;
use tt_core::error::TtResult;
use tt_core::json::{self, JsonValue};
use tt_core::limits::Limits;
use tt_facts::{ArtifactType, FactKind, FieldValue};

pub const PARSER_VERSION: i64 = 1;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// A commit-like revision: 7 to 40 lowercase hex characters.
///
/// Branch and tag names are deliberately excluded. `main` moves, so it pins nothing.
fn looks_like_commit(s: &str) -> bool {
    let n = s.len();
    (7..=40).contains(&n) && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Pull a revision out of a reference of the form `org/model@<commit>`.
fn revision_in_reference(reference: &str) -> Option<&str> {
    let (_, rev) = reference.rsplit_once('@')?;
    looks_like_commit(rev).then_some(rev)
}

fn text_of(v: &JsonValue) -> Option<String> {
    match v {
        JsonValue::Str(s) => Some(s.clone()),
        JsonValue::Int(i) => Some(i.to_string()),
        JsonValue::Num(s) => Some(s.clone()),
        JsonValue::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Copy a scalar field across under its own name, preserving numeric text exactly.
fn copy_scalar(src: &JsonValue, key: &str, f: PendingFact) -> PendingFact {
    match src.get(key) {
        Some(JsonValue::Int(i)) => f.with(key, *i),
        Some(JsonValue::Num(s)) => f.with(key, FieldValue::Num(s.clone())),
        Some(JsonValue::Str(s)) => f.with(key, s.as_str()),
        Some(JsonValue::Bool(b)) => f.with(key, *b),
        _ => f,
    }
}

/// A sorted, de-duplicated list of strings from an array field.
fn string_list(src: &JsonValue, key: &str) -> Option<Vec<String>> {
    let arr = src.get(key)?.as_arr()?;
    let mut v: Vec<String> = arr.iter().filter_map(text_of).collect();
    v.sort();
    v.dedup();
    Some(v)
}

/// Build the `BaseModelReference` fact, recording whether the reference is pinned.
fn base_reference(reference: &str, explicit_revision: Option<&str>) -> PendingFact {
    let embedded = revision_in_reference(reference);
    let revision = explicit_revision
        .filter(|r| !r.is_empty())
        .or(embedded);
    let pinned = revision.map(looks_like_commit).unwrap_or(false);
    PendingFact::new(FactKind::BaseModelReference)
        .with("base_ref", reference)
        .with("revision_pinned", pinned)
        .with_opt("revision", revision.map(|r| r.to_string()))
}

// ---------------------------------------------------------------------------
// config.json
// ---------------------------------------------------------------------------

pub const CONFIG_PARSER: &str = "transformers_config";

pub fn parse_transformers_config(bytes: &[u8], limits: &Limits) -> TtResult<ParseOutput> {
    let v = json::parse(bytes, limits)?;
    let mut out = ParseOutput::new(ArtifactType::TransformersConfig, CONFIG_PARSER, PARSER_VERSION);

    let mut f = PendingFact::new(FactKind::ModelConfig);
    if let Some(a) = string_list(&v, "architectures") {
        if let Some(first) = a.first() {
            f = f.with("architecture", first.as_str());
        }
        f = f.with("architectures", a);
    }
    for key in [
        "model_type",
        "hidden_size",
        "num_hidden_layers",
        "num_attention_heads",
        "num_key_value_heads",
        "intermediate_size",
        "vocab_size",
        "max_position_embeddings",
        "torch_dtype",
        "transformers_version",
        "tie_word_embeddings",
    ] {
        f = copy_scalar(&v, key, f);
    }
    out.push(f);

    if let Some(name) = v.get("_name_or_path").and_then(|x| x.as_str()) {
        if !name.is_empty() {
            out.push(base_reference(name, None));
        }
    }

    if let Some(q) = v.get("quantization_config") {
        let mut qf = PendingFact::new(FactKind::QuantizationRecord).with("source", "config.json");
        for key in ["quant_method", "bits", "group_size", "load_in_4bit", "load_in_8bit"] {
            qf = copy_scalar(q, key, qf);
        }
        qf = qf.with(
            "reason",
            "the model configuration declares a quantisation method".to_string(),
        );
        out.push(qf);
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// adapter_config.json
// ---------------------------------------------------------------------------

pub const ADAPTER_PARSER: &str = "peft_adapter_config";

pub fn parse_peft_adapter_config(bytes: &[u8], limits: &Limits) -> TtResult<ParseOutput> {
    let v = json::parse(bytes, limits)?;
    let mut out =
        ParseOutput::new(ArtifactType::PeftAdapterConfig, ADAPTER_PARSER, PARSER_VERSION);

    let mut f = PendingFact::new(FactKind::AdapterConfig);
    for key in [
        "peft_type",
        "task_type",
        "lora_alpha",
        "lora_dropout",
        "bias",
        "fan_in_fan_out",
        "use_dora",
        "use_rslora",
        "inference_mode",
    ] {
        f = copy_scalar(&v, key, f);
    }

    // `r` is the rank. A string here is a real thing that happens in hand-edited
    // configs, and it must not be silently coerced: the rank is compared against
    // observed tensor shapes, and a coerced value could manufacture a contradiction.
    match v.get("r") {
        Some(JsonValue::Int(i)) => f = f.with("r", *i),
        Some(other) => {
            out.note(
                "TT-FMT-009",
                format!(
                    "`r` is a {} rather than an integer, so the declared rank was not \
                     compared against the observed tensor shapes",
                    other.type_name()
                ),
            );
        }
        None => {}
    }

    if let Some(t) = string_list(&v, "target_modules") {
        f = f.with("target_modules", t);
    }
    if let Some(m) = string_list(&v, "modules_to_save") {
        if !m.is_empty() {
            f = f.with("modules_to_save", m);
        }
    }
    if let Some(base) = v.get("base_model_name_or_path").and_then(|x| x.as_str()) {
        f = f.with("base_model_name_or_path", base);
    }
    out.push(f);

    if let Some(base) = v.get("base_model_name_or_path").and_then(|x| x.as_str()) {
        if !base.is_empty() {
            let rev = v.get("revision").and_then(|x| x.as_str());
            out.push(base_reference(base, rev));
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// *.index.json
// ---------------------------------------------------------------------------

pub const SHARD_INDEX_PARSER: &str = "shard_index";

pub fn parse_shard_index(bytes: &[u8], limits: &Limits) -> TtResult<ParseOutput> {
    let v = json::parse(bytes, limits)?;
    let mut out = ParseOutput::new(ArtifactType::ShardIndex, SHARD_INDEX_PARSER, PARSER_VERSION);

    let mut shards: Vec<String> = Vec::new();
    let mut tensor_count = 0i64;
    if let Some(map) = v.get("weight_map").and_then(|m| m.as_obj()) {
        tensor_count = map.len() as i64;
        for (_, file) in map {
            if let Some(s) = file.as_str() {
                shards.push(s.to_string());
            }
        }
    }
    shards.sort();
    shards.dedup();

    let mut f = PendingFact::new(FactKind::ShardIndex)
        .with("tensor_count", tensor_count)
        .with("shard_file_count", shards.len() as i64)
        .with("shard_files", shards);
    if let Some(total) = v.get("metadata").and_then(|m| m.get("total_size")) {
        f = match total {
            JsonValue::Int(i) => f.with("declared_total_size", *i),
            JsonValue::Num(s) => f.with("declared_total_size", FieldValue::Num(s.clone())),
            _ => f,
        };
    }
    out.push(f);
    Ok(out)
}

// ---------------------------------------------------------------------------
// tokenizer_config.json / tokenizer.json
// ---------------------------------------------------------------------------

pub const TOKENIZER_PARSER: &str = "tokenizer_identity";

pub fn parse_tokenizer_identity(bytes: &[u8], limits: &Limits) -> TtResult<ParseOutput> {
    let mut out =
        ParseOutput::new(ArtifactType::TokenizerConfig, TOKENIZER_PARSER, PARSER_VERSION);
    if bytes.len() as u64 > limits.config_bytes {
        // A full `tokenizer.json` routinely exceeds the config bound. That is a
        // coverage limitation, not a failure: the rest of the scan continues and the
        // report says the tokenizer was not read.
        out.note(
            "TT-FMT-010",
            format!(
                "the tokenizer file is {} bytes, beyond the {} byte configuration bound, \
                 so its identity was not read",
                bytes.len(),
                limits.config_bytes
            ),
        );
        return Ok(out);
    }
    let v = json::parse(bytes, limits)?;

    let mut f = PendingFact::new(FactKind::TokenizerIdentity);
    for key in ["tokenizer_class", "model_max_length", "clean_up_tokenization_spaces"] {
        f = copy_scalar(&v, key, f);
    }
    if let Some(added) = v.get("added_tokens_decoder").and_then(|a| a.as_obj()) {
        f = f.with("added_token_count", added.len() as i64);
    } else if let Some(added) = v.get("added_tokens").and_then(|a| a.as_arr()) {
        f = f.with("added_token_count", added.len() as i64);
    }
    // `tokenizer.json` carries the vocabulary itself.
    if let Some(vocab) = v.get("model").and_then(|m| m.get("vocab")) {
        let n = match vocab {
            JsonValue::Obj(o) => Some(o.len() as i64),
            JsonValue::Arr(a) => Some(a.len() as i64),
            _ => None,
        };
        if let Some(n) = n {
            f = f.with("vocab_size", n);
        }
    }
    out.push(f);
    Ok(out)
}

// ---------------------------------------------------------------------------
// trainer_state.json
// ---------------------------------------------------------------------------

pub const TRAINER_STATE_PARSER: &str = "trainer_state";

/// Number of log entries examined. A long run must not be able to make the report
/// large; the summary is what the rules read.
const MAX_LOG_ENTRIES: usize = 100_000;

pub fn parse_trainer_state(bytes: &[u8], limits: &Limits) -> TtResult<ParseOutput> {
    let v = json::parse(bytes, limits)?;
    let mut out = ParseOutput::new(ArtifactType::TrainerState, TRAINER_STATE_PARSER, PARSER_VERSION);

    let entries: &[JsonValue] =
        v.get("log_history").and_then(|h| h.as_arr()).unwrap_or(&[]);

    let mut count = 0i64;
    let mut first_step: Option<i64> = None;
    let mut last_step: Option<i64> = None;
    let mut prev_step: Option<i64> = None;
    // Starts true and is only ever cleared. A series with nothing out of order is in
    // order, and rule TT-DENSE-007 reads `false` as a contradiction, so the initial
    // value must be the one that accuses nobody.
    let mut monotone = true;
    let mut saw_two = false;
    let mut first_loss: Option<String> = None;
    let mut last_loss: Option<String> = None;

    for e in entries.iter().take(MAX_LOG_ENTRIES) {
        count += 1;
        if let Some(step) = e.get("step").and_then(|s| s.as_int()) {
            if first_step.is_none() {
                first_step = Some(step);
            } else {
                saw_two = true;
            }
            if let Some(p) = prev_step {
                if step < p {
                    monotone = false;
                }
            }
            prev_step = Some(step);
            last_step = Some(step);
        }
        if let Some(l) = e.get("loss").and_then(|l| l.as_number_text()) {
            if first_loss.is_none() {
                first_loss = Some(l.clone());
            }
            last_loss = Some(l);
        }
    }
    if entries.len() > MAX_LOG_ENTRIES {
        out.note(
            "TT-FMT-010",
            format!(
                "the log history holds {} entries; the first {MAX_LOG_ENTRIES} were \
                 summarised and the remainder were not read",
                entries.len()
            ),
        );
    }

    let mut m = PendingFact::new(FactKind::TrainingMetric)
        .with("entry_count", count)
        .with_opt("first_step", first_step)
        .with_opt("last_step", last_step);
    if saw_two {
        m = m.with("monotone_step_order", monotone);
    }
    if let Some(l) = &first_loss {
        m = m.with("first_loss", FieldValue::Num(l.clone()));
    }
    if let Some(l) = &last_loss {
        m = m.with("last_loss", FieldValue::Num(l.clone()));
    }
    for key in ["global_step", "max_steps", "total_flos", "best_metric", "epoch"] {
        m = copy_scalar(&v, key, m);
    }
    out.push(m);

    // Checkpoint facts for the extremes only. Emitting one per entry would drown the
    // report in a long run without adding anything a rule reads.
    if let Some(s) = first_step {
        out.push(PendingFact::new(FactKind::CheckpointStep).with("step", s).with("position", "first"));
    }
    if let Some(s) = last_step {
        if Some(s) != first_step {
            out.push(
                PendingFact::new(FactKind::CheckpointStep).with("step", s).with("position", "last"),
            );
        }
    }
    // `global_step` is the state's own idea of where the run reached.
    if let Some(g) = v.get("global_step").and_then(|g| g.as_int()) {
        if Some(g) != last_step {
            out.push(
                PendingFact::new(FactKind::CheckpointStep)
                    .with("step", g)
                    .with("position", "global_step"),
            );
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// training_args.json
// ---------------------------------------------------------------------------

pub const TRAINING_ARGS_PARSER: &str = "training_args";

pub fn parse_training_args(bytes: &[u8], limits: &Limits) -> TtResult<ParseOutput> {
    let v = json::parse(bytes, limits)?;
    let mut out = ParseOutput::new(ArtifactType::TrainingArgs, TRAINING_ARGS_PARSER, PARSER_VERSION);

    let mut f = PendingFact::new(FactKind::OptimizerRecord);
    for key in [
        "learning_rate",
        "num_train_epochs",
        "max_steps",
        "per_device_train_batch_size",
        "gradient_accumulation_steps",
        "optim",
        "lr_scheduler_type",
        "warmup_steps",
        "weight_decay",
        "bf16",
        "fp16",
        "gradient_checkpointing",
    ] {
        f = copy_scalar(&v, key, f);
    }
    out.push(f);

    if let Some(seed) = v.get("seed").and_then(|s| s.as_int()) {
        out.push(PendingFact::new(FactKind::SeedRecord).with("seed", seed));
    }

    // An objective is only recorded when the file names one. Inferring "this looks
    // like SFT" from a batch size would be the parser forming a view, which is the
    // rules layer's job and not this one's.
    for key in ["objective", "task_type", "loss_type", "training_objective"] {
        if let Some(o) = v.get(key).and_then(|x| x.as_str()) {
            if !o.is_empty() {
                out.push(
                    PendingFact::new(FactKind::TrainingObjective)
                        .with("objective", o)
                        .with("declared_in", key),
                );
                break;
            }
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// README.md front matter
// ---------------------------------------------------------------------------

pub const MODEL_CARD_PARSER: &str = "model_card";

pub fn parse_model_card(bytes: &[u8], limits: &Limits) -> TtResult<ParseOutput> {
    let mut out = ParseOutput::new(ArtifactType::ModelCard, MODEL_CARD_PARSER, PARSER_VERSION);
    let Some(front) = crate::yamlish::front_matter(bytes) else {
        // Prose with no front matter is not an error. Most READMEs are just prose.
        return Ok(out);
    };
    let v = match crate::yamlish::parse(front, limits) {
        Ok(v) => v,
        Err(e) => {
            out.note("TT-FMT-010", format!("the model card front matter was not read: {e}"));
            return Ok(out);
        }
    };

    // `base_model` may be a scalar or a list; a merge lists several.
    let bases: Vec<String> = match v.get("base_model") {
        Some(JsonValue::Str(s)) => vec![s.clone()],
        Some(JsonValue::Arr(a)) => a.iter().filter_map(text_of).collect(),
        _ => Vec::new(),
    };
    for b in bases.iter().filter(|b| !b.is_empty()) {
        out.push(base_reference(b, None));
    }

    let mut card = PendingFact::new(FactKind::BaseModelReference).with("source", "model_card");
    let mut have_card = false;
    for key in ["library_name", "license", "pipeline_tag"] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            card = card.with(key, s);
            have_card = true;
        }
    }
    if let Some(tags) = string_list(&v, "tags") {
        if !tags.is_empty() {
            card = card.with("tags", tags);
            have_card = true;
        }
    }
    if have_card && bases.is_empty() {
        out.push(card);
    }

    if let Some(ds) = string_list(&v, "datasets") {
        if !ds.is_empty() {
            out.push(
                PendingFact::new(FactKind::DatasetManifest)
                    .with("datasets", ds)
                    .with("source", "model_card"),
            );
        }
    }

    Ok(out)
}

/// Dispatch a classified artifact to the parser for it.
pub fn parse_for(t: ArtifactType, bytes: &[u8], limits: &Limits) -> Option<TtResult<ParseOutput>> {
    Some(match t {
        ArtifactType::TransformersConfig | ArtifactType::GenerationConfig => {
            parse_transformers_config(bytes, limits)
        }
        ArtifactType::PeftAdapterConfig => parse_peft_adapter_config(bytes, limits),
        ArtifactType::ShardIndex => parse_shard_index(bytes, limits),
        ArtifactType::TokenizerConfig => parse_tokenizer_identity(bytes, limits),
        ArtifactType::TrainerState => parse_trainer_state(bytes, limits),
        ArtifactType::TrainingArgs => parse_training_args(bytes, limits),
        ArtifactType::ModelCard => parse_model_card(bytes, limits),
        _ => return None,
    })
}

/// Names carrying a base reference, for callers that want the whole picture.
pub fn base_references(out: &ParseOutput) -> BTreeMap<String, bool> {
    let mut m = BTreeMap::new();
    for f in out.facts_of(FactKind::BaseModelReference) {
        if let Some(FieldValue::Text(r)) = f.get("base_ref") {
            let pinned = matches!(f.get("revision_pinned"), Some(FieldValue::Bool(true)));
            m.insert(r.clone(), pinned);
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim() -> Limits {
        Limits::default()
    }

    fn field<'a>(out: &'a ParseOutput, k: FactKind, key: &str) -> Option<&'a FieldValue> {
        out.facts_of(k).find_map(|f| f.get(key))
    }

    // -- pinned revisions --------------------------------------------------

    #[test]
    fn a_commit_hash_pins_a_base_but_a_branch_name_does_not() {
        assert!(looks_like_commit("a1b2c3d"));
        assert!(looks_like_commit(&"f".repeat(40)));
        assert!(!looks_like_commit("main"), "a branch moves, so it pins nothing");
        assert!(!looks_like_commit("master"));
        assert!(!looks_like_commit("v1.0"));
        assert!(!looks_like_commit("abc"), "too short to be a commit");
        assert!(!looks_like_commit(&"a".repeat(41)));
        assert!(!looks_like_commit("A1B2C3D"), "uppercase is not the canonical form");
    }

    #[test]
    fn revision_main_is_not_reported_as_pinned() {
        let src = br#"{"peft_type":"LORA","r":16,"base_model_name_or_path":"Qwen/Qwen2.5-7B","revision":"main"}"#;
        let out = parse_peft_adapter_config(src, &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::BaseModelReference, "revision_pinned"),
            Some(&FieldValue::Bool(false)),
            "naming a branch must not reach TT-BASE-001"
        );
    }

    #[test]
    fn an_explicit_commit_is_reported_as_pinned() {
        let src = br#"{"peft_type":"LORA","r":16,"base_model_name_or_path":"Qwen/Qwen2.5-7B","revision":"a1b2c3d4e5f6a7b8"}"#;
        let out = parse_peft_adapter_config(src, &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::BaseModelReference, "revision_pinned"),
            Some(&FieldValue::Bool(true))
        );
    }

    #[test]
    fn a_commit_embedded_in_the_reference_also_pins() {
        let src = br#"{"_name_or_path":"Qwen/Qwen2.5-7B@a1b2c3d4e5f6"}"#;
        let out = parse_transformers_config(src, &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::BaseModelReference, "revision_pinned"),
            Some(&FieldValue::Bool(true))
        );
    }

    // -- adapter config ----------------------------------------------------

    #[test]
    fn a_realistic_lora_adapter_config_parses() {
        let src = br#"{
          "peft_type": "LORA", "task_type": "CAUSAL_LM", "r": 16, "lora_alpha": 32,
          "lora_dropout": 0.05, "bias": "none", "use_dora": false, "use_rslora": false,
          "target_modules": ["v_proj", "q_proj", "k_proj", "o_proj"],
          "modules_to_save": ["lm_head"],
          "base_model_name_or_path": "Qwen/Qwen2.5-7B", "revision": null
        }"#;
        let out = parse_peft_adapter_config(src, &lim()).unwrap();
        assert_eq!(field(&out, FactKind::AdapterConfig, "peft_type"), Some(&FieldValue::Text("LORA".into())));
        assert_eq!(field(&out, FactKind::AdapterConfig, "r"), Some(&FieldValue::Int(16)));
        // Target modules are sorted, so two configs listing the same set agree.
        assert_eq!(
            field(&out, FactKind::AdapterConfig, "target_modules"),
            Some(&FieldValue::List(vec![
                "k_proj".into(),
                "o_proj".into(),
                "q_proj".into(),
                "v_proj".into()
            ]))
        );
        assert_eq!(
            field(&out, FactKind::AdapterConfig, "modules_to_save"),
            Some(&FieldValue::List(vec!["lm_head".into()]))
        );
        // A fractional dropout keeps its exact text; no float enters the report.
        assert_eq!(
            field(&out, FactKind::AdapterConfig, "lora_dropout"),
            Some(&FieldValue::Num("0.05".into()))
        );
    }

    #[test]
    fn a_rank_given_as_a_string_is_refused_not_coerced() {
        // Coercing would let a hand-edited config manufacture agreement or a
        // contradiction against the observed tensor shapes.
        let src = br#"{"peft_type":"LORA","r":"16"}"#;
        let out = parse_peft_adapter_config(src, &lim()).unwrap();
        assert!(field(&out, FactKind::AdapterConfig, "r").is_none());
        assert!(out.has_note("TT-FMT-009"));
    }

    // -- model config ------------------------------------------------------

    #[test]
    fn a_qwen_shaped_config_parses() {
        let src = br#"{
          "architectures": ["Qwen2ForCausalLM"], "model_type": "qwen2",
          "hidden_size": 3584, "num_hidden_layers": 28, "num_attention_heads": 28,
          "num_key_value_heads": 4, "vocab_size": 152064, "torch_dtype": "bfloat16",
          "transformers_version": "4.44.0"
        }"#;
        let out = parse_transformers_config(src, &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::ModelConfig, "architecture"),
            Some(&FieldValue::Text("Qwen2ForCausalLM".into()))
        );
        assert_eq!(field(&out, FactKind::ModelConfig, "hidden_size"), Some(&FieldValue::Int(3584)));
        assert!(out.facts_of(FactKind::BaseModelReference).next().is_none());
    }

    #[test]
    fn a_quantization_config_produces_a_record() {
        let src = br#"{"model_type":"llama","quantization_config":{"quant_method":"gptq","bits":4}}"#;
        let out = parse_transformers_config(src, &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::QuantizationRecord, "quant_method"),
            Some(&FieldValue::Text("gptq".into()))
        );
    }

    // -- shard index -------------------------------------------------------

    #[test]
    fn a_shard_index_counts_tensors_and_distinct_files() {
        let src = br#"{
          "metadata": {"total_size": 15231234567},
          "weight_map": {
            "model.layers.0.w": "model-00001-of-00002.safetensors",
            "model.layers.1.w": "model-00001-of-00002.safetensors",
            "model.layers.2.w": "model-00002-of-00002.safetensors"
          }
        }"#;
        let out = parse_shard_index(src, &lim()).unwrap();
        assert_eq!(field(&out, FactKind::ShardIndex, "tensor_count"), Some(&FieldValue::Int(3)));
        assert_eq!(field(&out, FactKind::ShardIndex, "shard_file_count"), Some(&FieldValue::Int(2)));
        assert_eq!(
            field(&out, FactKind::ShardIndex, "declared_total_size"),
            Some(&FieldValue::Int(15231234567))
        );
    }

    // -- trainer state -----------------------------------------------------

    fn trainer_state_with(steps: &[i64]) -> Vec<u8> {
        let entries: Vec<String> = steps
            .iter()
            .enumerate()
            .map(|(i, s)| format!("{{\"step\": {s}, \"loss\": {}.5, \"epoch\": 0.1}}", 10 - i as i64))
            .collect();
        format!(
            "{{\"global_step\": {}, \"max_steps\": 500, \"log_history\": [{}]}}",
            steps.last().copied().unwrap_or(0),
            entries.join(",")
        )
        .into_bytes()
    }

    #[test]
    fn an_ordered_log_history_reports_monotone_order() {
        let out = parse_trainer_state(&trainer_state_with(&[100, 200, 300]), &lim()).unwrap();
        assert_eq!(field(&out, FactKind::TrainingMetric, "entry_count"), Some(&FieldValue::Int(3)));
        assert_eq!(field(&out, FactKind::TrainingMetric, "first_step"), Some(&FieldValue::Int(100)));
        assert_eq!(field(&out, FactKind::TrainingMetric, "last_step"), Some(&FieldValue::Int(300)));
        assert_eq!(
            field(&out, FactKind::TrainingMetric, "monotone_step_order"),
            Some(&FieldValue::Bool(true)),
            "an ordered history must not read as out of order; TT-DENSE-007 turns \
             false into a contradiction"
        );
    }

    #[test]
    fn an_out_of_order_log_history_is_reported_as_such() {
        let out = parse_trainer_state(&trainer_state_with(&[100, 300, 200]), &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::TrainingMetric, "monotone_step_order"),
            Some(&FieldValue::Bool(false))
        );
    }

    #[test]
    fn a_single_entry_asserts_no_ordering_at_all() {
        // One step is not a series. Emitting `false` would be a contradiction drawn
        // from a single data point.
        let out = parse_trainer_state(&trainer_state_with(&[100]), &lim()).unwrap();
        assert!(field(&out, FactKind::TrainingMetric, "monotone_step_order").is_none());
    }

    #[test]
    fn losses_keep_their_exact_text() {
        let out = parse_trainer_state(&trainer_state_with(&[10, 20]), &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::TrainingMetric, "first_loss"),
            Some(&FieldValue::Num("10.5".into()))
        );
        assert_eq!(
            field(&out, FactKind::TrainingMetric, "last_loss"),
            Some(&FieldValue::Num("9.5".into()))
        );
    }

    #[test]
    fn a_forty_entry_history_produces_one_metric_fact_not_forty() {
        let steps: Vec<i64> = (1..=40).map(|i| i * 10).collect();
        let out = parse_trainer_state(&trainer_state_with(&steps), &lim()).unwrap();
        assert_eq!(out.facts_of(FactKind::TrainingMetric).count(), 1);
        assert!(out.facts_of(FactKind::CheckpointStep).count() <= 3);
    }

    #[test]
    fn an_empty_trainer_state_is_not_an_error() {
        let out = parse_trainer_state(b"{}", &lim()).unwrap();
        assert_eq!(field(&out, FactKind::TrainingMetric, "entry_count"), Some(&FieldValue::Int(0)));
    }

    // -- training args -----------------------------------------------------

    #[test]
    fn training_args_yield_an_optimizer_record_and_a_seed() {
        let src = br#"{"learning_rate":5e-5,"num_train_epochs":3,"optim":"adamw_torch","seed":42,"bf16":true}"#;
        let out = parse_training_args(src, &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::OptimizerRecord, "learning_rate"),
            Some(&FieldValue::Num("5e-5".into()))
        );
        assert_eq!(field(&out, FactKind::SeedRecord, "seed"), Some(&FieldValue::Int(42)));
        assert!(out.facts_of(FactKind::TrainingObjective).next().is_none());
    }

    #[test]
    fn an_objective_is_recorded_only_when_the_file_names_one() {
        let src = br#"{"task_type":"CAUSAL_LM","learning_rate":1e-4}"#;
        let out = parse_training_args(src, &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::TrainingObjective, "objective"),
            Some(&FieldValue::Text("CAUSAL_LM".into()))
        );
    }

    // -- model card --------------------------------------------------------

    #[test]
    fn a_model_card_front_matter_yields_a_base_reference() {
        let src = b"---\nbase_model: Qwen/Qwen2.5-7B\nlibrary_name: peft\ntags:\n  - lora\n---\n\n# My model\n";
        let out = parse_model_card(src, &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::BaseModelReference, "base_ref"),
            Some(&FieldValue::Text("Qwen/Qwen2.5-7B".into()))
        );
        assert_eq!(
            field(&out, FactKind::BaseModelReference, "revision_pinned"),
            Some(&FieldValue::Bool(false))
        );
    }

    #[test]
    fn a_readme_without_front_matter_is_not_an_error() {
        let out = parse_model_card(b"# Just prose\n\nNo front matter here.\n", &lim()).unwrap();
        assert!(out.facts.is_empty());
        assert!(out.notes.is_empty());
    }

    #[test]
    fn a_merge_listing_several_bases_records_each() {
        let src = b"---\nbase_model:\n  - org/a\n  - org/b\n---\n";
        let out = parse_model_card(src, &lim()).unwrap();
        assert_eq!(out.facts_of(FactKind::BaseModelReference).count(), 2);
    }

    // -- abuse -------------------------------------------------------------

    #[test]
    fn malformed_and_empty_input_never_panics() {
        let tiny = Limits::tiny();
        let deep = format!("{}{}", "[".repeat(500), "]".repeat(500));
        for src in [
            &b""[..],
            &b"{"[..],
            &b"null"[..],
            &b"[]"[..],
            &b"{\"a\":1,\"a\":2}"[..],
            deep.as_bytes(),
            &[0xffu8, 0xfe][..],
        ] {
            for f in [
                parse_transformers_config as fn(&[u8], &Limits) -> TtResult<ParseOutput>,
                parse_peft_adapter_config,
                parse_shard_index,
                parse_trainer_state,
                parse_training_args,
                parse_tokenizer_identity,
            ] {
                let _ = f(src, &lim());
                let _ = f(src, &tiny);
            }
            let _ = parse_model_card(src, &lim());
        }
    }

    #[test]
    fn an_oversized_tokenizer_is_a_note_not_a_failure() {
        let tiny = Limits::tiny();
        let big = vec![b'x'; (tiny.config_bytes + 1) as usize];
        let out = parse_tokenizer_identity(&big, &tiny).unwrap();
        assert!(out.has_note("TT-FMT-010"));
        assert!(out.facts.is_empty(), "nothing may be claimed about a file that was not read");
    }

    #[test]
    fn dispatch_covers_every_type_it_claims() {
        let cfg = br#"{"model_type":"llama"}"#;
        assert!(parse_for(ArtifactType::TransformersConfig, cfg, &lim()).is_some());
        assert!(parse_for(ArtifactType::PeftAdapterConfig, b"{}", &lim()).is_some());
        assert!(parse_for(ArtifactType::SafeTensors, b"", &lim()).is_none());
        assert!(parse_for(ArtifactType::OpaqueSerialization, b"", &lim()).is_none());
    }
}
