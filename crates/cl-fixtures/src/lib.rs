//! The golden fixture corpus.
//!
//! This is the test set the whole product is judged against, so its realism *is*
//! the deliverable. A fixture that is accidentally malformed teaches the rules
//! engine the wrong lesson, so every case that claims to be structurally valid is
//! structurally valid: real 8-byte SafeTensors length prefixes, non-overlapping
//! `data_offsets`, adapter ranks that agree with their tensor shapes.
//!
//! ## Half of the corpus exists to make the scanner say nothing
//!
//! Positive cases are easy to write and easy to pass. The cases that matter are the
//! ones where the correct behaviour is to **abstain**: a merged adapter Stage 1
//! cannot prove, continued pretraining that is indistinguishable from fine-tuning
//! given only final weights, a from-scratch claim resting on nothing but the absence
//! of a match. Each of those carries `must_not_name`, and a scanner that grew
//! confident enough to name them would fail this suite rather than ship.
//!
//! Every case states its ground truth in `MANIFEST.md` and its machine-checkable
//! expectations in [`Case::expect`].

#![forbid(unsafe_code)]

use std::io;
use std::path::Path;
use cl_core::vocab::{AbstentionId, Facet, SupportBand};

/// What a correct Stage-1 result looks like for one case.
#[derive(Debug, Clone, Default)]
pub struct Expect {
    /// Facets on which no method may be named, whatever the evidence.
    pub must_not_name: &'static [Facet],
    /// Facets whose band is pinned exactly.
    pub band: &'static [(Facet, SupportBand)],
    /// Abstentions that must be present.
    pub abstentions: &'static [(Facet, AbstentionId)],
    /// True when the scan must produce no contradiction at all.
    ///
    /// This is the guard against the failure mode that matters most: a screen that
    /// accuses an honest vendor.
    pub no_contradictions: bool,
    /// Substrings that must never appear anywhere in the report.
    pub must_not_leak: &'static [&'static str],
}

/// Declared lineage, as the vendor would state it on the command line.
#[derive(Debug, Clone, Copy, Default)]
pub struct Declared {
    pub weight_origin: Option<&'static str>,
    pub parameter_update: Option<&'static str>,
    pub training_stage: Option<&'static str>,
    pub augmentation: &'static [&'static str],
}

pub struct Case {
    pub name: &'static str,
    pub kind: CaseKind,
    /// The ground truth, written into MANIFEST.md.
    pub truth: &'static str,
    /// The exact claim the vendor is making.
    pub claim: &'static str,
    pub declared: Declared,
    pub expect: Expect,
    /// Builds the case's files under `dir`.
    pub build: fn(&Path) -> io::Result<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseKind {
    /// The evidence genuinely supports the claim.
    Golden,
    /// The evidence looks supportive but must not be over-read.
    HardNegative,
    /// Malformed or hostile input.
    Abuse,
    /// Contains material that must never reach the report.
    Privacy,
}

impl CaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CaseKind::Golden => "golden",
            CaseKind::HardNegative => "hard_negative",
            CaseKind::Abuse => "abuse",
            CaseKind::Privacy => "privacy",
        }
    }
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

fn write(dir: &Path, rel: &str, bytes: &[u8]) -> io::Result<()> {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(p, bytes)
}

/// A structurally valid SafeTensors file: real length prefix, coherent offsets,
/// zero-filled data so the fixture stays small on disk.
pub fn safetensors(tensors: &[(String, &str, Vec<i64>)]) -> Vec<u8> {
    let mut entries: Vec<String> = Vec::new();
    let mut offset: u64 = 0;
    for (name, dtype, shape) in tensors {
        let elems: i64 = shape.iter().product();
        let size = (elems.max(0) as u64) * dtype_size(dtype);
        let dims = shape.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(",");
        entries.push(format!(
            "\"{name}\":{{\"dtype\":\"{dtype}\",\"shape\":[{dims}],\"data_offsets\":[{offset},{}]}}",
            offset + size
        ));
        offset += size;
    }
    let header = format!("{{{}}}", entries.join(","));
    let mut out = (header.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(header.as_bytes());
    out.resize(out.len() + offset as usize, 0);
    out
}

fn dtype_size(d: &str) -> u64 {
    match d {
        "BOOL" | "U8" | "I8" | "F8_E4M3" | "F8_E5M2" => 1,
        "I16" | "U16" | "F16" | "BF16" => 2,
        "I64" | "U64" | "F64" => 8,
        _ => 4,
    }
}

/// A small but realistic LoRA adapter tensor set at the given rank.
fn lora_tensors(rank: i64, layers: i64) -> Vec<(String, &'static str, Vec<i64>)> {
    let mut t = Vec::new();
    for l in 0..layers {
        for proj in ["q_proj", "v_proj"] {
            let base = format!("base_model.model.model.layers.{l}.self_attn.{proj}");
            t.push((format!("{base}.lora_A.weight"), "F32", vec![rank, 256]));
            t.push((format!("{base}.lora_B.weight"), "F32", vec![256, rank]));
        }
    }
    t
}

fn dense_tensors(layers: i64) -> Vec<(String, &'static str, Vec<i64>)> {
    let mut t = Vec::new();
    for l in 0..layers {
        t.push((format!("model.layers.{l}.self_attn.q_proj.weight"), "F32", vec![64, 64]));
        t.push((format!("model.layers.{l}.mlp.down_proj.weight"), "F32", vec![64, 64]));
    }
    t
}

const QWEN_CONFIG: &[u8] = br#"{"architectures":["Qwen2ForCausalLM"],"model_type":"qwen2","hidden_size":256,"num_hidden_layers":4,"num_attention_heads":8,"vocab_size":151936,"torch_dtype":"bfloat16","transformers_version":"4.44.0"}"#;

fn trainer_state(steps: &[i64]) -> Vec<u8> {
    let entries: Vec<String> = steps
        .iter()
        .enumerate()
        .map(|(i, s)| {
            format!("{{\"step\":{s},\"loss\":{}.{},\"learning_rate\":5e-05,\"epoch\":0.{i}}}", 3 - (i as i64).min(2), 25)
        })
        .collect();
    format!(
        "{{\"global_step\":{},\"max_steps\":{},\"log_history\":[{}]}}",
        steps.last().copied().unwrap_or(0),
        steps.last().copied().unwrap_or(0),
        entries.join(",")
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

pub fn cases() -> &'static [Case] {
    static CASES: std::sync::OnceLock<Vec<Case>> = std::sync::OnceLock::new();
    CASES.get_or_init(|| {
        vec![
        // ---------------- golden ----------------
        Case {
            name: "obvious_unmerged_lora",
            kind: CaseKind::Golden,
            truth: "A genuine unmerged LoRA adapter over a pinned base. The adapter config's \
                    rank agrees with the tensor shapes, and the base is named with a commit.",
            claim: "We fine-tuned Qwen2.5 with a LoRA adapter.",
            declared: Declared {
                weight_origin: Some("derivative_of_disclosed_base"),
                parameter_update: Some("unmerged_peft_observed"),
                ..Declared::none()
            },
            expect: Expect { no_contradictions: true, ..Expect::default_const() },
            build: |d| {
                write(d, "adapter/adapter_config.json", br#"{"peft_type":"LORA","task_type":"CAUSAL_LM","r":16,"lora_alpha":32,"lora_dropout":0.05,"target_modules":["q_proj","v_proj"],"base_model_name_or_path":"Qwen/Qwen2.5-7B","revision":"a1b2c3d4e5f6a7b8"}"#)?;
                write(d, "adapter/adapter_model.safetensors", &safetensors(&lora_tensors(16, 4)))?;
                write(d, "config.json", QWEN_CONFIG)?;
                write(d, "trainer_state.json", &trainer_state(&[100, 200, 300]))?;
                Ok(())
            },
        },
        Case {
            name: "renamed_valid_adapter",
            kind: CaseKind::Golden,
            truth: "The same adapter saved under an innocuous name. Classification is by \
                    magic bytes, so it must still be recognised as SafeTensors.",
            claim: "We fine-tuned an open model with LoRA.",
            declared: Declared { parameter_update: Some("unmerged_peft_observed"), ..Declared::none() },
            expect: Expect { no_contradictions: true, ..Expect::default_const() },
            build: |d| {
                write(d, "adapter_config.json", br#"{"peft_type":"LORA","r":8,"target_modules":["q_proj","v_proj"],"base_model_name_or_path":"meta-llama/Llama-3-8B"}"#)?;
                write(d, "weights.dat", &safetensors(&lora_tensors(8, 2)))?;
                Ok(())
            },
        },
        Case {
            name: "dense_finetune_coherent_logs",
            kind: CaseKind::Golden,
            truth: "A dense fine-tune with an ordered loss history. The history is in order, \
                    so no contradiction may be raised about it.",
            claim: "We fully fine-tuned an open base model.",
            declared: Declared {
                weight_origin: Some("derivative_of_disclosed_base"),
                parameter_update: Some("partial_or_dense_update"),
                ..Declared::none()
            },
            expect: Expect { no_contradictions: true, ..Expect::default_const() },
            build: |d| {
                write(d, "model.safetensors", &safetensors(&dense_tensors(6)))?;
                write(d, "config.json", QWEN_CONFIG)?;
                write(d, "trainer_state.json", &trainer_state(&[50, 100, 150, 200]))?;
                write(d, "training_args.json", br#"{"learning_rate":2e-5,"num_train_epochs":3,"optim":"adamw_torch","seed":42,"task_type":"CAUSAL_LM"}"#)?;
                Ok(())
            },
        },
        Case {
            name: "api_plus_rag_no_local_weights",
            kind: CaseKind::Golden,
            truth: "An API wrapper with retrieval and no local weights at all, while the \
                    vendor claims to have trained a model. The weight facets must report \
                    that the artifact was not supplied, and retrieval must still score.",
            claim: "We built and trained our own proprietary language model.",
            declared: Declared {
                weight_origin: Some("random_initialization_claimed"),
                augmentation: &["rag", "external_api_router"],
                ..Declared::none()
            },
            expect: Expect {
                must_not_name: &[Facet::WeightOrigin, Facet::ParameterUpdate],
                band: &[
                    (Facet::WeightOrigin, SupportBand::NotSupplied),
                    (Facet::ParameterUpdate, SupportBand::NotSupplied),
                ],
                ..Expect::default_const()
            },
            build: |d| {
                write(d, "requirements.txt", b"openai==1.30.1\nlangchain==0.2.5\nchromadb==0.5.0\n")?;
                write(d, "docker-compose.yml", b"services:\n  api:\n    image: python:3.11-slim\n    environment:\n      OPENAI_BASE_URL: https://api.openai.com/v1\n")?;
                write(d, "traces.jsonl", br#"{"query":"a","retrieved":[{"text":"x","score":0.9}]}
{"query":"b","retrieved":[{"text":"y","score":0.8}]}"#)?;
                write(d, "rag.jinja", b"Use {context} to answer {question}.")?;
                write(d, "chroma.sqlite3", b"SQLite format 3\0")?;
                Ok(())
            },
        },
        Case {
            name: "rag_plus_lora",
            kind: CaseKind::Golden,
            truth: "Both a real adapter and real retrieval. The facets are independent and \
                    neither may weigh against the other.",
            claim: "We fine-tuned with LoRA and added retrieval.",
            declared: Declared {
                parameter_update: Some("unmerged_peft_observed"),
                augmentation: &["rag"],
                ..Declared::none()
            },
            expect: Expect { no_contradictions: true, ..Expect::default_const() },
            build: |d| {
                write(d, "adapter/adapter_config.json", br#"{"peft_type":"LORA","r":16,"target_modules":["q_proj","v_proj"],"base_model_name_or_path":"Qwen/Qwen2.5-7B","revision":"a1b2c3d4e5f6"}"#)?;
                write(d, "adapter/adapter_model.safetensors", &safetensors(&lora_tensors(16, 3)))?;
                write(d, "rag/traces.jsonl", br#"{"query":"a","retrieved":[{"text":"x","score":0.9}]}"#)?;
                write(d, "rag/chroma.sqlite3", b"SQLite format 3\0")?;
                Ok(())
            },
        },
        // ---------------- must abstain ----------------
        Case {
            name: "lora_merged_into_full_weights",
            kind: CaseKind::HardNegative,
            truth: "An adapter merged into dense weights. Stage 1 does not compare tensors, \
                    so it CANNOT establish this and must abstain. Naming it would be the \
                    single worst over-claim available to this product.",
            claim: "We fine-tuned with LoRA and merged the adapter.",
            declared: Declared {
                weight_origin: Some("derivative_of_disclosed_base"),
                parameter_update: Some("merged_adapter_consistent"),
                ..Declared::none()
            },
            expect: Expect {
                must_not_name: &[Facet::ParameterUpdate],
                no_contradictions: true,
                ..Expect::default_const()
            },
            build: |d| {
                write(d, "model.safetensors", &safetensors(&dense_tensors(8)))?;
                write(d, "config.json", QWEN_CONFIG)?;
                write(d, "README.md", b"---\nbase_model: Qwen/Qwen2.5-7B\n---\nMerged LoRA into the base.\n")?;
                Ok(())
            },
        },
        Case {
            name: "cpt_vs_sft_final_only",
            kind: CaseKind::HardNegative,
            truth: "Continued pretraining is claimed, but only final weights are supplied. \
                    Final weights alone cannot distinguish CPT from supervised fine-tuning, \
                    so the training stage must abstain.",
            claim: "We continued pretraining an open model on our own corpus.",
            declared: Declared { training_stage: Some("continued_pretraining"), ..Declared::none() },
            expect: Expect {
                must_not_name: &[Facet::TrainingStage],
                abstentions: &[(Facet::TrainingStage, AbstentionId::CptFinalOnly)],
                no_contradictions: true,
                ..Expect::default_const()
            },
            build: |d| {
                write(d, "model.safetensors", &safetensors(&dense_tensors(6)))?;
                write(d, "config.json", QWEN_CONFIG)?;
                Ok(())
            },
        },
        Case {
            name: "scratch_claim_final_weights_only",
            kind: CaseKind::HardNegative,
            truth: "Training from random initialisation is claimed with nothing but final \
                    weights. Failure to match a known base does not establish scratch \
                    training, and Stage 1 makes no such comparison anyway.",
            claim: "We trained this model from scratch.",
            declared: Declared { weight_origin: Some("random_initialization_claimed"), ..Declared::none() },
            expect: Expect {
                must_not_name: &[Facet::WeightOrigin],
                abstentions: &[(Facet::WeightOrigin, AbstentionId::ScratchNoMatchOnly)],
                no_contradictions: true,
                ..Expect::default_const()
            },
            build: |d| {
                write(d, "model.safetensors", &safetensors(&dense_tensors(10)))?;
                write(d, "config.json", QWEN_CONFIG)?;
                Ok(())
            },
        },
        Case {
            name: "quantized_sibling",
            kind: CaseKind::HardNegative,
            truth: "Quantised weights. Quantisation erases the delta pattern any comparison \
                    would rest on, so parameter-update reasoning must abstain.",
            claim: "We fine-tuned and quantised our model.",
            declared: Declared { parameter_update: Some("merged_adapter_consistent"), ..Declared::none() },
            expect: Expect {
                must_not_name: &[Facet::ParameterUpdate],
                abstentions: &[(Facet::ParameterUpdate, AbstentionId::QuantizedOnly)],
                ..Expect::default_const()
            },
            build: |d| {
                write(d, "model.safetensors", &safetensors(&dense_tensors(4)))?;
                write(d, "config.json", br#"{"model_type":"llama","hidden_size":256,"quantization_config":{"quant_method":"gptq","bits":4}}"#)?;
                Ok(())
            },
        },
        Case {
            name: "fabricated_neat_logs",
            kind: CaseKind::HardNegative,
            truth: "A perfectly linear, suspiciously tidy loss curve. Stage 1 cannot tell a \
                    fabricated log from a real one and MUST NOT contradict on tidiness.",
            claim: "We fine-tuned an open model.",
            declared: Declared { parameter_update: Some("partial_or_dense_update"), ..Declared::none() },
            expect: Expect { no_contradictions: true, ..Expect::default_const() },
            build: |d| {
                write(d, "model.safetensors", &safetensors(&dense_tensors(4)))?;
                write(d, "trainer_state.json", &trainer_state(&[100, 200, 300, 400, 500]))?;
                Ok(())
            },
        },
        Case {
            name: "dora_adapter",
            kind: CaseKind::HardNegative,
            truth: "A DoRA adapter carries magnitude vectors alongside the usual pairs. The \
                    expected tensor set differs, and a rank check must not fire spuriously.",
            claim: "We fine-tuned with DoRA.",
            declared: Declared { parameter_update: Some("unmerged_peft_observed"), ..Declared::none() },
            expect: Expect { no_contradictions: true, ..Expect::default_const() },
            build: |d| {
                write(d, "adapter_config.json", br#"{"peft_type":"LORA","r":8,"use_dora":true,"target_modules":["q_proj","v_proj"],"base_model_name_or_path":"Qwen/Qwen2.5-7B"}"#)?;
                let mut t = lora_tensors(8, 2);
                for l in 0..2 {
                    t.push((
                        format!("base_model.model.model.layers.{l}.self_attn.q_proj.lora_magnitude_vector"),
                        "F32",
                        vec![256],
                    ));
                }
                write(d, "adapter_model.safetensors", &safetensors(&t))?;
                Ok(())
            },
        },
        Case {
            name: "copied_timestamps",
            kind: CaseKind::HardNegative,
            truth: "Every file shares one modification time, which is what copying a \
                    directory produces. That is an ambiguity, never a contradiction.",
            claim: "We fine-tuned an open model with LoRA.",
            declared: Declared { parameter_update: Some("unmerged_peft_observed"), ..Declared::none() },
            expect: Expect { no_contradictions: true, ..Expect::default_const() },
            build: |d| {
                write(d, "adapter_config.json", br#"{"peft_type":"LORA","r":16,"target_modules":["q_proj"]}"#)?;
                write(d, "adapter_model.safetensors", &safetensors(&lora_tensors(16, 2)))?;
                write(d, "config.json", QWEN_CONFIG)?;
                write(d, "README.md", b"# Model\n")?;
                Ok(())
            },
        },
        // ---------------- abuse ----------------
        Case {
            name: "malformed_adapter_config_mismatch",
            kind: CaseKind::Abuse,
            truth: "The config declares rank 32 while the tensors imply rank 8. That IS a \
                    contradiction: an exact claim conflicting with an observed artifact.",
            claim: "We fine-tuned with a rank-32 LoRA adapter.",
            declared: Declared { parameter_update: Some("unmerged_peft_observed"), ..Declared::none() },
            expect: Expect::default_const(),
            build: |d| {
                write(d, "adapter_config.json", br#"{"peft_type":"LORA","r":32,"target_modules":["q_proj","v_proj"],"base_model_name_or_path":"Qwen/Qwen2.5-7B"}"#)?;
                write(d, "adapter_model.safetensors", &safetensors(&lora_tensors(8, 2)))?;
                Ok(())
            },
        },
        Case {
            name: "parser_abuse",
            kind: CaseKind::Abuse,
            truth: "Truncated, overlapping, BOM-prefixed and duplicate-keyed files. Every \
                    one must produce a coverage note and none may crash the scan.",
            claim: "We fine-tuned an open model.",
            declared: Declared::none(),
            expect: Expect { no_contradictions: true, ..Expect::default_const() },
            build: |d| {
                // A length prefix that promises far more than the file holds.
                let mut truncated = 4096u64.to_le_bytes().to_vec();
                truncated.extend_from_slice(br#"{"a":{"dtype":"F32""#);
                write(d, "truncated.safetensors", &truncated)?;

                // Two tensors claiming the same bytes.
                let header = br#"{"a":{"dtype":"F32","shape":[4],"data_offsets":[0,16]},"b":{"dtype":"F32","shape":[4],"data_offsets":[8,24]}}"#;
                let mut overlap = (header.len() as u64).to_le_bytes().to_vec();
                overlap.extend_from_slice(header);
                overlap.resize(overlap.len() + 24, 0);
                write(d, "overlap.safetensors", &overlap)?;

                write(d, "bom.json", "\u{feff}{\"model_type\":\"llama\"}".as_bytes())?;
                write(d, "duplicate.json", br#"{"model_type":"llama","model_type":"qwen2"}"#)?;
                write(d, "deep.json", format!("{}1{}", "[".repeat(500), "]".repeat(500)).as_bytes())?;
                write(d, "anchors.yaml", b"base: &a\n  x: 1\nother: *a\n")?;
                write(d, "not_a_gguf.gguf", b"GGUF")?;
                Ok(())
            },
        },
        // ---------------- privacy ----------------
        Case {
            name: "privacy_bait",
            kind: CaseKind::Privacy,
            truth: "Every file here contains something that must never reach the report: an \
                    API key, an absolute Windows user path, an e-mail address, a private \
                    key block, and a sample of dataset text.",
            claim: "We fine-tuned an open model.",
            declared: Declared::none(),
            expect: Expect {
                must_not_leak: &[
                    "sk-abcdefghijklmnopqrstuvwxyz012345",
                    "hf_abcdefghijklmnopqrstuvwxyz012345",
                    "AKIAIOSFODNN7EXAMPLE",
                    "jane.doe@acme.example",
                    "BEGIN RSA PRIVATE KEY",
                    "MIIEowIBAAKCAQEA",
                ],
                ..Expect::default_const()
            },
            build: |d| {
                write(d, ".env", b"OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz012345\nHF_TOKEN=hf_abcdefghijklmnopqrstuvwxyz012345\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nMODEL_DIR=C:\\Users\\alice\\models\\private\n")?;
                write(d, "README.md", b"---\nbase_model: Qwen/Qwen2.5-7B\n---\nContact jane.doe@acme.example for access.\n")?;
                write(d, "id_rsa", b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0123456789abcdef\n-----END RSA PRIVATE KEY-----\n")?;
                write(d, "config.json", QWEN_CONFIG)?;
                write(d, "adapter_config.json", br#"{"peft_type":"LORA","r":8,"target_modules":["q_proj"],"base_model_name_or_path":"Qwen/Qwen2.5-7B"}"#)?;
                write(d, "adapter_model.safetensors", &safetensors(&lora_tensors(8, 2)))?;
                Ok(())
            },
        },
        ]
    })
}

impl Expect {
    /// `Default` is not const, and these live in a `const` slice.
    pub const fn default_const() -> Expect {
        Expect {
            must_not_name: &[],
            band: &[],
            abstentions: &[],
            no_contradictions: false,
            must_not_leak: &[],
        }
    }
}

impl Declared {
    pub const fn none() -> Declared {
        Declared { weight_origin: None, parameter_update: None, training_stage: None, augmentation: &[] }
    }
}

pub fn case(name: &str) -> Option<&'static Case> {
    cases().iter().find(|c| c.name == name)
}

/// Generate one case into `root/<name>/`, with its MANIFEST.md.
pub fn generate(case: &Case, root: &Path) -> io::Result<std::path::PathBuf> {
    let dir = root.join(case.name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    (case.build)(&dir)?;

    let mut m = String::new();
    m.push_str(&format!("# {}\n\n", case.name));
    m.push_str(&format!("**Kind:** {}\n\n", case.kind.as_str()));
    m.push_str(&format!("**Claim under test:** {}\n\n", case.claim));
    m.push_str("## Ground truth\n\n");
    m.push_str(case.truth);
    m.push_str("\n\n## Correct Stage-1 behaviour\n\n");
    if case.expect.must_not_name.is_empty() {
        m.push_str("- No facet is required to abstain.\n");
    } else {
        for f in case.expect.must_not_name {
            m.push_str(&format!("- **Must NOT name a method on `{}`.**\n", f.as_str()));
        }
    }
    for (f, b) in case.expect.band {
        m.push_str(&format!("- `{}` must report `{}`.\n", f.as_str(), b.as_str()));
    }
    for (f, a) in case.expect.abstentions {
        m.push_str(&format!("- `{}` must record abstention `{}`.\n", f.as_str(), a.as_str()));
    }
    if case.expect.no_contradictions {
        m.push_str("- The scan must produce **no contradiction**.\n");
    }
    for s in case.expect.must_not_leak {
        m.push_str(&format!("- The report must never contain `{s}`.\n"));
    }
    std::fs::write(dir.join("MANIFEST.md"), m)?;
    Ok(dir)
}

/// Generate every case and write a machine-readable index beside them.
pub fn generate_all(root: &Path) -> io::Result<()> {
    std::fs::create_dir_all(root)?;
    for c in cases() {
        generate(c, root)?;
    }
    let mut index = cl_core::canon::Obj::new();
    let entries: Vec<cl_core::canon::CanonValue> = cases()
        .iter()
        .map(|c| {
            let mut o = cl_core::canon::Obj::new()
                .with("name", c.name)
                .with("kind", c.kind.as_str())
                .with("claim", c.claim)
                .with("truth", c.truth)
                .with("no_contradictions", c.expect.no_contradictions);
            o.set(
                "must_not_name",
                c.expect.must_not_name.iter().map(|f| f.as_str().to_string()).collect::<Vec<_>>(),
            );
            o.set(
                "expected_bands",
                cl_core::canon::CanonValue::Arr(
                    c.expect
                        .band
                        .iter()
                        .map(|(f, b)| {
                            cl_core::canon::CanonValue::Obj(
                                cl_core::canon::Obj::new().with("facet", *f).with("band", *b),
                            )
                        })
                        .collect(),
                ),
            );
            cl_core::canon::CanonValue::Obj(o)
        })
        .collect();
    index.set("schema_version", cl_core::SCHEMA_VERSION);
    index.set("case_count", entries.len());
    index.set("cases", cl_core::canon::CanonValue::Arr(entries));
    std::fs::write(
        root.join("INDEX.json"),
        cl_core::canon::CanonValue::Obj(index).to_pretty_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("cl-fix-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn every_case_generates() {
        let root = tmp("all");
        generate_all(&root).expect("generate");
        for c in cases() {
            assert!(root.join(c.name).join("MANIFEST.md").exists(), "{} has no manifest", c.name);
        }
        assert!(root.join("INDEX.json").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Every file under `dir`, as (relative path, bytes), sorted.
    fn tree(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    let rel =
                        p.strip_prefix(dir).unwrap().to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
                    out.push((rel, std::fs::read(&p).unwrap_or_default()));
                }
            }
        }
        out.sort();
        out
    }

    #[test]
    fn generating_twice_produces_identical_bytes() {
        // Determinism is a product requirement, and the corpus is the thing every
        // other determinism claim is measured against.
        let a = tmp("det-a");
        let b = tmp("det-b");
        generate_all(&a).unwrap();
        generate_all(&b).unwrap();
        for c in cases() {
            let ta = tree(&a.join(c.name));
            let tb = tree(&b.join(c.name));
            assert!(!ta.is_empty(), "{} generated no files", c.name);
            assert_eq!(
                ta.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
                tb.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
                "{} listed different files between runs",
                c.name
            );
            for ((n, x), (_, y)) in ta.iter().zip(tb.iter()) {
                assert_eq!(x, y, "{}/{} differed between runs", c.name, n);
            }
        }
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn case_names_are_unique() {
        let mut seen = Vec::new();
        for c in cases() {
            assert!(!seen.contains(&c.name), "duplicate case {}", c.name);
            seen.push(c.name);
        }
    }

    #[test]
    fn the_corpus_contains_more_abstention_cases_than_positive_ones() {
        // The cases that matter are the ones where the correct answer is silence. If
        // the suite ever tilts towards cases that are easy to pass, it has stopped
        // testing the property this product is for.
        let must_abstain = cases().iter().filter(|c| !c.expect.must_not_name.is_empty()).count();
        assert!(must_abstain >= 4, "only {must_abstain} cases require abstention");
    }

    #[test]
    fn generated_safetensors_are_structurally_valid() {
        // A fixture that is accidentally malformed teaches the rules engine the wrong
        // lesson, so the ones claiming validity are checked here.
        let t = safetensors(&lora_tensors(16, 2));
        assert!(t.len() > 8);
        let mut n = [0u8; 8];
        n.copy_from_slice(&t[..8]);
        let header_len = u64::from_le_bytes(n) as usize;
        assert!(8 + header_len <= t.len(), "header runs past the end of the file");
        let header = std::str::from_utf8(&t[8..8 + header_len]).expect("header is UTF-8");
        assert!(header.starts_with('{') && header.ends_with('}'));
        assert!(header.contains("lora_A"), "the adapter shape is missing");
        // Offsets must be contiguous and inside the data region.
        let data_len = t.len() - 8 - header_len;
        let last_end: usize = header
            .rsplit("data_offsets\":[")
            .next()
            .and_then(|s| s.split(']').next())
            .and_then(|s| s.split(',').nth(1))
            .and_then(|s| s.trim().parse().ok())
            .expect("a final offset");
        assert_eq!(last_end, data_len, "declared offsets do not match the data region");
    }
}
