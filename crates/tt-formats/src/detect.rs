//! Artifact classification: deciding *what a file is* before deciding what it says.
//!
//! Classification runs on a file name and a bounded head buffer, never on the whole
//! file, because the scanner classifies every file it walks and most of them are
//! large or irrelevant.
//!
//! ## Magic first, name second
//!
//! A file's name is chosen by the party under scrutiny; its leading bytes are chosen
//! by the tool that wrote it. So a container is recognised by its magic wherever a
//! magic exists, and the extension is only consulted when the bytes are silent. That
//! ordering is what makes `renamed_valid_adapter` — an adapter saved under an
//! innocuous name — classify correctly, and it is also why a `.safetensors`
//! extension on a file whose header is not SafeTensors does not make it one.
//!
//! ## Classification is not judgement
//!
//! Recognising a file as an adapter is not evidence that an adapter was used. It only
//! selects a parser. Every conclusion is drawn later, by `tt-rules`, from the facts
//! that parser emits.

use std::path::Path;
use tt_facts::ArtifactType;

/// Bytes of head buffer the classifier can make use of.
///
/// A SafeTensors decision needs 8 length bytes plus the first header byte; ONNX and
/// GGUF need fewer. The rest is used for content sniffing of text formats.
pub const CLASSIFY_HEAD_BYTES: usize = 1024;

/// Formats that execute code when loaded. These are hashed and counted, never opened.
const OPAQUE_EXTENSIONS: &[&str] =
    &["pt", "pth", "bin", "pkl", "pickle", "joblib", "npy", "npz", "ckpt", "msgpack", "dill"];

fn ext_lower(path: &Path) -> String {
    path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default()
}

fn name_lower(path: &Path) -> String {
    path.file_name().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default()
}

/// True when the head looks like a SafeTensors container.
///
/// The format is an 8-byte little-endian header length followed by JSON. Requiring
/// the ninth byte to open an object rejects a file that merely happens to start with
/// eight plausible length bytes.
fn is_safetensors(head: &[u8]) -> bool {
    if head.len() < 9 {
        return false;
    }
    let mut n = [0u8; 8];
    n.copy_from_slice(&head[..8]);
    let len = u64::from_le_bytes(n);
    // A zero-length or absurd header is not a SafeTensors file.
    (2..=64 * 1024 * 1024).contains(&len) && head[8] == b'{'
}

fn is_gguf(head: &[u8]) -> bool {
    head.starts_with(b"GGUF")
}

/// ONNX is a bare protobuf with no magic. The best available signal is that
/// `ModelProto` almost always begins with field 1 (`ir_version`) as a varint, which
/// encodes as the tag byte `0x08`. This is weak on its own, so it is only trusted
/// alongside the extension.
fn looks_like_protobuf(head: &[u8]) -> bool {
    matches!(head.first(), Some(0x08))
}

fn is_zip(head: &[u8]) -> bool {
    head.starts_with(b"PK\x03\x04")
}

fn is_sqlite(head: &[u8]) -> bool {
    head.starts_with(b"SQLite format 3\0")
}

/// Does the head look like a retrieval trace rather than an ordinary JSONL file?
fn looks_like_retrieval_trace(head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(head).to_ascii_lowercase();
    let has_query = text.contains("\"query\"") || text.contains("\"question\"");
    let has_retrieved = text.contains("\"retrieved\"")
        || text.contains("\"documents\"")
        || text.contains("\"chunks\"")
        || text.contains("\"contexts\"");
    has_query && has_retrieved
}

fn looks_like_prompt_template(head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(head);
    text.contains("{context}") || text.contains("{{context}}") || text.contains("{question}")
}

/// Classify one file from its path and a bounded head buffer.
pub fn classify(path: &Path, head: &[u8]) -> ArtifactType {
    // 1. Magic bytes, which the vendor does not choose casually.
    if is_gguf(head) {
        return ArtifactType::Gguf;
    }
    if is_safetensors(head) {
        return ArtifactType::SafeTensors;
    }
    if is_sqlite(head) {
        // Chroma stores its index in SQLite; other SQLite files are still opaque to us.
        return ArtifactType::VectorIndex;
    }

    let name = name_lower(path);
    let ext = ext_lower(path);

    if ext == "onnx" && (looks_like_protobuf(head) || head.is_empty()) {
        return ArtifactType::Onnx;
    }

    // 2. Exact well-known file names.
    match name.as_str() {
        "adapter_config.json" => return ArtifactType::PeftAdapterConfig,
        "config.json" => return ArtifactType::TransformersConfig,
        "generation_config.json" => return ArtifactType::GenerationConfig,
        "tokenizer_config.json" | "tokenizer.json" | "special_tokens_map.json" | "vocab.json"
        | "merges.txt" => return ArtifactType::TokenizerConfig,
        "trainer_state.json" => return ArtifactType::TrainerState,
        "training_args.json" | "args.json" | "run_args.json" => return ArtifactType::TrainingArgs,
        "readme.md" | "model_card.md" => return ArtifactType::ModelCard,
        "dockerfile" | "containerfile" | "procfile" => return ArtifactType::DeploymentManifest,
        "requirements.txt" | "requirements-dev.txt" | "cargo.lock" | "package.json"
        | "package-lock.json" | "pyproject.toml" | "poetry.lock" | "environment.yml"
        | "environment.yaml" | "conda-list.txt" | "pip-freeze.txt" => {
            return ArtifactType::DependencyLockfile
        }
        "index.faiss" | "index.pkl" | "docstore.json" | "index_store.json"
        | "chroma.sqlite3" | "meta.json" => return ArtifactType::VectorIndex,
        "config_sentence_transformers.json" | "modules.json" => return ArtifactType::VectorIndex,
        ".env" | ".env.local" | ".env.production" => return ArtifactType::ServingConfig,
        _ => {}
    }

    // 3. Name patterns.
    if name.ends_with(".index.json") {
        return ArtifactType::ShardIndex;
    }
    if name.starts_with("docker-compose") && (ext == "yml" || ext == "yaml") {
        return ArtifactType::DeploymentManifest;
    }
    if name.starts_with("ds_config") || name.starts_with("deepspeed") {
        return ArtifactType::DeepSpeedConfig;
    }
    if name.contains("accelerate") && (ext == "yaml" || ext == "yml" || ext == "json") {
        return ArtifactType::AccelerateConfig;
    }
    if ext == "service" || name.starts_with("k8s") || name.starts_with("deployment.") {
        return ArtifactType::DeploymentManifest;
    }
    if OPAQUE_EXTENSIONS.contains(&ext.as_str()) {
        return ArtifactType::OpaqueSerialization;
    }
    if ext == "safetensors" {
        // The extension says SafeTensors but the header did not. Recording it as an
        // unvalidated container rather than as SafeTensors keeps the parser from
        // being handed something it will only reject, and leaves the mismatch
        // visible in the manifest.
        return ArtifactType::Unrecognised;
    }
    if ext == "gguf" {
        return ArtifactType::Unrecognised;
    }
    if ext == "onnx" {
        return ArtifactType::Onnx;
    }
    if is_zip(head) {
        // A PyTorch .zip checkpoint or a wheel. Either way we do not open it.
        return ArtifactType::OpaqueSerialization;
    }

    // 4. Content sniffing for text formats.
    if ext == "jsonl" || ext == "ndjson" {
        return if looks_like_retrieval_trace(head) {
            ArtifactType::RetrievalTrace
        } else {
            ArtifactType::TrainingLog
        };
    }
    if matches!(ext.as_str(), "jinja" | "j2" | "prompt" | "tmpl") || looks_like_prompt_template(head)
    {
        return ArtifactType::VectorIndex;
    }
    if ext == "log" || name.contains("train") && (ext == "txt" || ext == "out" || ext == "err") {
        return ArtifactType::TrainingLog;
    }

    match ext.as_str() {
        "json" => ArtifactType::GenericJson,
        "yaml" | "yml" => ArtifactType::GenericYaml,
        "toml" => ArtifactType::GenericToml,
        "md" | "txt" | "rst" | "csv" | "tsv" => ArtifactType::PlainText,
        _ => ArtifactType::Unrecognised,
    }
}

/// Whether a classified artifact is one whose *contents* a parser will read.
///
/// Anything answering `false` is hashed, counted and left closed.
pub fn is_parseable(t: ArtifactType) -> bool {
    !matches!(
        t,
        ArtifactType::OpaqueSerialization | ArtifactType::Unrecognised | ArtifactType::PlainText
    )
}

/// How many bytes of a file a parser for this type needs.
pub fn read_need(t: ArtifactType, limits: &tt_core::limits::Limits) -> crate::ReadNeed {
    use crate::ReadNeed;
    match t {
        ArtifactType::SafeTensors => ReadNeed::Prefix(limits.safetensors_header_bytes + 8),
        ArtifactType::Gguf => ReadNeed::Prefix(limits.gguf_metadata_bytes),
        ArtifactType::Onnx => ReadNeed::Prefix(limits.onnx_prefix_bytes),
        ArtifactType::TrainingLog | ArtifactType::RetrievalTrace => {
            ReadNeed::Suffix(limits.log_tail_bytes)
        }
        _ => ReadNeed::Prefix(limits.config_bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    /// A minimal but genuine SafeTensors head: 8-byte LE length then `{`.
    fn st_head(header: &str) -> Vec<u8> {
        let mut v = (header.len() as u64).to_le_bytes().to_vec();
        v.extend_from_slice(header.as_bytes());
        v
    }

    #[test]
    fn magic_beats_a_misleading_name() {
        let head = st_head("{\"a\":{}}");
        // The renamed-adapter case: the extension says nothing, the bytes say plenty.
        assert_eq!(classify(&p("weights.dat"), &head), ArtifactType::SafeTensors);
        assert_eq!(classify(&p("notes.txt"), &head), ArtifactType::SafeTensors);
        assert_eq!(classify(&p("x.gguf"), b"GGUF\x03\x00\x00\x00"), ArtifactType::Gguf);
    }

    #[test]
    fn a_safetensors_extension_without_the_header_is_not_safetensors() {
        // Claiming to be a container does not make a file one. Recording it as
        // unrecognised keeps the mismatch visible instead of handing the parser
        // something it can only reject.
        assert_eq!(classify(&p("model.safetensors"), b"not a header at all"), ArtifactType::Unrecognised);
        assert_eq!(classify(&p("model.gguf"), b"XXXX"), ArtifactType::Unrecognised);
    }

    #[test]
    fn zero_and_absurd_header_lengths_are_rejected() {
        let mut zero = 0u64.to_le_bytes().to_vec();
        zero.push(b'{');
        assert_ne!(classify(&p("a.dat"), &zero), ArtifactType::SafeTensors);

        let mut huge = u64::MAX.to_le_bytes().to_vec();
        huge.push(b'{');
        assert_ne!(classify(&p("a.dat"), &huge), ArtifactType::SafeTensors);
    }

    #[test]
    fn a_plausible_length_without_an_opening_brace_is_rejected() {
        let mut v = 64u64.to_le_bytes().to_vec();
        v.push(b'x');
        assert_ne!(classify(&p("a.dat"), &v), ArtifactType::SafeTensors);
    }

    #[test]
    fn well_known_names_are_recognised() {
        for (name, want) in [
            ("adapter_config.json", ArtifactType::PeftAdapterConfig),
            ("config.json", ArtifactType::TransformersConfig),
            ("trainer_state.json", ArtifactType::TrainerState),
            ("tokenizer_config.json", ArtifactType::TokenizerConfig),
            ("README.md", ArtifactType::ModelCard),
            ("requirements.txt", ArtifactType::DependencyLockfile),
            ("Dockerfile", ArtifactType::DeploymentManifest),
            ("model.safetensors.index.json", ArtifactType::ShardIndex),
            ("docker-compose.yml", ArtifactType::DeploymentManifest),
            (".env", ArtifactType::ServingConfig),
        ] {
            assert_eq!(classify(&p(name), b""), want, "for {name}");
        }
    }

    #[test]
    fn name_matching_is_case_insensitive() {
        assert_eq!(classify(&p("Adapter_Config.JSON"), b""), ArtifactType::PeftAdapterConfig);
        assert_eq!(classify(&p("DOCKERFILE"), b""), ArtifactType::DeploymentManifest);
    }

    #[test]
    fn code_executing_formats_are_marked_opaque() {
        for name in [
            "pytorch_model.bin",
            "model.pt",
            "checkpoint.pth",
            "state.pkl",
            "x.joblib",
            "arr.npy",
            "last.ckpt",
        ] {
            assert_eq!(
                classify(&p(name), b""),
                ArtifactType::OpaqueSerialization,
                "for {name}"
            );
        }
    }

    #[test]
    fn opaque_artifacts_are_never_parseable() {
        assert!(!is_parseable(ArtifactType::OpaqueSerialization));
        assert!(!is_parseable(ArtifactType::Unrecognised));
        assert!(is_parseable(ArtifactType::SafeTensors));
        assert!(is_parseable(ArtifactType::PeftAdapterConfig));
    }

    #[test]
    fn a_zip_checkpoint_is_opaque_not_a_container_we_open() {
        assert_eq!(classify(&p("weights.zip"), b"PK\x03\x04rest"), ArtifactType::OpaqueSerialization);
    }

    #[test]
    fn retrieval_traces_are_distinguished_from_ordinary_logs() {
        let trace = br#"{"query":"what is x","retrieved":[{"text":"a","score":0.9}]}"#;
        assert_eq!(classify(&p("t.jsonl"), trace), ArtifactType::RetrievalTrace);
        let plain = br#"{"loss":1.2,"step":10}"#;
        assert_eq!(classify(&p("t.jsonl"), plain), ArtifactType::TrainingLog);
    }

    #[test]
    fn generic_text_formats_fall_through_sensibly() {
        assert_eq!(classify(&p("thing.json"), b"{}"), ArtifactType::GenericJson);
        assert_eq!(classify(&p("thing.yaml"), b"a: 1"), ArtifactType::GenericYaml);
        assert_eq!(classify(&p("thing.toml"), b"[a]"), ArtifactType::GenericToml);
        assert_eq!(classify(&p("notes.md"), b"# hi"), ArtifactType::PlainText);
        assert_eq!(classify(&p("mystery"), b"\x00\x01\x02"), ArtifactType::Unrecognised);
    }

    #[test]
    fn empty_and_short_inputs_never_panic() {
        for head in [&b""[..], &b"G"[..], &b"GGU"[..], &[0u8; 8][..]] {
            let _ = classify(&p("x"), head);
            let _ = classify(&p("x.safetensors"), head);
            let _ = classify(&p(""), head);
        }
    }

    #[test]
    fn read_need_keeps_giant_checkpoints_to_a_prefix() {
        let l = tt_core::limits::Limits::default();
        assert!(matches!(
            read_need(ArtifactType::SafeTensors, &l),
            crate::ReadNeed::Prefix(n) if n == l.safetensors_header_bytes + 8
        ));
        assert!(matches!(
            read_need(ArtifactType::TrainingLog, &l),
            crate::ReadNeed::Suffix(_)
        ));
    }
}
