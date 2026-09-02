//! # tt-facts
//!
//! The normalised evidence model that sits between parsing and judgement.
//!
//! **Facts contain no verdict language.** A fact says "an adapter config declares
//! `peft_type = LORA`". It never says "this supports the LoRA claim". That
//! separation is the whole point: parsers can be wrong about *what a file says*, and
//! rules can be wrong about *what that means*, and keeping the two apart means each
//! can be tested, versioned and argued about on its own.
//!
//! A consequence worth stating: no type in this crate can express a score, a band,
//! a support level, or a contradiction.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use tt_core::canon::{CanonValue, Obj};
use tt_core::hash::{Digest, HashScope};
use tt_core::time::Timestamp;

// ---------------------------------------------------------------------------
// Artifacts
// ---------------------------------------------------------------------------

macro_rules! str_enum {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $variant:ident => $s:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name { $($(#[$vm])* $variant),+ }
        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];
            pub fn as_str(self) -> &'static str { match self { $($name::$variant => $s),+ } }
            pub fn parse(s: &str) -> Option<Self> {
                match s { $($s => Some($name::$variant),)+ _ => None }
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
        impl From<$name> for CanonValue {
            fn from(v: $name) -> Self { CanonValue::Str(v.as_str().to_string()) }
        }
    };
}

str_enum! {
    /// What kind of thing a file is, as far as the scanner could tell **without
    /// executing or deserialising it**.
    ArtifactType {
        SafeTensors => "safetensors",
        ShardIndex => "shard_index",
        Gguf => "gguf",
        Onnx => "onnx",
        /// Pickle, `.pt`, `.pth`, `.bin`, joblib, NumPy object arrays. Hashed and
        /// counted; never opened.
        OpaqueSerialization => "opaque_serialization",
        TransformersConfig => "transformers_config",
        PeftAdapterConfig => "peft_adapter_config",
        GenerationConfig => "generation_config",
        TokenizerConfig => "tokenizer_config",
        TrainerState => "trainer_state",
        TrainingArgs => "training_args",
        AccelerateConfig => "accelerate_config",
        DeepSpeedConfig => "deepspeed_config",
        TrainingLog => "training_log",
        DependencyLockfile => "dependency_lockfile",
        DeploymentManifest => "deployment_manifest",
        ServingConfig => "serving_config",
        VectorIndex => "vector_index",
        RetrievalTrace => "retrieval_trace",
        DatasetManifest => "dataset_manifest",
        ModelCard => "model_card",
        GenericJson => "generic_json",
        GenericYaml => "generic_yaml",
        GenericToml => "generic_toml",
        PlainText => "plain_text",
        Unrecognised => "unrecognised",
    }
}

str_enum! {
    ReadStatus {
        Ok => "ok",
        AccessDenied => "access_denied",
        TooLarge => "too_large",
        Changed => "changed",
        IoError => "io_error",
        SkippedReparsePoint => "skipped_reparse_point",
        SkippedBySubmitter => "skipped_by_submitter",
        NotHashed => "not_hashed",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRecord {
    pub artifact_id: String,
    /// Always an alias. An absolute path never reaches this struct.
    pub path_alias: String,
    pub artifact_type: ArtifactType,
    pub size_bytes: u64,
    pub sha256: Option<Digest>,
    pub hash_scope: HashScope,
    pub parser: Option<&'static str>,
    pub parser_version: i64,
    pub read_status: ReadStatus,
    pub changed_during_scan: bool,
    /// Filesystem modification time. E1 at best: trivially settable.
    pub mtime: Option<Timestamp>,
}

impl ArtifactRecord {
    pub fn to_canon(&self) -> CanonValue {
        let mut o = Obj::new()
            .with("artifact_id", self.artifact_id.as_str())
            .with("path_alias", self.path_alias.as_str())
            .with("artifact_type", self.artifact_type)
            .with("size_bytes", self.size_bytes)
            .with("hash_scope", self.hash_scope.as_str())
            .with("parser_version", self.parser_version)
            .with("read_status", self.read_status)
            .with("changed_during_scan", self.changed_during_scan);
        if let Some(d) = self.sha256 {
            o.set("sha256", d);
        }
        if let Some(p) = self.parser {
            o.set("parser", p);
        }
        if let HashScope::HeadOnly { bytes } = self.hash_scope {
            o.set("bytes_hashed", bytes);
        }
        if let Some(t) = self.mtime {
            o.set("mtime", t.to_rfc3339());
        }
        CanonValue::Obj(o)
    }
}

// ---------------------------------------------------------------------------
// Facts
// ---------------------------------------------------------------------------

str_enum! {
    /// The vocabulary of normalised observations.
    ///
    /// Adding a kind is a ruleset change: rules match on these.
    FactKind {
        /// What the vendor said, before any artifact was read. Always tier E0.
        DeclaredClaim => "declared_claim",
        DeclaredFacet => "declared_facet",

        AdapterConfig => "adapter_config",
        AdapterTensorSet => "adapter_tensor_set",
        TensorHeader => "tensor_header",
        ModelConfig => "model_config",
        TokenizerIdentity => "tokenizer_identity",
        ShardIndex => "shard_index",
        QuantizationRecord => "quantization_record",
        MergeRecord => "merge_record",

        CheckpointStep => "checkpoint_step",
        TrainingMetric => "training_metric",
        OptimizerRecord => "optimizer_record",
        TrainableParameterRecord => "trainable_parameter_record",
        TrainingObjective => "training_objective",
        DatasetManifest => "dataset_manifest",
        TokenCountRecord => "token_count_record",
        SeedRecord => "seed_record",
        TeacherReference => "teacher_reference",
        TeacherOutputCache => "teacher_output_cache",

        ProviderEndpoint => "provider_endpoint",
        SdkDependency => "sdk_dependency",
        OutboundRequestTrace => "outbound_request_trace",
        RetrievalIndex => "retrieval_index",
        EmbeddingModel => "embedding_model",
        RetrievalTrace => "retrieval_trace",
        PromptTemplate => "prompt_template",

        ServingConfig => "serving_config",
        ContainerManifest => "container_manifest",
        ArtifactReference => "artifact_reference",

        ComputeRecord => "compute_record",
        HardwareRecord => "hardware_record",
        FileChronology => "file_chronology",
        OpaqueArtifact => "opaque_artifact",
        BaseModelReference => "base_model_reference",
    }
}

/// A field value. Numbers that are not integral keep their exact source text,
/// so a learning rate of `5e-5` is never rounded on its way into a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    Int(i64),
    /// Exact source text of a non-integral number.
    Num(String),
    Text(String),
    Bool(bool),
    List(Vec<String>),
}

impl FieldValue {
    pub fn to_canon(&self) -> CanonValue {
        match self {
            FieldValue::Int(i) => CanonValue::Int(*i),
            // A non-integral number becomes a *string* in the authoritative
            // document, keeping its exact text without introducing a float.
            FieldValue::Num(s) => CanonValue::Str(s.clone()),
            FieldValue::Text(s) => CanonValue::Str(s.clone()),
            FieldValue::Bool(b) => CanonValue::Bool(*b),
            FieldValue::List(v) => {
                CanonValue::Arr(v.iter().map(|s| CanonValue::Str(s.clone())).collect())
            }
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            FieldValue::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_text(&self) -> Option<&str> {
        match self {
            FieldValue::Text(s) | FieldValue::Num(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            FieldValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_list(&self) -> Option<&[String]> {
        match self {
            FieldValue::List(v) => Some(v),
            _ => None,
        }
    }
}

impl From<i64> for FieldValue {
    fn from(v: i64) -> Self {
        FieldValue::Int(v)
    }
}
impl From<u64> for FieldValue {
    fn from(v: u64) -> Self {
        FieldValue::Int(v.min(i64::MAX as u64) as i64)
    }
}
impl From<usize> for FieldValue {
    fn from(v: usize) -> Self {
        FieldValue::Int(v as i64)
    }
}
impl From<bool> for FieldValue {
    fn from(v: bool) -> Self {
        FieldValue::Bool(v)
    }
}
impl From<&str> for FieldValue {
    fn from(v: &str) -> Self {
        FieldValue::Text(v.to_string())
    }
}
impl From<String> for FieldValue {
    fn from(v: String) -> Self {
        FieldValue::Text(v)
    }
}
impl From<Vec<String>> for FieldValue {
    fn from(v: Vec<String>) -> Self {
        FieldValue::List(v)
    }
}

/// One normalised observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    pub fact_id: String,
    pub kind: FactKind,
    pub artifact_id: Option<String>,
    /// Sorted on construction so the canonical form does not depend on insertion order.
    pub fields: BTreeMap<String, FieldValue>,
    /// Correlated evidence marker. Facts sharing a group contribute once.
    ///
    /// Defaults to `dir::<alias of the containing directory>`, which is what makes
    /// a README, a config and a generated model card in one folder count as one
    /// source rather than three confirmations.
    pub source_group: String,
}

impl Fact {
    pub fn new(fact_id: impl Into<String>, kind: FactKind, source_group: impl Into<String>) -> Self {
        Fact {
            fact_id: fact_id.into(),
            kind,
            artifact_id: None,
            fields: BTreeMap::new(),
            source_group: source_group.into(),
        }
    }

    #[must_use]
    pub fn with_artifact(mut self, id: impl Into<String>) -> Self {
        self.artifact_id = Some(id.into());
        self
    }

    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_opt(mut self, key: impl Into<String>, value: Option<impl Into<FieldValue>>) -> Self {
        if let Some(v) = value {
            self.fields.insert(key.into(), v.into());
        }
        self
    }

    pub fn field(&self, key: &str) -> Option<&FieldValue> {
        self.fields.get(key)
    }
    pub fn int(&self, key: &str) -> Option<i64> {
        self.fields.get(key).and_then(|v| v.as_int())
    }
    pub fn text(&self, key: &str) -> Option<&str> {
        self.fields.get(key).and_then(|v| v.as_text())
    }
    pub fn boolean(&self, key: &str) -> Option<bool> {
        self.fields.get(key).and_then(|v| v.as_bool())
    }
    pub fn list(&self, key: &str) -> Option<&[String]> {
        self.fields.get(key).and_then(|v| v.as_list())
    }

    pub fn to_canon(&self) -> CanonValue {
        let mut fields = Obj::new();
        for (k, v) in &self.fields {
            fields.set(k.clone(), v.to_canon());
        }
        let mut o = Obj::new()
            .with("fact_id", self.fact_id.as_str())
            .with("kind", self.kind)
            .with("fields", CanonValue::Obj(fields))
            .with("source_group", self.source_group.as_str());
        if let Some(a) = &self.artifact_id {
            o.set("artifact_id", a.as_str());
        }
        CanonValue::Obj(o)
    }
}

/// A place the scanner could not see. Always renders as a limitation of the
/// scanner, never as a property of the vendor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageNote {
    pub rule_id: &'static str,
    pub path_alias: String,
    pub detail: String,
}

impl CoverageNote {
    pub fn to_canon(&self) -> CanonValue {
        CanonValue::Obj(
            Obj::new()
                .with("rule_id", self.rule_id)
                .with("path_alias", self.path_alias.as_str())
                .with("detail", self.detail.as_str()),
        )
    }
}

// ---------------------------------------------------------------------------
// Declared facets
// ---------------------------------------------------------------------------

/// What the vendor says the system is. Recorded verbatim, scored separately.
///
/// `inference_augmentation` is a set because a system may be RAG *and* an external
/// router at once; the other three are single-valued.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeclaredFacets {
    pub weight_origin: Option<tt_core::vocab::WeightOrigin>,
    pub parameter_update: Option<tt_core::vocab::ParameterUpdate>,
    pub training_stage: Option<tt_core::vocab::TrainingStage>,
    pub inference_augmentation: Vec<tt_core::vocab::InferenceAugmentation>,
}

impl DeclaredFacets {
    pub fn to_canon(&self) -> CanonValue {
        let mut o = Obj::new();
        if let Some(v) = self.weight_origin {
            o.set("weight_origin", v);
        }
        if let Some(v) = self.parameter_update {
            o.set("parameter_update", v);
        }
        if let Some(v) = self.training_stage {
            o.set("training_stage", v);
        }
        let mut aug: Vec<&str> = self.inference_augmentation.iter().map(|v| v.as_str()).collect();
        aug.sort_unstable();
        aug.dedup();
        o.set(
            "inference_augmentation",
            CanonValue::Arr(aug.into_iter().map(|s| CanonValue::Str(s.to_string())).collect()),
        );
        CanonValue::Obj(o)
    }

    pub fn declares_weight_training(&self) -> bool {
        use tt_core::vocab::{ParameterUpdate as P, WeightOrigin as W};
        matches!(
            self.weight_origin,
            Some(W::RandomInitializationClaimed) | Some(W::DerivativeOfDisclosedBase) | Some(W::DistilledFromTeacher)
        ) || matches!(
            self.parameter_update,
            Some(P::UnmergedPeftObserved) | Some(P::MergedAdapterConsistent) | Some(P::PartialOrDenseUpdate)
        )
    }
}

// ---------------------------------------------------------------------------
// The fact set
// ---------------------------------------------------------------------------

/// Everything the scanner observed, with no judgement applied.
#[derive(Debug, Clone, Default)]
pub struct FactSet {
    pub artifacts: Vec<ArtifactRecord>,
    pub facts: Vec<Fact>,
    pub coverage: Vec<CoverageNote>,
    pub declared: DeclaredFacets,
    pub exact_claim_text: String,
}

impl FactSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_fact(&mut self, f: Fact) {
        self.facts.push(f);
    }
    pub fn push_artifact(&mut self, a: ArtifactRecord) {
        self.artifacts.push(a);
    }
    pub fn note(&mut self, rule_id: &'static str, path_alias: impl Into<String>, detail: impl Into<String>) {
        self.coverage.push(CoverageNote {
            rule_id,
            path_alias: path_alias.into(),
            detail: detail.into(),
        });
    }

    pub fn by_kind(&self, kind: FactKind) -> impl Iterator<Item = &Fact> {
        self.facts.iter().filter(move |f| f.kind == kind)
    }
    pub fn first(&self, kind: FactKind) -> Option<&Fact> {
        self.facts.iter().find(|f| f.kind == kind)
    }
    pub fn has(&self, kind: FactKind) -> bool {
        self.facts.iter().any(|f| f.kind == kind)
    }
    pub fn count(&self, kind: FactKind) -> usize {
        self.facts.iter().filter(|f| f.kind == kind).count()
    }
    pub fn artifact(&self, id: &str) -> Option<&ArtifactRecord> {
        self.artifacts.iter().find(|a| a.artifact_id == id)
    }
    pub fn artifacts_of(&self, t: ArtifactType) -> impl Iterator<Item = &ArtifactRecord> {
        self.artifacts.iter().filter(move |a| a.artifact_type == t)
    }
    pub fn has_artifact_type(&self, t: ArtifactType) -> bool {
        self.artifacts.iter().any(|a| a.artifact_type == t)
    }

    /// Distinct correlated-evidence groups among facts of a kind. Rules use this
    /// so that ten files in one directory are not ten independent confirmations.
    pub fn source_groups(&self, kind: FactKind) -> Vec<String> {
        let mut g: Vec<String> = self.by_kind(kind).map(|f| f.source_group.clone()).collect();
        g.sort();
        g.dedup();
        g
    }

    /// Total bytes across every artifact whose size is known.
    pub fn total_bytes(&self) -> u64 {
        self.artifacts.iter().map(|a| a.size_bytes).sum()
    }

    /// Sum of parameters across every `tensor_header` fact carrying `parameters`.
    pub fn observed_parameter_count(&self) -> Option<i64> {
        let mut total = 0i64;
        let mut seen = false;
        for f in self.by_kind(FactKind::TensorHeader) {
            if let Some(n) = f.int("parameters") {
                total = total.saturating_add(n);
                seen = true;
            }
        }
        seen.then_some(total)
    }

    pub fn artifact_manifest_canon(&self) -> CanonValue {
        let mut sorted: Vec<&ArtifactRecord> = self.artifacts.iter().collect();
        sorted.sort_by(|a, b| a.artifact_id.cmp(&b.artifact_id));
        CanonValue::Obj(
            Obj::new()
                .with("schema_version", tt_core::SCHEMA_VERSION)
                .with(
                    "artifacts",
                    CanonValue::Arr(sorted.iter().map(|a| a.to_canon()).collect()),
                ),
        )
    }

    pub fn observations_canon(&self) -> CanonValue {
        let mut sorted: Vec<&Fact> = self.facts.iter().collect();
        sorted.sort_by(|a, b| a.fact_id.cmp(&b.fact_id));
        CanonValue::Arr(sorted.iter().map(|f| f.to_canon()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facts_carry_no_verdict_vocabulary() {
        // A compile-time-ish guard expressed as a test: no FactKind name may
        // overlap the conclusion vocabulary.
        for k in FactKind::ALL {
            assert!(
                tt_core::vocab::SupportBand::parse(k.as_str()).is_none(),
                "{k} collides with a support band"
            );
            assert!(
                tt_core::vocab::Claim::parse(k.as_str()).is_none(),
                "{k} collides with a claim"
            );
        }
    }

    #[test]
    fn fact_canon_is_order_independent() {
        let a = Fact::new("F-0001", FactKind::AdapterConfig, "dir::ROOT1")
            .with("r", 16i64)
            .with("peft_type", "LORA");
        let b = Fact::new("F-0001", FactKind::AdapterConfig, "dir::ROOT1")
            .with("peft_type", "LORA")
            .with("r", 16i64);
        assert_eq!(a.to_canon().digest(), b.to_canon().digest());
    }

    #[test]
    fn non_integral_numbers_survive_as_exact_text() {
        let f = Fact::new("F-1", FactKind::TrainingMetric, "g")
            .with("learning_rate", FieldValue::Num("5e-5".into()));
        let c = f.to_canon().to_canonical_string();
        assert!(c.contains("\"5e-5\""), "{c}");
    }

    #[test]
    fn source_groups_dedupe() {
        let mut fs = FactSet::new();
        fs.push_fact(Fact::new("F-1", FactKind::ModelConfig, "dir::ROOT1/a"));
        fs.push_fact(Fact::new("F-2", FactKind::ModelConfig, "dir::ROOT1/a"));
        fs.push_fact(Fact::new("F-3", FactKind::ModelConfig, "dir::ROOT1/b"));
        assert_eq!(fs.source_groups(FactKind::ModelConfig).len(), 2);
        assert_eq!(fs.count(FactKind::ModelConfig), 3);
    }

    #[test]
    fn parameter_count_sums_tensor_headers() {
        let mut fs = FactSet::new();
        assert_eq!(fs.observed_parameter_count(), None);
        fs.push_fact(Fact::new("F-1", FactKind::TensorHeader, "g").with("parameters", 1000i64));
        fs.push_fact(Fact::new("F-2", FactKind::TensorHeader, "g").with("parameters", 2000i64));
        assert_eq!(fs.observed_parameter_count(), Some(3000));
    }

    #[test]
    fn manifest_is_sorted_and_stable() {
        let mk = |id: &str| ArtifactRecord {
            artifact_id: id.into(),
            path_alias: format!("ROOT1/{id}"),
            artifact_type: ArtifactType::SafeTensors,
            size_bytes: 1,
            sha256: Some(Digest::of(b"x")),
            hash_scope: HashScope::Full,
            parser: Some("safetensors_header"),
            parser_version: 1,
            read_status: ReadStatus::Ok,
            changed_during_scan: false,
            mtime: None,
        };
        let mut fs = FactSet::new();
        fs.push_artifact(mk("A-0002"));
        fs.push_artifact(mk("A-0001"));
        let d1 = fs.artifact_manifest_canon().digest();

        let mut fs2 = FactSet::new();
        fs2.push_artifact(mk("A-0001"));
        fs2.push_artifact(mk("A-0002"));
        assert_eq!(d1, fs2.artifact_manifest_canon().digest());
    }

    #[test]
    fn declared_facets_canon_sorts_augmentation() {
        use tt_core::vocab::InferenceAugmentation as I;
        let a = DeclaredFacets {
            inference_augmentation: vec![I::Rag, I::ExternalApiRouter],
            ..Default::default()
        };
        let b = DeclaredFacets {
            inference_augmentation: vec![I::ExternalApiRouter, I::Rag, I::Rag],
            ..Default::default()
        };
        assert_eq!(a.to_canon().digest(), b.to_canon().digest());
    }

    #[test]
    fn declares_weight_training_detects_any_training_facet() {
        use tt_core::vocab::{ParameterUpdate as P, WeightOrigin as W};
        assert!(!DeclaredFacets::default().declares_weight_training());
        assert!(DeclaredFacets {
            weight_origin: Some(W::RandomInitializationClaimed),
            ..Default::default()
        }
        .declares_weight_training());
        assert!(DeclaredFacets {
            parameter_update: Some(P::UnmergedPeftObserved),
            ..Default::default()
        }
        .declares_weight_training());
        assert!(!DeclaredFacets {
            weight_origin: Some(W::Unknown),
            parameter_update: Some(P::NoUpdateObserved),
            ..Default::default()
        }
        .declares_weight_training());
    }
}
