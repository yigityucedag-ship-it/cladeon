//! The scan pipeline: inventory, parse, judge, render, seal.
//!
//! ## Correlated evidence starts here
//!
//! The rules engine refuses to let one source corroborate itself, but it can only do
//! that if somebody tells it what "one source" means. That decision is made in
//! [`source_group`], and it is a judgement, not a mechanism:
//!
//! * A **binary container** is its own group. An adapter's tensor header and the
//!   config beside it are genuinely different kinds of evidence — one is structure
//!   the training tool emitted, the other is text somebody typed — so counting them
//!   separately is right.
//! * Everything **text** in one directory is a single group. A README, a config and
//!   a generated model card in the same folder are one act of authorship, and the
//!   plan is explicit that they must not read as three confirmations.
//!
//! Get this wrong in the permissive direction and a folder of hand-written files
//! reaches "corroborated"; get it wrong in the strict direction and genuine
//! independent evidence is discounted. The split above is the honest reading.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use cl_core::error::{ClError, ClResult};
use cl_core::hash::Digest;
use cl_core::ids::{CaseId, IdAllocator};
use cl_core::limits::Limits;
use cl_core::redact::Redactor;
use cl_core::time::Timestamp;
use cl_facts::{ArtifactRecord, ArtifactType, DeclaredFacets, Fact, FactSet};
use cl_formats::{detect, dispatch, ReadNeed};
use cl_inventory::{Inventory, ScanOptions};

/// Which stage the scan has reached.
///
/// Reported so a waiting person sees movement that corresponds to real work rather
/// than an invented percentage. The plan is explicit about this: progress is based
/// on bytes actually discovered, never on a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Phase {
    #[default]
    Inventory,
    Parsing,
    Judging,
    Sealing,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Phase::Inventory => "Listing and hashing files",
            Phase::Parsing => "Reading file metadata",
            Phase::Judging => "Applying the rules",
            Phase::Sealing => "Writing the evidence bundle",
        }
    }
}

/// A progress observation. Counts only, never a percentage of an unknown total.
#[derive(Debug, Clone, Copy, Default)]
pub struct Progress {
    pub phase: Phase,
    pub files_seen: u64,
    pub bytes_seen: u64,
    pub bytes_hashed: u64,
    /// Files whose metadata has been parsed, during `Phase::Parsing`.
    pub files_parsed: u64,
}

/// Everything a scan needs from the caller.
pub struct ScanRequest {
    pub roots: Vec<PathBuf>,
    pub excluded: Vec<PathBuf>,
    pub case_id: CaseId,
    pub vendor_label: String,
    pub exact_claim_text: String,
    pub declared: DeclaredFacets,
    pub hash_files: bool,
    pub limits: Limits,
    pub challenge_bytes: Option<Vec<u8>>,
}

/// The product of a scan, before it is written anywhere.
pub struct ScanResult {
    pub facts: FactSet,
    pub rules: cl_rules::RuleReport,
    pub report: cl_report::Report,
    pub inventory: Inventory,
    /// Published so the scanner can show the vendor what was removed.
    pub redaction_ledger: Vec<cl_core::redact::RedactionEvent>,
}

/// Which correlated-evidence group an artifact's facts belong to.
pub fn source_group(a: &ArtifactRecord) -> String {
    match a.artifact_type {
        ArtifactType::SafeTensors
        | ArtifactType::Gguf
        | ArtifactType::Onnx
        | ArtifactType::ShardIndex => format!("artifact::{}", a.artifact_id),
        _ => {
            let dir = a.path_alias.rsplit_once('/').map(|(d, _)| d).unwrap_or(&a.path_alias);
            format!("dir::{dir}")
        }
    }
}

/// Read the slice of a file a parser asked for, bounded in every direction.
fn read_for(path: &Path, need: ReadNeed, size: u64, limits: &Limits) -> ClResult<Vec<u8>> {
    let cap = match need {
        ReadNeed::Prefix(n) => n,
        ReadNeed::Suffix(n) => n,
        ReadNeed::Whole => limits.config_bytes,
    };
    let want = cap.min(size).min(limits.config_bytes.max(cap));
    // Refuse to allocate more than the file actually holds, whatever was asked for.
    let want = want.min(size) as usize;
    let mut f = std::fs::File::open(path)?;
    if let ReadNeed::Suffix(n) = need {
        let from = size.saturating_sub(n.min(size));
        f.seek(SeekFrom::Start(from))?;
    }
    let mut buf = vec![0u8; want];
    let mut filled = 0usize;
    while filled < buf.len() {
        match f.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Run a whole scan.
pub fn run(
    req: &ScanRequest,
    cancel: &(dyn Fn() -> bool + Sync),
    progress: &mut dyn FnMut(Progress),
) -> ClResult<ScanResult> {
    let started_at = Timestamp::now();
    let mut redactor = Redactor::new();

    let opts = ScanOptions {
        limits: req.limits,
        hash_files: req.hash_files,
        excluded: req.excluded.clone(),
        head_bytes: detect::CLASSIFY_HEAD_BYTES,
    };

    let inventory = cl_inventory::scan(
        &req.roots,
        &mut redactor,
        &opts,
        &|path, head| detect::classify(path, head),
        cancel,
        &mut |p| {
            progress(Progress {
                phase: Phase::Inventory,
                files_seen: p.files_enumerated,
                bytes_seen: p.bytes_enumerated,
                bytes_hashed: p.bytes_hashed,
                files_parsed: 0,
            });
        },
    )?;

    let mut facts = FactSet::new();
    facts.declared = req.declared.clone();
    facts.exact_claim_text = req.exact_claim_text.clone();
    for a in &inventory.artifacts {
        facts.push_artifact(a.clone());
    }
    for note in &inventory.coverage {
        facts.coverage.push(note.clone());
    }

    // ---- parse ----------------------------------------------------------
    let mut ids = IdAllocator::new();
    let mut parsers: BTreeMap<String, (&'static str, i64)> = BTreeMap::new();

    let mut parsed_count = 0u64;
    for a in &inventory.artifacts {
        if cancel() {
            return Err(ClError::io("cancelled"));
        }
        parsed_count += 1;
        progress(Progress {
            phase: Phase::Parsing,
            files_seen: inventory.files_enumerated,
            bytes_seen: inventory.bytes_enumerated,
            bytes_hashed: inventory.bytes_hashed,
            files_parsed: parsed_count,
        });
        if !detect::is_parseable(a.artifact_type) {
            continue;
        }
        let Some(path) = inventory.real_paths.get(&a.artifact_id) else { continue };

        let need = dispatch::read_need(a.artifact_type, &req.limits);
        let bytes = match read_for(path, need, a.size_bytes, &req.limits) {
            Ok(b) => b,
            Err(e) => {
                facts.note(
                    "CL-INV-002",
                    a.path_alias.clone(),
                    format!("could not be reopened for parsing: {e}"),
                );
                continue;
            }
        };

        // The base name only: dispatch routes several families by name, and it must
        // never see a real path.
        let file_name = a.path_alias.rsplit('/').next().unwrap_or("").to_string();
        let Some(result) =
            dispatch::parse(a.artifact_type, &file_name, &bytes, &req.limits, Some(a.size_bytes))
        else {
            continue;
        };
        let out = match result {
            Ok(o) => o,
            Err(e) => {
                // A malformed vendor file is ordinary. It becomes a coverage note
                // naming the file, and the scan carries on.
                facts.note(
                    if e.is_coverage_limitation() { "CL-FMT-002" } else { "CL-FMT-010" },
                    a.path_alias.clone(),
                    format!("{} could not be parsed: {e}", a.artifact_type),
                );
                continue;
            }
        };

        parsers.insert(a.artifact_id.clone(), (out.parser, out.parser_version));
        let group = source_group(a);
        for note in &out.notes {
            facts.note(note.rule_id, a.path_alias.clone(), note.detail.clone());
        }
        for pending in out.facts {
            let mut f = Fact::new(ids.fact(), pending.kind, group.clone())
                .with_artifact(a.artifact_id.clone());
            for (k, v) in pending.fields {
                // Path-like and URL-like fields are aliased by convention before
                // they can reach the report. A parser that mis-names such a key is
                // the one way a real path could leak, so the convention is applied
                // here rather than trusted upstream.
                let v = match &v {
                    cl_facts::FieldValue::Text(t)
                        if k.ends_with("_path") || k.ends_with("_url") =>
                    {
                        cl_facts::FieldValue::Text(redactor.scrub(t))
                    }
                    cl_facts::FieldValue::Text(t) => {
                        cl_facts::FieldValue::Text(redactor.scrub_field(&k, t))
                    }
                    other => other.clone(),
                };
                f = f.with(k, v);
            }
            facts.push_fact(f);
        }
    }

    // Record which parser read which artifact, now that we know.
    for a in facts.artifacts.iter_mut() {
        if let Some((name, version)) = parsers.get(&a.artifact_id) {
            a.parser = Some(name);
            a.parser_version = *version;
        }
    }

    // ---- judge ----------------------------------------------------------
    progress(Progress {
        phase: Phase::Judging,
        files_seen: inventory.files_enumerated,
        bytes_seen: inventory.bytes_enumerated,
        bytes_hashed: inventory.bytes_hashed,
        files_parsed: parsed_count,
    });
    let rules = cl_rules::evaluate(&facts);
    let finished_at = Timestamp::now();

    let challenge_sha256 = req.challenge_bytes.as_ref().map(|b| Digest::of(b));
    let report = cl_report::build(cl_report::ReportInput {
        case_id: &req.case_id,
        challenge_sha256,
        vendor_label: &req.vendor_label,
        exact_claim_text: &req.exact_claim_text,
        scanner_build_sha256: self_hash(),
        host: cl_report::HostInfo {
            os: os_name(),
            os_build: os_build(),
            arch: std::env::consts::ARCH.to_string(),
            started_at,
            finished_at,
        },
        facts: &facts,
        rules: &rules,
        scope: cl_report::ScopeInfo {
            selected_roots: inventory.root_aliases.clone(),
            excluded_paths: req
                .excluded
                .iter()
                .map(|p| redactor.alias_path_quiet(p))
                .collect(),
            bytes_enumerated: inventory.bytes_enumerated,
            bytes_hashed: inventory.bytes_hashed,
            files_enumerated: inventory.files_enumerated,
            files_hashed: inventory.files_hashed,
            coverage_status: inventory.coverage_status,
        },
        redaction_ledger: redactor.ledger(),
    })?;

    Ok(ScanResult {
        facts,
        rules,
        report,
        inventory,
        redaction_ledger: redactor.ledger(),
    })
}

/// SHA-256 of the running executable, so a report records which build produced it.
///
/// Returns `None` rather than guessing when the executable cannot be read: a wrong
/// build hash is worse than an absent one, because the buyer's challenge may pin the
/// expected value.
fn self_hash() -> Option<Digest> {
    let path = std::env::current_exe().ok()?;
    let h = cl_core::hash::hash_file(&path, u64::MAX, &|| false).ok()?;
    Some(h.digest)
}

fn os_name() -> String {
    std::env::consts::OS.to_string()
}

fn os_build() -> String {
    // Deliberately coarse. A precise build string is host fingerprinting, and the
    // report does not need it.
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};
    use cl_core::hash::HashScope;
    use cl_facts::ReadStatus;

    static SEQ: AtomicU32 = AtomicU32::new(0);

    struct Tree {
        root: PathBuf,
    }
    impl Tree {
        fn new(tag: &str) -> Tree {
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let root = std::env::temp_dir()
                .join(format!("cl-screen-{}-{}-{}", std::process::id(), tag, n));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            Tree { root }
        }
        fn file(&self, rel: &str, bytes: &[u8]) -> PathBuf {
            let p = self.root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, bytes).unwrap();
            p
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// A structurally valid SafeTensors file: 8-byte LE length, JSON header, zeros.
    fn safetensors(tensors: &[(&str, &str, Vec<i64>, u64, u64)]) -> Vec<u8> {
        let mut entries = Vec::new();
        let mut end = 0u64;
        for (name, dtype, shape, begin, e) in tensors {
            let dims = shape.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(",");
            entries.push(format!(
                "\"{name}\":{{\"dtype\":\"{dtype}\",\"shape\":[{dims}],\"data_offsets\":[{begin},{e}]}}"
            ));
            end = end.max(*e);
        }
        let header = format!("{{{}}}", entries.join(","));
        let mut out = (header.len() as u64).to_le_bytes().to_vec();
        out.extend_from_slice(header.as_bytes());
        out.extend(std::iter::repeat(0u8).take(end as usize));
        out
    }

    fn req(root: &Path) -> ScanRequest {
        ScanRequest {
            roots: vec![root.to_path_buf()],
            excluded: Vec::new(),
            case_id: CaseId::parse("CL-2026-0F3A9C").unwrap(),
            vendor_label: "Acme Analytics Ltd".into(),
            exact_claim_text: "We fine-tuned an open base model with LoRA.".into(),
            declared: DeclaredFacets {
                parameter_update: Some(cl_core::vocab::ParameterUpdate::UnmergedPeftObserved),
                ..Default::default()
            },
            hash_files: true,
            limits: Limits::default(),
            challenge_bytes: None,
        }
    }

    fn never() -> impl Fn() -> bool {
        || false
    }

    #[test]
    fn a_lora_tree_scans_end_to_end() {
        let t = Tree::new("lora");
        t.file(
            "adapter/adapter_config.json",
            br#"{"peft_type":"LORA","r":16,"lora_alpha":32,
                 "target_modules":["q_proj","v_proj"],
                 "base_model_name_or_path":"Qwen/Qwen2.5-7B","revision":"a1b2c3d4e5f6"}"#,
        );
        t.file(
            "adapter/adapter_model.safetensors",
            &safetensors(&[
                ("base_model.model.layers.0.self_attn.q_proj.lora_A.weight", "F32", vec![16, 3584], 0, 229376),
                ("base_model.model.layers.0.self_attn.q_proj.lora_B.weight", "F32", vec![3584, 16], 229376, 458752),
            ]),
        );
        t.file("README.md", b"---\nbase_model: Qwen/Qwen2.5-7B\nlibrary_name: peft\n---\n# Model\n");

        let r = run(&req(&t.root), &never(), &mut |_| {}).expect("scan");
        assert!(r.facts.artifacts.len() >= 3, "{:?}", r.facts.artifacts.len());
        assert!(r.facts.has(cl_facts::FactKind::AdapterConfig), "adapter config not parsed");
        assert!(
            r.facts.has(cl_facts::FactKind::AdapterTensorSet),
            "adapter tensors not recognised"
        );
        assert!(r.facts.has(cl_facts::FactKind::BaseModelReference));
        // The report must build, which means it passed the language guard.
        assert!(r.report.value.get("conclusions").is_some());
    }

    #[test]
    fn a_binary_container_is_its_own_source_but_text_shares_a_directory() {
        let mk = |id: &str, alias: &str, t: ArtifactType| ArtifactRecord {
            artifact_id: id.into(),
            path_alias: alias.into(),
            artifact_type: t,
            size_bytes: 1,
            sha256: None,
            hash_scope: HashScope::None,
            parser: None,
            parser_version: 0,
            read_status: ReadStatus::Ok,
            changed_during_scan: false,
            mtime: None,
        };
        let tensors = mk("A-0001", "ROOT1/adapter/adapter_model.safetensors", ArtifactType::SafeTensors);
        let cfg = mk("A-0002", "ROOT1/adapter/adapter_config.json", ArtifactType::PeftAdapterConfig);
        let card = mk("A-0003", "ROOT1/adapter/README.md", ArtifactType::ModelCard);

        assert_eq!(source_group(&tensors), "artifact::A-0001");
        assert_eq!(source_group(&cfg), "dir::ROOT1/adapter");
        assert_eq!(
            source_group(&cfg),
            source_group(&card),
            "text records in one directory are one source, not two confirmations"
        );
        assert_ne!(
            source_group(&tensors),
            source_group(&cfg),
            "structure and the text describing it are different evidence"
        );
    }

    #[test]
    fn a_tree_of_only_text_cannot_reach_a_method_label() {
        // The behaviour the whole caps design exists for: a folder of hand-written
        // configs, however tidy, names no method.
        let t = Tree::new("text-only");
        t.file(
            "adapter_config.json",
            br#"{"peft_type":"LORA","r":16,"target_modules":["q_proj"],
                 "base_model_name_or_path":"Qwen/Qwen2.5-7B","revision":"a1b2c3d4e5f6"}"#,
        );
        t.file("config.json", br#"{"model_type":"qwen2","hidden_size":3584}"#);
        t.file("README.md", b"---\nbase_model: Qwen/Qwen2.5-7B\n---\n");
        t.file("tokenizer_config.json", br#"{"tokenizer_class":"Qwen2Tokenizer"}"#);

        let r = run(&req(&t.root), &never(), &mut |_| {}).expect("scan");
        let c = r.rules.conclusion(cl_core::vocab::Facet::ParameterUpdate).unwrap();
        assert!(
            !c.method_label_emitted,
            "configuration text alone named a method at {} tenths",
            c.score_tenths
        );
    }

    #[test]
    fn an_opaque_checkpoint_is_counted_but_never_opened() {
        let t = Tree::new("opaque");
        // A real pickle opcode stream. If anything tried to interpret it, that would
        // be the defect; the scanner must only hash it.
        t.file("pytorch_model.bin", b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00}\x94.");
        let r = run(&req(&t.root), &never(), &mut |_| {}).expect("scan");
        let a = r
            .facts
            .artifacts
            .iter()
            .find(|a| a.path_alias.ends_with("pytorch_model.bin"))
            .expect("recorded");
        assert_eq!(a.artifact_type, ArtifactType::OpaqueSerialization);
        assert!(a.sha256.is_some(), "it must still be hashed");
        assert!(a.parser.is_none(), "no parser may have touched it");
    }

    #[test]
    fn scanning_twice_gives_the_same_evidence_digest() {
        let t = Tree::new("repeat");
        t.file("adapter/adapter_config.json", br#"{"peft_type":"LORA","r":8}"#);
        t.file("config.json", br#"{"model_type":"llama"}"#);
        let a = run(&req(&t.root), &never(), &mut |_| {}).unwrap();
        let b = run(&req(&t.root), &never(), &mut |_| {}).unwrap();
        assert_eq!(
            a.report.evidence_digest, b.report.evidence_digest,
            "unchanged evidence must produce the same digest"
        );
    }

    #[test]
    fn an_empty_directory_produces_a_report_that_says_so() {
        let t = Tree::new("empty");
        let r = run(&req(&t.root), &never(), &mut |_| {}).expect("scan");
        for f in cl_core::vocab::Facet::ALL {
            let c = r.rules.conclusion(*f).unwrap();
            assert!(
                !c.method_label_emitted,
                "an empty scan named a method on {f}"
            );
        }
    }

    #[test]
    fn a_secret_in_a_config_does_not_reach_the_report() {
        let t = Tree::new("secret");
        t.file(
            "serving.json",
            br#"{"api_key":"sk-abcdefghijklmnopqrstuvwxyz0123","endpoint_url":"https://api.example.com"}"#,
        );
        let r = run(&req(&t.root), &never(), &mut |_| {}).expect("scan");
        let json = r.report.to_canonical_bytes();
        let text = String::from_utf8_lossy(&json);
        assert!(
            !text.contains("sk-abcdefghijklmnopqrstuvwxyz0123"),
            "an API key reached the report"
        );
    }

    #[test]
    fn cancellation_stops_the_scan_rather_than_returning_a_partial_one() {
        let t = Tree::new("cancel");
        t.file("config.json", br#"{"model_type":"llama"}"#);
        match run(&req(&t.root), &|| true, &mut |_| {}) {
            Err(e) => assert!(matches!(e, ClError::Io { .. }), "{e:?}"),
            Ok(_) => panic!("a cancelled scan must not return a result"),
        }
    }
}
