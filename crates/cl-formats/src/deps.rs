//! Dependency manifests and lockfiles.
//!
//! What a project depends on is weak evidence, and the module is built to keep it
//! weak. A `requirements.txt` naming `openai` says the code *could* call a provider;
//! it does not say it does, and rule `CL-API-002` scores it accordingly (60 on the
//! `config` anchor, tier E1) while an actual observed request scores 100.
//!
//! ## Every package is emitted, not only the recognised ones
//!
//! The category table below is a convenience, not a filter. A package nobody
//! recognised is still recorded with `category = "other"`, because a report must be
//! able to say what was there rather than only what we had a label for — and because
//! the alternative is a scanner whose blind spots are invisible to its reader.

use crate::{ParseOutput, PendingFact};
use cl_core::error::ClResult;
use cl_core::json::JsonValue;
use cl_core::limits::Limits;
use cl_facts::{ArtifactType, FactKind};

pub const PARSER: &str = "dependency_manifest";
pub const PARSER_VERSION: i64 = 1;

/// Cap on packages recorded from one file. A lockfile with a hundred thousand
/// entries must not be able to make the report unbounded.
const MAX_PACKAGES: usize = 4096;

/// Packages whose presence says something about how a system is built.
///
/// Names are matched after normalising `_` to `-` and lowercasing, because
/// `google_generativeai` and `google-generativeai` are the same package.
const CATEGORIES: &[(&str, &str)] = &[
    // Provider SDKs: the system may call somebody else's model.
    ("openai", "provider_sdk"),
    ("anthropic", "provider_sdk"),
    ("cohere", "provider_sdk"),
    ("mistralai", "provider_sdk"),
    ("together", "provider_sdk"),
    ("replicate", "provider_sdk"),
    ("groq", "provider_sdk"),
    ("google-generativeai", "provider_sdk"),
    ("google-genai", "provider_sdk"),
    ("boto3", "provider_sdk"),
    ("botocore", "provider_sdk"),
    ("azure-ai-inference", "provider_sdk"),
    ("azure-identity", "provider_sdk"),
    ("litellm", "provider_sdk"),
    ("openrouter", "provider_sdk"),
    // Training stacks.
    ("transformers", "training"),
    ("peft", "training"),
    ("trl", "training"),
    ("accelerate", "training"),
    ("deepspeed", "training"),
    ("bitsandbytes", "training"),
    ("torch", "training"),
    ("datasets", "training"),
    ("tokenizers", "training"),
    ("unsloth", "training"),
    ("axolotl", "training"),
    ("torchtune", "training"),
    // Serving.
    ("vllm", "serving"),
    ("text-generation-inference", "serving"),
    ("llama-cpp-python", "serving"),
    ("ollama", "serving"),
    ("sglang", "serving"),
    ("fastapi", "serving"),
    ("uvicorn", "serving"),
    // Retrieval.
    ("langchain", "rag"),
    ("langchain-community", "rag"),
    ("llama-index", "rag"),
    ("haystack-ai", "rag"),
    ("chromadb", "rag"),
    ("faiss-cpu", "rag"),
    ("faiss-gpu", "rag"),
    ("qdrant-client", "rag"),
    ("weaviate-client", "rag"),
    ("pinecone-client", "rag"),
    ("pgvector", "rag"),
    ("sentence-transformers", "rag"),
    ("rank-bm25", "rag"),
];

fn normalise(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('_', "-")
}

/// The category for a package name, defaulting to `other`.
pub fn category(name: &str) -> &'static str {
    let n = normalise(name);
    CATEGORIES.iter().find(|(k, _)| *k == n).map(|(_, c)| *c).unwrap_or("other")
}

fn package_fact(name: &str, version: Option<&str>, ecosystem: &'static str) -> PendingFact {
    PendingFact::new(FactKind::SdkDependency)
        .with("name", normalise(name))
        .with("ecosystem", ecosystem)
        .with("category", category(name))
        .with_opt("version", version.map(|v| v.trim().to_string()).filter(|v| !v.is_empty()))
}

/// `requirements.txt`, `pip freeze` output, or a conda listing.
pub fn parse_requirements(bytes: &[u8], limits: &Limits) -> ClResult<ParseOutput> {
    let mut out = ParseOutput::new(ArtifactType::DependencyLockfile, PARSER, PARSER_VERSION);
    let text = bounded_text(bytes, limits, &mut out)?;
    let mut count = 0usize;

    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            // `-r other.txt` and `--index-url` are directives, not packages.
            continue;
        }
        if count >= MAX_PACKAGES {
            out.note("CL-FMT-010", format!("more than {MAX_PACKAGES} packages; the rest were not read"));
            break;
        }
        // name[extras]<op>version, or conda's `name version build`.
        let name_end = line
            .find(|c: char| matches!(c, '=' | '>' | '<' | '~' | '!' | '[' | ' ' | ';' | '@'))
            .unwrap_or(line.len());
        let name = &line[..name_end];
        if name.is_empty() {
            continue;
        }
        let rest = line[name_end..].trim_start_matches(['=', '>', '<', '~', '!', ' ']);
        let version = rest.split([' ', ';', ',']).next().filter(|v| !v.is_empty());
        out.push(package_fact(name, version, "python"));
        count += 1;
    }
    Ok(out)
}

/// `package.json` or `package-lock.json`.
pub fn parse_package_json(bytes: &[u8], limits: &Limits) -> ClResult<ParseOutput> {
    let v = cl_core::json::parse(bytes, limits)?;
    let mut out = ParseOutput::new(ArtifactType::DependencyLockfile, PARSER, PARSER_VERSION);
    let mut count = 0usize;
    for section in ["dependencies", "devDependencies", "packages"] {
        let Some(obj) = v.get(section).and_then(|d| d.as_obj()) else { continue };
        for (name, spec) in obj {
            if count >= MAX_PACKAGES {
                out.note("CL-FMT-010", "package list truncated at the configured cap");
                return Ok(out);
            }
            // `packages` in a lockfile keys on paths like "node_modules/x".
            let clean = name.rsplit("node_modules/").next().unwrap_or(name);
            if clean.is_empty() {
                continue;
            }
            let version = match spec {
                JsonValue::Str(s) => Some(s.clone()),
                JsonValue::Obj(_) => spec.get("version").and_then(|x| x.as_str()).map(String::from),
                _ => None,
            };
            out.push(package_fact(clean, version.as_deref(), "npm"));
            count += 1;
        }
    }
    Ok(out)
}

/// `Cargo.lock`, `pyproject.toml`, or another TOML manifest.
pub fn parse_toml_manifest(bytes: &[u8], limits: &Limits) -> ClResult<ParseOutput> {
    let v = crate::tomlish::parse(bytes, limits)?;
    let mut out = ParseOutput::new(ArtifactType::DependencyLockfile, PARSER, PARSER_VERSION);
    let mut count = 0usize;

    // Cargo.lock: an array of [[package]] tables.
    if let Some(pkgs) = v.get("package").and_then(|p| p.as_arr()) {
        for p in pkgs.iter().take(MAX_PACKAGES) {
            if let Some(name) = p.get("name").and_then(|n| n.as_str()) {
                let version = p.get("version").and_then(|x| x.as_str());
                out.push(package_fact(name, version, "cargo"));
                count += 1;
            }
        }
    }

    // pyproject.toml: project.dependencies is a list of requirement strings.
    if let Some(deps) = v.get("project").and_then(|p| p.get("dependencies")).and_then(|d| d.as_arr())
    {
        for d in deps.iter().take(MAX_PACKAGES.saturating_sub(count)) {
            if let Some(s) = d.as_str() {
                let end = s
                    .find(|c: char| matches!(c, '=' | '>' | '<' | '~' | '!' | '[' | ' ' | ';'))
                    .unwrap_or(s.len());
                if end > 0 {
                    let rest = s[end..].trim_start_matches(['=', '>', '<', '~', '!', ' ']);
                    let version = rest.split([' ', ';', ',']).next().filter(|v| !v.is_empty());
                    out.push(package_fact(&s[..end], version, "python"));
                    count += 1;
                }
            }
        }
    }

    // poetry: [tool.poetry.dependencies] is a table of name = spec.
    if let Some(t) = v
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_obj())
    {
        for (name, spec) in t.iter().take(MAX_PACKAGES.saturating_sub(count)) {
            let version = match spec {
                JsonValue::Str(s) => Some(s.clone()),
                _ => spec.get("version").and_then(|x| x.as_str()).map(String::from),
            };
            out.push(package_fact(name, version.as_deref(), "python"));
        }
    }

    Ok(out)
}

/// Route a dependency file by name.
pub fn parse_by_name(name: &str, bytes: &[u8], limits: &Limits) -> Option<ClResult<ParseOutput>> {
    let n = name.to_ascii_lowercase();
    Some(match n.as_str() {
        "package.json" | "package-lock.json" => parse_package_json(bytes, limits),
        "cargo.lock" | "pyproject.toml" | "poetry.lock" => parse_toml_manifest(bytes, limits),
        _ if n.starts_with("requirements") || n == "pip-freeze.txt" || n == "conda-list.txt" => {
            parse_requirements(bytes, limits)
        }
        _ => return None,
    })
}

fn bounded_text(bytes: &[u8], limits: &Limits, out: &mut ParseOutput) -> ClResult<String> {
    let cap = limits.config_bytes as usize;
    let slice = if bytes.len() > cap {
        out.note(
            "CL-FMT-010",
            format!("read the first {cap} of {} bytes", bytes.len()),
        );
        &bytes[..cap]
    } else {
        bytes
    };
    Ok(String::from_utf8_lossy(slice).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl_facts::FieldValue;

    fn lim() -> Limits {
        Limits::default()
    }

    fn names(out: &ParseOutput) -> Vec<String> {
        out.facts_of(FactKind::SdkDependency)
            .filter_map(|f| match f.get("name") {
                Some(FieldValue::Text(t)) => Some(t.clone()),
                _ => None,
            })
            .collect()
    }

    fn category_of(out: &ParseOutput, name: &str) -> Option<String> {
        out.facts_of(FactKind::SdkDependency)
            .find(|f| matches!(f.get("name"), Some(FieldValue::Text(t)) if t == name))
            .and_then(|f| match f.get("category") {
                Some(FieldValue::Text(c)) => Some(c.clone()),
                _ => None,
            })
    }

    #[test]
    fn a_requirements_file_is_categorised() {
        let src = b"# comment\nopenai==1.30.1\ntransformers>=4.44\nchromadb\n-r dev.txt\n\nsome-internal-lib==2.0\n";
        let out = parse_requirements(src, &lim()).unwrap();
        assert_eq!(category_of(&out, "openai").as_deref(), Some("provider_sdk"));
        assert_eq!(category_of(&out, "transformers").as_deref(), Some("training"));
        assert_eq!(category_of(&out, "chromadb").as_deref(), Some("rag"));
        // The unrecognised one is still there. A report must be able to say what was
        // present, not only what we had a label for.
        assert_eq!(category_of(&out, "some-internal-lib").as_deref(), Some("other"));
        assert!(!names(&out).iter().any(|n| n.starts_with('-')), "directives are not packages");
    }

    #[test]
    fn versions_are_captured_where_given() {
        let out = parse_requirements(b"openai==1.30.1\npeft\n", &lim()).unwrap();
        let openai = out
            .facts_of(FactKind::SdkDependency)
            .find(|f| matches!(f.get("name"), Some(FieldValue::Text(t)) if t == "openai"))
            .unwrap();
        assert_eq!(openai.get("version"), Some(&FieldValue::Text("1.30.1".into())));
        let peft = out
            .facts_of(FactKind::SdkDependency)
            .find(|f| matches!(f.get("name"), Some(FieldValue::Text(t)) if t == "peft"))
            .unwrap();
        assert!(peft.get("version").is_none(), "an unpinned package has no version to record");
    }

    #[test]
    fn underscores_and_case_normalise() {
        // All four spellings are the same package, and a lockfile may use any of
        // them. Matching only the canonical form would make recognition depend on
        // how the vendor happened to type it.
        assert_eq!(category("google-generativeai"), "provider_sdk");
        assert_eq!(category("google_generativeai"), "provider_sdk");
        assert_eq!(category("Google_GenerativeAI"), "provider_sdk");
        assert_eq!(category("OPENAI"), "provider_sdk");
        assert_eq!(category("  peft  "), "training");
        assert_eq!(category("something-nobody-listed"), "other");
    }

    #[test]
    fn extras_and_markers_do_not_become_part_of_the_name() {
        let out =
            parse_requirements(b"uvicorn[standard]==0.30.0\ntorch==2.4.0; sys_platform=='linux'\n", &lim())
                .unwrap();
        let n = names(&out);
        assert!(n.contains(&"uvicorn".to_string()), "{n:?}");
        assert!(n.contains(&"torch".to_string()), "{n:?}");
    }

    #[test]
    fn a_package_json_is_read() {
        let src = br#"{"dependencies":{"openai":"^4.0.0","express":"4.19.2"}}"#;
        let out = parse_package_json(src, &lim()).unwrap();
        assert_eq!(category_of(&out, "openai").as_deref(), Some("provider_sdk"));
        assert_eq!(category_of(&out, "express").as_deref(), Some("other"));
    }

    #[test]
    fn a_lockfile_path_key_is_reduced_to_the_package_name() {
        let src = br#"{"packages":{"node_modules/openai":{"version":"4.1.0"}}}"#;
        let out = parse_package_json(src, &lim()).unwrap();
        assert_eq!(names(&out), vec!["openai".to_string()]);
    }

    #[test]
    fn a_huge_manifest_is_capped_rather_than_unbounded() {
        let mut src = String::new();
        for i in 0..(MAX_PACKAGES + 500) {
            src.push_str(&format!("pkg{i}==1.0\n"));
        }
        let out = parse_requirements(src.as_bytes(), &lim()).unwrap();
        assert!(out.facts.len() <= MAX_PACKAGES);
        assert!(out.has_note("CL-FMT-010"));
    }

    #[test]
    fn empty_and_garbage_input_never_panics() {
        for src in [&b""[..], &b"\n\n\n"[..], &b"#only a comment"[..], &[0xffu8, 0xfe][..]] {
            let _ = parse_requirements(src, &lim());
            let _ = parse_package_json(src, &lim());
        }
    }

    #[test]
    fn routing_covers_the_known_file_names() {
        assert!(parse_by_name("requirements.txt", b"openai\n", &lim()).is_some());
        assert!(parse_by_name("requirements-dev.txt", b"", &lim()).is_some());
        assert!(parse_by_name("package.json", b"{}", &lim()).is_some());
        assert!(parse_by_name("Cargo.lock", b"", &lim()).is_some());
        assert!(parse_by_name("adapter_config.json", b"{}", &lim()).is_none());
    }
}
