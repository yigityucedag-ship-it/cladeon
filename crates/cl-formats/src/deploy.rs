//! Deployment and serving configuration.
//!
//! This module reads the files that say *what actually runs*: Dockerfiles, compose
//! and Kubernetes manifests, systemd units, `.env` files and serving command lines.
//! It is the only source of the binding anchor, so it is also the module with the
//! most direct route from a vendor's file to a number in the report.
//!
//! ## Two rules it never breaks
//!
//! **A credential value never leaves this module.** A `.env` yields the *names* of
//! the variables that were set and nothing else. Knowing that `OPENAI_API_KEY` is
//! configured is exactly the evidence the report wants; the key itself is not
//! evidence of anything and would be a leak. This is enforced here rather than left
//! to the scanner's scrubber, because a defence that only works when a second
//! component remembers to run is not a defence.
//!
//! **Path and URL fields are named by convention.** Any field whose value is a
//! filesystem path has a key ending in `_path`, and any URL ends in `_url`. The
//! scanner aliases and scrubs on exactly that suffix, so a mis-named key here is a
//! privacy bug, not a cosmetic one.

use crate::{ParseOutput, PendingFact};
use cl_core::error::ClResult;
use cl_core::json::JsonValue;
use cl_core::limits::Limits;
use cl_facts::{ArtifactType, FactKind};

pub const PARSER: &str = "deployment_manifest";
pub const PARSER_VERSION: i64 = 1;

const MAX_ITEMS: usize = 512;

/// Hosts that are somebody else's inference service.
const PROVIDER_HOSTS: &[(&str, &str)] = &[
    ("api.openai.com", "openai"),
    ("api.anthropic.com", "anthropic"),
    ("api.cohere.ai", "cohere"),
    ("api.cohere.com", "cohere"),
    ("api.mistral.ai", "mistral"),
    ("api.together.xyz", "together"),
    ("api.groq.com", "groq"),
    ("api.replicate.com", "replicate"),
    ("generativelanguage.googleapis.com", "google"),
    ("openrouter.ai", "openrouter"),
    ("api.deepseek.com", "deepseek"),
    ("api.x.ai", "xai"),
    ("bedrock-runtime", "aws_bedrock"),
    ("openai.azure.com", "azure_openai"),
];

/// Environment variable names that hold a credential.
fn is_credential_name(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH"]
        .iter()
        .any(|needle| n.contains(needle))
}

/// Strip a query string and any embedded credentials from a URL.
///
/// `https://user:pass@host/path?api_key=...` becomes `https://host/path`. A URL is
/// evidence of *where* a request goes; the rest is a leak waiting to happen.
pub fn clean_url(raw: &str) -> Option<String> {
    let raw = raw.trim().trim_matches(['"', '\'', ',', ';']);
    let (scheme, rest) = raw.split_once("://")?;
    if !matches!(scheme, "http" | "https" | "ws" | "wss") {
        return None;
    }
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    // Drop any userinfo before the host.
    let rest = rest.rsplit('@').next().unwrap_or(rest);
    if rest.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{rest}"))
}

pub fn host_of(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let host = rest.split(['/', ':']).next()?;
    (!host.is_empty()).then(|| host.to_string())
}

fn provider_for(url: &str) -> Option<&'static str> {
    let h = host_of(url)?.to_ascii_lowercase();
    PROVIDER_HOSTS.iter().find(|(needle, _)| h.contains(needle)).map(|(_, p)| *p)
}

fn endpoint_fact(url: &str) -> Option<PendingFact> {
    let cleaned = clean_url(url)?;
    let host = host_of(&cleaned)?;
    // A localhost endpoint is the vendor's own server, not an external provider,
    // and calling it "external" would be wrong in the direction that matters.
    let local = host.starts_with("127.")
        || host == "localhost"
        || host == "0.0.0.0"
        || host.starts_with("192.168.")
        || host.starts_with("10.")
        || host == "host.docker.internal";
    Some(
        PendingFact::new(FactKind::ProviderEndpoint)
            .with("endpoint_url", cleaned.clone())
            .with("host", host)
            .with("is_loopback_or_private", local)
            .with_opt("provider", provider_for(&cleaned).map(|p| p.to_string())),
    )
}

/// Serving engines whose command lines we understand.
const ENGINES: &[&str] = &[
    "vllm",
    "text-generation-launcher",
    "llama-server",
    "llama-cpp-server",
    "ollama",
    "sglang",
    "tgi",
    "mlc_llm",
];

/// Parse a serving command line into a `ServingConfig` fact.
pub fn serving_from_command(cmd: &str) -> Option<PendingFact> {
    let lower = cmd.to_ascii_lowercase();
    let engine = ENGINES.iter().find(|e| lower.contains(*e))?;
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let mut f = PendingFact::new(FactKind::ServingConfig).with("engine", *engine);

    // The model is often positional rather than flagged: `vllm serve /models/qwen`
    // and `ollama run qwen2.5` are the ordinary spellings, and a parser that only
    // understood `--model` would find no model in the most common command of all.
    let subcommands = ["serve", "run", "start"];
    if let Some(idx) = tokens.iter().position(|t| subcommands.contains(&t.to_ascii_lowercase().as_str()))
    {
        if let Some(next) = tokens.get(idx + 1) {
            if !next.starts_with('-') {
                f = f.with("model_path", *next);
            }
        }
    }

    let mut i = 0usize;
    let mut enable_lora = false;
    while i < tokens.len() {
        let t = tokens[i];
        // Accept both `--flag value` and `--flag=value`.
        let (flag, inline) = match t.split_once('=') {
            Some((f, v)) => (f, Some(v)),
            None => (t, None),
        };
        let take = |i: &mut usize| -> Option<String> {
            if let Some(v) = inline {
                return Some(v.to_string());
            }
            let v = tokens.get(*i + 1)?;
            if v.starts_with("--") {
                return None;
            }
            *i += 1;
            Some(v.to_string())
        };
        match flag {
            "--model" | "-m" | "--model-path" => {
                if let Some(v) = take(&mut i) {
                    f = f.with("model_path", v);
                }
            }
            "--served-model-name" => {
                if let Some(v) = take(&mut i) {
                    f = f.with("served_model_name", v);
                }
            }
            "--lora-modules" | "--lora" => {
                enable_lora = true;
                if let Some(v) = take(&mut i) {
                    f = f.with("lora_modules", v);
                }
            }
            "--enable-lora" => enable_lora = true,
            "--quantization" | "--quantize" => {
                if let Some(v) = take(&mut i) {
                    f = f.with("quantization", v);
                }
            }
            "--port" => {
                if let Some(v) = take(&mut i) {
                    if let Ok(p) = v.parse::<i64>() {
                        f = f.with("port", p);
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    Some(f.with("enable_lora", enable_lora))
}

/// Every model path a serving config names becomes an artifact reference.
///
/// `in_scope` is left `false` here on purpose: whether the path lies inside the
/// scanned roots is the scanner's question, not the parser's, and answering it here
/// would need the real filesystem the parser deliberately does not have.
fn artifact_reference(path: &str) -> PendingFact {
    PendingFact::new(FactKind::ArtifactReference)
        .with("target_path", path)
        .with("in_scope", false)
}

// ---------------------------------------------------------------------------
// Dockerfile
// ---------------------------------------------------------------------------

pub fn parse_dockerfile(bytes: &[u8], limits: &Limits) -> ClResult<ParseOutput> {
    let mut out = ParseOutput::new(ArtifactType::DeploymentManifest, PARSER, PARSER_VERSION);
    let text = bounded(bytes, limits, &mut out);
    for line in text.lines().take(MAX_ITEMS) {
        let l = line.trim();
        let upper = l.to_ascii_uppercase();
        if let Some(rest) = upper.strip_prefix("FROM ") {
            let image = l[l.len() - rest.len()..].split_whitespace().next().unwrap_or("").to_string();
            if !image.is_empty() {
                let digest = image.split_once("@sha256:").map(|(_, d)| d.to_string());
                out.push(
                    PendingFact::new(FactKind::ContainerManifest)
                        .with("image", image)
                        .with_opt("image_digest", digest),
                );
            }
        }
        if upper.starts_with("CMD ") || upper.starts_with("ENTRYPOINT ") {
            if let Some(s) = serving_from_command(l) {
                out.push(s);
            }
        }
        if let Some(rest) = upper.strip_prefix("ENV ") {
            let raw = &l[l.len() - rest.len()..];
            if let Some((name, value)) = raw.split_once('=').or_else(|| raw.split_once(' ')) {
                env_fact(name.trim(), value.trim(), &mut out);
            }
        }
    }
    collect_paths(&mut out);
    Ok(out)
}

// ---------------------------------------------------------------------------
// .env
// ---------------------------------------------------------------------------

/// Record that a variable was set. Never its value, when the name says credential.
fn env_fact(name: &str, value: &str, out: &mut ParseOutput) {
    if name.is_empty() {
        return;
    }
    if is_credential_name(name) {
        out.push(
            PendingFact::new(FactKind::ServingConfig)
                .with("env_var_set", name)
                .with("value_withheld", true)
                .with("reason", "the variable name indicates a credential"),
        );
        return;
    }
    let v = value.trim().trim_matches(['"', '\'']);
    if let Some(f) = endpoint_fact(v) {
        out.push(f.with("declared_in", name));
        return;
    }
    // A non-credential, non-URL variable is recorded with its value: it may name a
    // model or a mode, which is evidence.
    out.push(
        PendingFact::new(FactKind::ServingConfig)
            .with("env_var_set", name)
            .with("value", v)
            .with("value_withheld", false),
    );
}

pub fn parse_env_file(bytes: &[u8], limits: &Limits) -> ClResult<ParseOutput> {
    let mut out = ParseOutput::new(ArtifactType::ServingConfig, PARSER, PARSER_VERSION);
    let text = bounded(bytes, limits, &mut out);
    for line in text.lines().take(MAX_ITEMS) {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let l = l.strip_prefix("export ").unwrap_or(l);
        if let Some((name, value)) = l.split_once('=') {
            env_fact(name.trim(), value, &mut out);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// YAML: compose, Kubernetes, systemd-ish
// ---------------------------------------------------------------------------

pub fn parse_yaml_manifest(bytes: &[u8], limits: &Limits) -> ClResult<ParseOutput> {
    let mut out = ParseOutput::new(ArtifactType::DeploymentManifest, PARSER, PARSER_VERSION);
    let v = match crate::yamlish::parse(bytes, limits) {
        Ok(v) => v,
        Err(e) => {
            out.note("CL-FMT-010", format!("the manifest was not read: {e}"));
            return Ok(out);
        }
    };
    walk_yaml(&v, &mut out, 0);
    collect_paths(&mut out);
    Ok(out)
}

/// Walk any YAML manifest looking for the handful of keys that matter.
///
/// Shape-agnostic on purpose: compose, Kubernetes, Helm values and a dozen
/// in-house formats all express "here is an image and here is a command", and
/// enumerating each schema would mean silently ignoring the ones we forgot.
fn walk_yaml(v: &JsonValue, out: &mut ParseOutput, depth: usize) {
    if depth > 32 || out.facts.len() > MAX_ITEMS {
        return;
    }
    match v {
        JsonValue::Obj(entries) => {
            for (k, val) in entries {
                match (k.as_str(), val) {
                    ("image", JsonValue::Str(s)) => {
                        let digest = s.split_once("@sha256:").map(|(_, d)| d.to_string());
                        out.push(
                            PendingFact::new(FactKind::ContainerManifest)
                                .with("image", s.as_str())
                                .with_opt("image_digest", digest),
                        );
                    }
                    ("command" | "args" | "entrypoint" | "ExecStart", _) => {
                        let joined = flatten_command(val);
                        if let Some(f) = serving_from_command(&joined) {
                            out.push(f);
                        }
                    }
                    ("environment" | "env", _) => walk_env(val, out),
                    (key, JsonValue::Str(s))
                        if key.ends_with("url") || key.ends_with("endpoint") || key == "base_url" =>
                    {
                        if let Some(f) = endpoint_fact(s) {
                            out.push(f.with("declared_in", key));
                        }
                    }
                    _ => walk_yaml(val, out, depth + 1),
                }
            }
        }
        JsonValue::Arr(items) => {
            for i in items {
                walk_yaml(i, out, depth + 1);
            }
        }
        _ => {}
    }
}

fn walk_env(v: &JsonValue, out: &mut ParseOutput) {
    match v {
        // compose style: a mapping of NAME: value
        JsonValue::Obj(entries) => {
            for (k, val) in entries {
                let text = match val {
                    JsonValue::Str(s) => s.clone(),
                    JsonValue::Int(i) => i.to_string(),
                    _ => String::new(),
                };
                env_fact(k, &text, out);
            }
        }
        // compose list style: ["NAME=value"], or k8s [{name, value}]
        JsonValue::Arr(items) => {
            for i in items {
                match i {
                    JsonValue::Str(s) => {
                        if let Some((n, v)) = s.split_once('=') {
                            env_fact(n, v, out);
                        }
                    }
                    JsonValue::Obj(_) => {
                        let name = i.get("name").and_then(|x| x.as_str()).unwrap_or("");
                        let value = i.get("value").and_then(|x| x.as_str()).unwrap_or("");
                        env_fact(name, value, out);
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

fn flatten_command(v: &JsonValue) -> String {
    match v {
        JsonValue::Str(s) => s.clone(),
        JsonValue::Arr(items) => items
            .iter()
            .filter_map(|i| match i {
                JsonValue::Str(s) => Some(s.clone()),
                JsonValue::Int(n) => Some(n.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    }
}

/// Promote each model path named by a serving config into an artifact reference,
/// which is what the binding rules look for.
fn collect_paths(out: &mut ParseOutput) {
    let paths: Vec<String> = out
        .facts_of(FactKind::ServingConfig)
        .filter_map(|f| match f.get("model_path") {
            Some(cl_facts::FieldValue::Text(t)) => Some(t.clone()),
            _ => None,
        })
        .collect();
    for p in paths {
        out.push(artifact_reference(&p));
    }
}

fn bounded(bytes: &[u8], limits: &Limits, out: &mut ParseOutput) -> String {
    let cap = limits.config_bytes as usize;
    if bytes.len() > cap {
        out.note("CL-FMT-010", format!("read the first {cap} of {} bytes", bytes.len()));
        String::from_utf8_lossy(&bytes[..cap]).into_owned()
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

/// Route a deployment file by name.
pub fn parse_by_name(name: &str, bytes: &[u8], limits: &Limits) -> Option<ClResult<ParseOutput>> {
    let n = name.to_ascii_lowercase();
    Some(match n.as_str() {
        "dockerfile" | "containerfile" => parse_dockerfile(bytes, limits),
        _ if n.starts_with(".env") => parse_env_file(bytes, limits),
        _ if n.ends_with(".yml") || n.ends_with(".yaml") => parse_yaml_manifest(bytes, limits),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl_facts::FieldValue;

    fn lim() -> Limits {
        Limits::default()
    }

    fn field<'a>(out: &'a ParseOutput, k: FactKind, key: &str) -> Option<&'a FieldValue> {
        out.facts_of(k).find_map(|f| f.get(key))
    }

    fn all_text(out: &ParseOutput) -> String {
        let mut s = String::new();
        for f in &out.facts {
            for (k, v) in &f.fields {
                s.push_str(k);
                if let FieldValue::Text(t) = v {
                    s.push_str(t);
                }
                s.push('\n');
            }
        }
        s
    }

    // -- the privacy rule --------------------------------------------------

    #[test]
    fn an_api_key_never_leaves_this_module() {
        let env = b"OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123\n\
                    HF_TOKEN=hf_abcdefghijklmnopqrstuvwxyz012345\n\
                    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG\n\
                    MODEL_NAME=qwen2.5-7b\n";
        let out = parse_env_file(env, &lim()).unwrap();
        let text = all_text(&out);
        for leak in ["sk-abcdefghij", "hf_abcdefghij", "wJalrXUtnFEMI"] {
            assert!(!text.contains(leak), "leaked `{leak}` in:\n{text}");
        }
        // The names are still reported: knowing the variable was set IS the evidence.
        assert!(text.contains("OPENAI_API_KEY"), "{text}");
        assert!(text.contains("HF_TOKEN"));
        // A non-credential value survives, because it is evidence.
        assert!(text.contains("qwen2.5-7b"), "{text}");
    }

    #[test]
    fn credential_name_detection_is_broad_but_not_absurd() {
        assert!(is_credential_name("OPENAI_API_KEY"));
        assert!(is_credential_name("hf_token"));
        assert!(is_credential_name("DB_PASSWORD"));
        assert!(is_credential_name("Authorization"));
        assert!(!is_credential_name("MODEL_NAME"));
        assert!(!is_credential_name("PORT"));
    }

    #[test]
    fn a_url_is_stripped_of_credentials_and_query() {
        assert_eq!(
            clean_url("https://user:pass@api.openai.com/v1?api_key=secret"),
            Some("https://api.openai.com/v1".into())
        );
        assert_eq!(clean_url("http://localhost:8000/v1"), Some("http://localhost:8000/v1".into()));
        assert_eq!(clean_url("file:///etc/passwd"), None, "only network schemes");
        assert_eq!(clean_url("not a url"), None);
    }

    #[test]
    fn a_url_in_an_env_file_does_not_carry_its_query_string() {
        let out = parse_env_file(b"OPENAI_BASE_URL=https://api.openai.com/v1?key=sk-secret\n", &lim())
            .unwrap();
        let text = all_text(&out);
        assert!(!text.contains("sk-secret"), "{text}");
        assert!(text.contains("api.openai.com"));
    }

    // -- endpoints ---------------------------------------------------------

    #[test]
    fn a_provider_host_is_named_and_a_local_one_is_marked_local() {
        let f = endpoint_fact("https://api.anthropic.com/v1/messages").unwrap();
        assert_eq!(f.get("provider"), Some(&FieldValue::Text("anthropic".into())));
        assert_eq!(f.get("is_loopback_or_private"), Some(&FieldValue::Bool(false)));

        let l = endpoint_fact("http://127.0.0.1:8000/v1").unwrap();
        assert_eq!(l.get("is_loopback_or_private"), Some(&FieldValue::Bool(true)));
        assert!(l.get("provider").is_none(), "a loopback address has no provider");
    }

    // -- serving command lines ---------------------------------------------

    #[test]
    fn a_vllm_command_line_is_understood() {
        let f = serving_from_command(
            "vllm serve /models/qwen --served-model-name qwen2.5 --enable-lora \
             --lora-modules adapter=/models/adapter --quantization awq --port 8000",
        )
        .unwrap();
        assert_eq!(f.get("engine"), Some(&FieldValue::Text("vllm".into())));
        assert_eq!(f.get("enable_lora"), Some(&FieldValue::Bool(true)));
        assert_eq!(f.get("quantization"), Some(&FieldValue::Text("awq".into())));
        assert_eq!(f.get("port"), Some(&FieldValue::Int(8000)));
    }

    #[test]
    fn equals_and_space_flag_forms_are_both_accepted() {
        let a = serving_from_command("vllm --model=/models/x --port=9000").unwrap();
        let b = serving_from_command("vllm --model /models/x --port 9000").unwrap();
        assert_eq!(a.get("model_path"), b.get("model_path"));
        assert_eq!(a.get("port"), b.get("port"));
    }

    #[test]
    fn a_flag_with_no_value_does_not_swallow_the_next_flag() {
        let f = serving_from_command("vllm --model --port 8000").unwrap();
        assert!(f.get("model_path").is_none(), "an empty --model must stay empty");
        assert_eq!(f.get("port"), Some(&FieldValue::Int(8000)));
    }

    #[test]
    fn a_command_for_no_known_engine_yields_nothing() {
        assert!(serving_from_command("python train.py --model foo").is_none());
    }

    #[test]
    fn a_positional_model_argument_is_found() {
        // `vllm serve <model>` and `ollama run <model>` are the ordinary spellings;
        // only understanding --model would miss the most common command of all.
        let a = serving_from_command("vllm serve /models/qwen --port 8000").unwrap();
        assert_eq!(a.get("model_path"), Some(&FieldValue::Text("/models/qwen".into())));
        let b = serving_from_command("ollama run qwen2.5:7b").unwrap();
        assert_eq!(b.get("model_path"), Some(&FieldValue::Text("qwen2.5:7b".into())));
        // A subcommand followed by a flag has no positional model.
        let c = serving_from_command("vllm serve --model /models/x").unwrap();
        assert_eq!(c.get("model_path"), Some(&FieldValue::Text("/models/x".into())));
    }

    // -- manifests ---------------------------------------------------------

    #[test]
    fn a_dockerfile_yields_images_and_a_pinned_digest() {
        let src = b"FROM vllm/vllm-openai@sha256:abc123 AS base\n\
                    ENV OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz01\n\
                    CMD vllm serve /models/qwen --port 8000\n";
        let out = parse_dockerfile(src, &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::ContainerManifest, "image_digest"),
            Some(&FieldValue::Text("abc123".into()))
        );
        assert_eq!(field(&out, FactKind::ServingConfig, "engine"), Some(&FieldValue::Text("vllm".into())));
        assert!(!all_text(&out).contains("sk-abcdefghij"), "the key leaked from ENV");
    }

    #[test]
    fn a_compose_file_yields_an_image_and_a_model_reference() {
        let src = b"services:\n  api:\n    image: vllm/vllm-openai:latest\n    command: vllm serve /models/qwen --port 8000\n    environment:\n      OPENAI_API_KEY: sk-abcdefghijklmnopqrstuvwxyz01\n";
        let out = parse_yaml_manifest(src, &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::ContainerManifest, "image"),
            Some(&FieldValue::Text("vllm/vllm-openai:latest".into()))
        );
        assert_eq!(
            field(&out, FactKind::ArtifactReference, "target_path"),
            Some(&FieldValue::Text("/models/qwen".into()))
        );
        assert!(!all_text(&out).contains("sk-abcdefghij"));
    }

    #[test]
    fn an_artifact_reference_leaves_scope_resolution_to_the_scanner() {
        let out = parse_dockerfile(b"CMD vllm serve /models/x\n", &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::ArtifactReference, "in_scope"),
            Some(&FieldValue::Bool(false)),
            "the parser has no filesystem and must not claim to know"
        );
    }

    #[test]
    fn path_and_url_fields_follow_the_naming_convention() {
        // The scanner scrubs on these suffixes, so a mis-named key is a leak.
        let out = parse_dockerfile(b"CMD vllm serve /models/x\n", &lim()).unwrap();
        for f in &out.facts {
            for (k, v) in &f.fields {
                if let FieldValue::Text(t) = v {
                    if t.starts_with('/') || t.contains(":\\") {
                        assert!(
                            k.ends_with("_path"),
                            "field `{k}` holds a path `{t}` but does not end in _path"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn malformed_and_empty_input_never_panics() {
        for src in [&b""[..], &b"FROM"[..], &b"\xff\xfe"[..], &b"= = ="[..], &b"["[..]] {
            let _ = parse_dockerfile(src, &lim());
            let _ = parse_env_file(src, &lim());
            let _ = parse_yaml_manifest(src, &lim());
        }
    }

    #[test]
    fn routing_covers_the_known_names() {
        assert!(parse_by_name("Dockerfile", b"", &lim()).is_some());
        assert!(parse_by_name(".env", b"", &lim()).is_some());
        assert!(parse_by_name("docker-compose.yml", b"", &lim()).is_some());
        assert!(parse_by_name("config.json", b"{}", &lim()).is_none());
    }
}
