//! Retrieval evidence: indexes, embedding models, prompt templates and traces.
//!
//! ## One boolean carries most of the weight
//!
//! `TT-RAG-001` scores a *request-level retrieval chain* at 100 and anything weaker
//! at 40, and the difference between those turns entirely on
//! `request_level_chain`. So the bar for setting it is strict and stated here:
//!
//! > every sampled entry must carry **a query**, **retrieved chunks**, and **a score
//! > per chunk**.
//!
//! A file full of queries proves somebody asked things. A file full of documents
//! proves a corpus exists. Only the two joined together, with the scores that show a
//! retriever actually ranked them, is evidence that retrieval happened on the way to
//! an answer — which is the claim being tested. Anything short of that is real
//! evidence and is reported as such, at 40.
//!
//! ## A vector store on disk is not production retrieval
//!
//! Rule `TT-RAG-007` says so on every report that finds an index, and this module
//! never implies otherwise. A `chroma.sqlite3` in a project folder may be a
//! prototype somebody abandoned.

use crate::{ParseOutput, PendingFact};
use tt_core::error::TtResult;
use tt_core::hash::Digest;
use tt_core::json::{self, JsonValue};
use tt_core::limits::Limits;
use tt_facts::{ArtifactType, FactKind};

pub const PARSER: &str = "retrieval_evidence";
pub const PARSER_VERSION: i64 = 1;

/// Prompt templates can be long. Store enough to recognise, plus a digest of the
/// whole, so a report never carries a wall of somebody's proprietary prompt.
const PROMPT_PREVIEW_CHARS: usize = 400;

/// Entries sampled from a trace file.
const MAX_TRACE_ENTRIES: usize = 10_000;

/// File names that identify a retrieval store.
const INDEX_MARKERS: &[(&str, &str)] = &[
    ("chroma.sqlite3", "chroma"),
    ("chroma-collections.parquet", "chroma"),
    ("index.faiss", "faiss"),
    ("index.pkl", "faiss"),
    ("docstore.json", "llama_index"),
    ("index_store.json", "llama_index"),
    ("meta.json", "qdrant"),
    ("collection.json", "qdrant"),
    ("_lance", "lancedb"),
];

/// Identify a retrieval store from a file name alone.
pub fn index_kind(file_name: &str) -> Option<&'static str> {
    let n = file_name.to_ascii_lowercase();
    INDEX_MARKERS.iter().find(|(needle, _)| n == *needle || n.contains(needle)).map(|(_, k)| *k)
}

/// A file whose presence indicates a retrieval store.
pub fn index_fact(file_name: &str) -> Option<PendingFact> {
    let kind = index_kind(file_name)?;
    Some(
        PendingFact::new(FactKind::RetrievalIndex)
            .with("store", kind)
            .with("evidence", "a store file of this kind is present in the scanned scope"),
    )
}

/// `config_sentence_transformers.json` or `modules.json`.
pub fn parse_embedding_config(bytes: &[u8], limits: &Limits) -> TtResult<ParseOutput> {
    let v = json::parse(bytes, limits)?;
    let mut out = ParseOutput::new(ArtifactType::VectorIndex, PARSER, PARSER_VERSION);
    let mut f = PendingFact::new(FactKind::EmbeddingModel);
    let mut have = false;
    for key in ["model_name_or_path", "model_name", "__version__", "similarity_fn_name"] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            f = f.with(key, s);
            have = true;
        }
    }
    // `modules.json` is a list of module descriptors.
    if let Some(items) = v.as_arr() {
        for m in items {
            if let Some(t) = m.get("type").and_then(|x| x.as_str()) {
                f = f.with("module_type", t);
                have = true;
                break;
            }
        }
    }
    if have {
        out.push(f);
    }
    Ok(out)
}

/// Chunking and index-build settings, wherever they appear in a JSON config.
pub fn parse_chunking_config(bytes: &[u8], limits: &Limits) -> TtResult<ParseOutput> {
    let v = json::parse(bytes, limits)?;
    let mut out = ParseOutput::new(ArtifactType::VectorIndex, PARSER, PARSER_VERSION);
    let mut f = PendingFact::new(FactKind::RetrievalIndex);
    let mut have = false;
    for key in ["chunk_size", "chunk_overlap", "top_k", "similarity_top_k"] {
        if let Some(n) = v.get(key).and_then(|x| x.as_int()) {
            f = f.with(key, n);
            have = true;
        }
    }
    for key in ["splitter", "text_splitter", "embed_model", "vector_store"] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            f = f.with(key, s);
            have = true;
        }
    }
    if have {
        out.push(f.with("store", "config"));
    }
    Ok(out)
}

/// Does this text look like a prompt template that assembles retrieved context?
pub fn looks_like_prompt_template(text: &str) -> bool {
    let markers = ["{context}", "{{context}}", "{question}", "{{question}}", "{retrieved", "{documents}"];
    markers.iter().filter(|m| text.contains(*m)).count() >= 1
}

pub fn parse_prompt_template(bytes: &[u8], limits: &Limits) -> TtResult<ParseOutput> {
    let mut out = ParseOutput::new(ArtifactType::VectorIndex, PARSER, PARSER_VERSION);
    let cap = limits.config_bytes as usize;
    let slice = if bytes.len() > cap { &bytes[..cap] } else { bytes };
    let text = String::from_utf8_lossy(slice);
    if !looks_like_prompt_template(&text) {
        return Ok(out);
    }
    let preview: String = text.chars().take(PROMPT_PREVIEW_CHARS).collect();
    out.push(
        PendingFact::new(FactKind::PromptTemplate)
            .with("preview", preview)
            .with("sha256", Digest::of(bytes).to_hex())
            .with("length_bytes", bytes.len() as i64)
            .with("has_context_placeholder", text.contains("{context}") || text.contains("{{context}}")),
    );
    Ok(out)
}

fn is_query_field(k: &str) -> bool {
    matches!(k, "query" | "question" | "input" | "prompt")
}

fn is_chunks_field(k: &str) -> bool {
    matches!(k, "retrieved" | "documents" | "chunks" | "contexts" | "source_nodes" | "sources")
}

/// Does one trace entry carry a full query -> scored chunks chain?
fn entry_is_full_chain(e: &JsonValue) -> bool {
    let JsonValue::Obj(fields) = e else { return false };
    let has_query = fields
        .iter()
        .any(|(k, v)| is_query_field(k) && matches!(v, JsonValue::Str(s) if !s.is_empty()));
    if !has_query {
        return false;
    }
    // The chunks must be a non-empty list, and every one of them must carry a score.
    // A retriever that returned results without ranking them has not been shown to
    // have ranked anything.
    fields.iter().any(|(k, v)| {
        if !is_chunks_field(k) {
            return false;
        }
        let Some(items) = v.as_arr() else { return false };
        !items.is_empty()
            && items.iter().all(|c| {
                ["score", "similarity", "distance", "relevance_score"]
                    .iter()
                    .any(|s| c.get(s).is_some())
            })
    })
}

/// A JSONL retrieval trace.
pub fn parse_retrieval_trace(bytes: &[u8], limits: &Limits) -> TtResult<ParseOutput> {
    let mut out = ParseOutput::new(ArtifactType::RetrievalTrace, PARSER, PARSER_VERSION);

    let entries = match json::parse_lines(bytes, limits) {
        Ok(e) => e,
        Err(e) => {
            out.note("TT-FMT-010", format!("the retrieval trace was not read: {e}"));
            return Ok(out);
        }
    };
    if entries.is_empty() {
        return Ok(out);
    }

    let sampled: Vec<&JsonValue> = entries.iter().take(MAX_TRACE_ENTRIES).collect();
    if entries.len() > MAX_TRACE_ENTRIES {
        out.note(
            "TT-FMT-010",
            format!("sampled the first {MAX_TRACE_ENTRIES} of {} entries", entries.len()),
        );
    }

    let full = sampled.iter().filter(|e| entry_is_full_chain(e)).count();
    let mut field_names: Vec<String> = Vec::new();
    for e in &sampled {
        if let JsonValue::Obj(fields) = e {
            for (k, _) in fields {
                if !field_names.contains(k) {
                    field_names.push(k.clone());
                }
            }
        }
    }
    field_names.sort();
    field_names.truncate(64);

    out.push(
        PendingFact::new(FactKind::RetrievalTrace)
            .with("entry_count", sampled.len() as i64)
            .with("full_chain_entry_count", full as i64)
            // Strict on purpose: every sampled entry must carry the whole chain.
            // "Most of them did" is not what the rule is scoring.
            .with("request_level_chain", full == sampled.len() && full > 0)
            .with("field_names", field_names),
    );
    Ok(out)
}

/// Route a retrieval-related file by name.
pub fn parse_by_name(name: &str, bytes: &[u8], limits: &Limits) -> Option<TtResult<ParseOutput>> {
    let n = name.to_ascii_lowercase();
    if n == "config_sentence_transformers.json" || n == "modules.json" {
        return Some(parse_embedding_config(bytes, limits));
    }
    if n.ends_with(".jsonl") || n.ends_with(".ndjson") {
        return Some(parse_retrieval_trace(bytes, limits));
    }
    if n.ends_with(".jinja") || n.ends_with(".j2") || n.ends_with(".prompt") || n.ends_with(".tmpl") {
        return Some(parse_prompt_template(bytes, limits));
    }
    if index_kind(&n).is_some() {
        let mut out = ParseOutput::new(ArtifactType::VectorIndex, PARSER, PARSER_VERSION);
        if let Some(f) = index_fact(&n) {
            out.push(f);
        }
        return Some(Ok(out));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tt_facts::FieldValue;

    fn lim() -> Limits {
        Limits::default()
    }

    fn field<'a>(out: &'a ParseOutput, k: FactKind, key: &str) -> Option<&'a FieldValue> {
        out.facts_of(k).find_map(|f| f.get(key))
    }

    // -- the strict boolean ------------------------------------------------

    #[test]
    fn a_full_chain_requires_query_chunks_and_scores() {
        let trace = br#"{"query":"what is x","retrieved":[{"text":"a","score":0.91},{"text":"b","score":0.72}],"answer":"..."}
{"query":"and y","retrieved":[{"text":"c","score":0.88}],"answer":"..."}"#;
        let out = parse_retrieval_trace(trace, &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::RetrievalTrace, "request_level_chain"),
            Some(&FieldValue::Bool(true))
        );
        assert_eq!(
            field(&out, FactKind::RetrievalTrace, "entry_count"),
            Some(&FieldValue::Int(2))
        );
    }

    #[test]
    fn queries_without_retrieved_chunks_are_not_a_chain() {
        let trace = br#"{"query":"what is x","answer":"..."}"#;
        let out = parse_retrieval_trace(trace, &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::RetrievalTrace, "request_level_chain"),
            Some(&FieldValue::Bool(false)),
            "a log of questions is not evidence that retrieval happened"
        );
    }

    #[test]
    fn chunks_without_scores_are_not_a_chain() {
        // A retriever that returned results without ranking them has not been shown
        // to have ranked anything.
        let trace = br#"{"query":"x","retrieved":[{"text":"a"},{"text":"b"}]}"#;
        let out = parse_retrieval_trace(trace, &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::RetrievalTrace, "request_level_chain"),
            Some(&FieldValue::Bool(false))
        );
    }

    #[test]
    fn one_incomplete_entry_breaks_the_chain_for_the_whole_file() {
        let trace = br#"{"query":"x","retrieved":[{"text":"a","score":0.9}]}
{"query":"y"}"#;
        let out = parse_retrieval_trace(trace, &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::RetrievalTrace, "request_level_chain"),
            Some(&FieldValue::Bool(false)),
            "the rule scores whether the chain is present, not whether it usually is"
        );
        // The partial evidence is still reported, so the reader can see the shape.
        assert_eq!(
            field(&out, FactKind::RetrievalTrace, "full_chain_entry_count"),
            Some(&FieldValue::Int(1))
        );
    }

    #[test]
    fn an_empty_trace_is_not_a_chain() {
        let out = parse_retrieval_trace(b"", &lim()).unwrap();
        assert!(out.facts.is_empty(), "nothing to say about an empty file");
    }

    #[test]
    fn alternative_field_spellings_are_accepted() {
        for src in [
            br#"{"question":"x","documents":[{"t":"a","similarity":0.5}]}"#.as_slice(),
            br#"{"query":"x","contexts":[{"t":"a","distance":0.2}]}"#.as_slice(),
            br#"{"input":"x","source_nodes":[{"t":"a","relevance_score":0.9}]}"#.as_slice(),
        ] {
            let out = parse_retrieval_trace(src, &lim()).unwrap();
            assert_eq!(
                field(&out, FactKind::RetrievalTrace, "request_level_chain"),
                Some(&FieldValue::Bool(true)),
                "failed for {}",
                String::from_utf8_lossy(src)
            );
        }
    }

    // -- indexes and templates ---------------------------------------------

    #[test]
    fn store_files_are_recognised_by_name() {
        assert_eq!(index_kind("chroma.sqlite3"), Some("chroma"));
        assert_eq!(index_kind("index.faiss"), Some("faiss"));
        assert_eq!(index_kind("docstore.json"), Some("llama_index"));
        assert_eq!(index_kind("model.safetensors"), None);
    }

    #[test]
    fn a_prompt_template_is_previewed_and_hashed_not_copied_whole() {
        let long = format!("Answer using {{context}}\n\n{}", "x".repeat(5000));
        let out = parse_prompt_template(long.as_bytes(), &lim()).unwrap();
        let preview = match field(&out, FactKind::PromptTemplate, "preview") {
            Some(FieldValue::Text(t)) => t.clone(),
            other => panic!("no preview: {other:?}"),
        };
        assert!(preview.chars().count() <= PROMPT_PREVIEW_CHARS);
        assert!(
            field(&out, FactKind::PromptTemplate, "sha256").is_some(),
            "the whole template must still be identifiable by digest"
        );
        assert_eq!(
            field(&out, FactKind::PromptTemplate, "has_context_placeholder"),
            Some(&FieldValue::Bool(true))
        );
    }

    #[test]
    fn ordinary_text_is_not_mistaken_for_a_template() {
        let out = parse_prompt_template(b"Just some notes about the project.\n", &lim()).unwrap();
        assert!(out.facts.is_empty());
    }

    #[test]
    fn an_embedding_config_is_read() {
        let src = br#"{"model_name_or_path":"BAAI/bge-small-en","similarity_fn_name":"cosine"}"#;
        let out = parse_embedding_config(src, &lim()).unwrap();
        assert_eq!(
            field(&out, FactKind::EmbeddingModel, "model_name_or_path"),
            Some(&FieldValue::Text("BAAI/bge-small-en".into()))
        );
    }

    #[test]
    fn chunking_settings_are_captured() {
        let src = br#"{"chunk_size":512,"chunk_overlap":64,"embed_model":"bge-small"}"#;
        let out = parse_chunking_config(src, &lim()).unwrap();
        assert_eq!(field(&out, FactKind::RetrievalIndex, "chunk_size"), Some(&FieldValue::Int(512)));
    }

    // -- abuse -------------------------------------------------------------

    #[test]
    fn malformed_and_empty_input_never_panics() {
        for src in [&b""[..], &b"{"[..], &b"\xff\xfe"[..], &b"[]"[..], &b"null"[..]] {
            let _ = parse_retrieval_trace(src, &lim());
            let _ = parse_embedding_config(src, &lim());
            let _ = parse_prompt_template(src, &lim());
            let _ = parse_chunking_config(src, &lim());
        }
    }

    #[test]
    fn a_malformed_trace_is_a_note_not_a_failure() {
        let out = parse_retrieval_trace(b"{not json}\n", &lim()).unwrap();
        assert!(out.has_note("TT-FMT-010"));
        assert!(out.facts.is_empty(), "nothing may be claimed from a file that did not parse");
    }

    #[test]
    fn a_very_long_trace_is_sampled_and_says_so() {
        let mut src = String::new();
        for i in 0..(MAX_TRACE_ENTRIES + 10) {
            src.push_str(&format!(
                "{{\"query\":\"q{i}\",\"retrieved\":[{{\"t\":\"a\",\"score\":0.5}}]}}\n"
            ));
        }
        let out = parse_retrieval_trace(src.as_bytes(), &lim()).unwrap();
        assert!(out.has_note("TT-FMT-010"));
        assert_eq!(
            field(&out, FactKind::RetrievalTrace, "entry_count"),
            Some(&FieldValue::Int(MAX_TRACE_ENTRIES as i64))
        );
    }

    #[test]
    fn routing_covers_the_known_shapes() {
        assert!(parse_by_name("trace.jsonl", b"", &lim()).is_some());
        assert!(parse_by_name("modules.json", b"[]", &lim()).is_some());
        assert!(parse_by_name("rag.jinja", b"{context}", &lim()).is_some());
        assert!(parse_by_name("chroma.sqlite3", b"", &lim()).is_some());
        assert!(parse_by_name("config.json", b"{}", &lim()).is_none());
    }
}
