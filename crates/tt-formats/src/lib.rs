//! # tt-formats
//!
//! Safe, bounded parsers for vendor-supplied artifacts.
//!
//! ## The rule every parser in this crate obeys
//!
//! **Read metadata. Never load the model. Never execute anything.**
//!
//! * SafeTensors: the JSON header only — names, shapes, dtypes, offsets. The tensor
//!   data region is never read.
//! * GGUF: the header and key/value metadata block only.
//! * ONNX: the protobuf metadata fields only; no operator is instantiated.
//! * Pickle, `.pt`, `.pth`, `.bin`, joblib, NumPy object arrays: **hashed and
//!   counted, never opened.** These formats execute code on load, so their presence
//!   is evidence and their content is out of scope.
//!
//! Every parser is bounded by [`tt_core::limits::Limits`]. Exceeding a bound
//! produces a [`PendingNote`], which becomes a `coverage_limitation` in the report —
//! never a contradiction, and never a truncated parse presented as complete.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use tt_core::error::TtResult;
use tt_core::limits::Limits;
use tt_facts::{ArtifactType, FactKind, FieldValue};

pub mod deploy;
pub mod deps;
pub mod detect;
pub mod dispatch;
pub mod gguf;
pub mod hf;
pub mod logs;
pub mod onnx;
pub mod rag;
pub mod safetensors;
pub mod tomlish;
pub mod yamlish;

/// A fact before it has been given an id. Parsers do not allocate ids, because id
/// allocation must be deterministic across the whole scan, not per file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingFact {
    pub kind: FactKind,
    pub fields: BTreeMap<String, FieldValue>,
}

impl PendingFact {
    pub fn new(kind: FactKind) -> Self {
        PendingFact { kind, fields: BTreeMap::new() }
    }
    #[must_use]
    pub fn with(mut self, k: impl Into<String>, v: impl Into<FieldValue>) -> Self {
        self.fields.insert(k.into(), v.into());
        self
    }
    #[must_use]
    pub fn with_opt(mut self, k: impl Into<String>, v: Option<impl Into<FieldValue>>) -> Self {
        if let Some(v) = v {
            self.fields.insert(k.into(), v.into());
        }
        self
    }
    pub fn get(&self, k: &str) -> Option<&FieldValue> {
        self.fields.get(k)
    }
}

/// Something the parser could not see or could not resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingNote {
    /// A `TT-FMT-*` or `TT-INV-*` rule id from `docs/01-RULE-CATALOGUE.md`.
    pub rule_id: &'static str,
    pub detail: String,
}

impl PendingNote {
    pub fn new(rule_id: &'static str, detail: impl Into<String>) -> Self {
        PendingNote { rule_id, detail: detail.into() }
    }
}

/// What one parser produced from one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOutput {
    pub artifact_type: ArtifactType,
    pub parser: &'static str,
    pub parser_version: i64,
    pub facts: Vec<PendingFact>,
    pub notes: Vec<PendingNote>,
}

impl ParseOutput {
    pub fn new(artifact_type: ArtifactType, parser: &'static str, parser_version: i64) -> Self {
        ParseOutput { artifact_type, parser, parser_version, facts: Vec::new(), notes: Vec::new() }
    }
    pub fn push(&mut self, f: PendingFact) -> &mut Self {
        self.facts.push(f);
        self
    }
    pub fn note(&mut self, rule_id: &'static str, detail: impl Into<String>) -> &mut Self {
        self.notes.push(PendingNote::new(rule_id, detail));
        self
    }
    pub fn facts_of(&self, kind: FactKind) -> impl Iterator<Item = &PendingFact> {
        self.facts.iter().filter(move |f| f.kind == kind)
    }
    pub fn has_note(&self, rule_id: &str) -> bool {
        self.notes.iter().any(|n| n.rule_id == rule_id)
    }
}

/// How much of a file a parser needs to see.
///
/// The scanner uses this to read a bounded prefix instead of a whole checkpoint:
/// a 40 GB SafeTensors file is parsed from its first few hundred kilobytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadNeed {
    /// A prefix of at most this many bytes.
    Prefix(u64),
    /// The last `n` bytes, for log tails.
    Suffix(u64),
    /// The whole file, subject to the relevant limit.
    Whole,
}

/// The interface every format module exposes.
pub trait FormatParser {
    /// Stable parser name recorded in the artifact manifest.
    fn name() -> &'static str;
    fn version() -> i64;
    /// How much of the file [`FormatParser::parse`] needs.
    fn read_need(limits: &Limits) -> ReadNeed;
    /// Parse the supplied bytes. `bytes` may be a prefix, per [`FormatParser::read_need`].
    fn parse(bytes: &[u8], limits: &Limits) -> TtResult<ParseOutput>;
}

/// Convenience: the number of elements implied by a tensor shape.
pub fn shape_elements(shape: &[i64]) -> Option<i64> {
    let mut n: i64 = 1;
    for d in shape {
        if *d < 0 {
            return None;
        }
        n = n.checked_mul(*d)?;
    }
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_elements_handles_overflow_and_negatives() {
        assert_eq!(shape_elements(&[2, 3, 4]), Some(24));
        assert_eq!(shape_elements(&[]), Some(1));
        assert_eq!(shape_elements(&[-1, 2]), None);
        assert_eq!(shape_elements(&[i64::MAX, 2]), None);
    }

    #[test]
    fn pending_fact_builder() {
        let f = PendingFact::new(FactKind::AdapterConfig).with("r", 16i64).with("peft_type", "LORA");
        assert_eq!(f.get("r"), Some(&FieldValue::Int(16)));
    }
}
