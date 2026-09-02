//! SafeTensors header parsing — **the header only, never the tensor data**.
//!
//! A SafeTensors file is an 8-byte little-endian header length `N`, then `N` bytes of
//! UTF-8 JSON, then the raw tensor region. This module reads the first two and stops.
//! It never reads, maps or decodes the third, which is why a 40 GB checkpoint can be
//! screened from a few hundred kilobytes of prefix.
//!
//! ## Why the header is validated rather than believed
//!
//! The header is written by the party under scrutiny and is the cheapest thing in the
//! whole submission to edit. A tensor table that *claims* 7 billion parameters costs
//! nothing to write, and a scan that reports the claim as an observation would be
//! reporting the vendor's arithmetic as the scanner's. So every entry is checked for
//! internal consistency: `begin <= end`, byte length equal to element count times dtype
//! size, no two tensors overlapping, and — when the file size is known — nothing
//! pointing past the end of the file. A table that fails any of those checks yields
//! `TT-FMT-002` notes and **no tensor-derived facts at all**, because a half-believed
//! table is worse than none.
//!
//! ## What still survives a failed table
//!
//! `__metadata__` is copied out verbatim even then. Those bytes are what the vendor
//! literally wrote, they are independent of the offset arithmetic, and copying them is
//! never a fabrication. They go into their own `ModelConfig` fact so that a
//! vendor-chosen key can never shadow a parser-derived field. Redaction is the
//! scanner's job, not this module's: nothing here filters, renames or interprets.
//!
//! ## Errors versus notes
//!
//! * **Error** — the bytes are not a readable SafeTensors header at all: shorter than
//!   the length prefix, a declared header over the limit or past the end of the file,
//!   header JSON that will not parse, or a header that is valid JSON but not an object.
//! * **Note** — the header *is* a well-formed JSON object but says something internally
//!   inconsistent. That is a coverage limitation with a precise description, not a
//!   crash and not a contradiction about the vendor.
//!
//! One bound is worth stating because it is not obvious: the JSON reader carries its
//! own `config_bytes` limit (8 MiB by default), which is *lower* than
//! `safetensors_header_bytes` (16 MiB). A header between the two is rejected by the
//! JSON reader and surfaces as `LimitExceeded { limit: "config_bytes" }`. That is
//! honest — the scanner really did decline to read it — and it is still a coverage
//! limitation rather than a finding.

use std::collections::{BTreeMap, BTreeSet};

use tt_core::error::{TtError, TtResult};
use tt_core::json::{self, JsonValue};
use tt_core::limits::Limits;
use tt_facts::{ArtifactType, FactKind, FieldValue};

use crate::{shape_elements, FormatParser, ParseOutput, PendingFact, ReadNeed};

/// Stable parser name recorded in the artifact manifest.
pub const PARSER_NAME: &str = "safetensors_header";
/// Bumping this invalidates cached parses of the same bytes.
pub const PARSER_VERSION: i64 = 1;

/// `docs/01-RULE-CATALOGUE.md`: "SafeTensors header malformed, truncated or over limit".
const NOTE_ID: &str = "TT-FMT-002";

/// A hostile header can contain tens of thousands of bad entries. Notes are capped so
/// one file cannot flood the report; the overflow is summarised in a final note.
const MAX_NOTES: usize = 16;

/// The reserved key that holds vendor free-text rather than a tensor.
const METADATA_KEY: &str = "__metadata__";

/// Substrings whose presence in `__metadata__` is recorded as a quantisation mention.
/// This list decides what gets *recorded*, never what it means.
const QUANT_HINTS: [&str; 8] = [
    "quant",
    "gptq",
    "awq",
    "bitsandbytes",
    "nf4",
    "int4",
    "int8",
    "fp8",
];

/// Storage width in bytes of a SafeTensors dtype.
///
/// Returns `None` for anything not in the table. An unrecognised dtype is reported as
/// an observation, never widened into a guess, because guessing the width would turn a
/// consistency check into a fabrication.
pub fn dtype_size(dtype: &str) -> Option<u64> {
    match dtype {
        "BOOL" | "U8" | "I8" | "F8_E4M3" | "F8_E5M2" => Some(1),
        "I16" | "U16" | "F16" | "BF16" => Some(2),
        "I32" | "U32" | "F32" => Some(4),
        "I64" | "U64" | "F64" => Some(8),
        _ => None,
    }
}

/// dtypes that store one byte per element and therefore indicate quantised or 8-bit
/// storage. `BOOL` is excluded: a boolean mask is one byte per element for reasons
/// that have nothing to do with quantisation.
fn is_eight_bit_storage(dtype: &str) -> bool {
    matches!(dtype, "U8" | "I8" | "F8_E4M3" | "F8_E5M2")
}

/// The SafeTensors header parser.
pub struct SafeTensorsHeader;

impl FormatParser for SafeTensorsHeader {
    fn name() -> &'static str {
        PARSER_NAME
    }
    fn version() -> i64 {
        PARSER_VERSION
    }
    fn read_need(limits: &Limits) -> ReadNeed {
        // The 8-byte length prefix plus the largest header we are willing to read.
        ReadNeed::Prefix(limits.safetensors_header_bytes.saturating_add(8))
    }
    fn parse(bytes: &[u8], limits: &Limits) -> TtResult<ParseOutput> {
        parse_header(bytes, limits, None)
    }
}

/// Parse a SafeTensors header from `bytes`, which may be a prefix of the file.
///
/// `file_size` is the size of the whole file when the caller knows it. Supplying it
/// enables the "offsets lie inside the file" check, which is the only way to catch a
/// tensor table that points past the end of the data region.
pub fn parse_header(bytes: &[u8], limits: &Limits, file_size: Option<u64>) -> TtResult<ParseOutput> {
    let mut out = ParseOutput::new(ArtifactType::SafeTensors, PARSER_NAME, PARSER_VERSION);

    let header = read_header_slice(bytes, limits, file_size)?;
    let doc = json::parse(header.json, limits)?;
    let entries = doc.as_obj().ok_or_else(|| {
        TtError::malformed(
            "safetensors_header",
            8,
            format!("header is a JSON {} rather than an object", doc.type_name()),
        )
    })?;

    let mut suppressed: usize = 0;
    let mut invalid = false;
    let mut tensors: Vec<Tensor> = Vec::new();
    let mut metadata: BTreeMap<String, String> = BTreeMap::new();
    let mut metadata_seen = false;
    let mut unknown_dtypes: BTreeSet<String> = BTreeSet::new();

    for (key, value) in entries {
        if key == METADATA_KEY {
            metadata_seen = true;
            read_metadata(value, &mut metadata, &mut out, &mut suppressed);
            continue;
        }
        match read_tensor(key, value) {
            Ok(t) => {
                if dtype_size(&t.dtype).is_none() {
                    unknown_dtypes.insert(t.dtype.clone());
                }
                tensors.push(t);
            }
            Err(detail) => {
                invalid = true;
                note(&mut out, &mut suppressed, detail);
            }
        }
    }

    for d in &unknown_dtypes {
        note(
            &mut out,
            &mut suppressed,
            format!("dtype `{d}` is not a known SafeTensors dtype; its byte length was not checked"),
        );
    }

    if !check_layout(&tensors, &header, file_size, &mut out, &mut suppressed) {
        invalid = true;
    }

    // `__metadata__` is copied out even when the tensor table is unusable: it is the
    // vendor's own bytes, and it does not depend on the offset arithmetic.
    let metadata_quant_reason = metadata_quant_reason(&metadata);
    if !metadata.is_empty() {
        let mut f = PendingFact::new(FactKind::ModelConfig);
        for (k, v) in &metadata {
            f = f.with(k.clone(), FieldValue::Text(v.clone()));
        }
        out.push(f);
    } else if metadata_seen {
        note(
            &mut out,
            &mut suppressed,
            "`__metadata__` present but contributed no string entries".to_string(),
        );
    }

    let mut reasons: Vec<String> = Vec::new();
    if !invalid {
        let eight_bit: Vec<String> = tensors
            .iter()
            .map(|t| t.dtype.clone())
            .filter(|d| is_eight_bit_storage(d))
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        if !eight_bit.is_empty() {
            reasons.push(format!(
                "tensor dtypes include 8-bit storage: {}",
                eight_bit.join(", ")
            ));
        }
        out.push(aggregate_fact(&tensors, header.header_bytes));
        if let Some(adapter) = adapter_fact(&tensors, &mut out, &mut suppressed) {
            out.push(adapter);
        }
    }
    if let Some(r) = metadata_quant_reason {
        reasons.push(r);
    }
    if !reasons.is_empty() {
        out.push(PendingFact::new(FactKind::QuantizationRecord).with("reason", reasons.join("; ")));
    }

    if suppressed > 0 {
        out.note(
            NOTE_ID,
            format!("{suppressed} further header problems not listed individually"),
        );
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Header framing
// ---------------------------------------------------------------------------

struct HeaderSlice<'a> {
    json: &'a [u8],
    /// Declared header length `N`, i.e. the JSON region without the 8-byte prefix.
    header_bytes: u64,
    /// First byte of the tensor data region: `8 + N`. Offsets are relative to it.
    data_start: u64,
}

fn read_header_slice<'a>(
    bytes: &'a [u8],
    limits: &Limits,
    file_size: Option<u64>,
) -> TtResult<HeaderSlice<'a>> {
    let prefix: [u8; 8] = match bytes.get(..8).and_then(|s| <[u8; 8]>::try_from(s).ok()) {
        Some(p) => p,
        None => {
            return Err(TtError::malformed(
                "safetensors_header",
                0,
                format!(
                    "file holds {} bytes, fewer than the 8-byte header length prefix",
                    bytes.len()
                ),
            ))
        }
    };
    let n = u64::from_le_bytes(prefix);
    if n > limits.safetensors_header_bytes {
        return Err(TtError::LimitExceeded {
            limit: "safetensors_header_bytes",
            value: n,
            max: limits.safetensors_header_bytes,
        });
    }
    let data_start = n.checked_add(8).ok_or_else(|| {
        TtError::malformed("safetensors_header", 0, "declared header length overflows")
    })?;
    if let Some(size) = file_size {
        if data_start > size {
            return Err(TtError::malformed(
                "safetensors_header",
                0,
                format!("declared header of {n} bytes extends past the {size}-byte file"),
            ));
        }
    }
    let end = usize::try_from(data_start).map_err(|_| {
        TtError::malformed("safetensors_header", 0, "declared header length exceeds usize")
    })?;
    let json = bytes.get(8..end).ok_or_else(|| {
        TtError::malformed(
            "safetensors_header",
            8,
            format!(
                "declared header of {n} bytes but only {} bytes follow the prefix",
                bytes.len().saturating_sub(8)
            ),
        )
    })?;
    Ok(HeaderSlice { json, header_bytes: n, data_start })
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

struct Tensor {
    name: String,
    dtype: String,
    shape: Vec<i64>,
    elements: i64,
    begin: u64,
    end: u64,
}

/// Read one tensor entry. The `Err` string is the text of a `TT-FMT-002` note, so it
/// describes exactly what was wrong and names the entry.
fn read_tensor(name: &str, v: &JsonValue) -> Result<Tensor, String> {
    let obj = v
        .as_obj()
        .ok_or_else(|| format!("tensor `{name}` is a {} rather than an object", v.type_name()))?;
    let _ = obj;

    let dtype = v
        .get("dtype")
        .and_then(|d| d.as_str())
        .ok_or_else(|| format!("tensor `{name}` has no string `dtype`"))?
        .to_string();

    let shape_arr = v
        .get("shape")
        .and_then(|s| s.as_arr())
        .ok_or_else(|| format!("tensor `{name}` has no `shape` array"))?;
    let mut shape: Vec<i64> = Vec::with_capacity(shape_arr.len());
    for d in shape_arr {
        match d.as_int() {
            Some(i) if i >= 0 => shape.push(i),
            _ => {
                return Err(format!(
                    "tensor `{name}` has a shape dimension that is not a non-negative integer"
                ))
            }
        }
    }
    let elements = shape_elements(&shape)
        .ok_or_else(|| format!("tensor `{name}` has a shape whose element count is not representable"))?;

    let off = v
        .get("data_offsets")
        .and_then(|o| o.as_arr())
        .ok_or_else(|| format!("tensor `{name}` has no `data_offsets` array"))?;
    if off.len() != 2 {
        return Err(format!(
            "tensor `{name}` has {} data_offsets, expected exactly 2",
            off.len()
        ));
    }
    let mut bounds = [0u64; 2];
    for (k, item) in off.iter().enumerate() {
        match item.as_int() {
            Some(i) if i >= 0 => bounds[k] = i as u64,
            _ => {
                return Err(format!(
                    "tensor `{name}` has a data_offset that is not a non-negative integer"
                ))
            }
        }
    }
    let (begin, end) = (bounds[0], bounds[1]);
    if begin > end {
        return Err(format!("tensor `{name}` has data_offsets [{begin}, {end}] with begin > end"));
    }

    if let Some(width) = dtype_size(&dtype) {
        let expected = (elements as u64).checked_mul(width).ok_or_else(|| {
            format!("tensor `{name}` byte length is not representable for dtype {dtype}")
        })?;
        let actual = end - begin;
        if actual != expected {
            return Err(format!(
                "tensor `{name}` spans {actual} bytes but {elements} elements of {dtype} need {expected}"
            ));
        }
    }

    Ok(Tensor { name: name.to_string(), dtype, shape, elements, begin, end })
}

fn read_metadata(
    v: &JsonValue,
    into: &mut BTreeMap<String, String>,
    out: &mut ParseOutput,
    suppressed: &mut usize,
) {
    let obj = match v.as_obj() {
        Some(o) => o,
        None => {
            note(
                out,
                suppressed,
                format!("`__metadata__` is a {} rather than an object", v.type_name()),
            );
            return;
        }
    };
    for (k, val) in obj {
        match val {
            // Verbatim. No filtering, no renaming: the scanner redacts, this does not.
            JsonValue::Str(s) => {
                into.insert(k.clone(), s.clone());
            }
            other => note(
                out,
                suppressed,
                format!(
                    "`__metadata__` entry `{k}` holds a {} rather than a string",
                    other.type_name()
                ),
            ),
        }
    }
}

/// Cross-entry checks. Returns `false` when the table is unusable.
fn check_layout(
    tensors: &[Tensor],
    header: &HeaderSlice<'_>,
    file_size: Option<u64>,
    out: &mut ParseOutput,
    suppressed: &mut usize,
) -> bool {
    let mut ok = true;

    let mut spans: Vec<(u64, u64, &str)> =
        tensors.iter().map(|t| (t.begin, t.end, t.name.as_str())).collect();
    spans.sort_unstable();
    for w in spans.windows(2) {
        let (_, prev_end, prev_name) = w[0];
        let (begin, _, name) = w[1];
        if begin < prev_end {
            ok = false;
            note(
                out,
                suppressed,
                format!("tensors `{prev_name}` and `{name}` have overlapping data_offsets"),
            );
        }
    }

    if let Some(size) = file_size {
        // Offsets are relative to the end of the header, so the last byte a tensor
        // claims is `8 + N + end`.
        let max_end = tensors.iter().map(|t| t.end).max().unwrap_or(0);
        match header.data_start.checked_add(max_end) {
            Some(limit) if limit <= size => {}
            _ => {
                ok = false;
                note(
                    out,
                    suppressed,
                    format!(
                        "tensor data extends to offset {max_end} past the header, beyond the {size}-byte file"
                    ),
                );
            }
        }
    }

    ok
}

// ---------------------------------------------------------------------------
// Facts
// ---------------------------------------------------------------------------

/// One aggregate fact for the whole file.
///
/// A per-tensor fact would be useless: a 300-shard model has hundreds of thousands of
/// tensors and no rule reads them individually.
fn aggregate_fact(tensors: &[Tensor], header_bytes: u64) -> PendingFact {
    let mut parameters: i64 = 0;
    let mut max_rank: i64 = 0;
    let mut largest: i64 = 0;
    let mut dtypes: BTreeSet<String> = BTreeSet::new();
    for t in tensors {
        parameters = parameters.saturating_add(t.elements);
        max_rank = max_rank.max(t.shape.len() as i64);
        largest = largest.max(t.elements);
        dtypes.insert(t.dtype.clone());
    }
    PendingFact::new(FactKind::TensorHeader)
        .with("tensor_count", tensors.len())
        .with("parameters", parameters)
        .with("dtypes", dtypes.into_iter().collect::<Vec<String>>())
        .with("max_rank", max_rank)
        .with("largest_tensor_elements", largest)
        .with("header_bytes", header_bytes)
}

/// The four paired adapter markers, longest first so that `lora_embedding_A` is never
/// read as a plain `lora_A`.
const LORA_MARKERS: [(&str, &str, bool); 4] = [
    ("lora_embedding_A", "lora_embedding", true),
    ("lora_embedding_B", "lora_embedding", false),
    ("lora_A", "lora", true),
    ("lora_B", "lora", false),
];
/// DoRA's magnitude vector. Unpaired by construction.
const DORA_MARKER: &str = "lora_magnitude_vector";
/// PEFT's marker for extra modules trained in full alongside the adapter.
const MODULES_TO_SAVE: &str = "modules_to_save";

/// Split a tensor name on the first adapter marker it contains.
/// Returns `(family, prefix, suffix, is_a_side)`.
fn split_marker(key: &str) -> Option<(&'static str, &str, &str, bool)> {
    for (marker, family, is_a) in LORA_MARKERS {
        if let Some(pos) = key.find(marker) {
            let (prefix, rest) = key.split_at(pos);
            let suffix = &rest[marker.len()..];
            return Some((family, prefix, suffix, is_a));
        }
    }
    None
}

/// The module a key targets, taken as the last dotted segment before the marker.
/// `...self_attn.q_proj.lora_A.weight` yields `q_proj`.
fn target_suffix(prefix: &str) -> Option<&str> {
    let trimmed = prefix.trim_end_matches('.');
    let seg = trimmed.rsplit('.').next().unwrap_or("");
    (!seg.is_empty()).then_some(seg)
}

#[derive(Default)]
struct Pair<'a> {
    a: Option<&'a Tensor>,
    b: Option<&'a Tensor>,
}

/// Describe the adapter structure, if there is one.
///
/// Everything here is an observation. "The A and B halves of this pair disagree about
/// r" is recorded; what that implies about the vendor's claim is a rule's problem.
fn adapter_fact(
    tensors: &[Tensor],
    out: &mut ParseOutput,
    suppressed: &mut usize,
) -> Option<PendingFact> {
    let mut pairs: BTreeMap<(&str, &str, &str), Pair<'_>> = BTreeMap::new();
    let mut suffixes: BTreeSet<String> = BTreeSet::new();
    let mut has_dora = false;
    let mut modules_to_save = false;
    let mut any_marker = false;

    for t in tensors {
        if t.name.contains(MODULES_TO_SAVE) {
            modules_to_save = true;
        }
        if let Some(pos) = t.name.find(DORA_MARKER) {
            has_dora = true;
            any_marker = true;
            if let Some(s) = target_suffix(&t.name[..pos]) {
                suffixes.insert(s.to_string());
            }
            continue;
        }
        if let Some((family, prefix, suffix, is_a)) = split_marker(&t.name) {
            any_marker = true;
            if let Some(s) = target_suffix(prefix) {
                suffixes.insert(s.to_string());
            }
            let slot = pairs.entry((family, prefix, suffix)).or_default();
            if is_a {
                slot.a = Some(t);
            } else {
                slot.b = Some(t);
            }
        }
    }

    if !any_marker {
        return None;
    }

    let mut ranks: BTreeSet<i64> = BTreeSet::new();
    let mut pair_count: i64 = 0;
    let mut unpaired: i64 = 0;
    let mut disagreements: i64 = 0;

    for ((_, prefix, _), pair) in &pairs {
        match (pair.a, pair.b) {
            (Some(a), Some(b)) => {
                pair_count += 1;
                // lora_A is [r, in_features]; lora_B is [out_features, r].
                let ra = a.shape.first().copied();
                let rb = b.shape.last().copied();
                match (ra, rb) {
                    (Some(ra), Some(rb)) if ra == rb => {
                        ranks.insert(ra);
                    }
                    (Some(ra), Some(rb)) => {
                        disagreements += 1;
                        ranks.insert(ra);
                        ranks.insert(rb);
                        note(
                            out,
                            suppressed,
                            format!(
                                "adapter pair under `{prefix}` shows r = {ra} on the A side and r = {rb} on the B side"
                            ),
                        );
                    }
                    _ => {
                        disagreements += 1;
                        note(
                            out,
                            suppressed,
                            format!("adapter pair under `{prefix}` has a rank-0 tensor; r not observable"),
                        );
                    }
                }
            }
            _ => unpaired += 1,
        }
    }

    Some(
        PendingFact::new(FactKind::AdapterTensorSet)
            .with("lora_pair_count", pair_count)
            .with("inferred_ranks", ranks.into_iter().map(|r| r.to_string()).collect::<Vec<String>>())
            .with("target_module_suffixes", suffixes.into_iter().collect::<Vec<String>>())
            .with("has_dora", has_dora)
            .with("modules_to_save_present", modules_to_save)
            .with("unpaired_key_count", unpaired)
            .with("rank_disagreement_count", disagreements),
    )
}

/// Record — never interpret — a quantisation mention in `__metadata__`.
fn metadata_quant_reason(metadata: &BTreeMap<String, String>) -> Option<String> {
    for (k, v) in metadata {
        let hay = format!("{k}\u{0}{v}").to_ascii_lowercase();
        if let Some(hint) = QUANT_HINTS.iter().find(|h| hay.contains(**h)) {
            return Some(format!("`__metadata__` entry `{k}` mentions `{hint}`"));
        }
    }
    None
}

fn note(out: &mut ParseOutput, suppressed: &mut usize, detail: String) {
    if out.notes.len() < MAX_NOTES {
        out.note(NOTE_ID, detail);
    } else {
        *suppressed = suppressed.saturating_add(1);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(header: &str) -> Vec<u8> {
        let mut v = (header.len() as u64).to_le_bytes().to_vec();
        v.extend_from_slice(header.as_bytes());
        v
    }

    fn frame_with_data(header: &str, data: usize) -> Vec<u8> {
        let mut v = frame(header);
        v.extend(std::iter::repeat(0u8).take(data));
        v
    }

    fn lim() -> Limits {
        Limits::default()
    }

    fn ok(bytes: &[u8]) -> ParseOutput {
        parse_header(bytes, &lim(), None).expect("expected a parse")
    }

    fn tensor_fact(out: &ParseOutput) -> Option<&PendingFact> {
        out.facts_of(FactKind::TensorHeader).next()
    }

    // -- happy path ---------------------------------------------------------

    #[test]
    fn reads_a_two_tensor_header() {
        let h = r#"{"a":{"dtype":"F32","shape":[2,3],"data_offsets":[0,24]},
                    "b":{"dtype":"F16","shape":[4],"data_offsets":[24,32]}}"#;
        let out = ok(&frame_with_data(h, 32));
        assert!(out.notes.is_empty(), "{:?}", out.notes);
        let f = tensor_fact(&out).unwrap();
        assert_eq!(f.get("tensor_count"), Some(&FieldValue::Int(2)));
        assert_eq!(f.get("parameters"), Some(&FieldValue::Int(10)));
        assert_eq!(f.get("max_rank"), Some(&FieldValue::Int(2)));
        assert_eq!(f.get("largest_tensor_elements"), Some(&FieldValue::Int(6)));
        assert_eq!(
            f.get("dtypes"),
            Some(&FieldValue::List(vec!["F16".into(), "F32".into()]))
        );
        assert_eq!(
            f.get("header_bytes"),
            Some(&FieldValue::Int(h.len() as i64))
        );
    }

    #[test]
    fn zero_tensor_header_is_valid_and_fabricates_nothing() {
        let out = ok(&frame("{}"));
        let f = tensor_fact(&out).unwrap();
        assert_eq!(f.get("tensor_count"), Some(&FieldValue::Int(0)));
        assert_eq!(f.get("parameters"), Some(&FieldValue::Int(0)));
        assert_eq!(f.get("largest_tensor_elements"), Some(&FieldValue::Int(0)));
        assert!(out.facts_of(FactKind::AdapterTensorSet).next().is_none());
        assert!(out.facts_of(FactKind::QuantizationRecord).next().is_none());
    }

    #[test]
    fn scalar_and_empty_tensors_are_accepted() {
        // shape [] is one element; shape [0, 5] is none. Both are legal.
        let h = r#"{"s":{"dtype":"F32","shape":[],"data_offsets":[0,4]},
                    "e":{"dtype":"F32","shape":[0,5],"data_offsets":[4,4]}}"#;
        let out = ok(&frame_with_data(h, 4));
        assert!(out.notes.is_empty(), "{:?}", out.notes);
        assert_eq!(
            tensor_fact(&out).unwrap().get("parameters"),
            Some(&FieldValue::Int(1))
        );
    }

    #[test]
    fn output_is_identical_for_identical_bytes() {
        let h = r#"{"b":{"dtype":"F32","shape":[2],"data_offsets":[0,8]},
                    "a":{"dtype":"I8","shape":[3],"data_offsets":[8,11]}}"#;
        let bytes = frame_with_data(h, 11);
        assert_eq!(ok(&bytes), ok(&bytes));
    }

    // -- framing abuse ------------------------------------------------------

    #[test]
    fn empty_file_is_an_error_not_a_panic() {
        assert!(parse_header(&[], &lim(), None).is_err());
    }

    #[test]
    fn short_files_error_at_every_length_below_the_prefix() {
        for k in 0..8 {
            let bytes = vec![0u8; k];
            assert!(parse_header(&bytes, &lim(), None).is_err(), "len {k}");
        }
    }

    #[test]
    fn header_length_of_u64_max_hits_the_limit() {
        let mut v = u64::MAX.to_le_bytes().to_vec();
        v.extend_from_slice(b"{}");
        match parse_header(&v, &lim(), None) {
            Err(TtError::LimitExceeded { limit, .. }) => {
                assert_eq!(limit, "safetensors_header_bytes")
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn header_longer_than_the_file_is_refused() {
        let mut v = 4096u64.to_le_bytes().to_vec();
        v.extend_from_slice(b"{}");
        assert!(parse_header(&v, &lim(), None).is_err());
        // And refused again, earlier, when the true file size is supplied.
        assert!(parse_header(&v, &lim(), Some(10)).is_err());
    }

    #[test]
    fn header_over_the_configured_limit_is_refused() {
        let lim = Limits::tiny();
        let mut v = (lim.safetensors_header_bytes + 1).to_le_bytes().to_vec();
        v.extend(std::iter::repeat(b' ').take(64));
        match parse_header(&v, &lim, None) {
            Err(TtError::LimitExceeded { limit, max, .. }) => {
                assert_eq!(limit, "safetensors_header_bytes");
                assert_eq!(max, lim.safetensors_header_bytes);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn truncation_at_every_boundary_errors_and_never_panics() {
        let h = r#"{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#;
        let full = frame_with_data(h, 8);
        let header_end = 8 + h.len();
        for k in 0..full.len() {
            let r = parse_header(&full[..k], &lim(), None);
            if k < header_end {
                assert!(r.is_err(), "prefix of {k} bytes should not parse");
            } else {
                // The data region is never read, so any prefix containing the whole
                // header parses identically.
                assert!(r.is_ok(), "prefix of {k} bytes should parse");
            }
        }
    }

    #[test]
    fn random_bytes_do_not_parse() {
        let mut v: Vec<u8> = Vec::new();
        for i in 0..512u32 {
            v.push((i.wrapping_mul(2654435761) >> 13) as u8);
        }
        // Whatever the leading 8 bytes decode to, the result is an error, never a fact.
        match parse_header(&v, &lim(), None) {
            Ok(out) => assert!(tensor_fact(&out).is_none()),
            Err(_) => {}
        }
    }

    #[test]
    fn valid_json_that_is_not_an_object_is_refused() {
        for body in ["[1,2,3]", "\"hello\"", "42", "null", "true"] {
            let r = parse_header(&frame(body), &lim(), None);
            assert!(matches!(r, Err(TtError::Malformed { .. })), "{body}: {r:?}");
        }
    }

    #[test]
    fn header_that_is_not_json_is_refused() {
        assert!(parse_header(&frame("{not json"), &lim(), None).is_err());
        assert!(parse_header(&frame(""), &lim(), None).is_err());
    }

    #[test]
    fn duplicate_tensor_names_are_refused_by_the_json_reader() {
        let h = r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},
                    "a":{"dtype":"F32","shape":[1],"data_offsets":[4,8]}}"#;
        assert!(matches!(
            parse_header(&frame(h), &lim(), None),
            Err(TtError::Ambiguous { .. })
        ));
    }

    // -- table validation ---------------------------------------------------

    #[test]
    fn overlapping_offsets_yield_a_note_and_no_tensor_fact() {
        let h = r#"{"a":{"dtype":"F32","shape":[4],"data_offsets":[0,16]},
                    "b":{"dtype":"F32","shape":[4],"data_offsets":[8,24]}}"#;
        let out = ok(&frame_with_data(h, 24));
        assert!(out.has_note(NOTE_ID));
        assert!(tensor_fact(&out).is_none(), "no fact may survive an overlap");
    }

    #[test]
    fn touching_offsets_do_not_count_as_overlap() {
        let h = r#"{"a":{"dtype":"U8","shape":[4],"data_offsets":[0,4]},
                    "b":{"dtype":"U8","shape":[4],"data_offsets":[4,8]}}"#;
        let out = ok(&frame_with_data(h, 8));
        assert!(tensor_fact(&out).is_some());
    }

    #[test]
    fn byte_length_mismatch_yields_a_note_and_no_tensor_fact() {
        let h = r#"{"a":{"dtype":"F32","shape":[2,3],"data_offsets":[0,20]}}"#;
        let out = ok(&frame_with_data(h, 20));
        assert!(out.has_note(NOTE_ID));
        assert!(tensor_fact(&out).is_none());
        assert!(out.notes.iter().any(|n| n.detail.contains("24")), "{:?}", out.notes);
    }

    #[test]
    fn begin_after_end_is_rejected() {
        let h = r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[16,4]}}"#;
        let out = ok(&frame_with_data(h, 20));
        assert!(out.has_note(NOTE_ID));
        assert!(tensor_fact(&out).is_none());
    }

    #[test]
    fn negative_offsets_and_dimensions_are_rejected() {
        for h in [
            r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[-4,4]}}"#,
            r#"{"a":{"dtype":"F32","shape":[-1],"data_offsets":[0,4]}}"#,
        ] {
            let out = ok(&frame_with_data(h, 8));
            assert!(out.has_note(NOTE_ID), "{h}");
            assert!(tensor_fact(&out).is_none(), "{h}");
        }
    }

    #[test]
    fn offsets_beyond_a_known_file_size_are_rejected() {
        let h = r#"{"a":{"dtype":"F32","shape":[4],"data_offsets":[0,16]}}"#;
        let bytes = frame_with_data(h, 16);
        let size = bytes.len() as u64;
        assert!(tensor_fact(&parse_header(&bytes, &lim(), Some(size)).unwrap()).is_some());
        let out = parse_header(&bytes, &lim(), Some(size - 1)).unwrap();
        assert!(out.has_note(NOTE_ID));
        assert!(tensor_fact(&out).is_none());
    }

    #[test]
    fn shape_that_overflows_is_rejected_rather_than_wrapped() {
        let h = format!(
            r#"{{"a":{{"dtype":"F32","shape":[{m},{m}],"data_offsets":[0,0]}}}}"#,
            m = i64::MAX
        );
        let out = ok(&frame(&h));
        assert!(out.has_note(NOTE_ID));
        assert!(tensor_fact(&out).is_none());
    }

    #[test]
    fn malformed_entries_of_every_shape_are_notes_not_panics() {
        for h in [
            r#"{"a":42}"#,
            r#"{"a":{"shape":[1],"data_offsets":[0,4]}}"#,
            r#"{"a":{"dtype":"F32","data_offsets":[0,4]}}"#,
            r#"{"a":{"dtype":"F32","shape":[1]}}"#,
            r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0]}}"#,
            r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4,8]}}"#,
            r#"{"a":{"dtype":7,"shape":[1],"data_offsets":[0,4]}}"#,
            r#"{"a":{"dtype":"F32","shape":"big","data_offsets":[0,4]}}"#,
            r#"{"a":{"dtype":"F32","shape":[1.5],"data_offsets":[0,4]}}"#,
        ] {
            let out = ok(&frame_with_data(h, 16));
            assert!(out.has_note(NOTE_ID), "{h}");
            assert!(tensor_fact(&out).is_none(), "{h}");
        }
    }

    #[test]
    fn unknown_dtype_is_a_note_not_a_guess() {
        let h = r#"{"a":{"dtype":"F4_E2M1","shape":[8],"data_offsets":[0,4]}}"#;
        let out = ok(&frame_with_data(h, 4));
        assert!(out.notes.iter().any(|n| n.detail.contains("F4_E2M1")));
        // The rest of the table is still consistent, so the aggregate survives and
        // reports the dtype as observed rather than inventing a width for it.
        let f = tensor_fact(&out).expect("unknown dtype is not a table failure");
        assert_eq!(
            f.get("dtypes"),
            Some(&FieldValue::List(vec!["F4_E2M1".into()]))
        );
    }

    #[test]
    fn note_flood_is_capped() {
        let mut parts = Vec::new();
        for i in 0..200 {
            parts.push(format!(
                r#""t{i}":{{"dtype":"F32","shape":[1],"data_offsets":[0,99]}}"#
            ));
        }
        let h = format!("{{{}}}", parts.join(","));
        let out = ok(&frame(&h));
        assert!(out.notes.len() <= MAX_NOTES + 1, "{} notes", out.notes.len());
        assert!(out.notes.iter().any(|n| n.detail.contains("further header problems")));
    }

    // -- dtype table --------------------------------------------------------

    #[test]
    fn dtype_widths_match_the_frozen_table() {
        for d in ["BOOL", "U8", "I8", "F8_E4M3", "F8_E5M2"] {
            assert_eq!(dtype_size(d), Some(1), "{d}");
        }
        for d in ["I16", "U16", "F16", "BF16"] {
            assert_eq!(dtype_size(d), Some(2), "{d}");
        }
        for d in ["I32", "U32", "F32"] {
            assert_eq!(dtype_size(d), Some(4), "{d}");
        }
        for d in ["I64", "U64", "F64"] {
            assert_eq!(dtype_size(d), Some(8), "{d}");
        }
        for d in ["f32", "FLOAT32", "", "F4"] {
            assert_eq!(dtype_size(d), None, "{d}");
        }
    }

    // -- adapters -----------------------------------------------------------

    fn lora_header(rank: i64) -> String {
        format!(
            r#"{{
              "base_model.model.model.layers.0.self_attn.q_proj.lora_A.weight":
                {{"dtype":"F32","shape":[{r},16],"data_offsets":[0,{a}]}},
              "base_model.model.model.layers.0.self_attn.q_proj.lora_B.weight":
                {{"dtype":"F32","shape":[16,{r}],"data_offsets":[{a},{b}]}},
              "base_model.model.model.layers.0.self_attn.v_proj.lora_A.weight":
                {{"dtype":"F32","shape":[{r},16],"data_offsets":[{b},{c}]}},
              "base_model.model.model.layers.0.self_attn.v_proj.lora_B.weight":
                {{"dtype":"F32","shape":[16,{r}],"data_offsets":[{c},{d}]}}
            }}"#,
            r = rank,
            a = rank * 16 * 4,
            b = rank * 16 * 4 * 2,
            c = rank * 16 * 4 * 3,
            d = rank * 16 * 4 * 4,
        )
    }

    #[test]
    fn detects_a_lora_adapter_set() {
        let h = lora_header(8);
        let out = ok(&frame_with_data(&h, 8 * 16 * 4 * 4));
        let f = out.facts_of(FactKind::AdapterTensorSet).next().expect("adapter fact");
        assert_eq!(f.get("lora_pair_count"), Some(&FieldValue::Int(2)));
        assert_eq!(
            f.get("inferred_ranks"),
            Some(&FieldValue::List(vec!["8".into()]))
        );
        assert_eq!(
            f.get("target_module_suffixes"),
            Some(&FieldValue::List(vec!["q_proj".into(), "v_proj".into()]))
        );
        assert_eq!(f.get("has_dora"), Some(&FieldValue::Bool(false)));
        assert_eq!(f.get("modules_to_save_present"), Some(&FieldValue::Bool(false)));
        assert_eq!(f.get("unpaired_key_count"), Some(&FieldValue::Int(0)));
        assert_eq!(f.get("rank_disagreement_count"), Some(&FieldValue::Int(0)));
    }

    #[test]
    fn plain_model_emits_no_adapter_fact() {
        let h = r#"{"model.layers.0.self_attn.q_proj.weight":
                     {"dtype":"BF16","shape":[8,8],"data_offsets":[0,128]}}"#;
        let out = ok(&frame_with_data(h, 128));
        assert!(out.facts_of(FactKind::AdapterTensorSet).next().is_none());
    }

    #[test]
    fn dora_magnitude_vector_and_modules_to_save_are_seen() {
        let h = r#"{
          "base_model.model.layers.0.mlp.up_proj.lora_A.weight":
            {"dtype":"F32","shape":[4,8],"data_offsets":[0,128]},
          "base_model.model.layers.0.mlp.up_proj.lora_B.weight":
            {"dtype":"F32","shape":[8,4],"data_offsets":[128,256]},
          "base_model.model.layers.0.mlp.up_proj.lora_magnitude_vector":
            {"dtype":"F32","shape":[8],"data_offsets":[256,288]},
          "base_model.model.score.modules_to_save.default.weight":
            {"dtype":"F32","shape":[2,8],"data_offsets":[288,352]}
        }"#;
        let out = ok(&frame_with_data(h, 352));
        let f = out.facts_of(FactKind::AdapterTensorSet).next().unwrap();
        assert_eq!(f.get("has_dora"), Some(&FieldValue::Bool(true)));
        assert_eq!(f.get("modules_to_save_present"), Some(&FieldValue::Bool(true)));
        assert_eq!(f.get("lora_pair_count"), Some(&FieldValue::Int(1)));
    }

    #[test]
    fn embedding_adapters_pair_separately_from_plain_lora() {
        // Same prefix and suffix on both families: they must not be cross-paired.
        let h = r#"{
          "m.lora_A.weight":{"dtype":"F32","shape":[4,8],"data_offsets":[0,128]},
          "m.lora_embedding_B.weight":{"dtype":"F32","shape":[8,4],"data_offsets":[128,256]}
        }"#;
        let out = ok(&frame_with_data(h, 256));
        let f = out.facts_of(FactKind::AdapterTensorSet).next().unwrap();
        assert_eq!(f.get("lora_pair_count"), Some(&FieldValue::Int(0)));
        assert_eq!(f.get("unpaired_key_count"), Some(&FieldValue::Int(2)));
    }

    #[test]
    fn disagreeing_ranks_are_recorded_not_averaged() {
        let h = r#"{
          "m.q_proj.lora_A.weight":{"dtype":"F32","shape":[8,16],"data_offsets":[0,512]},
          "m.q_proj.lora_B.weight":{"dtype":"F32","shape":[16,4],"data_offsets":[512,768]}
        }"#;
        let out = ok(&frame_with_data(h, 768));
        let f = out.facts_of(FactKind::AdapterTensorSet).next().unwrap();
        assert_eq!(f.get("rank_disagreement_count"), Some(&FieldValue::Int(1)));
        assert_eq!(
            f.get("inferred_ranks"),
            Some(&FieldValue::List(vec!["4".into(), "8".into()]))
        );
        assert!(out.notes.iter().any(|n| n.detail.contains("A side")));
    }

    #[test]
    fn unpaired_adapter_keys_are_counted() {
        let h = r#"{"m.q_proj.lora_A.weight":
                     {"dtype":"F32","shape":[4,8],"data_offsets":[0,128]}}"#;
        let out = ok(&frame_with_data(h, 128));
        let f = out.facts_of(FactKind::AdapterTensorSet).next().unwrap();
        assert_eq!(f.get("unpaired_key_count"), Some(&FieldValue::Int(1)));
        assert_eq!(f.get("lora_pair_count"), Some(&FieldValue::Int(0)));
    }

    #[test]
    fn marker_splitting_is_exact() {
        assert_eq!(
            split_marker("a.b.lora_A.weight"),
            Some(("lora", "a.b.", ".weight", true))
        );
        assert_eq!(
            split_marker("a.lora_embedding_B.weight"),
            Some(("lora_embedding", "a.", ".weight", false))
        );
        assert_eq!(split_marker("model.layers.0.mlp.weight"), None);
        assert_eq!(target_suffix("m.self_attn.q_proj."), Some("q_proj"));
        assert_eq!(target_suffix(""), None);
        assert_eq!(target_suffix("."), None);
    }

    // -- metadata and quantisation -----------------------------------------

    #[test]
    fn metadata_is_copied_verbatim_and_unfiltered() {
        let h = r#"{"__metadata__":{"format":"pt","note":"C:\\Users\\someone\\run"},
                    "a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#;
        let out = ok(&frame_with_data(h, 4));
        let f = out.facts_of(FactKind::ModelConfig).next().expect("metadata fact");
        assert_eq!(f.get("format"), Some(&FieldValue::Text("pt".into())));
        // Redaction belongs to the scanner: this module must not have touched it.
        assert_eq!(
            f.get("note"),
            Some(&FieldValue::Text("C:\\Users\\someone\\run".into()))
        );
    }

    #[test]
    fn metadata_survives_an_unusable_tensor_table() {
        let h = r#"{"__metadata__":{"format":"pt"},
                    "a":{"dtype":"F32","shape":[1],"data_offsets":[0,99]}}"#;
        let out = ok(&frame_with_data(h, 128));
        assert!(tensor_fact(&out).is_none());
        assert!(out.facts_of(FactKind::ModelConfig).next().is_some());
    }

    #[test]
    fn non_string_metadata_values_are_noted_not_coerced() {
        let h = r#"{"__metadata__":{"steps":100,"ok":"yes"}}"#;
        let out = ok(&frame(h));
        assert!(out.notes.iter().any(|n| n.detail.contains("steps")));
        let f = out.facts_of(FactKind::ModelConfig).next().unwrap();
        assert_eq!(f.get("ok"), Some(&FieldValue::Text("yes".into())));
        assert!(f.get("steps").is_none());
    }

    #[test]
    fn metadata_that_is_not_an_object_is_a_note() {
        let out = ok(&frame(r#"{"__metadata__":"nope"}"#));
        assert!(out.has_note(NOTE_ID));
        assert!(out.facts_of(FactKind::ModelConfig).next().is_none());
    }

    #[test]
    fn eight_bit_dtypes_raise_a_quantization_record() {
        let h = r#"{"a":{"dtype":"I8","shape":[8],"data_offsets":[0,8]}}"#;
        let out = ok(&frame_with_data(h, 8));
        let q = out.facts_of(FactKind::QuantizationRecord).next().expect("quant fact");
        let reason = q.get("reason").and_then(|v| v.as_text()).unwrap_or("");
        assert!(reason.contains("I8"), "{reason}");
    }

    #[test]
    fn bool_tensors_alone_are_not_quantisation() {
        let h = r#"{"m":{"dtype":"BOOL","shape":[8],"data_offsets":[0,8]}}"#;
        let out = ok(&frame_with_data(h, 8));
        assert!(out.facts_of(FactKind::QuantizationRecord).next().is_none());
    }

    #[test]
    fn metadata_quantisation_mention_is_recorded_even_without_8_bit_dtypes() {
        let h = r#"{"__metadata__":{"quantization_config":"gptq-4bit"},
                    "a":{"dtype":"F16","shape":[2],"data_offsets":[0,4]}}"#;
        let out = ok(&frame_with_data(h, 4));
        let q = out.facts_of(FactKind::QuantizationRecord).next().unwrap();
        assert!(q
            .get("reason")
            .and_then(|v| v.as_text())
            .unwrap_or("")
            .contains("quantization_config"));
    }

    #[test]
    fn read_need_covers_the_length_prefix() {
        let l = Limits::default();
        assert_eq!(
            SafeTensorsHeader::read_need(&l),
            ReadNeed::Prefix(l.safetensors_header_bytes + 8)
        );
        assert_eq!(SafeTensorsHeader::name(), PARSER_NAME);
        assert_eq!(SafeTensorsHeader::version(), PARSER_VERSION);
    }

    #[test]
    fn trait_entry_point_matches_the_direct_call() {
        let h = r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#;
        let bytes = frame_with_data(h, 4);
        assert_eq!(
            SafeTensorsHeader::parse(&bytes, &lim()).unwrap(),
            parse_header(&bytes, &lim(), None).unwrap()
        );
    }
}
