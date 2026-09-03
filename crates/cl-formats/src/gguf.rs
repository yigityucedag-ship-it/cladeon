//! GGUF header and key/value metadata — **the metadata block only, never tensor data**.
//!
//! A GGUF file opens with `GGUF`, a `u32` version, a `u64` tensor count and a `u64`
//! metadata pair count, followed by that many key/value pairs. After the pairs come
//! the tensor info blocks and then the tensor data itself. This module reads the
//! fixed header and the key/value block and stops. It never reads a tensor info
//! block and never touches the data region, so a 30 GB quantised checkpoint is
//! screened from a bounded prefix.
//!
//! ## Why the metadata is walked rather than searched
//!
//! Every value in the block is length-prefixed by the party under scrutiny, and the
//! block is not indexed: the only way to reach the ninth pair is to believe the
//! declared lengths of the first eight. So each length is checked against the bytes
//! actually supplied *before* it is used, and the walk stops at the first length it
//! cannot honour. A scan that guessed its way past a bad length would be reporting
//! its own arithmetic as an observation.
//!
//! ## Two `ModelConfig` facts, deliberately
//!
//! The first carries a closed, parser-chosen set of fields — `general.architecture`,
//! `general.name`, `general.file_type`, `general.quantization_version`, and the
//! architecture-prefixed context length and block count under normalised names. The
//! second carries every *other* scalar metadata key verbatim. Keeping them apart
//! means a vendor-chosen key can never shadow a parser-derived one, which is the same
//! reason `safetensors.rs` isolates `__metadata__`.
//!
//! Counts that describe the *file* rather than the model — tensor count, declared and
//! read pair counts, format version — go on the `TensorHeader` fact, which holds
//! nothing a vendor wrote as a key.
//!
//! Array-valued keys are walked so the stream stays aligned, but their elements are
//! not carried into facts. Those elements are tokenizer vocabularies and merge lists:
//! bulk data no Stage-1 rule consumes, and copying them would put megabytes of vendor
//! strings into a report for nothing.
//!
//! ## Floats
//!
//! `float32` and `float64` values are recorded as [`FieldValue::Num`] holding the
//! shortest decimal text that reads back as the same value — an `f32` printed as an
//! `f32`, never widened to `f64` first, because widening `0.1f32` produces
//! `0.10000000149011612` and that is a different number than the one in the file.
//! Non-finite values keep their printed form (`NaN`, `inf`, `-inf`) rather than being
//! replaced by a stand-in.
//!
//! ## Errors versus notes
//!
//! * **Error** — the bytes are not a readable GGUF header at all: too short, wrong
//!   magic, an unsupported version, or a pair count that no configured limit or
//!   supplied byte count could hold.
//! * **Note** — the fixed header read but the walk could not finish, or a value was
//!   read and could not be carried into a report. Both are `CL-FMT-004`, a coverage
//!   limitation naming what the scanner could not do.
//!
//! A completed walk also emits `CL-FMT-003`. The two can appear together: a file
//! whose pairs all read, one of which declares a `file_type` this reader does not
//! recognise, is a complete parse with a limitation recorded against one value.
//!
//! ## Known limitation: version 1 framing
//!
//! Lengths are read as `u64`, which is the version 2 and 3 framing. Version 1 wrote
//! 32-bit lengths for strings and arrays. A version 1 file is accepted by the version
//! check and then fails on its first length, producing `CL-FMT-004` and no facts
//! beyond the fixed header. That is the honest outcome — the reader really cannot
//! read it — and it is preferred to a second framing path that would have no fixture
//! to test it against.

use std::collections::{BTreeMap, BTreeSet};

use cl_core::error::{ClError, ClResult};
use cl_core::limits::Limits;
use cl_facts::{ArtifactType, FactKind, FieldValue};

use crate::{FormatParser, ParseOutput, PendingFact, ReadNeed};

/// Stable parser name recorded in the artifact manifest.
pub const PARSER_NAME: &str = "gguf_metadata";
/// Bumping this invalidates cached parses of the same bytes.
pub const PARSER_VERSION: i64 = 1;

/// `docs/01-RULE-CATALOGUE.md`: "GGUF header and key/value metadata parsed".
const NOTE_OK: &str = "CL-FMT-003";
/// `docs/01-RULE-CATALOGUE.md`: "GGUF header malformed or over limit".
const NOTE_ID: &str = "CL-FMT-004";

const MAGIC: [u8; 4] = *b"GGUF";
/// Magic, version, tensor count, pair count.
const HEADER_BYTES: u64 = 4 + 4 + 8 + 8;
/// The smallest a pair can be: an 8-byte key length, an empty key, a 4-byte type
/// code and a one-byte value. Used to reject a declared pair count that the supplied
/// bytes could not possibly contain, before the walk allocates anything.
const MIN_PAIR_BYTES: u64 = 8 + 4 + 1;
/// Versions this reader will attempt. See the module note on version 1 framing.
const MIN_VERSION: u32 = 1;
const MAX_VERSION: u32 = 3;
/// A hostile metadata block can produce a note per pair. Notes are capped so one file
/// cannot flood the report; the overflow is summarised in a final note.
const MAX_NOTES: usize = 16;

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------

/// The thirteen GGUF value types, codes `0..=12`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VType {
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    F32,
    Bool,
    Str,
    Array,
    U64,
    I64,
    F64,
}

impl VType {
    fn from_code(code: u32) -> Option<VType> {
        Some(match code {
            0 => VType::U8,
            1 => VType::I8,
            2 => VType::U16,
            3 => VType::I16,
            4 => VType::U32,
            5 => VType::I32,
            6 => VType::F32,
            7 => VType::Bool,
            8 => VType::Str,
            9 => VType::Array,
            10 => VType::U64,
            11 => VType::I64,
            12 => VType::F64,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            VType::U8 => "uint8",
            VType::I8 => "int8",
            VType::U16 => "uint16",
            VType::I16 => "int16",
            VType::U32 => "uint32",
            VType::I32 => "int32",
            VType::F32 => "float32",
            VType::Bool => "bool",
            VType::Str => "string",
            VType::Array => "array",
            VType::U64 => "uint64",
            VType::I64 => "int64",
            VType::F64 => "float64",
        }
    }

    /// Storage width, or `None` for the two variable-length types. A fixed-width
    /// array is skipped by arithmetic instead of element by element.
    fn fixed_width(self) -> Option<u64> {
        Some(match self {
            VType::U8 | VType::I8 | VType::Bool => 1,
            VType::U16 | VType::I16 => 2,
            VType::U32 | VType::I32 | VType::F32 => 4,
            VType::U64 | VType::I64 | VType::F64 => 8,
            VType::Str | VType::Array => return None,
        })
    }
}

/// A value the walk read. `Opaque` means the bytes were consumed correctly but the
/// value cannot be carried into a report — an array, or a scalar outside the range
/// the fact model can hold. Recording it as `Opaque` keeps the key visible to the
/// duplicate check without inventing a value for it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Scalar {
    Int(i64),
    Num(String),
    Bool(bool),
    Str(String),
    Opaque,
}

fn scalar_text(s: &Scalar) -> Option<&str> {
    match s {
        Scalar::Str(t) => Some(t),
        _ => None,
    }
}

fn scalar_int(s: &Scalar) -> Option<i64> {
    match s {
        Scalar::Int(i) => Some(*i),
        _ => None,
    }
}

/// A string that was framed correctly. Invalid UTF-8 is not a framing failure: the
/// bytes were consumed, the stream is still aligned, and only that one value is lost.
enum StrRead {
    Text(String),
    NotUtf8(u64),
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// A bounds-checked forward reader. Every method returns the text of a `CL-FMT-004`
/// note on failure, so the caller can say exactly which length could not be honoured.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }

    fn remaining(&self) -> u64 {
        self.bytes.len().saturating_sub(self.pos) as u64
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8], String> {
        let want = usize::try_from(n)
            .map_err(|_| format!("a declared length of {n} bytes is larger than this platform can address"))?;
        let end = self
            .pos
            .checked_add(want)
            .ok_or_else(|| format!("a declared length of {n} bytes overflows the read position"))?;
        let slice = self.bytes.get(self.pos..end).ok_or_else(|| {
            format!(
                "{n} bytes were declared at offset {} but only {} remain",
                self.pos,
                self.remaining()
            )
        })?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?.first().copied().unwrap_or(0))
    }

    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([get(b, 0), get(b, 1)]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([get(b, 0), get(b, 1), get(b, 2), get(b, 3)]))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            get(b, 0),
            get(b, 1),
            get(b, 2),
            get(b, 3),
            get(b, 4),
            get(b, 5),
            get(b, 6),
            get(b, 7),
        ]))
    }
}

/// Indexing a slice that `take` already sized. Written as a total function rather
/// than `slice[i]` so that no path in this module can panic on a length mistake.
fn get(b: &[u8], i: usize) -> u8 {
    b.get(i).copied().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

/// The GGUF metadata parser.
pub struct GgufMetadata;

impl FormatParser for GgufMetadata {
    fn name() -> &'static str {
        PARSER_NAME
    }
    fn version() -> i64 {
        PARSER_VERSION
    }
    fn read_need(limits: &Limits) -> ReadNeed {
        ReadNeed::Prefix(limits.gguf_metadata_bytes.saturating_add(HEADER_BYTES))
    }
    fn parse(bytes: &[u8], limits: &Limits) -> ClResult<ParseOutput> {
        parse_metadata(bytes, limits)
    }
}

/// Parse the GGUF fixed header and key/value metadata from `bytes`, which may be a
/// prefix of the file. Bytes beyond `limits.gguf_metadata_bytes` past the fixed
/// header are not read at all.
pub fn parse_metadata(bytes: &[u8], limits: &Limits) -> ClResult<ParseOutput> {
    let mut out = ParseOutput::new(ArtifactType::Gguf, PARSER_NAME, PARSER_VERSION);
    let mut suppressed: usize = 0;

    let max_window = limits.gguf_metadata_bytes.saturating_add(HEADER_BYTES);
    let window_len = usize::try_from(max_window).unwrap_or(usize::MAX).min(bytes.len());
    let bounded = bytes.get(..window_len).unwrap_or(bytes);
    let clipped_by_limit = window_len < bytes.len();

    let mut r = Reader::new(bounded);
    let header = read_fixed_header(&mut r, limits)?;

    let mut kv: BTreeMap<String, Scalar> = BTreeMap::new();
    let mut duplicated: BTreeSet<String> = BTreeSet::new();
    let mut pairs_read: u64 = 0;
    let mut stopped: Option<String> = None;

    for index in 0..header.kv_count {
        match read_pair(&mut r, limits, &mut out, &mut suppressed) {
            Ok(pair) => {
                pairs_read += 1;
                if let Some((key, value)) = pair {
                    if duplicated.contains(&key) {
                        continue;
                    }
                    if kv.contains_key(&key) {
                        // A metadata block that says two things must not be silently
                        // resolved to one of them, so the key is dropped entirely.
                        kv.remove(&key);
                        duplicated.insert(key.clone());
                        note(
                            &mut out,
                            &mut suppressed,
                            format!("metadata declares the key `{key}` more than once; no value is taken from it"),
                        );
                    } else {
                        kv.insert(key, value);
                    }
                }
            }
            Err(detail) => {
                stopped = Some(format!(
                    "metadata reading stopped at pair {index} of {}: {detail}",
                    header.kv_count
                ));
                break;
            }
        }
    }

    let complete = stopped.is_none();
    if let Some(mut detail) = stopped {
        if clipped_by_limit {
            detail.push_str(&format!(
                "; the reader is bounded to {max_window} bytes of header and metadata"
            ));
        }
        note(&mut out, &mut suppressed, detail);
    }

    emit_facts(&header, &kv, pairs_read, r.pos, &mut out, &mut suppressed);

    if suppressed > 0 {
        out.note(
            NOTE_ID,
            format!("{suppressed} further metadata problems not listed individually"),
        );
    }
    if complete {
        out.note(
            NOTE_OK,
            format!(
                "GGUF version {} header and all {} metadata pairs read; tensor data not read",
                header.version, header.kv_count
            ),
        );
    }
    Ok(out)
}

struct Header {
    version: u32,
    tensor_count: u64,
    kv_count: u64,
}

/// The fixed 24-byte header. Every failure here is an error rather than a note: if
/// this does not read, there is no stream to walk and nothing to report about.
fn read_fixed_header(r: &mut Reader<'_>, limits: &Limits) -> ClResult<Header> {
    let magic = r
        .take(4)
        .map_err(|d| ClError::malformed("gguf_header", 0, format!("magic could not be read: {d}")))?;
    if magic != MAGIC {
        return Err(ClError::malformed(
            "gguf_header",
            0,
            format!("leading bytes {magic:02x?} are not the GGUF magic"),
        ));
    }
    let version = r
        .u32()
        .map_err(|d| ClError::malformed("gguf_header", 4, format!("version could not be read: {d}")))?;
    if !(MIN_VERSION..=MAX_VERSION).contains(&version) {
        return Err(ClError::malformed(
            "gguf_header",
            4,
            format!("version {version} is outside the supported range {MIN_VERSION}..={MAX_VERSION}"),
        ));
    }
    let tensor_count = r
        .u64()
        .map_err(|d| ClError::malformed("gguf_header", 8, format!("tensor count could not be read: {d}")))?;
    let kv_count = r
        .u64()
        .map_err(|d| ClError::malformed("gguf_header", 16, format!("pair count could not be read: {d}")))?;

    let max_pairs = limits.json_max_object_keys as u64;
    if kv_count > max_pairs {
        return Err(ClError::LimitExceeded {
            limit: "json_max_object_keys",
            value: kv_count,
            max: max_pairs,
        });
    }
    // A count that the supplied bytes could not hold even if every pair were minimal
    // is refused before the loop, so a fabricated count cannot drive a long walk.
    let capacity = r.remaining() / MIN_PAIR_BYTES;
    if kv_count > capacity {
        return Err(ClError::malformed(
            "gguf_header",
            16,
            format!(
                "{kv_count} metadata pairs are declared, more than the {} readable bytes could hold",
                r.remaining()
            ),
        ));
    }
    Ok(Header { version, tensor_count, kv_count })
}

/// Read one key/value pair. `Ok(None)` means the pair was framed correctly but its
/// key was not usable, so the value was consumed and discarded; the walk continues.
fn read_pair(
    r: &mut Reader<'_>,
    limits: &Limits,
    out: &mut ParseOutput,
    suppressed: &mut usize,
) -> Result<Option<(String, Scalar)>, String> {
    let key = match read_string(r, limits)? {
        StrRead::Text(s) => Some(s),
        StrRead::NotUtf8(n) => {
            note(
                out,
                suppressed,
                format!("a {n}-byte metadata key is not valid UTF-8; the pair is skipped"),
            );
            None
        }
    };
    let code = r.u32()?;
    let vtype = VType::from_code(code)
        .ok_or_else(|| format!("value type {code} is not one of the thirteen GGUF value types"))?;
    let value = read_value(r, vtype, limits, out, suppressed)?;
    Ok(key.map(|k| (k, value)))
}

fn read_value(
    r: &mut Reader<'_>,
    vtype: VType,
    limits: &Limits,
    out: &mut ParseOutput,
    suppressed: &mut usize,
) -> Result<Scalar, String> {
    Ok(match vtype {
        VType::U8 => Scalar::Int(i64::from(r.u8()?)),
        VType::I8 => Scalar::Int(i64::from(r.u8()? as i8)),
        VType::U16 => Scalar::Int(i64::from(r.u16()?)),
        VType::I16 => Scalar::Int(i64::from(r.u16()? as i16)),
        VType::U32 => Scalar::Int(i64::from(r.u32()?)),
        VType::I32 => Scalar::Int(i64::from(r.u32()? as i32)),
        VType::I64 => Scalar::Int(r.u64()? as i64),
        VType::U64 => {
            let raw = r.u64()?;
            match i64::try_from(raw) {
                Ok(v) => Scalar::Int(v),
                Err(_) => {
                    note(
                        out,
                        suppressed,
                        format!("a uint64 value of {raw} is outside the signed 64-bit range a fact can carry"),
                    );
                    Scalar::Opaque
                }
            }
        }
        VType::F32 => Scalar::Num(format!("{:?}", f32::from_bits(r.u32()?))),
        VType::F64 => Scalar::Num(format!("{:?}", f64::from_bits(r.u64()?))),
        VType::Bool => {
            let raw = r.u8()?;
            match raw {
                0 => Scalar::Bool(false),
                1 => Scalar::Bool(true),
                other => {
                    note(
                        out,
                        suppressed,
                        format!("a bool value holds the byte 0x{other:02x}, which is neither 0 nor 1"),
                    );
                    Scalar::Opaque
                }
            }
        }
        VType::Str => match read_string(r, limits)? {
            StrRead::Text(s) => Scalar::Str(s),
            StrRead::NotUtf8(n) => {
                note(
                    out,
                    suppressed,
                    format!("a {n}-byte metadata value is not valid UTF-8; no value is taken from it"),
                );
                Scalar::Opaque
            }
        },
        VType::Array => {
            read_array(r, limits, out, suppressed)?;
            Scalar::Opaque
        }
    })
}

/// A length-prefixed string. The declared length is checked against the configured
/// bound and against the bytes that remain *before* anything is copied out of it.
fn read_string(r: &mut Reader<'_>, limits: &Limits) -> Result<StrRead, String> {
    let len = r.u64()?;
    let max = limits.json_max_string_bytes as u64;
    if len > max {
        return Err(format!("a string of {len} bytes exceeds the {max}-byte bound on one string"));
    }
    if len > r.remaining() {
        return Err(format!(
            "a string declares {len} bytes but only {} remain",
            r.remaining()
        ));
    }
    let raw = r.take(len)?;
    Ok(match std::str::from_utf8(raw) {
        Ok(s) => StrRead::Text(s.to_string()),
        Err(_) => StrRead::NotUtf8(len),
    })
}

/// Walk an array to keep the stream aligned. Elements are not retained.
///
/// An array of arrays is refused rather than recursed into: nesting is the one shape
/// in this format that could drive unbounded recursion, and no GGUF writer produces
/// it, so refusing costs nothing a real file needs.
fn read_array(
    r: &mut Reader<'_>,
    limits: &Limits,
    out: &mut ParseOutput,
    suppressed: &mut usize,
) -> Result<(), String> {
    let code = r.u32()?;
    let elem = VType::from_code(code)
        .ok_or_else(|| format!("an array declares element type {code}, which is not a GGUF value type"))?;
    if elem == VType::Array {
        return Err("an array declares array elements; nested arrays are refused rather than walked".to_string());
    }
    let count = r.u64()?;
    let max = limits.json_max_array_elements as u64;
    if count > max {
        return Err(format!(
            "an array declares {count} elements of {}, beyond the {max}-element bound",
            elem.name()
        ));
    }
    match elem.fixed_width() {
        Some(width) => {
            let span = count.checked_mul(width).ok_or_else(|| {
                format!("an array of {count} {} elements has a byte length that overflows", elem.name())
            })?;
            if span > r.remaining() {
                return Err(format!(
                    "an array declares {span} bytes of {} elements but only {} remain",
                    elem.name(),
                    r.remaining()
                ));
            }
            r.take(span)?;
        }
        None => {
            let mut not_utf8: u64 = 0;
            for _ in 0..count {
                if let StrRead::NotUtf8(_) = read_string(r, limits)? {
                    not_utf8 = not_utf8.saturating_add(1);
                }
            }
            if not_utf8 > 0 {
                note(
                    out,
                    suppressed,
                    format!("{not_utf8} of {count} string elements in an array are not valid UTF-8"),
                );
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Facts
// ---------------------------------------------------------------------------

fn emit_facts(
    header: &Header,
    kv: &BTreeMap<String, Scalar>,
    pairs_read: u64,
    bytes_read: usize,
    out: &mut ParseOutput,
    suppressed: &mut usize,
) {
    let mut file = PendingFact::new(FactKind::TensorHeader)
        .with("gguf_version", i64::from(header.version))
        .with("metadata_kv_declared", header.kv_count)
        .with("metadata_kv_read", pairs_read)
        .with("metadata_bytes_read", bytes_read);
    match i64::try_from(header.tensor_count) {
        Ok(n) => file = file.with("tensor_count", n),
        Err(_) => note(
            out,
            suppressed,
            format!(
                "the header declares {} tensors, outside the signed 64-bit range a fact can carry",
                header.tensor_count
            ),
        ),
    }
    out.push(file);

    // Fact one: the parser-chosen, closed set of fields.
    let arch = kv.get("general.architecture").and_then(scalar_text);
    let mut summary = PendingFact::new(FactKind::ModelConfig);
    let mut taken: BTreeSet<String> = BTreeSet::new();
    let mut have_summary = false;

    for key in ["general.architecture", "general.name"] {
        if let Some(text) = kv.get(key).and_then(scalar_text) {
            summary = summary.with(key, text.to_string());
            taken.insert(key.to_string());
            have_summary = true;
        }
    }
    let file_type = kv.get("general.file_type").and_then(scalar_int);
    for key in ["general.file_type", "general.quantization_version"] {
        if let Some(v) = kv.get(key).and_then(scalar_int) {
            summary = summary.with(key, v);
            taken.insert(key.to_string());
            have_summary = true;
        }
    }
    for (leaf, field, key_field) in [
        ("context_length", "context_length", "context_length_key"),
        ("block_count", "block_count", "block_count_key"),
    ] {
        if let Some((source_key, value)) = suffix_int(kv, arch, leaf, out, suppressed) {
            summary = summary.with(field, value).with(key_field, source_key.clone());
            taken.insert(source_key);
            have_summary = true;
        }
    }
    if have_summary {
        out.push(summary);
    }

    // Fact two: every other scalar key, verbatim, so a vendor key cannot shadow one
    // of the parser-derived fields above.
    let mut verbatim = PendingFact::new(FactKind::ModelConfig);
    let mut have_verbatim = false;
    for (key, value) in kv {
        if taken.contains(key) {
            continue;
        }
        let field = match value {
            Scalar::Int(i) => FieldValue::Int(*i),
            Scalar::Num(s) => FieldValue::Num(s.clone()),
            Scalar::Bool(b) => FieldValue::Bool(*b),
            Scalar::Str(s) => FieldValue::Text(s.clone()),
            Scalar::Opaque => continue,
        };
        verbatim = verbatim.with(key.clone(), field);
        have_verbatim = true;
    }
    if have_verbatim {
        out.push(verbatim);
    }

    if let Some(ft) = file_type {
        match file_type_name(ft) {
            Some((name, true)) => {
                out.push(
                    PendingFact::new(FactKind::QuantizationRecord)
                        .with("file_type", ft)
                        .with("file_type_name", name)
                        .with("reason", format!("`general.file_type` = {ft} denotes {name} storage")),
                );
            }
            // A full-precision file type is recorded in the config fact and produces
            // no quantisation record, because presence of that record is what a rule
            // reads as an indication of quantised storage.
            Some((_, false)) => {}
            None => note(
                out,
                suppressed,
                format!("`general.file_type` = {ft} is outside this reader's table; the storage type is not established"),
            ),
        }
    }
}

/// Find an architecture-prefixed key such as `llama.context_length`.
///
/// The exact `<architecture>.<leaf>` key wins. Failing that, a single key ending in
/// `.<leaf>` is taken; several are an ambiguity and none is recorded, because picking
/// one would be the scanner choosing which of the vendor's numbers to believe.
fn suffix_int(
    kv: &BTreeMap<String, Scalar>,
    arch: Option<&str>,
    leaf: &str,
    out: &mut ParseOutput,
    suppressed: &mut usize,
) -> Option<(String, i64)> {
    if let Some(a) = arch {
        let exact = format!("{a}.{leaf}");
        if let Some(v) = kv.get(&exact).and_then(scalar_int) {
            return Some((exact, v));
        }
    }
    let dotted = format!(".{leaf}");
    let hits: Vec<(&String, i64)> = kv
        .iter()
        .filter(|(k, _)| k.ends_with(&dotted))
        .filter_map(|(k, v)| scalar_int(v).map(|i| (k, i)))
        .collect();
    match hits.split_first() {
        None => None,
        Some((&(key, value), rest)) if rest.is_empty() => Some((key.clone(), value)),
        Some(_) => {
            note(
                out,
                suppressed,
                format!(
                    "{} keys end in `{dotted}` and no architecture selects one; none is recorded",
                    hits.len()
                ),
            );
            None
        }
    }
}

/// GGML file type codes, and whether the code denotes quantised storage.
///
/// Only codes this reader is confident about are listed. Codes 5 and 6 were withdrawn
/// from the format and are deliberately absent, so a file declaring one is reported as
/// unrecognised rather than given a name it no longer has. An unknown code produces a
/// note and no quantisation record: "I do not know" is not "not quantised".
fn file_type_name(code: i64) -> Option<(&'static str, bool)> {
    Some(match code {
        0 => ("all F32", false),
        1 => ("mostly F16", false),
        2 => ("mostly Q4_0", true),
        3 => ("mostly Q4_1", true),
        4 => ("mostly Q4_1 with F16 embeddings", true),
        7 => ("mostly Q8_0", true),
        8 => ("mostly Q5_0", true),
        9 => ("mostly Q5_1", true),
        10 => ("mostly Q2_K", true),
        11 => ("mostly Q3_K_S", true),
        12 => ("mostly Q3_K_M", true),
        13 => ("mostly Q3_K_L", true),
        14 => ("mostly Q4_K_S", true),
        15 => ("mostly Q4_K_M", true),
        16 => ("mostly Q5_K_S", true),
        17 => ("mostly Q5_K_M", true),
        18 => ("mostly Q6_K", true),
        _ => return None,
    })
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

    /// Hand-builds GGUF byte sequences. The pair count is written by the caller so
    /// that a file can declare more pairs than it contains.
    struct Build {
        v: Vec<u8>,
    }

    impl Build {
        fn new(version: u32, tensors: u64, pairs: u64) -> Self {
            let mut v = MAGIC.to_vec();
            v.extend_from_slice(&version.to_le_bytes());
            v.extend_from_slice(&tensors.to_le_bytes());
            v.extend_from_slice(&pairs.to_le_bytes());
            Build { v }
        }
        fn raw(&mut self, b: &[u8]) {
            self.v.extend_from_slice(b);
        }
        fn lp(&mut self, b: &[u8]) {
            self.raw(&(b.len() as u64).to_le_bytes());
            self.raw(b);
        }
        fn head(&mut self, key: &str, code: u32) {
            self.lp(key.as_bytes());
            self.raw(&code.to_le_bytes());
        }
        fn str(mut self, key: &str, val: &str) -> Self {
            self.head(key, 8);
            self.lp(val.as_bytes());
            self
        }
        fn u32v(mut self, key: &str, val: u32) -> Self {
            self.head(key, 4);
            self.raw(&val.to_le_bytes());
            self
        }
        fn u64v(mut self, key: &str, val: u64) -> Self {
            self.head(key, 10);
            self.raw(&val.to_le_bytes());
            self
        }
        fn i32v(mut self, key: &str, val: i32) -> Self {
            self.head(key, 5);
            self.raw(&val.to_le_bytes());
            self
        }
        fn f32v(mut self, key: &str, val: f32) -> Self {
            self.head(key, 6);
            self.raw(&val.to_bits().to_le_bytes());
            self
        }
        fn f64v(mut self, key: &str, val: f64) -> Self {
            self.head(key, 12);
            self.raw(&val.to_bits().to_le_bytes());
            self
        }
        fn boolv(mut self, key: &str, raw: u8) -> Self {
            self.head(key, 7);
            self.v.push(raw);
            self
        }
        fn arr_u32(mut self, key: &str, vals: &[u32]) -> Self {
            self.head(key, 9);
            self.raw(&4u32.to_le_bytes());
            self.raw(&(vals.len() as u64).to_le_bytes());
            for x in vals {
                self.raw(&x.to_le_bytes());
            }
            self
        }
        fn arr_str(mut self, key: &str, vals: &[&str]) -> Self {
            self.head(key, 9);
            self.raw(&8u32.to_le_bytes());
            self.raw(&(vals.len() as u64).to_le_bytes());
            for s in vals {
                self.lp(s.as_bytes());
            }
            self
        }
        /// An array header with a declared count that the body does not contain.
        fn arr_header(mut self, key: &str, elem: u32, count: u64) -> Self {
            self.head(key, 9);
            self.raw(&elem.to_le_bytes());
            self.raw(&count.to_le_bytes());
            self
        }
        fn bytes(&self) -> &[u8] {
            &self.v
        }
    }

    fn lim() -> Limits {
        Limits::default()
    }

    fn ok(b: &[u8]) -> ParseOutput {
        parse_metadata(b, &lim()).expect("expected a parse")
    }

    fn file_fact(out: &ParseOutput) -> &PendingFact {
        out.facts_of(FactKind::TensorHeader).next().expect("file fact")
    }

    /// The parser-derived config fact is the one carrying a `general.*` key or a
    /// normalised length; the verbatim fact never does.
    fn summary(out: &ParseOutput) -> Option<&PendingFact> {
        out.facts_of(FactKind::ModelConfig).find(|f| {
            f.get("general.architecture").is_some()
                || f.get("general.name").is_some()
                || f.get("general.file_type").is_some()
                || f.get("general.quantization_version").is_some()
                || f.get("context_length").is_some()
                || f.get("block_count").is_some()
        })
    }

    fn verbatim(out: &ParseOutput) -> Option<&PendingFact> {
        let s = summary(out).cloned();
        out.facts_of(FactKind::ModelConfig).find(|f| Some(*f) != s.as_ref())
    }

    // -- happy path ---------------------------------------------------------

    #[test]
    fn reads_a_header_with_no_metadata() {
        let out = ok(Build::new(3, 0, 0).bytes());
        assert!(out.has_note(NOTE_OK));
        assert!(!out.has_note(NOTE_ID), "{:?}", out.notes);
        let f = file_fact(&out);
        assert_eq!(f.get("tensor_count"), Some(&FieldValue::Int(0)));
        assert_eq!(f.get("gguf_version"), Some(&FieldValue::Int(3)));
        assert_eq!(f.get("metadata_kv_declared"), Some(&FieldValue::Int(0)));
        assert_eq!(f.get("metadata_kv_read"), Some(&FieldValue::Int(0)));
        assert!(summary(&out).is_none(), "nothing may be invented from an empty block");
        assert!(out.facts_of(FactKind::QuantizationRecord).next().is_none());
    }

    #[test]
    fn reads_the_named_configuration_fields() {
        let b = Build::new(3, 291, 6)
            .str("general.architecture", "llama")
            .str("general.name", "Vendor Model 7B")
            .u32v("general.file_type", 15)
            .u32v("general.quantization_version", 2)
            .u32v("llama.context_length", 4096)
            .u32v("llama.block_count", 32);
        let out = ok(b.bytes());
        assert!(out.has_note(NOTE_OK));
        let s = summary(&out).expect("summary fact");
        assert_eq!(s.get("general.architecture"), Some(&FieldValue::Text("llama".into())));
        assert_eq!(s.get("general.name"), Some(&FieldValue::Text("Vendor Model 7B".into())));
        assert_eq!(s.get("general.file_type"), Some(&FieldValue::Int(15)));
        assert_eq!(s.get("general.quantization_version"), Some(&FieldValue::Int(2)));
        assert_eq!(s.get("context_length"), Some(&FieldValue::Int(4096)));
        assert_eq!(s.get("block_count"), Some(&FieldValue::Int(32)));
        assert_eq!(
            s.get("context_length_key"),
            Some(&FieldValue::Text("llama.context_length".into()))
        );
        assert_eq!(file_fact(&out).get("tensor_count"), Some(&FieldValue::Int(291)));
    }

    #[test]
    fn quantisation_record_follows_the_file_type() {
        let out = ok(Build::new(3, 1, 1).u32v("general.file_type", 15).bytes());
        let q = out.facts_of(FactKind::QuantizationRecord).next().expect("record");
        assert_eq!(q.get("file_type"), Some(&FieldValue::Int(15)));
        assert_eq!(q.get("file_type_name"), Some(&FieldValue::Text("mostly Q4_K_M".into())));
    }

    #[test]
    fn full_precision_file_types_produce_no_quantisation_record() {
        for ft in [0u32, 1] {
            let out = ok(Build::new(3, 1, 1).u32v("general.file_type", ft).bytes());
            assert!(
                out.facts_of(FactKind::QuantizationRecord).next().is_none(),
                "file_type {ft} must not be recorded as quantised"
            );
            assert!(!out.has_note(NOTE_ID), "file_type {ft}: {:?}", out.notes);
        }
    }

    #[test]
    fn an_unknown_file_type_is_a_note_and_never_a_guess() {
        for ft in [5u32, 6, 900] {
            let out = ok(Build::new(3, 1, 1).u32v("general.file_type", ft).bytes());
            assert!(out.facts_of(FactKind::QuantizationRecord).next().is_none());
            assert!(out.has_note(NOTE_ID), "file_type {ft}");
            // The value itself is still reported: only its meaning is withheld.
            assert_eq!(
                summary(&out).and_then(|f| f.get("general.file_type")),
                Some(&FieldValue::Int(i64::from(ft)))
            );
        }
    }

    #[test]
    fn floats_keep_their_exact_printed_text() {
        let b = Build::new(3, 0, 3)
            .f32v("a.epsilon", 1.0e-5)
            .f32v("a.tenth", 0.1)
            .f64v("a.wide", 0.1);
        let out = ok(b.bytes());
        let v = verbatim(&out).expect("verbatim fact");
        // 0.1f32 widened to f64 would print 0.10000000149011612; it must not be.
        assert_eq!(v.get("a.tenth"), Some(&FieldValue::Num("0.1".into())));
        assert_eq!(v.get("a.wide"), Some(&FieldValue::Num("0.1".into())));
        assert_eq!(v.get("a.epsilon"), Some(&FieldValue::Num("1e-5".into())));
    }

    #[test]
    fn every_scalar_type_round_trips_into_a_field() {
        let b = Build::new(3, 0, 4)
            .i32v("s.negative", -7)
            .u64v("s.big", 9_000_000_000)
            .boolv("s.flag", 1)
            .str("s.text", "value");
        let out = ok(b.bytes());
        let v = verbatim(&out).expect("verbatim fact");
        assert_eq!(v.get("s.negative"), Some(&FieldValue::Int(-7)));
        assert_eq!(v.get("s.big"), Some(&FieldValue::Int(9_000_000_000)));
        assert_eq!(v.get("s.flag"), Some(&FieldValue::Bool(true)));
        assert_eq!(v.get("s.text"), Some(&FieldValue::Text("value".into())));
    }

    #[test]
    fn arrays_are_walked_and_the_next_pair_still_reads() {
        let b = Build::new(3, 0, 3)
            .arr_str("tokenizer.ggml.tokens", &["a", "bb", "ccc"])
            .arr_u32("tokenizer.ggml.token_type", &[1, 2, 3])
            .str("general.architecture", "llama");
        let out = ok(b.bytes());
        assert!(out.has_note(NOTE_OK), "{:?}", out.notes);
        assert_eq!(
            summary(&out).and_then(|f| f.get("general.architecture")),
            Some(&FieldValue::Text("llama".into()))
        );
        // Array contents are not carried into facts.
        assert!(verbatim(&out).and_then(|f| f.get("tokenizer.ggml.tokens")).is_none());
    }

    #[test]
    fn output_is_identical_for_identical_bytes() {
        let b = Build::new(3, 2, 2).str("general.architecture", "llama").u32v("llama.block_count", 4);
        assert_eq!(ok(b.bytes()), ok(b.bytes()));
    }

    // -- framing abuse ------------------------------------------------------

    #[test]
    fn empty_file_is_an_error_not_a_panic() {
        assert!(parse_metadata(&[], &lim()).is_err());
    }

    #[test]
    fn short_files_error_at_every_length_below_the_fixed_header() {
        let full = Build::new(3, 0, 0);
        for k in 0..full.bytes().len() {
            assert!(
                parse_metadata(&full.bytes()[..k], &lim()).is_err(),
                "prefix of {k} bytes must not parse"
            );
        }
    }

    #[test]
    fn wrong_magic_is_refused() {
        let mut v = b"GGUX".to_vec();
        v.extend_from_slice(&3u32.to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes());
        assert!(matches!(parse_metadata(&v, &lim()), Err(ClError::Malformed { .. })));
    }

    #[test]
    fn only_versions_one_to_three_are_accepted() {
        for v in [0u32, 4, u32::MAX] {
            assert!(parse_metadata(Build::new(v, 0, 0).bytes(), &lim()).is_err(), "version {v}");
        }
        for v in [1u32, 2, 3] {
            assert!(parse_metadata(Build::new(v, 0, 0).bytes(), &lim()).is_ok(), "version {v}");
        }
    }

    #[test]
    fn a_pair_count_of_u64_max_is_refused_before_any_walk() {
        match parse_metadata(Build::new(3, 0, u64::MAX).bytes(), &lim()) {
            Err(ClError::LimitExceeded { limit, max, .. }) => {
                assert_eq!(limit, "json_max_object_keys");
                assert_eq!(max, lim().json_max_object_keys as u64);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_pair_count_the_bytes_cannot_hold_is_refused() {
        // Within the configured key limit, but far more pairs than bytes supplied.
        let b = Build::new(3, 0, 4096).str("general.architecture", "llama");
        assert!(matches!(parse_metadata(b.bytes(), &lim()), Err(ClError::Malformed { .. })));
    }

    #[test]
    fn a_tensor_count_beyond_i64_is_noted_and_never_clamped() {
        let out = ok(Build::new(3, u64::MAX, 0).bytes());
        assert!(file_fact(&out).get("tensor_count").is_none());
        assert!(out.has_note(NOTE_ID));
    }

    #[test]
    fn truncation_at_every_boundary_never_panics_and_never_fabricates() {
        let b = Build::new(3, 1, 2)
            .str("general.architecture", "llama")
            .u32v("llama.block_count", 32);
        let full = b.bytes();
        for k in 0..full.len() {
            match parse_metadata(&full[..k], &lim()) {
                Err(_) => {}
                Ok(out) => {
                    assert!(!out.has_note(NOTE_OK), "prefix of {k} bytes claimed a complete read");
                    assert!(out.has_note(NOTE_ID), "prefix of {k} bytes recorded no limitation");
                    // Whatever survived must be a prefix of the real content.
                    if let Some(s) = summary(&out) {
                        if let Some(FieldValue::Text(t)) = s.get("general.architecture") {
                            assert_eq!(t, "llama");
                        }
                    }
                }
            }
        }
        assert!(parse_metadata(full, &lim()).expect("full parse").has_note(NOTE_OK));
    }

    #[test]
    fn a_string_length_of_u64_max_stops_the_walk() {
        let mut b = Build::new(3, 0, 1);
        b.raw(&u64::MAX.to_le_bytes());
        b.raw(b"key");
        // Padding so the declared pair count clears the up-front capacity gate. That
        // gate refuses a header whose byte count could not hold even one minimal
        // pair; without the padding this fixture would be rejected there and would
        // never reach the walk it is meant to exercise.
        b.raw(&[0u8; 16]);
        let out = ok(b.bytes());
        assert!(out.has_note(NOTE_ID));
        assert!(!out.has_note(NOTE_OK));
        assert!(summary(&out).is_none(), "no fact may be built from an unread pair");
    }

    #[test]
    fn a_string_longer_than_the_buffer_stops_the_walk() {
        let mut b = Build::new(3, 0, 2).str("general.architecture", "llama");
        b.raw(&64u64.to_le_bytes());
        b.raw(b"short");
        let out = ok(b.bytes());
        assert!(out.has_note(NOTE_ID));
        assert!(!out.has_note(NOTE_OK));
        // The pair that did read is still reported; the one that did not is not.
        assert_eq!(
            summary(&out).and_then(|f| f.get("general.architecture")),
            Some(&FieldValue::Text("llama".into()))
        );
        assert_eq!(file_fact(&out).get("metadata_kv_read"), Some(&FieldValue::Int(1)));
        assert_eq!(file_fact(&out).get("metadata_kv_declared"), Some(&FieldValue::Int(2)));
    }

    #[test]
    fn an_unknown_value_type_stops_the_walk() {
        let mut b = Build::new(3, 0, 1);
        b.head("general.name", 13);
        b.raw(&[0u8; 8]);
        let out = ok(b.bytes());
        assert!(out.has_note(NOTE_ID));
        assert!(out.notes.iter().any(|n| n.detail.contains("13")), "{:?}", out.notes);
        assert!(summary(&out).is_none());
    }

    #[test]
    fn a_huge_array_count_is_refused_before_allocation() {
        let b = Build::new(3, 0, 1).arr_header("tokenizer.ggml.tokens", 8, u64::MAX);
        let out = ok(b.bytes());
        assert!(out.has_note(NOTE_ID));
        assert!(!out.has_note(NOTE_OK));
    }

    #[test]
    fn a_fixed_width_array_longer_than_the_buffer_is_refused() {
        let b = Build::new(3, 0, 1).arr_header("a.list", 4, 1_000_000);
        let out = ok(b.bytes());
        assert!(out.has_note(NOTE_ID));
        assert!(!out.has_note(NOTE_OK));
    }

    #[test]
    fn nested_arrays_are_refused_rather_than_recursed_into() {
        let b = Build::new(3, 0, 1).arr_header("a.nested", 9, 4);
        let out = ok(b.bytes());
        assert!(out.has_note(NOTE_ID));
        assert!(
            out.notes.iter().any(|n| n.detail.contains("nested arrays are refused")),
            "{:?}",
            out.notes
        );
    }

    #[test]
    fn an_array_of_an_unknown_element_type_is_refused() {
        let b = Build::new(3, 0, 1).arr_header("a.weird", 42, 1);
        let out = ok(b.bytes());
        assert!(out.has_note(NOTE_ID));
        assert!(!out.has_note(NOTE_OK));
    }

    #[test]
    fn random_bytes_do_not_produce_facts() {
        let mut v: Vec<u8> = Vec::new();
        for i in 0..1024u32 {
            v.push((i.wrapping_mul(2_654_435_761) >> 11) as u8);
        }
        match parse_metadata(&v, &lim()) {
            Err(_) => {}
            Ok(out) => assert!(summary(&out).is_none()),
        }
        // The same bytes behind a valid fixed header must also stay harmless.
        let mut b = Build::new(3, 0, 8);
        b.raw(&v);
        match parse_metadata(b.bytes(), &lim()) {
            Err(_) => {}
            Ok(out) => assert!(!out.has_note(NOTE_OK) || summary(&out).is_none()),
        }
    }

    // -- values that read but cannot be carried ------------------------------

    #[test]
    fn a_duplicate_key_is_dropped_rather_than_resolved() {
        let b = Build::new(3, 0, 3)
            .str("general.architecture", "llama")
            .str("general.architecture", "mistral")
            .u32v("llama.block_count", 8);
        let out = ok(b.bytes());
        assert!(out.has_note(NOTE_ID));
        let s = summary(&out).expect("block count still reported");
        assert!(
            s.get("general.architecture").is_none(),
            "a key declared twice must contribute nothing"
        );
        assert_eq!(s.get("block_count"), Some(&FieldValue::Int(8)));
    }

    #[test]
    fn a_third_occurrence_cannot_resurrect_a_dropped_key() {
        let b = Build::new(3, 0, 3)
            .str("general.name", "one")
            .str("general.name", "two")
            .str("general.name", "three");
        let out = ok(b.bytes());
        assert!(summary(&out).is_none());
    }

    #[test]
    fn a_key_that_is_not_utf8_skips_the_pair_and_keeps_walking() {
        let mut b = Build::new(3, 0, 2);
        b.lp(&[0xff, 0xfe, 0xfd]);
        b.raw(&8u32.to_le_bytes());
        b.lp(b"ignored");
        let b = b.str("general.architecture", "llama");
        let out = ok(b.bytes());
        assert!(out.has_note(NOTE_ID));
        assert!(out.has_note(NOTE_OK), "the walk completed: {:?}", out.notes);
        assert_eq!(
            summary(&out).and_then(|f| f.get("general.architecture")),
            Some(&FieldValue::Text("llama".into()))
        );
    }

    #[test]
    fn a_bool_byte_that_is_neither_zero_nor_one_yields_no_value() {
        let b = Build::new(3, 0, 2).boolv("a.flag", 2).str("general.architecture", "llama");
        let out = ok(b.bytes());
        assert!(out.has_note(NOTE_ID));
        assert!(out.has_note(NOTE_OK));
        assert!(verbatim(&out).and_then(|f| f.get("a.flag")).is_none());
    }

    #[test]
    fn a_uint64_beyond_i64_yields_no_value_rather_than_a_clamp() {
        let b = Build::new(3, 0, 2).u64v("a.huge", u64::MAX).str("general.architecture", "llama");
        let out = ok(b.bytes());
        assert!(out.has_note(NOTE_ID));
        assert!(out.has_note(NOTE_OK));
        assert!(verbatim(&out).and_then(|f| f.get("a.huge")).is_none());
    }

    // -- key selection ------------------------------------------------------

    #[test]
    fn the_architecture_prefix_selects_between_competing_keys() {
        let b = Build::new(3, 0, 3)
            .str("general.architecture", "llama")
            .u32v("llama.context_length", 4096)
            .u32v("falcon.context_length", 2048);
        let out = ok(b.bytes());
        let s = summary(&out).expect("summary");
        assert_eq!(s.get("context_length"), Some(&FieldValue::Int(4096)));
        assert_eq!(
            s.get("context_length_key"),
            Some(&FieldValue::Text("llama.context_length".into()))
        );
        // The one not selected is still visible verbatim.
        assert_eq!(
            verbatim(&out).and_then(|f| f.get("falcon.context_length")),
            Some(&FieldValue::Int(2048))
        );
    }

    #[test]
    fn competing_length_keys_with_no_architecture_record_nothing() {
        let b = Build::new(3, 0, 2)
            .u32v("llama.context_length", 4096)
            .u32v("falcon.context_length", 2048);
        let out = ok(b.bytes());
        assert!(summary(&out).is_none());
        assert!(out.has_note(NOTE_ID));
    }

    #[test]
    fn a_lone_length_key_is_taken_without_an_architecture() {
        let out = ok(Build::new(3, 0, 1).u32v("phi3.block_count", 32).bytes());
        let s = summary(&out).expect("summary");
        assert_eq!(s.get("block_count"), Some(&FieldValue::Int(32)));
        assert_eq!(s.get("block_count_key"), Some(&FieldValue::Text("phi3.block_count".into())));
    }

    #[test]
    fn a_vendor_key_cannot_shadow_a_parser_derived_field() {
        // A vendor key literally called `context_length` lands in the verbatim fact,
        // never in the fact a rule reads for the architecture-prefixed value.
        let b = Build::new(3, 0, 3)
            .str("general.architecture", "llama")
            .u32v("llama.context_length", 4096)
            .u32v("context_length", 999_999);
        let out = ok(b.bytes());
        assert_eq!(summary(&out).and_then(|f| f.get("context_length")), Some(&FieldValue::Int(4096)));
        assert_eq!(
            verbatim(&out).and_then(|f| f.get("context_length")),
            Some(&FieldValue::Int(999_999))
        );
    }

    // -- limits -------------------------------------------------------------

    #[test]
    fn the_tiny_profile_bounds_strings_and_arrays() {
        let tiny = Limits::tiny();
        let long = "x".repeat(tiny.json_max_string_bytes + 1);
        let out = parse_metadata(Build::new(3, 0, 1).str("a.long", &long).bytes(), &tiny).expect("parse");
        assert!(out.has_note(NOTE_ID));
        assert!(!out.has_note(NOTE_OK));

        let over = tiny.json_max_array_elements as u64 + 1;
        let out = parse_metadata(Build::new(3, 0, 1).arr_header("a.list", 0, over).bytes(), &tiny)
            .expect("parse");
        assert!(out.has_note(NOTE_ID));
    }

    #[test]
    fn the_pair_count_limit_comes_from_the_profile() {
        let tiny = Limits::tiny();
        let over = tiny.json_max_object_keys as u64 + 1;
        match parse_metadata(Build::new(3, 0, over).bytes(), &tiny) {
            Err(ClError::LimitExceeded { limit, value, .. }) => {
                assert_eq!(limit, "json_max_object_keys");
                assert_eq!(value, over);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bytes_beyond_the_metadata_bound_are_never_read() {
        let tiny = Limits::tiny();
        let bound = tiny.gguf_metadata_bytes + HEADER_BYTES;
        // Few keys, long values: the declared pair count is checked against
        // `json_max_object_keys` before the walk, so a fixture with more keys than
        // that limit would be refused for the wrong reason and never test the byte
        // bound this case is named for.
        let pairs = 12usize;
        assert!(pairs <= tiny.json_max_object_keys, "fixture must clear the key-count gate");
        let filler = "y".repeat(400);
        let mut b = Build::new(3, 0, pairs as u64);
        for i in 0..pairs {
            b = b.str(&format!("pad.{i:03}"), &filler);
        }
        assert!(
            b.bytes().len() as u64 > bound,
            "fixture must exceed the {bound}-byte bound"
        );
        let out = parse_metadata(b.bytes(), &tiny).expect("parse");
        assert!(!out.has_note(NOTE_OK), "a clipped read must not claim completeness");
        assert!(
            out.notes.iter().any(|n| n.detail.contains("bounded to")),
            "{:?}",
            out.notes
        );
        let read = file_fact(&out).get("metadata_bytes_read").and_then(|v| v.as_int()).unwrap_or(0);
        assert!(read as u64 <= bound, "read {read} bytes past the {bound}-byte bound");
    }

    #[test]
    fn notes_are_capped_so_one_file_cannot_flood_the_report() {
        let mut b = Build::new(3, 0, 64);
        for _ in 0..64 {
            b = b.boolv("a.flag", 2);
        }
        let out = ok(b.bytes());
        // MAX_NOTES caps the individual notes; the rest are summarised, and the
        // success note is still allowed through.
        assert!(out.notes.len() <= MAX_NOTES + 2, "{}", out.notes.len());
        assert!(
            out.notes.iter().any(|n| n.detail.contains("not listed individually")),
            "{:?}",
            out.notes
        );
    }

    #[test]
    fn read_need_is_bounded_by_the_profile() {
        match GgufMetadata::read_need(&Limits::tiny()) {
            ReadNeed::Prefix(n) => assert_eq!(n, Limits::tiny().gguf_metadata_bytes + HEADER_BYTES),
            other => panic!("{other:?}"),
        }
    }
}
