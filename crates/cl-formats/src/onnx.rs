//! ONNX metadata, read without a protobuf library.
//!
//! ONNX is a bare protobuf message with no magic number and no length prefix. There
//! is no protobuf crate in this workspace and there will not be one: a general
//! decoder is a large amount of machinery to point at a file chosen by the party
//! under scrutiny, and we need six fields out of it.
//!
//! ## The graph is skipped by length, never walked
//!
//! `ModelProto` field 7 is the graph, and the graph is where the weights are. This
//! reader reads its length, steps over it, and never descends. That is the whole
//! design: the parser physically cannot reach tensor data, rather than choosing not
//! to. Nesting is capped at three levels and a varint at ten bytes, so a crafted
//! file cannot make the walk long or deep.
//!
//! What comes back is provenance metadata: which tool wrote the file, at which
//! version, targeting which opset, plus whatever the producer chose to record in
//! `metadata_props`. That is `E1` evidence - a producer string is written by the
//! same pipeline the vendor controls - and the rules treat it as such.

use crate::{ParseOutput, PendingFact};
use cl_core::error::{ClError, ClResult};
use cl_core::limits::Limits;
use cl_facts::{ArtifactType, FactKind};

pub const PARSER: &str = "onnx_metadata";
pub const PARSER_VERSION: i64 = 1;

/// A varint longer than this is malformed for any field we read.
const MAX_VARINT_BYTES: usize = 10;
/// How deep a nested message may go before we refuse it.
const MAX_DEPTH: usize = 3;
/// Cap on `metadata_props` entries recorded.
const MAX_PROPS: usize = 256;

/// Wire types we understand. Anything else ends the walk.
const WIRE_VARINT: u64 = 0;
const WIRE_I64: u64 = 1;
const WIRE_LEN: u64 = 2;
const WIRE_I32: u64 = 5;

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, i: 0 }
    }

    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.i)
    }

    fn varint(&mut self) -> ClResult<u64> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        let mut used = 0usize;
        loop {
            let byte = *self
                .b
                .get(self.i)
                .ok_or_else(|| ClError::malformed("onnx", self.i, "truncated varint"))?;
            self.i += 1;
            used += 1;
            if used > MAX_VARINT_BYTES {
                return Err(ClError::malformed("onnx", self.i, "over-long varint"));
            }
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift >= 64 {
                return Err(ClError::malformed("onnx", self.i, "varint out of range"));
            }
        }
    }

    /// A length-delimited field, checked against what the buffer actually holds
    /// before any slice is taken.
    fn bytes(&mut self) -> ClResult<&'a [u8]> {
        let len = self.varint()?;
        if len > self.remaining() as u64 {
            return Err(ClError::malformed(
                "onnx",
                self.i,
                format!("field declares {len} bytes, more than the {} remaining", self.remaining()),
            ));
        }
        let start = self.i;
        self.i += len as usize;
        Ok(&self.b[start..self.i])
    }

    fn skip(&mut self, wire: u64) -> ClResult<()> {
        match wire {
            WIRE_VARINT => {
                self.varint()?;
            }
            WIRE_I64 => {
                if self.remaining() < 8 {
                    return Err(ClError::malformed("onnx", self.i, "truncated 64-bit field"));
                }
                self.i += 8;
            }
            WIRE_LEN => {
                self.bytes()?;
            }
            WIRE_I32 => {
                if self.remaining() < 4 {
                    return Err(ClError::malformed("onnx", self.i, "truncated 32-bit field"));
                }
                self.i += 4;
            }
            other => {
                return Err(ClError::malformed(
                    "onnx",
                    self.i,
                    format!("unsupported wire type {other}"),
                ))
            }
        }
        Ok(())
    }
}

fn utf8(b: &[u8]) -> Option<String> {
    std::str::from_utf8(b).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// `StringStringEntryProto`: field 1 key, field 2 value.
fn string_pair(b: &[u8], depth: usize) -> ClResult<(Option<String>, Option<String>)> {
    if depth > MAX_DEPTH {
        return Err(ClError::malformed("onnx", 0, "message nested too deeply"));
    }
    let mut r = Reader::new(b);
    let (mut k, mut v) = (None, None);
    while r.remaining() > 0 {
        let tag = r.varint()?;
        let (field, wire) = (tag >> 3, tag & 7);
        match (field, wire) {
            (1, WIRE_LEN) => k = utf8(r.bytes()?),
            (2, WIRE_LEN) => v = utf8(r.bytes()?),
            _ => r.skip(wire)?,
        }
    }
    Ok((k, v))
}

/// `OperatorSetIdProto`: field 1 domain, field 2 version.
fn opset(b: &[u8], depth: usize) -> ClResult<(Option<String>, Option<i64>)> {
    if depth > MAX_DEPTH {
        return Err(ClError::malformed("onnx", 0, "message nested too deeply"));
    }
    let mut r = Reader::new(b);
    let (mut domain, mut version) = (None, None);
    while r.remaining() > 0 {
        let tag = r.varint()?;
        let (field, wire) = (tag >> 3, tag & 7);
        match (field, wire) {
            (1, WIRE_LEN) => domain = utf8(r.bytes()?),
            (2, WIRE_VARINT) => version = Some(r.varint()? as i64),
            _ => r.skip(wire)?,
        }
    }
    Ok((domain, version))
}

/// Read `ModelProto` metadata from a bounded prefix.
pub fn parse_metadata(bytes: &[u8], limits: &Limits) -> ClResult<ParseOutput> {
    let mut out = ParseOutput::new(ArtifactType::Onnx, PARSER, PARSER_VERSION);
    if bytes.is_empty() {
        return Err(ClError::malformed("onnx", 0, "empty file"));
    }
    let cap = limits.onnx_prefix_bytes.min(bytes.len() as u64) as usize;
    let slice = &bytes[..cap];
    if (bytes.len() as u64) > limits.onnx_prefix_bytes {
        out.note(
            "CL-FMT-005",
            format!(
                "read the first {} of {} bytes; ONNX metadata is at the head of the file",
                cap,
                bytes.len()
            ),
        );
    }

    let mut r = Reader::new(slice);
    let mut f = PendingFact::new(FactKind::ModelConfig).with("container", "onnx");
    let mut have = false;
    let mut props = 0usize;
    let mut graph_skipped = false;

    while r.remaining() > 0 {
        let tag = match r.varint() {
            Ok(t) => t,
            Err(e) => {
                // A truncated tail is expected when we only read a prefix.
                out.note("CL-FMT-005", format!("the metadata walk stopped early: {e}"));
                break;
            }
        };
        let (field, wire) = (tag >> 3, tag & 7);
        let step = match (field, wire) {
            (1, WIRE_VARINT) => r.varint().map(|v| {
                f = f.clone().with("ir_version", v as i64);
                have = true;
            }),
            (2, WIRE_LEN) => r.bytes().map(|b| {
                if let Some(s) = utf8(b) {
                    f = f.clone().with("producer_name", s);
                    have = true;
                }
            }),
            (3, WIRE_LEN) => r.bytes().map(|b| {
                if let Some(s) = utf8(b) {
                    f = f.clone().with("producer_version", s);
                    have = true;
                }
            }),
            (4, WIRE_LEN) => r.bytes().map(|b| {
                if let Some(s) = utf8(b) {
                    f = f.clone().with("domain", s);
                    have = true;
                }
            }),
            (5, WIRE_VARINT) => r.varint().map(|v| {
                f = f.clone().with("model_version", v as i64);
                have = true;
            }),
            // Field 7 is the graph. Step over it by length; never descend.
            (7, WIRE_LEN) => r.bytes().map(|_| {
                graph_skipped = true;
            }),
            (8, WIRE_LEN) => r.bytes().and_then(|b| {
                let (domain, version) = opset(b, 1)?;
                if let Some(v) = version {
                    let key = match domain.as_deref() {
                        None | Some("") | Some("ai.onnx") => "opset_version".to_string(),
                        Some(d) => format!("opset_version.{d}"),
                    };
                    f = f.clone().with(key, v);
                    have = true;
                }
                Ok(())
            }),
            (14, WIRE_LEN) => r.bytes().and_then(|b| {
                if props < MAX_PROPS {
                    let (k, v) = string_pair(b, 1)?;
                    if let (Some(k), Some(v)) = (k, v) {
                        f = f.clone().with(format!("metadata.{k}"), v);
                        have = true;
                        props += 1;
                    }
                }
                Ok(())
            }),
            _ => r.skip(wire),
        };
        if let Err(e) = step {
            out.note("CL-FMT-005", format!("the metadata walk stopped early: {e}"));
            break;
        }
    }

    if graph_skipped {
        f = f.with("graph_present", true);
    }
    if have {
        out.push(f);
    } else {
        out.note("CL-FMT-005", "no ONNX metadata field was readable in the prefix");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim() -> Limits {
        Limits::default()
    }

    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                return out;
            }
        }
    }

    fn tag(field: u64, wire: u64) -> Vec<u8> {
        varint((field << 3) | wire)
    }

    fn len_field(field: u64, body: &[u8]) -> Vec<u8> {
        let mut o = tag(field, WIRE_LEN);
        o.extend(varint(body.len() as u64));
        o.extend_from_slice(body);
        o
    }

    fn varint_field(field: u64, v: u64) -> Vec<u8> {
        let mut o = tag(field, WIRE_VARINT);
        o.extend(varint(v));
        o
    }

    /// A ModelProto carrying metadata and a large fake graph.
    fn model(graph_bytes: usize) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend(varint_field(1, 9)); // ir_version
        m.extend(len_field(2, b"pytorch")); // producer_name
        m.extend(len_field(3, b"2.4.0")); // producer_version
        m.extend(varint_field(5, 1)); // model_version
        let mut op = Vec::new();
        op.extend(len_field(1, b"")); // domain
        op.extend(varint_field(2, 17)); // version
        m.extend(len_field(8, &op)); // opset_import
        let mut prop = Vec::new();
        prop.extend(len_field(1, b"base_model"));
        prop.extend(len_field(2, b"Qwen/Qwen2.5-7B"));
        m.extend(len_field(14, &prop)); // metadata_props
        m.extend(len_field(7, &vec![0xAAu8; graph_bytes])); // graph
        m
    }

    fn field<'a>(out: &'a ParseOutput, key: &str) -> Option<&'a cl_facts::FieldValue> {
        out.facts_of(FactKind::ModelConfig).find_map(|f| f.get(key))
    }

    #[test]
    fn producer_and_opset_metadata_is_read() {
        let out = parse_metadata(&model(64), &lim()).unwrap();
        assert_eq!(
            field(&out, "producer_name"),
            Some(&cl_facts::FieldValue::Text("pytorch".into()))
        );
        assert_eq!(field(&out, "ir_version"), Some(&cl_facts::FieldValue::Int(9)));
        assert_eq!(field(&out, "opset_version"), Some(&cl_facts::FieldValue::Int(17)));
        assert_eq!(
            field(&out, "metadata.base_model"),
            Some(&cl_facts::FieldValue::Text("Qwen/Qwen2.5-7B".into()))
        );
    }

    #[test]
    fn the_graph_is_stepped_over_and_never_walked() {
        // The graph body is 0xAA repeated, which is not valid protobuf. If the reader
        // descended into it the walk would error; stepping over it by length must
        // leave the metadata intact and simply record that a graph was present.
        let out = parse_metadata(&model(4096), &lim()).unwrap();
        assert_eq!(field(&out, "graph_present"), Some(&cl_facts::FieldValue::Bool(true)));
        assert_eq!(
            field(&out, "producer_name"),
            Some(&cl_facts::FieldValue::Text("pytorch".into()))
        );
        // Nothing from inside the graph may appear anywhere in the output.
        for f in &out.facts {
            for (k, v) in &f.fields {
                if let cl_facts::FieldValue::Text(t) = v {
                    assert!(!t.contains('\u{aa}'), "graph bytes leaked via {k}");
                }
            }
        }
    }

    #[test]
    fn a_length_field_larger_than_the_buffer_is_refused_before_allocating() {
        let mut m = tag(2, WIRE_LEN);
        m.extend(varint(u64::MAX));
        let out = parse_metadata(&m, &lim()).unwrap();
        assert!(out.has_note("CL-FMT-005"));
        assert!(out.facts.is_empty(), "nothing may be claimed from an unreadable file");
    }

    #[test]
    fn an_over_long_varint_is_refused() {
        let mut m = tag(1, WIRE_VARINT);
        m.extend(vec![0xFFu8; 12]);
        let out = parse_metadata(&m, &lim()).unwrap();
        assert!(out.has_note("CL-FMT-005"));
    }

    #[test]
    fn truncation_at_every_boundary_never_panics() {
        let full = model(128);
        for cut in 0..full.len() {
            let _ = parse_metadata(&full[..cut], &lim());
        }
    }

    #[test]
    fn random_and_empty_bytes_are_handled() {
        assert!(parse_metadata(b"", &lim()).is_err(), "an empty file is not an ONNX model");
        for junk in [&[0xffu8; 64][..], &[0u8; 64][..], b"not protobuf at all".as_slice()] {
            let _ = parse_metadata(junk, &lim());
        }
    }

    #[test]
    fn an_unsupported_wire_type_stops_the_walk_cleanly() {
        let mut m = model(16);
        m.extend(tag(9, 3)); // wire type 3 is a deprecated group
        let out = parse_metadata(&m, &lim()).unwrap();
        // What was read before the bad tag is still reported.
        assert_eq!(
            field(&out, "producer_name"),
            Some(&cl_facts::FieldValue::Text("pytorch".into()))
        );
        assert!(out.has_note("CL-FMT-005"));
    }

    #[test]
    fn a_file_beyond_the_prefix_bound_is_noted() {
        let mut tiny = Limits::tiny();
        tiny.onnx_prefix_bytes = 32;
        let out = parse_metadata(&model(4096), &tiny).unwrap();
        assert!(out.has_note("CL-FMT-005"));
    }

    #[test]
    fn metadata_props_are_capped() {
        let mut m = Vec::new();
        m.extend(len_field(2, b"pytorch"));
        for i in 0..(MAX_PROPS + 50) {
            let mut prop = Vec::new();
            prop.extend(len_field(1, format!("k{i}").as_bytes()));
            prop.extend(len_field(2, b"v"));
            m.extend(len_field(14, &prop));
        }
        let out = parse_metadata(&m, &lim()).unwrap();
        let recorded = out
            .facts_of(FactKind::ModelConfig)
            .map(|f| f.fields.keys().filter(|k| k.starts_with("metadata.")).count())
            .sum::<usize>();
        assert!(recorded <= MAX_PROPS, "recorded {recorded} properties");
    }
}
