//! Canonical JSON (RFC 8785 / JCS) for authoritative documents.
//!
//! ## Why there is no float
//!
//! RFC 8785 exists because hashing and signing require an invariant serialisation.
//! Its hardest corner is number formatting: ECMAScript double-to-string is exact but
//! easy to implement subtly differently across languages, and `0.1 + 0.2` is a
//! reproducibility hazard that no amount of care in the serialiser removes.
//!
//! TrainTrace sidesteps the whole class of problem by removing floats from the
//! authoritative model entirely. [`CanonValue`] has no float variant, so a float
//! cannot reach a hashed or signed document even by mistake. Quantities that need a
//! fractional part are stored as integers in a named unit — `score_tenths = 743`
//! rather than `score = 74.3`.
//!
//! Vendor-supplied numbers that genuinely are fractional (`5e-5`) are retained as
//! their exact source text by [`crate::json::JsonValue::Num`] and never converted.

use crate::error::{TtError, TtResult};
use crate::hash::Digest;
use crate::json::JsonValue;
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonValue {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<CanonValue>),
    Obj(Obj),
}

/// A JSON object with unique keys by construction.
///
/// [`Obj::set`] replaces rather than appends, so a duplicate key is unrepresentable
/// and the "reject duplicates" requirement is enforced by the type rather than by a
/// check somebody can forget to call.
#[derive(Debug, Clone, Default)]
pub struct Obj {
    entries: Vec<(String, CanonValue)>,
}

/// Equality ignores insertion order.
///
/// Canonical JSON has no key order — two objects holding the same pairs serialise
/// to identical bytes and are therefore the same document. A derived `PartialEq`
/// would be stricter than the format's own notion of identity, which would make a
/// round-trip through [`parse_canonical`] appear to change a document that it did
/// not change.
impl PartialEq for Obj {
    fn eq(&self, other: &Self) -> bool {
        self.entries.len() == other.entries.len()
            && self.entries.iter().all(|(k, v)| other.get(k) == Some(v))
    }
}

impl Eq for Obj {}

impl Obj {
    pub fn new() -> Self {
        Obj { entries: Vec::new() }
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<CanonValue>) -> &mut Self {
        let key = key.into();
        let value = value.into();
        match self.entries.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = value,
            None => self.entries.push((key, value)),
        }
        self
    }

    /// Chaining form of [`Obj::set`].
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<CanonValue>) -> Self {
        self.set(key, value);
        self
    }

    /// Set only when `value` is `Some`. Absent fields are omitted, never null,
    /// because `null` and "not applicable" are different statements in a report.
    #[must_use]
    pub fn with_opt(mut self, key: impl Into<String>, value: Option<impl Into<CanonValue>>) -> Self {
        if let Some(v) = value {
            self.set(key, v);
        }
        self
    }

    pub fn get(&self, key: &str) -> Option<&CanonValue> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &CanonValue)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(k, _)| k.as_str())
    }
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

impl From<Obj> for CanonValue {
    fn from(o: Obj) -> Self {
        CanonValue::Obj(o)
    }
}
impl From<bool> for CanonValue {
    fn from(b: bool) -> Self {
        CanonValue::Bool(b)
    }
}
impl From<i64> for CanonValue {
    fn from(i: i64) -> Self {
        CanonValue::Int(i)
    }
}
impl From<i32> for CanonValue {
    fn from(i: i32) -> Self {
        CanonValue::Int(i as i64)
    }
}
impl From<usize> for CanonValue {
    fn from(i: usize) -> Self {
        CanonValue::Int(i as i64)
    }
}
impl From<u64> for CanonValue {
    fn from(i: u64) -> Self {
        // Sizes beyond i64::MAX do not occur for real artifacts; saturate rather
        // than wrap, so a nonsense value is large rather than negative.
        CanonValue::Int(i.min(i64::MAX as u64) as i64)
    }
}
impl From<u32> for CanonValue {
    fn from(i: u32) -> Self {
        CanonValue::Int(i as i64)
    }
}
impl From<&str> for CanonValue {
    fn from(s: &str) -> Self {
        CanonValue::Str(s.to_string())
    }
}
impl From<String> for CanonValue {
    fn from(s: String) -> Self {
        CanonValue::Str(s)
    }
}
impl From<&String> for CanonValue {
    fn from(s: &String) -> Self {
        CanonValue::Str(s.clone())
    }
}
impl<T: Into<CanonValue>> From<Vec<T>> for CanonValue {
    fn from(v: Vec<T>) -> Self {
        CanonValue::Arr(v.into_iter().map(Into::into).collect())
    }
}
impl From<Digest> for CanonValue {
    fn from(d: Digest) -> Self {
        CanonValue::Str(d.to_hex())
    }
}

/// Build an array from an iterator of convertibles.
pub fn arr<T: Into<CanonValue>, I: IntoIterator<Item = T>>(items: I) -> CanonValue {
    CanonValue::Arr(items.into_iter().map(Into::into).collect())
}

// ---------------------------------------------------------------------------
// Canonical serialisation
// ---------------------------------------------------------------------------

/// Lexicographic comparison of UTF-16 code-unit sequences, as RFC 8785 §3.2.3
/// requires. This differs from Rust's byte-wise `str` ordering for characters
/// outside the Basic Multilingual Plane, so it is implemented explicitly rather
/// than delegated to `sort_by_key`.
pub fn utf16_cmp(a: &str, b: &str) -> Ordering {
    let mut ai = a.encode_utf16();
    let mut bi = b.encode_utf16();
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) if x != y => return x.cmp(&y),
            _ => {}
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_value(out: &mut String, v: &CanonValue) {
    match v {
        CanonValue::Null => out.push_str("null"),
        CanonValue::Bool(true) => out.push_str("true"),
        CanonValue::Bool(false) => out.push_str("false"),
        CanonValue::Int(i) => {
            // i64 Display never emits a leading `+`, leading zeros, or `-0`.
            out.push_str(&i.to_string());
        }
        CanonValue::Str(s) => write_string(out, s),
        CanonValue::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        CanonValue::Obj(o) => {
            let mut keys: Vec<&(String, CanonValue)> = o.entries.iter().collect();
            keys.sort_by(|a, b| utf16_cmp(&a.0, &b.0));
            out.push('{');
            for (i, (k, val)) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_value(out, val);
            }
            out.push('}');
        }
    }
}

impl CanonValue {
    /// RFC 8785 canonical form. UTF-8, no BOM, no insignificant whitespace.
    pub fn to_canonical_string(&self) -> String {
        let mut out = String::new();
        write_value(&mut out, self);
        out
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.to_canonical_string().into_bytes()
    }

    /// SHA-256 of the canonical bytes.
    pub fn digest(&self) -> Digest {
        Digest::of(&self.to_canonical_bytes())
    }

    pub fn as_obj(&self) -> Option<&Obj> {
        match self {
            CanonValue::Obj(o) => Some(o),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            CanonValue::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            CanonValue::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            CanonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&[CanonValue]> {
        match self {
            CanonValue::Arr(a) => Some(a),
            _ => None,
        }
    }

    /// Dotted-path lookup, e.g. `conclusions` then index is done by the caller.
    pub fn get(&self, key: &str) -> Option<&CanonValue> {
        self.as_obj().and_then(|o| o.get(key))
    }

    /// Recursively collect every string in the document. Used by the forbidden
    /// language test, which must see rendered text wherever it hides.
    pub fn collect_strings(&self, out: &mut Vec<String>) {
        match self {
            CanonValue::Str(s) => out.push(s.clone()),
            CanonValue::Arr(items) => items.iter().for_each(|i| i.collect_strings(out)),
            CanonValue::Obj(o) => o.entries.iter().for_each(|(_, v)| v.collect_strings(out)),
            _ => {}
        }
    }

    /// Human-readable indented form. **Not authoritative** and never hashed.
    pub fn to_pretty_string(&self) -> String {
        let mut out = String::new();
        write_pretty(&mut out, self, 0);
        out
    }
}

fn write_pretty(out: &mut String, v: &CanonValue, indent: usize) {
    let pad = "  ".repeat(indent);
    let pad2 = "  ".repeat(indent + 1);
    match v {
        CanonValue::Arr(items) if !items.is_empty() => {
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                out.push_str(&pad2);
                write_pretty(out, item, indent + 1);
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push(']');
        }
        CanonValue::Obj(o) if !o.entries.is_empty() => {
            let mut keys: Vec<&(String, CanonValue)> = o.entries.iter().collect();
            keys.sort_by(|a, b| utf16_cmp(&a.0, &b.0));
            out.push_str("{\n");
            for (i, (k, val)) in keys.iter().enumerate() {
                out.push_str(&pad2);
                write_string(out, k);
                out.push_str(": ");
                write_pretty(out, val, indent + 1);
                if i + 1 < keys.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push('}');
        }
        other => {
            let mut s = String::new();
            write_value(&mut s, other);
            out.push_str(&s);
        }
    }
}

// ---------------------------------------------------------------------------
// Importing untrusted JSON into the authoritative model
// ---------------------------------------------------------------------------

/// Convert a parsed untrusted document into the authoritative model.
///
/// Fails on any non-integral number. This is the single gate through which
/// external data can become part of a hashed document, and it is deliberately
/// strict: a report that silently rounded `0.15` to `0` would be worse than one
/// that refused to build.
pub fn from_json_value(v: &JsonValue) -> TtResult<CanonValue> {
    Ok(match v {
        JsonValue::Null => CanonValue::Null,
        JsonValue::Bool(b) => CanonValue::Bool(*b),
        JsonValue::Int(i) => CanonValue::Int(*i),
        JsonValue::Num(raw) => {
            return Err(TtError::contract(format!(
                "non-integral number `{raw}` cannot enter an authoritative document"
            )))
        }
        JsonValue::Str(s) => CanonValue::Str(s.clone()),
        JsonValue::Arr(items) => {
            let mut out = Vec::with_capacity(items.len());
            for i in items {
                out.push(from_json_value(i)?);
            }
            CanonValue::Arr(out)
        }
        JsonValue::Obj(entries) => {
            let mut o = Obj::new();
            for (k, val) in entries {
                if o.get(k).is_some() {
                    return Err(TtError::contract(format!("duplicate key `{k}`")));
                }
                o.set(k.clone(), from_json_value(val)?);
            }
            CanonValue::Obj(o)
        }
    })
}

/// Parse canonical JSON bytes back into the authoritative model, and verify that
/// the input was *already* canonical. Verify uses this so that a bundle whose JSON
/// was reformatted by a well-meaning editor is detected as modified.
pub fn parse_canonical(bytes: &[u8], limits: &crate::limits::Limits) -> TtResult<CanonValue> {
    let json = crate::json::parse(bytes, limits)?;
    let value = from_json_value(&json)?;
    if value.to_canonical_bytes() != bytes {
        return Err(TtError::integrity(
            "document is valid JSON but not in canonical form".to_string(),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_sort_by_utf16_code_units() {
        // U+FF3A FULLWIDTH LATIN CAPITAL Z is BMP (0xFF3A).
        // U+1F600 GRINNING FACE is non-BMP and encodes as surrogates 0xD83D 0xDE00.
        // In code-point order the emoji sorts last; in UTF-16 code-unit order the
        // leading surrogate 0xD83D sorts BEFORE 0xFF3A. RFC 8785 requires the latter.
        assert_eq!(utf16_cmp("\u{1F600}", "\u{FF3A}"), Ordering::Less);
        assert!("\u{1F600}" > "\u{FF3A}", "byte order disagrees, as expected");

        let o = Obj::new().with("\u{FF3A}", 1i64).with("\u{1F600}", 2i64);
        let s = CanonValue::Obj(o).to_canonical_string();
        let emoji_at = s.find('\u{1F600}').unwrap();
        let full_at = s.find('\u{FF3A}').unwrap();
        assert!(emoji_at < full_at, "emoji key must sort first: {s}");
    }

    #[test]
    fn rfc8785_string_escaping() {
        let v = CanonValue::Str("a\"b\\c\u{0008}\u{000c}\n\r\t\u{0001}é".to_string());
        assert_eq!(
            v.to_canonical_string(),
            "\"a\\\"b\\\\c\\b\\f\\n\\r\\t\\u0001é\""
        );
    }

    #[test]
    fn forward_slash_is_not_escaped() {
        let v = CanonValue::Str("a/b".to_string());
        assert_eq!(v.to_canonical_string(), "\"a/b\"");
    }

    #[test]
    fn no_insignificant_whitespace() {
        let o = Obj::new().with("b", 2i64).with("a", arr(vec![1i64, 2, 3]));
        assert_eq!(CanonValue::Obj(o).to_canonical_string(), "{\"a\":[1,2,3],\"b\":2}");
    }

    #[test]
    fn set_replaces_rather_than_duplicates() {
        let mut o = Obj::new();
        o.set("k", 1i64);
        o.set("k", 2i64);
        assert_eq!(o.len(), 1);
        assert_eq!(CanonValue::Obj(o).to_canonical_string(), "{\"k\":2}");
    }

    #[test]
    fn integers_have_no_leading_plus_or_negative_zero() {
        assert_eq!(CanonValue::Int(0).to_canonical_string(), "0");
        assert_eq!(CanonValue::Int(-1).to_canonical_string(), "-1");
        assert_eq!(CanonValue::Int(i64::MIN).to_canonical_string(), i64::MIN.to_string());
    }

    #[test]
    fn floats_cannot_enter_authoritative_documents() {
        let j = crate::json::parse(b"{\"lr\":5e-5}", &crate::limits::Limits::default()).unwrap();
        let err = from_json_value(&j).unwrap_err();
        assert!(matches!(err, TtError::ContractViolation { .. }));
    }

    #[test]
    fn round_trip_through_parse_canonical() {
        let o = Obj::new().with("z", 1i64).with("a", "x").with("m", CanonValue::Null);
        let v = CanonValue::Obj(o);
        let bytes = v.to_canonical_bytes();
        let back = parse_canonical(&bytes, &crate::limits::Limits::default()).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn non_canonical_input_is_rejected() {
        let pretty = b"{ \"a\": 1 }";
        let err = parse_canonical(pretty, &crate::limits::Limits::default()).unwrap_err();
        assert!(matches!(err, TtError::Integrity { .. }));
    }

    #[test]
    fn digest_is_stable_across_construction_order() {
        let a = CanonValue::Obj(Obj::new().with("one", 1i64).with("two", 2i64));
        let b = CanonValue::Obj(Obj::new().with("two", 2i64).with("one", 1i64));
        assert_eq!(a.digest(), b.digest());
    }
}
