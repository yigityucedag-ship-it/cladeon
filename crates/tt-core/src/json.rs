//! A strict, bounded JSON parser for untrusted input.
//!
//! This is the only JSON reader in the product. It is written in-repo because it
//! parses bytes chosen by the party under scrutiny, and every bound it enforces is
//! one the report has to be able to describe:
//!
//! * depth, key count, element count and string length are capped, so a nested or
//!   wide document becomes a `coverage_limitation` instead of a stack overflow or
//!   an allocation spike;
//! * duplicate object keys are **rejected**, because a config that says two things
//!   must not be silently resolved to one of them (rule `TT-FMT-011`);
//! * numbers are never converted to binary floating point — a fractional or
//!   exponential literal is retained as its exact source text.
//!
//! Recursion is bounded by [`crate::limits::Limits::json_max_depth`] before any
//! descent occurs, so the recursive-descent shape cannot exhaust the stack.

use crate::error::{TtError, TtResult};
use crate::limits::Limits;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    /// An integral literal with no fraction or exponent that fits in `i64`.
    Int(i64),
    /// Any other number, retained as its exact source text. Never a float.
    Num(String),
    Str(String),
    Arr(Vec<JsonValue>),
    /// Insertion-ordered, guaranteed duplicate-free by the parser.
    Obj(Vec<(String, JsonValue)>),
}

impl JsonValue {
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Obj(e) => e.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            JsonValue::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Arr(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_obj(&self) -> Option<&[(String, JsonValue)]> {
        match self {
            JsonValue::Obj(o) => Some(o),
            _ => None,
        }
    }
    /// The literal source text of any number, integral or not.
    pub fn as_number_text(&self) -> Option<String> {
        match self {
            JsonValue::Int(i) => Some(i.to_string()),
            JsonValue::Num(s) => Some(s.clone()),
            _ => None,
        }
    }
    /// Stable type name for coverage messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            JsonValue::Null => "null",
            JsonValue::Bool(_) => "bool",
            JsonValue::Int(_) | JsonValue::Num(_) => "number",
            JsonValue::Str(_) => "string",
            JsonValue::Arr(_) => "array",
            JsonValue::Obj(_) => "object",
        }
    }
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
    limits: &'a Limits,
}

/// Parse a complete JSON document. Trailing content is an error.
pub fn parse(bytes: &[u8], limits: &Limits) -> TtResult<JsonValue> {
    if bytes.len() as u64 > limits.config_bytes {
        return Err(TtError::LimitExceeded {
            limit: "config_bytes",
            value: bytes.len() as u64,
            max: limits.config_bytes,
        });
    }
    // A BOM is not JSON. Reject rather than silently strip, so that a file which
    // differs by three bytes is not reported as identical.
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(TtError::malformed("json", 0, "byte order mark"));
    }
    std::str::from_utf8(bytes).map_err(|e| TtError::malformed("json", e.valid_up_to(), "invalid UTF-8"))?;

    let mut p = Parser { b: bytes, i: 0, depth: 0, limits };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.i != p.b.len() {
        return Err(TtError::malformed("json", p.i, "trailing content after value"));
    }
    Ok(v)
}

/// Parse newline-delimited JSON. Blank lines are skipped. Used for JSONL traces.
pub fn parse_lines(bytes: &[u8], limits: &Limits) -> TtResult<Vec<JsonValue>> {
    let mut out = Vec::new();
    for line in bytes.split(|c| *c == b'\n') {
        let line = match line.strip_suffix(b"\r") {
            Some(l) => l,
            None => line,
        };
        if line.iter().all(|c| matches!(c, b' ' | b'\t')) {
            continue;
        }
        if line.len() > limits.json_max_string_bytes {
            return Err(TtError::LimitExceeded {
                limit: "jsonl_line_bytes",
                value: line.len() as u64,
                max: limits.json_max_string_bytes as u64,
            });
        }
        out.push(parse(line, limits)?);
    }
    Ok(out)
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            // RFC 8259 whitespace only. Vertical tab and form feed are not whitespace.
            if matches!(c, b' ' | b'\t' | b'\n' | b'\r') {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, c: u8) -> TtResult<()> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(TtError::malformed("json", self.i, format!("expected `{}`", c as char)))
        }
    }

    fn value(&mut self) -> TtResult<JsonValue> {
        match self.peek() {
            None => Err(TtError::malformed("json", self.i, "unexpected end of input")),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(JsonValue::Str(self.string()?)),
            Some(b't') => self.literal(b"true", JsonValue::Bool(true)),
            Some(b'f') => self.literal(b"false", JsonValue::Bool(false)),
            Some(b'n') => self.literal(b"null", JsonValue::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(c) => Err(TtError::malformed(
                "json",
                self.i,
                format!("unexpected byte 0x{c:02x}"),
            )),
        }
    }

    fn literal(&mut self, word: &[u8], v: JsonValue) -> TtResult<JsonValue> {
        if self.b[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(TtError::malformed("json", self.i, "invalid literal"))
        }
    }

    fn enter(&mut self) -> TtResult<()> {
        self.depth += 1;
        if self.depth > self.limits.json_max_depth {
            return Err(TtError::LimitExceeded {
                limit: "json_max_depth",
                value: self.depth as u64,
                max: self.limits.json_max_depth as u64,
            });
        }
        Ok(())
    }

    fn array(&mut self) -> TtResult<JsonValue> {
        self.enter()?;
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            self.depth -= 1;
            return Ok(JsonValue::Arr(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            if items.len() > self.limits.json_max_array_elements {
                return Err(TtError::LimitExceeded {
                    limit: "json_max_array_elements",
                    value: items.len() as u64,
                    max: self.limits.json_max_array_elements as u64,
                });
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(TtError::malformed("json", self.i, "expected `,` or `]`")),
            }
        }
        self.depth -= 1;
        Ok(JsonValue::Arr(items))
    }

    fn object(&mut self) -> TtResult<JsonValue> {
        self.enter()?;
        self.expect(b'{')?;
        let mut entries: Vec<(String, JsonValue)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            self.depth -= 1;
            return Ok(JsonValue::Obj(entries));
        }
        loop {
            self.skip_ws();
            let at = self.i;
            let key = self.string()?;
            if entries.iter().any(|(k, _)| *k == key) {
                // TT-FMT-011: an authoritative config that says two things must not
                // be silently resolved to one of them.
                return Err(TtError::ambiguous("duplicate_key", format!("`{key}` at byte {at}")));
            }
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let v = self.value()?;
            entries.push((key, v));
            if entries.len() > self.limits.json_max_object_keys {
                return Err(TtError::LimitExceeded {
                    limit: "json_max_object_keys",
                    value: entries.len() as u64,
                    max: self.limits.json_max_object_keys as u64,
                });
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(TtError::malformed("json", self.i, "expected `,` or `}`")),
            }
        }
        self.depth -= 1;
        Ok(JsonValue::Obj(entries))
    }

    fn string(&mut self) -> TtResult<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let c = self
                .peek()
                .ok_or_else(|| TtError::malformed("json", self.i, "unterminated string"))?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = self
                        .peek()
                        .ok_or_else(|| TtError::malformed("json", self.i, "unterminated escape"))?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&hi) {
                                // High surrogate: a low surrogate must follow.
                                if self.peek() != Some(b'\\') {
                                    return Err(TtError::malformed(
                                        "json",
                                        self.i,
                                        "lone high surrogate",
                                    ));
                                }
                                self.i += 1;
                                if self.peek() != Some(b'u') {
                                    return Err(TtError::malformed(
                                        "json",
                                        self.i,
                                        "lone high surrogate",
                                    ));
                                }
                                self.i += 1;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(TtError::malformed(
                                        "json",
                                        self.i,
                                        "invalid low surrogate",
                                    ));
                                }
                                let cp = 0x10000
                                    + (((hi as u32) - 0xD800) << 10)
                                    + ((lo as u32) - 0xDC00);
                                char::from_u32(cp).ok_or_else(|| {
                                    TtError::malformed("json", self.i, "invalid code point")
                                })?
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(TtError::malformed("json", self.i, "lone low surrogate"));
                            } else {
                                char::from_u32(hi as u32).ok_or_else(|| {
                                    TtError::malformed("json", self.i, "invalid code point")
                                })?
                            };
                            out.push(ch);
                        }
                        other => {
                            return Err(TtError::malformed(
                                "json",
                                self.i,
                                format!("invalid escape `\\{}`", other as char),
                            ))
                        }
                    }
                }
                c if c < 0x20 => {
                    return Err(TtError::malformed(
                        "json",
                        self.i,
                        "unescaped control character in string",
                    ))
                }
                _ => {
                    // Copy one whole UTF-8 sequence. The slice was validated as UTF-8
                    // up front, so the boundary walk cannot run past the end.
                    let start = self.i;
                    self.i += 1;
                    while self.i < self.b.len() && (self.b[self.i] & 0xC0) == 0x80 {
                        self.i += 1;
                    }
                    out.push_str(std::str::from_utf8(&self.b[start..self.i]).map_err(|_| {
                        TtError::malformed("json", start, "invalid UTF-8 in string")
                    })?);
                }
            }
            if out.len() > self.limits.json_max_string_bytes {
                return Err(TtError::LimitExceeded {
                    limit: "json_max_string_bytes",
                    value: out.len() as u64,
                    max: self.limits.json_max_string_bytes as u64,
                });
            }
        }
    }

    fn hex4(&mut self) -> TtResult<u16> {
        if self.i + 4 > self.b.len() {
            return Err(TtError::malformed("json", self.i, "truncated \\u escape"));
        }
        let mut v: u16 = 0;
        for k in 0..4 {
            let c = self.b[self.i + k];
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(TtError::malformed("json", self.i + k, "bad hex digit")),
            };
            v = (v << 4) | d as u16;
        }
        self.i += 4;
        Ok(v)
    }

    fn number(&mut self) -> TtResult<JsonValue> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        // int part
        match self.peek() {
            Some(b'0') => {
                self.i += 1;
                if matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    return Err(TtError::malformed("json", self.i, "leading zero"));
                }
            }
            Some(c) if c.is_ascii_digit() => {
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.i += 1;
                }
            }
            _ => return Err(TtError::malformed("json", self.i, "expected digit")),
        }
        let mut integral = true;
        if self.peek() == Some(b'.') {
            integral = false;
            self.i += 1;
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(TtError::malformed("json", self.i, "expected digit after `.`"));
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            integral = false;
            self.i += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(TtError::malformed("json", self.i, "expected digit in exponent"));
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        let raw = std::str::from_utf8(&self.b[start..self.i])
            .map_err(|_| TtError::malformed("json", start, "invalid number"))?;
        if integral {
            if let Ok(i) = raw.parse::<i64>() {
                return Ok(JsonValue::Int(i));
            }
        }
        // Fractional, exponential, or wider than i64: keep the exact source text.
        Ok(JsonValue::Num(raw.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> TtResult<JsonValue> {
        parse(s.as_bytes(), &Limits::default())
    }

    #[test]
    fn basic_shapes() {
        assert_eq!(p("null").unwrap(), JsonValue::Null);
        assert_eq!(p("true").unwrap(), JsonValue::Bool(true));
        assert_eq!(p("  [1, 2 ,3] ").unwrap(), JsonValue::Arr(vec![
            JsonValue::Int(1),
            JsonValue::Int(2),
            JsonValue::Int(3)
        ]));
        assert_eq!(p("{}").unwrap(), JsonValue::Obj(vec![]));
    }

    #[test]
    fn integral_versus_fractional() {
        assert_eq!(p("42").unwrap(), JsonValue::Int(42));
        assert_eq!(p("-0").unwrap(), JsonValue::Int(0));
        assert_eq!(p("5e-5").unwrap(), JsonValue::Num("5e-5".into()));
        assert_eq!(p("0.05").unwrap(), JsonValue::Num("0.05".into()));
        // Wider than i64 stays exact rather than saturating.
        assert_eq!(
            p("123456789012345678901234567890").unwrap(),
            JsonValue::Num("123456789012345678901234567890".into())
        );
    }

    #[test]
    fn rejects_json5_and_relatives() {
        assert!(p("{a:1}").is_err(), "unquoted key");
        assert!(p("[1,]").is_err(), "trailing comma");
        assert!(p("01").is_err(), "leading zero");
        assert!(p("+1").is_err(), "leading plus");
        assert!(p(".5").is_err(), "bare fraction");
        assert!(p("1.").is_err(), "trailing point");
        assert!(p("'x'").is_err(), "single quotes");
        assert!(p("{} {}").is_err(), "trailing content");
        assert!(p("NaN").is_err());
        assert!(p("Infinity").is_err());
        assert!(p("").is_err());
    }

    #[test]
    fn rejects_duplicate_keys() {
        let e = p("{\"a\":1,\"a\":2}").unwrap_err();
        assert!(matches!(e, TtError::Ambiguous { what: "duplicate_key", .. }));
    }

    #[test]
    fn rejects_bom() {
        assert!(parse("\u{feff}{}".as_bytes(), &Limits::default()).is_err());
    }

    #[test]
    fn rejects_unescaped_control_characters() {
        assert!(parse(b"\"a\nb\"", &Limits::default()).is_err());
    }

    #[test]
    fn surrogate_pairs() {
        assert_eq!(p("\"\\ud83d\\ude00\"").unwrap(), JsonValue::Str("\u{1F600}".into()));
        assert!(p("\"\\ud83d\"").is_err(), "lone high surrogate");
        assert!(p("\"\\udc00\"").is_err(), "lone low surrogate");
        assert!(p("\"\\ud83dx\"").is_err(), "high surrogate not followed by escape");
    }

    #[test]
    fn depth_limit_stops_recursion() {
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        let e = parse(deep.as_bytes(), &Limits::default()).unwrap_err();
        assert!(matches!(e, TtError::LimitExceeded { limit: "json_max_depth", .. }));
    }

    #[test]
    fn deeply_nested_within_limit_is_accepted() {
        let n = Limits::default().json_max_depth;
        let ok = format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(parse(ok.as_bytes(), &Limits::default()).is_ok());
        let bad = format!("{}{}", "[".repeat(n + 1), "]".repeat(n + 1));
        assert!(parse(bad.as_bytes(), &Limits::default()).is_err());
    }

    #[test]
    fn width_limits() {
        let lim = Limits::tiny();
        let wide: String = format!("[{}]", vec!["1"; 100].join(","));
        assert!(matches!(
            parse(wide.as_bytes(), &lim).unwrap_err(),
            TtError::LimitExceeded { limit: "json_max_array_elements", .. }
        ));
        let keys: Vec<String> = (0..100).map(|i| format!("\"k{i}\":1")).collect();
        let obj = format!("{{{}}}", keys.join(","));
        assert!(matches!(
            parse(obj.as_bytes(), &lim).unwrap_err(),
            TtError::LimitExceeded { limit: "json_max_object_keys", .. }
        ));
        let long = format!("\"{}\"", "a".repeat(1000));
        assert!(matches!(
            parse(long.as_bytes(), &lim).unwrap_err(),
            TtError::LimitExceeded { limit: "json_max_string_bytes", .. }
        ));
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        assert!(parse(&[b'"', 0xff, b'"'], &Limits::default()).is_err());
    }

    #[test]
    fn jsonl() {
        let v = parse_lines(b"{\"a\":1}\n\n{\"b\":2}\r\n", &Limits::default()).unwrap();
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn multibyte_strings_round_trip() {
        let v = p("\"héllo 世界\"").unwrap();
        assert_eq!(v, JsonValue::Str("héllo 世界".into()));
    }
}
