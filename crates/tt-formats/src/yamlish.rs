//! A deliberately small YAML subset — block structure and scalars, nothing else.
//!
//! ## Why not YAML
//!
//! Full YAML is not a config format, it is a serialisation format with an object
//! graph. Anchors and aliases turn a document into a DAG, merge keys add
//! inheritance, and tags name types a loader is expected to *construct*. Every one
//! of those has been a code-execution or resource-exhaustion vector somewhere, and
//! none of them is needed to read `README.md` front matter, an `accelerate` config
//! or a compose file. So this module implements the part that carries evidence and
//! **refuses the rest by name**.
//!
//! A refusal is not a failed scan. The caller turns the error into coverage note
//! `TT-FMT-010`, so the report says the scanner declined to interpret the file —
//! which is true — instead of guessing at a construct whose meaning depends on
//! which loader you happen to use.
//!
//! ## Supported
//!
//! Block mappings, block sequences, indentation nesting, `#` comments, single- and
//! double-quoted and plain scalars, single-line flow collections (`[a, b]`,
//! `{a: 1}`), compact sequence entries (`- name: x`), a leading `---` marker, and a
//! key with no value (which is null).
//!
//! ## Refused, each with its own message
//!
//! Anchors (`&a`), aliases (`*a`), tags (`!t`), merge keys (`<<`), explicit keys
//! (`? k`), directives (`%YAML`), tab indentation, multi-line flow collections,
//! multi-line plain scalars, and duplicate keys in one mapping.
//!
//! ## Block scalars are captured, not interpreted
//!
//! `|` and `>` blocks are captured as *opaque text*: the block's own lines,
//! dedented, joined with `\n`, with no trailing newline and **no folding applied**.
//! Reproducing YAML's chomping and folding rules exactly would be a second parser's
//! worth of subtlety for a construct that carries no evidence in this product, so
//! the value is recorded as what the file visibly contains. The two indicators that
//! would make that capture actively misleading — the keep indicator `+` and an
//! explicit indentation indicator such as `|2` — are refused instead.
//!
//! ## Types are read conservatively
//!
//! `true`/`false` (and their capitalised spellings) are booleans; `yes`, `no`, `on`
//! and `off` are **strings**, because YAML 1.1's boolean spelling is a well-known
//! footgun and a scanner that silently reads `no` as false is inventing a fact. A
//! number keeps its exact source text unless it is a plain integer that fits `i64`,
//! so `5e-5` survives to the report unrounded and `0755` stays a string rather than
//! becoming a guess about octal.

use std::collections::BTreeSet;

use tt_core::error::{TtError, TtResult};
use tt_core::json::JsonValue;
use tt_core::limits::Limits;

/// Subject recorded in error positions, so a caller can tell a YAML refusal from a
/// JSON one without parsing the message.
const WHAT: &str = "yaml";

/// Parse the first document of a bounded YAML subset.
///
/// An empty document, or one that holds only comments, is [`JsonValue::Null`].
/// Content after the first `---`/`...` separator is deliberately not read.
pub fn parse(bytes: &[u8], limits: &Limits) -> TtResult<JsonValue> {
    if bytes.len() as u64 > limits.config_bytes {
        return Err(TtError::LimitExceeded {
            limit: "config_bytes",
            value: bytes.len() as u64,
            max: limits.config_bytes,
        });
    }
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        // Stripping a BOM would make a file that differs by three bytes report as
        // identical to one that does not have it.
        return Err(TtError::malformed(WHAT, 0, "byte order mark"));
    }
    let src = std::str::from_utf8(bytes)
        .map_err(|e| TtError::malformed(WHAT, e.valid_up_to(), "invalid UTF-8"))?;

    let lines = split_lines(src)?;
    let mut p = Parser { lines, idx: 0, limits };
    p.document()
}

/// The YAML front matter of a Markdown document, if it has any.
///
/// Front matter is only front matter when the *first* line of the file opens the
/// fence: a `---` further down a README is a horizontal rule, and treating it as a
/// document start would invent metadata out of prose. An unterminated fence returns
/// `None` for the same reason.
pub fn front_matter(bytes: &[u8]) -> Option<&[u8]> {
    let mut offset = 0usize;
    let mut body_start: Option<usize> = None;
    for raw in bytes.split(|c| *c == b'\n') {
        let line_start = offset;
        offset = offset.saturating_add(raw.len()).saturating_add(1);
        let t = raw.trim_ascii();
        match body_start {
            None => {
                if t != b"---" {
                    return None;
                }
                body_start = Some(offset.min(bytes.len()));
            }
            Some(s) => {
                if t == b"---" || t == b"..." {
                    return bytes.get(s..line_start);
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Lines
// ---------------------------------------------------------------------------

/// One physical line, split into its indentation and its content.
///
/// `text` keeps the line exactly as written after the indentation, because a block
/// scalar's content is whitespace-significant and a comment's `#` has to stay
/// visible to the scalar scanner.
#[derive(Clone, Copy)]
struct Line<'a> {
    indent: usize,
    text: &'a str,
    /// Byte offset of the start of the line within the document.
    offset: usize,
    /// False for a blank line and for a comment-only line.
    significant: bool,
}

fn split_lines(src: &str) -> TtResult<Vec<Line<'_>>> {
    let mut lines = Vec::new();
    let mut offset = 0usize;
    for raw in src.split('\n') {
        let consumed = raw.len().saturating_add(1);
        let body = raw.strip_suffix('\r').unwrap_or(raw);
        let b = body.as_bytes();
        let mut indent = 0usize;
        while b.get(indent) == Some(&b' ') {
            indent += 1;
        }
        if b.get(indent) == Some(&b'\t') {
            // A tab is not indentation in YAML, and a parser that quietly accepts
            // one produces a structure the vendor's own loader would refuse.
            return Err(TtError::malformed(
                WHAT,
                offset.saturating_add(indent),
                "tab used for indentation",
            ));
        }
        let text = body.get(indent..).unwrap_or("");
        let head = text.trim_start();
        let significant = !(head.is_empty() || head.starts_with('#'));
        lines.push(Line { indent, text, offset, significant });
        offset = offset.saturating_add(consumed);
    }
    Ok(lines)
}

/// Is this line a block sequence entry (`- item`, or a bare `-`)?
fn is_seq_entry(text: &str) -> bool {
    let b = text.as_bytes();
    b.first() == Some(&b'-') && matches!(b.get(1), None | Some(b' '))
}

/// `---` or `...`, which end the first document.
fn is_doc_marker(text: &str) -> bool {
    let t = text.trim_end();
    t == "---" || t == "..." || t.starts_with("--- ") || t.starts_with("... ")
}

fn depth_guard(depth: usize, limits: &Limits) -> TtResult<()> {
    if depth > limits.json_max_depth {
        return Err(TtError::LimitExceeded {
            limit: "json_max_depth",
            value: depth as u64,
            max: limits.json_max_depth as u64,
        });
    }
    Ok(())
}

fn check_string_len(s: &str, limits: &Limits) -> TtResult<()> {
    if s.len() > limits.json_max_string_bytes {
        return Err(TtError::LimitExceeded {
            limit: "json_max_string_bytes",
            value: s.len() as u64,
            max: limits.json_max_string_bytes as u64,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Block structure
// ---------------------------------------------------------------------------

struct Parser<'a> {
    lines: Vec<Line<'a>>,
    idx: usize,
    limits: &'a Limits,
}

impl<'a> Parser<'a> {
    fn cur(&self) -> Option<Line<'a>> {
        self.lines.get(self.idx).copied()
    }

    fn skip_insignificant(&mut self) {
        while let Some(l) = self.lines.get(self.idx) {
            if l.significant {
                return;
            }
            self.idx += 1;
        }
    }

    fn document(&mut self) -> TtResult<JsonValue> {
        self.skip_insignificant();
        if let Some(l) = self.cur() {
            if l.indent == 0 && is_doc_marker(l.text) {
                let t = l.text.trim_end();
                if t == "..." {
                    return Ok(JsonValue::Null);
                }
                if t != "---" {
                    return Err(TtError::out_of_scope(
                        "inline content on a `---` document marker",
                    ));
                }
                self.idx += 1;
                self.skip_insignificant();
            }
        }
        let Some(l) = self.cur() else { return Ok(JsonValue::Null) };
        if l.indent == 0 && is_doc_marker(l.text) {
            return Ok(JsonValue::Null);
        }
        let v = self.block(l.indent, 1)?;
        self.skip_insignificant();
        if let Some(l) = self.cur() {
            if !(l.indent == 0 && is_doc_marker(l.text)) {
                return Err(TtError::malformed(
                    WHAT,
                    l.offset.saturating_add(l.indent),
                    "content after the end of the first document",
                ));
            }
        }
        Ok(v)
    }

    /// A mapping, a sequence, or a flow collection - whichever the current line
    /// starts.
    ///
    /// The flow case has to be handled here rather than left to `map`. A line like
    /// `{a: 1}` at the head of a block contains a colon, so `map` would happily split
    /// it and record a key called `{a` with the value `1}` — inventing structure that
    /// is not in the file. Recognising the flow opener first means such a document
    /// either parses correctly or, if anything follows it, is refused by the
    /// trailing-content check in `document`.
    fn block(&mut self, indent: usize, depth: usize) -> TtResult<JsonValue> {
        let Some(l) = self.cur() else { return Ok(JsonValue::Null) };
        let trimmed = l.text.trim();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            let at = l.offset.saturating_add(l.indent);
            let text = trimmed.to_string();
            let v = scalar_or_flow(&text, at, depth, self.limits)?;
            self.idx += 1;
            return Ok(v);
        }
        if is_seq_entry(l.text) {
            self.seq(indent, depth)
        } else {
            self.map(indent, depth)
        }
    }

    fn map(&mut self, indent: usize, depth: usize) -> TtResult<JsonValue> {
        depth_guard(depth, self.limits)?;
        let mut entries: Vec<(String, JsonValue)> = Vec::new();
        // Linear duplicate detection would be quadratic in the key count, which is
        // exactly what a hostile file would aim for.
        let mut seen: BTreeSet<String> = BTreeSet::new();
        loop {
            self.skip_insignificant();
            let Some(l) = self.cur() else { break };
            if l.indent < indent || (l.indent == 0 && is_doc_marker(l.text)) {
                break;
            }
            let at = l.offset.saturating_add(l.indent);
            if l.indent > indent {
                return Err(TtError::malformed(WHAT, at, "unexpected indentation"));
            }
            if is_seq_entry(l.text) {
                return Err(TtError::malformed(
                    WHAT,
                    at,
                    "sequence entry where a mapping key was expected",
                ));
            }

            let (key, after) = split_key(l.text, at, self.limits)?;
            if !seen.insert(key.clone()) {
                // TT-FMT-011: a config that says two things must not be silently
                // resolved to one of them.
                return Err(TtError::ambiguous(
                    "duplicate_key",
                    format!("`{key}` at byte {at}"),
                ));
            }
            let rest = l.text.get(after..).unwrap_or("").trim();
            self.idx += 1;
            let value =
                self.value_after_key(rest, indent, depth, l.offset.saturating_add(after))?;
            entries.push((key, value));
            if entries.len() > self.limits.json_max_object_keys {
                return Err(TtError::LimitExceeded {
                    limit: "json_max_object_keys",
                    value: entries.len() as u64,
                    max: self.limits.json_max_object_keys as u64,
                });
            }
        }
        Ok(JsonValue::Obj(entries))
    }

    /// The value of `key:`, given whatever followed the colon on the same line.
    fn value_after_key(
        &mut self,
        rest: &str,
        parent_indent: usize,
        depth: usize,
        at: usize,
    ) -> TtResult<JsonValue> {
        if rest.starts_with('|') || rest.starts_with('>') {
            return self.block_scalar(rest, parent_indent, at);
        }
        if !rest.is_empty() {
            return scalar_or_flow(rest, at, depth, self.limits);
        }
        self.skip_insignificant();
        match self.cur() {
            // A nested block, indented under the key.
            Some(l) if l.indent > parent_indent => self.block(l.indent, depth + 1),
            // A sequence written at the key's own indentation, which YAML allows
            // and every hand-written config uses.
            Some(l) if l.indent == parent_indent && is_seq_entry(l.text) => {
                self.seq(parent_indent, depth + 1)
            }
            _ => Ok(JsonValue::Null),
        }
    }

    fn seq(&mut self, indent: usize, depth: usize) -> TtResult<JsonValue> {
        depth_guard(depth, self.limits)?;
        let mut items: Vec<JsonValue> = Vec::new();
        loop {
            self.skip_insignificant();
            let Some(l) = self.cur() else { break };
            if l.indent < indent || (l.indent == 0 && is_doc_marker(l.text)) {
                break;
            }
            let at = l.offset.saturating_add(l.indent);
            if l.indent > indent {
                return Err(TtError::malformed(WHAT, at, "unexpected indentation"));
            }
            if !is_seq_entry(l.text) {
                // A mapping key at the sequence's own indentation ends it.
                break;
            }

            let b = l.text.as_bytes();
            let mut p = 1usize;
            while b.get(p) == Some(&b' ') {
                p += 1;
            }
            let rest = l.text.get(p..).unwrap_or("").trim_end();
            let rest_col = l.indent.saturating_add(p);

            if rest.is_empty() {
                self.idx += 1;
                self.skip_insignificant();
                let v = match self.cur() {
                    Some(n) if n.indent > indent => self.block(n.indent, depth + 1)?,
                    _ => JsonValue::Null,
                };
                items.push(v);
            } else if has_key_colon(rest) || is_seq_entry(rest) {
                // Compact notation: `- name: x` is a mapping whose first key starts
                // in the dash's own line. Rewriting the line so it begins at the
                // key's column is what lets the following lines, which align with
                // that key, join the same mapping.
                if let Some(m) = self.lines.get_mut(self.idx) {
                    m.indent = rest_col;
                    m.text = rest;
                }
                let v = self.block(rest_col, depth + 1)?;
                items.push(v);
            } else {
                self.idx += 1;
                items.push(scalar_or_flow(
                    rest,
                    l.offset.saturating_add(rest_col),
                    depth,
                    self.limits,
                )?);
            }

            if items.len() > self.limits.json_max_array_elements {
                return Err(TtError::LimitExceeded {
                    limit: "json_max_array_elements",
                    value: items.len() as u64,
                    max: self.limits.json_max_array_elements as u64,
                });
            }
        }
        Ok(JsonValue::Arr(items))
    }

    /// Capture a `|` or `>` block as opaque text. See the module header.
    fn block_scalar(
        &mut self,
        header: &str,
        parent_indent: usize,
        at: usize,
    ) -> TtResult<JsonValue> {
        let b = header.as_bytes();
        let mut p = 1usize;
        match b.get(1) {
            Some(b'-') => p = 2,
            Some(b'+') => {
                return Err(TtError::out_of_scope(
                    "block scalar keep indicator `+`, whose trailing newlines this \
                     parser does not reproduce",
                ))
            }
            Some(c) if c.is_ascii_digit() => {
                return Err(TtError::out_of_scope(
                    "explicit block scalar indentation indicator",
                ))
            }
            _ => {}
        }
        let tail = header.get(p..).unwrap_or("").trim();
        if !tail.is_empty() && !tail.starts_with('#') {
            return Err(TtError::malformed(
                WHAT,
                at,
                "unexpected text after a block scalar header",
            ));
        }

        let start = self.idx;
        let mut end = self.idx;
        while let Some(l) = self.lines.get(end) {
            // Blank lines belong to the block; a comment inside a block is content,
            // so indentation decides membership rather than significance.
            if l.text.trim().is_empty() || l.indent > parent_indent {
                end += 1;
            } else {
                break;
            }
        }

        let mut block_indent: Option<usize> = None;
        let mut out: Vec<String> = Vec::new();
        for k in start..end {
            let Some(l) = self.lines.get(k) else { break };
            if l.text.trim().is_empty() {
                out.push(String::new());
                continue;
            }
            let bi = *block_indent.get_or_insert(l.indent);
            let mut s = " ".repeat(l.indent.saturating_sub(bi));
            s.push_str(l.text.trim_end());
            out.push(s);
        }
        while out.last().map(|s| s.is_empty()).unwrap_or(false) {
            out.pop();
        }
        self.idx = end;

        let text = out.join("\n");
        check_string_len(&text, self.limits)?;
        Ok(JsonValue::Str(text))
    }
}

// ---------------------------------------------------------------------------
// Keys and scalars
// ---------------------------------------------------------------------------

/// Split `key:` off the front of a line, returning the key and the byte index just
/// past the colon.
fn split_key(text: &str, at: usize, limits: &Limits) -> TtResult<(String, usize)> {
    let b = text.as_bytes();
    if let Some(e) = refusal_for(b.first().copied()) {
        return Err(e);
    }
    if b.first() == Some(&b'?') && matches!(b.get(1), None | Some(b' ')) {
        return Err(TtError::out_of_scope(
            "explicit mapping keys (`? key`) are outside the supported YAML subset",
        ));
    }

    if matches!(b.first(), Some(b'"') | Some(b'\'')) {
        let (key, next) = read_quoted(text, 0, at, limits)?;
        let after = text.get(next..).unwrap_or("");
        let trimmed = after.trim_start();
        if !trimmed.starts_with(':') {
            return Err(TtError::malformed(WHAT, at + next, "expected `:` after a quoted key"));
        }
        let colon = next + (after.len() - trimmed.len()) + 1;
        check_string_len(&key, limits)?;
        return Ok((key, colon));
    }

    let mut i = 0usize;
    while i < b.len() {
        match b.get(i) {
            Some(b':') if matches!(b.get(i + 1), None | Some(b' ') | Some(b'\t')) => {
                let key = text.get(..i).unwrap_or("").trim_end();
                if key == "<<" {
                    return Err(TtError::out_of_scope(
                        "merge keys (`<<`) are outside the supported YAML subset",
                    ));
                }
                if key.is_empty() {
                    return Err(TtError::malformed(WHAT, at, "empty mapping key"));
                }
                check_string_len(key, limits)?;
                return Ok((key.to_string(), i + 1));
            }
            Some(b'#') if matches!(b.get(i.wrapping_sub(1)), Some(b' ')) && i > 0 => break,
            _ => i += 1,
        }
    }
    Err(TtError::malformed(
        WHAT,
        at,
        "expected `key:` — a plain multi-line scalar or an unquoted `:` would both \
         produce this",
    ))
}

/// The YAML features this subset declines to interpret, keyed by their sigil.
fn refusal_for(first: Option<u8>) -> Option<TtError> {
    match first {
        Some(b'&') => Some(TtError::out_of_scope(
            "YAML anchors (`&name`) are outside the supported subset",
        )),
        Some(b'*') => Some(TtError::out_of_scope(
            "YAML aliases (`*name`) are outside the supported subset",
        )),
        Some(b'!') => Some(TtError::out_of_scope(
            "YAML tags (`!type`) are outside the supported subset",
        )),
        Some(b'%') => Some(TtError::out_of_scope(
            "YAML directives (`%YAML`) are outside the supported subset",
        )),
        _ => None,
    }
}

/// Does this text contain a `key:` at flow depth zero?
fn has_key_colon(s: &str) -> bool {
    let b = s.as_bytes();
    let mut quote: Option<u8> = None;
    let mut flow = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        let c = match b.get(i) {
            Some(c) => *c,
            None => break,
        };
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                b'"' | b'\'' => quote = Some(c),
                b'[' | b'{' => flow += 1,
                b']' | b'}' => flow = flow.saturating_sub(1),
                b'#' if i > 0 && b.get(i - 1) == Some(&b' ') => return false,
                b':' if flow == 0 && matches!(b.get(i + 1), None | Some(b' ') | Some(b'\t')) => {
                    return true
                }
                _ => {}
            },
        }
        i += 1;
    }
    false
}

/// Where a plain scalar ends because a comment begins.
fn plain_end(s: &str) -> usize {
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b.get(i) == Some(&b'#')
            && (i == 0 || matches!(b.get(i - 1), Some(b' ') | Some(b'\t')))
        {
            return i;
        }
        i += 1;
    }
    b.len()
}

/// A value written on one line: a flow collection, a quoted scalar or a plain one.
fn scalar_or_flow(s: &str, at: usize, depth: usize, limits: &Limits) -> TtResult<JsonValue> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(JsonValue::Null);
    }
    if let Some(e) = refusal_for(t.as_bytes().first().copied()) {
        return Err(e);
    }
    match t.as_bytes().first() {
        Some(b'[') | Some(b'{') => {
            let mut f = Flow { s: t, i: 0, at, limits };
            let v = f.value(depth + 1)?;
            f.finish()?;
            Ok(v)
        }
        Some(b'"') | Some(b'\'') => {
            let (v, next) = read_quoted(t, 0, at, limits)?;
            let after = t.get(next..).unwrap_or("").trim();
            if !after.is_empty() && !after.starts_with('#') {
                return Err(TtError::malformed(
                    WHAT,
                    at + next,
                    "trailing content after a quoted scalar",
                ));
            }
            Ok(JsonValue::Str(v))
        }
        _ => {
            let cut = plain_end(t);
            let v = t.get(..cut).unwrap_or("").trim_end();
            check_string_len(v, limits)?;
            Ok(interpret(v))
        }
    }
}

/// Give a plain scalar its type, conservatively. See the module header.
fn interpret(t: &str) -> JsonValue {
    match t {
        "" | "~" | "null" | "Null" | "NULL" => return JsonValue::Null,
        "true" | "True" | "TRUE" => return JsonValue::Bool(true),
        "false" | "False" | "FALSE" => return JsonValue::Bool(false),
        _ => {}
    }
    if looks_integral(t) {
        if let Ok(i) = t.parse::<i64>() {
            return JsonValue::Int(i);
        }
        // Wider than i64: keep the digits rather than saturating them.
        return JsonValue::Num(t.to_string());
    }
    if looks_fractional(t) {
        return JsonValue::Num(t.to_string());
    }
    JsonValue::Str(t.to_string())
}

/// `-?` then digits, with no leading zero. `0755` deliberately fails: guessing at
/// octal is a fabrication, and `Str("0755")` is what the file actually says.
fn looks_integral(t: &str) -> bool {
    let b = t.as_bytes();
    let digits = if b.first() == Some(&b'-') { b.get(1..).unwrap_or(&[]) } else { b };
    if digits.is_empty() || !digits.iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    digits.first() != Some(&b'0') || digits.len() == 1
}

/// The JSON number grammar with a mandatory fraction or exponent.
fn looks_fractional(t: &str) -> bool {
    let b = t.as_bytes();
    let mut i = 0usize;
    if b.get(i) == Some(&b'-') {
        i += 1;
    }
    let int_start = i;
    while matches!(b.get(i), Some(c) if c.is_ascii_digit()) {
        i += 1;
    }
    if i == int_start {
        return false;
    }
    let mut decorated = false;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let frac_start = i;
        while matches!(b.get(i), Some(c) if c.is_ascii_digit()) {
            i += 1;
        }
        if i == frac_start {
            return false;
        }
        decorated = true;
    }
    if matches!(b.get(i), Some(b'e') | Some(b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+') | Some(b'-')) {
            i += 1;
        }
        let exp_start = i;
        while matches!(b.get(i), Some(c) if c.is_ascii_digit()) {
            i += 1;
        }
        if i == exp_start {
            return false;
        }
        decorated = true;
    }
    decorated && i == b.len()
}

/// Read a quoted scalar starting at `start`, returning it and the index past the
/// closing quote.
fn read_quoted(s: &str, start: usize, at: usize, limits: &Limits) -> TtResult<(String, usize)> {
    let b = s.as_bytes();
    let q = match b.get(start) {
        Some(c @ (b'"' | b'\'')) => *c,
        _ => return Err(TtError::malformed(WHAT, at + start, "expected a quoted scalar")),
    };
    let mut i = start + 1;
    let mut out = String::new();
    while i < b.len() {
        let c = match b.get(i) {
            Some(c) => *c,
            None => break,
        };
        if c == q {
            // In a single-quoted scalar `''` is one literal quote.
            if q == b'\'' && b.get(i + 1) == Some(&b'\'') {
                out.push('\'');
                i += 2;
                check_string_len(&out, limits)?;
                continue;
            }
            return Ok((out, i + 1));
        }
        if q == b'"' && c == b'\\' {
            let e = *b
                .get(i + 1)
                .ok_or_else(|| TtError::malformed(WHAT, at + i, "unterminated escape"))?;
            i += 2;
            match e {
                b'n' => out.push('\n'),
                b't' => out.push('\t'),
                b'r' => out.push('\r'),
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'0' => out.push('\0'),
                b'b' => out.push('\u{8}'),
                b'f' => out.push('\u{c}'),
                b'e' => out.push('\u{1b}'),
                b' ' => out.push(' '),
                b'u' => {
                    let mut v: u32 = 0;
                    for k in 0..4 {
                        let d = hex_digit(b.get(i + k).copied()).ok_or_else(|| {
                            TtError::malformed(WHAT, at + i + k, "bad hex digit in `\\u` escape")
                        })?;
                        v = (v << 4) | d as u32;
                    }
                    i += 4;
                    // `char::from_u32` rejects surrogates, which is what we want: a
                    // lone surrogate has no meaning outside a pair and this subset
                    // does not implement pairing.
                    let ch = char::from_u32(v).ok_or_else(|| {
                        TtError::malformed(WHAT, at + i, "invalid `\\u` code point")
                    })?;
                    out.push(ch);
                }
                _ => {
                    return Err(TtError::malformed(
                        WHAT,
                        at + i,
                        format!("unsupported escape `\\{}`", e as char),
                    ))
                }
            }
            check_string_len(&out, limits)?;
            continue;
        }
        // Copy one whole UTF-8 sequence. The input is a `&str`, so the boundary
        // walk cannot run past the end or land mid-character.
        let st = i;
        i += 1;
        while i < b.len() && matches!(b.get(i), Some(c) if (c & 0xC0) == 0x80) {
            i += 1;
        }
        out.push_str(
            s.get(st..i)
                .ok_or_else(|| TtError::malformed(WHAT, at + st, "invalid UTF-8 in scalar"))?,
        );
        check_string_len(&out, limits)?;
    }
    Err(TtError::malformed(WHAT, at + start, "unterminated quoted scalar"))
}

fn hex_digit(c: Option<u8>) -> Option<u8> {
    match c {
        Some(c @ b'0'..=b'9') => Some(c - b'0'),
        Some(c @ b'a'..=b'f') => Some(c - b'a' + 10),
        Some(c @ b'A'..=b'F') => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Flow collections
// ---------------------------------------------------------------------------

/// A single-line `[a, b]` or `{a: 1}`.
///
/// Flow collections are parsed from one line's text, so a collection left open at
/// the end of the line is refused rather than continued. That keeps the block
/// structure and the flow structure from having to agree about indentation.
struct Flow<'a> {
    s: &'a str,
    i: usize,
    at: usize,
    limits: &'a Limits,
}

impl<'a> Flow<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.as_bytes().get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ') | Some(b'\t')) {
            self.i += 1;
        }
    }

    fn unexpected_end(&self) -> TtError {
        TtError::malformed(
            WHAT,
            self.at + self.i,
            "flow collection is not closed on the line it started",
        )
    }

    /// After the top-level collection: nothing but spaces and a comment may follow.
    fn finish(&mut self) -> TtResult<()> {
        self.ws();
        let rest = self.s.get(self.i..).unwrap_or("").trim();
        if rest.is_empty() || rest.starts_with('#') {
            Ok(())
        } else {
            Err(TtError::malformed(
                WHAT,
                self.at + self.i,
                "trailing content after a flow collection",
            ))
        }
    }

    fn value(&mut self, depth: usize) -> TtResult<JsonValue> {
        self.ws();
        if let Some(e) = refusal_for(self.peek()) {
            return Err(e);
        }
        match self.peek() {
            None => Err(self.unexpected_end()),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.map(depth),
            Some(b'"') | Some(b'\'') => {
                let (v, next) = read_quoted(self.s, self.i, self.at, self.limits)?;
                self.i = next;
                Ok(JsonValue::Str(v))
            }
            _ => {
                let start = self.i;
                while !matches!(self.peek(), None | Some(b',') | Some(b']') | Some(b'}')) {
                    self.i += 1;
                }
                let raw = self.s.get(start..self.i).unwrap_or("");
                let cut = plain_end(raw);
                let t = raw.get(..cut).unwrap_or("").trim();
                check_string_len(t, self.limits)?;
                Ok(interpret(t))
            }
        }
    }

    fn array(&mut self, depth: usize) -> TtResult<JsonValue> {
        depth_guard(depth, self.limits)?;
        self.i += 1;
        let mut items: Vec<JsonValue> = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(JsonValue::Arr(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            if items.len() > self.limits.json_max_array_elements {
                return Err(TtError::LimitExceeded {
                    limit: "json_max_array_elements",
                    value: items.len() as u64,
                    max: self.limits.json_max_array_elements as u64,
                });
            }
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                    self.ws();
                    // A trailing comma before `]` is legal in flow context.
                    if self.peek() == Some(b']') {
                        self.i += 1;
                        break;
                    }
                }
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                None => return Err(self.unexpected_end()),
                _ => {
                    return Err(TtError::malformed(
                        WHAT,
                        self.at + self.i,
                        "expected `,` or `]` in a flow sequence",
                    ))
                }
            }
        }
        Ok(JsonValue::Arr(items))
    }

    fn map(&mut self, depth: usize) -> TtResult<JsonValue> {
        depth_guard(depth, self.limits)?;
        self.i += 1;
        let mut entries: Vec<(String, JsonValue)> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(JsonValue::Obj(entries));
        }
        loop {
            self.ws();
            if let Some(e) = refusal_for(self.peek()) {
                return Err(e);
            }
            let key = match self.peek() {
                Some(b'"') | Some(b'\'') => {
                    let (k, next) = read_quoted(self.s, self.i, self.at, self.limits)?;
                    self.i = next;
                    k
                }
                None => return Err(self.unexpected_end()),
                _ => {
                    let start = self.i;
                    while !matches!(self.peek(), None | Some(b':') | Some(b',') | Some(b'}')) {
                        self.i += 1;
                    }
                    let k = self.s.get(start..self.i).unwrap_or("").trim().to_string();
                    check_string_len(&k, self.limits)?;
                    k
                }
            };
            self.ws();
            if self.peek() != Some(b':') {
                return Err(TtError::malformed(
                    WHAT,
                    self.at + self.i,
                    "flow mapping entry without a value",
                ));
            }
            self.i += 1;
            if key.is_empty() {
                return Err(TtError::malformed(WHAT, self.at + self.i, "empty mapping key"));
            }
            if !seen.insert(key.clone()) {
                return Err(TtError::ambiguous(
                    "duplicate_key",
                    format!("`{key}` in a flow mapping at byte {}", self.at + self.i),
                ));
            }
            let v = self.value(depth + 1)?;
            entries.push((key, v));
            if entries.len() > self.limits.json_max_object_keys {
                return Err(TtError::LimitExceeded {
                    limit: "json_max_object_keys",
                    value: entries.len() as u64,
                    max: self.limits.json_max_object_keys as u64,
                });
            }
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                    self.ws();
                    if self.peek() == Some(b'}') {
                        self.i += 1;
                        break;
                    }
                }
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                None => return Err(self.unexpected_end()),
                _ => {
                    return Err(TtError::malformed(
                        WHAT,
                        self.at + self.i,
                        "expected `,` or `}` in a flow mapping",
                    ))
                }
            }
        }
        Ok(JsonValue::Obj(entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> TtResult<JsonValue> {
        parse(s.as_bytes(), &Limits::default())
    }
    fn ok(s: &str) -> JsonValue {
        p(s).expect("should parse")
    }
    fn field<'v>(v: &'v JsonValue, key: &str) -> &'v JsonValue {
        v.get(key).unwrap_or(&JsonValue::Null)
    }

    // -- the shapes a real config actually has ------------------------------

    #[test]
    fn accelerate_shaped_config() {
        let v = ok("\
compute_environment: LOCAL_MACHINE
distributed_type: MULTI_GPU
mixed_precision: bf16
num_processes: 4
gpu_ids: all
main_training_function: main
deepspeed_config:
  gradient_accumulation_steps: 8
  zero_stage: 2
  offload_optimizer_device: none
");
        assert_eq!(field(&v, "num_processes"), &JsonValue::Int(4));
        assert_eq!(field(&v, "mixed_precision"), &JsonValue::Str("bf16".into()));
        let ds = field(&v, "deepspeed_config");
        assert_eq!(field(ds, "zero_stage"), &JsonValue::Int(2));
        assert_eq!(field(ds, "gradient_accumulation_steps"), &JsonValue::Int(8));
    }

    #[test]
    fn model_card_front_matter_shape() {
        let v = ok("\
license: apache-2.0
base_model: Qwen/Qwen2.5-7B-Instruct
library_name: peft
tags:
  - lora
  - text-generation
datasets:
- teknium/OpenHermes-2.5
pipeline_tag: text-generation
model-index:
  - name: my-model
    results:
      - task:
          type: text-generation
        metrics:
          - name: accuracy
            value: 0.71
");
        assert_eq!(field(&v, "license"), &JsonValue::Str("apache-2.0".into()));
        assert_eq!(
            field(&v, "tags"),
            &JsonValue::Arr(vec![
                JsonValue::Str("lora".into()),
                JsonValue::Str("text-generation".into())
            ])
        );
        // A sequence written at the key's own indentation is the common spelling.
        assert_eq!(
            field(&v, "datasets"),
            &JsonValue::Arr(vec![JsonValue::Str("teknium/OpenHermes-2.5".into())])
        );
        let mi = field(&v, "model-index").as_arr().expect("array").first().cloned();
        let mi = mi.expect("one entry");
        assert_eq!(field(&mi, "name"), &JsonValue::Str("my-model".into()));
        let results = field(&mi, "results").as_arr().expect("array").to_vec();
        let metrics = field(&results[0], "metrics").as_arr().expect("array").to_vec();
        // 0.71 keeps its exact text rather than becoming a float.
        assert_eq!(field(&metrics[0], "value"), &JsonValue::Num("0.71".into()));
    }

    #[test]
    fn compose_shaped_nesting_and_flow() {
        let v = ok("\
version: '3.8'
services:
  api:
    image: vendor/serve:1.4
    command: [\"--model\", \"/models/final\", \"--lora\"]
    environment: {OPENAI_API_KEY: secret, MAX_TOKENS: 512}
    ports:
      - \"8000:8000\"
");
        assert_eq!(field(&v, "version"), &JsonValue::Str("3.8".into()));
        let api = field(field(&v, "services"), "api");
        assert_eq!(
            field(api, "command"),
            &JsonValue::Arr(vec![
                JsonValue::Str("--model".into()),
                JsonValue::Str("/models/final".into()),
                JsonValue::Str("--lora".into())
            ])
        );
        let env = field(api, "environment");
        assert_eq!(field(env, "MAX_TOKENS"), &JsonValue::Int(512));
        assert_eq!(
            field(api, "ports"),
            &JsonValue::Arr(vec![JsonValue::Str("8000:8000".into())])
        );
    }

    // -- scalars ------------------------------------------------------------

    #[test]
    fn numbers_keep_their_exact_text() {
        let v = ok("lr: 5e-5\ndropout: 0.05\nsteps: 1000\nneg: -3\nbig: 123456789012345678901234567890\n");
        assert_eq!(field(&v, "lr"), &JsonValue::Num("5e-5".into()));
        assert_eq!(field(&v, "dropout"), &JsonValue::Num("0.05".into()));
        assert_eq!(field(&v, "steps"), &JsonValue::Int(1000));
        assert_eq!(field(&v, "neg"), &JsonValue::Int(-3));
        assert_eq!(
            field(&v, "big"),
            &JsonValue::Num("123456789012345678901234567890".into())
        );
    }

    #[test]
    fn ambiguous_spellings_stay_strings() {
        let v = ok("a: yes\nb: no\nc: on\nd: off\ne: 0755\nf: 0x1f\ng: .inf\nh: 1_000\n");
        for k in ["a", "b", "c", "d", "e", "f", "g", "h"] {
            assert!(
                matches!(field(&v, k), JsonValue::Str(_)),
                "{k} should stay a string, got {:?}",
                field(&v, k)
            );
        }
    }

    #[test]
    fn booleans_and_nulls() {
        let v = ok("a: true\nb: False\nc: NULL\nd: ~\ne:\n");
        assert_eq!(field(&v, "a"), &JsonValue::Bool(true));
        assert_eq!(field(&v, "b"), &JsonValue::Bool(false));
        assert_eq!(field(&v, "c"), &JsonValue::Null);
        assert_eq!(field(&v, "d"), &JsonValue::Null);
        // A key with no value at all is null, not an error.
        assert_eq!(field(&v, "e"), &JsonValue::Null);
    }

    #[test]
    fn quoting_and_comments() {
        let v = ok("\
# leading comment
a: 'it''s here'   # trailing comment
b: \"tab\\there\"
c: plain # not part of the value
d: \"#hash inside\"
e: url#fragment
");
        assert_eq!(field(&v, "a"), &JsonValue::Str("it's here".into()));
        assert_eq!(field(&v, "b"), &JsonValue::Str("tab\there".into()));
        assert_eq!(field(&v, "c"), &JsonValue::Str("plain".into()));
        assert_eq!(field(&v, "d"), &JsonValue::Str("#hash inside".into()));
        // A `#` with no space before it is not a comment.
        assert_eq!(field(&v, "e"), &JsonValue::Str("url#fragment".into()));
    }

    #[test]
    fn unicode_escape_and_multibyte() {
        let v = ok("a: \"\\u00e9t\\u00e9\"\nb: héllo 世界\n");
        assert_eq!(field(&v, "a"), &JsonValue::Str("été".into()));
        assert_eq!(field(&v, "b"), &JsonValue::Str("héllo 世界".into()));
    }

    // -- documents ----------------------------------------------------------

    #[test]
    fn only_the_first_document_is_read() {
        let v = ok("---\na: 1\n---\na: 2\nb: 3\n");
        assert_eq!(field(&v, "a"), &JsonValue::Int(1));
        assert_eq!(v.as_obj().map(|o| o.len()), Some(1));
    }

    #[test]
    fn empty_and_comment_only_documents_are_null() {
        assert_eq!(ok(""), JsonValue::Null);
        assert_eq!(ok("\n\n  \n"), JsonValue::Null);
        assert_eq!(ok("# nothing here\n"), JsonValue::Null);
        assert_eq!(ok("---\n"), JsonValue::Null);
    }

    #[test]
    fn crlf_is_handled() {
        let v = ok("a: 1\r\nb:\r\n  c: 2\r\n");
        assert_eq!(field(&v, "a"), &JsonValue::Int(1));
        assert_eq!(field(field(&v, "b"), "c"), &JsonValue::Int(2));
    }

    #[test]
    fn front_matter_extraction() {
        let md = b"---\nbase_model: a/b\n---\n\n# Heading\n\ntext --- more\n";
        assert_eq!(front_matter(md), Some(&b"base_model: a/b\n"[..]));
        // A rule further down a README is not front matter.
        assert_eq!(front_matter(b"# Title\n\n---\n\ntext\n"), None);
        // An unterminated fence is not front matter either.
        assert_eq!(front_matter(b"---\nbase_model: a/b\n"), None);
        assert_eq!(front_matter(b""), None);
        assert_eq!(front_matter(b"---\n---\n"), Some(&b""[..]));
    }

    // -- block scalars ------------------------------------------------------

    #[test]
    fn block_scalars_are_captured_opaquely() {
        let v = ok("\
a: |
  line one
  line two

    indented
b: >-
  folded text
c: 1
");
        assert_eq!(
            field(&v, "a"),
            &JsonValue::Str("line one\nline two\n\n  indented".into())
        );
        assert_eq!(field(&v, "b"), &JsonValue::Str("folded text".into()));
        assert_eq!(field(&v, "c"), &JsonValue::Int(1));
    }

    #[test]
    fn block_scalar_indicators_we_cannot_reproduce_are_refused() {
        assert!(matches!(p("a: |+\n  x\n"), Err(TtError::OutOfScope { .. })));
        assert!(matches!(p("a: |2\n  x\n"), Err(TtError::OutOfScope { .. })));
        assert!(p("a: | junk\n  x\n").is_err());
    }

    // -- refusals -----------------------------------------------------------

    #[test]
    fn anchors_aliases_tags_and_merges_are_refused_by_name() {
        for (src, needle) in [
            ("a: &anchor 1\nb: 2\n", "anchor"),
            ("a: 1\nb: *anchor\n", "alias"),
            ("a: !!python/object:os.system\n", "tag"),
            ("base: &b {x: 1}\nchild:\n  <<: *b\n", "anchor"),
            ("%YAML 1.2\n---\na: 1\n", "directive"),
            ("? complex\n: value\n", "explicit mapping key"),
        ] {
            let e = p(src).unwrap_err();
            assert!(
                matches!(e, TtError::OutOfScope { .. }),
                "{src:?} should be refused, got {e:?}"
            );
            assert!(e.to_string().contains(needle), "{src:?} -> {e}");
        }
    }

    #[test]
    fn a_merge_key_on_its_own_is_named() {
        let e = p("a: 1\n<<: b\n").unwrap_err();
        assert!(e.to_string().contains("merge key"), "{e}");
    }

    #[test]
    fn tabs_used_for_indentation_are_refused() {
        assert!(matches!(p("a:\n\tb: 1\n"), Err(TtError::Malformed { .. })));
        assert!(matches!(p("  \tb: 1\n"), Err(TtError::Malformed { .. })));
        // A tab inside a value is only whitespace and is fine.
        assert!(p("a:\tvalue\n").is_ok());
    }

    #[test]
    fn duplicate_keys_are_refused_in_block_and_flow() {
        assert!(matches!(
            p("a: 1\na: 2\n"),
            Err(TtError::Ambiguous { what: "duplicate_key", .. })
        ));
        assert!(matches!(
            p("x: {a: 1, a: 2}\n"),
            Err(TtError::Ambiguous { what: "duplicate_key", .. })
        ));
        // The same key in *different* mappings is not a duplicate.
        assert!(p("a:\n  k: 1\nb:\n  k: 2\n").is_ok());
    }

    #[test]
    fn unterminated_quotes_and_flow_are_errors() {
        assert!(p("a: \"unterminated\n").is_err());
        assert!(p("a: 'unterminated\n").is_err());
        assert!(p("a: [1, 2\n").is_err());
        assert!(p("a: {b: 1\n").is_err());
        // A flow collection continued on the next line is refused, not guessed at.
        let e = p("a: [\n  1,\n  2\n]\n").unwrap_err();
        assert!(e.to_string().contains("closed on the line"), "{e}");
    }

    #[test]
    fn structural_confusion_is_an_error_not_a_partial_parse() {
        assert!(p("a: 1\n  b: 2\n").is_err(), "unexpected indentation");
        assert!(p("just a scalar document\n").is_err(), "bare scalar document");
        assert!(p("a: [1] junk\n").is_err(), "trailing content after flow");
        assert!(p("a: \"x\" junk\n").is_err(), "trailing content after quote");
        assert!(p("{a: 1}\nb: 2\n").is_err(), "flow root then block");
    }

    // -- bounds -------------------------------------------------------------

    #[test]
    fn oversized_input_is_a_limit_not_a_parse() {
        let lim = Limits::tiny();
        let big = "a: 1\n".repeat(2000);
        assert!(matches!(
            parse(big.as_bytes(), &lim).unwrap_err(),
            TtError::LimitExceeded { limit: "config_bytes", .. }
        ));
    }

    #[test]
    fn a_two_megabyte_scalar_hits_the_string_bound() {
        let src = format!("a: {}\n", "x".repeat(2 * 1024 * 1024));
        assert!(matches!(
            parse(src.as_bytes(), &Limits::default()).unwrap_err(),
            TtError::LimitExceeded { limit: "json_max_string_bytes", .. }
        ));
        // The same size inside quotes, and inside a block scalar.
        let quoted = format!("a: \"{}\"\n", "x".repeat(2 * 1024 * 1024));
        assert!(matches!(
            parse(quoted.as_bytes(), &Limits::default()).unwrap_err(),
            TtError::LimitExceeded { limit: "json_max_string_bytes", .. }
        ));
        let block = format!("a: |\n  {}\n", "x".repeat(2 * 1024 * 1024));
        assert!(matches!(
            parse(block.as_bytes(), &Limits::default()).unwrap_err(),
            TtError::LimitExceeded { limit: "json_max_string_bytes", .. }
        ));
    }

    #[test]
    fn a_hundred_thousand_keys_hits_the_key_bound() {
        let mut src = String::new();
        for i in 0..100_000 {
            src.push_str(&format!("k{i}: 1\n"));
        }
        assert!(matches!(
            parse(src.as_bytes(), &Limits::default()).unwrap_err(),
            TtError::LimitExceeded { limit: "json_max_object_keys", .. }
        ));
    }

    #[test]
    fn deep_nesting_stops_at_the_depth_bound() {
        // Ten thousand levels of block nesting.
        let mut src = String::new();
        for i in 0..10_000 {
            src.push_str(&" ".repeat(i.min(200)));
            src.push_str("k:\n");
        }
        assert!(parse(src.as_bytes(), &Limits::default()).is_err());

        // The same through flow nesting, which recurses on one line.
        let flow = format!("a: {}{}", "[".repeat(5_000), "]".repeat(5_000));
        assert!(matches!(
            parse(flow.as_bytes(), &Limits::default()).unwrap_err(),
            TtError::LimitExceeded { limit: "json_max_depth", .. }
        ));

        // And through sequence compaction, which recurses on one line too.
        let dashes = format!("a: 1\n{}x\n", "- ".repeat(5_000));
        assert!(parse(dashes.as_bytes(), &Limits::default()).is_err());
    }

    #[test]
    fn depth_just_inside_the_bound_is_accepted() {
        let lim = Limits::tiny();
        let inner = format!("{}{}", "[".repeat(lim.json_max_depth - 1), "]".repeat(lim.json_max_depth - 1));
        assert!(parse(format!("a: {inner}\n").as_bytes(), &lim).is_ok());
        let over = format!("{}{}", "[".repeat(lim.json_max_depth + 1), "]".repeat(lim.json_max_depth + 1));
        assert!(parse(format!("a: {over}\n").as_bytes(), &lim).is_err());
    }

    #[test]
    fn width_bounds_apply_to_flow_too() {
        let lim = Limits::tiny();
        let arr = format!("a: [{}]", vec!["1"; 100].join(","));
        assert!(matches!(
            parse(arr.as_bytes(), &lim).unwrap_err(),
            TtError::LimitExceeded { limit: "json_max_array_elements", .. }
        ));
        let seq: String = (0..100).map(|i| format!("- {i}\n")).collect();
        assert!(matches!(
            parse(seq.as_bytes(), &lim).unwrap_err(),
            TtError::LimitExceeded { limit: "json_max_array_elements", .. }
        ));
    }

    #[test]
    fn invalid_utf8_and_bom_are_rejected() {
        assert!(parse(&[b'a', b':', b' ', 0xff], &Limits::default()).is_err());
        assert!(parse("\u{feff}a: 1".as_bytes(), &Limits::default()).is_err());
    }

    // -- adversarial --------------------------------------------------------

    #[test]
    fn hostile_fragments_never_panic() {
        let cases: &[&str] = &[
            "",
            "-",
            "- ",
            ":",
            ": value",
            "a:",
            "a::",
            "a: :",
            "-\n-\n-\n",
            "- - - - -",
            "a: [",
            "a: ]",
            "a: {",
            "a: }",
            "a: [}",
            "a: {]",
            "a: {,}",
            "a: [,]",
            "a: [1,]",
            "a: {b: }",
            "a: {b}",
            "a: \"\\",
            "a: \"\\q\"",
            "a: \"\\u00\"",
            "a: \"\\ud800\"",
            "a: '",
            "---",
            "...",
            "--- a",
            "... a",
            "\t",
            " \t ",
            "a: |",
            "a: >",
            "a: |-",
            "a: 1\n\ta: 2",
            "- a: 1\n  b: 2\n- c: 3",
            "  a: 1\n b: 2\n",
            "a:\n - b\n  - c\n",
            "#",
            "# comment only",
            "a: #",
            "a: 1 #",
            "'a': 1",
            "\"a\": 1",
            "\"a\" b: 1",
            "a: \u{1F600}",
            "\u{1F600}: a",
        ];
        for c in cases {
            let _ = parse(c.as_bytes(), &Limits::default());
            let _ = parse(c.as_bytes(), &Limits::tiny());
        }
    }

    #[test]
    fn every_byte_prefix_of_a_real_document_terminates() {
        let src = "---\nbase_model: a/b\ntags:\n  - lora\nnested:\n  x: [1, {y: 2}]\n";
        for n in 0..=src.len() {
            let _ = parse(&src.as_bytes()[..n], &Limits::default());
        }
    }
}
