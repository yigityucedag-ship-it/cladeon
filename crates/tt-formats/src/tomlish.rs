//! A deliberately small, bounded TOML subset.
//!
//! Enough to read `Cargo.lock`, `pyproject.toml` and pip configuration; nothing
//! more. Full TOML has date-times, multi-line literals, heterogeneous arrays and
//! several string forms this product has no use for, and every one of them is
//! parser surface that would only ever be exercised by a file somebody chose to
//! hand us.
//!
//! Anything unsupported is **refused with an error**, never guessed at. The caller
//! turns that refusal into coverage note `TT-FMT-010`, so a file we could not read
//! appears in the report as a file we could not read — which is the honest outcome,
//! and a far better one than a half-parse presented as a whole.
//!
//! Output is [`JsonValue`] so that everything downstream handles one shape, with
//! non-integral numbers kept as their exact source text rather than converted to
//! binary floating point.

use tt_core::error::{TtError, TtResult};
use tt_core::json::JsonValue;
use tt_core::limits::Limits;

const WHAT: &str = "toml";

/// Parse a TOML document.
pub fn parse(bytes: &[u8], limits: &Limits) -> TtResult<JsonValue> {
    if bytes.len() as u64 > limits.config_bytes {
        return Err(TtError::LimitExceeded {
            limit: "config_bytes",
            value: bytes.len() as u64,
            max: limits.config_bytes,
        });
    }
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(TtError::malformed(WHAT, 0, "byte order mark"));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|e| TtError::malformed(WHAT, e.valid_up_to(), "invalid UTF-8"))?;

    let mut root = JsonValue::Obj(Vec::new());
    // The table the next bare `key = value` belongs to.
    let mut path: Vec<String> = Vec::new();
    let mut keys_seen = 0usize;

    let mut lines = text.lines().enumerate().peekable();
    while let Some((lineno, raw)) = lines.next() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("[[") {
            let name = rest.strip_suffix("]]").ok_or_else(|| {
                TtError::malformed(WHAT, lineno, "unterminated array-of-tables header")
            })?;
            path = dotted(name.trim(), lineno)?;
            depth_guard(path.len(), limits)?;
            append_table(&mut root, &path, limits)?;
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let name = rest
                .strip_suffix(']')
                .ok_or_else(|| TtError::malformed(WHAT, lineno, "unterminated table header"))?;
            path = dotted(name.trim(), lineno)?;
            depth_guard(path.len(), limits)?;
            ensure_table(&mut root, &path, limits)?;
            continue;
        }

        let eq = line
            .find('=')
            .ok_or_else(|| TtError::malformed(WHAT, lineno, "expected `key = value`"))?;
        let key_text = line[..eq].trim();
        let mut value_text = line[eq + 1..].trim().to_string();

        // An array or inline table may run across lines. Keep pulling until the
        // brackets balance, bounded by the same line budget as everything else.
        let mut joined = 0usize;
        while unbalanced(&value_text) {
            let Some((_, next)) = lines.next() else {
                return Err(TtError::malformed(WHAT, lineno, "unterminated array or inline table"));
            };
            value_text.push(' ');
            value_text.push_str(strip_comment(next).trim());
            joined += 1;
            if joined > 4096 {
                return Err(TtError::LimitExceeded {
                    limit: "toml_value_lines",
                    value: joined as u64,
                    max: 4096,
                });
            }
        }

        let key_path = dotted(key_text, lineno)?;
        let (value, rest) = parse_value(value_text.trim(), lineno, 1, limits)?;
        if !rest.trim().is_empty() {
            return Err(TtError::malformed(WHAT, lineno, "trailing content after value"));
        }

        keys_seen += 1;
        if keys_seen > limits.json_max_object_keys {
            return Err(TtError::LimitExceeded {
                limit: "json_max_object_keys",
                value: keys_seen as u64,
                max: limits.json_max_object_keys as u64,
            });
        }

        let mut full = path.clone();
        full.extend(key_path);
        depth_guard(full.len(), limits)?;
        insert(&mut root, &full, value, lineno, limits)?;
    }

    Ok(root)
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

/// Remove a `#` comment, respecting quotes so a `#` inside a string survives.
fn strip_comment(line: &str) -> &str {
    let b = line.as_bytes();
    let mut in_basic = false;
    let mut in_literal = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' if !in_literal => in_basic = !in_basic,
            b'\'' if !in_basic => in_literal = !in_literal,
            b'\\' if in_basic => i += 1,
            b'#' if !in_basic && !in_literal => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

/// True when brackets or braces are still open outside of any string.
fn unbalanced(s: &str) -> bool {
    let b = s.as_bytes();
    let (mut depth, mut in_basic, mut in_literal) = (0i32, false, false);
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' if !in_literal => in_basic = !in_basic,
            b'\'' if !in_basic => in_literal = !in_literal,
            b'\\' if in_basic => i += 1,
            b'[' | b'{' if !in_basic && !in_literal => depth += 1,
            b']' | b'}' if !in_basic && !in_literal => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    depth > 0
}

/// Split a dotted key into its parts, honouring quoted segments.
fn dotted(s: &str, at: usize) -> TtResult<Vec<String>> {
    if s.is_empty() {
        return Err(TtError::malformed(WHAT, at, "empty key"));
    }
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in s.chars() {
        match (quote, c) {
            (Some(q), ch) if ch == q => quote = None,
            (Some(_), ch) => cur.push(ch),
            (None, '"') => quote = Some('"'),
            (None, '\'') => quote = Some('\''),
            (None, '.') => {
                let t = cur.trim().to_string();
                if t.is_empty() {
                    return Err(TtError::malformed(WHAT, at, "empty key segment"));
                }
                parts.push(t);
                cur.clear();
            }
            (None, ch) => cur.push(ch),
        }
    }
    if quote.is_some() {
        return Err(TtError::malformed(WHAT, at, "unterminated quoted key"));
    }
    let t = cur.trim().to_string();
    if t.is_empty() {
        return Err(TtError::malformed(WHAT, at, "empty key segment"));
    }
    parts.push(t);
    Ok(parts)
}

fn obj_get_mut<'a>(v: &'a mut JsonValue, key: &str) -> Option<&'a mut JsonValue> {
    match v {
        JsonValue::Obj(e) => e.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn obj_insert(v: &mut JsonValue, key: &str, value: JsonValue) {
    if let JsonValue::Obj(e) = v {
        e.push((key.to_string(), value));
    }
}

/// Walk to a table, creating objects on the way. An array-of-tables step descends
/// into its most recent element, which is what makes `[[package]]` then `name = ...`
/// attach to the right entry.
fn walk<'a>(root: &'a mut JsonValue, path: &[String], limits: &Limits) -> TtResult<&'a mut JsonValue> {
    let mut cur = root;
    for (i, seg) in path.iter().enumerate() {
        depth_guard(i + 1, limits)?;
        if obj_get_mut(cur, seg).is_none() {
            obj_insert(cur, seg, JsonValue::Obj(Vec::new()));
        }
        let next = obj_get_mut(cur, seg).expect("just inserted");
        cur = match next {
            JsonValue::Arr(items) => items.last_mut().ok_or_else(|| {
                TtError::malformed(WHAT, 0, "array of tables referenced before any entry")
            })?,
            other => other,
        };
    }
    Ok(cur)
}

fn ensure_table(root: &mut JsonValue, path: &[String], limits: &Limits) -> TtResult<()> {
    walk(root, path, limits).map(|_| ())
}

/// `[[name]]`: append a fresh table to the array at `path`.
fn append_table(root: &mut JsonValue, path: &[String], limits: &Limits) -> TtResult<()> {
    let (last, parent) = path.split_last().ok_or_else(|| {
        TtError::malformed(WHAT, 0, "empty array-of-tables header")
    })?;
    let target = walk(root, parent, limits)?;
    match obj_get_mut(target, last) {
        Some(JsonValue::Arr(items)) => {
            if items.len() >= limits.json_max_array_elements {
                return Err(TtError::LimitExceeded {
                    limit: "json_max_array_elements",
                    value: items.len() as u64,
                    max: limits.json_max_array_elements as u64,
                });
            }
            items.push(JsonValue::Obj(Vec::new()));
        }
        Some(_) => {
            return Err(TtError::ambiguous(
                "duplicate_key",
                format!("`{last}` is already a table and cannot also be an array of tables"),
            ))
        }
        None => obj_insert(target, last, JsonValue::Arr(vec![JsonValue::Obj(Vec::new())])),
    }
    Ok(())
}

fn insert(
    root: &mut JsonValue,
    path: &[String],
    value: JsonValue,
    at: usize,
    limits: &Limits,
) -> TtResult<()> {
    let (last, parent) = path
        .split_last()
        .ok_or_else(|| TtError::malformed(WHAT, at, "empty key path"))?;
    let target = walk(root, parent, limits)?;
    if obj_get_mut(target, last).is_some() {
        // A config that says two things must not be silently resolved to one.
        return Err(TtError::ambiguous("duplicate_key", format!("`{last}` at line {at}")));
    }
    obj_insert(target, last, value);
    Ok(())
}

/// Parse one value, returning it and whatever text followed.
fn parse_value<'a>(
    s: &'a str,
    at: usize,
    depth: usize,
    limits: &Limits,
) -> TtResult<(JsonValue, &'a str)> {
    depth_guard(depth, limits)?;
    let s = s.trim_start();
    let Some(first) = s.chars().next() else {
        return Err(TtError::malformed(WHAT, at, "missing value"));
    };
    match first {
        '"' | '\'' => {
            let (text, rest) = parse_string(s, at, limits)?;
            Ok((JsonValue::Str(text), rest))
        }
        '[' => {
            let mut rest = &s[1..];
            let mut items = Vec::new();
            loop {
                rest = rest.trim_start();
                if let Some(r) = rest.strip_prefix(']') {
                    return Ok((JsonValue::Arr(items), r));
                }
                if rest.is_empty() {
                    return Err(TtError::malformed(WHAT, at, "unterminated array"));
                }
                let (v, r) = parse_value(rest, at, depth + 1, limits)?;
                items.push(v);
                if items.len() > limits.json_max_array_elements {
                    return Err(TtError::LimitExceeded {
                        limit: "json_max_array_elements",
                        value: items.len() as u64,
                        max: limits.json_max_array_elements as u64,
                    });
                }
                rest = r.trim_start();
                if let Some(r) = rest.strip_prefix(',') {
                    rest = r;
                } else if !rest.starts_with(']') {
                    return Err(TtError::malformed(WHAT, at, "expected `,` or `]` in array"));
                }
            }
        }
        '{' => {
            let mut rest = &s[1..];
            let mut entries: Vec<(String, JsonValue)> = Vec::new();
            loop {
                rest = rest.trim_start();
                if let Some(r) = rest.strip_prefix('}') {
                    return Ok((JsonValue::Obj(entries), r));
                }
                if rest.is_empty() {
                    return Err(TtError::malformed(WHAT, at, "unterminated inline table"));
                }
                let eq = rest
                    .find('=')
                    .ok_or_else(|| TtError::malformed(WHAT, at, "expected `=` in inline table"))?;
                let key = rest[..eq].trim().trim_matches(['"', '\'']).to_string();
                if key.is_empty() {
                    return Err(TtError::malformed(WHAT, at, "empty inline-table key"));
                }
                if entries.iter().any(|(k, _)| *k == key) {
                    return Err(TtError::ambiguous("duplicate_key", key));
                }
                let (v, r) = parse_value(&rest[eq + 1..], at, depth + 1, limits)?;
                entries.push((key, v));
                rest = r.trim_start();
                if let Some(r) = rest.strip_prefix(',') {
                    rest = r;
                } else if !rest.starts_with('}') {
                    return Err(TtError::malformed(WHAT, at, "expected `,` or `}` in inline table"));
                }
            }
        }
        _ => {
            let end = s
                .find(|c: char| c == ',' || c == ']' || c == '}')
                .unwrap_or(s.len());
            let token = s[..end].trim();
            let rest = &s[end..];
            let value = match token {
                "true" => JsonValue::Bool(true),
                "false" => JsonValue::Bool(false),
                "" => return Err(TtError::malformed(WHAT, at, "missing value")),
                t => {
                    // Date-times and the other TOML scalar forms are out of scope.
                    // Refusing beats silently storing a shape nothing downstream
                    // knows how to read.
                    let cleaned = t.replace('_', "");
                    if let Ok(i) = cleaned.parse::<i64>() {
                        JsonValue::Int(i)
                    } else if is_number_like(&cleaned) {
                        JsonValue::Num(t.to_string())
                    } else {
                        return Err(TtError::out_of_scope(format!(
                            "unsupported TOML scalar `{t}` at line {at}"
                        )));
                    }
                }
            };
            Ok((value, rest))
        }
    }
}

fn is_number_like(s: &str) -> bool {
    let t = s.strip_prefix(['+', '-']).unwrap_or(s);
    !t.is_empty()
        && t.bytes().all(|c| c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-'))
        && t.bytes().any(|c| c.is_ascii_digit())
}

fn parse_string<'a>(s: &'a str, at: usize, limits: &Limits) -> TtResult<(String, &'a str)> {
    if s.starts_with("\"\"\"") || s.starts_with("'''") {
        return Err(TtError::out_of_scope("multi-line TOML strings"));
    }
    let literal = s.starts_with('\'');
    let quote = if literal { '\'' } else { '"' };
    let mut out = String::new();
    let mut chars = s[1..].char_indices();
    while let Some((i, c)) = chars.next() {
        if c == quote {
            return Ok((out, &s[1 + i + c.len_utf8()..]));
        }
        if !literal && c == '\\' {
            let Some((_, e)) = chars.next() else {
                return Err(TtError::malformed(WHAT, at, "unterminated escape"));
            };
            out.push(match e {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '"' => '"',
                '\\' => '\\',
                'b' => '\u{08}',
                'f' => '\u{0c}',
                other => {
                    return Err(TtError::malformed(
                        WHAT,
                        at,
                        format!("unsupported escape `\\{other}`"),
                    ))
                }
            });
        } else {
            out.push(c);
        }
        if out.len() > limits.json_max_string_bytes {
            return Err(TtError::LimitExceeded {
                limit: "json_max_string_bytes",
                value: out.len() as u64,
                max: limits.json_max_string_bytes as u64,
            });
        }
    }
    Err(TtError::malformed(WHAT, at, "unterminated string"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> TtResult<JsonValue> {
        parse(s.as_bytes(), &Limits::default())
    }

    #[test]
    fn a_cargo_lock_shape_parses() {
        let src = "\
version = 3

[[package]]
name = \"tt-core\"
version = \"0.1.0\"

[[package]]
name = \"sha2\"
version = \"0.10.9\"
dependencies = [\"cfg-if\", \"digest\"]
";
        let v = p(src).unwrap();
        let pkgs = v.get("package").unwrap().as_arr().unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].get("name").and_then(|x| x.as_str()), Some("tt-core"));
        assert_eq!(pkgs[1].get("name").and_then(|x| x.as_str()), Some("sha2"));
        assert_eq!(pkgs[1].get("dependencies").unwrap().as_arr().unwrap().len(), 2);
    }

    #[test]
    fn nested_tables_and_dotted_keys() {
        let src = "[tool.poetry]\nname = \"x\"\n\n[tool.poetry.dependencies]\nopenai = \"^1.0\"\n";
        let v = p(src).unwrap();
        let deps = v.get("tool").unwrap().get("poetry").unwrap().get("dependencies").unwrap();
        assert_eq!(deps.get("openai").and_then(|x| x.as_str()), Some("^1.0"));
    }

    #[test]
    fn a_pyproject_dependency_list_parses() {
        let src = "[project]\nname = \"demo\"\ndependencies = [\n  \"openai>=1.0\",\n  \"peft\",\n]\n";
        let v = p(src).unwrap();
        let d = v.get("project").unwrap().get("dependencies").unwrap().as_arr().unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].as_str(), Some("openai>=1.0"));
    }

    #[test]
    fn numbers_keep_their_kind_and_text() {
        let v = p("a = 42\nb = 1_000\nc = 0.05\nd = 5e-5\n").unwrap();
        assert_eq!(v.get("a"), Some(&JsonValue::Int(42)));
        assert_eq!(v.get("b"), Some(&JsonValue::Int(1000)));
        // A fractional value keeps its exact source text; no float is created.
        assert_eq!(v.get("c"), Some(&JsonValue::Num("0.05".into())));
        assert_eq!(v.get("d"), Some(&JsonValue::Num("5e-5".into())));
    }

    #[test]
    fn booleans_strings_and_inline_tables() {
        let v = p("a = true\nb = 'literal \\n'\nc = { x = 1, y = \"two\" }\n").unwrap();
        assert_eq!(v.get("a"), Some(&JsonValue::Bool(true)));
        assert_eq!(v.get("b").and_then(|x| x.as_str()), Some("literal \\n"));
        assert_eq!(v.get("c").unwrap().get("y").and_then(|x| x.as_str()), Some("two"));
    }

    #[test]
    fn a_hash_inside_a_string_is_not_a_comment() {
        let v = p("a = \"value # not a comment\"  # this is\n").unwrap();
        assert_eq!(v.get("a").and_then(|x| x.as_str()), Some("value # not a comment"));
    }

    #[test]
    fn duplicate_keys_are_refused() {
        let e = p("a = 1\na = 2\n").unwrap_err();
        assert!(matches!(e, TtError::Ambiguous { what: "duplicate_key", .. }), "{e:?}");
    }

    #[test]
    fn unsupported_constructs_are_refused_not_guessed() {
        // A date-time is valid TOML and out of scope here. Refusing beats storing a
        // shape nothing downstream can read.
        assert!(p("a = 1979-05-27T07:32:00Z\n").is_err());
        assert!(p("a = \"\"\"multi\nline\"\"\"\n").is_err());
        assert!(p("a = \n").is_err());
        assert!(p("[unterminated\n").is_err());
        assert!(p("no equals sign here\n").is_err());
        assert!(p("a = [1, 2\n").is_err(), "unterminated array");
        assert!(p("a = \"unterminated\n").is_err());
    }

    #[test]
    fn bounds_are_enforced() {
        let tiny = Limits::tiny();
        let big = "a = 1\n".repeat(5000);
        assert!(matches!(
            parse(big.as_bytes(), &tiny).unwrap_err(),
            TtError::LimitExceeded { limit: "config_bytes", .. }
        ));
        let many: String = (0..100).map(|i| format!("k{i} = 1\n")).collect();
        assert!(matches!(
            parse(many.as_bytes(), &tiny).unwrap_err(),
            TtError::LimitExceeded { limit: "json_max_object_keys", .. }
        ));
        let deep = format!("a = {}1{}\n", "[".repeat(200), "]".repeat(200));
        assert!(parse(deep.as_bytes(), &tiny).is_err());
    }

    #[test]
    fn empty_input_is_an_empty_document() {
        assert_eq!(p("").unwrap(), JsonValue::Obj(Vec::new()));
        assert_eq!(p("# just a comment\n\n").unwrap(), JsonValue::Obj(Vec::new()));
    }

    #[test]
    fn a_bom_is_rejected_rather_than_stripped() {
        assert!(parse("\u{feff}a = 1".as_bytes(), &Limits::default()).is_err());
    }

    #[test]
    fn garbage_bytes_never_panic() {
        for src in [&b"\xff\xfe"[..], &[0u8; 64][..], b"[[[[[[".as_slice()] {
            let _ = parse(src, &Limits::default());
        }
    }
}
