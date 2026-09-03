//! Redaction: nothing leaves the vendor machine that the vendor has not seen.
//!
//! Two separate jobs live here, and conflating them is the classic way these tools
//! leak:
//!
//! 1. **Path aliasing.** Absolute paths are replaced by scoped aliases
//!    (`ROOT1/adapter/adapter_config.json`). A path outside every selected root
//!    becomes `[OUT-OF-SCOPE-PATH]`, never a partial real path.
//! 2. **Secret scrubbing.** Free text is scanned for credential shapes, e-mail
//!    addresses, private-key blocks and Windows user names.
//!
//! The scrubber is **allow-nothing on values, allow-list on keys**: a field whose
//! key looks like a credential is redacted wholesale regardless of what its value
//! looks like, because an unrecognised token shape is exactly the case where shape
//! matching fails.
//!
//! Every redaction increments a counter that is published in the report's redaction
//! ledger. The vendor may hide a *value*; the *fact that something was hidden* is
//! never removable.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// One row of the published redaction ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionEvent {
    pub rule: &'static str,
    pub kind: &'static str,
    pub count: u64,
}

#[derive(Debug, Clone)]
struct Root {
    canonical: PathBuf,
    alias: String,
}

#[derive(Debug, Default)]
pub struct Redactor {
    roots: Vec<Root>,
    usernames: Vec<String>,
    counts: BTreeMap<(&'static str, &'static str), u64>,
}

/// Placeholder for a path that lies outside every selected root.
pub const OUT_OF_SCOPE_PATH: &str = "[OUT-OF-SCOPE-PATH]";

impl Redactor {
    pub fn new() -> Self {
        let mut r = Redactor::default();
        if let Ok(u) = std::env::var("USERNAME") {
            r.add_username(&u);
        }
        if let Ok(u) = std::env::var("USER") {
            r.add_username(&u);
        }
        r
    }

    /// Register a selected root and return its alias (`ROOT1`, `ROOT2`, ...).
    pub fn add_root(&mut self, path: &Path) -> String {
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        // A root under C:\Users\<name> tells us the account name even when the
        // environment does not.
        self.learn_username_from_path(&canonical);
        let alias = format!("ROOT{}", self.roots.len() + 1);
        self.roots.push(Root { canonical, alias: alias.clone() });
        alias
    }

    pub fn add_username(&mut self, name: &str) {
        let name = name.trim();
        // Very short names would alias ordinary words out of the report.
        if name.len() >= 3 && !self.usernames.iter().any(|u| u.eq_ignore_ascii_case(name)) {
            self.usernames.push(name.to_string());
        }
    }

    fn learn_username_from_path(&mut self, p: &Path) {
        let comps: Vec<String> = p
            .components()
            .filter_map(|c| match c {
                Component::Normal(s) => Some(s.to_string_lossy().to_string()),
                _ => None,
            })
            .collect();
        for w in comps.windows(2) {
            if w[0].eq_ignore_ascii_case("Users") || w[0].eq_ignore_ascii_case("home") {
                self.add_username(&w[1]);
            }
        }
    }

    fn bump(&mut self, rule: &'static str, kind: &'static str) {
        *self.counts.entry((rule, kind)).or_insert(0) += 1;
    }

    /// The published ledger, sorted for determinism.
    pub fn ledger(&self) -> Vec<RedactionEvent> {
        self.counts
            .iter()
            .map(|((rule, kind), count)| RedactionEvent { rule, kind, count: *count })
            .collect()
    }

    pub fn total_redactions(&self) -> u64 {
        self.counts.values().sum()
    }

    /// Record that the submitter excluded a source. Recorded, never removable.
    pub fn note_submitter_exclusion(&mut self) {
        self.bump("CL-PRIV-004", "submitter_exclusion");
    }

    /// Record that the submitter redacted a displayed value. The underlying fact
    /// stays in the report.
    pub fn note_submitter_display_redaction(&mut self) {
        self.bump("CL-PRIV-005", "submitter_display_redaction");
    }

    // -----------------------------------------------------------------------
    // Path aliasing
    // -----------------------------------------------------------------------

    /// Map an absolute path to `ROOTn/relative/path`, or to
    /// [`OUT_OF_SCOPE_PATH`] when it is under no selected root.
    ///
    /// Comparison is case-insensitive because Windows paths are, and a
    /// case-different prefix that failed to match would leak the real path.
    pub fn alias_path(&mut self, path: &Path) -> String {
        let aliased = self.alias_path_quiet(path);
        self.bump("CL-PRIV-003", "absolute_path");
        aliased
    }

    /// Alias without counting, for internal comparisons.
    pub fn alias_path_quiet(&self, path: &Path) -> String {
        for root in &self.roots {
            if let Some(rel) = strip_prefix_ci(path, &root.canonical) {
                return if rel.is_empty() {
                    root.alias.clone()
                } else {
                    format!("{}/{}", root.alias, rel)
                };
            }
        }
        OUT_OF_SCOPE_PATH.to_string()
    }

    // -----------------------------------------------------------------------
    // Key-name policy
    // -----------------------------------------------------------------------

    /// True when a key name means "the value is a credential" regardless of shape.
    pub fn is_sensitive_key(key: &str) -> bool {
        let k = key.to_ascii_lowercase();
        const NEEDLES: &[&str] = &[
            "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
            "access_key", "secret_key", "private_key", "credential", "authorization",
            "auth_token", "session", "cookie", "bearer", "signature", "client_secret",
            "connection_string", "conn_str", "dsn", "sas_token", "account_key",
        ];
        // `public_key` and `key_dim` must not trip the `key` needles, so match on
        // the specific compounds above rather than on a bare `key`.
        NEEDLES.iter().any(|n| k.contains(n))
    }

    /// Redact a value because of its key name. Returns the placeholder and counts it.
    pub fn scrub_field(&mut self, key: &str, value: &str) -> String {
        if Redactor::is_sensitive_key(key) && !value.is_empty() {
            self.bump("CL-PRIV-001", "sensitive_key_value");
            return "[REDACTED:by-key-name]".to_string();
        }
        self.scrub(value)
    }

    // -----------------------------------------------------------------------
    // Free-text scrubbing
    // -----------------------------------------------------------------------

    /// Scan free text and replace every credential shape, e-mail address, private
    /// key block, absolute path and known user name.
    pub fn scrub(&mut self, text: &str) -> String {
        let mut matches: Vec<Match> = Vec::new();
        find_pem_blocks(text, &mut matches);
        find_windows_paths(text, &mut matches);
        find_tokens(text, &mut matches);
        find_jwts(text, &mut matches);
        find_emails(text, &mut matches);
        for u in &self.usernames {
            find_literal_ci(text, u, "windows_username", "[USER]", &mut matches);
        }

        // Earliest wins; on a tie the longest wins. Overlaps are then dropped, so a
        // path containing a user name is replaced once, as a path.
        matches.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));

        let mut out = String::with_capacity(text.len());
        let mut cursor = 0usize;
        let bytes = text.as_bytes();
        for m in matches {
            if m.start < cursor {
                continue;
            }
            out.push_str(&text[cursor..m.start]);
            let replacement = match m.kind {
                "windows_path" => {
                    let raw = &text[m.start..m.end];
                    let aliased = self.alias_path_quiet(Path::new(raw));
                    if aliased == OUT_OF_SCOPE_PATH {
                        self.bump("CL-PRIV-003", "absolute_path");
                        OUT_OF_SCOPE_PATH.to_string()
                    } else {
                        self.bump("CL-PRIV-003", "absolute_path");
                        aliased
                    }
                }
                "windows_username" => {
                    self.bump("CL-PRIV-002", "windows_username");
                    m.replacement.to_string()
                }
                "email_address" => {
                    self.bump("CL-PRIV-001", "email_address");
                    m.replacement.to_string()
                }
                _ => {
                    self.bump("CL-PRIV-001", "credential");
                    m.replacement.to_string()
                }
            };
            out.push_str(&replacement);
            cursor = m.end;
        }
        out.push_str(&text[cursor.min(bytes.len())..]);
        out
    }

    /// True when scrubbing would change the text. Used by the preflight preview.
    pub fn would_change(&self, text: &str) -> bool {
        let mut probe = Redactor {
            roots: self.roots.clone(),
            usernames: self.usernames.clone(),
            counts: BTreeMap::new(),
        };
        probe.scrub(text) != text
    }
}

struct Match {
    start: usize,
    end: usize,
    kind: &'static str,
    replacement: &'static str,
}

fn strip_prefix_ci(path: &Path, root: &Path) -> Option<String> {
    let p: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().to_string()),
            Component::Prefix(p) => Some(p.as_os_str().to_string_lossy().to_string()),
            Component::RootDir => Some(String::new()),
            _ => None,
        })
        .collect();
    let r: Vec<String> = root
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().to_string()),
            Component::Prefix(p) => Some(p.as_os_str().to_string_lossy().to_string()),
            Component::RootDir => Some(String::new()),
            _ => None,
        })
        .collect();
    if p.len() < r.len() {
        return None;
    }
    for (a, b) in p.iter().zip(r.iter()) {
        if !a.eq_ignore_ascii_case(b) {
            return None;
        }
    }
    Some(p[r.len()..].join("/"))
}

// ---------------------------------------------------------------------------
// Matchers
// ---------------------------------------------------------------------------

fn find_literal_ci(
    hay: &str,
    needle: &str,
    kind: &'static str,
    replacement: &'static str,
    out: &mut Vec<Match>,
) {
    if needle.is_empty() {
        return;
    }
    let h = hay.to_ascii_lowercase();
    let n = needle.to_ascii_lowercase();
    let mut from = 0usize;
    while let Some(pos) = h[from..].find(&n) {
        let start = from + pos;
        let end = start + n.len();
        // Only a whole token, so a user called "sam" does not blank "same".
        let before_ok = start == 0 || !is_word_byte(hay.as_bytes()[start - 1]);
        let after_ok = end >= hay.len() || !is_word_byte(hay.as_bytes()[end]);
        if before_ok && after_ok {
            out.push(Match { start, end, kind, replacement });
        }
        from = end;
    }
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

struct TokenSpec {
    prefix: &'static str,
    min_tail: usize,
    upper_only: bool,
    replacement: &'static str,
}

const TOKEN_SPECS: &[TokenSpec] = &[
    TokenSpec { prefix: "AKIA", min_tail: 16, upper_only: true, replacement: "[REDACTED:aws-access-key-id]" },
    TokenSpec { prefix: "ASIA", min_tail: 16, upper_only: true, replacement: "[REDACTED:aws-access-key-id]" },
    TokenSpec { prefix: "sk-", min_tail: 20, upper_only: false, replacement: "[REDACTED:api-key]" },
    TokenSpec { prefix: "rk-", min_tail: 20, upper_only: false, replacement: "[REDACTED:api-key]" },
    TokenSpec { prefix: "github_pat_", min_tail: 20, upper_only: false, replacement: "[REDACTED:github-token]" },
    TokenSpec { prefix: "ghp_", min_tail: 30, upper_only: false, replacement: "[REDACTED:github-token]" },
    TokenSpec { prefix: "gho_", min_tail: 30, upper_only: false, replacement: "[REDACTED:github-token]" },
    TokenSpec { prefix: "ghs_", min_tail: 30, upper_only: false, replacement: "[REDACTED:github-token]" },
    TokenSpec { prefix: "ghu_", min_tail: 30, upper_only: false, replacement: "[REDACTED:github-token]" },
    TokenSpec { prefix: "ghr_", min_tail: 30, upper_only: false, replacement: "[REDACTED:github-token]" },
    TokenSpec { prefix: "hf_", min_tail: 30, upper_only: false, replacement: "[REDACTED:hf-token]" },
    TokenSpec { prefix: "AIza", min_tail: 30, upper_only: false, replacement: "[REDACTED:google-api-key]" },
    TokenSpec { prefix: "xoxb-", min_tail: 10, upper_only: false, replacement: "[REDACTED:slack-token]" },
    TokenSpec { prefix: "xoxp-", min_tail: 10, upper_only: false, replacement: "[REDACTED:slack-token]" },
    TokenSpec { prefix: "xoxa-", min_tail: 10, upper_only: false, replacement: "[REDACTED:slack-token]" },
    TokenSpec { prefix: "xapp-", min_tail: 10, upper_only: false, replacement: "[REDACTED:slack-token]" },
    TokenSpec { prefix: "glpat-", min_tail: 15, upper_only: false, replacement: "[REDACTED:gitlab-token]" },
    TokenSpec { prefix: "dckr_pat_", min_tail: 15, upper_only: false, replacement: "[REDACTED:docker-token]" },
    TokenSpec { prefix: "wandb_", min_tail: 30, upper_only: false, replacement: "[REDACTED:wandb-key]" },
];

fn tail_len(bytes: &[u8], from: usize, upper_only: bool) -> usize {
    let mut i = from;
    while i < bytes.len() {
        let c = bytes[i];
        let ok = if upper_only {
            c.is_ascii_uppercase() || c.is_ascii_digit()
        } else {
            c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
        };
        if !ok {
            break;
        }
        i += 1;
    }
    i - from
}

fn find_tokens(text: &str, out: &mut Vec<Match>) {
    let b = text.as_bytes();
    for spec in TOKEN_SPECS {
        let p = spec.prefix.as_bytes();
        let mut i = 0usize;
        while i + p.len() <= b.len() {
            if &b[i..i + p.len()] == p {
                // Must start at a token boundary.
                let boundary = i == 0 || !is_word_byte(b[i - 1]);
                if boundary {
                    let t = tail_len(b, i + p.len(), spec.upper_only);
                    if t >= spec.min_tail {
                        out.push(Match {
                            start: i,
                            end: i + p.len() + t,
                            kind: "credential",
                            replacement: spec.replacement,
                        });
                        i += p.len() + t;
                        continue;
                    }
                }
            }
            i += 1;
        }
    }
}

fn find_pem_blocks(text: &str, out: &mut Vec<Match>) {
    const BEGIN: &str = "-----BEGIN";
    let mut from = 0usize;
    while let Some(pos) = text[from..].find(BEGIN) {
        let start = from + pos;
        // Only private material; a certificate or public key is not a secret.
        let header_end = text[start..].find("-----\n").or_else(|| text[start..].find("-----\r"))
            .or_else(|| text[start..].find("-----"));
        let is_private = match header_end {
            Some(e) => text[start..start + e].contains("PRIVATE KEY"),
            None => false,
        };
        if is_private {
            let end = match text[start..].find("-----END") {
                Some(e) => {
                    let tail = start + e;
                    match text[tail..].find("-----\n").or_else(|| text[tail..].find("-----")) {
                        Some(x) => tail + x + 5,
                        None => text.len(),
                    }
                }
                None => text.len(),
            };
            out.push(Match {
                start,
                end,
                kind: "credential",
                replacement: "[REDACTED:private-key-block]",
            });
            from = end;
            continue;
        }
        from = start + BEGIN.len();
    }
}

fn is_b64url(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

fn find_jwts(text: &str, out: &mut Vec<Match>) {
    let b = text.as_bytes();
    let mut i = 0usize;
    while i + 3 <= b.len() {
        if &b[i..i + 3] == b"eyJ" && (i == 0 || !is_word_byte(b[i - 1])) {
            let mut j = i;
            let mut dots = 0usize;
            let mut seg = 0usize;
            let mut ok = true;
            while j < b.len() {
                let c = b[j];
                if is_b64url(c) {
                    seg += 1;
                    j += 1;
                } else if c == b'.' {
                    if seg < 4 {
                        ok = false;
                        break;
                    }
                    dots += 1;
                    seg = 0;
                    j += 1;
                    if dots > 2 {
                        break;
                    }
                } else {
                    break;
                }
            }
            if ok && dots == 2 && seg >= 4 {
                out.push(Match {
                    start: i,
                    end: j,
                    kind: "credential",
                    replacement: "[REDACTED:jwt]",
                });
                i = j;
                continue;
            }
        }
        i += 1;
    }
}

fn is_email_local(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'%' | b'+' | b'-')
}
fn is_email_domain(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'.' || c == b'-'
}

fn find_emails(text: &str, out: &mut Vec<Match>) {
    let b = text.as_bytes();
    for (i, c) in b.iter().enumerate() {
        if *c != b'@' {
            continue;
        }
        let mut s = i;
        while s > 0 && is_email_local(b[s - 1]) {
            s -= 1;
        }
        let mut e = i + 1;
        while e < b.len() && is_email_domain(b[e]) {
            e += 1;
        }
        if s == i || e == i + 1 {
            continue;
        }
        let domain = &text[i + 1..e];
        // Require a dot and a plausible TLD so `@mentions` and `user@host` are left.
        let tld_ok = domain
            .rsplit_once('.')
            .map(|(_, tld)| (2..=24).contains(&tld.len()) && tld.bytes().all(|x| x.is_ascii_alphabetic()))
            .unwrap_or(false);
        if tld_ok {
            out.push(Match {
                start: s,
                end: e,
                kind: "email_address",
                replacement: "[REDACTED:email]",
            });
        }
    }
}

fn find_windows_paths(text: &str, out: &mut Vec<Match>) {
    let b = text.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        // Drive-letter form: X:\ or X:/
        let drive = i + 2 < b.len()
            && b[i].is_ascii_alphabetic()
            && b[i + 1] == b':'
            && (b[i + 2] == b'\\' || b[i + 2] == b'/')
            && (i == 0 || !is_word_byte(b[i - 1]));
        // UNC form: \\server\share
        let unc = i + 1 < b.len() && b[i] == b'\\' && b[i + 1] == b'\\';
        if drive || unc {
            let mut j = i;
            while j < b.len() {
                let c = b[j];
                // Stop at characters Windows forbids in a path, plus quotes and
                // whitespace, which almost always delimit a path in free text.
                if matches!(c, b'"' | b'\'' | b'<' | b'>' | b'|' | b'?' | b'*' | b'\n' | b'\r' | b'\t') {
                    break;
                }
                if c == b' ' {
                    // A single space may be inside a path ("Program Files"), but two
                    // in a row, or a space before a non-path-ish token, ends it.
                    if j + 1 < b.len() && b[j + 1] == b' ' {
                        break;
                    }
                    // Look ahead: keep going only if the next run still looks like a
                    // path component.
                    let mut k = j + 1;
                    while k < b.len() && b[k] != b'\\' && b[k] != b'/' && b[k] != b' ' {
                        k += 1;
                    }
                    if k >= b.len() || (b[k] != b'\\' && b[k] != b'/') {
                        break;
                    }
                }
                j += 1;
            }
            while j > i && matches!(b[j - 1], b'.' | b',' | b';' | b')' | b']' | b' ') {
                j -= 1;
            }
            if j > i + 3 {
                out.push(Match {
                    start: i,
                    end: j,
                    kind: "windows_path",
                    replacement: OUT_OF_SCOPE_PATH,
                });
                i = j;
                continue;
            }
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r() -> Redactor {
        Redactor { roots: Vec::new(), usernames: Vec::new(), counts: BTreeMap::new() }
    }

    #[test]
    fn aws_key_is_redacted() {
        let mut x = r();
        let out = x.scrub("key=AKIAIOSFODNN7EXAMPLE rest");
        assert_eq!(out, "key=[REDACTED:aws-access-key-id] rest");
        assert_eq!(x.total_redactions(), 1);
    }

    #[test]
    fn openai_style_key_is_redacted() {
        let mut x = r();
        let out = x.scrub("OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123");
        assert!(out.contains("[REDACTED:api-key]"), "{out}");
        assert!(!out.contains("abcdefghij"));
    }

    #[test]
    fn short_sk_prefix_is_left_alone() {
        let mut x = r();
        // Not a key: too short to be one, and blanking it would damage prose.
        assert_eq!(x.scrub("sk-short"), "sk-short");
    }

    #[test]
    fn jwt_is_redacted() {
        let mut x = r();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let out = x.scrub(&format!("Authorization: Bearer {jwt}"));
        assert!(out.contains("[REDACTED:jwt]"), "{out}");
    }

    #[test]
    fn private_key_block_is_redacted_but_certificate_is_not() {
        let mut x = r();
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----";
        assert!(x.scrub(pem).contains("[REDACTED:private-key-block]"));
        let cert = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
        assert_eq!(x.scrub(cert), cert);
    }

    #[test]
    fn email_is_redacted_but_mention_is_not() {
        let mut x = r();
        assert_eq!(x.scrub("write to jo.smith@example.com now"), "write to [REDACTED:email] now");
        assert_eq!(x.scrub("ping @channel please"), "ping @channel please");
        assert_eq!(x.scrub("root@localhost"), "root@localhost");
    }

    #[test]
    fn windows_path_outside_scope_becomes_placeholder() {
        let mut x = r();
        let out = x.scrub("loaded from C:\\Users\\alice\\models\\final.safetensors ok");
        assert_eq!(out, format!("loaded from {OUT_OF_SCOPE_PATH} ok"));
        assert!(!out.contains("alice"));
    }

    #[test]
    fn unc_path_is_redacted() {
        let mut x = r();
        let out = x.scrub("share \\\\fileserver\\models\\a.bin end");
        assert!(out.contains(OUT_OF_SCOPE_PATH), "{out}");
        assert!(!out.contains("fileserver"));
    }

    #[test]
    fn username_is_replaced_only_as_a_whole_word() {
        let mut x = r();
        x.add_username("sam");
        assert_eq!(x.scrub("user sam ran it"), "user [USER] ran it");
        assert_eq!(x.scrub("the same thing"), "the same thing");
    }

    #[test]
    fn two_character_usernames_are_ignored() {
        let mut x = r();
        x.add_username("jo");
        assert_eq!(x.scrub("jo and jonas"), "jo and jonas");
    }

    #[test]
    fn sensitive_key_names_redact_any_value() {
        assert!(Redactor::is_sensitive_key("HF_TOKEN"));
        assert!(Redactor::is_sensitive_key("aws_secret_access_key"));
        assert!(Redactor::is_sensitive_key("Authorization"));
        assert!(!Redactor::is_sensitive_key("public_key_dim"));
        assert!(!Redactor::is_sensitive_key("num_key_value_heads"));

        let mut x = r();
        assert_eq!(x.scrub_field("api_key", "anything at all"), "[REDACTED:by-key-name]");
        assert_eq!(x.scrub_field("hidden_size", "4096"), "4096");
    }

    #[test]
    fn overlapping_matches_are_applied_once() {
        let mut x = r();
        x.add_username("alice");
        // The path contains the user name; the path wins and there is no double
        // substitution or torn output.
        let out = x.scrub("C:\\Users\\alice\\x\\y.json");
        assert_eq!(out, OUT_OF_SCOPE_PATH);
    }

    #[test]
    fn ledger_is_deterministic_and_counts_kinds() {
        let mut x = r();
        x.scrub("a@b.com and c@d.com and AKIAIOSFODNN7EXAMPLE");
        let l = x.ledger();
        let emails = l.iter().find(|e| e.kind == "email_address").unwrap();
        assert_eq!(emails.count, 2);
        assert_eq!(emails.rule, "CL-PRIV-001");
        let l2 = x.ledger();
        assert_eq!(l, l2, "ledger must be stable");
    }

    #[test]
    fn scrubbing_is_idempotent() {
        let mut x = r();
        x.add_username("alice");
        let once = x.scrub("C:\\Users\\alice\\a.json key=AKIAIOSFODNN7EXAMPLE me@x.com");
        let twice = x.scrub(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn alias_path_maps_under_root() {
        let mut x = r();
        x.roots.push(Root {
            canonical: PathBuf::from("C:\\models\\acme"),
            alias: "ROOT1".to_string(),
        });
        let got = x.alias_path(Path::new("C:\\Models\\ACME\\adapter\\adapter_config.json"));
        assert_eq!(got, "ROOT1/adapter/adapter_config.json");
        let outside = x.alias_path(Path::new("D:\\other\\thing.json"));
        assert_eq!(outside, OUT_OF_SCOPE_PATH);
    }

    #[test]
    fn root_itself_aliases_to_bare_alias() {
        let mut x = r();
        x.roots.push(Root { canonical: PathBuf::from("C:\\m"), alias: "ROOT1".into() });
        assert_eq!(x.alias_path(Path::new("C:\\m")), "ROOT1");
    }

    #[test]
    fn no_secret_survives_a_mixed_document() {
        let mut x = r();
        x.add_username("alice");
        let doc = "\
user: alice
path: C:\\Users\\alice\\project\\train.py
email: alice@acme.example
aws: AKIAIOSFODNN7EXAMPLE
hf: hf_abcdefghijklmnopqrstuvwxyz012345
slack: xoxb-1234567890-abcdefghij
gitlab: glpat-abcdefghijklmnop1234
";
        let out = x.scrub(doc);
        for leak in [
            "alice", "AKIAIOSFODNN7EXAMPLE", "hf_abcdefghij", "xoxb-1234567890",
            "glpat-abcdefghij", "Users",
        ] {
            assert!(!out.contains(leak), "leaked `{leak}` in:\n{out}");
        }
    }
}
