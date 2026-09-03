//! The numeric canary: a per-case rendering-integrity digit appended to displayed
//! numbers.
//!
//! ## What it is, plainly
//!
//! A report shows `74.32%` where the authoritative `score_tenths` is `743`. The final
//! `2` is **not** a hundredth of a point. It is one digit of a short sequence derived
//! from the report's own `evidence_digest`, the case id and the challenge nonce. If
//! somebody opens the PDF, edits a number and re-exports it, the digits stop agreeing
//! with the digest and Verify says so.
//!
//! That is the entire claim. It catches casual editing and retyping. It is **not** a
//! root of trust: the derivation is written down in `docs/02-SCHEMAS.md` §5 and shipped
//! inside `forensic-markers.json`, and an offline scanner in hostile hands can be
//! reverse-engineered. Anyone who regenerates the whole bundle regenerates consistent
//! digits. Security must not depend on the method being secret, and here it does not,
//! because the method is published.
//!
//! ## Why the analytical value must survive untouched
//!
//! The digit is cosmetic and the number is not. Every function here is built around one
//! invariant: [`strip_canary`] recovers exactly the `value_tenths` that
//! [`render_with_canary`] was given, for every digit, with no rounding and no drift. If
//! that ever failed, a tripwire meant to detect tampering would itself have altered a
//! score, and the tool would be lying about its own arithmetic. It is asserted over the
//! whole `0..=1000` score range against every digit in the tests below, and again
//! against the frozen band thresholds, so a regression cannot pass silently.
//!
//! The corollary is a documentation duty rather than a code one, and it belongs in the
//! report: the extra digit must be described as a **non-analytical rendering-integrity
//! digit**, never as precision. A report that showed `74.32%` while implying two
//! decimal places of measured support would be misrepresenting itself, which is exactly
//! the failure mode this whole tool exists to screen for.
//!
//! ## Why the digits are spread out
//!
//! `docs/CLADEON_BUILD_PLAN.md` §17.2 is explicit that two digits are only a hundred
//! combinations and that the sequence must be distributed across several displayed
//! values. Concentrating six digits on one figure would mean a single retyped number
//! erases the whole canary, and would also push a plainly absurd number of decimals
//! onto one line. [`render_series`] enforces one digit per carrier value mechanically
//! and refuses to render when there are fewer carriers than digits, because a rule with
//! no check is a wish.
//!
//! ## A known, accepted ambiguity in the derivation
//!
//! The derivation string is frozen: `sha256(evidence_digest || case_id || nonce)`, with
//! no separator and no length prefix. So `case_id = "AB", nonce = "C"` hashes to the
//! same digits as `case_id = "A", nonce = "BC"`. That is a genuine ambiguity and it is
//! recorded here rather than quietly fixed, because the string is normative. It costs
//! nothing that matters: both fields are published verbatim in the bundle, neither is a
//! secret, and colliding with a different split of the same characters yields a canary
//! for a case that does not exist. The tint marker, whose derivation is not frozen,
//! uses length-prefixed domain separation instead — see `tint.rs`.

use cl_core::error::{ClError, ClResult};
use cl_core::hash::{Digest, Hasher};

/// The derivation, verbatim as `docs/02-SCHEMAS.md` §5 records it in
/// `forensic-markers.json`. Emitted so a reader can reproduce the digits.
pub const DERIVATION: &str = "sha256(evidence_digest || case_id || nonce)";

/// How many digits a report carries by default.
///
/// Six digits is a million combinations spread over six displayed values. Two, the
/// number in the schema example, is only a hundred, which the build plan calls out as
/// too few to be worth much on its own.
pub const DEFAULT_CANARY_DIGITS: usize = 6;

/// Upper bound on digits, so a caller cannot ask for an unbounded allocation.
/// A request above this is clamped, not honoured.
pub const MAX_CANARY_DIGITS: usize = 64;

/// Digest blocks consumed by rejection sampling before the fallback takes over.
/// Each block yields about 31 usable digits, so even `MAX_CANARY_DIGITS` needs three.
const MAX_REJECTION_BLOCKS: u32 = 16;

/// Bytes at or above this are rejected rather than reduced modulo ten.
///
/// `256` is not a multiple of `10`, so a plain `b % 10` would make `0..=5` appear
/// slightly more often than `6..=9`. The skew is far too small to matter for a
/// tripwire, but a published derivation invites recomputation by third parties and a
/// biased one is harder to justify than an unbiased one that costs a single compare.
const REJECT_AT: u8 = 250;

/// A derived digit sequence together with the derivation that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canary {
    /// One decimal digit per carrier value, each in `0..=9`.
    pub digits: Vec<u8>,
    /// The derivation string, for `forensic-markers.json`.
    pub derivation: &'static str,
}

impl Canary {
    /// The digits as the compact string `forensic-markers.json` stores in
    /// `expected_digit_sequence`.
    pub fn to_sequence(&self) -> String {
        let mut s = String::with_capacity(self.digits.len());
        for d in &self.digits {
            // `derive_canary` cannot produce anything outside `0..=9`; a hand-built
            // `Canary` could, and it renders as `?` rather than as a wrong digit.
            s.push(if *d <= 9 { (b'0' + d) as char } else { '?' });
        }
        s
    }

    pub fn len(&self) -> usize {
        self.digits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.digits.is_empty()
    }
}

/// Parse a stored `expected_digit_sequence` back into digits.
///
/// Strict: ASCII `0..=9` only, and an empty sequence is rejected. An empty sequence
/// would verify against anything, which must never be reported as a consistent marker.
pub fn parse_sequence(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() > MAX_CANARY_DIGITS {
        return None;
    }
    let mut out = Vec::with_capacity(s.len());
    for b in s.as_bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        out.push(b - b'0');
    }
    Some(out)
}

/// Derive `count` canary digits for one case.
///
/// `count` above [`MAX_CANARY_DIGITS`] is clamped; `count == 0` yields an empty canary,
/// which [`verify_canary`] then refuses to accept.
pub fn derive_canary(
    evidence_digest: &Digest,
    case_id: &str,
    nonce: &str,
    count: usize,
) -> Canary {
    let want = count.min(MAX_CANARY_DIGITS);
    let seed = canary_seed(evidence_digest, case_id, nonce);
    Canary { digits: digit_stream(&seed, want), derivation: DERIVATION }
}

/// True when `observed` is exactly the sequence this case should carry.
///
/// An empty `observed` is always false. "We found no digits" is
/// [`cl_core::vocab::MarkerStatus::Absent`], and it must never be allowed to
/// masquerade as agreement.
pub fn verify_canary(
    evidence_digest: &Digest,
    case_id: &str,
    nonce: &str,
    observed: &[u8],
) -> bool {
    if observed.is_empty() || observed.len() > MAX_CANARY_DIGITS {
        return false;
    }
    derive_canary(evidence_digest, case_id, nonce, observed.len()).digits == observed
}

/// Render `value_tenths` with one canary digit appended.
///
/// `743` with digit `2` renders as `74.32`. The value keeps its own tenth; the canary
/// occupies a hundredths position that carries no analytical meaning.
///
/// A `digit` outside `0..=9` is folded modulo ten rather than panicking. Nothing in
/// this crate produces one, and a rendering routine is the wrong place to abort a scan.
pub fn render_with_canary(value_tenths: i64, digit: u8) -> String {
    let digit = digit % 10;
    // `unsigned_abs`, not `abs`: `i64::MIN.abs()` overflows.
    let magnitude = value_tenths.unsigned_abs();
    let whole = magnitude / 10;
    let tenth = magnitude % 10;
    let sign = if value_tenths < 0 { "-" } else { "" };
    format!("{sign}{whole}.{tenth}{digit}")
}

/// Recover the analytical `value_tenths` from a rendered value, discarding the canary.
///
/// Deliberately strict, and returns `None` rather than a best effort for anything it
/// did not itself produce: exactly one `.`, exactly two digits after it, ASCII digits
/// only, no leading `+`, no surrounding whitespace, no leading zeros (`07.43`), and no
/// negative zero (`-0.05` would map to `0`, which is not a value this function could
/// have rendered). Guessing at a malformed figure is how a verifier ends up reporting a
/// number the report never contained.
pub fn strip_canary(rendered: &str) -> Option<i64> {
    let bytes = rendered.as_bytes();
    let (negative, digits) = match bytes.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, bytes),
    };

    // `<whole>.<tenth><canary>`: at least one whole digit, then four fixed bytes.
    let dot = digits.len().checked_sub(3)?;
    if dot == 0 || digits.get(dot) != Some(&b'.') {
        return None;
    }
    let whole_part = digits.get(..dot)?;
    let tenth = ascii_digit(*digits.get(dot + 1)?)?;
    // The canary itself is discarded, but it must still be a digit for the string to
    // be one this module produced.
    ascii_digit(*digits.get(dot + 2)?)?;

    if whole_part.len() > 1 && whole_part.first() == Some(&b'0') {
        return None;
    }
    let mut whole: u64 = 0;
    for b in whole_part {
        let d = ascii_digit(*b)?;
        whole = whole.checked_mul(10)?.checked_add(d as u64)?;
    }
    let magnitude = whole.checked_mul(10)?.checked_add(tenth as u64)?;

    if negative {
        if magnitude == 0 {
            return None;
        }
        // `-i64::MIN` is not representable, so the boundary is handled explicitly
        // rather than by negating a value that has already overflowed.
        if magnitude == (i64::MAX as u64) + 1 {
            return Some(i64::MIN);
        }
        i64::try_from(magnitude).ok().map(|v| -v)
    } else {
        i64::try_from(magnitude).ok()
    }
}

/// Recover just the canary digit from a rendered value.
///
/// Verify needs the digit and the value separately: the value feeds nothing, the digit
/// feeds [`verify_canary`]. Returns `None` on anything [`strip_canary`] would reject,
/// so the two can never disagree about whether a string is well formed.
pub fn extract_digit(rendered: &str) -> Option<u8> {
    strip_canary(rendered)?;
    ascii_digit(*rendered.as_bytes().last()?)
}

/// Render one carrier value per canary digit, in order.
///
/// Errors when `values` is shorter than the digit sequence, because the alternative is
/// to drop digits and quietly weaken the canary, and when the canary is empty, because
/// a report with no digits must not be presented as carrying one. Surplus values are
/// left to the caller to render plainly; this function returns exactly one string per
/// digit.
pub fn render_series(values: &[i64], canary: &Canary) -> ClResult<Vec<String>> {
    if canary.is_empty() {
        return Err(ClError::contract("canary has no digits to render"));
    }
    if values.len() < canary.len() {
        return Err(ClError::contract(format!(
            "canary needs {} carrier values, {} supplied",
            canary.len(),
            values.len()
        )));
    }
    let mut out = Vec::with_capacity(canary.len());
    for (value, digit) in values.iter().zip(canary.digits.iter()) {
        out.push(render_with_canary(*value, *digit));
    }
    Ok(out)
}

fn ascii_digit(b: u8) -> Option<u8> {
    if b.is_ascii_digit() {
        Some(b - b'0')
    } else {
        None
    }
}

/// `sha256(evidence_digest || case_id || nonce)`, exactly as the frozen schema states.
fn canary_seed(evidence_digest: &Digest, case_id: &str, nonce: &str) -> Digest {
    let mut h = Hasher::new();
    h.update(&evidence_digest.0);
    h.update(case_id.as_bytes());
    h.update(nonce.as_bytes());
    h.finish()
}

/// Expansion block `k`, so a sequence longer than the 32 seed bytes stays deterministic
/// without reusing bytes.
fn expansion_block(seed: &Digest, k: u32) -> Digest {
    let mut h = Hasher::new();
    h.update(b"CL-CANARY-BLOCK");
    h.update(&seed.0);
    h.update(&k.to_be_bytes());
    h.finish()
}

/// Unbiased digits from the seed, extended by expansion blocks as needed.
///
/// The rejection loop is bounded and the fallback below it makes 32 digits of progress
/// per iteration, so this terminates for every input. Reaching the fallback requires
/// sixteen consecutive blocks in which almost every byte landed in `250..=255`, which
/// has probability well under `2^-300`; it exists so the function is provably total,
/// not because it is expected to run.
fn digit_stream(seed: &Digest, count: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(count);
    let mut block: u32 = 0;
    while out.len() < count && block < MAX_REJECTION_BLOCKS {
        let bytes = if block == 0 { *seed } else { expansion_block(seed, block) };
        for b in bytes.0 {
            if out.len() == count {
                break;
            }
            if b < REJECT_AT {
                out.push(b % 10);
            }
        }
        block = block.saturating_add(1);
    }
    let mut extra: u32 = 0;
    while out.len() < count {
        let bytes = expansion_block(seed, MAX_REJECTION_BLOCKS.saturating_add(extra));
        for b in bytes.0 {
            if out.len() == count {
                break;
            }
            out.push(b % 10);
        }
        extra = extra.saturating_add(1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl_core::vocab::SupportBand;

    fn digest(tag: &str) -> Digest {
        Digest::of(tag.as_bytes())
    }

    // -- the invariant that matters most -----------------------------------------

    /// The canary must never move an analytical value. Every score in the frozen
    /// `0..=1000` range, against every digit, must come back byte-identical.
    #[test]
    fn round_trips_over_the_whole_score_range_with_every_digit() {
        for value in 0..=1000i64 {
            for digit in 0..=9u8 {
                let rendered = render_with_canary(value, digit);
                assert_eq!(
                    strip_canary(&rendered),
                    Some(value),
                    "round trip failed for {value} with digit {digit} ({rendered})"
                );
                assert_eq!(extract_digit(&rendered), Some(digit), "digit lost in {rendered}");
            }
        }
    }

    /// The stronger statement of the same rule: the canary cannot move a value across
    /// a band threshold, because it cannot move the value at all.
    #[test]
    fn canary_never_changes_the_support_band() {
        for value in 0..=1000i64 {
            let expected = SupportBand::from_tenths(value);
            for digit in 0..=9u8 {
                let recovered = strip_canary(&render_with_canary(value, digit));
                assert_eq!(recovered, Some(value));
                assert_eq!(SupportBand::from_tenths(recovered.unwrap_or(-1)), expected);
            }
        }
    }

    #[test]
    fn renders_the_documented_example() {
        assert_eq!(render_with_canary(743, 2), "74.32");
        assert_eq!(strip_canary("74.32"), Some(743));
    }

    #[test]
    fn renders_small_and_zero_values() {
        assert_eq!(render_with_canary(0, 0), "0.00");
        assert_eq!(render_with_canary(0, 7), "0.07");
        assert_eq!(render_with_canary(5, 3), "0.53");
        assert_eq!(strip_canary("0.07"), Some(0));
        assert_eq!(strip_canary("0.53"), Some(5));
    }

    #[test]
    fn round_trips_the_extremes_of_i64() {
        for value in [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX - 1, i64::MAX] {
            for digit in 0..=9u8 {
                assert_eq!(strip_canary(&render_with_canary(value, digit)), Some(value));
            }
        }
    }

    #[test]
    fn round_trips_negative_values() {
        for value in -1000..=-1i64 {
            for digit in [0u8, 4, 9] {
                let rendered = render_with_canary(value, digit);
                assert!(rendered.starts_with('-'));
                assert_eq!(strip_canary(&rendered), Some(value));
            }
        }
    }

    #[test]
    fn out_of_range_digit_is_folded_not_panicked() {
        assert_eq!(render_with_canary(743, 12), "74.32");
        assert_eq!(render_with_canary(743, 255), "74.35");
        assert_eq!(strip_canary(&render_with_canary(743, 255)), Some(743));
    }

    // -- strip is strict ----------------------------------------------------------

    #[test]
    fn strip_rejects_everything_it_did_not_render() {
        for bad in [
            "",
            ".",
            "..",
            "0",
            "74",
            "74.",
            "74.3",     // one decimal: no canary present
            "74.321",   // three decimals
            ".32",      // no whole part
            "-.32",
            "+74.32",   // leading plus
            "07.43",    // leading zero
            "-07.43",
            "-0.00",    // negative zero is not renderable
            "74,32",
            "74 32",
            " 74.32",
            "74.32 ",
            "74.32%",
            "7a.32",
            "74.3a",
            "74.a2",
            "-",
            "--74.32",
            "74.-2",
            "1e3.42",
            "NaN",
            "\u{0664}\u{0664}.32", // Arabic-Indic digits are not ASCII digits
        ] {
            assert_eq!(strip_canary(bad), None, "accepted malformed input {bad:?}");
            assert_eq!(extract_digit(bad), None, "extracted a digit from {bad:?}");
        }
    }

    #[test]
    fn strip_rejects_values_that_overflow_i64() {
        assert_eq!(strip_canary("99999999999999999999.12"), None);
        assert_eq!(strip_canary("922337203685477580.88"), None); // i64::MAX + 1 tenth
        assert_eq!(strip_canary("-922337203685477580.97"), None); // past i64::MIN
        assert_eq!(strip_canary(&format!("{}.12", "9".repeat(400))), None);
    }

    #[test]
    fn strip_accepts_exactly_the_i64_boundaries() {
        assert_eq!(strip_canary("922337203685477580.70"), Some(i64::MAX));
        assert_eq!(strip_canary("-922337203685477580.80"), Some(i64::MIN));
    }

    // -- derivation ---------------------------------------------------------------

    #[test]
    fn derivation_is_deterministic() {
        let d = digest("evidence");
        let a = derive_canary(&d, "CL-2026-0F3A9C", "0123456789abcdef", 6);
        let b = derive_canary(&d, "CL-2026-0F3A9C", "0123456789abcdef", 6);
        assert_eq!(a, b);
        assert_eq!(a.derivation, DERIVATION);
    }

    #[test]
    fn all_digits_are_in_range() {
        for i in 0..200u32 {
            let c = derive_canary(&Digest::of(&i.to_be_bytes()), "CASE", "nonce", 32);
            assert_eq!(c.len(), 32);
            assert!(c.digits.iter().all(|d| *d <= 9));
        }
    }

    #[test]
    fn changing_the_evidence_digest_changes_the_digits() {
        let a = derive_canary(&digest("evidence-a"), "CASE", "nonce", 6);
        let b = derive_canary(&digest("evidence-b"), "CASE", "nonce", 6);
        assert_ne!(a.digits, b.digits);
    }

    #[test]
    fn changing_the_case_id_changes_the_digits() {
        let d = digest("evidence");
        let a = derive_canary(&d, "CL-2026-0F3A9C", "nonce", 6);
        let b = derive_canary(&d, "CL-2026-0F3A9D", "nonce", 6);
        assert_ne!(a.digits, b.digits);
    }

    #[test]
    fn changing_the_nonce_changes_the_digits() {
        let d = digest("evidence");
        let a = derive_canary(&d, "CASE", "0123456789abcdef", 6);
        let b = derive_canary(&d, "CASE", "0123456789abcdee", 6);
        assert_ne!(a.digits, b.digits);
    }

    /// A shorter request is a prefix of a longer one. Verify recovers however many
    /// digits it can read from the PDF and compares that many, so the two must agree.
    #[test]
    fn shorter_requests_are_prefixes_of_longer_ones() {
        let d = digest("evidence");
        let long = derive_canary(&d, "CASE", "nonce", MAX_CANARY_DIGITS);
        for n in 1..=MAX_CANARY_DIGITS {
            let short = derive_canary(&d, "CASE", "nonce", n);
            assert_eq!(short.digits, long.digits[..n]);
        }
    }

    #[test]
    fn count_is_clamped_and_zero_is_allowed() {
        let d = digest("evidence");
        assert_eq!(derive_canary(&d, "CASE", "nonce", 0).len(), 0);
        assert!(derive_canary(&d, "CASE", "nonce", 0).is_empty());
        assert_eq!(derive_canary(&d, "CASE", "nonce", usize::MAX).len(), MAX_CANARY_DIGITS);
    }

    #[test]
    fn empty_case_id_and_nonce_are_handled() {
        let d = digest("evidence");
        let c = derive_canary(&d, "", "", DEFAULT_CANARY_DIGITS);
        assert_eq!(c.len(), DEFAULT_CANARY_DIGITS);
        assert!(verify_canary(&d, "", "", &c.digits));
    }

    #[test]
    fn non_ascii_case_id_is_handled() {
        let d = digest("evidence");
        let c = derive_canary(&d, "案件-\u{1F600}", "nonce", 6);
        assert!(verify_canary(&d, "案件-\u{1F600}", "nonce", &c.digits));
        assert!(!verify_canary(&d, "案件", "nonce", &c.digits));
    }

    /// Not a uniformity proof, only a guard against a derivation that collapses onto a
    /// few values — which would make the canary far cheaper to guess than it looks.
    #[test]
    fn digits_cover_the_whole_decimal_range_across_cases() {
        let mut seen = [false; 10];
        for i in 0..500u32 {
            let c = derive_canary(&Digest::of(&i.to_be_bytes()), "CASE", "nonce", 6);
            for d in c.digits {
                if let Some(slot) = seen.get_mut(d as usize) {
                    *slot = true;
                }
            }
        }
        assert!(seen.iter().all(|s| *s), "some decimal digit never appeared: {seen:?}");
    }

    // -- verification -------------------------------------------------------------

    #[test]
    fn verify_accepts_the_derived_sequence() {
        let d = digest("evidence");
        let c = derive_canary(&d, "CASE", "nonce", DEFAULT_CANARY_DIGITS);
        assert!(verify_canary(&d, "CASE", "nonce", &c.digits));
    }

    #[test]
    fn verify_rejects_one_altered_digit() {
        let d = digest("evidence");
        let c = derive_canary(&d, "CASE", "nonce", DEFAULT_CANARY_DIGITS);
        for i in 0..c.len() {
            let mut tampered = c.digits.clone();
            if let Some(slot) = tampered.get_mut(i) {
                *slot = (*slot + 1) % 10;
            }
            assert!(!verify_canary(&d, "CASE", "nonce", &tampered), "digit {i} not checked");
        }
    }

    #[test]
    fn verify_rejects_an_empty_sequence() {
        let d = digest("evidence");
        assert!(!verify_canary(&d, "CASE", "nonce", &[]));
    }

    #[test]
    fn verify_rejects_an_oversized_sequence() {
        let d = digest("evidence");
        assert!(!verify_canary(&d, "CASE", "nonce", &vec![0u8; MAX_CANARY_DIGITS + 1]));
    }

    #[test]
    fn verify_rejects_a_sequence_from_another_case() {
        let d = digest("evidence");
        let c = derive_canary(&d, "CASE-A", "nonce", 6);
        assert!(!verify_canary(&d, "CASE-B", "nonce", &c.digits));
        assert!(!verify_canary(&d, "CASE-A", "other", &c.digits));
        assert!(!verify_canary(&digest("other-evidence"), "CASE-A", "nonce", &c.digits));
    }

    /// A one-digit canary agrees with an unrelated case one time in ten. That is a
    /// property of the construction, not a bug, and it is why the default is six.
    #[test]
    fn a_one_digit_canary_is_weak_and_six_digits_are_not() {
        let mut collisions_one = 0u32;
        let mut collisions_six = 0u32;
        let reference_one = derive_canary(&digest("reference"), "CASE", "nonce", 1);
        let reference_six = derive_canary(&digest("reference"), "CASE", "nonce", 6);
        for i in 0..1000u32 {
            let d = Digest::of(&i.to_be_bytes());
            if derive_canary(&d, "CASE", "nonce", 1).digits == reference_one.digits {
                collisions_one += 1;
            }
            if derive_canary(&d, "CASE", "nonce", 6).digits == reference_six.digits {
                collisions_six += 1;
            }
        }
        assert!(collisions_one > 30, "one-digit collisions {collisions_one} implausibly low");
        assert_eq!(collisions_six, 0);
    }

    // -- sequence encoding --------------------------------------------------------

    #[test]
    fn sequence_round_trips() {
        let c = derive_canary(&digest("evidence"), "CASE", "nonce", 6);
        let s = c.to_sequence();
        assert_eq!(s.len(), 6);
        assert_eq!(parse_sequence(&s), Some(c.digits));
    }

    #[test]
    fn parse_sequence_is_strict() {
        assert_eq!(parse_sequence(""), None);
        assert_eq!(parse_sequence("4a"), None);
        assert_eq!(parse_sequence("4 7"), None);
        assert_eq!(parse_sequence("-47"), None);
        assert_eq!(parse_sequence("\u{0664}7"), None);
        assert_eq!(parse_sequence(&"7".repeat(MAX_CANARY_DIGITS + 1)), None);
        assert_eq!(parse_sequence("47"), Some(vec![4, 7]));
    }

    #[test]
    fn out_of_range_digits_render_as_a_question_mark_not_a_wrong_digit() {
        let c = Canary { digits: vec![3, 42, 5], derivation: DERIVATION };
        assert_eq!(c.to_sequence(), "3?5");
        assert_eq!(parse_sequence(&c.to_sequence()), None);
    }

    // -- spreading ----------------------------------------------------------------

    #[test]
    fn series_places_one_digit_per_carrier_value() {
        let c = derive_canary(&digest("evidence"), "CASE", "nonce", 4);
        let values = [743i64, 0, 1000, -25];
        let rendered = render_series(&values, &c).expect("four values for four digits");
        assert_eq!(rendered.len(), 4);
        for (i, text) in rendered.iter().enumerate() {
            assert_eq!(strip_canary(text), values.get(i).copied());
            assert_eq!(extract_digit(text), c.digits.get(i).copied());
        }
    }

    #[test]
    fn series_refuses_to_concentrate_digits_when_carriers_are_short() {
        let c = derive_canary(&digest("evidence"), "CASE", "nonce", 6);
        assert!(render_series(&[743, 12], &c).is_err());
        assert!(render_series(&[], &c).is_err());
        assert!(render_series(&[743, 12, 0, 1, 2, 3], &c).is_ok());
        assert!(render_series(&[743, 12, 0, 1, 2, 3, 4], &c).is_ok());
    }

    #[test]
    fn series_refuses_an_empty_canary() {
        let c = Canary { digits: Vec::new(), derivation: DERIVATION };
        assert!(render_series(&[743], &c).is_err());
    }

    #[test]
    fn series_survives_extreme_carrier_values() {
        let c = derive_canary(&digest("evidence"), "CASE", "nonce", 3);
        let values = [i64::MIN, 0, i64::MAX];
        let rendered = render_series(&values, &c).expect("three values for three digits");
        for (i, text) in rendered.iter().enumerate() {
            assert_eq!(strip_canary(text), values.get(i).copied());
        }
    }
}
