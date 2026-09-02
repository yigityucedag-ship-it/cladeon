//! The tint marker: a 128-bit report-bound tag hidden in ±1 changes to a small footer
//! raster.
//!
//! ## What it is, plainly
//!
//! `docs/TRAINTRACE_BUILD_PLAN.md` §17.3 asks for a footer block on every page whose
//! low-order RGB values are nudged by one at many pseudo-random locations, encoding a
//! tag bound to this report, with enough redundancy that the detector can decide by
//! correlation rather than by peeking at a handful of pixels. That is what this module
//! builds and reads back.
//!
//! It survives being emailed as an attachment, because nothing in that path rewrites
//! pixels. It does not survive re-export, re-compression, re-rendering or rebuilding
//! the PDF, and it is not meant to: those are the events it exists to notice.
//!
//! ## What it is not
//!
//! Not a root of trust, and not a watermark that resists an informed attacker. The
//! construction is written down here and in `docs/02-SCHEMAS.md` §5, the tag travels in
//! `forensic-markers.json`, and an offline scanner in hostile hands can be
//! reverse-engineered. Anyone who reads this file can strip the marker, or regenerate a
//! whole bundle whose marker is internally consistent. What the marker rules out is the
//! *casual* case: opening the PDF, changing a figure, and saving.
//!
//! The one attack it is built to defeat outright is copying a marker between reports.
//! Positions come from the tag, so a carrier lifted from report A lands in the wrong
//! slots for report B's tag and correlates at noise level. That case is asserted below.
//!
//! ## Construction
//!
//! * 128 tag bits, each written at [`REPETITION`] distinct positions, so
//!   [`CARRIER_POSITIONS`] carrier bytes in all. A *position* is one channel byte, that
//!   is `pixel_index * 3 + channel`.
//! * Positions come from [`SplitMix64`] seeded from the tag and the marker version.
//!   They are drawn without replacement: overlapping two bits onto one byte would make
//!   the majority vote read a value that no bit wrote.
//! * A `1` bit adds one to its byte, a `0` bit subtracts one. One 8-bit step is well
//!   under any ordinary viewing threshold on a light grey footer.
//!
//! ## Why the base colour may not sit at 0 or 255
//!
//! Modulation saturates at the ends of the byte range. At base `255` a `1` bit stays
//! `255` and is indistinguishable from an untouched byte; at base `0` a `0` bit stays
//! `0`. Roughly half of every affected channel's bits would be silently unreadable and
//! the detector would report a marked page as unmarked. Rather than emit a
//! half-working marker, [`build_carrier`] refuses to mark at all when any base channel
//! is at an extreme and returns a plain uniform raster, which reads honestly as
//! `absent`. [`RECOMMENDED_BASE`] is a light grey with room on both sides.
//!
//! ## Why the detector estimates the base instead of being told it
//!
//! [`detect`] receives only a raster and a tag, because that is all Verify has: it
//! extracts the footer image from a PDF it did not create. Fewer than four percent of
//! the carrier's bytes are modulated, so the per-channel *mode* is the unmodulated base
//! whenever the carrier is a flat block — which the schema pins, along with
//! `expected_carrier_sha256`. A textured carrier would break this estimate, so the
//! carrier is required to be flat; that requirement lives in the schema and this module
//! depends on it.
//!
//! ## Why the two reported numbers are never merged
//!
//! [`Detection`] reports a normalised correlation *and* a bit count, in the same spirit
//! as `docs/00-FROZEN-VOCABULARY.md` §12: they answer different questions. Correlation
//! says how much of the expected pattern is still present, including partial evidence
//! from positions that were nudged but not destroyed. `bits_recovered` says how many of
//! the 128 bits a majority vote would actually agree on. A page can hold a strong
//! correlation with a few undecided bits, and collapsing that into one verdict would
//! discard the distinction between "degraded" and "wrong".

use tt_core::hash::{Digest, Hasher};
use tt_core::raster::Raster;
use tt_core::MARKER_VERSION;

use crate::prng::SplitMix64;

/// Bits in the tag.
pub const TAG_BITS: usize = 128;
/// Times each bit is written. Odd, so a majority vote never ties on intact input.
pub const REPETITION: usize = 7;
/// Carrier bytes the marker consumes: `TAG_BITS * REPETITION`.
pub const CARRIER_POSITIONS: usize = TAG_BITS * REPETITION;

/// Correlation at or above which [`Detection::matched`] is true, from
/// `docs/02-SCHEMAS.md` §5 (`detector_threshold_percent`).
pub const DETECTOR_THRESHOLD_PERCENT: u32 = 70;

/// A light grey with headroom on both sides of the ±1 modulation.
///
/// `242` also has the property that `241`, `242` and `243` fall in one bucket under
/// rounding to multiples of eight, so an optimiser that quantises the footer erases the
/// marker cleanly instead of leaving half of it readable.
pub const RECOMMENDED_BASE: [u8; 3] = [242, 242, 242];

/// Largest carrier this module will touch. The footer in `docs/02-SCHEMAS.md` §5 is
/// 240x40; this leaves four orders of magnitude of slack while keeping the position
/// bookkeeping bounded. A larger request yields an empty raster rather than a
/// multi-gigabyte allocation.
pub const MAX_CARRIER_PIXELS: u64 = 1_048_576;

/// Domain separation for the tag derivation. Distinct from the canary's, so the two
/// markers cannot be derived from one another even though they take the same inputs.
const TAG_DOMAIN: &[u8] = b"TT-TINT-TAG";
/// Domain separation for the position seed.
const POSITION_DOMAIN: &[u8] = b"TT-TINT-POSITIONS";

/// What a detection run observed. The two measurements are reported side by side and
/// are never combined into a single verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detection {
    /// Normalised correlation between the expected modulation pattern and the observed
    /// deviations from the estimated base, as an integer percent in `0..=100`.
    /// Anti-correlation is reported as `0` rather than as a negative number.
    pub correlation_percent: u32,
    /// True when `correlation_percent >= DETECTOR_THRESHOLD_PERCENT`.
    pub matched: bool,
    /// How many of the 128 tag bits a majority vote agrees on. A tied vote — every
    /// position at the base — recovers nothing and is counted as such.
    pub bits_recovered: u32,
}

impl Detection {
    /// Nothing found: an unmarked, unreadable or undersized carrier.
    const fn absent() -> Detection {
        Detection { correlation_percent: 0, matched: false, bits_recovered: 0 }
    }
}

/// Derive the 128-bit tag for one report.
///
/// Length-prefixed so that `(case_id, nonce)` pairs cannot be re-split into a different
/// pair with the same tag. The canary's derivation is frozen in the schema and cannot
/// do this; nothing freezes the tag's, so it does.
pub fn tint_tag(evidence_digest: &Digest, case_id: &str, nonce: &str) -> [u8; 16] {
    let mut h = Hasher::new();
    h.update(TAG_DOMAIN);
    h.update(&MARKER_VERSION.to_be_bytes());
    h.update(&evidence_digest.0);
    h.update(&(case_id.len() as u64).to_be_bytes());
    h.update(case_id.as_bytes());
    h.update(&(nonce.len() as u64).to_be_bytes());
    h.update(nonce.as_bytes());
    let digest = h.finish();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&digest.0[..16]);
    tag
}

/// True when a `width x height` raster can carry the marker.
///
/// Exposed so the report writer can size the footer without having to know
/// [`CARRIER_POSITIONS`], and so a too-small footer is caught where it is chosen rather
/// than discovered later as a missing marker.
pub fn carrier_fits(width: u32, height: u32) -> bool {
    match carrier_capacity(width, height) {
        Some(capacity) => capacity >= CARRIER_POSITIONS,
        None => false,
    }
}

/// Build the footer carrier for `tag`.
///
/// Returns a uniform raster with **no marker** — never a partial one — when the raster
/// cannot hold [`CARRIER_POSITIONS`] distinct positions, or when a channel of `base`
/// sits at `0` or `255`. A request above [`MAX_CARRIER_PIXELS`] returns an empty
/// raster; the caller's own size limit should have rejected it first.
pub fn build_carrier(tag: &[u8; 16], width: u32, height: u32, base: [u8; 3]) -> Raster {
    let capacity = match carrier_capacity(width, height) {
        Some(capacity) => capacity,
        None => return Raster::new(0, 0, base),
    };
    let mut raster = Raster::new(width, height, base);
    if capacity < CARRIER_POSITIONS || !base_is_modulable(base) {
        return raster;
    }

    for (bit, positions) in slot_positions(tag, capacity).chunks(REPETITION).enumerate() {
        let delta: i8 = if tag_bit(tag, bit) { 1 } else { -1 };
        for slot in positions {
            if let Some(byte) = raster.rgb.get_mut(*slot) {
                // Saturating, although `base_is_modulable` has already ruled out the
                // only inputs that could saturate. A future carrier that paints over
                // the base must not be able to wrap a byte round.
                *byte = byte.saturating_add_signed(delta);
            }
        }
    }
    raster
}

/// Look for `tag` in `carrier`.
///
/// Reports `absent` for a raster that is empty, oversized, too small to hold the
/// marker, or whose buffer length disagrees with its dimensions. A raster whose size
/// has changed since it was built is genuinely no longer the carrier: the positions are
/// byte offsets into a buffer of a known length, so a crop moves every one of them.
pub fn detect(carrier: &Raster, tag: &[u8; 16]) -> Detection {
    let capacity = match carrier_capacity(carrier.width, carrier.height) {
        Some(capacity) => capacity,
        None => return Detection::absent(),
    };
    if capacity < CARRIER_POSITIONS || carrier.rgb.len() != capacity {
        return Detection::absent();
    }

    let base = estimate_base(carrier);
    let mut correlation: i64 = 0;
    let mut bits_recovered: u32 = 0;

    for (bit, positions) in slot_positions(tag, capacity).chunks(REPETITION).enumerate() {
        let expected: i64 = if tag_bit(tag, bit) { 1 } else { -1 };
        let mut vote: i64 = 0;
        for slot in positions {
            let channel = slot % 3;
            let reference = base.get(channel).copied().unwrap_or(0);
            let observed = carrier.rgb.get(*slot).copied().unwrap_or(reference);
            let deviation = (i64::from(observed) - i64::from(reference)).signum();
            correlation += expected * deviation;
            vote += deviation;
        }
        // A tied vote decides nothing. Counting it as a recovered bit would turn a
        // blank carrier into a half-recovered tag.
        if vote != 0 && vote.signum() == expected {
            bits_recovered += 1;
        }
    }

    // |correlation| <= CARRIER_POSITIONS, so the scaling cannot overflow.
    let percent = if correlation <= 0 {
        0
    } else {
        ((correlation * 100) / CARRIER_POSITIONS as i64) as u32
    };
    Detection {
        correlation_percent: percent,
        matched: percent >= DETECTOR_THRESHOLD_PERCENT,
        bits_recovered,
    }
}

/// Channel bytes available in a raster, or `None` when it is larger than
/// [`MAX_CARRIER_PIXELS`].
fn carrier_capacity(width: u32, height: u32) -> Option<usize> {
    let pixels = u64::from(width) * u64::from(height);
    if pixels > MAX_CARRIER_PIXELS {
        return None;
    }
    // `pixels * 3` is at most 3 145 728, so this fits every supported `usize`.
    usize::try_from(pixels * 3).ok()
}

/// A base is modulable when every channel has room to move both up and down.
fn base_is_modulable(base: [u8; 3]) -> bool {
    base.iter().all(|c| *c > 0 && *c < u8::MAX)
}

/// Bit `index` of the tag, most significant bit of the first byte first.
fn tag_bit(tag: &[u8; 16], index: usize) -> bool {
    match tag.get(index / 8) {
        Some(byte) => (byte >> (7 - index % 8)) & 1 == 1,
        None => false,
    }
}

/// Seed for the position generator: the tag and the marker version, nothing else.
///
/// Deliberately independent of the carrier's size, so that the same report always lays
/// its bits out in the same order; only the modulo against the capacity differs.
fn position_seed(tag: &[u8; 16]) -> u64 {
    let mut h = Hasher::new();
    h.update(POSITION_DOMAIN);
    h.update(&MARKER_VERSION.to_be_bytes());
    h.update(tag);
    let digest = h.finish();
    let mut seed = [0u8; 8];
    seed.copy_from_slice(&digest.0[..8]);
    u64::from_be_bytes(seed)
}

/// [`CARRIER_POSITIONS`] distinct channel-byte offsets, in bit order.
///
/// Distinctness is the point: two bits sharing a byte would each be read as whatever
/// the second one wrote. A drawn slot that is already taken is resolved by walking
/// forward to the next free one rather than by redrawing, because rejection sampling
/// has no bound when the carrier is nearly full, and this loop provably terminates —
/// at most `CARRIER_POSITIONS - 1` slots are taken and `capacity` is at least
/// `CARRIER_POSITIONS`, so a free slot always exists within one pass.
///
/// Returns an empty vector when the capacity is too small, so both the writer and the
/// detector fall through to "no marker" by the same path.
fn slot_positions(tag: &[u8; 16], capacity: usize) -> Vec<usize> {
    if capacity < CARRIER_POSITIONS {
        return Vec::new();
    }
    let mut rng = SplitMix64::new(position_seed(tag));
    let mut taken = vec![false; capacity];
    let mut out = Vec::with_capacity(CARRIER_POSITIONS);
    for _ in 0..CARRIER_POSITIONS {
        let mut slot = rng.below(capacity as u64) as usize;
        for _ in 0..capacity {
            match taken.get(slot) {
                Some(false) => break,
                Some(true) => slot = if slot + 1 == capacity { 0 } else { slot + 1 },
                // Unreachable: `below` bounds the draw and probing wraps within range.
                None => slot = 0,
            }
        }
        if let Some(flag) = taken.get_mut(slot) {
            *flag = true;
        }
        out.push(slot);
    }
    out
}

/// Per-channel modal byte value, used as the unmodulated base.
///
/// Ties go to the lower value so the estimate is deterministic. On a flat carrier the
/// mode is exactly the base: at most [`CARRIER_POSITIONS`] of the bytes were moved, and
/// the smallest carrier this module will mark has 896 bytes of which... it has exactly
/// 896, so the smallest legal carrier is the one case where the estimate can fail.
/// That is why the schema fixes a 240x40 footer, 28 800 bytes, of which 3.1 percent are
/// modulated.
fn estimate_base(carrier: &Raster) -> [u8; 3] {
    let mut histogram = [[0u32; 256]; 3];
    for (index, byte) in carrier.rgb.iter().enumerate() {
        if let Some(channel) = histogram.get_mut(index % 3) {
            if let Some(count) = channel.get_mut(*byte as usize) {
                *count = count.saturating_add(1);
            }
        }
    }
    let mut base = [0u8; 3];
    for (channel, counts) in histogram.iter().enumerate() {
        let mut best_value = 0usize;
        let mut best_count = 0u32;
        for (value, count) in counts.iter().enumerate() {
            if *count > best_count {
                best_count = *count;
                best_value = value;
            }
        }
        if let Some(slot) = base.get_mut(channel) {
            *slot = best_value as u8;
        }
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: u32 = 240;
    const H: u32 = 40;

    fn tag_of(seed: &str) -> [u8; 16] {
        tint_tag(&Digest::of(seed.as_bytes()), "TT-2026-0F3A9C", "0123456789abcdef")
    }

    fn marked() -> Raster {
        build_carrier(&tag_of("report"), W, H, RECOMMENDED_BASE)
    }

    /// Deterministic perturbation, so a failure is reproducible rather than a flake.
    fn perturb_pixels(raster: &mut Raster, permille: u64, seed: u64) {
        let mut rng = SplitMix64::new(seed);
        let pixels = raster.pixel_count();
        for pixel in 0..pixels {
            if rng.below(1000) < permille {
                let up = rng.below(2) == 1;
                for channel in 0..3 {
                    if let Some(byte) = raster.rgb.get_mut(pixel * 3 + channel) {
                        *byte = if up { byte.saturating_add(1) } else { byte.saturating_sub(1) };
                    }
                }
            }
        }
    }

    fn quantise(raster: &mut Raster, step: u32) {
        for byte in raster.rgb.iter_mut() {
            let rounded = ((u32::from(*byte) + step / 2) / step) * step;
            *byte = rounded.min(255) as u8;
        }
    }

    // -- tag ----------------------------------------------------------------------

    #[test]
    fn tag_is_deterministic() {
        let d = Digest::of(b"evidence");
        assert_eq!(tint_tag(&d, "CASE", "nonce"), tint_tag(&d, "CASE", "nonce"));
    }

    #[test]
    fn tag_changes_with_every_input() {
        let d = Digest::of(b"evidence");
        let reference = tint_tag(&d, "CASE", "nonce");
        assert_ne!(reference, tint_tag(&Digest::of(b"evidence2"), "CASE", "nonce"));
        assert_ne!(reference, tint_tag(&d, "CASF", "nonce"));
        assert_ne!(reference, tint_tag(&d, "CASE", "nonce2"));
    }

    /// Length prefixing: re-splitting the same characters must not give the same tag.
    #[test]
    fn tag_is_not_ambiguous_across_field_boundaries() {
        let d = Digest::of(b"evidence");
        assert_ne!(tint_tag(&d, "AB", "C"), tint_tag(&d, "A", "BC"));
    }

    // -- construction ---------------------------------------------------------------

    #[test]
    fn positions_are_distinct_and_complete() {
        let slots = slot_positions(&tag_of("report"), (W * H * 3) as usize);
        assert_eq!(slots.len(), CARRIER_POSITIONS);
        let mut sorted = slots.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), CARRIER_POSITIONS, "positions overlap");
        assert!(sorted.iter().all(|s| *s < (W * H * 3) as usize));
    }

    #[test]
    fn positions_are_distinct_at_the_minimum_carrier_size() {
        // Exactly 896 bytes of capacity: every slot must be used exactly once, which
        // is the case that would expose a probing bug.
        let slots = slot_positions(&tag_of("report"), CARRIER_POSITIONS);
        let mut sorted = slots.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), CARRIER_POSITIONS);
    }

    #[test]
    fn build_is_deterministic() {
        assert_eq!(marked(), marked());
        assert_eq!(marked().digest(), marked().digest());
    }

    #[test]
    fn marker_touches_exactly_the_expected_bytes_by_exactly_one() {
        let plain = Raster::new(W, H, RECOMMENDED_BASE);
        let carrier = marked();
        assert_eq!(carrier.width, W);
        assert_eq!(carrier.height, H);
        assert_eq!(carrier.rgb.len(), plain.rgb.len());

        let mut changed = 0usize;
        for (index, byte) in carrier.rgb.iter().enumerate() {
            let reference = plain.rgb.get(index).copied().unwrap_or(0);
            let delta = i32::from(*byte) - i32::from(reference);
            assert!(delta.abs() <= 1, "byte {index} moved by {delta}");
            if delta != 0 {
                changed += 1;
            }
        }
        assert_eq!(changed, CARRIER_POSITIONS, "overlapping or lost positions");
    }

    #[test]
    fn different_tags_produce_different_carriers() {
        let a = build_carrier(&tag_of("report-a"), W, H, RECOMMENDED_BASE);
        let b = build_carrier(&tag_of("report-b"), W, H, RECOMMENDED_BASE);
        assert_ne!(a, b);
    }

    // -- detection ------------------------------------------------------------------

    #[test]
    fn fresh_carrier_detects_perfectly() {
        let d = detect(&marked(), &tag_of("report"));
        assert_eq!(d.correlation_percent, 100);
        assert_eq!(d.bits_recovered, TAG_BITS as u32);
        assert!(d.matched);
    }

    #[test]
    fn detects_across_many_tags_and_carrier_sizes() {
        for size in [(W, H), (32, 10), (100, 100), (896, 1), (1, 300)] {
            for i in 0..8u32 {
                let tag = tag_of(&format!("case-{i}"));
                let carrier = build_carrier(&tag, size.0, size.1, RECOMMENDED_BASE);
                let d = detect(&carrier, &tag);
                assert!(d.matched, "{size:?} tag {i} did not detect: {d:?}");
                assert_eq!(d.correlation_percent, 100);
                assert_eq!(d.bits_recovered, TAG_BITS as u32);
            }
        }
    }

    #[test]
    fn survives_five_percent_of_pixels_moving_by_one() {
        for seed in 0..16u64 {
            let mut carrier = marked();
            perturb_pixels(&mut carrier, 50, seed);
            let d = detect(&carrier, &tag_of("report"));
            assert!(
                d.correlation_percent > DETECTOR_THRESHOLD_PERCENT,
                "seed {seed} fell to {}",
                d.correlation_percent
            );
            assert!(d.matched);
        }
    }

    /// The marker should degrade rather than snap. Half the pixels moving by one is
    /// far past anything email transport does, and it must still not read as a clean
    /// detection of some *other* tag.
    #[test]
    fn degrades_gracefully_under_heavy_perturbation() {
        let mut previous = 100u32;
        for permille in [0u64, 100, 300, 500, 800] {
            let mut carrier = marked();
            perturb_pixels(&mut carrier, permille, 7);
            let d = detect(&carrier, &tag_of("report"));
            assert!(d.correlation_percent <= previous, "correlation rose at {permille}");
            previous = d.correlation_percent;
            assert_eq!(detect(&carrier, &tag_of("other")).matched, false);
        }
    }

    /// Copying a marker from one report into another must not succeed. This is the
    /// attack the tag-derived positions exist to stop.
    #[test]
    fn a_carrier_built_for_another_tag_does_not_match() {
        let carrier = marked();
        for i in 0..64u32 {
            let other = tag_of(&format!("other-{i}"));
            let d = detect(&carrier, &other);
            assert!(!d.matched, "tag {i} matched a foreign carrier: {d:?}");
            assert!(d.correlation_percent < 20, "tag {i} correlated at {}", d.correlation_percent);
            assert!(d.bits_recovered < 32, "tag {i} recovered {} bits", d.bits_recovered);
        }
    }

    #[test]
    fn a_single_bit_difference_in_the_tag_does_not_match() {
        let tag = tag_of("report");
        let carrier = build_carrier(&tag, W, H, RECOMMENDED_BASE);
        for bit in 0..TAG_BITS {
            let mut near = tag;
            if let Some(byte) = near.get_mut(bit / 8) {
                *byte ^= 1 << (7 - bit % 8);
            }
            assert!(!detect(&carrier, &near).matched, "flipping bit {bit} still matched");
        }
    }

    // -- false positives --------------------------------------------------------------

    #[test]
    fn flat_rasters_never_false_positive() {
        let mut false_positives = 0u32;
        let mut trials = 0u32;
        for base in [0u8, 1, 17, 128, 200, 242, 254, 255] {
            for size in [(W, H), (32, 10), (64, 64), (896, 1)] {
                let flat = Raster::new(size.0, size.1, [base, base, base]);
                for i in 0..8u32 {
                    let d = detect(&flat, &tag_of(&format!("case-{i}")));
                    trials += 1;
                    assert_eq!(d.correlation_percent, 0);
                    assert_eq!(d.bits_recovered, 0);
                    if d.matched {
                        false_positives += 1;
                    }
                }
            }
        }
        assert!(trials >= 256);
        assert_eq!(false_positives, 0, "{false_positives} of {trials} flat rasters matched");
    }

    /// Harder than a flat raster: dithered noise with no marker at all. A detector that
    /// counted agreement instead of correlating would light up here.
    #[test]
    fn noisy_unmarked_rasters_never_false_positive() {
        let mut worst = 0u32;
        for seed in 0..200u64 {
            let mut noise = Raster::new(W, H, RECOMMENDED_BASE);
            perturb_pixels(&mut noise, 500, seed);
            let d = detect(&noise, &tag_of("report"));
            assert!(!d.matched, "seed {seed} matched noise: {d:?}");
            worst = worst.max(d.correlation_percent);
        }
        assert!(worst < DETECTOR_THRESHOLD_PERCENT, "worst noise correlation {worst}");
    }

    // -- destruction is reported, never papered over ------------------------------------

    #[test]
    fn quantisation_to_multiples_of_eight_destroys_the_marker() {
        let mut carrier = marked();
        quantise(&mut carrier, 8);
        let d = detect(&carrier, &tag_of("report"));
        assert!(!d.matched, "quantised carrier still matched: {d:?}");
        // 241, 242 and 243 all land on 240, so nothing at all survives.
        assert_eq!(d.correlation_percent, 0);
        assert_eq!(d.bits_recovered, 0);
    }

    /// A base whose ±1 straddles a quantisation boundary is the awkward case: half the
    /// modulation survives. It must still fail the threshold rather than half-pass.
    #[test]
    fn quantisation_across_a_bucket_boundary_still_fails() {
        let tag = tag_of("report");
        let mut carrier = build_carrier(&tag, W, H, [4, 4, 4]);
        quantise(&mut carrier, 8);
        let d = detect(&carrier, &tag);
        assert!(!d.matched, "boundary-straddling base still matched: {d:?}");
    }

    #[test]
    fn cropping_the_carrier_destroys_the_marker() {
        let carrier = marked();
        let rows = (H - 1) as usize;
        let cropped = Raster::from_rgb(
            W,
            H - 1,
            carrier.rgb.get(..rows * (W as usize) * 3).unwrap_or(&[]).to_vec(),
        )
        .expect("crop keeps a whole number of rows");
        assert!(!detect(&cropped, &tag_of("report")).matched);
    }

    #[test]
    fn overwriting_the_carrier_with_a_flat_block_destroys_the_marker() {
        let flat = Raster::new(W, H, RECOMMENDED_BASE);
        assert!(!detect(&flat, &tag_of("report")).matched);
    }

    // -- refusals ---------------------------------------------------------------------

    #[test]
    fn a_carrier_too_small_is_left_uniform() {
        for size in [(0u32, 0u32), (1, 1), (10, 10), (16, 18), (895, 1)] {
            assert!(!carrier_fits(size.0, size.1), "{size:?} unexpectedly fits");
            let carrier = build_carrier(&tag_of("report"), size.0, size.1, RECOMMENDED_BASE);
            assert_eq!(carrier, Raster::new(size.0, size.1, RECOMMENDED_BASE));
            let d = detect(&carrier, &tag_of("report"));
            assert_eq!(d, Detection::absent());
        }
    }

    #[test]
    fn the_minimum_fitting_carrier_is_exactly_896_bytes() {
        assert!(carrier_fits(299, 1)); // 897 bytes
        assert!(!carrier_fits(298, 1)); // 894 bytes
        assert_eq!(CARRIER_POSITIONS, 896);
    }

    #[test]
    fn an_extreme_base_is_refused_rather_than_half_marked() {
        for base in [[0u8, 0, 0], [255, 255, 255], [242, 0, 242], [242, 242, 255]] {
            let carrier = build_carrier(&tag_of("report"), W, H, base);
            assert_eq!(carrier, Raster::new(W, H, base), "base {base:?} was marked anyway");
            assert!(!detect(&carrier, &tag_of("report")).matched);
        }
    }

    /// The reason the refusal above exists: if the extreme base *were* marked, half of
    /// every saturated channel's bits would be unreadable. Demonstrated by hand so the
    /// rule does not survive as folklore.
    #[test]
    fn an_extreme_base_would_lose_half_its_bits_if_it_were_marked() {
        let tag = tag_of("report");
        let capacity = (W * H * 3) as usize;
        let mut carrier = Raster::new(W, H, [255, 255, 255]);
        for (bit, positions) in slot_positions(&tag, capacity).chunks(REPETITION).enumerate() {
            let delta: i8 = if tag_bit(&tag, bit) { 1 } else { -1 };
            for slot in positions {
                if let Some(byte) = carrier.rgb.get_mut(*slot) {
                    *byte = byte.saturating_add_signed(delta);
                }
            }
        }
        let d = detect(&carrier, &tag);
        assert!(d.correlation_percent < 70, "saturated carrier read at {}", d.correlation_percent);
        assert!(d.bits_recovered < TAG_BITS as u32);
    }

    #[test]
    fn an_oversized_request_yields_an_empty_raster() {
        let carrier = build_carrier(&tag_of("report"), 65535, 65535, RECOMMENDED_BASE);
        assert_eq!(carrier.width, 0);
        assert_eq!(carrier.height, 0);
        assert!(carrier.rgb.is_empty());
        assert!(!carrier_fits(65535, 65535));
    }

    #[test]
    fn a_raster_whose_buffer_disagrees_with_its_dimensions_is_absent() {
        let mut broken = marked();
        broken.rgb.truncate(broken.rgb.len() - 1);
        assert_eq!(detect(&broken, &tag_of("report")), Detection::absent());

        let oversized = Raster { width: W, height: H, rgb: vec![242; (W * H * 3) as usize + 1] };
        assert_eq!(detect(&oversized, &tag_of("report")), Detection::absent());

        let huge = Raster { width: 65535, height: 65535, rgb: Vec::new() };
        assert_eq!(detect(&huge, &tag_of("report")), Detection::absent());
    }

    #[test]
    fn an_empty_raster_is_absent() {
        let empty = Raster::new(0, 0, RECOMMENDED_BASE);
        assert_eq!(detect(&empty, &tag_of("report")), Detection::absent());
    }

    // -- base estimation -----------------------------------------------------------

    #[test]
    fn base_estimate_finds_the_flat_colour_under_marking_and_noise() {
        let mut carrier = build_carrier(&tag_of("report"), W, H, [200, 210, 220]);
        assert_eq!(estimate_base(&carrier), [200, 210, 220]);
        perturb_pixels(&mut carrier, 200, 3);
        assert_eq!(estimate_base(&carrier), [200, 210, 220]);
    }

    #[test]
    fn base_estimate_is_per_channel() {
        let carrier = Raster::new(4, 4, [1, 2, 3]);
        assert_eq!(estimate_base(&carrier), [1, 2, 3]);
    }
}
