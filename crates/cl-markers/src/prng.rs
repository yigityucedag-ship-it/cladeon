//! SplitMix64, implemented here because the marker must be reproducible byte-for-byte
//! and we may not add a dependency.
//!
//! The workspace dependency policy allows exactly four external crates, none of which
//! is a random number generator. That is not a hardship: the tint marker does not want
//! *entropy*, it wants a **stable, publishable pseudo-random sequence** derived from
//! the tag. Two runs of Verify on two machines must place the carrier positions in
//! exactly the same slots, so an OS-seeded generator would be actively wrong here.
//!
//! SplitMix64 (Steele, Lea and Flood, 2014) is chosen because its state transition and
//! output mixing are a fixed sequence of wrapping adds, multiplies and shifts — there
//! is no table, no seeding ritual and no branch, so an independent reimplementation in
//! another language cannot drift from this one.
//!
//! This is not a cryptographic generator and nothing here depends on it being one. The
//! positions are recoverable by anyone holding the tag, and the tag travels in
//! `forensic-markers.json`.

/// A deterministic 64-bit generator with a 64-bit state.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

/// The golden-ratio increment from the reference SplitMix64.
const GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
const MIX_A: u64 = 0xBF58_476D_1CE4_E5B9;
const MIX_B: u64 = 0x94D0_49BB_1331_11EB;

/// Rejection attempts allowed in [`SplitMix64::below`] before accepting a
/// slightly biased value. Each attempt fails with probability below one half, so
/// reaching this cap has probability under `2^-64`; the cap exists only so that the
/// function is provably total.
const REJECTION_ATTEMPTS: u32 = 128;

impl SplitMix64 {
    pub fn new(seed: u64) -> SplitMix64 {
        SplitMix64 { state: seed }
    }

    /// Next value in the sequence. All arithmetic wraps, so this cannot overflow.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(GAMMA);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(MIX_A);
        z = (z ^ (z >> 27)).wrapping_mul(MIX_B);
        z ^ (z >> 31)
    }

    /// Uniform value in `0..bound`, or `0` when `bound` is zero.
    ///
    /// Uses rejection sampling rather than a plain modulo so that slot selection is not
    /// skewed towards the low end of a raster. The bias would be harmless for a marker
    /// but it would show up as a visible cluster of modulated pixels in the top-left
    /// corner of the carrier, which defeats the point of an imperceptible mark.
    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        // Largest multiple of `bound` that fits; values at or above it are rejected.
        let zone = (u64::MAX / bound).saturating_mul(bound);
        for _ in 0..REJECTION_ATTEMPTS {
            let v = self.next_u64();
            if v < zone {
                return v % bound;
            }
        }
        self.next_u64() % bound
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference values for SplitMix64 seeded with 0, from the original paper's
    /// sequence. A change here means the marker layout has silently moved and every
    /// previously issued report would stop verifying.
    #[test]
    fn matches_reference_vectors_for_seed_zero() {
        let mut r = SplitMix64::new(0);
        assert_eq!(r.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(r.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(r.next_u64(), 0x06C4_5D18_8009_454F);
        assert_eq!(r.next_u64(), 0xF88B_B8A8_724C_81EC);
    }

    #[test]
    fn same_seed_same_sequence() {
        let mut a = SplitMix64::new(0x1234_5678_9ABC_DEF0);
        let mut b = SplitMix64::new(0x1234_5678_9ABC_DEF0);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge_immediately() {
        let mut a = SplitMix64::new(0);
        let mut b = SplitMix64::new(1);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn seed_max_does_not_overflow() {
        let mut r = SplitMix64::new(u64::MAX);
        for _ in 0..1000 {
            let _ = r.next_u64();
        }
    }

    #[test]
    fn below_respects_the_bound() {
        let mut r = SplitMix64::new(99);
        for bound in [1u64, 2, 3, 7, 896, 28_800, u64::MAX] {
            for _ in 0..200 {
                assert!(r.below(bound) < bound);
            }
        }
    }

    #[test]
    fn below_zero_is_zero_not_a_panic() {
        let mut r = SplitMix64::new(7);
        assert_eq!(r.below(0), 0);
    }

    #[test]
    fn below_covers_the_range_reasonably_evenly() {
        // 24 buckets, 24_000 draws. A modulo-biased generator over a small bound
        // would not show up here, but a generator stuck in a short cycle would.
        let mut r = SplitMix64::new(0xDEAD_BEEF);
        let mut counts = [0u32; 24];
        for _ in 0..24_000 {
            let v = r.below(24) as usize;
            if let Some(c) = counts.get_mut(v) {
                *c += 1;
            }
        }
        for c in counts {
            assert!(c > 700 && c < 1300, "bucket count {c} is far from the 1000 expected");
        }
    }
}
