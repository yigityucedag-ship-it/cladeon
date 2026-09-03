//! CRC-32 (IEEE 802.3), reflected, polynomial `0xEDB88320`.
//!
//! Implemented here rather than pulled in as a dependency for two reasons. The
//! dependency policy forbids third-party code on the path of bundle bytes, and CRC-32
//! is a checksum on untrusted input: it is the first thing an adversary's archive
//! makes us evaluate. Eight lines of shift-and-xor with a compile-time table are
//! easier to audit than a crate, and the algorithm is fixed by the ZIP format, so
//! there is nothing to keep up to date.
//!
//! This is a *checksum*, never a security primitive. It detects an entry whose bytes
//! disagree with the header that describes them. Anything that must resist a forger
//! uses SHA-256 via `cl_core::hash`.

/// Reflected CRC-32 table, built at compile time so there is no lazy initialisation
/// and no runtime state to get wrong.
const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            bit += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static TABLE: [u32; 256] = build_table();

/// Incremental CRC-32, so a large entry never has to be concatenated in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc32(u32);

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    pub fn new() -> Self {
        Crc32(0xFFFF_FFFF)
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let mut c = self.0;
        for b in bytes {
            // The index is `u8`-derived, so it is always in range for a 256-entry
            // table; the lookup cannot panic regardless of input.
            let idx = ((c ^ (*b as u32)) & 0xff) as usize;
            c = TABLE[idx] ^ (c >> 8);
        }
        self.0 = c;
    }

    #[must_use]
    pub fn updated(mut self, bytes: &[u8]) -> Self {
        self.update(bytes);
        self
    }

    pub fn finish(self) -> u32 {
        self.0 ^ 0xFFFF_FFFF
    }
}

/// One-shot CRC-32 of a byte slice.
pub fn crc32(bytes: &[u8]) -> u32 {
    Crc32::new().updated(bytes).finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector_empty_is_zero() {
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn known_vector_check_string() {
        // The standard CRC "check" value: CRC-32 of the ASCII digits 1..9.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn known_vectors_short_strings() {
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(b"abc"), 0x3524_41C2);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let data: Vec<u8> = (0u16..1000).map(|i| (i % 251) as u8).collect();
        let mut c = Crc32::new();
        for chunk in data.chunks(7) {
            c.update(chunk);
        }
        assert_eq!(c.finish(), crc32(&data));
    }

    #[test]
    fn empty_update_is_identity() {
        let mut c = Crc32::new();
        c.update(b"");
        c.update(b"abc");
        c.update(b"");
        assert_eq!(c.finish(), crc32(b"abc"));
    }

    #[test]
    fn single_bit_flip_changes_the_checksum() {
        let a = [0x00u8; 64];
        let mut b = a;
        b[31] = 0x01;
        assert_ne!(crc32(&a), crc32(&b));
    }

    #[test]
    fn handles_every_byte_value() {
        let all: Vec<u8> = (0..=255u8).collect();
        // Exercises all 256 table slots; the point is that it terminates without
        // panicking and is stable, not the specific constant.
        assert_eq!(crc32(&all), crc32(&all));
        assert_ne!(crc32(&all), 0);
    }
}
