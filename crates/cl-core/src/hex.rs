//! Strict lowercase hex. Decoding rejects uppercase, odd lengths and any
//! non-hex byte, because a permissive decoder is an aliasing bug in a format
//! whose digests are compared for equality.

use crate::error::{ClError, ClResult};

const TABLE: &[u8; 16] = b"0123456789abcdef";

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

fn nibble(c: u8, at: usize) -> ClResult<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(ClError::malformed("hex", at, "expected lowercase hex digit")),
    }
}

pub fn decode(s: &str) -> ClResult<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err(ClError::malformed("hex", b.len(), "odd number of hex digits"));
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((nibble(b[i], i)? << 4) | nibble(b[i + 1], i + 1)?);
        i += 2;
    }
    Ok(out)
}

/// Decode exactly `N` bytes, rejecting any other length.
pub fn decode_fixed<const N: usize>(s: &str) -> ClResult<[u8; N]> {
    let v = decode(s)?;
    if v.len() != N {
        return Err(ClError::malformed("hex", v.len(), format!("expected {N} bytes")));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}

/// True if `s` is exactly 64 lowercase hex characters.
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let data = [0u8, 1, 15, 16, 254, 255];
        assert_eq!(encode(&data), "00010f10feff");
        assert_eq!(decode("00010f10feff").unwrap(), data);
    }

    #[test]
    fn rejects_uppercase() {
        assert!(decode("00FF").is_err());
    }

    #[test]
    fn rejects_odd_length() {
        assert!(decode("abc").is_err());
    }

    #[test]
    fn rejects_non_hex() {
        assert!(decode("zz").is_err());
    }

    #[test]
    fn sha256_hex_shape() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex(&"A".repeat(64)));
        assert!(!is_sha256_hex(&"a".repeat(63)));
    }
}
