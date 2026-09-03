//! The buyer's issuing key, and detached Ed25519 verification.
//!
//! ## Why the secret half never ships
//!
//! The scanner runs on the vendor's machine, under the vendor's control. Anything
//! compiled into it is available to the party being screened. So the scanner holds
//! **only** a public key: it can tell whether a challenge was issued by the buyer,
//! and it cannot mint one. [`IssuerKey`] therefore lives in the buyer-side Case
//! Builder, and the only thing that crosses to the vendor is
//! [`IssuerKey::public_hex`] plus a hex signature.
//!
//! ## Why `from_bytes` rather than `SigningKey::generate`
//!
//! An Ed25519 secret key is a uniform 32-byte string, so seeding it directly from
//! the OS CSPRNG through `getrandom` is exactly equivalent to the library's own
//! generator, and it avoids pulling a random-number adapter crate into a workspace
//! whose dependency policy is four crates wide.
//!
//! ## Why `verify_strict`
//!
//! Plain `verify` accepts small-order public keys and non-canonical `R` values,
//! which admit signatures that verify under more than one key. That is exactly the
//! ambiguity a binding must not have, so verification uses `verify_strict` and
//! additionally refuses weak keys outright.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use cl_core::error::{ClError, ClResult};
use cl_core::hex;

use crate::challenge::Challenge;

/// Hex length of an Ed25519 secret key (32 bytes).
pub const SECRET_KEY_HEX_LEN: usize = 64;
/// Hex length of an Ed25519 public key (32 bytes).
pub const PUBLIC_KEY_HEX_LEN: usize = 64;
/// Hex length of an Ed25519 signature (64 bytes).
pub const SIGNATURE_HEX_LEN: usize = 128;

/// Fill `buf` from the operating system CSPRNG.
///
/// Entropy failure is an `Io` error rather than a panic: on a locked-down host the
/// honest outcome is "this case could not be issued", not a crash.
pub(crate) fn fill_random(buf: &mut [u8]) -> ClResult<()> {
    getrandom::getrandom(buf).map_err(|e| ClError::io(format!("os entropy unavailable: {e}")))
}

/// An Ed25519 keypair held by the buyer who issues cases.
///
/// The secret half is never written into a challenge, a report or a bundle. It
/// exists only to produce `challenge.sig`.
pub struct IssuerKey {
    signing: SigningKey,
}

/// Debug prints the public key only.
///
/// A derived `Debug` would place the secret key into any log line, panic message or
/// test failure that happens to format the surrounding structure. That is a
/// realistic way for a signing key to escape, so the impl is written by hand.
impl std::fmt::Debug for IssuerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IssuerKey(public={})", self.public_hex())
    }
}

impl IssuerKey {
    /// Generate a fresh keypair from OS entropy.
    pub fn generate() -> ClResult<IssuerKey> {
        let mut secret = [0u8; 32];
        fill_random(&mut secret)?;
        let key = IssuerKey { signing: SigningKey::from_bytes(&secret) };
        // Best effort only: the workspace dependency policy excludes `zeroize`, so
        // this store may be elided. The copy that matters — the one inside
        // `SigningKey` — is zeroised on drop by ed25519-dalek itself.
        secret.fill(0);
        Ok(key)
    }

    /// Load a key from 64 lowercase hex characters.
    ///
    /// Uppercase, short, long and non-hex inputs are rejected rather than padded or
    /// folded, because a key that silently changes shape is a key that silently
    /// changes identity.
    pub fn from_secret_hex(s: &str) -> ClResult<IssuerKey> {
        if s.len() != SECRET_KEY_HEX_LEN {
            return Err(ClError::malformed(
                "issuer_secret_key",
                s.len(),
                format!("expected {SECRET_KEY_HEX_LEN} lowercase hex characters"),
            ));
        }
        let bytes = hex::decode_fixed::<32>(s)?;
        Ok(IssuerKey { signing: SigningKey::from_bytes(&bytes) })
    }

    /// The secret key as 64 lowercase hex characters.
    ///
    /// Provided so a buyer can persist an issuing identity across cases. It must
    /// never be placed in a challenge, a report, a bundle or a log.
    pub fn to_secret_hex(&self) -> String {
        hex::encode(self.signing.as_bytes())
    }

    /// The public key as 64 lowercase hex characters. This is the only half that
    /// travels to the vendor.
    pub fn public_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().as_bytes())
    }

    /// Sign the canonical bytes of `challenge`, returning 128 lowercase hex
    /// characters.
    ///
    /// Signing goes through [`Challenge::to_canonical_bytes`], so a challenge that
    /// does not satisfy its own schema cannot be signed at all: the failure happens
    /// at issuance, on the buyer's machine, rather than as an unverifiable document
    /// on the vendor's.
    pub fn sign(&self, challenge: &Challenge) -> ClResult<String> {
        Ok(self.sign_bytes(&challenge.to_canonical_bytes()?))
    }

    /// Sign arbitrary bytes. Ed25519 signing is deterministic, so the same key over
    /// the same bytes always yields the same hex.
    pub fn sign_bytes(&self, bytes: &[u8]) -> String {
        hex::encode(&self.signing.sign(bytes).to_bytes())
    }
}

/// Verify a detached hex signature over `message` under a hex public key.
///
/// Returns `false` for every failure mode — malformed hex, wrong length, an
/// unusable or weak public key, a bad signature — because the caller's vocabulary
/// has one value for "did not verify" and distinguishing the reasons here would
/// invite a caller to treat some of them as benign.
pub fn verify_detached(message: &[u8], sig_hex: &str, public_hex: &str) -> bool {
    if sig_hex.len() != SIGNATURE_HEX_LEN || public_hex.len() != PUBLIC_KEY_HEX_LEN {
        return false;
    }
    let (Ok(sig_bytes), Ok(pub_bytes)) =
        (hex::decode_fixed::<64>(sig_hex), hex::decode_fixed::<32>(public_hex))
    else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&pub_bytes) else {
        return false;
    };
    if verifying.is_weak() {
        return false;
    }
    verifying.verify_strict(message, &Signature::from_bytes(&sig_bytes)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed() -> IssuerKey {
        IssuerKey::from_secret_hex(&"11".repeat(32)).expect("fixed test key")
    }

    #[test]
    fn secret_hex_round_trips_and_is_lowercase() {
        let k = fixed();
        assert_eq!(k.to_secret_hex(), "11".repeat(32));
        let again = IssuerKey::from_secret_hex(&k.to_secret_hex()).unwrap();
        assert_eq!(again.public_hex(), k.public_hex());
    }

    #[test]
    fn public_key_is_derived_and_fixed_width() {
        let k = fixed();
        assert_eq!(k.public_hex().len(), PUBLIC_KEY_HEX_LEN);
        assert!(k.public_hex().bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
        // Derivation is a pure function of the secret.
        assert_eq!(k.public_hex(), fixed().public_hex());
        assert_ne!(k.public_hex(), k.to_secret_hex());
    }

    #[test]
    fn from_secret_hex_rejects_malformed_input() {
        assert!(IssuerKey::from_secret_hex("").is_err());
        assert!(IssuerKey::from_secret_hex(&"11".repeat(31)).is_err(), "too short");
        assert!(IssuerKey::from_secret_hex(&"11".repeat(33)).is_err(), "too long");
        assert!(IssuerKey::from_secret_hex(&"AB".repeat(32)).is_err(), "uppercase");
        assert!(IssuerKey::from_secret_hex(&"zz".repeat(32)).is_err(), "non-hex");
        assert!(IssuerKey::from_secret_hex(&" ".repeat(64)).is_err(), "whitespace");
    }

    #[test]
    fn all_zero_secret_is_accepted_but_yields_a_usable_key() {
        // An Ed25519 secret is hashed before use, so even a degenerate seed gives a
        // strong key. Rejecting it would be security theatre; asserting it still
        // signs and verifies is the useful check.
        let k = IssuerKey::from_secret_hex(&"00".repeat(32)).unwrap();
        let sig = k.sign_bytes(b"payload");
        assert!(verify_detached(b"payload", &sig, &k.public_hex()));
    }

    #[test]
    fn signing_is_deterministic() {
        let k = fixed();
        assert_eq!(k.sign_bytes(b"same message"), k.sign_bytes(b"same message"));
        assert_ne!(k.sign_bytes(b"a"), k.sign_bytes(b"b"));
        assert_eq!(k.sign_bytes(b"a").len(), SIGNATURE_HEX_LEN);
    }

    #[test]
    fn signature_verifies_and_does_not_verify_elsewhere() {
        let k = fixed();
        let other = IssuerKey::from_secret_hex(&"22".repeat(32)).unwrap();
        let sig = k.sign_bytes(b"bound message");
        assert!(verify_detached(b"bound message", &sig, &k.public_hex()));
        assert!(!verify_detached(b"other message", &sig, &k.public_hex()), "wrong message");
        assert!(!verify_detached(b"bound message", &sig, &other.public_hex()), "wrong key");
    }

    #[test]
    fn empty_message_still_signs_and_verifies() {
        let k = fixed();
        let sig = k.sign_bytes(b"");
        assert!(verify_detached(b"", &sig, &k.public_hex()));
        assert!(!verify_detached(b"\0", &sig, &k.public_hex()));
    }

    #[test]
    fn verify_detached_rejects_hostile_encodings_without_panicking() {
        let k = fixed();
        let pubk = k.public_hex();
        let sig = k.sign_bytes(b"msg");
        assert!(!verify_detached(b"msg", "", &pubk), "empty signature");
        assert!(!verify_detached(b"msg", &sig[..126], &pubk), "truncated signature");
        assert!(!verify_detached(b"msg", &format!("{sig}00"), &pubk), "overlong signature");
        assert!(!verify_detached(b"msg", &sig.to_uppercase(), &pubk), "uppercase signature");
        assert!(!verify_detached(b"msg", &"zz".repeat(64), &pubk), "non-hex signature");
        assert!(!verify_detached(b"msg", &sig, ""), "empty key");
        assert!(!verify_detached(b"msg", &sig, &pubk.to_uppercase()), "uppercase key");
        assert!(!verify_detached(b"msg", &sig, &"zz".repeat(32)), "non-hex key");
        assert!(!verify_detached(b"msg", &sig, &pubk[..62]), "truncated key");
        // Signature and key transposed: the length check alone rejects this.
        assert!(!verify_detached(b"msg", &pubk, &sig));
    }

    #[test]
    fn weak_public_keys_are_refused() {
        // The all-zero encoding is the identity point: a small-order key under
        // which crafted signatures verify for any message.
        let weak = "00".repeat(32);
        assert!(!verify_detached(b"msg", &"00".repeat(64), &weak));
        assert!(!verify_detached(b"", &"11".repeat(64), &weak));
    }

    #[test]
    fn every_single_bit_flip_of_a_signature_is_rejected() {
        let k = fixed();
        let pubk = k.public_hex();
        let sig = hex::decode_fixed::<64>(&k.sign_bytes(b"anchor")).unwrap();
        for byte in 0..64 {
            for bit in 0..8 {
                let mut tampered = sig;
                tampered[byte] ^= 1 << bit;
                assert!(
                    !verify_detached(b"anchor", &hex::encode(&tampered), &pubk),
                    "bit {bit} of byte {byte} verified"
                );
            }
        }
    }

    #[test]
    fn generate_draws_fresh_entropy() {
        let a = IssuerKey::generate().expect("entropy");
        let b = IssuerKey::generate().expect("entropy");
        assert_ne!(a.to_secret_hex(), b.to_secret_hex());
        assert_ne!(a.public_hex(), b.public_hex());
        assert_eq!(a.to_secret_hex().len(), SECRET_KEY_HEX_LEN);
        let sig = a.sign_bytes(b"x");
        assert!(verify_detached(b"x", &sig, &a.public_hex()));
        assert!(!verify_detached(b"x", &sig, &b.public_hex()));
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let k = fixed();
        let shown = format!("{k:?}");
        assert!(shown.contains(&k.public_hex()));
        assert!(!shown.contains(&k.to_secret_hex()), "secret key leaked into Debug: {shown}");
    }
}
