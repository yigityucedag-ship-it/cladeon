//! The one-time challenge a buyer issues before a scan.
//!
//! The challenge is what makes a report *answer a question* rather than float free.
//! It pins the exact claim being tested, the ruleset that must evaluate it, and a
//! nonce that makes replaying an old report detectable.
//!
//! ## Unsigned challenges are legitimate
//!
//! A pilot buyer with no key management still needs to run cases. An unsigned
//! challenge therefore verifies as [`ChallengeStatus::Unsigned`] rather than as an
//! error. Refusing to work without a signature would make the pilot impossible;
//! silently reporting unsigned as `Bound` would be a lie. Naming the state is the
//! only honest option.

use cl_core::canon::{arr, CanonValue, Obj};
use cl_core::error::{ClError, ClResult};
use cl_core::ids::{CaseId, Nonce};
use cl_core::limits::Limits;
use cl_core::time::Timestamp;
use cl_core::vocab::ChallengeStatus;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub case_id: CaseId,
    pub nonce: Nonce,
    pub vendor_label: String,
    pub exact_claim_text: String,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    /// SHA-256 of the scanner build the buyer expects to be run, when known.
    pub expected_scanner_sha256: Option<String>,
    pub ruleset_version: i64,
    pub vocabulary_version: i64,
    pub requested_evidence: Vec<String>,
    /// Ed25519 public key of the issuer, hex. Absent for an unsigned pilot case.
    pub issuer_public_key: Option<String>,
}

impl Challenge {
    /// Build a challenge from a supplied clock, so issuance is testable.
    pub fn new(
        case_id: CaseId,
        nonce: Nonce,
        vendor_label: impl Into<String>,
        exact_claim_text: impl Into<String>,
        issued_at: Timestamp,
        valid_days: i64,
        requested_evidence: Vec<String>,
        issuer_public_key: Option<String>,
    ) -> Challenge {
        Challenge {
            case_id,
            nonce,
            vendor_label: vendor_label.into(),
            exact_claim_text: exact_claim_text.into(),
            issued_at,
            expires_at: issued_at.plus_days(valid_days),
            expected_scanner_sha256: None,
            ruleset_version: cl_core::RULESET_VERSION,
            vocabulary_version: cl_core::VOCABULARY_VERSION,
            requested_evidence,
            issuer_public_key,
        }
    }

    pub fn to_canon(&self) -> CanonValue {
        let mut ev = self.requested_evidence.clone();
        ev.sort();
        ev.dedup();
        CanonValue::Obj(
            Obj::new()
                .with("schema_version", cl_core::SCHEMA_VERSION)
                .with("case_id", &self.case_id)
                .with("nonce", &self.nonce)
                .with("vendor_label", self.vendor_label.as_str())
                .with("exact_claim_text", self.exact_claim_text.as_str())
                .with("issued_at", self.issued_at.to_rfc3339())
                .with("expires_at", self.expires_at.to_rfc3339())
                .with("ruleset_version", self.ruleset_version)
                .with("vocabulary_version", self.vocabulary_version)
                .with("requested_evidence", arr(ev))
                .with_opt("expected_scanner_sha256", self.expected_scanner_sha256.clone())
                .with_opt("issuer_public_key", self.issuer_public_key.clone()),
        )
    }

    pub fn to_canonical_bytes(&self) -> ClResult<Vec<u8>> {
        Ok(self.to_canon().to_canonical_bytes())
    }

    /// Parse a challenge, requiring it to already be in canonical form.
    ///
    /// A challenge that is valid JSON but reformatted has been through something,
    /// and since the signature covers canonical bytes, accepting a reformatted copy
    /// would only produce a confusing signature failure later. Rejecting it here
    /// reports the actual problem.
    pub fn parse(bytes: &[u8]) -> ClResult<Challenge> {
        let v = cl_core::canon::parse_canonical(bytes, &Limits::default())?;
        let s = |k: &str| -> ClResult<String> {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(|x| x.to_string())
                .ok_or_else(|| ClError::malformed("challenge", 0, format!("missing `{k}`")))
        };
        let i = |k: &str| -> ClResult<i64> {
            v.get(k)
                .and_then(|x| x.as_int())
                .ok_or_else(|| ClError::malformed("challenge", 0, format!("missing `{k}`")))
        };
        Ok(Challenge {
            case_id: CaseId::parse(&s("case_id")?)?,
            nonce: Nonce::parse(&s("nonce")?)?,
            vendor_label: s("vendor_label")?,
            exact_claim_text: s("exact_claim_text")?,
            issued_at: Timestamp::parse_rfc3339(&s("issued_at")?)?,
            expires_at: Timestamp::parse_rfc3339(&s("expires_at")?)?,
            expected_scanner_sha256: v
                .get("expected_scanner_sha256")
                .and_then(|x| x.as_str())
                .map(|x| x.to_string()),
            ruleset_version: i("ruleset_version")?,
            vocabulary_version: i("vocabulary_version")?,
            requested_evidence: v
                .get("requested_evidence")
                .and_then(|x| x.as_arr())
                .map(|a| a.iter().filter_map(|e| e.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            issuer_public_key: v
                .get("issuer_public_key")
                .and_then(|x| x.as_str())
                .map(|x| x.to_string()),
        })
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        now > self.expires_at
    }
}

/// Verify a challenge against an optional detached signature.
///
/// `now` is supplied rather than read from the clock so that verification is
/// reproducible: the same bundle checked twice must give the same answer.
pub fn verify_challenge(
    challenge_bytes: Option<&[u8]>,
    signature_hex: Option<&str>,
    now: Timestamp,
    expected_case_id: Option<&CaseId>,
) -> ChallengeStatus {
    let Some(bytes) = challenge_bytes else {
        return ChallengeStatus::Absent;
    };
    let Ok(challenge) = Challenge::parse(bytes) else {
        return ChallengeStatus::SignatureInvalid;
    };
    if let Some(want) = expected_case_id {
        if *want != challenge.case_id {
            return ChallengeStatus::CaseMismatch;
        }
    }

    // Expiry is checked before the signature so that an expired-but-valid challenge
    // reports the reason a reader can act on.
    if challenge.is_expired(now) {
        return ChallengeStatus::Expired;
    }

    match (signature_hex, challenge.issuer_public_key.as_deref()) {
        (Some(sig), Some(pk)) => {
            if crate::key::verify_detached(bytes, sig, pk) {
                ChallengeStatus::Bound
            } else {
                ChallengeStatus::SignatureInvalid
            }
        }
        // A signature with no key to check it against establishes nothing.
        (Some(_), None) => ChallengeStatus::SignatureInvalid,
        (None, _) => ChallengeStatus::Unsigned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> Timestamp {
        Timestamp::parse_rfc3339(s).unwrap()
    }

    fn sample(pk: Option<String>) -> Challenge {
        Challenge::new(
            CaseId::parse("CL-2026-0F3A9C").unwrap(),
            Nonce::parse(&"a1".repeat(16)).unwrap(),
            "Acme Analytics Ltd",
            "We trained our own large language model from scratch.",
            ts("2026-09-02T13:00:00Z"),
            14,
            vec!["adapter_config".into(), "base_identity".into()],
            pk,
        )
    }

    #[test]
    fn canonical_round_trip() {
        let c = sample(None);
        let bytes = c.to_canonical_bytes().unwrap();
        assert_eq!(Challenge::parse(&bytes).unwrap(), c);
    }

    #[test]
    fn expiry_is_derived_from_the_supplied_clock() {
        let c = sample(None);
        assert_eq!(c.expires_at.to_rfc3339(), "2026-09-16T13:00:00Z");
        assert!(!c.is_expired(ts("2026-09-16T13:00:00Z")));
        assert!(c.is_expired(ts("2026-09-16T13:00:01Z")));
    }

    #[test]
    fn non_canonical_json_is_rejected() {
        let pretty = b"{ \"case_id\": \"CL-2026-0F3A9C\" }";
        assert!(Challenge::parse(pretty).is_err());
    }

    #[test]
    fn absent_challenge_reports_absent() {
        assert_eq!(
            verify_challenge(None, None, ts("2026-09-03T00:00:00Z"), None),
            ChallengeStatus::Absent
        );
    }

    #[test]
    fn unsigned_challenge_is_a_named_state_not_an_error() {
        let c = sample(None);
        let b = c.to_canonical_bytes().unwrap();
        assert_eq!(
            verify_challenge(Some(&b), None, ts("2026-09-03T00:00:00Z"), None),
            ChallengeStatus::Unsigned
        );
    }

    #[test]
    fn expired_challenge_reports_expired() {
        let c = sample(None);
        let b = c.to_canonical_bytes().unwrap();
        assert_eq!(
            verify_challenge(Some(&b), None, ts("2026-10-01T00:00:00Z"), None),
            ChallengeStatus::Expired
        );
    }

    #[test]
    fn case_id_mismatch_is_detected() {
        let c = sample(None);
        let b = c.to_canonical_bytes().unwrap();
        let other = CaseId::parse("CL-2026-AAAAAA").unwrap();
        assert_eq!(
            verify_challenge(Some(&b), None, ts("2026-09-03T00:00:00Z"), Some(&other)),
            ChallengeStatus::CaseMismatch
        );
    }

    #[test]
    fn signature_without_a_public_key_establishes_nothing() {
        let c = sample(None);
        let b = c.to_canonical_bytes().unwrap();
        assert_eq!(
            verify_challenge(Some(&b), Some(&"00".repeat(64)), ts("2026-09-03T00:00:00Z"), None),
            ChallengeStatus::SignatureInvalid
        );
    }

    #[test]
    fn signed_challenge_binds_and_tampering_breaks_it() {
        let key = crate::key::IssuerKey::generate().unwrap();
        let c = sample(Some(key.public_hex()));
        let b = c.to_canonical_bytes().unwrap();
        let sig = key.sign(&c).unwrap();
        assert_eq!(
            verify_challenge(Some(&b), Some(&sig), ts("2026-09-03T00:00:00Z"), None),
            ChallengeStatus::Bound
        );

        let mut tampered = c.clone();
        tampered.exact_claim_text = "We fine-tuned an open model.".into();
        let tb = tampered.to_canonical_bytes().unwrap();
        assert_eq!(
            verify_challenge(Some(&tb), Some(&sig), ts("2026-09-03T00:00:00Z"), None),
            ChallengeStatus::SignatureInvalid
        );
    }
}
