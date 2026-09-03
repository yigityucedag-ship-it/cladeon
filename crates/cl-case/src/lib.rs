//! # cl-case
//!
//! Buyer-side challenge issuance and the Ed25519 binding that ties a report to one
//! case. The scanner ships only the public key; the issuing secret never leaves the
//! buyer, so a vendor who fully controls the scanning machine still cannot mint a
//! challenge.

#![forbid(unsafe_code)]

pub mod challenge;
pub mod key;

pub use challenge::{verify_challenge, Challenge};
pub use key::{verify_detached, IssuerKey};
