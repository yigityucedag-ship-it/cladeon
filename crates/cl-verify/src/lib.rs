//! # cl-verify
//!
//! Buyer-side verification of a `.clade` bundle, as a library.
//!
//! Exposed so the desktop application and the command line share one implementation.
//! Verification is the part a buyer relies on, and two copies of it would eventually
//! disagree about whether a bundle was sound.

#![forbid(unsafe_code)]

pub mod verify;

pub use verify::{facts_from_report, recompute, verify_bundle, Recomputation, Verification};
