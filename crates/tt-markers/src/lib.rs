//! # tt-markers
//!
//! Offline tamper-evidence tripwires.
//!
//! Be clear about what these are: they catch casual editing and reconstruction of a
//! PDF. They are NOT a root of trust. An offline scanner in hostile hands can be
//! reverse-engineered, so security must never depend on their secrecy.

#![forbid(unsafe_code)]

pub mod prng;

pub use prng::SplitMix64;
