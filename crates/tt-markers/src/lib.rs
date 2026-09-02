//! # tt-markers
//!
//! Offline tamper-evidence tripwires.
//!
//! Be clear about what these are: they catch casual editing and reconstruction of a
//! PDF. They are NOT a root of trust. An offline scanner in hostile hands can be
//! reverse-engineered, so security must never depend on their secrecy.

#![forbid(unsafe_code)]

pub mod canary;
pub mod prng;
pub mod tint;

pub use canary::{derive_canary, render_with_canary, strip_canary, verify_canary, Canary};
pub use prng::SplitMix64;
pub use tint::{build_carrier, detect, tint_tag, Detection, DETECTOR_THRESHOLD_PERCENT};
