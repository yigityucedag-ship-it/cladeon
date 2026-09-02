//! # tt-core
//!
//! Foundation types for TrainTrace: canonical JSON (RFC 8785), bounded parsing of
//! untrusted input, hashing, timestamps, redaction, and the frozen vocabulary.
//!
//! ## Two value models, deliberately
//!
//! * [`canon::CanonValue`] is the **authoritative** model. It has no floating-point
//!   variant at all, so a float cannot reach a signed or hashed document even by
//!   mistake. Scores are stored as integer tenths.
//! * [`json::JsonValue`] is the **untrusted input** model. Vendor configs legitimately
//!   contain `5e-5` and `0.05`, so numbers are retained as their exact source text and
//!   never round-tripped through a binary float.
//!
//! Nothing in this crate executes, deserialises or trusts vendor-supplied bytes.

#![forbid(unsafe_code)]

pub mod canon;
pub mod error;
pub mod hash;
pub mod hex;
pub mod ids;
pub mod json;
pub mod limits;
pub mod raster;
pub mod redact;
pub mod time;
pub mod vocab;

pub use error::{TtError, TtResult};

/// Schema version of every authoritative document produced by this build.
pub const SCHEMA_VERSION: i64 = 1;
/// Version of the frozen vocabulary in `docs/00-FROZEN-VOCABULARY.md`.
pub const VOCABULARY_VERSION: i64 = 1;
/// Version of the rule catalogue in `docs/01-RULE-CATALOGUE.md`.
pub const RULESET_VERSION: i64 = 1;
/// Version of the scoring rubric weights.
pub const RUBRIC_VERSION: i64 = 1;
/// Version of the `.ttscan` container layout.
pub const BUNDLE_FORMAT: i64 = 1;
/// Version of the forensic marker construction.
pub const MARKER_VERSION: i64 = 1;

/// Product name written into reports.
pub const SCANNER_NAME: &str = "TrainTrace Screen";
/// Verifier name written into verification output.
pub const VERIFIER_NAME: &str = "TrainTrace Verify";
/// Build version of this workspace.
pub const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The statement that must appear verbatim in every report.
pub const REQUIRED_STATEMENT: &str = "This Stage-1 report evaluates consistency within \
vendor-supplied evidence. It does not establish intent, independently verify the \
production environment, or prove historical training events that cannot be \
reconstructed from the supplied artifacts.";
