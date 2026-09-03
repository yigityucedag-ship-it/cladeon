//! Error model.
//!
//! Errors carry a machine-readable kind so that a parse failure becomes a
//! `coverage_limitation` in the report rather than a crash or, worse, a silent
//! partial result presented as complete.

use std::fmt;

pub type ClResult<T> = Result<T, ClError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClError {
    /// A bounded parser hit a configured limit. Always a coverage limitation.
    LimitExceeded { limit: &'static str, value: u64, max: u64 },
    /// Input was not well-formed.
    Malformed { what: &'static str, at: usize, detail: String },
    /// Input was well-formed but ambiguous in a way that forbids a decision.
    Ambiguous { what: &'static str, detail: String },
    /// An authoritative document contained something that must never appear.
    ContractViolation { detail: String },
    /// Filesystem or IO problem, already classified.
    Io { detail: String },
    /// A signature or digest did not verify.
    Integrity { detail: String },
    /// Feature is deliberately not implemented in Stage 1.
    OutOfScope { detail: String },
}

impl ClError {
    pub fn malformed(what: &'static str, at: usize, detail: impl Into<String>) -> Self {
        ClError::Malformed { what, at, detail: detail.into() }
    }
    pub fn contract(detail: impl Into<String>) -> Self {
        ClError::ContractViolation { detail: detail.into() }
    }
    pub fn io(detail: impl Into<String>) -> Self {
        ClError::Io { detail: detail.into() }
    }
    pub fn integrity(detail: impl Into<String>) -> Self {
        ClError::Integrity { detail: detail.into() }
    }
    pub fn ambiguous(what: &'static str, detail: impl Into<String>) -> Self {
        ClError::Ambiguous { what, detail: detail.into() }
    }
    pub fn out_of_scope(detail: impl Into<String>) -> Self {
        ClError::OutOfScope { detail: detail.into() }
    }

    /// Stable machine-readable kind, safe to place in a report.
    pub fn kind(&self) -> &'static str {
        match self {
            ClError::LimitExceeded { .. } => "limit_exceeded",
            ClError::Malformed { .. } => "malformed",
            ClError::Ambiguous { .. } => "ambiguous",
            ClError::ContractViolation { .. } => "contract_violation",
            ClError::Io { .. } => "io",
            ClError::Integrity { .. } => "integrity",
            ClError::OutOfScope { .. } => "out_of_scope",
        }
    }

    /// True when this error should surface as a `coverage_limitation` rather than
    /// aborting the scan. A malformed vendor file is normal and must not stop work.
    pub fn is_coverage_limitation(&self) -> bool {
        matches!(
            self,
            ClError::LimitExceeded { .. }
                | ClError::Malformed { .. }
                | ClError::Ambiguous { .. }
                | ClError::Io { .. }
                | ClError::OutOfScope { .. }
        )
    }
}

impl fmt::Display for ClError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClError::LimitExceeded { limit, value, max } => {
                write!(f, "limit `{limit}` exceeded: {value} > {max}")
            }
            ClError::Malformed { what, at, detail } => {
                write!(f, "malformed {what} at byte {at}: {detail}")
            }
            ClError::Ambiguous { what, detail } => write!(f, "ambiguous {what}: {detail}"),
            ClError::ContractViolation { detail } => write!(f, "contract violation: {detail}"),
            ClError::Io { detail } => write!(f, "io: {detail}"),
            ClError::Integrity { detail } => write!(f, "integrity: {detail}"),
            ClError::OutOfScope { detail } => write!(f, "out of scope for Stage 1: {detail}"),
        }
    }
}

impl std::error::Error for ClError {}

impl From<std::io::Error> for ClError {
    fn from(e: std::io::Error) -> Self {
        ClError::Io { detail: format!("{:?}", e.kind()) }
    }
}
