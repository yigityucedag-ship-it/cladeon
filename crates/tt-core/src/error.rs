//! Error model.
//!
//! Errors carry a machine-readable kind so that a parse failure becomes a
//! `coverage_limitation` in the report rather than a crash or, worse, a silent
//! partial result presented as complete.

use std::fmt;

pub type TtResult<T> = Result<T, TtError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TtError {
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

impl TtError {
    pub fn malformed(what: &'static str, at: usize, detail: impl Into<String>) -> Self {
        TtError::Malformed { what, at, detail: detail.into() }
    }
    pub fn contract(detail: impl Into<String>) -> Self {
        TtError::ContractViolation { detail: detail.into() }
    }
    pub fn io(detail: impl Into<String>) -> Self {
        TtError::Io { detail: detail.into() }
    }
    pub fn integrity(detail: impl Into<String>) -> Self {
        TtError::Integrity { detail: detail.into() }
    }
    pub fn ambiguous(what: &'static str, detail: impl Into<String>) -> Self {
        TtError::Ambiguous { what, detail: detail.into() }
    }
    pub fn out_of_scope(detail: impl Into<String>) -> Self {
        TtError::OutOfScope { detail: detail.into() }
    }

    /// Stable machine-readable kind, safe to place in a report.
    pub fn kind(&self) -> &'static str {
        match self {
            TtError::LimitExceeded { .. } => "limit_exceeded",
            TtError::Malformed { .. } => "malformed",
            TtError::Ambiguous { .. } => "ambiguous",
            TtError::ContractViolation { .. } => "contract_violation",
            TtError::Io { .. } => "io",
            TtError::Integrity { .. } => "integrity",
            TtError::OutOfScope { .. } => "out_of_scope",
        }
    }

    /// True when this error should surface as a `coverage_limitation` rather than
    /// aborting the scan. A malformed vendor file is normal and must not stop work.
    pub fn is_coverage_limitation(&self) -> bool {
        matches!(
            self,
            TtError::LimitExceeded { .. }
                | TtError::Malformed { .. }
                | TtError::Ambiguous { .. }
                | TtError::Io { .. }
                | TtError::OutOfScope { .. }
        )
    }
}

impl fmt::Display for TtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TtError::LimitExceeded { limit, value, max } => {
                write!(f, "limit `{limit}` exceeded: {value} > {max}")
            }
            TtError::Malformed { what, at, detail } => {
                write!(f, "malformed {what} at byte {at}: {detail}")
            }
            TtError::Ambiguous { what, detail } => write!(f, "ambiguous {what}: {detail}"),
            TtError::ContractViolation { detail } => write!(f, "contract violation: {detail}"),
            TtError::Io { detail } => write!(f, "io: {detail}"),
            TtError::Integrity { detail } => write!(f, "integrity: {detail}"),
            TtError::OutOfScope { detail } => write!(f, "out of scope for Stage 1: {detail}"),
        }
    }
}

impl std::error::Error for TtError {}

impl From<std::io::Error> for TtError {
    fn from(e: std::io::Error) -> Self {
        TtError::Io { detail: format!("{:?}", e.kind()) }
    }
}
