//! # cl-rules
//!
//! Deterministic evidence rules and the scoring engine.
//!
//! The crate is deliberately split in three:
//!
//! * [`families`] reads facts and emits outcomes. It never scores.
//! * [`engine`] scores, caps, abstains and gates. It never reads a fact.
//! * [`model`] is the vocabulary the two exchange.
//!
//! Keeping evidence and judgement apart is what lets each be argued about on its
//! own: a rule can be wrong about what a file means without the scoring being
//! wrong, and the scoring can be recalibrated without touching a single rule.

#![forbid(unsafe_code)]

pub mod engine;
pub mod families;
pub mod model;

pub use engine::{judge, Emissions};
pub use model::{AnchorScore, CapApplied, ClaimScore, Conclusion, RuleOutcome, RuleReport};

use cl_facts::FactSet;

/// Run every rule family over a fact set and judge the result.
pub fn evaluate(facts: &FactSet) -> RuleReport {
    judge(families::run_all(facts))
}
