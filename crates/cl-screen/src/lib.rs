//! # cl-screen
//!
//! The vendor-side scanning pipeline, as a library.
//!
//! It lives here rather than inside a `main.rs` because two front ends need
//! identical behaviour: the command line, and the desktop window a non-technical
//! vendor actually uses. Keeping the pipeline in one place means the window and the
//! terminal cannot drift in what they put into an evidence bundle.

#![forbid(unsafe_code)]

pub mod scan;
pub mod seal;

#[cfg(test)]
mod corpus;

pub use scan::{Phase, Progress, ScanRequest, ScanResult};
pub use seal::{scan_and_seal, SealedBundle};
