//! # cl-report
//!
//! Assembly and rendering of the Stage-1 report.
//!
//! `report.json` is authoritative; the PDF is a rendering of it. Keeping that
//! ordering explicit matters, because a buyer who was sent a screenshot or a
//! re-exported PDF has been sent something non-authoritative, and the verifier says
//! so rather than guessing.

#![forbid(unsafe_code)]

pub mod document;
pub mod pdf;
pub mod render;

pub use document::{build, HostInfo, Report, ReportInput, ScopeInfo};
pub use pdf::{extract_footer_raster, extract_text, PdfBuilder};
pub use render::render;
