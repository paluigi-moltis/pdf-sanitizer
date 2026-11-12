//! pdfsan-core — offline PDF prompt-injection detector & WYSIWYG sanitizer.
//!
//! Dual-path pipeline:
//! - **Path A** ([`path_a`]): raw structural extraction via `lopdf` — every
//!   text span with style + bbox, DocumentInfo, XMP, annotations, AcroForm,
//!   `/URI` & `/JavaScript` actions.
//! - **Path B** ([`path_b`]): visual extraction via `hayro` rasterization +
//!   `ocrs` OCR — only what a human actually sees.
//! - **Reconciliation** ([`pipeline`]): deterministic rule engine flagging
//!   raw text that is hidden, missing from the visual render, or carrying
//!   canary/exfiltration/prompt-override payloads.
//!
//! The engine is WASM-safe: no OS-specific APIs, all I/O behind explicit
//! parameters (bytes in, report out). OCR models are passed in loaded.

pub mod models;
pub mod path_a;
pub mod path_b;
pub mod pipeline;
pub mod report;
pub mod rules;
pub mod synth;

pub use pipeline::{SanitizeOptions, Sanitizer};
pub use report::Report;
