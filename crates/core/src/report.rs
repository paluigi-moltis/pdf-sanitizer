//! Audit-report data model (see README for the JSON schema).

use serde::{Deserialize, Serialize};

/// Severity of a single finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Finding category (machine-readable, snake_case).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Text present in the raw PDF stream but not in the visual render.
    InvisibleTextInjection,
    /// Invisible/bidi-override/Unicode-tag characters.
    SuspiciousUnicode,
    /// Known canary-token / webhook / exfiltration endpoint domains.
    CanaryOrExfiltrationLink,
    /// `![...](https://...)` markdown-image exfiltration payloads.
    MarkdownImageExfiltration,
    /// Prompt-override phrases aimed at LLM consumers of the document.
    PromptOverridePhrase,
    /// Injections in DocumentInfo / XMP metadata surfaces.
    MetadataInjection,
    /// `/JavaScript` actions (open actions, annotations, form fields).
    JavascriptAction,
    /// Injections in AcroForm field names/values.
    FormFieldInjection,
    /// Raw-stream text that OCR of the visual render failed to reproduce
    /// (false-positive-controlled, low severity).
    VisualMismatch,
}

/// Non-body surface where a finding was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    PageBody,
    DocumentInfo,
    XmpMetadata,
    Annotation,
    AcroForm,
    OpenAction,
}

impl Surface {
    pub fn as_str(self) -> &'static str {
        match self {
            Surface::PageBody => "page_body",
            Surface::DocumentInfo => "document_info",
            Surface::XmpMetadata => "xmp_metadata",
            Surface::Annotation => "annotation",
            Surface::AcroForm => "acroform",
            Surface::OpenAction => "open_action",
        }
    }
}

/// Where in the document a finding lives. `page` is 1-based; `0` means
/// document-level (metadata, open actions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub page: usize,
    pub surface: Surface,
    /// Normalized bounding box `[x0, y0, x1, y1]` in `0.0..=1.0` page
    /// coordinates, origin top-left, y downwards. Absent for non-body
    /// surfaces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bbox_norm: Option<[f64; 4]>,
    /// Reference to the raw PDF object the finding came from (e.g.
    /// `"obj 12 0"`), when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable finding id, e.g. `F-001`.
    pub id: String,
    pub severity: Severity,
    pub category: Category,
    /// Human-readable explanation of why this was flagged.
    pub reason: String,
    /// What the sanitizer did: `removed`, `stripped` or `flagged`.
    pub action_taken: String,
    pub location: Location,
    /// Short evidence snippet (quarantined, never copied to the output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantined_snippet: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub total_findings: usize,
    pub hidden_text_removed: usize,
    pub metadata_or_links_stripped: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSummary {
    pub filename: String,
    pub page_count: usize,
    /// `none` | `low` | `medium` | `high`.
    pub risk_level: String,
    pub summary: Summary,
}

/// Full audit report. Every run of the sanitizer produces one of these
/// alongside the sanitized Markdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub document: DocumentSummary,
    pub findings: Vec<Finding>,
    /// The sanitized Markdown, reconstructed exclusively from the visual
    /// (OCR) pass. Also embedded here so `.report.json` is self-contained.
    pub sanitized_markdown: String,
}

impl Report {
    /// Compute overall risk level from finding severities.
    pub fn risk_level(findings: &[Finding]) -> &'static str {
        let mut max = None;
        for f in findings {
            max = match max {
                None => Some(f.severity),
                Some(m) if f.severity > m => Some(f.severity),
                Some(m) => Some(m),
            };
        }
        match max {
            Some(Severity::Critical) | Some(Severity::High) => "high",
            Some(Severity::Medium) => "medium",
            Some(Severity::Low) => "low",
            None => "none",
        }
    }
}

pub(crate) fn snippet_of(text: &str, max_len: usize) -> String {
    let t = text.trim();
    if t.chars().count() <= max_len {
        t.to_string()
    } else {
        let prefix: String = t.chars().take(max_len).collect();
        format!("{}...", prefix)
    }
}
