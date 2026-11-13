//! Dual-path reconciliation pipeline.
//!
//! Streams the document page by page: Path A (raw structure) and Path B
//! (rasterize + OCR) are computed for one page at a time, then reconciled by
//! the deterministic rule engine. Memory stays bounded by one page bitmap.

use anyhow::{anyhow, Context, Result};

use crate::path_a::{self, RawDocument, RawSpan};
use crate::path_b::{
    self, OcrModels, VisualPage, LOW_CONTRAST_DELTA, MIN_VISIBLE_FONT_PT, MISSING_TOKEN_COVERAGE,
};
use crate::report::{
    snippet_of, Category, DocumentSummary, Finding, Location, Report, Severity, Surface,
};
use crate::rules::{self, RuleHit};

/// Options for a sanitize run.
#[derive(Debug, Clone)]
pub struct SanitizeOptions {
    /// Rasterization DPI for the visual pass (150–200 recommended).
    pub dpi: f64,
    /// Keep rendered page bitmaps in the result (for the PWA overlay;
    /// disabled in the CLI to bound memory).
    pub keep_page_images: bool,
}

impl Default for SanitizeOptions {
    fn default() -> Self {
        Self {
            dpi: 150.0,
            keep_page_images: false,
        }
    }
}

/// Reusable sanitizer holding the OCR engine.
pub struct Sanitizer {
    engine: ocrs::OcrEngine,
    options: SanitizeOptions,
}

/// A rendered page bitmap retained for the caller (PWA overlay rendering).
#[derive(Debug, Clone)]
pub struct PageImage {
    /// 1-based page number.
    pub page_number: usize,
    pub width: u32,
    pub height: u32,
    /// RGBA, row-major, 4 bytes per pixel.
    pub rgba: Vec<u8>,
}

/// Full sanitize output: the audit report plus (optionally) the rendered
/// page bitmaps, so callers can draw bbox overlays (the report itself never
/// embeds images).
#[derive(Debug, Clone)]
pub struct SanitizeOutput {
    pub report: Report,
    pub page_images: Vec<PageImage>,
}

impl Sanitizer {
    pub fn new(models: OcrModels, options: SanitizeOptions) -> Result<Self> {
        let engine = path_b::build_engine(models)?;
        Ok(Self { engine, options })
    }

    /// Sanitize a document from raw bytes and produce the audit report.
    pub fn sanitize(&self, filename: &str, bytes: &[u8]) -> Result<Report> {
        self.sanitize_with_progress(filename, bytes, &mut |_, _| {})
            .map(|out| out.report)
    }

    /// Sanitize a document, invoking `progress(done_pages, total_pages)`
    /// after each processed page and returning the rendered page bitmaps
    /// when `keep_page_images` is enabled. Pages are streamed one at a time
    /// so memory stays bounded (important in WebAssembly).
    pub fn sanitize_with_progress(
        &self,
        filename: &str,
        bytes: &[u8],
        progress: &mut dyn FnMut(usize, usize),
    ) -> Result<SanitizeOutput> {
        let raw: RawDocument = path_a::extract_document(bytes)?;

        let page_count = raw.pages.len();
        if page_count == 0 {
            return Err(anyhow!("document has no pages"));
        }

        let hayro_pdf = hayro::hayro_syntax::Pdf::new(bytes.to_vec())
            .map_err(|e| anyhow!("hayro failed to open PDF: {e:?}"))
            .context("opening PDF for rasterization")?;

        let mut findings: Vec<Finding> = Vec::new();
        let mut visual_pages: Vec<VisualPage> = Vec::with_capacity(page_count);
        let mut page_images: Vec<PageImage> = Vec::new();

        for page_extract in &raw.pages {
            let page_number = page_extract.page_number;

            // ---- Path B ----
            let raster = path_b::rasterize_page(&hayro_pdf, page_number - 1, self.options.dpi)?;
            let lines = path_b::ocr_page(&self.engine, &raster)?;
            visual_pages.push(VisualPage {
                page_number,
                lines,
                rasterized: if self.options.keep_page_images {
                    Some(raster)
                } else {
                    None
                },
            });
            if self.options.keep_page_images {
                let last = visual_pages.last().expect("page just pushed");
                if let Some(r) = &last.rasterized {
                    page_images.push(PageImage {
                        page_number,
                        width: r.width,
                        height: r.height,
                        rgba: r.rgba.clone(),
                    });
                }
            }

            let ocr_text: String = visual_pages
                .last()
                .map(|p| {
                    p.lines
                        .iter()
                        .map(|l| l.text.clone())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();
            let ocr_tokens = rules::normalize_tokens(&ocr_text);

            // ---- Reconciliation: every raw span of this page ----
            for span in &page_extract.spans {
                let ocr_lines_px: Vec<[f64; 4]> = visual_pages
                    .last()
                    .map(|p| p.lines.iter().map(|l| l.bbox_px).collect())
                    .unwrap_or_default();
                self.judge_span(
                    span,
                    &ocr_tokens,
                    &ocr_lines_px,
                    page_extract.media_box,
                    page_number,
                    &mut findings,
                );
            }

            progress(page_number, page_count);
        }

        // ---- Non-body surfaces ----
        self.judge_metadata(&raw, &mut findings);

        // ---- Output markdown: exclusively Path B ----
        let markdown = path_b::build_markdown(&visual_pages);

        let hidden_removed = findings
            .iter()
            .filter(|f| f.category == Category::InvisibleTextInjection)
            .count();
        let meta_stripped = findings
            .iter()
            .filter(|f| {
                matches!(
                    f.category,
                    Category::MetadataInjection
                        | Category::CanaryOrExfiltrationLink
                        | Category::JavascriptAction
                        | Category::FormFieldInjection
                        | Category::SuspiciousUnicode
                        | Category::MarkdownImageExfiltration
                        | Category::PromptOverridePhrase
                )
            })
            .count();

        // Stable ordering and ids.
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(a.location.page.cmp(&b.location.page))
                .then(a.category.debug_ord().cmp(&b.category.debug_ord()))
                .then(a.reason.cmp(&b.reason))
        });
        for (i, f) in findings.iter_mut().enumerate() {
            f.id = format!("F-{:03}", i + 1);
        }

        let risk_level = Report::risk_level(&findings).to_string();

        Ok(SanitizeOutput {
            report: Report {
                document: DocumentSummary {
                    filename: filename.to_string(),
                    page_count,
                    risk_level,
                    summary: crate::report::Summary {
                        total_findings: findings.len(),
                        hidden_text_removed: hidden_removed,
                        metadata_or_links_stripped: meta_stripped,
                    },
                },
                findings,
                sanitized_markdown: markdown,
            },
            page_images,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn judge_span(
        &self,
        span: &RawSpan,
        ocr_tokens: &[String],
        ocr_lines_px: &[[f64; 4]],
        media_box: [f64; 4],
        page_number: usize,
        findings: &mut Vec<Finding>,
    ) {
        // Style-based stealth reasons.
        let mut reasons: Vec<String> = Vec::new();
        if span.font_size > 0.0 && span.font_size < MIN_VISIBLE_FONT_PT {
            reasons.push(format!(
                "font size {:.2}pt < {}pt",
                span.font_size, MIN_VISIBLE_FONT_PT
            ));
        }
        if span.render_mode == 3 {
            reasons.push("text render mode 3 (invisible)".to_string());
        }
        if span.off_page {
            reasons.push("off-canvas coordinates (outside MediaBox)".to_string());
        }
        if contrast(span.fill_color, span.bg_color) < LOW_CONTRAST_DELTA {
            reasons.push(format!(
                "zero visual contrast (fill {:?} on background {:?})",
                span.fill_color, span.bg_color
            ));
        }
        let style_hidden = !reasons.is_empty();

        // Rule-engine signatures in the raw text.
        let hits = rules::scan_surface(&span.text);
        let signature_hit = hits.iter().find(|h| {
            h.category == Category::CanaryOrExfiltrationLink
                || h.category == Category::PromptOverridePhrase
                || h.category == Category::MarkdownImageExfiltration
        });

        // Visual reconciliation: the span counts as *visible* only if its
        // tokens were OCR-recognized AND recognized text sits inside the
        // span's own bbox (page-level token matches alone can come from the
        // same string printed elsewhere). This conjunction keeps style
        // heuristics (tiny fonts in Type3 glyph tricks, contrast tracking
        // artifacts) from firing on text a human plainly sees.
        let coverage = rules::token_coverage(&span.text, ocr_tokens);
        let tokens_present = coverage >= MISSING_TOKEN_COVERAGE;
        let bbox_has_visible_text =
            span_bbox_intersects_ocr(span, media_box, self.options.dpi, ocr_lines_px);
        // Off-canvas spans can never be visible.
        let visually_present = !span.off_page && tokens_present && bbox_has_visible_text;
        let missing_from_visual = !visually_present;

        // Content gate: single glyphs, control-character runs and bare
        // numbers placed off-canvas (stray text objects from embedded
        // figures) cannot carry an injection payload; don't report them.
        // A real payload always contains at least one alphabetic word, and
        // never contains control characters (those indicate a UTF-16 string
        // misdecoded as Latin-1 — a producer artifact, not an attack).
        let tokens = rules::normalize_tokens(&span.text);
        let has_payload_content = tokens.len() >= 2
            && tokens
                .iter()
                .any(|t| t.len() >= 3 && t.chars().any(|c| c.is_alphabetic()))
            && !span.text.chars().any(|c| c.is_control());

        if (style_hidden || signature_hit.is_some()) && missing_from_visual && has_payload_content {
            let mut all_reasons = reasons;
            if missing_from_visual {
                all_reasons.push(
                    "present in raw PDF stream but absent from the visual (OCR) render".to_string(),
                );
            }
            let severity = if signature_hit.is_some() {
                Severity::Critical
            } else {
                Severity::High
            };
            findings.push(Finding {
                id: String::new(),
                severity,
                category: Category::InvisibleTextInjection,
                reason: all_reasons.join("; "),
                action_taken: "removed".to_string(),
                location: Location {
                    page: page_number,
                    surface: Surface::PageBody,
                    bbox_norm: Some(span.bbox_norm),
                    object_ref: Some(span.object_ref.clone()),
                },
                quarantined_snippet: Some(snippet_of(&span.text, 200)),
            });
        } else if !tokens_present && is_latin_prose(&span.text) {
            // Present in the raw stream, styled normally, but OCR could not
            // reproduce it. Usually an OCR artifact on equations/symbols;
            // surfaced at low severity so pipelines can filter it out
            // without losing true positives. Only spans that look like
            // real Latin prose (>= 3 tokens) are reported — single symbols
            // and math glyphs are inherently unOCRable noise.
            findings.push(Finding {
                id: String::new(),
                severity: Severity::Low,
                category: Category::VisualMismatch,
                reason: format!(
                    "raw text not reproduced by visual OCR pass (token coverage {:.0}%)",
                    coverage * 100.0
                ),
                action_taken: "flagged".to_string(),
                location: Location {
                    page: page_number,
                    surface: Surface::PageBody,
                    bbox_norm: Some(span.bbox_norm),
                    object_ref: Some(span.object_ref.clone()),
                },
                quarantined_snippet: Some(snippet_of(&span.text, 200)),
            });
        }

        // Spans confirmed visible are still scanned for signatures (they
        // reach the Markdown output, so consumers must be warned).
        if visually_present {
            for hit in hits {
                findings.push(hit_to_finding(
                    hit,
                    Location {
                        page: page_number,
                        surface: Surface::PageBody,
                        bbox_norm: Some(span.bbox_norm),
                        object_ref: Some(span.object_ref.clone()),
                    },
                    "flagged",
                ));
            }
        }

        // Invisible Unicode inside body text.
        push_unicode_findings(
            &span.text,
            Location {
                page: page_number,
                surface: Surface::PageBody,
                bbox_norm: Some(span.bbox_norm),
                object_ref: Some(span.object_ref.clone()),
            },
            findings,
        );
    }

    fn judge_metadata(&self, raw: &RawDocument, findings: &mut Vec<Finding>) {
        // DocumentInfo
        for (key, value) in &raw.doc_info {
            let loc = Location {
                page: 0,
                surface: Surface::DocumentInfo,
                bbox_norm: None,
                object_ref: Some(key.clone()),
            };
            for hit in rules::scan_surface(value) {
                let category = match hit.category {
                    Category::CanaryOrExfiltrationLink
                    | Category::MarkdownImageExfiltration
                    | Category::PromptOverridePhrase
                    | Category::SuspiciousUnicode => Category::MetadataInjection,
                    other => other,
                };
                findings.push(hit_to_finding(
                    RuleHit { category, ..hit },
                    loc.clone(),
                    "stripped",
                ));
            }
            push_unicode_findings(value, loc, findings);
        }

        // XMP
        if let Some(xmp) = &raw.xmp {
            let loc = Location {
                page: 0,
                surface: Surface::XmpMetadata,
                bbox_norm: None,
                object_ref: None,
            };
            for hit in rules::scan_surface(xmp) {
                let category = match hit.category {
                    Category::CanaryOrExfiltrationLink
                    | Category::MarkdownImageExfiltration
                    | Category::PromptOverridePhrase => Category::MetadataInjection,
                    other => other,
                };
                findings.push(hit_to_finding(
                    RuleHit { category, ..hit },
                    loc.clone(),
                    "stripped",
                ));
            }
            push_unicode_findings(xmp, loc, findings);
        }

        // URI actions (annotations + open actions)
        for (i, uri) in raw.uri_actions.iter().enumerate() {
            for hit in rules::scan_surface(uri) {
                let loc = Location {
                    page: 0,
                    surface: Surface::Annotation,
                    bbox_norm: None,
                    object_ref: Some(format!("uri[{i}]")),
                };
                findings.push(hit_to_finding(hit, loc, "stripped"));
            }
            push_unicode_findings(
                uri,
                Location {
                    page: 0,
                    surface: Surface::Annotation,
                    bbox_norm: None,
                    object_ref: Some(format!("uri[{i}]")),
                },
                findings,
            );
        }

        // JavaScript actions
        for (i, js) in raw.js_actions.iter().enumerate() {
            let loc = Location {
                page: 0,
                surface: Surface::OpenAction,
                bbox_norm: None,
                object_ref: raw
                    .open_action_ref
                    .clone()
                    .or_else(|| Some(format!("js[{i}]"))),
            };
            findings.push(Finding {
                id: String::new(),
                severity: Severity::High,
                category: Category::JavascriptAction,
                reason: "PDF contains a /JavaScript action".to_string(),
                action_taken: "stripped".to_string(),
                location: loc.clone(),
                quarantined_snippet: Some(snippet_of(js, 200)),
            });
            for hit in rules::scan_surface(js) {
                findings.push(hit_to_finding(hit, loc.clone(), "stripped"));
            }
        }

        // AcroForm fields
        for (name, value) in &raw.form_fields {
            let loc = Location {
                page: 0,
                surface: Surface::AcroForm,
                bbox_norm: None,
                object_ref: Some(name.clone()),
            };
            let scanned = format!("{name} {value}");
            let hits = rules::scan_surface(&scanned);
            if !hits.is_empty() {
                for hit in hits {
                    let category = match hit.category {
                        Category::CanaryOrExfiltrationLink
                        | Category::MarkdownImageExfiltration
                        | Category::PromptOverridePhrase => Category::FormFieldInjection,
                        other => other,
                    };
                    findings.push(hit_to_finding(
                        RuleHit { category, ..hit },
                        loc.clone(),
                        "stripped",
                    ));
                }
            }
            push_unicode_findings(&scanned, loc, findings);
        }

        // Annotation rectangles with canary URIs get a page-anchored finding
        // so the PWA can draw overlay boxes on the right page.
        for page in &raw.pages {
            for annot in &page.annots {
                if let Some(uri) = &annot.uri {
                    if rules::scan_surface(uri)
                        .iter()
                        .any(|h| h.category == Category::CanaryOrExfiltrationLink)
                    {
                        findings.push(Finding {
                            id: String::new(),
                            severity: Severity::Critical,
                            category: Category::CanaryOrExfiltrationLink,
                            reason: "link annotation points to a canary/exfiltration domain"
                                .to_string(),
                            action_taken: "stripped".to_string(),
                            location: Location {
                                page: annot.page,
                                surface: Surface::Annotation,
                                bbox_norm: annot.rect_norm,
                                object_ref: Some(annot.object_ref.clone()),
                            },
                            quarantined_snippet: Some(snippet_of(uri, 200)),
                        });
                    }
                }
            }
        }
    }
}

fn hit_to_finding(hit: RuleHit, location: Location, action: &str) -> Finding {
    Finding {
        id: String::new(),
        severity: hit.severity,
        category: hit.category,
        reason: hit.reason,
        action_taken: action.to_string(),
        location,
        quarantined_snippet: Some(hit.snippet),
    }
}

fn push_unicode_findings(text: &str, location: Location, findings: &mut Vec<Finding>) {
    let invisible = rules::find_invisible_unicode(text);
    if invisible.is_empty() {
        return;
    }
    let mut classes: Vec<&str> = invisible
        .iter()
        .map(|(_, c)| rules::invisible_unicode_class(*c))
        .collect();
    classes.sort_unstable();
    classes.dedup();
    // A lone byte-order mark is a common producer artifact (e.g. pdfTeX
    // metadata) — keep it at low severity. Anything else stays medium.
    let only_bom = invisible.iter().all(|(_, c)| *c == '\u{FEFF}');
    findings.push(Finding {
        id: String::new(),
        severity: if only_bom {
            Severity::Low
        } else {
            Severity::Medium
        },
        category: Category::SuspiciousUnicode,
        reason: format!(
            "invisible Unicode present: {} ({} occurrence(s)); stripped from output",
            classes.join(", "),
            invisible.len()
        ),
        action_taken: "stripped".to_string(),
        location,
        quarantined_snippet: Some(snippet_of(
            &format!(
                "{:?}",
                invisible.iter().map(|(_, c)| *c).collect::<Vec<char>>()
            ),
            120,
        )),
    });
}

fn luminance(rgb: [f64; 3]) -> f64 {
    0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2]
}

/// True when OCR-recognized text (pixel-space line boxes) intersects the
/// span's own bounding box — i.e. a human sees text right there.
fn span_bbox_intersects_ocr(
    span: &RawSpan,
    media_box: [f64; 4],
    dpi: f64,
    ocr_lines_px: &[[f64; 4]],
) -> bool {
    if ocr_lines_px.is_empty() {
        return false;
    }
    let s = dpi / 72.0;
    let pad = (span.font_size * s).max(4.0) * 1.5;
    let sx0 = (span.bbox_pt[0] - media_box[0]) * s - pad;
    let sx1 = (span.bbox_pt[2] - media_box[0]) * s + pad;
    let sy0 = (media_box[3] - span.bbox_pt[3]) * s - pad;
    let sy1 = (media_box[3] - span.bbox_pt[1]) * s + pad;
    ocr_lines_px
        .iter()
        .any(|l| sx0 <= l[2] && l[0] <= sx1 && sy0 <= l[3] && l[1] <= sy1)
}

/// Heuristic "is this ordinary Latin prose worth reporting as an OCR
/// mismatch" — filters math glyph runs and single symbols, which the Latin
/// OCR models cannot read by design.
fn is_latin_prose(text: &str) -> bool {
    let tokens = rules::normalize_tokens(text);
    if tokens.len() < 3 {
        return false;
    }
    if !tokens.iter().any(|t| t.len() >= 3) {
        return false;
    }
    let total = text.chars().count();
    if total == 0 {
        return false;
    }
    let ascii = text
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric() || c.is_ascii_whitespace() || c.is_ascii_punctuation()
        })
        .count();
    (ascii as f64 / total as f64) >= 0.5
}

fn contrast(a: [f64; 3], b: [f64; 3]) -> f64 {
    (luminance(a) - luminance(b)).abs()
}

impl Category {
    fn debug_ord(self) -> u32 {
        match self {
            Category::InvisibleTextInjection => 0,
            Category::CanaryOrExfiltrationLink => 1,
            Category::MarkdownImageExfiltration => 2,
            Category::PromptOverridePhrase => 3,
            Category::MetadataInjection => 4,
            Category::JavascriptAction => 5,
            Category::FormFieldInjection => 6,
            Category::SuspiciousUnicode => 7,
            Category::VisualMismatch => 8,
        }
    }
}
