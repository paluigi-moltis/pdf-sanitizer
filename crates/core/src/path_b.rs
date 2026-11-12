//! Path B — visual WYSIWYG extraction.
//!
//! Rasterizes each page with the pure-Rust `hayro` renderer at 150–200 DPI
//! and runs the pure-Rust `ocrs` ML OCR on the bitmap. Only text that is
//! *actually visible to a human* survives this path; it is the sole source
//! of the sanitized Markdown.

use anyhow::{anyhow, Context, Result};

use hayro::hayro_interpret::InterpreterSettings;
use hayro::hayro_syntax::Pdf;
use hayro::vello_cpu::color::palette::css::WHITE;
use hayro::{PixmapSettings, RenderCache, RenderSettings, render};

use ocrs::{ImageSource, OcrEngine, OcrEngineParams, TextItem, TextLine};
use rten::Model;

use crate::rules::sanitize_unicode;

/// Minimum font size (pt) considered "visible" by the rule engine.
pub const MIN_VISIBLE_FONT_PT: f64 = 2.0;
/// Luminance distance below which text is treated as zero-contrast.
pub const LOW_CONTRAST_DELTA: f64 = 0.08;
/// Token-coverage below which a raw span counts as missing from the render.
pub const MISSING_TOKEN_COVERAGE: f64 = 0.5;

/// Loaded OCR models (rten format; ONNX also accepted by `rten`).
pub struct OcrModels {
    pub detection_model: Model,
    pub recognition_model: Model,
}

impl OcrModels {
    pub fn new(detection_model: Model, recognition_model: Model) -> Self {
        Self {
            detection_model,
            recognition_model,
        }
    }
}

/// Build the OCR engine from loaded models.
pub fn build_engine(models: OcrModels) -> Result<OcrEngine> {
    OcrEngine::new(OcrEngineParams {
        detection_model: Some(models.detection_model),
        recognition_model: Some(models.recognition_model),
        ..Default::default()
    })
    .map_err(|e| anyhow!("failed to init OCR engine: {e}"))
}

/// A rendered page bitmap.
#[derive(Debug, Clone)]
pub struct RasterizedPage {
    pub width: u32,
    pub height: u32,
    /// RGBA, row-major, 4 bytes per pixel.
    pub rgba: Vec<u8>,
}

/// One OCR-recognized line of visible text.
#[derive(Debug, Clone)]
pub struct OcrLine {
    pub text: String,
    /// Bounding box in bitmap pixels `[x0, y0, x1, y1]`.
    pub bbox_px: [f64; 4],
    /// Median character height in pixels (used for heading heuristics).
    pub height_px: f64,
}

/// Per-page visual extraction result.
#[derive(Debug, Clone)]
pub struct VisualPage {
    pub page_number: usize,
    pub lines: Vec<OcrLine>,
    pub rasterized: Option<RasterizedPage>,
}

/// Rasterize one page of an open `Pdf` at the given DPI.
pub fn rasterize_page(pdf: &Pdf, page_index: usize, dpi: f64) -> Result<RasterizedPage> {
    let scale = (dpi / 72.0) as f32;
    let cache = RenderCache::new();
    let settings = InterpreterSettings::default();
    let page = pdf
        .pages()
        .get(page_index)
        .ok_or_else(|| anyhow!("page index {page_index} out of range"))?;
    let pixmap = render(
        page,
        &cache,
        &settings,
        &RenderSettings::default(),
        &PixmapSettings {
            x_scale: scale,
            y_scale: scale,
            bg_color: WHITE,
        },
    );
    let width = pixmap.width() as u32;
    let height = pixmap.height() as u32;
    // vello_cpu pixmaps are premultiplied RGBA; on an opaque background the
    // premultiplied components are what we want for OCR.
    let mut rgba = Vec::with_capacity((width as usize) * (height as usize) * 4);
    for px in pixmap.data() {
        rgba.extend_from_slice(&[px.r, px.g, px.b, px.a]);
    }
    Ok(RasterizedPage {
        width,
        height,
        rgba,
    })
}

/// Run OCR over a rendered page bitmap.
pub fn ocr_page(engine: &OcrEngine, raster: &RasterizedPage) -> Result<Vec<OcrLine>> {
    let rgb = rgba_to_rgb(&raster.rgba);
    let source = ImageSource::from_bytes(&rgb, (raster.width, raster.height))
        .map_err(|e| anyhow!("image source: {e}"))?;
    let input = engine
        .prepare_input(source)
        .map_err(|e| anyhow!("ocr prepare: {e}"))?;
    let word_rects = engine
        .detect_words(&input)
        .map_err(|e| anyhow!("ocr detect: {e}"))?;
    let line_rects = engine.find_text_lines(&input, &word_rects);
    let line_texts: Vec<Option<TextLine>> = engine
        .recognize_text(&input, &line_rects)
        .map_err(|e| anyhow!("ocr recognize: {e}"))?;

    let mut lines = Vec::new();
    for line in line_texts.iter().flatten() {
        let text = line.to_string();
        let trimmed = text.trim();
        if trimmed.chars().count() <= 1 {
            continue; // spurious detection, as in the ocrs examples
        }
        let rect = line.bounding_rect();
        let height = rect.height() as f64;
        lines.push(OcrLine {
            text: trimmed.to_string(),
            bbox_px: [
                rect.left() as f64,
                rect.top() as f64,
                rect.right() as f64,
                rect.bottom() as f64,
            ],
            height_px: height,
        });
    }
    Ok(lines)
}

fn rgba_to_rgb(rgba: &[u8]) -> Vec<u8> {
    let mut rgb = Vec::with_capacity(rgba.len() / 4 * 3);
    for px in rgba.chunks_exact(4) {
        // vello_cpu pixmaps are premultiplied RGBA; on an opaque white
        // background un-premultiplying is a no-op for our purposes.
        rgb.extend_from_slice(&px[..3]);
    }
    rgb
}

/// Reconstruct clean Markdown exclusively from the OCR lines of every page.
pub fn build_markdown(pages: &[VisualPage]) -> String {
    let mut doc_parts: Vec<String> = Vec::new();

    for page in pages {
        if page.lines.is_empty() {
            continue;
        }
        let heights: Vec<f64> = page.lines.iter().map(|l| l.height_px).collect();
        let median = median_of(&heights).max(1.0);

        let mut md = String::new();
        let mut prev_bottom: Option<f64> = None;
        for line in &page.lines {
            let gap_break = match prev_bottom {
                Some(pb) => (line.bbox_px[1] - pb) > 1.8 * line.height_px.max(1.0),
                None => false,
            };
            if gap_break {
                md.push_str("\n\n");
            } else if !md.is_empty() {
                md.push('\n');
            }
            let text = sanitize_unicode(&line.text);
            let h = line.height_px;
            let prefix = if h > 2.2 * median {
                "# "
            } else if h > 1.5 * median {
                "## "
            } else {
                ""
            };
            md.push_str(prefix);
            md.push_str(&text);
            prev_bottom = Some(line.bbox_px[3]);
        }
        doc_parts.push(md);
    }

    sanitize_unicode(&doc_parts.join("\n\n---\n\n"))
}

fn median_of(values: &[f64]) -> f64 {
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if v.is_empty() {
        0.0
    } else {
        v[v.len() / 2]
    }
}

/// Convenience: load a model file (`.rten` or `.onnx`) from disk.
pub fn load_model(path: &std::path::Path) -> Result<Model> {
    Model::load_file(path).with_context(|| format!("loading model {}", path.display()))
}
