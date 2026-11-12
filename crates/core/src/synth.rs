//! Minimal synthetic PDF generator.
//!
//! Produces small, hand-built PDF 1.7 documents used by the integration test
//! suite (`tests/fixtures`) and by examples. It deliberately writes raw PDF
//! syntax so that fixtures can embed *hostile* constructs — white-on-white
//! text, 0.5pt fonts, render mode 3, off-canvas text, canary `/URI`
//! annotations, XMP prompt injections and `/JavaScript` open actions — that
//! higher-level PDF writers would refuse or normalize away.

use std::collections::BTreeMap;

/// Standard Type1 font usable in synthetic documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Font {
    Helvetica,
    HelveticaBold,
}

impl Font {
    fn resource_name(self) -> &'static str {
        match self {
            Font::Helvetica => "/F1",
            Font::HelveticaBold => "/F2",
        }
    }

    fn base_font(self) -> &'static str {
        match self {
            Font::Helvetica => "Helvetica",
            Font::HelveticaBold => "Helvetica-Bold",
        }
    }
}

/// One text-showing operation on a page.
#[derive(Debug, Clone)]
pub struct TextSpec {
    /// X position in PDF points (origin bottom-left).
    pub x: f64,
    /// Y position in PDF points.
    pub y: f64,
    /// Font size in points (`Tf` operand).
    pub size: f64,
    /// Fill colour, each component in 0.0..=1.0 (RGB).
    pub fill: (f64, f64, f64),
    /// Text render mode (`Tr`). 3 = invisible.
    pub render_mode: i32,
    /// Raw literal string bytes (already PDF-escaped by the caller helpers).
    pub(crate) escaped_text: String,
    pub(crate) font: Font,
}

/// A builder for one text item.
#[derive(Debug, Clone)]
pub struct TextBuilder {
    spec: TextSpec,
}

impl TextBuilder {
    /// Black visible text.
    pub fn new(x: f64, y: f64, size: f64, text: &str) -> Self {
        Self::with_fill(x, y, size, text, (0.0, 0.0, 0.0))
    }

    pub fn with_fill(x: f64, y: f64, size: f64, text: &str, fill: (f64, f64, f64)) -> Self {
        Self::with_options(x, y, size, text, fill, 0)
    }

    pub fn with_options(
        x: f64,
        y: f64,
        size: f64,
        text: &str,
        fill: (f64, f64, f64),
        render_mode: i32,
    ) -> Self {
        TextBuilder {
            spec: TextSpec {
                x,
                y,
                fill,
                render_mode,
                escaped_text: escape_pdf_string(&encode_win_ansi(text)),
                font: Font::Helvetica,
                size,
            },
        }
    }

    /// Override the raw string bytes (already escaped). Use for byte payloads
    /// that are not representable in WinAnsi.
    pub fn raw_escaped_bytes(mut self, escaped: impl Into<String>) -> Self {
        self.spec.escaped_text = escaped.into();
        self
    }

    pub fn bold(mut self) -> Self {
        self.spec.font = Font::HelveticaBold;
        self
    }

    pub fn build(self) -> TextSpec {
        self.spec
    }
}

/// A link annotation with a `/URI` action.
#[derive(Debug, Clone)]
pub struct UriAnnot {
    pub rect: [f64; 4],
    /// URI as raw bytes (may contain hostile Unicode).
    pub uri: String,
}

/// A raw content-stream fragment injected verbatim (e.g. a background
/// rectangle: `"0 0 0 rg 0 0 612 792 re f"`).
#[derive(Debug, Clone)]
pub struct RawOp {
    pub ops: String,
}

/// One synthetic page.
#[derive(Debug, Clone, Default)]
pub struct SynthPage {
    pub width: f64,
    pub height: f64,
    pub items: Vec<SynthItem>,
    pub uri_annots: Vec<UriAnnot>,
}

#[derive(Debug, Clone)]
pub enum SynthItem {
    Text(TextSpec),
    Raw(RawOp),
}

impl SynthPage {
    /// US Letter page.
    pub fn letter() -> Self {
        SynthPage {
            width: 612.0,
            height: 792.0,
            ..Default::default()
        }
    }

    pub fn push_text(&mut self, spec: TextSpec) -> &mut Self {
        self.items.push(SynthItem::Text(spec));
        self
    }

    pub fn push_raw(&mut self, ops: impl Into<String>) -> &mut Self {
        self.items.push(SynthItem::Raw(RawOp { ops: ops.into() }));
        self
    }

    pub fn push_uri_annot(&mut self, rect: [f64; 4], uri: impl Into<String>) -> &mut Self {
        self.uri_annots.push(UriAnnot {
            rect,
            uri: uri.into(),
        });
        self
    }
}

/// Whole synthetic document.
#[derive(Debug, Clone, Default)]
pub struct SynthDoc {
    pub pages: Vec<SynthPage>,
    /// DocumentInfo entries (raw string bytes; may contain hostile Unicode).
    pub info_entries: BTreeMap<String, String>,
    /// Optional XMP metadata stream payload (verbatim XML text).
    pub xmp: Option<String>,
    /// Optional `/OpenAction` with a `/JavaScript` action (raw bytes).
    pub open_action_js: Option<String>,
    /// Optional AcroForm text field: (field name, field value).
    pub form_field: Option<(String, String)>,
}

impl SynthDoc {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn page(mut self, page: SynthPage) -> Self {
        self.pages.push(page);
        self
    }

    pub fn info(mut self, key: &str, raw_value: &str) -> Self {
        self.info_entries
            .insert(key.to_string(), raw_value.to_string());
        self
    }

    pub fn xmp(mut self, xml: &str) -> Self {
        self.xmp = Some(xml.to_string());
        self
    }

    pub fn open_action_js(mut self, js: &str) -> Self {
        self.open_action_js = Some(js.to_string());
        self
    }

    pub fn form_field(mut self, name: &str, value: &str) -> Self {
        self.form_field = Some((name.to_string(), value.to_string()));
        self
    }

    /// Serialize to PDF bytes.
    pub fn finish(self) -> Vec<u8> {
        let mut objects: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        let mut next_id: u32 = 1;

        let catalog_id = next_id;
        next_id += 1;
        let pages_id = next_id;
        next_id += 1;
        let font_f1_id = next_id;
        next_id += 1;
        let font_f2_id = next_id;
        next_id += 1;
        let info_id = next_id;
        next_id += 1;

        let xmp_id = self.xmp.as_ref().map(|_| next_id);
        if xmp_id.is_some() {
            next_id += 1;
        }

        let mut page_ids = Vec::new();
        let mut content_ids = Vec::new();
        let mut annot_ids: Vec<Vec<u32>> = Vec::new();
        for _ in &self.pages {
            page_ids.push(next_id);
            next_id += 1;
            content_ids.push(next_id);
            next_id += 1;
            let ann: Vec<u32> = Vec::new();
            // Reserve ids after we know counts; simpler: reserve now per annot count later.
            annot_ids.push(ann);
        }
        // Reserve annotation object ids per page.
        for (i, page) in self.pages.iter().enumerate() {
            for _ in &page.uri_annots {
                annot_ids[i].push(next_id);
                next_id += 1;
            }
        }

        let form_field_id = self.form_field.as_ref().map(|_| next_id);
        if form_field_id.is_some() {
            next_id += 1;
        }

        // ---- fonts ----
        objects.insert(
            font_f1_id,
            format!(
                "<< /Type /Font /Subtype /Type1 /BaseFont /{} /Encoding /WinAnsiEncoding >>",
                Font::Helvetica.base_font()
            )
            .into_bytes(),
        );
        objects.insert(
            font_f2_id,
            format!(
                "<< /Type /Font /Subtype /Type1 /BaseFont /{} /Encoding /WinAnsiEncoding >>",
                Font::HelveticaBold.base_font()
            )
            .into_bytes(),
        );

        // ---- info ----
        let mut info = String::from("<<");
        info.push_str(" /Producer (pdfsan-core synth)");
        for (k, v) in &self.info_entries {
            info.push_str(&format!(" /{} ({})", k, escape_pdf_string(v.as_bytes())));
        }
        info.push_str(" >>");
        objects.insert(info_id, info.into_bytes());

        // ---- XMP ----
        if let (Some(xid), Some(xml)) = (xmp_id, &self.xmp) {
            let body = xml.as_bytes();
            objects.insert(
                xid,
                format!(
                    "<< /Type /Metadata /Subtype /XML /Length {} >>\nstream\n",
                    body.len()
                )
                .into_bytes()
                .iter()
                .chain(body)
                .chain(b"\nendstream")
                .cloned()
                .collect(),
            );
        }

        // ---- pages ----
        for (i, page) in self.pages.iter().enumerate() {
            let mut content = String::new();
            for item in &page.items {
                match item {
                    SynthItem::Raw(raw) => {
                        content.push_str(&raw.ops);
                        content.push('\n');
                    }
                    SynthItem::Text(t) => {
                        let (r, g, b) = t.fill;
                        content.push_str(&format!(
                            "q\n{:.3} {:.3} {:.3} rg\nBT\n{} {:.3} Tf\n{} Tr\n1 0 0 1 {:.3} {:.3} Tm\n({}) Tj\nET\nQ\n",
                            r, g, b,
                            t.font.resource_name(),
                            t.size,
                            t.render_mode,
                            t.x,
                            t.y,
                            t.escaped_text,
                        ));
                    }
                }
            }
            let body = content.into_bytes();
            objects.insert(
                content_ids[i],
                format!("<< /Length {} >>\nstream\n", body.len())
                    .into_bytes()
                    .iter()
                    .chain(&body)
                    .chain(b"\nendstream")
                    .cloned()
                    .collect(),
            );

            let mut annots_ref = String::new();
            if !page.uri_annots.is_empty() {
                let refs: Vec<String> = annot_ids[i]
                    .iter()
                    .map(|id| format!("{} 0 R", id))
                    .collect();
                annots_ref = format!(" /Annots [{}]", refs.join(" "));
            }
            objects.insert(
                page_ids[i],
                format!(
                    "<< /Type /Page /Parent {} 0 R /MediaBox [0 0 {:.3} {:.3}] /Resources << /Font << /F1 {} 0 R /F2 {} 0 R >> >> /Contents {} 0 R{} >>",
                    pages_id, page.width, page.height, font_f1_id, font_f2_id, content_ids[i], annots_ref
                )
                .into_bytes(),
            );

            for (a, annot) in page.uri_annots.iter().enumerate() {
                objects.insert(
                    annot_ids[i][a],
                    format!(
                        "<< /Type /Annot /Subtype /Link /Rect [{:.3} {:.3} {:.3} {:.3}] /Border [0 0 0] /A << /S /URI /URI ({}) >> >>",
                        annot.rect[0],
                        annot.rect[1],
                        annot.rect[2],
                        annot.rect[3],
                        escape_pdf_string(annot.uri.as_bytes())
                    )
                    .into_bytes(),
                );
            }
        }

        // ---- pages tree ----
        let kids: Vec<String> = page_ids.iter().map(|id| format!("{} 0 R", id)).collect();
        objects.insert(
            pages_id,
            format!("<< /Type /Pages /Kids [{}] /Count {} >>", kids.join(" "), page_ids.len())
                .into_bytes(),
        );

        // ---- form field ----
        if let (Some(fid), Some((name, value))) = (form_field_id, &self.form_field) {
            objects.insert(
                fid,
                format!(
                    "<< /FT /Tx /T ({}) /V ({}) >>",
                    escape_pdf_string(name.as_bytes()),
                    escape_pdf_string(value.as_bytes())
                )
                .into_bytes(),
            );
        }

        // ---- catalog ----
        let mut catalog = format!("<< /Type /Catalog /Pages {} 0 R", pages_id);
        if let Some(xid) = xmp_id {
            catalog.push_str(&format!(" /Metadata {} 0 R", xid));
        }
        if let Some(js) = &self.open_action_js {
            catalog.push_str(&format!(
                " /OpenAction << /S /JavaScript /JS ({}) >>",
                escape_pdf_string(js.as_bytes())
            ));
        }
        if let Some(fid) = form_field_id {
            catalog.push_str(&format!(
                " /AcroForm << /Fields [{} 0 R] /SigFlags 0 >>",
                fid
            ));
        }
        catalog.push_str(" >>");
        objects.insert(catalog_id, catalog.into_bytes());

        // ---- serialize with xref ----
        let mut out: Vec<u8> = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
        let mut offsets: BTreeMap<u32, usize> = BTreeMap::new();
        for (id, body) in &objects {
            offsets.insert(*id, out.len());
            out.extend_from_slice(format!("{} 0 obj\n", id).as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }
        let size = next_id;
        let max_id = objects.keys().copied().max().unwrap_or(0);
        let _ = max_id;
        let xref_pos = out.len();
        out.extend_from_slice(format!("xref\n0 {}\n", size).as_bytes());
        out.extend_from_slice(b"0000000000 65535 f \n");
        for id in 1..size {
            match offsets.get(&id) {
                Some(off) => out.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes()),
                None => out.extend_from_slice(b"0000000000 65535 f \n"),
            }
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root {} 0 R /Info {} 0 R >>\nstartxref\n{}\n%%EOF\n",
                size, catalog_id, info_id, xref_pos
            )
            .as_bytes(),
        );
        out
    }
}

fn encode_win_ansi(text: &str) -> Vec<u8> {
    // Latin-1 superset approximation: ASCII passthrough, everything else
    // mapped to '?' except Latin-1 range.
    text.chars()
        .map(|c| if (c as u32) <= 0xFF { c as u8 } else { b'?' })
        .collect()
}

fn escape_pdf_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'(' => out.push_str("\\("),
            b')' => out.push_str("\\)"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            0x20..=0x7E => out.push(b as char),
            _ => out.push_str(&format!("\\{:03o}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_loadable_pdf() {
        let mut page = SynthPage::letter();
        page.push_text(TextBuilder::new(72.0, 700.0, 24.0, "Hello World").build());
        let doc = SynthDoc::new().page(page).finish();
        let parsed = lopdf::Document::load_mem(&doc).expect("lopdf must parse synthetic PDF");
        assert_eq!(parsed.get_pages().len(), 1);
    }

    #[test]
    fn multi_page_roundtrip() {
        let mut d = SynthDoc::new();
        for i in 0..3 {
            let mut p = SynthPage::letter();
            p.push_text(
                TextBuilder::new(72.0, 700.0, 18.0, &format!("Page {i} body text")).build(),
            );
            d.pages.push(p);
        }
        let bytes = d.finish();
        let parsed = lopdf::Document::load_mem(&bytes).unwrap();
        assert_eq!(parsed.get_pages().len(), 3);
    }
}
