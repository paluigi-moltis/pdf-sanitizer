//! Debug helper: render a synthetic page and dump OCR lines + bboxes.
//! Run: cargo run -p pdfsan-core --example debug_ocr

use pdfsan_core::models;
use pdfsan_core::path_b::{self, VisualPage};
use pdfsan_core::synth::{SynthDoc, SynthPage, TextBuilder};

fn main() -> anyhow::Result<()> {
    let mut page = SynthPage::letter();
    page.push_text(
        TextBuilder::new(72.0, 700.0, 28.0, "Quarterly Financial Report")
            .bold()
            .build(),
    );
    page.push_text(TextBuilder::new(
        72.0,
        640.0,
        14.0,
        "Revenue grew twelve percent year over year.",
    )
    .build());
    page.push_text(TextBuilder::new(
        72.0,
        610.0,
        14.0,
        "Operating expenses remained flat during the period.",
    )
    .build());
    let bytes = SynthDoc::new().page(page).finish();

    let dir = models::discover_models_dir()
        .or_else(|| Some(models::default_models_dir()))
        .expect("no models dir");
    let loaded = models::load_models(&dir, false)?;
    let engine = path_b::build_engine(loaded)?;

    let pdf = hayro::hayro_syntax::Pdf::new(bytes)
        .map_err(|e| anyhow::anyhow!("hayro: {e:?}"))?;
    let raster = path_b::rasterize_page(&pdf, 0, 150.0)?;
    println!("raster: {}x{}", raster.width, raster.height);
    std::fs::create_dir_all("/tmp/pdfsan")?;
    let png = encode_png(&raster)?;
    std::fs::write("/tmp/pdfsan/page.png", png)?;
    let lines = path_b::ocr_page(&engine, &raster)?;
    let vpage = VisualPage {
        page_number: 1,
        lines,
        rasterized: None,
    };
    for l in &vpage.lines {
        println!(
            "h={:6.1} y={:6.1}  {:?}",
            l.height_px,
            l.bbox_px[1],
            l.text
        );
    }
    println!("--- markdown ---\n{}", path_b::build_markdown(&[vpage]));
    Ok(())
}

fn encode_png(raster: &path_b::RasterizedPage) -> anyhow::Result<Vec<u8>> {
    use png::{BitDepth, ColorType, Encoder};
    let mut out = Vec::new();
    {
        let mut encoder = Encoder::new(&mut out, raster.width, raster.height);
        encoder.set_color(ColorType::Rgba);
        encoder.set_depth(BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&raster.rgba)?;
    }
    Ok(out)
}
