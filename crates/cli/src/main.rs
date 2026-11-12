//! `pdf-sanitizer` — offline PDF prompt-injection detector & WYSIWYG
//! sanitizer CLI.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use pdfsan_core::models;
use pdfsan_core::report::{Category, Report, Severity};
use pdfsan_core::{SanitizeOptions, Sanitizer};

#[derive(Parser)]
#[command(
    name = "pdf-sanitizer",
    version,
    about = "Offline PDF prompt-injection detector & WYSIWYG sanitizer",
    long_about = "Detects hidden AI prompt injections / call-home canary traps in PDFs and \
                  sanitizes documents into clean Markdown using a rasterize + OCR \
                  (what-you-see-is-what-you-get) pipeline. 100% offline: all document \
                  processing is local; only the optional first-run OCR model download \
                  touches the network."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan and sanitize a PDF.
    Scan {
        /// Input PDF file.
        input: PathBuf,
        /// Output path for the sanitized Markdown (default: <input>.sanitized.md).
        #[arg(long)]
        out_md: Option<PathBuf>,
        /// Output path for the audit report (default: <input>.report.json).
        #[arg(long)]
        out_json: Option<PathBuf>,
        /// Directory holding text-detection.rten / text-recognition.rten
        /// (default: auto-discovered, then ~/.cache/pdf-sanitizer/models).
        #[arg(long)]
        models_dir: Option<PathBuf>,
        /// Rasterization DPI for the visual pass (150-200 recommended).
        #[arg(long, default_value_t = 150.0)]
        dpi: f64,
        /// Exit with status 1 when any finding is reported.
        #[arg(long)]
        fail_on_findings: bool,
        /// Never download OCR models; fail if they are missing locally.
        #[arg(long)]
        no_download: bool,
        /// Directory to write rendered page PNGs into (debug/overlay support).
        #[arg(long)]
        dump_page_images: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Scan {
            input,
            out_md,
            out_json,
            models_dir,
            dpi,
            fail_on_findings,
            no_download,
            dump_page_images,
        } => run_scan(
            &input,
            out_md.as_deref(),
            out_json.as_deref(),
            models_dir.as_deref(),
            dpi,
            fail_on_findings,
            !no_download,
            dump_page_images.as_deref(),
        )
        .unwrap_or(2),
        // 0 = ok, 1 = findings (only with --fail-on-findings), 2 = error
    };
    std::process::exit(code);
}

#[allow(clippy::too_many_arguments)]
fn run_scan(
    input: &Path,
    out_md: Option<&Path>,
    out_json: Option<&Path>,
    models_dir: Option<&Path>,
    dpi: f64,
    fail_on_findings: bool,
    allow_download: bool,
    dump_page_images: Option<&Path>,
) -> Result<i32> {
    let bytes = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;

    let models_dir = match models_dir {
        Some(dir) => dir.to_path_buf(),
        None => models::discover_models_dir().unwrap_or_else(models::default_models_dir),
    };
    let loaded = models::load_models(&models_dir, allow_download)
        .with_context(|| format!("loading OCR models from {}", models_dir.display()))?;

    let sanitizer = Sanitizer::new(
        loaded,
        SanitizeOptions {
            dpi,
            keep_page_images: dump_page_images.is_some(),
        },
    )?;

    let filename = input
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "document.pdf".to_string());

    let report = sanitizer
        .sanitize(&filename, &bytes)
        .context("sanitization failed")?;

    if let Some(dir) = dump_page_images {
        dump_images(&report, dir)?;
    }

    let out_md = out_md
        .map(PathBuf::from)
        .unwrap_or_else(|| sibling(input, "sanitized.md"));
    let out_json = out_json
        .map(PathBuf::from)
        .unwrap_or_else(|| sibling(input, "report.json"));

    std::fs::write(&out_md, &report.sanitized_markdown)
        .with_context(|| format!("writing {}", out_md.display()))?;
    let json = serde_json::to_string_pretty(&report).context("serializing report")?;
    std::fs::write(&out_json, json).with_context(|| format!("writing {}", out_json.display()))?;

    print_summary(&report, &out_md, &out_json);

    if fail_on_findings && !report.findings.is_empty() {
        Ok(1)
    } else {
        Ok(0)
    }
}

fn sibling(input: &Path, suffix: &str) -> PathBuf {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "document".to_string());
    input.with_file_name(format!("{stem}.{suffix}"))
}

fn print_summary(report: &Report, out_md: &Path, out_json: &Path) {
    println!(
        "\n{} — {} page(s), risk level: {}",
        report.document.filename, report.document.page_count, report.document.risk_level
    );
    println!(
        "findings: {} (hidden text removed: {}, metadata/links stripped: {})",
        report.document.summary.total_findings,
        report.document.summary.hidden_text_removed,
        report.document.summary.metadata_or_links_stripped
    );
    for f in &report.findings {
        println!(
            "  [{}] {} {} p.{} {} — {} ({})",
            severity_tag(f.severity),
            f.id,
            serde_json::to_string(&f.category)
                .unwrap_or_default()
                .trim_matches('"'),
            f.location.page,
            f.location.surface.as_str(),
            f.reason,
            f.action_taken
        );
        if let Some(snip) = &f.quarantined_snippet {
            let one_line: String = snip.chars().filter(|c| !c.is_control()).take(100).collect();
            println!("          > {}", one_line);
        }
    }
    println!("\nsanitized markdown : {}", out_md.display());
    println!("audit report       : {}", out_json.display());
}

fn severity_tag(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED ",
        Severity::Low => "LOW ",
    }
}

fn dump_images(report: &Report, dir: &Path) -> Result<()> {
    // Page images are currently only retained in the PWA path (M3); in the
    // CLI this flag reserves the hook and validates the output dir.
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let _ = report;
    Ok(())
}

// Re-exported for main's use of Category tags without extra imports.
#[allow(dead_code)]
fn _unused(_c: Category) {}
