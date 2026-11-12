//! OCR model discovery, loading and (optional, one-time) download.
//!
//! All *document processing* is 100% offline. The only network access in the
//! entire tool is the optional bootstrap download of the two ocrs `.rten`
//! model files, cached under the models dir and re-used forever after.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

pub const DETECTION_MODEL_RTEN: &str = "text-detection.rten";
pub const RECOGNITION_MODEL_RTEN: &str = "text-recognition.rten";
pub const DETECTION_MODEL_ONNX_NAME: &str = "text-detection.onnx";
pub const RECOGNITION_MODEL_ONNX_NAME: &str = "text-recognition.onnx";

const BASE_URL: &str = "https://ocrs-models.s3-accelerate.amazonaws.com";

/// Default models cache dir: `$XDG_CACHE_HOME/pdf-sanitizer/models` or
/// `~/.cache/pdf-sanitizer/models`.
pub fn default_models_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        PathBuf::from(xdg).join("pdf-sanitizer").join("models")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".cache")
            .join("pdf-sanitizer")
            .join("models")
    } else {
        PathBuf::from(".cache").join("pdf-sanitizer").join("models")
    }
}

/// Search order for the models dir: `PDF_SANITIZER_MODELS_DIR` env var,
/// `<workspace>/tests/fixtures/models` (test runs), then the default cache.
pub fn discover_models_dir() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(dir) = std::env::var("PDF_SANITIZER_MODELS_DIR") {
        candidates.push(PathBuf::from(dir));
    }
    // Test-fixture location, relative to the crate manifest
    // (`<repo>/crates/core` -> `<repo>/tests/fixtures/models`).
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        candidates.push(
            PathBuf::from(manifest)
                .join("../..")
                .join("tests")
                .join("fixtures")
                .join("models"),
        );
    }
    candidates.push(default_models_dir());

    candidates.into_iter().find(|d| has_models(d))
}

pub fn has_models(dir: &Path) -> bool {
    detection_model_path(dir).is_file() && recognition_model_path(dir).is_file()
}

fn detection_model_path(dir: &Path) -> PathBuf {
    let rten = dir.join(DETECTION_MODEL_RTEN);
    if rten.is_file() {
        rten
    } else {
        dir.join(DETECTION_MODEL_ONNX_NAME)
    }
}

fn recognition_model_path(dir: &Path) -> PathBuf {
    let rten = dir.join(RECOGNITION_MODEL_RTEN);
    if rten.is_file() {
        rten
    } else {
        dir.join(RECOGNITION_MODEL_ONNX_NAME)
    }
}

/// Load the OCR models from `dir`, optionally downloading them first.
pub fn load_models(dir: &Path, allow_download: bool) -> Result<crate::path_b::OcrModels> {
    if !has_models(dir) {
        if allow_download {
            download_models(dir)?;
        } else {
            return Err(anyhow!(
                "OCR models not found in {}. Run with download enabled or place {} and {} there (see scripts/download-models.sh).",
                dir.display(),
                DETECTION_MODEL_RTEN,
                RECOGNITION_MODEL_RTEN
            ));
        }
    }
    let detection = crate::path_b::load_model(&detection_model_path(dir))?;
    let recognition = crate::path_b::load_model(&recognition_model_path(dir))?;
    Ok(crate::path_b::OcrModels::new(detection, recognition))
}

/// One-time bootstrap download of the ocrs models (feature `download`).
#[cfg(feature = "download")]
pub fn download_models(dir: &Path) -> Result<()> {
    use anyhow::Context as _;
    std::fs::create_dir_all(dir).context("creating models dir")?;
    download_file(
        &format!("{BASE_URL}/{DETECTION_MODEL_RTEN}"),
        &dir.join(DETECTION_MODEL_RTEN),
        &format!("{BASE_URL}/{DETECTION_MODEL_ONNX_NAME}"),
        &dir.join(DETECTION_MODEL_ONNX_NAME),
    )?;
    download_file(
        &format!("{BASE_URL}/{RECOGNITION_MODEL_RTEN}"),
        &dir.join(RECOGNITION_MODEL_RTEN),
        &format!("{BASE_URL}/{RECOGNITION_MODEL_ONNX_NAME}"),
        &dir.join(RECOGNITION_MODEL_ONNX_NAME),
    )?;
    Ok(())
}

#[cfg(feature = "download")]
fn download_file(
    primary: &str,
    primary_path: &Path,
    fallback: &str,
    fallback_path: &Path,
) -> Result<()> {
    use anyhow::Context as _;
    if primary_path.is_file() || fallback_path.is_file() {
        return Ok(());
    }
    println!("downloading {primary}");
    match fetch(primary) {
        Ok(bytes) => std::fs::write(primary_path, bytes),
        Err(e) => {
            println!("falling back to ONNX variant ({e})");
            let bytes = fetch(fallback)?;
            std::fs::write(fallback_path, bytes)
        }
    }
    .with_context(|| format!("writing {}", primary_path.display()))
}

#[cfg(feature = "download")]
fn fetch(url: &str) -> Result<Vec<u8>> {
    use anyhow::Context as _;
    use std::io::Read;
    let response = ureq::get(url)
        .call()
        .map_err(|e| anyhow!("GET {url}: {e}"))?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut bytes)
        .context("reading model body")?;
    if bytes.len() < 1024 {
        return Err(anyhow!("suspiciously small model body from {url}"));
    }
    Ok(bytes)
}

#[cfg(not(feature = "download"))]
pub fn download_models(_dir: &Path) -> Result<()> {
    Err(anyhow!(
        "model download support is not compiled in (rebuild with the `download` feature)"
    ))
}
