//! WebAssembly bindings for `pdfsan-core`, designed for execution inside a
//! Web Worker: the whole dual-path pipeline (rasterization + OCR + rule
//! engine) runs client-side with page-by-page progress callbacks.
//!
//! Model weights are fetched by the JS host (from Cache Storage when
//! offline) and passed in as bytes — the wasm module itself performs zero
//! network access.

use wasm_bindgen::prelude::*;

use pdfsan_core::path_b::OcrModels;
use pdfsan_core::{SanitizeOptions, Sanitizer};

/// WebAssembly sanitizer. Construct once per worker with the OCR model
/// weights, then run `sanitize` per document.
#[wasm_bindgen]
pub struct SanitizerWasm {
    inner: Sanitizer,
}

fn set(obj: &js_sys::Object, key: &str, value: JsValue) {
    let _ = js_sys::Reflect::set(obj, &JsValue::from_str(key), &value);
}

#[wasm_bindgen]
impl SanitizerWasm {
    /// Create a sanitizer from raw OCR model weights (`.rten` or `.onnx`).
    #[wasm_bindgen(constructor)]
    pub fn new(
        detection_model: Vec<u8>,
        recognition_model: Vec<u8>,
    ) -> Result<SanitizerWasm, JsError> {
        let detection = rten::Model::load(detection_model)
            .map_err(|e| JsError::new(&format!("detection model: {e:?}")))?;
        let recognition = rten::Model::load(recognition_model)
            .map_err(|e| JsError::new(&format!("recognition model: {e:?}")))?;
        let inner = Sanitizer::new(
            OcrModels::new(detection, recognition),
            SanitizeOptions {
                dpi: 150.0,
                keep_page_images: true,
            },
        )
        .map_err(|e| JsError::new(&format!("engine init: {e:?}")))?;
        Ok(SanitizerWasm { inner })
    }

    /// Sanitize a PDF from raw bytes.
    ///
    /// `on_progress` is a JS callback invoked as `on_progress(done, total)`
    /// after every processed page.
    ///
    /// Returns `{ report, pageImages }`: `report` is the audit-report object
    /// (same schema as the CLI's `.report.json`) and `pageImages` is an
    /// array of `{ pageNumber, width, height, rgba }` with raw RGBA bytes
    /// for `ImageData` / canvas overlay rendering.
    pub fn sanitize(
        &self,
        pdf: Vec<u8>,
        filename: String,
        on_progress: &js_sys::Function,
    ) -> Result<JsValue, JsError> {
        let mut cb = |done: usize, total: usize| {
            let _ = on_progress.call2(&JsValue::NULL, &JsValue::from(done), &JsValue::from(total));
        };

        let output = self
            .inner
            .sanitize_with_progress(&filename, &pdf, &mut cb)
            .map_err(|e| JsError::new(&format!("{e:#}")))?;

        let report = serde_wasm_bindgen::to_value(&output.report)
            .map_err(|e| JsError::new(&format!("report serialization: {e:?}")))?;

        let images: Vec<JsValue> = output
            .page_images
            .iter()
            .map(|img| {
                let o = js_sys::Object::new();
                set(&o, "pageNumber", JsValue::from(img.page_number as u32));
                set(&o, "width", JsValue::from(img.width));
                set(&o, "height", JsValue::from(img.height));
                let arr = js_sys::Uint8Array::new_with_length(img.rgba.len() as u32);
                arr.copy_from(&img.rgba);
                set(&o, "rgba", arr.into());
                o.into()
            })
            .collect();

        let result = js_sys::Object::new();
        set(&result, "report", report);
        set(
            &result,
            "pageImages",
            js_sys::Array::from_iter(images).into(),
        );
        Ok(result.into())
    }
}

/// Generate the benign synthetic demo PDF.
#[wasm_bindgen]
pub fn synth_benign_pdf() -> Vec<u8> {
    pdfsan_core::synth::benign_demo()
}

/// Generate the hostile synthetic demo PDF (all stealth techniques).
#[wasm_bindgen]
pub fn synth_hostile_pdf() -> Vec<u8> {
    pdfsan_core::synth::hostile_demo()
}
