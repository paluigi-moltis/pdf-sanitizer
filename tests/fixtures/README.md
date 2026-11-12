# Test fixtures

Synthetic benign & malicious PDFs are generated **at test time** by
`pdfsan_core::synth` (see `crates/core/tests/integration.rs`), so the exact
hostile constructs (white-on-white text, off-canvas text, 0.5pt fonts,
render-mode-3 text, XMP injections, canary `/URI` annotations, invisible
Unicode payloads) are always in sync with the rule engine.

`models/` holds the ocrs OCR model files downloaded once by
`../../scripts/download-models.sh`; it is gitignored.
