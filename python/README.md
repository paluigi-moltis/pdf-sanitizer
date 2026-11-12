# python/ — Milestone 2: maturin package

`pdf-sanitizer` — Python package exposing the offline dual-path sanitizer.

## Install (from repo)

```console
$ scripts/download-models.sh tests/fixtures/models   # one-time OCR models
$ cd python
$ uv venv && uv pip install maturin pytest
$ uv run maturin develop                             # editable install
$ uv run pytest
```

## API

```python
from pdf_sanitizer import sanitize_pdf, sanitize_pdf_isolated

# In-process PyO3 bindings (fast path)
result = sanitize_pdf("report.pdf")            # or bytes
result.risk_level          # "high"
result.total_findings      # 12
result.findings            # [Finding(...), ...] with .severity .category .page .bbox_norm ...
result.sanitized_markdown  # clean Markdown, reconstructed from the visual OCR pass only
result.to_json()           # full audit report JSON

# Isolated subprocess with hard timeout (untrusted input defense)
result = sanitize_pdf_isolated("report.pdf", timeout_sec=30)
```

Both entry points return duck-compatible result objects
(`filename`, `page_count`, `risk_level`, `sanitized_markdown`,
`total_findings`, `hidden_text_removed`, `metadata_or_links_stripped`,
`findings`, `to_dict()`, `to_json()`).

`synth_benign_pdf()` / `synth_hostile_pdf()` generate the synthetic test
documents (useful for demos and CI).

## Building wheels with the bundled CLI

The isolated runner uses the Rust `pdf-sanitizer` CLI binary. When building
wheels for distribution, place the binary **and the OCR models** in the
package dirs first so the wheel is fully self-contained:

```console
$ cargo build --release -p pdf-sanitizer
$ mkdir -p python/python/pdf_sanitizer/bin python/python/pdf_sanitizer/models
$ cp target/release/pdf-sanitizer python/python/pdf_sanitizer/bin/
$ cp tests/fixtures/models/*.rten python/python/pdf_sanitizer/models/ 2>/dev/null \
  || cp tests/fixtures/models/*.onnx python/python/pdf_sanitizer/models/
$ cd python && uv run maturin build
```

Dev/test runs fall back to `target/{release,debug}` automatically, or honor
`PDF_SANITIZER_BIN`. Model files are resolved from
`PDF_SANITIZER_MODELS_DIR`, a `models/` dir inside the package, or
`~/.cache/pdf-sanitizer/models`.
