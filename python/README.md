# python/ — Milestone 2 (not yet implemented)

maturin (abi3) package exposing:

- `sanitize_pdf(path_or_bytes) -> SanitizationResult` — in-process PyO3
  bindings to `pdfsan-core`.
- `sanitize_pdf_isolated(path, timeout_sec=30) -> SanitizationResult` —
  spawns the bundled Rust `pdf-sanitizer` CLI binary in an isolated
  subprocess.

Will be wired up in Milestone 2 per the project plan (see root README).
