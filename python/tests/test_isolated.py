"""Isolated-subprocess wrapper tests (require the CLI binary + OCR models)."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from pdf_sanitizer.isolated import (
    CliResolutionError,
    SanitizationTimeout,
    find_cli_binary,
    sanitize_pdf_isolated,
)

from test_bindings import _models_available, requires_models

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def cli_binary():
    try:
        return find_cli_binary()
    except CliResolutionError:
        pytest.skip("pdf-sanitizer CLI binary not built")


@requires_models
def test_isolated_hostile(tmp_path, cli_binary):
    pdf = tmp_path / "hostile.pdf"
    pdf.write_bytes(b"%PDF-1.7\n")  # placeholder overwritten below
    import pdf_sanitizer

    pdf.write_bytes(pdf_sanitizer.synth_hostile_pdf())

    out = tmp_path / "out"
    result = sanitize_pdf_isolated(
        pdf, timeout_sec=180.0, out_dir=str(out)
    )  # generous for debug builds
    assert result.risk_level == "high"
    assert result.total_findings >= 6
    assert result.hidden_text_removed >= 3
    cats = {f.category for f in result.findings}
    assert "invisible_text_injection" in cats
    assert "canary_or_exfiltration_link" in cats

    md = result.sanitized_markdown.lower()
    assert "canarytokens" not in md
    assert "ignore previous" not in md

    # Artifacts were kept in out_dir.
    assert (out / "hostile.md").is_file()
    report = json.loads((out / "hostile.report.json").read_text())
    assert report["document"]["risk_level"] == "high"

    # Duck-typing with the in-process result.
    assert result.to_json()
    assert "findings" in result.to_dict()
    assert repr(result).startswith("<SanitizationResult")


@requires_models
def test_isolated_benign(tmp_path, cli_binary):
    import pdf_sanitizer

    pdf = tmp_path / "benign.pdf"
    pdf.write_bytes(pdf_sanitizer.synth_benign_pdf())
    result = sanitize_pdf_isolated(pdf, timeout_sec=180.0)
    assert result.risk_level == "none"
    assert result.total_findings == 0
    assert "quarterly" in result.sanitized_markdown.lower()


def test_isolated_missing_file():
    with pytest.raises(FileNotFoundError):
        sanitize_pdf_isolated("/nonexistent/file.pdf", timeout_sec=5)


def test_isolated_timeout(tmp_path, cli_binary):
    if not _models_available():
        pytest.skip("OCR models not available")

    import pdf_sanitizer

    pdf = tmp_path / "hostile.pdf"
    pdf.write_bytes(pdf_sanitizer.synth_hostile_pdf())
    # A timeout far below the real scan duration forces the kill path.
    with pytest.raises(SanitizationTimeout):
        sanitize_pdf_isolated(pdf, timeout_sec=0.05)
