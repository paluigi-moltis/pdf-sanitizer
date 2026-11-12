"""In-process PyO3 binding tests (require OCR models; auto-skip otherwise)."""

import os
import sys
from pathlib import Path

import pytest

import pdf_sanitizer


def _models_available() -> bool:
    env = os.environ.get("PDF_SANITIZER_MODELS_DIR")
    candidates = []
    if env:
        candidates.append(Path(env))
    repo = Path(__file__).resolve().parents[2]
    candidates.append(repo / "tests" / "fixtures" / "models")
    candidates.append(Path.home() / ".cache" / "pdf-sanitizer" / "models")
    for c in candidates:
        if (c / "text-detection.onnx").is_file() or (c / "text-detection.rten").is_file():
            return True
    return False


requires_models = pytest.mark.skipif(
    not _models_available(), reason="OCR models not available (run scripts/download-models.sh)"
)


def test_synth_generators_return_pdf_bytes():
    for gen in (pdf_sanitizer.synth_benign_pdf, pdf_sanitizer.synth_hostile_pdf):
        data = gen()
        assert isinstance(data, (bytes, bytearray))
        assert bytes(data[:5]) == b"%PDF-"


@requires_models
def test_sanitize_pdf_bytes_hostile():
    result = pdf_sanitizer.sanitize_pdf(
        pdf_sanitizer.synth_hostile_pdf(), allow_download=False
    )
    assert result.risk_level == "high"
    assert result.total_findings >= 6
    assert result.hidden_text_removed >= 3
    assert result.metadata_or_links_stripped >= 2

    categories = {f.category for f in result.findings}
    assert "invisible_text_injection" in categories
    assert "canary_or_exfiltration_link" in categories
    assert "javascript_action" in categories

    md = result.sanitized_markdown.lower()
    assert "canarytokens" not in md
    assert "ignore previous" not in md
    assert "webhook.site" not in md

    # JSON round-trip carries the documented schema.
    import json

    payload = json.loads(result.to_json())
    assert payload["document"]["risk_level"] == "high"
    assert payload["findings"][0]["id"].startswith("F-")


@requires_models
def test_sanitize_pdf_path_benign(tmp_path):
    pdf = tmp_path / "benign.pdf"
    pdf.write_bytes(pdf_sanitizer.synth_benign_pdf())
    result = pdf_sanitizer.sanitize_pdf(str(pdf), allow_download=False)
    assert result.risk_level == "none"
    assert result.total_findings == 0
    assert result.filename == "benign.pdf"
    assert "quarterly" in result.sanitized_markdown.lower()


def test_sanitize_pdf_rejects_bad_input():
    with pytest.raises(TypeError):
        pdf_sanitizer.sanitize_pdf(12345)


@requires_models
def test_finding_attributes():
    result = pdf_sanitizer.sanitize_pdf(
        pdf_sanitizer.synth_hostile_pdf(), allow_download=False
    )
    hidden = [f for f in result.findings if f.category == "invisible_text_injection"]
    assert hidden
    f = hidden[0]
    assert f.severity in ("critical", "high")
    assert f.action_taken == "removed"
    assert f.page >= 1
    assert f.surface == "page_body"
    bbox = f.bbox_norm
    assert bbox is not None and len(bbox) == 4
    assert all(0.0 <= v <= 1.05 for v in bbox)
    assert f.quarantined_snippet
