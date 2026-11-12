"""Isolated-subprocess sanitization via the bundled Rust CLI binary.

Spawns ``pdf-sanitizer scan`` in a separate process with a hard timeout, so
hostile PDFs can never crash or hang the host interpreter. The report JSON
is parsed into a :class:`SanitizationResult`-compatible object.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

__all__ = ["sanitize_pdf_isolated", "IsolatedResult", "CliResolutionError"]


class CliResolutionError(RuntimeError):
    """The bundled pdf-sanitizer CLI binary could not be located."""


class SanitizationTimeout(TimeoutError):
    """The CLI subprocess exceeded the configured timeout."""


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    reason: str
    action_taken: str
    page: int
    surface: str
    bbox_norm: Optional[tuple] = None
    object_ref: Optional[str] = None
    quarantined_snippet: Optional[str] = None

    def __repr__(self) -> str:
        return (
            f"<Finding {self.id} [{self.severity}] {self.category} "
            f"p.{self.page} ({self.surface})>"
        )


@dataclass
class IsolatedResult:
    filename: str
    page_count: int
    risk_level: str
    sanitized_markdown: str
    summary: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return int(self.summary.get("total_findings", len(self.findings)))

    @property
    def hidden_text_removed(self) -> int:
        return int(self.summary.get("hidden_text_removed", 0))

    @property
    def metadata_or_links_stripped(self) -> int:
        return int(self.summary.get("metadata_or_links_stripped", 0))

    def to_dict(self) -> dict:
        return {
            "document": {
                "filename": self.filename,
                "page_count": self.page_count,
                "risk_level": self.risk_level,
                "summary": self.summary,
            },
            "findings": [f.__dict__ for f in self.findings],
            "sanitized_markdown": self.sanitized_markdown,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def __repr__(self) -> str:
        return (
            f"<SanitizationResult {self.filename} risk={self.risk_level} "
            f"findings={self.total_findings}>"
        )


# Ducked-typed alias so both entry points present the same class name.
SanitizationResult = IsolatedResult


def find_cli_binary() -> Path:
    """Locate the pdf-sanitizer CLI: env var, bundled bin, then dev builds."""
    env = os.environ.get("PDF_SANITIZER_BIN")
    if env:
        path = Path(env)
        if path.is_file():
            return path
        raise CliResolutionError(f"PDF_SANITIZER_BIN={env} does not exist")

    bundled = Path(__file__).resolve().parent / "bin" / "pdf-sanitizer"
    if bundled.is_file():
        return bundled

    # Development layouts: <repo>/target/{debug,release} and python/../target/...
    here = Path(__file__).resolve()
    for base in (here.parents[3], here.parents[2]):
        for profile in ("release", "debug"):
            candidate = base / "target" / profile / "pdf-sanitizer"
            if candidate.is_file():
                return candidate

    raise CliResolutionError(
        "pdf-sanitizer CLI binary not found; build it with "
        "`cargo build -p pdf-sanitizer` or set PDF_SANITIZER_BIN"
    )


def _resolve_models_dir(models_dir: Optional[str]) -> Optional[str]:
    if models_dir:
        return models_dir
    if os.environ.get("PDF_SANITIZER_MODELS_DIR"):
        return os.environ["PDF_SANITIZER_MODELS_DIR"]
    bundled = Path(__file__).resolve().parent / "models"
    if (bundled / "text-detection.onnx").is_file() or (
        bundled / "text-detection.rten"
    ).is_file():
        return str(bundled)
    cache = Path.home() / ".cache" / "pdf-sanitizer" / "models"
    if cache.is_dir():
        return str(cache)
    return None


def sanitize_pdf_isolated(
    path,
    timeout_sec: float = 30.0,
    dpi: float = 150.0,
    models_dir: Optional[str] = None,
    out_dir: Optional[str] = None,
) -> IsolatedResult:
    """Sanitize a PDF by running the bundled CLI in an isolated subprocess.

    Args:
        path: Path to the PDF file (str / os.PathLike).
        timeout_sec: Hard timeout for the subprocess (default 30s); a
            ``SanitizationTimeout`` is raised and the process killed.
        dpi: Rasterization DPI for the visual pass.
        models_dir: Optional models dir; auto-resolved when omitted.
        out_dir: Optional directory to keep the ``.md`` / ``.report.json``
            artifacts in (defaults to a temp dir that is cleaned up).

    Returns:
        IsolatedResult (duck-compatible with SanitizationResult).
    """
    pdf_path = Path(path)
    if not pdf_path.is_file():
        raise FileNotFoundError(f"no such file: {pdf_path}")

    binary = find_cli_binary()
    resolved_models = _resolve_models_dir(models_dir)

    keep = out_dir is not None
    tmp = out_dir or tempfile.mkdtemp(prefix="pdfsan-")
    Path(tmp).mkdir(parents=True, exist_ok=True)
    stem = pdf_path.stem

    cmd = [
        str(binary),
        "scan",
        str(pdf_path),
        "--out-md",
        str(Path(tmp) / f"{stem}.md"),
        "--out-json",
        str(Path(tmp) / f"{stem}.report.json"),
        "--dpi",
        str(dpi),
        "--no-download",
    ]
    if resolved_models:
        cmd += ["--models-dir", resolved_models]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"pdf-sanitizer CLI failed (exit {proc.returncode}):\n{proc.stderr[-4000:]}"
            )

        report_path = Path(tmp) / f"{stem}.report.json"
        report: dict[str, Any] = json.loads(report_path.read_text(encoding="utf-8"))
    except subprocess.TimeoutExpired as exc:
        raise SanitizationTimeout(
            f"pdf-sanitizer CLI exceeded {timeout_sec}s for {pdf_path}"
        ) from exc
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)

    doc = report["document"]
    findings = [
        Finding(
            id=f["id"],
            severity=f["severity"],
            category=f["category"],
            reason=f["reason"],
            action_taken=f["action_taken"],
            page=f["location"]["page"],
            surface=f["location"]["surface"],
            bbox_norm=f["location"].get("bbox_norm"),
            object_ref=f["location"].get("object_ref"),
            quarantined_snippet=f.get("quarantined_snippet"),
        )
        for f in report["findings"]
    ]
    return IsolatedResult(
        filename=doc["filename"],
        page_count=doc["page_count"],
        risk_level=doc["risk_level"],
        sanitized_markdown=report["sanitized_markdown"],
        summary=doc["summary"],
        findings=findings,
    )
