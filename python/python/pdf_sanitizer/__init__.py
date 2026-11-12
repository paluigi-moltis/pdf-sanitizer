"""pdf_sanitizer — offline PDF prompt-injection detector & WYSIWYG sanitizer.

Two entry points:

- :func:`sanitize_pdf` — in-process PyO3 bindings (fast path).
- :func:`sanitize_pdf_isolated` — runs the bundled Rust CLI binary in an
  isolated subprocess with a hard timeout (defense in depth for untrusted
  input; a crash or hang cannot take down the host process).

All document processing is 100% local. The only network access in the whole
tool is the optional one-time OCR model download (see ``allow_download``).
"""

from .isolated import sanitize_pdf_isolated
from .pdf_sanitizer import (
    SanitizationResult,
    synth_benign_pdf,
    synth_hostile_pdf,
    sanitize_pdf as _sanitize_pdf,
)

__all__ = [
    "sanitize_pdf",
    "sanitize_pdf_isolated",
    "SanitizationResult",
    "synth_benign_pdf",
    "synth_hostile_pdf",
    "__version__",
]

__version__ = "0.1.0"


def sanitize_pdf(input, dpi: float = 150.0, models_dir=None, allow_download: bool = True):
    """Sanitize a PDF entirely in-process.

    Args:
        input: PDF bytes or a path (``str`` / ``os.PathLike``).
        dpi: Rasterization DPI for the visual pass (default 150).
        models_dir: Optional directory holding the ocrs model files;
            auto-discovered when omitted.
        allow_download: Download the OCR models on first use when missing.

    Returns:
        SanitizationResult
    """
    return _sanitize_pdf(input, dpi=dpi, models_dir=models_dir, allow_download=allow_download)
