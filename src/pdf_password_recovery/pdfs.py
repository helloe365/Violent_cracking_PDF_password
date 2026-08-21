from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from .errors import PdfValidationError


@dataclass(frozen=True, slots=True)
class PdfInfo:
    path: Path
    size: int


def validate_pdf(path: Path) -> PdfInfo:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise PdfValidationError(f"PDF file does not exist: {path}")
    try:
        with resolved.open("rb") as stream:
            reader = PdfReader(stream, strict=False)
            if not reader.is_encrypted:
                raise PdfValidationError("PDF is not encrypted")
    except PdfValidationError:
        raise
    except (OSError, PdfReadError, ValueError) as exc:
        raise PdfValidationError(f"Cannot read PDF: {exc}") from exc
    return PdfInfo(resolved, resolved.stat().st_size)
