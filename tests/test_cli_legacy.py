from __future__ import annotations

from io import StringIO

from pdf_password_recovery.cli import entrypoint


def test_unknown_first_token_keeps_legacy_parser() -> None:
    error = StringIO()
    code = entrypoint(
        ("missing.pdf", "--attack", "brute", "--yes"), output=StringIO(), error=error, is_tty=False
    )
    assert code == 2
    assert "Error:" in error.getvalue()


def test_zero_argument_non_tty_still_requires_legacy_attack() -> None:
    error = StringIO()
    code = entrypoint((), output=StringIO(), error=error, is_tty=False)
    assert code == 2
    assert "--attack" in error.getvalue()
