from __future__ import annotations

from pathlib import Path

import pytest

from pdf_password_recovery import BackendChoice, HybridAttack, RecoveryConfig, RulesAttack
from pdf_password_recovery.errors import ConfigurationError
from pdf_password_recovery.models import Cursor, CursorKind, OutcomeStatus, RecoveryOutcome
from pdf_password_recovery.service import (
    _hashcat_manifest_payload,
    _preflight,
    _run_cpu_with_checkpoint,
)


def test_rules_and_hybrid_preflight_without_charset_attribute(tmp_path, monkeypatch):
    monkeypatch.setattr("pdf_password_recovery.service.validate_pdf", lambda path: None)
    words = tmp_path / "words.txt"
    words.write_text("password\n", encoding="utf-8")
    for attack in (
        RulesAttack(words, ("c",)),
        HybridAttack(words, "?d", "append"),
    ):
        _preflight(RecoveryConfig(Path("input.pdf"), attack, backend=BackendChoice.HASHCAT))


def test_cpu_accepts_supported_rules_and_hybrid(tmp_path, monkeypatch):
    words = tmp_path / "words.txt"
    words.write_text("password\n", encoding="utf-8")
    def fake_run(config, **kwargs):
        kind = CursorKind.LINE if isinstance(config.attack, RulesAttack) else CursorKind.INDEX
        return RecoveryOutcome(OutcomeStatus.EXHAUSTED, None, Cursor(kind, 0), 0, 0.0, "cpu")

    monkeypatch.setattr("pdf_password_recovery.service.run_cpu", fake_run)
    for attack in (RulesAttack(words, ("c",)), HybridAttack(words, "?d", "append")):
        config = RecoveryConfig(Path("input.pdf"), attack, backend=BackendChoice.CPU)
        assert _run_cpu_with_checkpoint(config, None).status is OutcomeStatus.EXHAUSTED


def test_cpu_rejects_unsupported_rules_before_running(tmp_path, monkeypatch):
    words = tmp_path / "words.txt"
    words.write_text("password\n", encoding="utf-8")
    monkeypatch.setattr("pdf_password_recovery.service.validate_pdf", lambda path: None)
    config = RecoveryConfig(
        Path("input.pdf"), RulesAttack(words, ("unsupported-rule",)), backend=BackendChoice.CPU
    )
    with pytest.raises(ConfigurationError, match="smart rules"):
        _preflight(config)


def test_hashcat_manifest_tracks_rules_and_hybrid_wordlists(tmp_path):
    pdf = tmp_path / "input.pdf"
    pdf.write_bytes(b"pdf")
    words = tmp_path / "words.txt"
    words.write_text("one\n", encoding="utf-8")
    for index, attack in enumerate(
        (RulesAttack(words, ("c",)), HybridAttack(words, "?d", "append"))
    ):
        config = RecoveryConfig(pdf, attack, backend=BackendChoice.HASHCAT)
        before = _hashcat_manifest_payload(config)
        words.write_text(f"two-{index}\n", encoding="utf-8")
        after = _hashcat_manifest_payload(config)
        assert before["wordlist"] != after["wordlist"]
