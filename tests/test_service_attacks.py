from __future__ import annotations

from pathlib import Path

import pytest

from pdf_password_recovery import BackendChoice, HybridAttack, RecoveryConfig, RulesAttack
from pdf_password_recovery.errors import ConfigurationError
from pdf_password_recovery.service import _preflight, _run_cpu_with_checkpoint


def test_rules_and_hybrid_preflight_without_charset_attribute(tmp_path, monkeypatch):
    monkeypatch.setattr("pdf_password_recovery.service.validate_pdf", lambda path: None)
    words = tmp_path / "words.txt"
    words.write_text("password\n", encoding="utf-8")
    for attack in (
        RulesAttack(words, ("c",)),
        HybridAttack(words, "?d", "append"),
    ):
        _preflight(RecoveryConfig(Path("input.pdf"), attack, backend=BackendChoice.HASHCAT))


def test_cpu_rejects_rules_and_hybrid_with_stable_configuration_error(tmp_path):
    words = tmp_path / "words.txt"
    words.write_text("password\n", encoding="utf-8")
    for attack in (
        RulesAttack(words, ("c",)),
        HybridAttack(words, "?d", "append"),
    ):
        config = RecoveryConfig(Path("input.pdf"), attack, backend=BackendChoice.CPU)
        with pytest.raises(ConfigurationError, match="CPU backend"):
            _run_cpu_with_checkpoint(config, None)
