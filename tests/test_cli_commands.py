from __future__ import annotations

import json
from io import StringIO

from pdf_password_recovery.cli import entrypoint


def test_plan_dry_run_json_is_jsonl_only(tmp_path) -> None:
    pdf = tmp_path / "input.pdf"
    pdf.write_bytes(b"%PDF-1.7")
    words = tmp_path / "words.txt"
    words.write_text("one\n", encoding="utf-8")
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "schema": 1,
                "name": "test",
                "stages": [{"id": "dictionary", "type": "dictionary", "wordlist": "words.txt"}],
            }
        ),
        encoding="utf-8",
    )
    output = StringIO()
    code = entrypoint(
        ("plan", str(pdf), "--file", str(plan), "--dry-run", "--json"), output=output, is_tty=False
    )
    lines = [json.loads(line) for line in output.getvalue().splitlines()]
    assert code == 0
    assert lines and all(line["schema"] == 1 for line in lines)
    assert all(line["type"] in {"stage_started", "preflight"} for line in lines)


def test_sessions_list_json_has_no_secret(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("PDF_PASSWORD_RECOVERY_STATE_DIR", str(tmp_path / "state"))
    output = StringIO()
    assert entrypoint(("sessions", "list", "--json"), output=output, is_tty=False) == 0
    assert output.getvalue() == ""
