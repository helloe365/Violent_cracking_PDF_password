from __future__ import annotations

import json
from pathlib import Path

import pytest

from pdf_password_recovery.backends.hashcat_info import (
    DeviceInfo,
    HashcatCapabilities,
    PreflightReport,
)
from pdf_password_recovery.errors import ToolUnavailable
from pdf_password_recovery.events import event_payload
from pdf_password_recovery.models import (
    BackendChoice,
    CompiledPlan,
    CompiledStage,
    Cursor,
    CursorKind,
    DictionaryAttack,
    DictionaryStage,
    OutcomeStatus,
    RecoveryOutcome,
    WorkloadProfile,
)
from pdf_password_recovery.orchestrator import run_plan
from pdf_password_recovery.sessions import SessionStore


class Sink:
    def __init__(self) -> None:
        self.events = []

    def emit(self, event) -> None:
        self.events.append(event_payload(event))


def _plan(tmp_path: Path) -> tuple[CompiledPlan, Path]:
    pdf = tmp_path / "input.pdf"
    pdf.write_bytes(b"%PDF-1.7")
    words = tmp_path / "words.txt"
    words.write_text("one\n", encoding="utf-8")
    source = DictionaryStage("dictionary", words)
    stage = CompiledStage("dictionary", DictionaryAttack(words), 1, True, source)
    return CompiledPlan(1, "test", (stage,), "0" * 64), pdf


def _preflight() -> PreflightReport:
    device = DeviceInfo("1", "GPU", "CUDA", "GPU", False)
    capabilities = HashcatCapabilities(
        "7.1.2", "0" * 64, frozenset(), frozenset({10400}), (device,)
    )
    return PreflightReport(10400, capabilities, (device,), WorkloadProfile.BALANCED, 1.0, False)


def test_run_plan_sequences_stages_and_never_serializes_secret(tmp_path: Path) -> None:
    plan, pdf = _plan(tmp_path)
    sink = Sink()
    calls = []

    def recover(config, **kwargs):
        calls.append(config.attack)
        return RecoveryOutcome(
            OutcomeStatus.FOUND,
            "secret",
            Cursor(CursorKind.LINE, 1),
            1,
            0.1,
            "cpu",
        )

    outcome = run_plan(
        plan, pdf_path=pdf, backend=BackendChoice.CPU, recover_fn=recover, event_sink=sink
    )

    assert outcome.status is OutcomeStatus.FOUND
    assert len(calls) == 1
    assert [item["type"] for item in sink.events] == ["stage_started", "result"]
    assert "secret" not in json.dumps(sink.events)
    assert "$pdf$" not in json.dumps(sink.events)


def test_run_plan_exhausted_emits_terminal_result(tmp_path: Path) -> None:
    plan, pdf = _plan(tmp_path)
    sink = Sink()

    def recover(config, **kwargs):
        return RecoveryOutcome(
            OutcomeStatus.EXHAUSTED,
            None,
            Cursor(CursorKind.LINE, 1),
            1,
            0.1,
            "cpu",
        )

    outcome = run_plan(plan, pdf_path=pdf, backend="cpu", recover_fn=recover, event_sink=sink)
    assert outcome.status is OutcomeStatus.EXHAUSTED
    assert sink.events[-1]["payload"]["status"] == "exhausted"


def test_auto_resolves_one_backend_before_recover_and_does_not_retry(tmp_path: Path) -> None:
    plan, pdf = _plan(tmp_path)
    backends = []

    def recover(config, **kwargs):
        backends.append(config.backend)
        raise ToolUnavailable("hashcat failed")

    with pytest.raises(ToolUnavailable):
        run_plan(
            plan,
            pdf_path=pdf,
            recover_fn=recover,
            preflight_fn=lambda _pdf, **kwargs: _preflight(),
        )
    assert backends == [BackendChoice.HASHCAT]


@pytest.mark.parametrize("interrupt", [False, True])
def test_preflight_terminal_failure_is_saved_without_current_stage(
    tmp_path: Path, interrupt: bool
) -> None:
    plan, pdf = _plan(tmp_path)
    store = SessionStore(tmp_path / "state")

    def preflight(_pdf, **kwargs):
        if interrupt:
            raise KeyboardInterrupt
        raise ToolUnavailable("no hashcat")

    with pytest.raises((ToolUnavailable, KeyboardInterrupt)):
        run_plan(
            plan,
            pdf_path=pdf,
            backend=BackendChoice.HASHCAT,
            session="preflight",
            session_store=store,
            preflight_fn=preflight,
        )
    assert store.load("preflight").status.value == ("interrupted" if interrupt else "failed")
