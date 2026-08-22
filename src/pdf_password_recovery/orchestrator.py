from __future__ import annotations

import os
import time
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path

from .backends.hashcat_info import PreflightReport, run_preflight
from .errors import RecoveryError, ToolUnavailable
from .events import EventMessage, EventSink, EventType, RecoveryEvent
from .models import (
    BackendChoice,
    CompiledPlan,
    CompiledStage,
    OutcomeStatus,
    Progress,
    RecoveryConfig,
    RecoveryOutcome,
    SessionStatus,
    SessionSummary,
    WorkloadProfile,
)
from .service import recover
from .sessions import SessionStore


def _state_root() -> Path:
    configured = os.environ.get("PDF_PASSWORD_RECOVERY_STATE_DIR")
    if configured:
        return Path(configured)
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "pdf-password-recovery"
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / (
        "pdf-password-recovery"
    )


def _emit(
    sink: EventSink | None, event_type: EventType, payload: dict[str, object], session: str | None
) -> None:
    if sink is not None:
        sink.emit(RecoveryEvent(event_type, payload, session=session))


def _event_stage_id(value: str) -> str:
    return (
        "".join(char if char.isalnum() or char in "._-" else "-" for char in value)[:64] or "stage"
    )


def _event_backend(value: str, fallback: str = "auto") -> str:
    return value if value in {"auto", "cpu", "hashcat"} else fallback


def _artifact_name(value: Path) -> str:
    name = value.name or "password.txt"
    safe = "".join(char if char.isalnum() or char in "._-" else "-" for char in name)
    return safe or "password.txt"


def _preflight_payload(report: PreflightReport) -> dict[str, object]:
    return {
        "status": "ready",
        "backend": "hashcat",
        "device_ids": [device.id for device in report.selected_devices],
        "tool_version": report.capabilities.version,
        "workload": report.workload.value,
        "pdf_mode": report.pdf_mode,
    }


def _error_message(exc: BaseException) -> EventMessage:
    if isinstance(exc, RecoveryError) and getattr(exc, "code", "") == "configuration":
        return EventMessage.CONFIGURATION_INVALID
    if isinstance(exc, ToolUnavailable):
        return EventMessage.HASHCAT_UNAVAILABLE
    return EventMessage.STAGE_FAILED


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, ToolUnavailable):
        return "tool_unavailable"
    code = getattr(exc, "code", "execution")
    return code if isinstance(code, str) else "execution"


def _summary(
    name: str,
    pdf_path: Path,
    plan: CompiledPlan,
    workload: WorkloadProfile,
    backend: BackendChoice,
    stage: CompiledStage | None = None,
    status: SessionStatus = SessionStatus.PLANNED,
    attempted: int = 0,
    total: int = 0,
    elapsed: float = 0.0,
) -> SessionSummary:
    from .checkpoint import file_fingerprint

    fingerprint = file_fingerprint(pdf_path)
    return SessionSummary(
        name=name,
        status=status,
        pdf_display_name=pdf_path.name,
        pdf_fingerprint={"size": fingerprint.size, "sha256": fingerprint.sha256},
        plan_fingerprint=plan.fingerprint,
        stage_id=_event_stage_id(stage.id) if stage else None,
        stage_index=next(
            (index for index, item in enumerate(plan.stages) if item.id == stage.id), 0
        )
        if stage
        else 0,
        stage_count=len(plan.stages),
        backend=backend.value,
        workload=workload.value,
        completed=attempted,
        total=total,
        elapsed_seconds=elapsed,
    )


def run_plan(
    compiled_plan: CompiledPlan,
    *,
    pdf_path: Path,
    backend: BackendChoice = BackendChoice.AUTO,
    workers: int = 1,
    workload: WorkloadProfile = WorkloadProfile.BALANCED,
    requested_devices: str = "auto",
    session: str | None = None,
    output: Path | None = None,
    event_sink: EventSink | None = None,
    session_store: SessionStore | None = None,
    recover_fn: Callable[..., RecoveryOutcome] = recover,
    preflight_fn: Callable[..., PreflightReport] = run_preflight,
) -> RecoveryOutcome:
    """Execute compiled stages serially while adapting legacy recovery callbacks."""
    backend = BackendChoice(backend)
    workload = WorkloadProfile(workload)
    store = session_store or SessionStore(_state_root())
    lock = store.lock(session) if session else nullcontext()
    started = time.monotonic()
    attempted_total = 0
    last: RecoveryOutcome | None = None
    current: CompiledStage | None = None
    preflight: PreflightReport | None = None
    hashcat_ready = backend is BackendChoice.CPU
    try:
        with lock:
            if session:
                store.save(_summary(session, Path(pdf_path), compiled_plan, workload, backend))
            may_use_hashcat = backend is not BackendChoice.CPU
            if may_use_hashcat:
                try:
                    preflight = preflight_fn(
                        Path(pdf_path), workload=workload, requested_devices=requested_devices
                    )
                    hashcat_ready = True
                    _emit(event_sink, EventType.PREFLIGHT, _preflight_payload(preflight), session)
                except Exception:
                    _emit(
                        event_sink,
                        EventType.PREFLIGHT,
                        {
                            "status": "unavailable",
                            "backend": "hashcat",
                            "device_ids": [],
                            "tool_version": "0.0",
                            "workload": workload.value,
                        },
                        session,
                    )
                    _emit(
                        event_sink,
                        EventType.WARNING,
                        {
                            "code": "hashcat_unavailable",
                            "message": EventMessage.HASHCAT_UNAVAILABLE,
                        },
                        session,
                    )
                    if backend is BackendChoice.HASHCAT:
                        raise

            for index, stage in enumerate(compiled_plan.stages):
                current = stage
                stage_id = _event_stage_id(stage.id)
                if backend is BackendChoice.CPU and not stage.cpu_compatible:
                    raise ToolUnavailable(f"stage '{stage.id}' requires hashcat")
                if backend is BackendChoice.AUTO and not stage.cpu_compatible and not hashcat_ready:
                    raise ToolUnavailable(f"stage '{stage.id}' requires hashcat")
                stage_backend_choice = (
                    BackendChoice.HASHCAT
                    if backend is not BackendChoice.CPU and hashcat_ready
                    else BackendChoice.CPU
                )
                stage_backend = stage_backend_choice.value
                _emit(
                    event_sink,
                    EventType.STAGE_STARTED,
                    {
                        "stage_id": stage_id,
                        "stage_index": index,
                        "stage_count": len(compiled_plan.stages),
                        "backend": stage_backend,
                        "workload": workload.value,
                        "total": stage.keyspace,
                    },
                    session,
                )
                if session:
                    store.save(
                        _summary(
                            session,
                            Path(pdf_path),
                            compiled_plan,
                            workload,
                            backend,
                            stage,
                            SessionStatus.RUNNING,
                            attempted_total,
                            stage.keyspace,
                            time.monotonic() - started,
                        )
                    )

                def progress(
                    value: Progress,
                    _stage_id: str = stage_id,
                    _attempted_total: int = attempted_total,
                    _stage_backend: str = stage_backend,
                ) -> None:
                    _emit(
                        event_sink,
                        EventType.PROGRESS,
                        {
                            "stage_id": _stage_id,
                            "completed": value.completed,
                            "total": value.total,
                            "attempted": _attempted_total + value.attempted,
                            "elapsed_seconds": value.elapsed,
                            "rate": value.rate,
                            "backend": _event_backend(value.backend, _stage_backend),
                            "workers": value.workers,
                        },
                        session,
                    )

                config = RecoveryConfig(
                    Path(pdf_path),
                    stage.attack,
                    backend=stage_backend_choice,
                    workers=workers,
                    session=session,
                    output=output,
                    workload=workload,
                    device=requested_devices,
                )
                try:
                    outcome = recover_fn(config, progress=progress)
                except KeyboardInterrupt:
                    _emit(
                        event_sink,
                        EventType.CHECKPOINT,
                        {
                            "stage_id": stage_id,
                            "completed": 0,
                            "total": stage.keyspace,
                            "checkpoint_status": "saved",
                        },
                        session,
                    )
                    raise
                attempted_total += max(0, outcome.attempted)
                last = replace(outcome, attempted=attempted_total)
                if outcome.status is OutcomeStatus.INTERRUPTED:
                    if session:
                        store.save(
                            _summary(
                                session,
                                Path(pdf_path),
                                compiled_plan,
                                workload,
                                backend,
                                stage,
                                SessionStatus.INTERRUPTED,
                                attempted_total,
                                stage.keyspace,
                                time.monotonic() - started,
                            )
                        )
                    _emit(
                        event_sink,
                        EventType.CHECKPOINT,
                        {
                            "stage_id": stage_id,
                            "completed": outcome.cursor.value,
                            "total": stage.keyspace,
                            "checkpoint_status": "saved",
                        },
                        session,
                    )
                    _emit(
                        event_sink,
                        EventType.RESULT,
                        {
                            "status": "interrupted",
                            "stage_id": stage_id,
                            "attempted": attempted_total,
                            "elapsed_seconds": time.monotonic() - started,
                            "backend": _event_backend(outcome.backend, stage_backend),
                        },
                        session,
                    )
                    return last
                if outcome.status is OutcomeStatus.FOUND:
                    if output and outcome.password is not None:
                        from .cli import _write_password

                        _write_password(output, outcome.password)
                    if session:
                        store.save(
                            _summary(
                                session,
                                Path(pdf_path),
                                compiled_plan,
                                workload,
                                backend,
                                stage,
                                SessionStatus.FOUND,
                                attempted_total,
                                stage.keyspace,
                                time.monotonic() - started,
                            )
                        )
                    payload: dict[str, object] = {
                        "status": "found",
                        "stage_id": stage_id,
                        "attempted": attempted_total,
                        "elapsed_seconds": time.monotonic() - started,
                        "backend": _event_backend(outcome.backend, stage_backend),
                    }
                    if output is not None:
                        payload["output_path"] = f"artifacts/{_artifact_name(output)}"
                    _emit(event_sink, EventType.RESULT, payload, session)
                    return last
            assert last is not None
            if session:
                store.save(
                    _summary(
                        session,
                        Path(pdf_path),
                        compiled_plan,
                        workload,
                        backend,
                        current,
                        SessionStatus.EXHAUSTED,
                        attempted_total,
                        current.keyspace if current else 0,
                        time.monotonic() - started,
                    )
                )
            _emit(
                event_sink,
                EventType.RESULT,
                {
                    "status": "exhausted",
                    "stage_id": _event_stage_id(
                        current.id if current else compiled_plan.stages[-1].id
                    ),
                    "attempted": attempted_total,
                    "elapsed_seconds": time.monotonic() - started,
                    "backend": _event_backend(last.backend),
                },
                session,
            )
            return replace(last, attempted=attempted_total)
    except KeyboardInterrupt:
        if session:
            store.save(
                _summary(
                    session,
                    Path(pdf_path),
                    compiled_plan,
                    workload,
                    backend,
                    current,
                    SessionStatus.INTERRUPTED,
                    attempted_total,
                    current.keyspace if current else 0,
                    time.monotonic() - started,
                )
            )
        if current is not None:
            _emit(
                event_sink,
                EventType.CHECKPOINT,
                {
                    "stage_id": _event_stage_id(current.id),
                    "completed": 0,
                    "total": current.keyspace,
                    "checkpoint_status": "saved",
                },
                session,
            )
            _emit(
                event_sink,
                EventType.RESULT,
                {
                    "status": "interrupted",
                    "stage_id": _event_stage_id(current.id),
                    "attempted": attempted_total,
                    "elapsed_seconds": time.monotonic() - started,
                    "backend": backend.value,
                },
                session,
            )
        raise
    except Exception as exc:
        if session:
            store.save(
                _summary(
                    session,
                    Path(pdf_path),
                    compiled_plan,
                    workload,
                    backend,
                    current,
                    SessionStatus.FAILED,
                    attempted_total,
                    current.keyspace if current else 0,
                    time.monotonic() - started,
                )
            )
        _emit(
            event_sink,
            EventType.ERROR,
            {
                "code": _error_code(exc),
                "message": _error_message(exc),
                **({"stage_id": _event_stage_id(current.id)} if current else {}),
            },
            session,
        )
        raise
