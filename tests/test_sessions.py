from __future__ import annotations

import json
import multiprocessing
import os
from pathlib import Path

import pytest

from pdf_password_recovery import SessionStatus, SessionStore, SessionSummary
from pdf_password_recovery.errors import ActiveSession, ConfigurationError, SessionMismatch


def _hold_session_lock(root: str, name: str, acquired: object, release: object) -> None:
    store = SessionStore(Path(root))
    with store.lock(name):
        acquired.set()
        release.wait(10)


def _summary(
    name: str,
    status: SessionStatus = SessionStatus.RUNNING,
    *,
    completed: int = 1,
    updated_at: str = "2026-08-22T12:34:57Z",
) -> SessionSummary:
    return SessionSummary(
        name=name,
        status=status,
        pdf_display_name="invoice.pdf",
        pdf_fingerprint={"size": 42, "sha256": "a" * 64},
        plan_fingerprint="b" * 64,
        stage_id="dictionary",
        stage_index=0,
        stage_count=2,
        backend="hashcat",
        device_ids=("1",),
        tool_version="7.1.2",
        workload="balanced",
        completed=completed,
        total=100,
        elapsed_seconds=1.5,
        created_at="2026-08-22T12:34:56Z",
        updated_at=updated_at,
    )


def test_session_summary_has_concise_safe_defaults() -> None:
    summary = SessionSummary(name="planned-session")

    assert summary.schema == 1
    assert summary.status is SessionStatus.PLANNED
    assert summary.device_ids == ()
    assert summary.completed == 0
    assert summary.total == 0


@pytest.mark.parametrize("name", ["", ".", "..", "../escape", "nested/name", r"nested\name"])
def test_session_summary_rejects_invalid_session_names(name: str) -> None:
    with pytest.raises(ConfigurationError):
        SessionSummary(name=name)


@pytest.mark.parametrize(
    "overrides",
    [
        {"stage_index": -1},
        {"stage_count": -1},
        {"completed": -1},
        {"total": -1},
        {"elapsed_seconds": -0.1},
    ],
)
def test_session_summary_rejects_negative_progress_values(
    overrides: dict[str, float | int],
) -> None:
    with pytest.raises(ConfigurationError):
        SessionSummary(name="invalid", **overrides)


def test_session_summary_rejects_a_non_string_backend() -> None:
    with pytest.raises(ConfigurationError):
        SessionSummary(name="invalid-backend", backend=1)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "overrides",
    [
        {"pdf_fingerprint": {"note": "密码提示：北京"}},
        {"pdf_fingerprint": {"sha256": "not-a-hash"}},
        {"pdf_fingerprint": {"size": -1}},
        {"pdf_display_name": "C:/private/hint.pdf"},
        {"plan_fingerprint": "$pdf$5*5*example"},
        {"stage_id": "private prompt"},
        {"backend": "custom-backend"},
        {"device_ids": ("密码",)},
        {"tool_version": "version from hint"},
        {"workload": "aggressive"},
    ],
)
def test_session_summary_rejects_unstructured_or_unsafe_fields(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ConfigurationError):
        SessionSummary(name="private", **overrides)  # type: ignore[arg-type]


def test_session_summary_rejection_does_not_echo_sensitive_fingerprint_key() -> None:
    sensitive_key = "$pdf$5*5*example"

    with pytest.raises(ConfigurationError) as raised:
        SessionSummary(name="private", pdf_fingerprint={sensitive_key: "hint"})

    assert sensitive_key not in str(raised.value)


def test_session_summary_schema_is_an_int_one() -> None:
    for schema in (2, 1.0, True):
        with pytest.raises(ConfigurationError):
            SessionSummary(name="schema", schema=schema)  # type: ignore[arg-type]

    assert SessionSummary(name="schema", schema=1).schema == 1


@pytest.mark.parametrize(
    "fingerprint",
    [
        {"value": "$pdf$5*5*example"},
        {"hints_content": "password clue"},
    ],
)
def test_session_summary_rejects_hashes_and_hints_content(
    fingerprint: dict[str, str],
) -> None:
    with pytest.raises(ConfigurationError):
        SessionSummary(name="private", pdf_fingerprint=fingerprint)


def test_session_store_round_trips_summary_and_atomically_replaces_it(tmp_path: Path) -> None:
    store = SessionStore(tmp_path)
    original = _summary("run-1", completed=1)
    replacement = _summary("run-1", completed=57, updated_at="2026-08-22T12:35:00Z")

    store.save(original)
    store.save(replacement)

    summary_path = tmp_path / "sessions" / "run-1" / "summary.json"
    assert store.load("run-1") == replacement
    assert json.loads(summary_path.read_text(encoding="utf-8"))["completed"] == 57
    assert list(summary_path.parent.glob("*.tmp")) == []


@pytest.mark.parametrize(
    "key,value",
    [
        ("token", "$pdf$5*5*example"),
        ("hints_content", "a private clue"),
    ],
)
def test_session_save_rejects_sensitive_data_mutated_after_construction(
    tmp_path: Path,
    key: str,
    value: str,
) -> None:
    fingerprint: dict[str, object] = {"size": 42, "sha256": "a" * 64}
    summary = SessionSummary(name="mutated", pdf_fingerprint=fingerprint)
    fingerprint[key] = value

    with pytest.raises(ConfigurationError):
        SessionStore(tmp_path).save(summary)

    assert not (tmp_path / "sessions" / "mutated" / "summary.json").exists()


def test_session_store_io_errors_do_not_echo_sensitive_paths(tmp_path: Path) -> None:
    sensitive_root = tmp_path / "密码提示-$pdf$"
    sensitive_root.write_text("not a directory", encoding="utf-8")

    with pytest.raises(SessionMismatch) as raised:
        SessionStore(sensitive_root).save(_summary("safe"))

    assert str(sensitive_root) not in str(raised.value)
    assert "$pdf$" not in str(raised.value)


def test_session_save_rejects_nonfinite_json_values(tmp_path: Path) -> None:
    fingerprint: dict[str, object] = {"size": 42, "sha256": "a" * 64}
    summary = SessionSummary(name="nonfinite", pdf_fingerprint=fingerprint)
    fingerprint["size"] = float("inf")

    with pytest.raises(ConfigurationError):
        SessionStore(tmp_path).save(summary)

    assert not (tmp_path / "sessions" / "nonfinite" / "summary.json").exists()


def test_session_save_leaves_no_directory_after_nested_nonfinite_json_failure(
    tmp_path: Path,
) -> None:
    fingerprint: dict[str, object] = {"size": 1}
    summary = SessionSummary(name="nested-nonfinite", pdf_fingerprint=fingerprint)
    fingerprint["size"] = float("nan")
    store = SessionStore(tmp_path)

    with pytest.raises(ConfigurationError):
        store.save(summary)

    assert not (tmp_path / "sessions" / "nested-nonfinite").exists()
    assert store.list() == []


def test_session_store_lists_names_in_deterministic_order(tmp_path: Path) -> None:
    store = SessionStore(tmp_path)
    store.save(_summary("zebra"))
    store.save(_summary("alpha"))

    assert [summary.name for summary in store.list()] == ["alpha", "zebra"]


@pytest.mark.parametrize("content", ["not json", '{"schema": 1}'])
def test_session_store_rejects_malformed_saved_state(tmp_path: Path, content: str) -> None:
    summary_path = tmp_path / "sessions" / "broken" / "summary.json"
    summary_path.parent.mkdir(parents=True)
    summary_path.write_text(content, encoding="utf-8")

    with pytest.raises(SessionMismatch):
        SessionStore(tmp_path).list()


def test_session_store_rejects_a_summary_with_a_different_directory_name(tmp_path: Path) -> None:
    store = SessionStore(tmp_path)
    store.save(_summary("saved-name"))
    summary_path = tmp_path / "sessions" / "saved-name" / "summary.json"
    payload = json.loads(summary_path.read_text(encoding="utf-8"))
    payload["name"] = "forged-name"
    summary_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SessionMismatch):
        store.load("saved-name")


def test_prune_removes_only_terminal_session_summaries(tmp_path: Path) -> None:
    store = SessionStore(tmp_path)
    for name, status in (
        ("planned", SessionStatus.PLANNED),
        ("running", SessionStatus.RUNNING),
        ("interrupted", SessionStatus.INTERRUPTED),
        ("found", SessionStatus.FOUND),
        ("exhausted", SessionStatus.EXHAUSTED),
        ("failed", SessionStatus.FAILED),
    ):
        store.save(_summary(name, status))

    assert store.prune() == ["exhausted", "failed", "found"]
    assert [summary.name for summary in store.list()] == ["interrupted", "planned", "running"]


def test_delete_rejects_traversal_names_without_touching_the_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-summary.json"
    outside.write_text("keep", encoding="utf-8")

    with pytest.raises(ConfigurationError):
        SessionStore(tmp_path).delete("../outside")

    assert outside.read_text(encoding="utf-8") == "keep"


def test_delete_rejects_a_session_symlink_that_escapes_the_store_root(tmp_path: Path) -> None:
    root = tmp_path / "state"
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")
    sessions_root = root / "sessions"
    sessions_root.mkdir(parents=True)
    link = sessions_root / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks are unavailable in this environment: {exc}")

    with pytest.raises(SessionMismatch):
        SessionStore(root).delete("linked")

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_delete_refuses_unknown_session_contents_instead_of_recursing(tmp_path: Path) -> None:
    store = SessionStore(tmp_path)
    store.save(_summary("preserve"))
    extra = tmp_path / "sessions" / "preserve" / "keep.txt"
    extra.write_text("keep", encoding="utf-8")

    with pytest.raises(SessionMismatch):
        store.delete("preserve")

    assert extra.read_text(encoding="utf-8") == "keep"
    assert store.load("preserve").name == "preserve"


def test_active_lock_prevents_a_second_lock_and_delete_then_release_allows_delete(
    tmp_path: Path,
) -> None:
    store = SessionStore(tmp_path)
    store.save(_summary("active"))

    with store.lock("active"):
        with pytest.raises(ActiveSession) as second_lock, store.lock("active"):
            pass
        assert second_lock.value.code == "active_session"
        with pytest.raises(ActiveSession):
            store.delete("active")

    metadata = json.loads(
        (tmp_path / "sessions" / "active" / "active.lock").read_text(encoding="utf-8")
    )
    assert metadata["pid"] == os.getpid()
    assert metadata["timestamp"].endswith("Z")
    store.delete("active")

    assert not (tmp_path / "sessions" / "active").exists()


def test_second_process_cannot_lock_or_delete_a_held_session(tmp_path: Path) -> None:
    store = SessionStore(tmp_path)
    store.save(_summary("cross-process"))
    context = multiprocessing.get_context("spawn")
    acquired = context.Event()
    release = context.Event()
    process = context.Process(
        target=_hold_session_lock,
        args=(str(tmp_path), "cross-process", acquired, release),
    )
    process.start()
    try:
        assert acquired.wait(timeout=10)
        with pytest.raises(ActiveSession), store.lock("cross-process"):
            pass
        with pytest.raises(ActiveSession):
            store.delete("cross-process")
    finally:
        release.set()
        process.join(timeout=10)
        if process.is_alive():
            process.terminate()
            process.join(timeout=10)

    assert process.exitcode == 0
    store.delete("cross-process")
