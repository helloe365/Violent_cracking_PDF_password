from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from pdf_password_recovery import SessionStatus, SessionStore, SessionSummary
from pdf_password_recovery.errors import ActiveSession, ConfigurationError, SessionMismatch


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
