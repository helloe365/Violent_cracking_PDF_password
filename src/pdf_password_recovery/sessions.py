from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

from .errors import ActiveSession, ConfigurationError, SessionMismatch
from .models import SessionStatus, SessionSummary, _utc_timestamp

_SESSION_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_SUMMARY_FILE = "summary.json"
_LOCK_FILE = "active.lock"
_SUMMARY_KEYS = frozenset(
    {
        "schema",
        "name",
        "status",
        "pdf_display_name",
        "pdf_fingerprint",
        "plan_fingerprint",
        "stage_id",
        "stage_index",
        "stage_count",
        "backend",
        "device_ids",
        "tool_version",
        "workload",
        "completed",
        "total",
        "elapsed_seconds",
        "created_at",
        "updated_at",
    }
)
_TERMINAL_STATUSES = frozenset({SessionStatus.FOUND, SessionStatus.EXHAUSTED, SessionStatus.FAILED})


class SessionStore:
    """Persist safe, human-readable summaries under one state root."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def save(self, summary: SessionSummary) -> None:
        session_dir, summary_path, _ = self._paths(summary.name)
        self._assert_safe_target(session_dir)
        self._assert_safe_target(summary_path)
        try:
            session_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SessionMismatch(
                f"cannot create session directory '{session_dir}': {exc}"
            ) from exc
        self._assert_safe_target(session_dir)
        self._assert_safe_target(summary_path)
        _atomic_write(summary_path, _summary_payload(summary))

    def load(self, name: str) -> SessionSummary:
        _, summary_path, _ = self._paths(name)
        self._assert_safe_target(summary_path)
        try:
            with summary_path.open("r", encoding="utf-8") as stream:
                payload = json.load(stream)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SessionMismatch(f"cannot load session summary '{name}': {exc}") from exc
        try:
            summary = _summary_from_payload(payload)
        except (KeyError, TypeError, ValueError, ConfigurationError) as exc:
            raise SessionMismatch(f"invalid session summary '{name}': {exc}") from exc
        if summary.name != name:
            raise SessionMismatch("summary name does not match its session directory")
        return summary

    def list(self) -> list[SessionSummary]:
        sessions_root = self._sessions_root
        self._assert_safe_target(sessions_root)
        if not sessions_root.exists():
            return []
        if not sessions_root.is_dir():
            raise SessionMismatch("sessions root is not a directory")

        summaries: list[SessionSummary] = []
        try:
            entries = sorted(sessions_root.iterdir(), key=lambda entry: entry.name)
        except OSError as exc:
            raise SessionMismatch(f"cannot list sessions: {exc}") from exc
        for entry in entries:
            self._assert_safe_target(entry)
            if not entry.is_dir():
                raise SessionMismatch(f"invalid session entry '{entry.name}'")
            try:
                _validate_session_name(entry.name)
            except ConfigurationError as exc:
                raise SessionMismatch(f"invalid session entry '{entry.name}'") from exc
            summaries.append(self.load(entry.name))
        return summaries

    def delete(self, name: str) -> None:
        session_dir, summary_path, lock_path = self._paths(name)
        self._assert_safe_target(session_dir)
        self._assert_safe_target(summary_path)
        self._assert_safe_target(lock_path)
        if not session_dir.is_dir():
            raise SessionMismatch(f"session '{name}' does not exist")
        self._assert_only_known_files(session_dir)

        try:
            stream = lock_path.open("a+b")
        except OSError as exc:
            raise SessionMismatch(f"cannot inspect active session lock '{name}': {exc}") from exc
        try:
            _acquire_lock(stream, name)
            try:
                self._assert_safe_target(summary_path)
                if summary_path.exists():
                    summary_path.unlink()
            finally:
                _release_lock(stream)
        except OSError as exc:
            raise SessionMismatch(f"cannot delete session summary '{name}': {exc}") from exc
        finally:
            stream.close()

        self._assert_safe_target(lock_path)
        try:
            lock_path.unlink(missing_ok=True)
            session_dir.rmdir()
        except OSError as exc:
            raise SessionMismatch(f"cannot remove session '{name}': {exc}") from exc

    def prune(self) -> list[str]:
        deleted: list[str] = []
        for summary in self.list():
            if summary.status in _TERMINAL_STATUSES:
                self.delete(summary.name)
                deleted.append(summary.name)
        return deleted

    @contextmanager
    def lock(self, name: str) -> Iterator[None]:
        session_dir, _, lock_path = self._paths(name)
        self._assert_safe_target(session_dir)
        self._assert_safe_target(lock_path)
        try:
            session_dir.mkdir(parents=True, exist_ok=True)
            self._assert_safe_target(lock_path)
            stream = lock_path.open("a+b")
        except OSError as exc:
            raise SessionMismatch(f"cannot create session lock '{name}': {exc}") from exc
        try:
            _acquire_lock(stream, name)
            try:
                _write_lock_metadata(stream)
                yield
            finally:
                _release_lock(stream)
        finally:
            stream.close()

    @property
    def _sessions_root(self) -> Path:
        return self.root / "sessions"

    def _paths(self, name: str) -> tuple[Path, Path, Path]:
        validated = _validate_session_name(name)
        session_dir = self._sessions_root / validated
        return session_dir, session_dir / _SUMMARY_FILE, session_dir / _LOCK_FILE

    def _assert_only_known_files(self, session_dir: Path) -> None:
        try:
            entries = list(session_dir.iterdir())
        except OSError as exc:
            raise SessionMismatch(
                f"cannot inspect session directory '{session_dir}': {exc}"
            ) from exc
        known = {_SUMMARY_FILE, _LOCK_FILE}
        if any(entry.name not in known for entry in entries):
            raise SessionMismatch("session directory contains unexpected files")
        for entry in entries:
            self._assert_safe_target(entry)
            if not entry.is_file():
                raise SessionMismatch("session directory contains an invalid entry")

    def _assert_safe_target(self, target: Path) -> None:
        raw_root = self.root.absolute()
        raw_target = Path(target).absolute()
        try:
            relative = raw_target.relative_to(raw_root)
        except ValueError as exc:
            raise SessionMismatch("session target escapes the configured root") from exc

        current = raw_root
        if _is_link_or_reparse(current):
            raise SessionMismatch("configured session root may not be a link or reparse point")
        for component in relative.parts:
            current = current / component
            if _is_link_or_reparse(current):
                raise SessionMismatch("session target may not be a link or reparse point")

        resolved_root = raw_root.resolve(strict=False)
        resolved_target = raw_target.resolve(strict=False)
        if not resolved_target.is_relative_to(resolved_root):
            raise SessionMismatch("session target escapes the configured root")


def _validate_session_name(name: str) -> str:
    if not isinstance(name, str) or not _SESSION_NAME.fullmatch(name) or name in {".", ".."}:
        raise ConfigurationError("session name may contain only letters, digits, '.', '_' and '-'")
    return name


def _summary_payload(summary: SessionSummary) -> dict[str, object]:
    return {
        "schema": summary.schema,
        "name": summary.name,
        "status": summary.status.value,
        "pdf_display_name": summary.pdf_display_name,
        "pdf_fingerprint": summary.pdf_fingerprint,
        "plan_fingerprint": summary.plan_fingerprint,
        "stage_id": summary.stage_id,
        "stage_index": summary.stage_index,
        "stage_count": summary.stage_count,
        "backend": summary.backend,
        "device_ids": list(summary.device_ids),
        "tool_version": summary.tool_version,
        "workload": summary.workload,
        "completed": summary.completed,
        "total": summary.total,
        "elapsed_seconds": summary.elapsed_seconds,
        "created_at": summary.created_at,
        "updated_at": summary.updated_at,
    }


def _summary_from_payload(payload: object) -> SessionSummary:
    mapping = _require_mapping(payload, "summary")
    if set(mapping) != _SUMMARY_KEYS:
        raise ValueError("summary has missing or unknown fields")
    device_ids = mapping["device_ids"]
    if not isinstance(device_ids, list) or not all(isinstance(value, str) for value in device_ids):
        raise TypeError("device_ids must be an array of strings")
    return SessionSummary(
        schema=_require_int(mapping, "schema"),
        name=_require_str(mapping, "name"),
        status=SessionStatus(_require_str(mapping, "status")),
        pdf_display_name=_require_str(mapping, "pdf_display_name"),
        pdf_fingerprint=_require_mapping(mapping["pdf_fingerprint"], "pdf_fingerprint"),
        plan_fingerprint=_require_str(mapping, "plan_fingerprint"),
        stage_id=_require_optional_str(mapping, "stage_id"),
        stage_index=_require_int(mapping, "stage_index"),
        stage_count=_require_int(mapping, "stage_count"),
        backend=_require_str(mapping, "backend"),
        device_ids=tuple(device_ids),
        tool_version=_require_optional_str(mapping, "tool_version"),
        workload=_require_optional_str(mapping, "workload"),
        completed=_require_int(mapping, "completed"),
        total=_require_int(mapping, "total"),
        elapsed_seconds=_require_number(mapping, "elapsed_seconds"),
        created_at=_require_str(mapping, "created_at"),
        updated_at=_require_str(mapping, "updated_at"),
    )


def _atomic_write(path: Path, payload: Mapping[str, object]) -> None:
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
    except OSError as exc:
        raise SessionMismatch(f"cannot prepare session summary '{path}': {exc}") from exc
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except (OSError, TypeError, ValueError) as exc:
        raise SessionMismatch(f"cannot save session summary '{path}': {exc}") from exc
    finally:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)


def _write_lock_metadata(stream: Any) -> None:
    payload = json.dumps(
        {"pid": os.getpid(), "timestamp": _utc_timestamp()},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    stream.seek(0)
    stream.truncate()
    stream.write(payload)
    stream.flush()
    os.fsync(stream.fileno())


def _acquire_lock(stream: Any, name: str) -> None:
    try:
        stream.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        raise ActiveSession(f"session '{name}' is active") from exc


def _release_lock(stream: Any) -> None:
    stream.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _is_link_or_reparse(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(details.st_mode) or bool(
        getattr(details, "st_file_attributes", 0) & reparse_flag
    )


def _require_mapping(value: object, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise TypeError(f"{field_name} must be an object")
    return value


def _require_str(mapping: Mapping[str, object], key: str) -> str:
    value = mapping[key]
    if not isinstance(value, str):
        raise TypeError(f"{key} must be a string")
    return value


def _require_optional_str(mapping: Mapping[str, object], key: str) -> str | None:
    value = mapping[key]
    if value is not None and not isinstance(value, str):
        raise TypeError(f"{key} must be a string or null")
    return value


def _require_int(mapping: Mapping[str, object], key: str) -> int:
    value = mapping[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{key} must be an integer")
    return value


def _require_number(mapping: Mapping[str, object], key: str) -> float:
    value = mapping[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{key} must be a number")
    return float(value)


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    try:
        descriptor = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
