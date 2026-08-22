from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TypeAlias

from .errors import ConfigurationError


class AttackKind(StrEnum):
    DICTIONARY = "dictionary"
    MASK = "mask"
    BRUTE = "brute"


class BackendChoice(StrEnum):
    AUTO = "auto"
    HASHCAT = "hashcat"
    CPU = "cpu"


class SessionStatus(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    INTERRUPTED = "interrupted"
    FOUND = "found"
    EXHAUSTED = "exhausted"
    FAILED = "failed"


class OutcomeStatus(StrEnum):
    FOUND = "found"
    EXHAUSTED = "exhausted"
    INTERRUPTED = "interrupted"


class CursorKind(StrEnum):
    INDEX = "index"
    LINE = "line"


@dataclass(frozen=True, slots=True)
class DictionaryAttack:
    wordlist: Path
    encoding: str = "utf-8"
    min_length: int | None = None
    max_length: int | None = None
    apply_rules: bool = False

    def __post_init__(self) -> None:
        if (self.min_length is None) != (self.max_length is None):
            raise ConfigurationError("dictionary length bounds must be provided together")
        if self.min_length is not None and self.max_length is not None:
            if self.min_length < 1 or self.max_length < 1:
                raise ConfigurationError("dictionary length bounds must be at least 1")
            if self.max_length < self.min_length:
                raise ConfigurationError(
                    "dictionary maximum length cannot be less than minimum length"
                )

    @property
    def kind(self) -> AttackKind:
        return AttackKind.DICTIONARY


@dataclass(frozen=True, slots=True)
class MaskAttack:
    mask: str

    @property
    def kind(self) -> AttackKind:
        return AttackKind.MASK


@dataclass(frozen=True, slots=True)
class BruteAttack:
    charset: str = "alnum"
    min_length: int = 4
    max_length: int = 6

    @property
    def kind(self) -> AttackKind:
        return AttackKind.BRUTE


AttackSpec: TypeAlias = DictionaryAttack | MaskAttack | BruteAttack


@dataclass(frozen=True, slots=True)
class RecoveryConfig:
    pdf_path: Path
    attack: AttackSpec
    backend: BackendChoice = BackendChoice.AUTO
    workers: int = 1
    session: str | None = None
    resume: bool = False
    output: Path | None = None
    assume_yes: bool = False

    def __post_init__(self) -> None:
        if self.workers < 1:
            raise ConfigurationError("workers must be at least 1")
        if self.resume and not self.session:
            raise ConfigurationError("--resume requires --session")


@dataclass(frozen=True, slots=True)
class Cursor:
    kind: CursorKind
    value: int

    def __post_init__(self) -> None:
        if self.value < 0:
            raise ConfigurationError("cursor cannot be negative")


@dataclass(frozen=True, slots=True)
class IndexRange:
    start: int
    stop: int

    def __post_init__(self) -> None:
        if self.start < 0 or self.stop < self.start:
            raise ConfigurationError("invalid index range")


@dataclass(frozen=True, slots=True)
class Progress:
    completed: int
    total: int
    attempted: int
    elapsed: float
    rate: float
    backend: str
    workers: int


@dataclass(frozen=True, slots=True)
class RecoveryOutcome:
    status: OutcomeStatus
    password: str | None
    cursor: Cursor
    attempted: int
    elapsed: float
    backend: str


_SESSION_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_SUMMARY_SENSITIVE_KEYS = frozenset({"password", "pdf_hash", "extracted_hash", "hints"})


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class SessionSummary:
    name: str
    schema: int = 1
    status: SessionStatus = SessionStatus.PLANNED
    pdf_display_name: str = ""
    pdf_fingerprint: Mapping[str, object] = field(default_factory=dict)
    plan_fingerprint: str = ""
    stage_id: str | None = None
    stage_index: int = 0
    stage_count: int = 0
    backend: str = ""
    device_ids: tuple[str, ...] = ()
    tool_version: str | None = None
    workload: str | None = None
    completed: int = 0
    total: int = 0
    elapsed_seconds: float = 0.0
    created_at: str = field(default_factory=_utc_timestamp)
    updated_at: str = field(default_factory=_utc_timestamp)

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if not isinstance(self.name, str) or not _SESSION_NAME.fullmatch(self.name):
            raise ConfigurationError(
                "session name may contain only letters, digits, '.', '_' and '-'"
            )
        if self.name in {".", ".."}:
            raise ConfigurationError("session name may not be '.' or '..'")
        if isinstance(self.schema, bool) or self.schema != 1:
            raise ConfigurationError("session schema must be 1")
        if not isinstance(self.status, SessionStatus):
            raise ConfigurationError("session status must be a SessionStatus")
        if not isinstance(self.pdf_display_name, str):
            raise ConfigurationError("PDF display name must be a string")
        if not isinstance(self.pdf_fingerprint, Mapping):
            raise ConfigurationError("PDF fingerprint must be a mapping")
        if not isinstance(self.plan_fingerprint, str):
            raise ConfigurationError("plan fingerprint must be a string")
        if self.stage_id is not None and not isinstance(self.stage_id, str):
            raise ConfigurationError("stage ID must be a string or null")
        if not isinstance(self.backend, str):
            raise ConfigurationError("backend must be a string")
        for field_name in ("stage_index", "stage_count", "completed", "total"):
            _require_non_negative_int(field_name, getattr(self, field_name))
        if isinstance(self.elapsed_seconds, bool) or not isinstance(
            self.elapsed_seconds, (int, float)
        ):
            raise ConfigurationError("elapsed seconds must be a number")
        if not math.isfinite(self.elapsed_seconds) or self.elapsed_seconds < 0:
            raise ConfigurationError("elapsed seconds cannot be negative")
        if not isinstance(self.device_ids, tuple) or not all(
            isinstance(device_id, str) for device_id in self.device_ids
        ):
            raise ConfigurationError("device IDs must be a tuple of strings")
        if self.tool_version is not None and not isinstance(self.tool_version, str):
            raise ConfigurationError("tool version must be a string or null")
        if self.workload is not None and not isinstance(self.workload, str):
            raise ConfigurationError("workload must be a string or null")
        for value in (
            self.pdf_display_name,
            self.pdf_fingerprint,
            self.plan_fingerprint,
            self.stage_id,
            self.backend,
            self.device_ids,
            self.tool_version,
            self.workload,
        ):
            _reject_summary_sensitive_data(value)
        _validate_utc_timestamp(self.created_at, "created timestamp")
        _validate_utc_timestamp(self.updated_at, "updated timestamp")


def _require_non_negative_int(field_name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{field_name} must be an integer")
    if value < 0:
        raise ConfigurationError(f"{field_name} cannot be negative")


def _validate_utc_timestamp(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ConfigurationError(f"{field_name} must be UTC ISO-8601 ending in Z")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ConfigurationError(f"{field_name} must be UTC ISO-8601 ending in Z") from exc
    if parsed.tzinfo != UTC or parsed.utcoffset() != UTC.utcoffset(None):
        raise ConfigurationError(f"{field_name} must be UTC ISO-8601 ending in Z")


def _reject_summary_sensitive_data(value: object) -> None:
    if isinstance(value, str):
        if "$pdf$" in value:
            raise ConfigurationError("session summary may not contain an extracted PDF hash")
    elif isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = key.casefold() if isinstance(key, str) else ""
            if normalized in _SUMMARY_SENSITIVE_KEYS or "hint" in normalized:
                raise ConfigurationError(f"session summary may not contain '{key}'")
            _reject_summary_sensitive_data(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _reject_summary_sensitive_data(nested)
