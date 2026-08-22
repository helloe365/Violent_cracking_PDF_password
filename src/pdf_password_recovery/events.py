from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol, TextIO

from .errors import ConfigurationError


class EventType(StrEnum):
    PREFLIGHT = "preflight"
    STAGE_STARTED = "stage_started"
    PROGRESS = "progress"
    WARNING = "warning"
    CHECKPOINT = "checkpoint"
    RESULT = "result"
    ERROR = "error"


class EventMessage(StrEnum):
    """Fixed, non-sensitive messages that may be written to JSONL events."""

    READY = "已就绪"
    HASHCAT_UNAVAILABLE = "hashcat_unavailable"
    CONFIGURATION_INVALID = "configuration_invalid"
    CHECKPOINT_SAVED = "checkpoint_saved"
    STAGE_FAILED = "stage_failed"


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class RecoveryEvent:
    type: EventType
    payload: Mapping[str, object] = field(default_factory=dict)
    timestamp: str = field(default_factory=_utc_timestamp)
    session: str | None = None
    schema: int = 1

    def __post_init__(self) -> None:
        if isinstance(self.schema, bool) or not isinstance(self.schema, int) or self.schema != 1:
            raise ConfigurationError("event schema must be 1")
        if not isinstance(self.type, EventType):
            raise ConfigurationError("event type must be an EventType")
        if not isinstance(self.payload, Mapping):
            raise ConfigurationError("event payload must be a mapping")
        _validate_session(self.session)
        if not isinstance(self.timestamp, str) or not self.timestamp.endswith("Z"):
            raise ConfigurationError("event timestamp must be UTC ISO-8601 ending in Z")
        try:
            parsed = datetime.fromisoformat(self.timestamp.removesuffix("Z") + "+00:00")
        except ValueError as exc:
            raise ConfigurationError("event timestamp must be UTC ISO-8601 ending in Z") from exc
        if parsed.tzinfo != UTC or parsed.utcoffset() != UTC.utcoffset(None):
            raise ConfigurationError("event timestamp must be UTC ISO-8601 ending in Z")
        _validate_payload(self.type, self.payload)


class EventSink(Protocol):
    def emit(self, event: RecoveryEvent) -> None: ...


@dataclass(slots=True)
class JsonLineSink:
    stream: TextIO

    def emit(self, event: RecoveryEvent) -> None:
        try:
            line = json.dumps(
                event_payload(event),
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ConfigurationError("event payload is not valid JSON") from exc
        self.stream.write(line + "\n")
        self.stream.flush()


def event_payload(event: RecoveryEvent) -> dict[str, object]:
    """Convert an event to the fixed schema-1 JSONL payload."""
    _validate_session(event.session)
    _validate_payload(event.type, event.payload)
    return {
        "schema": event.schema,
        "type": event.type.value,
        "timestamp": event.timestamp,
        "session": event.session,
        "payload": event.payload,
    }


_SESSION_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9._-]+)?$")
_ARTIFACT_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_BACKENDS = frozenset({"auto", "cpu", "hashcat"})
_WORKLOADS = frozenset({"quiet", "balanced", "fast"})
_PREFLIGHT_STATUSES = frozenset({"ready", "unavailable"})
_RESULT_STATUSES = frozenset({"found", "exhausted", "interrupted", "failed"})
_CHECKPOINT_STATUSES = frozenset({"saved", "cleared"})


def _validate_payload(event_type: EventType, payload: Mapping[str, object]) -> None:
    """Apply the closed, event-specific JSONL payload contract."""
    validators = _PAYLOAD_VALIDATORS[event_type]
    for key, value in payload.items():
        validator = validators.get(key)
        if validator is None:
            raise ConfigurationError("event payload contains an unsupported field")
        validator(value)


def _validate_session(session: str | None) -> None:
    if session is None:
        return
    if not isinstance(session, str) or _SESSION_IDENTIFIER.fullmatch(session) is None:
        raise ConfigurationError("event session must be a safe identifier or null")


def _validate_identifier(value: object) -> None:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ConfigurationError("event identifiers must be safe machine identifiers")


def _validate_code(value: object) -> None:
    if not isinstance(value, str) or _CODE.fullmatch(value) is None:
        raise ConfigurationError("event codes must be lowercase machine identifiers")


def _validate_choice(choices: frozenset[str]):
    def validate(value: object) -> None:
        if not isinstance(value, str) or value not in choices:
            raise ConfigurationError("event value is not an allowed fixed choice")

    return validate


def _validate_version(value: object) -> None:
    if not isinstance(value, str) or _VERSION.fullmatch(value) is None:
        raise ConfigurationError("event tool_version must be a version identifier")


def _validate_message(value: object) -> None:
    if not isinstance(value, EventMessage):
        raise ConfigurationError("event messages must be fixed EventMessage values")


def _validate_nonnegative_int(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigurationError("event counter values must be non-negative integers")


def _validate_nonnegative_number(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError("event measurements must be non-negative finite numbers")
    if not math.isfinite(value) or value < 0:
        raise ConfigurationError("event measurements must be non-negative finite numbers")


def _validate_device_ids(value: object) -> None:
    if not isinstance(value, (list, tuple)):
        raise ConfigurationError("event device_ids must be a list of safe identifiers")
    for device_id in value:
        _validate_identifier(device_id)


def _validate_artifact_path(value: object) -> None:
    if not isinstance(value, str) or not value.startswith("artifacts/"):
        raise ConfigurationError("event output_path must be a relative artifacts path")
    parts = value.split("/")
    if len(parts) < 2 or any(_ARTIFACT_PART.fullmatch(part) is None for part in parts):
        raise ConfigurationError("event output_path must be a relative artifacts path")


_PAYLOAD_VALIDATORS = {
    EventType.PREFLIGHT: {
        "status": _validate_choice(_PREFLIGHT_STATUSES),
        "backend": _validate_choice(_BACKENDS),
        "device_ids": _validate_device_ids,
        "tool_version": _validate_version,
        "workload": _validate_choice(_WORKLOADS),
        "pdf_mode": _validate_nonnegative_int,
        "hint_count": _validate_nonnegative_int,
    },
    EventType.STAGE_STARTED: {
        "stage_id": _validate_identifier,
        "stage_index": _validate_nonnegative_int,
        "stage_count": _validate_nonnegative_int,
        "backend": _validate_choice(_BACKENDS),
        "workload": _validate_choice(_WORKLOADS),
        "total": _validate_nonnegative_int,
    },
    EventType.PROGRESS: {
        "stage_id": _validate_identifier,
        "completed": _validate_nonnegative_int,
        "total": _validate_nonnegative_int,
        "attempted": _validate_nonnegative_int,
        "elapsed_seconds": _validate_nonnegative_number,
        "rate": _validate_nonnegative_number,
        "backend": _validate_choice(_BACKENDS),
        "workers": _validate_nonnegative_int,
    },
    EventType.WARNING: {
        "code": _validate_code,
        "message": _validate_message,
        "backend": _validate_choice(_BACKENDS),
        "stage_id": _validate_identifier,
    },
    EventType.CHECKPOINT: {
        "stage_id": _validate_identifier,
        "completed": _validate_nonnegative_int,
        "total": _validate_nonnegative_int,
        "checkpoint_status": _validate_choice(_CHECKPOINT_STATUSES),
    },
    EventType.RESULT: {
        "status": _validate_choice(_RESULT_STATUSES),
        "stage_id": _validate_identifier,
        "attempted": _validate_nonnegative_int,
        "elapsed_seconds": _validate_nonnegative_number,
        "backend": _validate_choice(_BACKENDS),
        "output_path": _validate_artifact_path,
    },
    EventType.ERROR: {
        "code": _validate_code,
        "message": _validate_message,
        "stage_id": _validate_identifier,
        "backend": _validate_choice(_BACKENDS),
    },
}
