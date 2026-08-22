from __future__ import annotations

import json
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
        if isinstance(self.schema, bool) or self.schema != 1:
            raise ConfigurationError("event schema must be 1")
        if not isinstance(self.type, EventType):
            raise ConfigurationError("event type must be an EventType")
        if not isinstance(self.payload, Mapping):
            raise ConfigurationError("event payload must be a mapping")
        if self.session is not None and not isinstance(self.session, str):
            raise ConfigurationError("event session must be a string or null")
        if not isinstance(self.timestamp, str) or not self.timestamp.endswith("Z"):
            raise ConfigurationError("event timestamp must be UTC ISO-8601 ending in Z")
        try:
            parsed = datetime.fromisoformat(self.timestamp.removesuffix("Z") + "+00:00")
        except ValueError as exc:
            raise ConfigurationError("event timestamp must be UTC ISO-8601 ending in Z") from exc
        if parsed.tzinfo != UTC or parsed.utcoffset() != UTC.utcoffset(None):
            raise ConfigurationError("event timestamp must be UTC ISO-8601 ending in Z")
        _reject_sensitive_payload(self.payload)


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
    _reject_sensitive_payload(event.payload)
    return {
        "schema": event.schema,
        "type": event.type.value,
        "timestamp": event.timestamp,
        "session": event.session,
        "payload": event.payload,
    }


_SENSITIVE_KEYS = frozenset({"password", "pdf_hash", "extracted_hash"})


def _reject_sensitive_payload(value: object) -> None:
    if isinstance(value, str):
        if "$pdf$" in value:
            raise ConfigurationError("event payload may not contain an extracted PDF hash")
    elif isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = key.casefold() if isinstance(key, str) else ""
            if normalized in _SENSITIVE_KEYS or "hint" in normalized:
                raise ConfigurationError(f"event payload may not contain '{key}'")
            _reject_sensitive_payload(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _reject_sensitive_payload(nested)
