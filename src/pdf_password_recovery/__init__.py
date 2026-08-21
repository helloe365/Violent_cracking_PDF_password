"""Local PDF password recovery package."""

from .events import EventSink, EventType, JsonLineSink, RecoveryEvent, event_payload
from .models import (
    BackendChoice,
    BruteAttack,
    DictionaryAttack,
    MaskAttack,
    RecoveryConfig,
    SessionStatus,
    SessionSummary,
)
from .sessions import SessionStore

__all__ = [
    "BackendChoice",
    "BruteAttack",
    "DictionaryAttack",
    "EventSink",
    "EventType",
    "event_payload",
    "JsonLineSink",
    "MaskAttack",
    "RecoveryConfig",
    "RecoveryEvent",
    "SessionStatus",
    "SessionStore",
    "SessionSummary",
]

__version__ = "1.0.0"
