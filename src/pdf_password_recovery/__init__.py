"""Local PDF password recovery package."""

from .events import EventMessage, EventSink, EventType, JsonLineSink, RecoveryEvent, event_payload
from .models import (
    AttackPlan,
    BackendChoice,
    BruteAttack,
    BruteStage,
    CompiledPlan,
    CompiledStage,
    DictionaryAttack,
    DictionaryStage,
    HybridAttack,
    HybridStage,
    MaskAttack,
    MaskStage,
    RecoveryConfig,
    RulesAttack,
    RulesStage,
    SessionStatus,
    SessionSummary,
)
from .plans import HcmaskEntry, built_in_plan, compile_plan, load_plan, parse_hcmask
from .sessions import SessionStore

__all__ = [
    "BackendChoice",
    "AttackPlan",
    "BruteAttack",
    "BruteStage",
    "CompiledPlan",
    "CompiledStage",
    "DictionaryAttack",
    "DictionaryStage",
    "EventMessage",
    "EventSink",
    "EventType",
    "event_payload",
    "JsonLineSink",
    "MaskAttack",
    "MaskStage",
    "RecoveryConfig",
    "RecoveryEvent",
    "RulesAttack",
    "RulesStage",
    "SessionStatus",
    "SessionStore",
    "SessionSummary",
    "HybridAttack",
    "HybridStage",
    "HcmaskEntry",
    "built_in_plan",
    "compile_plan",
    "load_plan",
    "parse_hcmask",
]

__version__ = "1.0.0"
