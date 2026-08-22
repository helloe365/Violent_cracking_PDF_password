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
    WorkloadProfile,
)
from .orchestrator import run_plan
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
    "WorkloadProfile",
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
    "run_plan",
]

__version__ = "1.0.0"
