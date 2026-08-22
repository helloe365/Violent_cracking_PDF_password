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
    RULES = "rules"
    MASK = "mask"
    HYBRID = "hybrid"
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
class RulesAttack:
    wordlist: Path
    rules: tuple[str, ...]
    encoding: str = "utf-8"
    min_length: int | None = None
    max_length: int | None = None

    def __post_init__(self) -> None:
        _validate_dictionary_bounds(self.min_length, self.max_length)
        if (
            not isinstance(self.rules, tuple)
            or not self.rules
            or any(not isinstance(rule, str) or not rule for rule in self.rules)
        ):
            raise ConfigurationError("rules must be a non-empty tuple of rule strings")

    @property
    def kind(self) -> AttackKind:
        return AttackKind.RULES


@dataclass(frozen=True, slots=True)
class MaskAttack:
    mask: str
    custom_charsets: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.custom_charsets, tuple) or len(self.custom_charsets) > 8:
            raise ConfigurationError("mask supports at most eight custom charsets")
        if any(not isinstance(charset, str) or not charset for charset in self.custom_charsets):
            raise ConfigurationError("custom charsets cannot be empty")

    @property
    def kind(self) -> AttackKind:
        return AttackKind.MASK


@dataclass(frozen=True, slots=True)
class HybridAttack:
    wordlist: Path
    mask: str
    direction: str
    encoding: str = "utf-8"

    def __post_init__(self) -> None:
        if self.direction not in {"append", "prepend"}:
            raise ConfigurationError("hybrid direction must be 'append' or 'prepend'")

    @property
    def kind(self) -> AttackKind:
        return AttackKind.HYBRID


@dataclass(frozen=True, slots=True)
class BruteAttack:
    charset: str = "alnum"
    min_length: int = 4
    max_length: int = 6

    def __post_init__(self) -> None:
        if isinstance(self.min_length, bool) or not isinstance(self.min_length, int):
            raise ConfigurationError("minimum length must be an integer")
        if isinstance(self.max_length, bool) or not isinstance(self.max_length, int):
            raise ConfigurationError("maximum length must be an integer")
        if self.min_length < 1 or self.max_length < self.min_length:
            raise ConfigurationError("invalid brute-force length range")

    @property
    def kind(self) -> AttackKind:
        return AttackKind.BRUTE


AttackSpec: TypeAlias = DictionaryAttack | RulesAttack | MaskAttack | HybridAttack | BruteAttack


def _validate_dictionary_bounds(min_length: int | None, max_length: int | None) -> None:
    if (min_length is None) != (max_length is None):
        raise ConfigurationError("dictionary length bounds must be provided together")
    if min_length is not None and max_length is not None:
        if min_length < 1 or max_length < 1:
            raise ConfigurationError("dictionary length bounds must be at least 1")
        if max_length < min_length:
            raise ConfigurationError("dictionary maximum length cannot be less than minimum length")


def _validate_stage_id(value: str) -> None:
    if not isinstance(value, str) or not value:
        raise ConfigurationError("stage ID must be a non-empty string")


@dataclass(frozen=True, slots=True)
class DictionaryStage:
    id: str
    wordlist: Path
    encoding: str = "utf-8"
    min_length: int | None = None
    max_length: int | None = None
    type: str = field(default="dictionary", init=False)

    def __post_init__(self) -> None:
        _validate_stage_id(self.id)
        _validate_dictionary_bounds(self.min_length, self.max_length)


@dataclass(frozen=True, slots=True)
class RulesStage:
    id: str
    wordlist: Path
    rules: tuple[str, ...]
    encoding: str = "utf-8"
    min_length: int | None = None
    max_length: int | None = None
    type: str = field(default="rules", init=False)

    def __post_init__(self) -> None:
        _validate_stage_id(self.id)
        _validate_dictionary_bounds(self.min_length, self.max_length)
        if (
            not isinstance(self.rules, tuple)
            or not self.rules
            or any(not isinstance(rule, str) or not rule for rule in self.rules)
        ):
            raise ConfigurationError("rules must be a non-empty tuple of rule strings")


@dataclass(frozen=True, slots=True)
class MaskStage:
    id: str
    mask: str | None = None
    mask_file: Path | None = None
    type: str = field(default="mask", init=False)

    def __post_init__(self) -> None:
        _validate_stage_id(self.id)
        if (self.mask is None) == (self.mask_file is None):
            raise ConfigurationError("mask stage requires exactly one of mask or mask_file")
        if self.mask is not None and (not isinstance(self.mask, str) or not self.mask):
            raise ConfigurationError("mask cannot be empty")


@dataclass(frozen=True, slots=True)
class HybridStage:
    id: str
    wordlist: Path
    mask: str
    direction: str
    encoding: str = "utf-8"
    type: str = field(default="hybrid", init=False)

    def __post_init__(self) -> None:
        _validate_stage_id(self.id)
        if not isinstance(self.mask, str) or not self.mask:
            raise ConfigurationError("hybrid mask cannot be empty")
        if self.direction not in {"append", "prepend"}:
            raise ConfigurationError("hybrid direction must be 'append' or 'prepend'")
        if not isinstance(self.encoding, str) or not self.encoding:
            raise ConfigurationError("hybrid encoding cannot be empty")


@dataclass(frozen=True, slots=True)
class BruteStage:
    id: str
    charset: str
    min_length: int
    max_length: int
    type: str = field(default="brute", init=False)

    def __post_init__(self) -> None:
        _validate_stage_id(self.id)
        BruteAttack(self.charset, self.min_length, self.max_length)


AttackStage: TypeAlias = DictionaryStage | RulesStage | MaskStage | HybridStage | BruteStage


@dataclass(frozen=True, slots=True)
class AttackPlan:
    schema: int
    name: str
    stages: tuple[AttackStage, ...]

    def __post_init__(self) -> None:
        if isinstance(self.schema, bool) or not isinstance(self.schema, int) or self.schema != 1:
            raise ConfigurationError("plan schema must be 1")
        if not isinstance(self.name, str) or not self.name:
            raise ConfigurationError("plan name must be a non-empty string")
        if not isinstance(self.stages, tuple) or not self.stages:
            raise ConfigurationError("plan stages must be a non-empty tuple")
        ids = tuple(stage.id for stage in self.stages)
        if len(set(ids)) != len(ids):
            raise ConfigurationError("plan stage IDs must be unique")


@dataclass(frozen=True, slots=True)
class CompiledStage:
    id: str
    attack: AttackSpec
    keyspace: int
    cpu_compatible: bool
    source: AttackStage

    def __post_init__(self) -> None:
        _validate_stage_id(self.id)
        if (
            isinstance(self.keyspace, bool)
            or not isinstance(self.keyspace, int)
            or self.keyspace < 0
        ):
            raise ConfigurationError("compiled keyspace must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class CompiledPlan:
    schema: int
    name: str
    stages: tuple[CompiledStage, ...]
    fingerprint: str

    def __post_init__(self) -> None:
        if isinstance(self.schema, bool) or not isinstance(self.schema, int) or self.schema != 1:
            raise ConfigurationError("compiled plan schema must be 1")
        if not isinstance(self.name, str) or not self.name or not self.stages:
            raise ConfigurationError("compiled plan must have a name and stages")
        if _SHA256.fullmatch(self.fingerprint) is None:
            raise ConfigurationError("compiled plan fingerprint must be a SHA-256 digest")


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
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9._-]+)?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SUMMARY_BACKENDS = frozenset({"", "auto", "cpu", "hashcat"})
_SUMMARY_WORKLOADS = frozenset({"quiet", "balanced", "fast"})
_FINGERPRINT_FIELDS = frozenset({"size", "mtime_ns", "sha256"})


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
        if isinstance(self.schema, bool) or not isinstance(self.schema, int) or self.schema != 1:
            raise ConfigurationError("session schema must be 1")
        if not isinstance(self.status, SessionStatus):
            raise ConfigurationError("session status must be a SessionStatus")
        _validate_optional_identifier(self.pdf_display_name, "PDF display name")
        _validate_pdf_fingerprint(self.pdf_fingerprint)
        _validate_optional_sha256(self.plan_fingerprint, "plan fingerprint")
        if self.stage_id is not None:
            _validate_optional_identifier(self.stage_id, "stage ID")
        if not isinstance(self.backend, str) or self.backend not in _SUMMARY_BACKENDS:
            raise ConfigurationError("backend must be an allowed backend")
        for field_name in ("stage_index", "stage_count", "completed", "total"):
            _require_non_negative_int(field_name, getattr(self, field_name))
        if isinstance(self.elapsed_seconds, bool) or not isinstance(
            self.elapsed_seconds, (int, float)
        ):
            raise ConfigurationError("elapsed seconds must be a number")
        if not math.isfinite(self.elapsed_seconds) or self.elapsed_seconds < 0:
            raise ConfigurationError("elapsed seconds cannot be negative")
        if not isinstance(self.device_ids, tuple):
            raise ConfigurationError("device IDs must be a tuple of safe identifiers")
        for device_id in self.device_ids:
            _validate_optional_identifier(device_id, "device ID")
        if self.tool_version is not None and (
            not isinstance(self.tool_version, str) or _VERSION.fullmatch(self.tool_version) is None
        ):
            raise ConfigurationError("tool version must be a version identifier or null")
        if self.workload is not None and self.workload not in _SUMMARY_WORKLOADS:
            raise ConfigurationError("workload must be an allowed workload or null")
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


def _validate_optional_identifier(value: object, field_name: str) -> None:
    if value == "":
        return
    if not isinstance(value, str) or _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ConfigurationError(f"{field_name} must be a safe identifier")


def _validate_optional_sha256(value: object, field_name: str) -> None:
    if value == "":
        return
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ConfigurationError(f"{field_name} must be a SHA-256 digest")


def _validate_pdf_fingerprint(value: object) -> None:
    if not isinstance(value, Mapping) or not set(value).issubset(_FINGERPRINT_FIELDS):
        raise ConfigurationError("PDF fingerprint has an invalid structure")
    for key, nested in value.items():
        if key in {"size", "mtime_ns"}:
            _require_non_negative_int("PDF fingerprint value", nested)
        elif key == "sha256":
            _validate_optional_sha256(nested, "PDF fingerprint digest")
        else:
            raise ConfigurationError("PDF fingerprint has an invalid structure")
