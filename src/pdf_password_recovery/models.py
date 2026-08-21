from __future__ import annotations

from dataclasses import dataclass
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
