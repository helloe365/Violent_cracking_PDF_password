from __future__ import annotations

import math
import string
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigurationError, MaskSyntaxError
from .models import IndexRange

PRESET_CHARSETS = {
    "digits": string.digits,
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "letters": string.ascii_letters,
    "alnum": string.ascii_letters + string.digits,
}

MASK_CHARSETS = {
    "d": string.digits,
    "l": string.ascii_lowercase,
    "u": string.ascii_uppercase,
    "a": "".join(chr(codepoint) for codepoint in range(32, 127)),
    "?": "?",
}

RULESET_VERSION = 1
SMART_RULES = (
    "l",
    "u",
    "c",
    *(f"^{digit}" for digit in string.digits),
    *(f"${digit}" for digit in string.digits),
    "$1$2",
    "$1$2$3",
    "$1$2$3$4",
    "$2$0$2$4",
    "$2$0$2$5",
    "$2$0$2$6",
    "$5$2$0",
    "$6$6$6",
    "$8$8$8",
    "$!",
    "$@",
    "sa4",
    "se3",
    "si1",
    "so0",
)


def iter_smart_variants(word: str) -> Iterator[str]:
    """Yield distinct smart-rule mutations in rule-file order, excluding ``word``."""
    yield from iter_rule_variants(word, SMART_RULES)


def iter_rule_variants(word: str, rules: tuple[str, ...]) -> Iterator[str]:
    """Yield distinct variants for the CPU-supported smart rules."""
    seen = {word}
    for rule in rules:
        variant = _apply_smart_rule(word, rule)
        if variant not in seen:
            seen.add(variant)
            yield variant


def _apply_smart_rule(word: str, rule: str) -> str:
    if rule == "l":
        return word.lower()
    if rule == "u":
        return word.upper()
    if rule == "c":
        return word.capitalize()
    if rule[0] == "^":
        return rule[1:] + word
    if rule[0] == "$":
        return word + rule.replace("$", "")
    if rule[0] == "s":
        return word.replace(rule[1], rule[2])
    raise AssertionError(f"unsupported smart rule: {rule}")


def resolve_charset(value: str) -> str:
    """Resolve a preset or stably deduplicate a custom character set."""
    charset = PRESET_CHARSETS.get(value)
    if charset is not None:
        return charset
    charset = "".join(dict.fromkeys(value))
    if not charset:
        raise ConfigurationError("charset cannot be empty")
    return charset


def candidate_at(positions: tuple[str, ...], index: int) -> str:
    if not positions or any(not position for position in positions):
        raise ConfigurationError("candidate positions cannot be empty")
    total = math.prod(len(position) for position in positions)
    if index < 0 or index >= total:
        raise IndexError("candidate index out of range")

    return _candidate_at_unchecked(positions, index)


def _candidate_at_unchecked(positions: tuple[str, ...], index: int) -> str:

    characters = [""] * len(positions)
    for position in range(len(positions) - 1, -1, -1):
        alphabet = positions[position]
        index, offset = divmod(index, len(alphabet))
        characters[position] = alphabet[offset]
    return "".join(characters)


@dataclass(frozen=True, slots=True)
class MaskSpace:
    positions: tuple[str, ...]
    _total: int = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.positions or any(not position for position in self.positions):
            raise MaskSyntaxError("mask cannot be empty")
        object.__setattr__(self, "_total", math.prod(len(position) for position in self.positions))

    @classmethod
    def compile(cls, mask: str, custom_charsets: tuple[str, ...] = ()) -> MaskSpace:
        return cls(compile_mask(mask, custom_charsets))

    @property
    def total(self) -> int:
        return self._total

    def candidate_at(self, index: int) -> str:
        if index < 0 or index >= self._total:
            raise IndexError("candidate index out of range")
        return _candidate_at_unchecked(self.positions, index)


def compile_mask(mask: str, custom_charsets: tuple[str, ...] = ()) -> tuple[str, ...]:
    if not mask:
        raise MaskSyntaxError("mask cannot be empty")

    if not isinstance(custom_charsets, tuple) or len(custom_charsets) > 8:
        raise MaskSyntaxError("mask supports at most eight custom charsets")
    if any(not isinstance(charset, str) or not charset for charset in custom_charsets):
        raise MaskSyntaxError("custom charsets cannot be empty")

    resolved_custom: list[str] = []
    for charset in custom_charsets:
        resolved_custom.append("".join(_compile_mask_tokens(charset, tuple(resolved_custom))))
    return _compile_mask_tokens(mask, tuple(resolved_custom))


def _compile_mask_tokens(mask: str, custom_charsets: tuple[str, ...]) -> tuple[str, ...]:
    positions: list[str] = []
    index = 0
    while index < len(mask):
        character = mask[index]
        if character != "?":
            positions.append(character)
            index += 1
            continue
        if index + 1 == len(mask):
            raise MaskSyntaxError("mask ends with an incomplete token")
        token = mask[index + 1]
        if token in "12345678":
            custom_index = int(token) - 1
            if custom_index >= len(custom_charsets):
                raise MaskSyntaxError(f"undefined custom mask token '?{token}'")
            positions.append(custom_charsets[custom_index])
        else:
            try:
                positions.append(MASK_CHARSETS[token])
            except KeyError as exc:
                raise MaskSyntaxError(f"unsupported mask token '?{token}'") from exc
        index += 2
    return tuple(positions)


@dataclass(frozen=True, slots=True)
class HybridSpace:
    wordlist: Path
    encoding: str
    mask_space: MaskSpace
    direction: str
    _word_count: int = field(init=False, repr=False)
    _total: int = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.direction not in {"append", "prepend"}:
            raise ConfigurationError("hybrid direction must be 'append' or 'prepend'")
        words = _count_words(self.wordlist, self.encoding)
        object.__setattr__(self, "_word_count", words)
        object.__setattr__(self, "_total", words * self.mask_space.total)

    @property
    def total(self) -> int:
        return self._total

    def candidate_at(self, index: int) -> str:
        if index < 0 or index >= self._total:
            raise IndexError("candidate index out of range")
        word_index, mask_index = divmod(index, self.mask_space.total)
        word = _word_at(self.wordlist, self.encoding, word_index)
        suffix = self.mask_space.candidate_at(mask_index)
        return word + suffix if self.direction == "append" else suffix + word

    def iter_candidates(self, start: int = 0, stop: int | None = None) -> Iterator[str]:
        stop = self._total if stop is None else stop
        if start < 0 or stop < start or stop > self._total:
            raise IndexError("candidate range is out of bounds")
        for index in range(start, stop):
            yield self.candidate_at(index)


def _count_words(path: Path, encoding: str) -> int:
    try:
        with Path(path).open("r", encoding=encoding, errors="strict", newline=None) as source:
            return sum(1 for _ in source)
    except UnicodeDecodeError as exc:
        raise ConfigurationError(f"cannot decode wordlist using {encoding}") from exc
    except LookupError as exc:
        raise ConfigurationError(f"unknown wordlist encoding: {encoding}") from exc
    except OSError as exc:
        raise ConfigurationError(f"cannot read wordlist: {exc}") from exc


def _word_at(path: Path, encoding: str, target: int) -> str:
    try:
        with Path(path).open("r", encoding=encoding, errors="strict", newline=None) as source:
            for index, line in enumerate(source):
                if index == target:
                    return line.rstrip("\r\n")
    except UnicodeDecodeError as exc:
        raise ConfigurationError(f"cannot decode wordlist using {encoding}") from exc
    except LookupError as exc:
        raise ConfigurationError(f"unknown wordlist encoding: {encoding}") from exc
    except OSError as exc:
        raise ConfigurationError(f"cannot read wordlist: {exc}") from exc
    raise AssertionError("validated hybrid word index was not resolved")


@dataclass(frozen=True, slots=True)
class BruteSpace:
    charset: str
    min_length: int
    max_length: int
    _length_totals: tuple[int, ...] = field(init=False, repr=False)
    _total: int = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.min_length < 1:
            raise ConfigurationError("minimum length must be at least 1")
        if self.max_length < self.min_length:
            raise ConfigurationError("maximum length cannot be less than minimum length")
        charset = resolve_charset(self.charset)
        length_totals = tuple(
            len(charset) ** length for length in range(self.min_length, self.max_length + 1)
        )
        object.__setattr__(self, "charset", charset)
        object.__setattr__(self, "_length_totals", length_totals)
        object.__setattr__(self, "_total", sum(length_totals))

    @classmethod
    def create(cls, charset: str, min_length: int, max_length: int) -> BruteSpace:
        return cls(charset, min_length, max_length)

    @property
    def total(self) -> int:
        return self._total

    def candidate_at(self, index: int) -> str:
        if index < 0 or index >= self._total:
            raise IndexError("candidate index out of range")
        for length, length_total in zip(
            range(self.min_length, self.max_length + 1), self._length_totals, strict=True
        ):
            if index < length_total:
                return _candidate_at_unchecked((self.charset,) * length, index)
            index -= length_total
        raise AssertionError("validated candidate index was not resolved")


def brute_space_size(charset: str, min_length: int, max_length: int) -> int:
    return BruteSpace.create(charset, min_length, max_length).total


def brute_candidate_at(charset: str, min_length: int, max_length: int, index: int) -> str:
    return BruteSpace.create(charset, min_length, max_length).candidate_at(index)


def iter_index_ranges(total: int, chunk_size: int, start: int = 0) -> Iterator[IndexRange]:
    if total < 0:
        raise ConfigurationError("total cannot be negative")
    if chunk_size < 1:
        raise ConfigurationError("chunk size must be at least 1")
    if start < 0 or start > total:
        raise ConfigurationError("start must be within the search space")

    while start < total:
        stop = min(start + chunk_size, total)
        yield IndexRange(start, stop)
        start = stop
