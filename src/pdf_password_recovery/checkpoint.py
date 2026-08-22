from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .candidates import RULESET_VERSION
from .errors import CheckpointError, SessionMismatch
from .models import (
    AttackSpec,
    BruteAttack,
    Cursor,
    CursorKind,
    DictionaryAttack,
    HybridAttack,
    MaskAttack,
    RecoveryConfig,
    RulesAttack,
)

SCHEMA_VERSION = 1
_HASH_CHUNK_SIZE = 1024 * 1024
_SESSION_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclass(frozen=True, slots=True)
class FileFingerprint:
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class Checkpoint:
    schema: int
    backend: str
    pdf: FileFingerprint
    attack: dict[str, Any]
    wordlist: FileFingerprint | None
    cursor: Cursor


def file_fingerprint(path: Path) -> FileFingerprint:
    """Hash a file using fixed-size reads so memory use stays bounded."""
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as source:
            while block := source.read(_HASH_CHUNK_SIZE):
                digest.update(block)
                size += len(block)
    except (OSError, ValueError) as exc:
        raise CheckpointError(f"cannot fingerprint file '{path}': {exc}") from exc
    return FileFingerprint(size=size, sha256=digest.hexdigest())


def normalize_attack(attack: AttackSpec) -> dict[str, Any]:
    """Return only attack settings that affect candidate generation."""
    if isinstance(attack, DictionaryAttack):
        normalized: dict[str, str | int | None] = {
            "kind": "dictionary",
            "encoding": attack.encoding,
        }
        if attack.min_length is not None:
            normalized.update(min_length=attack.min_length, max_length=attack.max_length)
        if attack.apply_rules:
            normalized.update(
                min_length=attack.min_length,
                max_length=attack.max_length,
                ruleset_version=RULESET_VERSION,
            )
        return normalized
    if isinstance(attack, MaskAttack):
        return {
            "kind": "mask",
            "mask": attack.mask,
            "custom_charsets": list(attack.custom_charsets),
        }
    if isinstance(attack, RulesAttack):
        return {
            "kind": "rules",
            "encoding": attack.encoding,
            "rules": list(attack.rules),
            "min_length": attack.min_length,
            "max_length": attack.max_length,
        }
    if isinstance(attack, HybridAttack):
        return {
            "kind": "hybrid",
            "encoding": attack.encoding,
            "mask": attack.mask,
            "direction": attack.direction,
        }
    if isinstance(attack, BruteAttack):
        return {
            "kind": "brute",
            "charset": attack.charset,
            "min_length": attack.min_length,
            "max_length": attack.max_length,
        }
    raise CheckpointError(f"unsupported attack type: {type(attack).__name__}")


def build_checkpoint(config: RecoveryConfig, cursor: Cursor) -> Checkpoint:
    expected_kind = (
        CursorKind.LINE
        if isinstance(config.attack, (DictionaryAttack, RulesAttack))
        else CursorKind.INDEX
    )
    if cursor.kind is not expected_kind:
        raise CheckpointError(
            f"{config.attack.kind.value} attack requires a {expected_kind.value} cursor"
        )
    wordlist = (
        file_fingerprint(config.attack.wordlist)
        if isinstance(config.attack, (DictionaryAttack, RulesAttack, HybridAttack))
        else None
    )
    return Checkpoint(
        schema=SCHEMA_VERSION,
        backend="cpu",
        pdf=file_fingerprint(config.pdf_path),
        attack=normalize_attack(config.attack),
        wordlist=wordlist,
        cursor=cursor,
    )


def save_checkpoint(path: Path, checkpoint: Checkpoint) -> None:
    """Atomically replace a checkpoint after its contents reach stable storage."""
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
    except OSError as exc:
        raise CheckpointError(f"cannot prepare checkpoint '{path}': {exc}") from exc

    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as destination:
            json.dump(_to_payload(checkpoint), destination, sort_keys=True, separators=(",", ":"))
            destination.write("\n")
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except (OSError, TypeError, ValueError) as exc:
        raise CheckpointError(f"cannot save checkpoint '{path}': {exc}") from exc
    finally:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)


def load_checkpoint(path: Path) -> Checkpoint:
    path = Path(path)
    try:
        with path.open("r", encoding="utf-8") as source:
            payload = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CheckpointError(f"cannot load checkpoint '{path}': {exc}") from exc
    try:
        return _from_payload(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise CheckpointError(f"invalid checkpoint '{path}': {exc}") from exc


def validate_checkpoint(checkpoint: Checkpoint, config: RecoveryConfig) -> None:
    """Reject a resume when any candidate-affecting input has changed."""
    if checkpoint.schema != SCHEMA_VERSION:
        raise SessionMismatch(f"checkpoint schema {checkpoint.schema} is not supported")
    if checkpoint.backend != "cpu":
        raise SessionMismatch("checkpoint was created by a different backend")

    expected_attack = normalize_attack(config.attack)
    if checkpoint.attack != expected_attack:
        raise SessionMismatch("attack parameters do not match the checkpoint")
    if checkpoint.pdf != file_fingerprint(config.pdf_path):
        raise SessionMismatch("PDF fingerprint does not match the checkpoint")

    expected_wordlist = (
        file_fingerprint(config.attack.wordlist)
        if isinstance(config.attack, (DictionaryAttack, RulesAttack, HybridAttack))
        else None
    )
    if checkpoint.wordlist != expected_wordlist:
        raise SessionMismatch("wordlist fingerprint does not match the checkpoint")

    expected_cursor = (
        CursorKind.LINE
        if isinstance(config.attack, (DictionaryAttack, RulesAttack))
        else CursorKind.INDEX
    )
    if checkpoint.cursor.kind is not expected_cursor:
        raise SessionMismatch("cursor type does not match the attack")


def checkpoint_path(session: str, *, root: Path | None = None) -> Path:
    if not session or _SESSION_NAME.fullmatch(session) is None or session in {".", ".."}:
        raise CheckpointError("session name may contain only letters, digits, '.', '_' and '-'")
    sessions_root = Path(root) if root is not None else _user_data_root() / "sessions"
    return sessions_root / session / "checkpoint.json"


def _user_data_root() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / "pdf-password-recovery"
    xdg_data = os.environ.get("XDG_DATA_HOME")
    if xdg_data:
        return Path(xdg_data) / "pdf-password-recovery"
    return Path.home() / ".local" / "share" / "pdf-password-recovery"


def _to_payload(checkpoint: Checkpoint) -> dict[str, Any]:
    return {
        "schema": checkpoint.schema,
        "backend": checkpoint.backend,
        "pdf": _fingerprint_payload(checkpoint.pdf),
        "attack": checkpoint.attack,
        "wordlist": (
            _fingerprint_payload(checkpoint.wordlist) if checkpoint.wordlist is not None else None
        ),
        "cursor": {"kind": checkpoint.cursor.kind.value, "value": checkpoint.cursor.value},
    }


def _from_payload(payload: object) -> Checkpoint:
    mapping = _require_mapping(payload, "root")
    schema = _require_int(mapping, "schema")
    if schema != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema version {schema}")
    backend = _require_str(mapping, "backend")
    if backend != "cpu":
        raise ValueError(f"unsupported backend '{backend}'")
    attack = _parse_attack(_require_mapping(mapping.get("attack"), "attack"))
    wordlist_value = mapping.get("wordlist")
    wordlist = (
        None
        if wordlist_value is None
        else _parse_fingerprint(_require_mapping(wordlist_value, "wordlist"), "wordlist")
    )
    cursor_mapping = _require_mapping(mapping.get("cursor"), "cursor")
    cursor_kind = CursorKind(_require_str(cursor_mapping, "kind"))
    cursor = Cursor(cursor_kind, _require_int(cursor_mapping, "value"))
    return Checkpoint(
        schema=schema,
        backend=backend,
        pdf=_parse_fingerprint(_require_mapping(mapping.get("pdf"), "pdf"), "pdf"),
        attack=attack,
        wordlist=wordlist,
        cursor=cursor,
    )


def _parse_attack(mapping: Mapping[str, Any]) -> dict[str, Any]:
    kind = _require_str(mapping, "kind")
    if kind == "dictionary":
        attack: dict[str, str | int | None] = {
            "kind": kind,
            "encoding": _require_str(mapping, "encoding"),
        }
        if "min_length" in mapping or "max_length" in mapping:
            attack["min_length"] = _require_optional_int(mapping, "min_length")
            attack["max_length"] = _require_optional_int(mapping, "max_length")
        if "ruleset_version" in mapping:
            attack["ruleset_version"] = _require_int(mapping, "ruleset_version")
        return attack
    if kind == "mask":
        custom = mapping.get("custom_charsets", [])
        if not isinstance(custom, list) or any(not isinstance(item, str) for item in custom):
            raise TypeError("custom_charsets must be an array of strings")
        return {"kind": kind, "mask": _require_str(mapping, "mask"), "custom_charsets": custom}
    if kind == "rules":
        rules = mapping.get("rules")
        if not isinstance(rules, list) or any(not isinstance(item, str) for item in rules):
            raise TypeError("rules must be an array of strings")
        has_min = "min_length" in mapping
        has_max = "max_length" in mapping
        if has_min != has_max:
            raise TypeError("rules length bounds must be provided together")
        return {
            "kind": kind,
            "encoding": _require_str(mapping, "encoding"),
            "rules": rules,
            "min_length": _require_optional_int(mapping, "min_length") if has_min else None,
            "max_length": _require_optional_int(mapping, "max_length") if has_max else None,
        }
    if kind == "hybrid":
        return {
            "kind": kind,
            "encoding": _require_str(mapping, "encoding"),
            "mask": _require_str(mapping, "mask"),
            "direction": _require_str(mapping, "direction"),
        }
    if kind == "brute":
        return {
            "kind": kind,
            "charset": _require_str(mapping, "charset"),
            "min_length": _require_int(mapping, "min_length"),
            "max_length": _require_int(mapping, "max_length"),
        }
    raise ValueError(f"unsupported attack kind '{kind}'")


def _fingerprint_payload(fingerprint: FileFingerprint) -> dict[str, str | int]:
    return {"size": fingerprint.size, "sha256": fingerprint.sha256}


def _parse_fingerprint(mapping: Mapping[str, Any], field: str) -> FileFingerprint:
    size = _require_int(mapping, "size")
    digest = _require_str(mapping, "sha256")
    if size < 0:
        raise ValueError(f"{field}.size cannot be negative")
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError(f"{field}.sha256 is invalid")
    return FileFingerprint(size=size, sha256=digest)


def _require_mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{field} must be an object")
    return value


def _require_str(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping[key]
    if not isinstance(value, str):
        raise TypeError(f"{key} must be a string")
    return value


def _require_int(mapping: Mapping[str, Any], key: str) -> int:
    value = mapping[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{key} must be an integer")
    return value


def _require_optional_int(mapping: Mapping[str, Any], key: str) -> int | None:
    value = mapping[key]
    return None if value is None else _require_int(mapping, key)


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
