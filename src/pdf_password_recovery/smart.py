from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from .assets import bundled_wordlist
from .backends.cpu import ProgressCallback
from .candidates import RULESET_VERSION
from .checkpoint import FileFingerprint, file_fingerprint
from .errors import ConfigurationError, SessionMismatch
from .models import (
    BackendChoice,
    BruteAttack,
    Cursor,
    CursorKind,
    DictionaryAttack,
    MaskAttack,
    OutcomeStatus,
    RecoveryConfig,
    RecoveryOutcome,
)
from .service import NoticeCallback, recover

STRATEGY_VERSION = 1
ResumeCallback = Callable[[], bool]


@dataclass(frozen=True, slots=True)
class SmartOptions:
    pdf_path: Path
    min_length: int
    max_length: int
    workers: int

    def __post_init__(self) -> None:
        if self.min_length < 1 or self.max_length < self.min_length:
            raise ConfigurationError("invalid smart password length range")
        if self.workers < 1:
            raise ConfigurationError("workers must be at least 1")


def build_stages(options: SmartOptions, wordlist: Path) -> tuple[RecoveryConfig, ...]:
    """Build the fixed dictionary, rules, masks, and bounded brute sequence."""
    key = _strategy_key(options, file_fingerprint(options.pdf_path), file_fingerprint(wordlist))
    return _build_stages(options, wordlist, key)


def _build_stages(options: SmartOptions, wordlist: Path, key: str) -> tuple[RecoveryConfig, ...]:
    attacks = [
        DictionaryAttack(wordlist, min_length=options.min_length, max_length=options.max_length),
        DictionaryAttack(
            wordlist,
            min_length=options.min_length,
            max_length=options.max_length,
            apply_rules=True,
        ),
    ]
    for length in range(options.min_length, options.max_length + 1):
        attacks.extend(
            MaskAttack(mask)
            for mask in (
                "?d" * length,
                "?l" * length,
                "?u" * length,
                *(("?u" + "?l" * (length - 3) + "?d?d",) if length >= 4 else ()),
            )
        )
    attacks.append(BruteAttack("alnum", options.min_length, options.max_length))
    return tuple(
        RecoveryConfig(
            options.pdf_path,
            attack,
            BackendChoice.AUTO,
            workers=options.workers,
            session=f"smart-{key}-{index:02d}",
        )
        for index, attack in enumerate(attacks)
    )


def run_smart(
    options: SmartOptions,
    *,
    progress: ProgressCallback | None = None,
    notice: NoticeCallback | None = None,
    confirm_resume: ResumeCallback | None = None,
    wordlist: Path | None = None,
    recover_fn: Callable[..., RecoveryOutcome] = recover,
    state_root: Path | None = None,
) -> RecoveryOutcome:
    """Run the fixed smart stages, retaining only minimal cross-stage state."""
    wordlist = wordlist or bundled_wordlist()
    pdf_fingerprint = file_fingerprint(options.pdf_path)
    wordlist_fingerprint = file_fingerprint(wordlist)
    stages = _build_stages(
        options, wordlist, _strategy_key(options, pdf_fingerprint, wordlist_fingerprint)
    )
    stage_ids = _stage_ids(options)
    manifest = _manifest_path(options.pdf_path, state_root)
    identity = _identity(options, pdf_fingerprint, wordlist_fingerprint)
    saved = _load_state(manifest) if manifest.is_file() else None
    if saved is not None:
        _validate_state(saved, identity, stage_ids)
        if confirm_resume is not None and not confirm_resume():
            manifest.unlink(missing_ok=True)
            saved = None

    completed = list(saved["completed_stages"]) if saved else []
    current = int(saved["current_stage"]) if saved else -1
    attempted = 0

    last: RecoveryOutcome | None = None
    for index, (stage_id, stage) in enumerate(zip(stage_ids, stages, strict=True)):
        if stage_id in completed:
            continue
        should_resume = saved is not None and index == current
        config = replace(stage, resume=should_resume)
        if notice is not None:
            notice(f"smart stage {index + 1}/{len(stages)}: {stage_id}")
        if should_resume:
            if completed:
                _save_state(manifest, identity, len(completed) - 1, completed)
            else:
                manifest.unlink(missing_ok=True)
        outcome = recover_fn(config, progress=progress, notice=notice)
        attempted += outcome.attempted
        last = replace(outcome, attempted=attempted)
        if outcome.status is OutcomeStatus.FOUND:
            manifest.unlink(missing_ok=True)
            return last
        if outcome.status is OutcomeStatus.INTERRUPTED:
            _save_state(manifest, identity, index, completed)
            return last
        completed.append(stage_id)
        _save_state(manifest, identity, index, completed)
        saved = None

    manifest.unlink(missing_ok=True)
    return last or RecoveryOutcome(
        OutcomeStatus.EXHAUSTED,
        None,
        Cursor(CursorKind.INDEX, 0),
        attempted,
        0.0,
        "smart",
    )


def _stage_ids(options: SmartOptions) -> tuple[str, ...]:
    ids = ["dictionary", "rules"]
    for length in range(options.min_length, options.max_length + 1):
        ids.extend(f"mask-{length}-{kind}" for kind in ("digits", "lower", "upper"))
        if length >= 4:
            ids.append(f"mask-{length}-capitalized-two-digits")
    return (*ids, "brute-alnum")


def _fingerprint_payload(value: FileFingerprint) -> dict[str, str | int]:
    return {"size": value.size, "sha256": value.sha256}


def _identity(
    options: SmartOptions, pdf: FileFingerprint, wordlist: FileFingerprint
) -> dict[str, object]:
    return {
        "schema": 1,
        "strategy": STRATEGY_VERSION,
        "pdf": _fingerprint_payload(pdf),
        "wordlist": _fingerprint_payload(wordlist),
        "ruleset": RULESET_VERSION,
        "min_length": options.min_length,
        "max_length": options.max_length,
    }


def _strategy_key(options: SmartOptions, pdf: FileFingerprint, wordlist: FileFingerprint) -> str:
    raw = (
        f"{pdf.sha256}:{wordlist.sha256}:{RULESET_VERSION}:"
        f"{options.min_length}:{options.max_length}"
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def _manifest_path(pdf_path: Path, root: Path | None) -> Path:
    path_key = os.path.normcase(str(pdf_path.resolve()))
    name = hashlib.sha256(path_key.encode()).hexdigest()[:24] + ".json"
    return (root or _default_state_root()) / "smart" / name


def _default_state_root() -> Path:
    configured = os.environ.get("PDF_PASSWORD_RECOVERY_STATE_DIR")
    if configured:
        return Path(configured)
    if os.name == "nt" and (base := os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")):
        return Path(base) / "pdf-password-recovery"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / (
        "pdf-password-recovery"
    )


def _load_state(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SessionMismatch(f"cannot load smart recovery state: {exc}") from exc
    if not isinstance(value, dict):
        raise SessionMismatch("invalid smart recovery state")
    return value


def _validate_state(
    saved: dict[str, object], identity: dict[str, object], stage_ids: tuple[str, ...]
) -> None:
    fields = {*identity, "current_stage", "completed_stages"}
    current = saved.get("current_stage")
    completed = saved.get("completed_stages")
    valid = (
        set(saved) == fields
        and type(current) is int
        and 0 <= current < len(stage_ids)
        and isinstance(completed, list)
        and tuple(completed)
        == (stage_ids[: current + 1] if stage_ids[current] in completed else stage_ids[:current])
    )
    if not valid:
        raise SessionMismatch("invalid smart recovery state")
    if any(saved[key] != value for key, value in identity.items()):
        raise SessionMismatch("smart recovery inputs do not match the saved state")


def _save_state(
    path: Path,
    identity: dict[str, object],
    current: int,
    completed: list[str],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    payload = {
        **identity,
        "current_stage": current,
        "completed_stages": completed,
    }
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
