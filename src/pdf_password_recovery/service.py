from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

from .backends.cpu import ProgressCallback, run_cpu
from .backends.hashcat import HashcatStatus, SessionPaths, run_hashcat
from .candidates import SMART_RULES, BruteSpace, MaskSpace
from .checkpoint import (
    build_checkpoint,
    checkpoint_path,
    file_fingerprint,
    load_checkpoint,
    normalize_attack,
    save_checkpoint,
    validate_checkpoint,
)
from .errors import (
    ConfigurationError,
    HashExtractionError,
    SessionMismatch,
    ToolIncompatible,
    ToolUnavailable,
    UnsupportedPdfHash,
)
from .models import (
    BackendChoice,
    Cursor,
    CursorKind,
    DictionaryAttack,
    HybridAttack,
    OutcomeStatus,
    RecoveryConfig,
    RecoveryOutcome,
    RulesAttack,
)
from .pdfs import validate_pdf
from .wordlists import iter_wordlist_chunks

NoticeCallback = Callable[[str], None]
_LOG = logging.getLogger(__name__)


def recover(
    config: RecoveryConfig,
    *,
    progress: ProgressCallback | None = None,
    notice: NoticeCallback | None = None,
) -> RecoveryOutcome:
    _preflight(config)
    if config.backend is BackendChoice.CPU:
        return _run_cpu_with_checkpoint(config, progress)
    if config.backend is BackendChoice.HASHCAT:
        return _hashcat_outcome(config, progress)
    if config.resume and config.session and _cpu_checkpoint_path(config).is_file():
        _notify(notice, "existing CPU checkpoint selected for resume")
        return _run_cpu_with_checkpoint(config, progress)
    try:
        return _hashcat_outcome(config, progress)
    except (ToolUnavailable, ToolIncompatible, HashExtractionError, UnsupportedPdfHash) as exc:
        _notify(notice, f"hashcat unavailable ({exc}); falling back to CPU")
        return _run_cpu_with_checkpoint(config, progress)


def _preflight(config: RecoveryConfig) -> None:
    validate_pdf(config.pdf_path)
    attack = config.attack
    if isinstance(attack, DictionaryAttack):
        if not attack.wordlist.is_file():
            raise ConfigurationError(f"wordlist does not exist: {attack.wordlist}")
        iterator = iter_wordlist_chunks(
            attack.wordlist, encoding=attack.encoding, chunk_candidates=1
        )
        with suppress(StopIteration):
            next(iterator)
    elif isinstance(attack, (RulesAttack, HybridAttack)):
        if not attack.wordlist.is_file():
            raise ConfigurationError(f"wordlist does not exist: {attack.wordlist}")
        if (
            isinstance(attack, RulesAttack)
            and config.backend is BackendChoice.CPU
            and any(rule not in SMART_RULES for rule in attack.rules)
        ):
            raise ConfigurationError("CPU backend supports only the built-in smart rules")
        if isinstance(attack, HybridAttack):
            MaskSpace.compile(attack.mask)
    elif hasattr(attack, "mask"):
        MaskSpace.compile(attack.mask, getattr(attack, "custom_charsets", ()))
    elif hasattr(attack, "charset"):
        BruteSpace.create(attack.charset, attack.min_length, attack.max_length)
    else:
        raise ConfigurationError(f"unsupported attack type: {type(attack).__name__}")


def _state_root() -> Path | None:
    configured = os.environ.get("PDF_PASSWORD_RECOVERY_STATE_DIR")
    return Path(configured) if configured else None


def _cpu_checkpoint_path(config: RecoveryConfig) -> Path:
    assert config.session is not None
    root = _state_root()
    return checkpoint_path(config.session, root=(root / "cpu") if root else None)


def _run_cpu_with_checkpoint(
    config: RecoveryConfig, progress: ProgressCallback | None
) -> RecoveryOutcome:
    if isinstance(config.attack, RulesAttack) and any(
        rule not in SMART_RULES for rule in config.attack.rules
    ):
        raise ConfigurationError("CPU backend supports only the built-in smart rules")
    state_path = _cpu_checkpoint_path(config) if config.session else None
    cursor = None
    if config.resume:
        assert state_path is not None
        checkpoint = load_checkpoint(state_path)
        validate_checkpoint(checkpoint, config)
        cursor = checkpoint.cursor

    outcome = run_cpu(config, cursor=cursor, progress=progress)
    if state_path is not None:
        if outcome.status is OutcomeStatus.INTERRUPTED:
            save_checkpoint(state_path, build_checkpoint(config, outcome.cursor))
        else:
            state_path.unlink(missing_ok=True)
            with suppress(OSError):
                state_path.parent.rmdir()
    return outcome


def _hashcat_outcome(
    config: RecoveryConfig, progress: ProgressCallback | None = None
) -> RecoveryOutcome:
    started = time.monotonic()
    root = _state_root()
    paths = SessionPaths.for_run(config.session, base_dir=(root / "hashcat") if root else None)
    manifest = paths.prefix.parent / f"{paths.prefix.name}.manifest.json"
    if config.resume:
        _validate_hashcat_manifest(manifest, config)
    else:
        paths.restore.unlink(missing_ok=True)
        _save_hashcat_manifest(manifest, config)
    try:
        result = run_hashcat(config, paths=paths, progress=progress)
    except Exception:
        if not paths.restore.is_file():
            manifest.unlink(missing_ok=True)
        raise
    status = {
        HashcatStatus.FOUND: OutcomeStatus.FOUND,
        HashcatStatus.EXHAUSTED: OutcomeStatus.EXHAUSTED,
        HashcatStatus.INTERRUPTED: OutcomeStatus.INTERRUPTED,
    }[result.status]
    kind = CursorKind.LINE if isinstance(config.attack, DictionaryAttack) else CursorKind.INDEX
    outcome = RecoveryOutcome(
        status,
        result.password,
        Cursor(kind, 0),
        0,
        time.monotonic() - started,
        "hashcat",
    )
    if status is not OutcomeStatus.INTERRUPTED or not paths.restore.is_file():
        manifest.unlink(missing_ok=True)
    return outcome


def _hashcat_manifest_payload(config: RecoveryConfig) -> dict[str, object]:
    attack = config.attack
    wordlist_fingerprint = (
        file_fingerprint(attack.wordlist)
        if isinstance(attack, (DictionaryAttack, RulesAttack, HybridAttack))
        else None
    )
    wordlist = (
        {"size": wordlist_fingerprint.size, "sha256": wordlist_fingerprint.sha256}
        if wordlist_fingerprint is not None
        else None
    )
    pdf = file_fingerprint(config.pdf_path)
    return {
        "schema": 1,
        "pdf": {"size": pdf.size, "sha256": pdf.sha256},
        "wordlist": wordlist,
        "attack": normalize_attack(attack),
    }


def _save_hashcat_manifest(path: Path, config: RecoveryConfig) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(_hashcat_manifest_payload(config), stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _validate_hashcat_manifest(path: Path, config: RecoveryConfig) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SessionMismatch(f"cannot load hashcat session manifest: {exc}") from exc
    if payload != _hashcat_manifest_payload(config):
        raise SessionMismatch("hashcat session inputs do not match the saved manifest")


def _notify(callback: NoticeCallback | None, message: str) -> None:
    _LOG.warning(message)
    if callback is not None:
        callback(message)
