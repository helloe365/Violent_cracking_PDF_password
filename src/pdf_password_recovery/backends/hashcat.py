from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from pdf_password_recovery.errors import (
    HashcatExecutionError,
    HashExtractionError,
    ToolIncompatible,
    ToolUnavailable,
    UnsupportedPdfHash,
)
from pdf_password_recovery.models import (
    BruteAttack,
    DictionaryAttack,
    MaskAttack,
    Progress,
    RecoveryConfig,
)

_SMART_RULE_PATH = Path(__file__).resolve().parents[1] / "data" / "smart.rule"

SUPPORTED_PDF_MODES = frozenset({10400, 10500, 10600, 10700, 25400})
SESSION_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
MODE_PATTERN = re.compile(r"Hash-mode\s+#?(\d+)", re.IGNORECASE)
MODE_TABLE_PATTERN = re.compile(r"^\s*(\d+)\s*\|", re.MULTILINE)
GPU_DEVICE_PATTERN = re.compile(r"(?:Device\s+)?Type[^\r\n]*GPU", re.IGNORECASE)
BACKEND_DEVICE_PATTERN = re.compile(
    r"Backend Device ID #(\d+)(?:\s+\(Alias: #(\d+)\))?"
    r"(.*?)(?=\n\s*Backend Device ID #|\Z)",
    re.DOTALL,
)
UNIFIED_MEMORY_PATTERN = re.compile(r"Memory\.Unified[^\r\n]*:\s*0\b", re.IGNORECASE)


class Runner(Protocol):
    def __call__(self, args: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]: ...


Which = Callable[[str], str | None]
ProgressCallback = Callable[[Progress], None]


@dataclass(frozen=True, slots=True)
class Toolchain:
    hashcat: tuple[str, ...]
    pdf2john: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExtractedHash:
    value: str


@dataclass(frozen=True, slots=True)
class SessionPaths:
    prefix: Path
    outfile: Path
    restore: Path

    @classmethod
    def for_session(cls, session: str, base_dir: Path | None = None) -> SessionPaths:
        if not SESSION_PATTERN.fullmatch(session) or session in {".", ".."}:
            raise ToolIncompatible(
                "hashcat session must contain only letters, digits, '.', '_' or '-'"
            )
        root = base_dir or default_session_dir()
        root.mkdir(parents=True, exist_ok=True)
        prefix = (root / session).resolve()
        return cls(
            prefix=prefix,
            outfile=prefix.with_suffix(prefix.suffix + ".outfile"),
            restore=prefix.with_suffix(prefix.suffix + ".restore"),
        )

    @classmethod
    def for_run(cls, session: str | None, base_dir: Path | None = None) -> SessionPaths:
        return cls.for_session(session or f"run-{uuid.uuid4().hex}", base_dir)


class HashcatStatus(StrEnum):
    FOUND = "found"
    EXHAUSTED = "exhausted"
    INTERRUPTED = "interrupted"


@dataclass(frozen=True, slots=True)
class HashcatResult:
    status: HashcatStatus
    password: str | None = None


def default_session_dir() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir()))
    else:
        root = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return root / "pdf-password-recovery" / "hashcat"


def discover_toolchain(
    *,
    which: Which = shutil.which,
    local_root: Path | None = None,
) -> Toolchain:
    if local_root is None and which is shutil.which:
        local_root = _default_local_tool_root()
    hashcat = (
        os.environ.get("PDF_PASSWORD_RECOVERY_HASHCAT")
        or which("hashcat")
        or which("hashcat.exe")
        or _find_local_hashcat(local_root)
    )
    if not hashcat:
        raise ToolUnavailable("hashcat executable was not found on PATH")

    extractor = (
        os.environ.get("PDF_PASSWORD_RECOVERY_PDF2JOHN")
        or which("pdf2john.exe")
        or which("pdf2john")
        or which("pdf2john.py")
        or which("pdf2john.pl")
        or _find_local_extractor(local_root)
    )
    if extractor:
        extractor_path = Path(extractor).resolve()
        if extractor_path.suffix.lower() == ".py":
            return Toolchain(
                (str(Path(hashcat).resolve()),),
                (sys.executable, str(extractor_path)),
            )
        if extractor_path.suffix.lower() == ".pl":
            perl = which("perl") or which("perl.exe")
            if not perl:
                raise ToolUnavailable("pdf2john.pl was found, but Perl is unavailable")
            return Toolchain(
                (str(Path(hashcat).resolve()),),
                (str(Path(perl).resolve()), str(extractor_path)),
            )
        return Toolchain(
            (str(Path(hashcat).resolve()),),
            (str(extractor_path),),
        )

    raise ToolUnavailable("pdf2john, pdf2john.py, or pdf2john.pl was not found on PATH")


def _default_local_tool_root() -> Path | None:
    try:
        root = Path(__file__).resolve().parents[3] / "downloads" / "gpu-tools"
    except IndexError:  # pragma: no cover - installed layouts are always deeper
        return None
    return root if root.is_dir() else None


def _find_local_hashcat(root: Path | None) -> str | None:
    if root is None:
        return None
    candidates = sorted(root.glob("hashcat-*/hashcat.exe"), reverse=True)
    return str(candidates[0]) if candidates else None


def _find_local_extractor(root: Path | None) -> str | None:
    if root is None:
        return None
    for name in ("pdf2john.exe", "pdf2john.py", "pdf2john.pl"):
        candidate = root / name
        if candidate.is_file():
            return str(candidate)
    return None


def _run_preflight(runner: Runner, args: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    cwd = _command_cwd(args)
    try:
        return runner(args, capture_output=True, text=True, shell=False, cwd=cwd)
    except OSError as exc:
        raise ToolUnavailable(f"could not start external tool {args[0]!r}: {exc}") from exc


def _command_cwd(args: Sequence[str]) -> str | None:
    for value in args[:2]:
        path = Path(value)
        if path.is_absolute() and path.suffix.lower() in {".py", ".pl"}:
            return str(path.parent)
    executable = Path(args[0])
    return str(executable.parent) if executable.is_absolute() else None


def extract_pdf_hash(
    toolchain: Toolchain,
    pdf_path: Path,
    runner: Runner = subprocess.run,
) -> ExtractedHash:
    args = (*toolchain.pdf2john, str(pdf_path.resolve()))
    result = _run_preflight(runner, args)
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit code {result.returncode}"
        raise HashExtractionError(f"pdf2john failed: {detail}")
    for line in result.stdout.splitlines():
        marker = line.find("$pdf$")
        if marker >= 0:
            value = line[marker:].strip()
            if value and not any(char.isspace() for char in value):
                return ExtractedHash(_normalize_pdf_hash(value))
    raise HashExtractionError("pdf2john produced no single-line $pdf$ hash")


def _normalize_pdf_hash(value: str) -> str:
    fields = value.split("*")
    if len(fields) < 5 or not fields[0].startswith("$pdf$"):
        return value
    try:
        permissions = int(fields[3])
    except ValueError:
        return value
    if 2**31 <= permissions < 2**32:
        fields[3] = str(permissions - 2**32)
    return "*".join(fields)


def identify_pdf_mode(
    toolchain: Toolchain,
    pdf_hash: str | ExtractedHash,
    runner: Runner = subprocess.run,
) -> int:
    value = pdf_hash.value if isinstance(pdf_hash, ExtractedHash) else pdf_hash
    args = (*toolchain.hashcat, "--identify", value)
    result = _run_preflight(runner, args)
    combined = f"{result.stdout}\n{result.stderr}"
    modes = {
        int(match)
        for pattern in (MODE_PATTERN, MODE_TABLE_PATTERN)
        for match in pattern.findall(combined)
    }
    if result.returncode != 0 or len(modes) != 1 or not modes <= SUPPORTED_PDF_MODES:
        raise UnsupportedPdfHash(
            "hashcat did not uniquely identify a supported PDF mode "
            f"({', '.join(map(str, sorted(SUPPORTED_PDF_MODES)))})"
        )
    return modes.pop()


def verify_gpu_device(
    toolchain: Toolchain,
    runner: Runner = subprocess.run,
) -> tuple[str, ...]:
    args = (*toolchain.hashcat, "-I")
    result = _run_preflight(runner, args)
    inventory = f"{result.stdout}\n{result.stderr}"
    if result.returncode != 0 or GPU_DEVICE_PATTERN.search(inventory) is None:
        raise ToolIncompatible("hashcat found no usable GPU device")
    selected: list[str] = []
    covered_ids: set[str] = set()
    for match in BACKEND_DEVICE_PATTERN.finditer(inventory):
        device_id, alias, details = match.groups()
        normalized_id = str(int(device_id))
        normalized_alias = str(int(alias)) if alias else None
        if normalized_id in covered_ids or not UNIFIED_MEMORY_PATTERN.search(details):
            continue
        selected.append(normalized_id)
        covered_ids.add(normalized_id)
        if normalized_alias is not None:
            covered_ids.add(normalized_alias)
    return tuple(selected)


def _parse_hashcat_status(line: str, elapsed: float) -> Progress | None:
    start = line.find("{")
    end = line.rfind("}")
    if start < 0 or end < start:
        return None
    try:
        payload = json.loads(line[start : end + 1])
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    values = payload.get("progress")
    devices = payload.get("devices")
    if (
        not isinstance(values, list)
        or len(values) != 2
        or not all(isinstance(value, int) and not isinstance(value, bool) for value in values)
        or values[0] < 0
        or values[1] <= 0
        or not isinstance(devices, list)
        or not devices
    ):
        return None
    speeds: list[float] = []
    for device in devices:
        if not isinstance(device, dict):
            return None
        speed = device.get("speed")
        if not isinstance(speed, (int, float)) or isinstance(speed, bool) or speed < 0:
            return None
        speeds.append(float(speed))
    completed, total = values
    return Progress(
        completed=completed,
        total=total,
        attempted=completed,
        elapsed=elapsed,
        rate=sum(speeds),
        backend="hashcat",
        workers=len(devices),
    )


def _common_args(
    toolchain: Toolchain,
    mode: int,
    attack_mode: int,
    paths: SessionPaths,
    device_ids: Sequence[str] = (),
) -> list[str]:
    args = [
        *toolchain.hashcat,
        "-m",
        str(mode),
        "-a",
        str(attack_mode),
        "-D",
        "2",
    ]
    if device_ids:
        args.extend(("-d", ",".join(device_ids)))
    args.extend(
        [
            "--status",
            "--status-json",
            "--status-timer",
            "1",
            "--potfile-disable",
            "--outfile",
            str(paths.outfile),
            "--outfile-format",
            "2",
            "--session",
            paths.prefix.name,
            "--restore-file-path",
            str(paths.restore),
        ]
    )
    return args


def _brute_charset(charset: str) -> str:
    presets: Mapping[str, str] = {
        "digits": "0123456789",
        "lower": "abcdefghijklmnopqrstuvwxyz",
        "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "letters": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "alnum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    }
    value = presets.get(charset, charset)
    if not value:
        raise ToolIncompatible("hashcat custom charset cannot be empty")
    if not value.isascii():
        raise ToolIncompatible("hashcat custom charset must contain only ASCII characters")
    return "".join(dict.fromkeys(value))


def _hashcat_length_rule(min_length: int, max_length: int) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    try:
        minimum = alphabet[min_length]
        maximum = alphabet[max_length]
    except IndexError as exc:
        raise ToolIncompatible("hashcat dictionary length bounds cannot exceed 35") from exc
    return f">{minimum}<{maximum}"


def build_hashcat_args(
    config: RecoveryConfig,
    toolchain: Toolchain,
    mode: int,
    pdf_hash: str | ExtractedHash,
    paths: SessionPaths,
    device_ids: Sequence[str] = (),
) -> tuple[str, ...]:
    if config.resume:
        args = [
            *toolchain.hashcat,
            "-D",
            "2",
        ]
        if device_ids:
            args.extend(("-d", ",".join(device_ids)))
        args.extend(
            [
                "--status",
                "--status-json",
                "--status-timer",
                "1",
                "--session",
                paths.prefix.name,
                "--restore-file-path",
                str(paths.restore),
                "--restore",
            ]
        )
        return tuple(args)

    value = pdf_hash.value if isinstance(pdf_hash, ExtractedHash) else pdf_hash
    attack = config.attack
    if isinstance(attack, DictionaryAttack):
        args = _common_args(toolchain, mode, 0, paths, device_ids)
        if attack.min_length is not None:
            args.extend(("-j", _hashcat_length_rule(attack.min_length, attack.max_length)))
        if attack.apply_rules:
            args.extend(("-r", str(_SMART_RULE_PATH)))
        args.extend((value, str(attack.wordlist.resolve())))
    elif isinstance(attack, MaskAttack):
        args = _common_args(toolchain, mode, 3, paths, device_ids)
        args.extend((value, attack.mask))
    elif isinstance(attack, BruteAttack):
        charset = _brute_charset(attack.charset)
        args = _common_args(toolchain, mode, 3, paths, device_ids)
        args.extend(
            (
                "--increment",
                "--increment-min",
                str(attack.min_length),
                "--increment-max",
                str(attack.max_length),
                "-1",
                charset,
                value,
                "?1" * attack.max_length,
            )
        )
    else:  # pragma: no cover - RecoveryConfig constrains the union
        raise ToolIncompatible(f"unsupported hashcat attack: {type(attack).__name__}")
    return tuple(args)


def _read_password(outfile: Path, encoding: str) -> str:
    try:
        lines = outfile.read_bytes().splitlines()
    except OSError as exc:
        raise HashcatExecutionError(f"could not read hashcat result: {exc}") from exc
    if not lines:
        raise HashcatExecutionError("hashcat reported success but produced no password")
    raw = lines[0]
    if raw.startswith(b"$HEX["):
        if not raw.endswith(b"]"):
            raise HashcatExecutionError("hashcat produced an invalid $HEX password")
        encoded = raw[5:-1]
        if not re.fullmatch(rb"[0-9a-fA-F]*", encoded):
            raise HashcatExecutionError("hashcat produced an invalid $HEX password")
        try:
            raw = bytes.fromhex(encoded.decode("ascii"))
        except ValueError as exc:
            raise HashcatExecutionError("hashcat produced an invalid $HEX password") from exc
    try:
        return raw.decode(encoding)
    except LookupError as exc:
        raise HashcatExecutionError(f"unknown password encoding: {encoding}") from exc
    except UnicodeDecodeError as exc:
        raise HashcatExecutionError(
            f"hashcat password cannot be decoded using {encoding}: {exc}"
        ) from exc


def run_hashcat(
    config: RecoveryConfig,
    toolchain: Toolchain | None = None,
    paths: SessionPaths | None = None,
    runner: Runner = subprocess.run,
    progress: ProgressCallback | None = None,
) -> HashcatResult:
    tools = toolchain or discover_toolchain()
    device_ids: tuple[str, ...] = ()
    if runner is subprocess.run:
        device_ids = verify_gpu_device(tools, runner)
    session_paths = paths or SessionPaths.for_run(config.session)
    session_paths.outfile.unlink(missing_ok=True)

    if config.resume:
        args = build_hashcat_args(config, tools, 0, "", session_paths, device_ids)
    else:
        extracted = extract_pdf_hash(tools, config.pdf_path, runner)
        mode = identify_pdf_mode(tools, extracted, runner)
        args = build_hashcat_args(config, tools, mode, extracted, session_paths, device_ids)

    try:
        if runner is subprocess.run:
            result = _run_live_hashcat(args, progress=progress)
        else:
            try:
                result = runner(args, capture_output=True, text=True, shell=False)
            except OSError as exc:
                raise ToolUnavailable(f"could not start hashcat: {exc}") from exc
        if result.returncode == 0:
            encoding = (
                config.attack.encoding if isinstance(config.attack, DictionaryAttack) else "utf-8"
            )
            return HashcatResult(
                HashcatStatus.FOUND,
                _read_password(session_paths.outfile, encoding),
            )
        if result.returncode == 1:
            return HashcatResult(HashcatStatus.EXHAUSTED)
        if result.returncode in {2, 3}:
            return HashcatResult(HashcatStatus.INTERRUPTED)
        stderr = result.stderr or ""
        stdout = result.stdout or ""
        detail = stderr.strip() or stdout.strip() or f"exit code {result.returncode}"
        raise HashcatExecutionError(f"hashcat failed: {detail}")
    finally:
        session_paths.outfile.unlink(missing_ok=True)


def _run_live_hashcat(
    args: Sequence[str], progress: ProgressCallback | None = None
) -> subprocess.CompletedProcess[str]:
    executable = Path(args[0])
    try:
        process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE if progress is not None else None,
            stderr=None,
            text=True,
            bufsize=1,
            shell=False,
            cwd=str(executable.parent) if executable.is_absolute() else None,
        )
    except OSError as exc:
        raise ToolUnavailable(f"could not start hashcat: {exc}") from exc
    try:
        try:
            if progress is None:
                stdout, stderr = process.communicate()
            else:
                started = time.monotonic()
                captured: list[str] = []
                assert process.stdout is not None
                for line in process.stdout:
                    captured.append(line)
                    update = _parse_hashcat_status(line, time.monotonic() - started)
                    if update is not None:
                        progress(update)
                process.wait()
                stdout, stderr = "".join(captured), None
        except KeyboardInterrupt:
            if process.stdin is not None:
                try:
                    process.stdin.write("c\n")
                    process.stdin.flush()
                except OSError:
                    pass
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    stdout, stderr = process.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
            return subprocess.CompletedProcess(args, 2, stdout, stderr)
        except OSError as exc:
            with suppress(OSError):
                process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                with suppress(OSError):
                    process.kill()
                with suppress(OSError, subprocess.TimeoutExpired):
                    process.wait(timeout=2)
            raise HashcatExecutionError(f"hashcat process I/O failed: {exc}") from exc
        return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
