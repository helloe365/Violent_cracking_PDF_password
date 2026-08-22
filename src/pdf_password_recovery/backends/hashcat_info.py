from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pdf_password_recovery.errors import ConfigurationError, ToolIncompatible
from pdf_password_recovery.models import WorkloadProfile

from .hashcat import SUPPORTED_PDF_MODES, Toolchain, extract_pdf_hash, identify_pdf_mode

Runner = Callable[..., subprocess.CompletedProcess[str]]

_VERSION = re.compile(r"(?:hashcat\s*\(?\s*v?|\bv)(\d+(?:\.\d+){1,3})", re.I)
_DEVICE = re.compile(
    r"Backend Device ID\s*#\s*(\d+)\s*(?:\(\s*Alias:\s*#?([\d,\s#]+)\))?"
    r"(.*?)(?=\n\s*Backend Device ID\s*#|\Z)",
    re.I | re.S,
)
_FIELD = re.compile(r"^\s*([^.:\r\n]+?)[. ]*:\s*(.*?)\s*$", re.M)
_SPEED = re.compile(r"Speed(?:\.#\d+)?[^:]*:\s*([\d.,]+)\s*([KMGTPE]?)(?:i?H/s)?", re.I)
_REQUIRED_OPTIONS = frozenset(
    {
        "--benchmark",
        "--identify",
        "--potfile-disable",
        "--restore",
        "--restore-file-path",
        "--runtime",
        "--session",
        "--status-json",
        "-a",
        "-D",
        "-d",
        "-m",
        "-w",
    }
)


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    id: str
    name: str
    runtime: str
    device_type: str
    unified_memory: bool
    alias_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class HashcatCapabilities:
    version: str
    executable_fingerprint: str
    supported_options: frozenset[str]
    supported_pdf_modes: frozenset[int]
    devices: tuple[DeviceInfo, ...]


@dataclass(frozen=True, slots=True)
class PreflightReport:
    pdf_mode: int
    capabilities: HashcatCapabilities
    selected_devices: tuple[DeviceInfo, ...]
    workload: WorkloadProfile
    benchmark_hps: float | None
    cache_hit: bool
    warnings: tuple[str, ...] = ()


def _workload(value: WorkloadProfile | str) -> WorkloadProfile:
    try:
        return WorkloadProfile(value)
    except ValueError as exc:
        raise ConfigurationError("workload must be quiet, balanced, or fast") from exc


def _run(runner: Runner, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    executable = Path(args[0])
    cwd = str(executable.parent) if executable.is_absolute() else None
    try:
        return runner(args, capture_output=True, text=True, shell=False, cwd=cwd)
    except OSError as exc:
        raise ToolIncompatible(f"could not start hashcat: {exc}") from exc


def _text(result: subprocess.CompletedProcess[str]) -> str:
    stdout = result.stdout if isinstance(result.stdout, str) else ""
    stderr = result.stderr if isinstance(result.stderr, str) else ""
    return f"{stdout}\n{stderr}"


def _fingerprint(executable: str) -> str:
    try:
        digest = hashlib.sha256()
        with Path(executable).open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return hashlib.sha256(executable.encode()).hexdigest()


def _parse_options(help_text: str) -> frozenset[str]:
    options: set[str] = set()
    for line in help_text.splitlines():
        for option in re.findall(r"(?<![\w-])(--[a-z0-9][a-z0-9-]*|-[A-Za-z0-9])(?![\w-])", line):
            options.add(option)
    return frozenset(options)


def _parse_devices(inventory: str) -> tuple[DeviceInfo, ...]:
    raw: list[tuple[str, set[str], dict[str, str]]] = []
    for match in _DEVICE.finditer(inventory):
        device_id, aliases, details = match.groups()
        ids = {str(int(device_id))}
        if aliases:
            ids.update(str(int(value)) for value in re.findall(r"\d+", aliases))
        fields = {
            key.strip().lower().replace(" ", "_"): value.strip()
            for key, value in _FIELD.findall(details)
        }
        unified_match = re.search(r"Memory\.Unified[^:]*:\s*(\d+)", details, re.I)
        if unified_match:
            fields["memory_unified"] = unified_match.group(1)
        raw.append((str(int(device_id)), ids, fields))
    if not raw:
        return ()

    groups: list[set[str]] = []
    for _, ids, _ in raw:
        matching = [group for group in groups if group & ids]
        if not matching:
            groups.append(set(ids))
        else:
            merged = set(ids)
            for group in matching:
                merged.update(group)
                groups.remove(group)
            groups.append(merged)

    devices: list[DeviceInfo] = []
    for group in sorted(groups, key=lambda value: min(map(int, value))):
        records = [item for item in raw if item[1] & group]
        canonical = min(group, key=int)
        fields = records[0][2]
        name = fields.get("name", "")
        runtime = fields.get("backend", fields.get("runtime", ""))
        device_type = fields.get("type", "GPU").upper()
        unified = fields.get("memory_unified", "") not in {"", "0", "false", "no"}
        for _, _, candidate in records[1:]:
            name = name or candidate.get("name", "")
            runtime = runtime or candidate.get("backend", candidate.get("runtime", ""))
            unified = unified or candidate.get("memory_unified", "") not in {
                "",
                "0",
                "false",
                "no",
            }
        devices.append(
            DeviceInfo(
                canonical,
                name,
                runtime,
                device_type,
                unified,
                tuple(sorted(group - {canonical}, key=int)),
            )
        )
    return tuple(devices)


def inspect_hashcat(toolchain: Toolchain, runner: Runner = subprocess.run) -> HashcatCapabilities:
    executable = toolchain.hashcat[0]
    version_result = _run(runner, (*toolchain.hashcat, "--version"))
    version_match = _VERSION.search(_text(version_result))
    if version_result.returncode != 0 or version_match is None:
        raise ToolIncompatible("could not determine hashcat version")
    help_result = _run(runner, (*toolchain.hashcat, "--help"))
    options = _parse_options(_text(help_result))
    missing = _REQUIRED_OPTIONS - options
    if help_result.returncode != 0 or missing:
        missing_text = ", ".join(sorted(missing))
        raise ToolIncompatible(f"hashcat is missing required options: {missing_text}")
    inventory_result = _run(runner, (*toolchain.hashcat, "-I"))
    if inventory_result.returncode != 0:
        raise ToolIncompatible("hashcat backend inventory failed")
    devices = _parse_devices(_text(inventory_result))
    if not devices:
        raise ToolIncompatible("hashcat backend inventory contained no devices")
    return HashcatCapabilities(
        version=version_match.group(1),
        executable_fingerprint=_fingerprint(executable),
        supported_options=options,
        supported_pdf_modes=frozenset(SUPPORTED_PDF_MODES),
        devices=devices,
    )


def _device_map(capabilities: HashcatCapabilities) -> dict[str, DeviceInfo]:
    values: dict[str, DeviceInfo] = {}
    for device in capabilities.devices:
        values[device.id] = device
        for alias in device.alias_ids:
            values[alias] = device
    return values


def select_devices(
    capabilities: HashcatCapabilities, requested: str | Sequence[str] | None = "auto"
) -> tuple[DeviceInfo, ...]:
    request = "auto" if requested is None else requested
    if isinstance(request, str) and request.strip().lower() == "auto":
        selected = tuple(
            device
            for device in capabilities.devices
            if device.device_type.upper() == "GPU" and not device.unified_memory
        )
        if not selected:
            raise ToolIncompatible("hashcat found no usable discrete GPU device")
        return selected
    values = request.split(",") if isinstance(request, str) else list(request)
    if not values or any(not str(value).strip().isdigit() for value in values):
        raise ConfigurationError("device selection must be auto or comma-separated IDs")
    lookup = _device_map(capabilities)
    selected: list[DeviceInfo] = []
    seen_input: set[str] = set()
    seen_physical: set[str] = set()
    for value in values:
        device_id = str(int(str(value).strip()))
        if device_id in seen_input:
            continue
        seen_input.add(device_id)
        device = lookup.get(device_id)
        if device is None:
            raise ToolIncompatible(f"hashcat device ID does not exist: {device_id}")
        if device.device_type.upper() != "GPU":
            raise ToolIncompatible(f"hashcat device ID is not a GPU: {device_id}")
        if device.unified_memory:
            raise ToolIncompatible(f"hashcat device ID uses unified memory: {device_id}")
        if device.id in seen_physical:
            raise ToolIncompatible("device aliases cannot select one physical GPU twice")
        seen_physical.add(device.id)
        selected.append(device)
    return tuple(selected)


class PreflightCache:
    def __init__(self, root: Path, ttl: timedelta = timedelta(days=7)) -> None:
        self.root = Path(root)
        self.ttl = ttl
        self.path = self.root / "preflight-cache.json"

    @staticmethod
    def make_key(
        capabilities: HashcatCapabilities,
        pdf_mode: int,
        devices: Sequence[DeviceInfo],
        workload: WorkloadProfile | str,
    ) -> str:
        payload = {
            "executable": capabilities.executable_fingerprint,
            "version": capabilities.version,
            "pdf_mode": pdf_mode,
            "devices": [
                {"id": d.id, "runtime": d.runtime, "aliases": d.alias_ids} for d in devices
            ],
            "workload": _workload(workload).value,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def lookup(self, key: str) -> tuple[float | None, str | None]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            entry = payload["entries"][key]
            created = datetime.fromisoformat(entry["created_at"])
            value = entry["benchmark_hps"]
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValueError("invalid benchmark value")
            if datetime.now(UTC) - created > self.ttl:
                return None, "cached hashcat benchmark is stale"
            return float(value), None
        except FileNotFoundError:
            return None, None
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return None, f"ignored malformed hashcat benchmark cache: {exc}"

    def get(self, key: str) -> float | None:
        return self.lookup(key)[0]

    def write(self, key: str, benchmark_hps: float) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or not isinstance(payload.get("entries"), dict):
                payload = {"schema": 1, "entries": {}}
        except (OSError, ValueError, json.JSONDecodeError):
            payload = {"schema": 1, "entries": {}}
        payload["entries"][key] = {
            "created_at": datetime.now(UTC).isoformat(),
            "benchmark_hps": float(benchmark_hps),
        }
        handle, name = tempfile.mkstemp(prefix=".preflight-", suffix=".tmp", dir=self.root)
        temporary = Path(name)
        try:
            with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(payload, stream, sort_keys=True)
                stream.write("\n")
                stream.flush()
            temporary.replace(self.path)
        finally:
            temporary.unlink(missing_ok=True)

    set = write


def _parse_speed(output: str) -> float | None:
    total = 0.0
    found = False
    multipliers = {"": 1.0, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18}
    for match in _SPEED.finditer(output):
        try:
            total += float(match.group(1).replace(",", "")) * multipliers[match.group(2).upper()]
            found = True
        except (KeyError, ValueError):
            continue
    return total if found else None


def run_preflight(
    pdf_path: Path,
    workload: WorkloadProfile | str = WorkloadProfile.BALANCED,
    requested_devices: str | Sequence[str] = "auto",
    refresh: bool = False,
    cache: PreflightCache | None = None,
    toolchain: Toolchain | None = None,
    runner: Runner = subprocess.run,
) -> PreflightReport:
    selected_workload = _workload(workload)
    tools = toolchain
    if tools is None:
        from .hashcat import discover_toolchain

        tools = discover_toolchain()
    pdf_hash = extract_pdf_hash(tools, Path(pdf_path), runner)
    mode = identify_pdf_mode(tools, pdf_hash, runner)
    capabilities = inspect_hashcat(tools, runner)
    devices = select_devices(capabilities, requested_devices)
    store = cache or PreflightCache(Path.home() / ".cache" / "pdf-password-recovery")
    key = store.make_key(capabilities, mode, devices, selected_workload)
    warnings: list[str] = []
    if not refresh:
        speed, warning = store.lookup(key)
        if warning:
            warnings.append(warning)
        if speed is not None:
            return PreflightReport(
                mode, capabilities, devices, selected_workload, speed, True, tuple(warnings)
            )
    args = (
        *tools.hashcat,
        "-m",
        str(mode),
        "-D",
        "2",
        "-d",
        ",".join(device.id for device in devices),
        "-w",
        selected_workload.hashcat_value,
        "--benchmark",
        "--runtime",
        "3",
        "--potfile-disable",
    )
    try:
        result = _run(runner, args)
        speed = _parse_speed(_text(result)) if result.returncode == 0 else None
    except (OSError, ToolIncompatible):
        speed = None
    if speed is None:
        warnings.append("hashcat benchmark failed; ETA is unknown")
    else:
        store.write(key, speed)
    return PreflightReport(
        mode, capabilities, devices, selected_workload, speed, False, tuple(warnings)
    )
