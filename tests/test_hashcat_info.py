from __future__ import annotations

import subprocess

from pdf_password_recovery.backends.hashcat import Toolchain
from pdf_password_recovery.backends.hashcat_info import (
    DeviceInfo,
    HashcatCapabilities,
    PreflightCache,
    _parse_devices,
    _parse_speed,
    inspect_hashcat,
    select_devices,
)


def test_inventory_merges_aliases_and_keeps_discrete_gpu(tmp_path):
    inventory = """
Backend Device ID #1 (Alias: #2)
  Type...........: GPU
  Name...........: NVIDIA RTX 3050
  Backend........: CUDA
  Memory.Unified.: 0
Backend Device ID #2
  Type...........: GPU
  Name...........: NVIDIA RTX 3050
  Backend........: OpenCL
  Memory.Unified.: 0
Backend Device ID #3
  Type...........: GPU
  Name...........: Intel UHD
  Backend........: OpenCL
  Memory.Unified.: 1
"""
    devices = _parse_devices(inventory)
    assert devices[0].alias_ids == ("2",)
    assert select_devices(HashcatCapabilities("7.1.2", "x", frozenset(), frozenset(), devices)) == (
        devices[0],
    )


def test_explicit_alias_duplicate_is_rejected():
    devices = (DeviceInfo("1", "RTX", "CUDA", "GPU", False, ("2",)),)
    capabilities = HashcatCapabilities("7.1.2", "x", frozenset(), frozenset(), devices)
    try:
        select_devices(capabilities, "1,2")
    except Exception as exc:
        assert "physical" in str(exc)
    else:
        raise AssertionError("expected duplicate physical device rejection")


def test_explicit_gpu_id_may_select_unified_memory_device():
    device = DeviceInfo("3", "Intel UHD", "OpenCL", "GPU", True)
    capabilities = HashcatCapabilities("7.1.2", "x", frozenset(), frozenset(), (device,))
    assert select_devices(capabilities, "3") == (device,)


def test_cache_round_trip_and_stale_state(tmp_path):
    cache = PreflightCache(tmp_path)
    cache.write("key", 1234.0)
    assert cache.get("key") == 1234.0
    cache.path.write_text(
        '{"entries":{"key":{"created_at":"2000-01-01T00:00:00+00:00","benchmark_hps":1}}}',
        encoding="utf-8",
    )
    value, warning = cache.lookup("key")
    assert value is None and warning and "stale" in warning


def test_speed_parser_sums_hashcat_units():
    assert _parse_speed("Speed.#01.........: 1.5 GH/s\nSpeed.#02: 500 MH/s") == 2_000_000_000


def test_inspect_hashcat_parses_version_help_and_inventory(tmp_path):
    executable = tmp_path / "hashcat.exe"
    executable.write_bytes(b"fixture")
    toolchain = Toolchain((str(executable),), ("pdf2john",))
    help_text = " ".join(
        [
            "--benchmark --identify --potfile-disable --restore --restore-file-path",
            "--runtime --session --status-json -a -D -d -m -w",
        ]
    )
    inventory = "Backend Device ID #1\n Type: GPU\n Name: RTX\n Backend: CUDA\n Memory.Unified.: 0"

    def runner(args, **kwargs):
        flag = args[-1]
        if flag == "--version":
            return subprocess.CompletedProcess(args, 0, "hashcat (v7.1.2)", "")
        if flag == "--help":
            return subprocess.CompletedProcess(args, 0, help_text, "")
        return subprocess.CompletedProcess(args, 0, inventory, "")

    capabilities = inspect_hashcat(toolchain, runner)
    assert capabilities.version == "7.1.2"
    assert capabilities.devices[0].name == "RTX"
