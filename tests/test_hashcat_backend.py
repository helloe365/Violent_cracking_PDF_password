from __future__ import annotations

from pathlib import Path

from pdf_password_recovery.backends.hashcat import SessionPaths, Toolchain, build_hashcat_args
from pdf_password_recovery.models import (
    BruteAttack,
    BackendChoice,
    DictionaryAttack,
    HybridAttack,
    MaskAttack,
    RecoveryConfig,
    WorkloadProfile,
)


def _paths(tmp_path: Path) -> SessionPaths:
    return SessionPaths.for_session("test", tmp_path)


def test_legacy_dictionary_args_keep_core_flags_and_add_balanced_workload(tmp_path):
    config = RecoveryConfig(Path("a.pdf"), DictionaryAttack(tmp_path / "words.txt"))
    args = build_hashcat_args(
        config, Toolchain(("hashcat",), ("pdf2john",)), 10400, "$pdf$hash", _paths(tmp_path), ("1",)
    )
    assert args[0:4] == ("hashcat", "-m", "10400", "-a")
    assert "--potfile-disable" in args and "--status-json" in args
    assert args[args.index("-w") + 1] == "2"


def test_mask_and_hybrid_modes(tmp_path):
    toolchain = Toolchain(("hashcat",), ("pdf2john",))
    paths = _paths(tmp_path)
    base = dict(backend=BackendChoice.HASHCAT, workload=WorkloadProfile.FAST)
    mask = build_hashcat_args(
        RecoveryConfig(Path("a.pdf"), MaskAttack("?d?d"), **base), toolchain, 10400, "hash", paths
    )
    append = build_hashcat_args(
        RecoveryConfig(Path("a.pdf"), HybridAttack(tmp_path / "w", "?d", "append"), **base),
        toolchain,
        10400,
        "hash",
        paths,
    )
    prepend = build_hashcat_args(
        RecoveryConfig(Path("a.pdf"), HybridAttack(tmp_path / "w", "?d", "prepend"), **base),
        toolchain,
        10400,
        "hash",
        paths,
    )
    assert "-a" in mask and mask[mask.index("-a") + 1] == "3"
    assert append[append.index("-a") + 1] == "6"
    assert prepend[prepend.index("-a") + 1] == "7"


def test_restore_has_no_attack_hash_or_potfile(tmp_path):
    config = RecoveryConfig(
        Path("a.pdf"),
        BruteAttack(),
        session="test",
        resume=True,
        workload=WorkloadProfile.QUIET,
    )
    args = build_hashcat_args(
        config, Toolchain(("hashcat",), ("pdf2john",)), 10400, "", _paths(tmp_path)
    )
    assert "--restore" in args and "--potfile-disable" not in args
    assert args.count("--status-json") == 1
    assert args[args.index("-w") + 1] == "1"
