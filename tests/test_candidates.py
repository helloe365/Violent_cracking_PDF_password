from __future__ import annotations

from pathlib import Path

import pytest

from pdf_password_recovery.backends.hashcat import SessionPaths, Toolchain, build_hashcat_args
from pdf_password_recovery.candidates import (
    BruteSpace,
    HybridSpace,
    MaskSpace,
    compile_mask,
)
from pdf_password_recovery.errors import MaskSyntaxError
from pdf_password_recovery.models import BackendChoice, MaskAttack, RecoveryConfig
from pdf_password_recovery.plans import parse_hcmask


def test_mask_compilation_supports_caller_custom_charsets_without_changing_legacy_tokens() -> None:
    assert compile_mask("?1?2?d??", ("ab", "XY")) == ("ab", "XY", "0123456789", "?")
    assert MaskSpace.compile("?d??").candidate_at(9) == "9?"


def test_parse_hcmask_skips_comments_and_keeps_escaped_leading_hash_and_charsets(
    tmp_path: Path,
) -> None:
    mask_file = tmp_path / "common.hcmask"
    mask_file.write_text("# comment\n\\#?d\n?d?l,!?1\n\n", encoding="utf-8")

    entries = parse_hcmask(mask_file)

    assert [(entry.line_number, entry.mask, entry.custom_charsets) for entry in entries] == [
        (2, "#?d", ()),
        (3, "!?1", ("?d?l",)),
    ]


@pytest.mark.parametrize("content", ["a,b,c,d,e,f,g,h,i,?1\n", "?d,\n", "?9\n"])
def test_parse_hcmask_reports_invalid_physical_lines(tmp_path: Path, content: str) -> None:
    mask_file = tmp_path / "invalid.hcmask"
    mask_file.write_text(content, encoding="utf-8")

    with pytest.raises(MaskSyntaxError, match=r"invalid\.hcmask:1"):
        parse_hcmask(mask_file)


def test_hybrid_space_is_lazy_and_maps_append_and_prepend_boundaries(tmp_path: Path) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("a\nb\n", encoding="utf-8")
    mask = MaskSpace.compile("?d")

    append = HybridSpace(wordlist, "utf-8", mask, "append")
    prepend = HybridSpace(wordlist, "utf-8", mask, "prepend")

    assert append.total == 20
    assert [append.candidate_at(index) for index in (0, 9, 10, 19)] == ["a0", "a9", "b0", "b9"]
    assert [prepend.candidate_at(index) for index in (0, 19)] == ["0a", "9b"]
    assert not hasattr(append, "words")


def test_legacy_brute_space_boundaries_remain_unchanged() -> None:
    space = BruteSpace.create("digits", 1, 2)

    assert space.total == 110
    assert [space.candidate_at(index) for index in (0, 9, 10, 109)] == ["0", "9", "00", "99"]


def test_mask_custom_charsets_reach_cpu_and_hashcat_argv_in_order(tmp_path: Path) -> None:
    attack = MaskAttack("?1?2", ("ab", "CD"))
    assert MaskSpace.compile(attack.mask, attack.custom_charsets).candidate_at(0) == "aC"

    paths = SessionPaths(tmp_path / "session", tmp_path / "out", tmp_path / "restore")
    config = RecoveryConfig(tmp_path / "protected.pdf", attack, BackendChoice.HASHCAT)
    args = build_hashcat_args(config, Toolchain(("hashcat",), ("pdf2john",)), 10400, "hash", paths)
    assert args[args.index("-1") : args.index("hash")] == ("-1", "ab", "-2", "CD")
