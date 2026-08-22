from __future__ import annotations

import json
from pathlib import Path

import pytest

from pdf_password_recovery.assets import bundled_wordlist
from pdf_password_recovery.candidates import SMART_RULES
from pdf_password_recovery.errors import ConfigurationError, PlanSchemaError
from pdf_password_recovery.models import BackendChoice, DictionaryStage, MaskStage, RulesStage
from pdf_password_recovery.plans import built_in_plan, compile_plan, load_plan


def _write_plan(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _dictionary_plan(wordlist: str = "words.txt") -> dict[str, object]:
    return {
        "schema": 1,
        "name": "small-plan",
        "stages": [{"id": "words", "type": "dictionary", "wordlist": wordlist}],
    }


def test_load_plan_requires_the_exact_schema_and_resolves_relative_paths(tmp_path: Path) -> None:
    plan_path = tmp_path / "plans" / "attack.json"
    plan_path.parent.mkdir(parents=True)
    _write_plan(plan_path, _dictionary_plan("../words.txt"))

    plan = load_plan(plan_path)

    assert plan.schema == 1
    assert plan.name == "small-plan"
    assert plan.stages == (
        DictionaryStage(id="words", wordlist=(tmp_path / "words.txt").resolve()),
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"schema": 1, "name": "x", "stages": [], "extra": 1},
        {"schema": True, "name": "x", "stages": []},
        {"schema": 1, "name": "x", "stages": [{"id": "x", "type": "unknown"}]},
        {
            "schema": 1,
            "name": "x",
            "stages": [
                {"id": "same", "type": "mask", "mask": "?d"},
                {"id": "same", "type": "mask", "mask": "?l"},
            ],
        },
        {
            "schema": 1,
            "name": "x",
            "stages": [
                {
                    "id": "both",
                    "type": "mask",
                    "mask": "?d",
                    "mask_file": "masks.hcmask",
                }
            ],
        },
        {
            "schema": 1,
            "name": "x",
            "stages": [
                {
                    "id": "wrong-direction",
                    "type": "hybrid",
                    "wordlist": "words.txt",
                    "mask": "?d",
                    "direction": "sideways",
                }
            ],
        },
    ],
)
def test_load_plan_rejects_unknown_or_invalid_schema_values(
    tmp_path: Path, payload: object
) -> None:
    with pytest.raises(PlanSchemaError) as raised:
        load_plan(_write_plan(tmp_path / "invalid.json", payload))

    assert raised.value.code == "plan_schema"


def test_load_plan_resolves_only_the_documented_builtin_references(tmp_path: Path) -> None:
    payload = {
        "schema": 1,
        "name": "builtins",
        "stages": [
            {"id": "words", "type": "dictionary", "wordlist": "builtin:wordlist"},
            {
                "id": "rules",
                "type": "rules",
                "wordlist": "builtin:wordlist",
                "rules": ["builtin:smart-rules"],
            },
            {"id": "masks", "type": "mask", "mask_file": "builtin:common-masks"},
        ],
    }

    plan = load_plan(_write_plan(tmp_path / "builtins.json", payload))

    assert plan.stages[0] == DictionaryStage(id="words", wordlist=bundled_wordlist())
    assert plan.stages[1] == RulesStage(id="rules", wordlist=bundled_wordlist(), rules=SMART_RULES)
    mask_stage = plan.stages[2]
    assert isinstance(mask_stage, MaskStage)
    assert mask_stage.mask_file is not None
    assert mask_stage.mask_file.name == "common.hcmask"


def test_compile_plan_fingerprints_input_content_without_using_its_path(tmp_path: Path) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("alpha\nbeta\n", encoding="utf-8")
    plan = load_plan(_write_plan(tmp_path / "plan.json", _dictionary_plan(wordlist.name)))

    first = compile_plan(plan, base_dir=tmp_path, backend=BackendChoice.CPU)
    wordlist.write_text("alpha\ngamma\n", encoding="utf-8")
    second = compile_plan(plan, base_dir=tmp_path, backend=BackendChoice.CPU)

    assert first.stages[0].keyspace == 2
    assert second.stages[0].keyspace == 2
    assert first.fingerprint != second.fingerprint


def test_profiles_are_deterministic_and_only_thorough_ends_in_bounded_brute(
    tmp_path: Path,
) -> None:
    hints = tmp_path / "hints.txt"
    hints.write_text("birthday\n", encoding="utf-8")

    fast = built_in_plan("fast", tmp_path / "protected.pdf", 4, 6)
    balanced = built_in_plan("balanced", tmp_path / "protected.pdf", 4, 6, hints)
    thorough = built_in_plan("thorough", tmp_path / "protected.pdf", 4, 6, hints)

    assert tuple(stage.type for stage in fast.stages) == ("dictionary", "mask", "mask")
    assert any(isinstance(stage, RulesStage) for stage in balanced.stages)
    assert any(getattr(stage, "wordlist", None) == hints for stage in balanced.stages)
    assert thorough.stages[-1].type == "brute"
    assert all(stage.type != "brute" for stage in (*fast.stages, *balanced.stages))


def test_profiles_skip_fixed_masks_outside_user_bounds(tmp_path: Path) -> None:
    plan = built_in_plan("thorough", tmp_path / "protected.pdf", 5, 7)

    mask_ids = {stage.id for stage in plan.stages if stage.type == "mask"}
    assert "pin6" in mask_ids
    assert not {"pin4", "pin8", "lower-mask", "upper-mask"} & mask_ids


def test_compile_plan_marks_external_rules_hashcat_required_and_cpu_refuses_them(
    tmp_path: Path,
) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("alpha\n", encoding="utf-8")
    plan = load_plan(
        _write_plan(
            tmp_path / "rules.json",
            {
                "schema": 1,
                "name": "rules",
                "stages": [
                    {
                        "id": "external",
                        "type": "rules",
                        "wordlist": wordlist.name,
                        "rules": ["unsupported-rule"],
                    }
                ],
            },
        )
    )

    automatic = compile_plan(plan, base_dir=tmp_path, backend=BackendChoice.AUTO)

    assert automatic.stages[0].cpu_compatible is False
    with pytest.raises(ConfigurationError):
        compile_plan(plan, base_dir=tmp_path, backend=BackendChoice.CPU)


def test_load_plan_rejects_reversed_brute_bounds(tmp_path: Path) -> None:
    with pytest.raises(PlanSchemaError) as raised:
        load_plan(
            _write_plan(
                tmp_path / "invalid-brute.json",
                {
                    "schema": 1,
                    "name": "invalid-brute",
                    "stages": [
                        {
                            "id": "brute",
                            "type": "brute",
                            "charset": "digits",
                            "min_length": 8,
                            "max_length": 4,
                        }
                    ],
                },
            )
        )
    assert raised.value.code == "plan_schema"
