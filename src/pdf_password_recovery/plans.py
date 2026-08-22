from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .assets import bundled_wordlist
from .candidates import SMART_RULES, BruteSpace, HybridSpace, MaskSpace, compile_mask
from .errors import ConfigurationError, MaskSyntaxError, PlanSchemaError
from .models import (
    AttackPlan,
    BackendChoice,
    BruteAttack,
    BruteStage,
    CompiledPlan,
    CompiledStage,
    DictionaryAttack,
    DictionaryStage,
    HybridAttack,
    HybridStage,
    MaskAttack,
    MaskStage,
    RulesAttack,
    RulesStage,
)


@dataclass(frozen=True, slots=True)
class HcmaskEntry:
    line_number: int
    mask: str
    custom_charsets: tuple[str, ...] = ()


def parse_hcmask(path: Path) -> tuple[HcmaskEntry, ...]:
    path = Path(path)
    entries: list[HcmaskEntry] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise MaskSyntaxError(f"cannot read hcmask '{path}': {exc}") from exc
    for line_number, physical in enumerate(lines, 1):
        if not physical.strip() or physical.lstrip().startswith("#"):
            continue
        line = physical
        leading = len(line) - len(line.lstrip())
        if line[leading:].startswith(r"\#"):
            line = line[:leading] + line[leading + 1 :]
        fields = line.split(",")
        mask = fields[-1]
        custom = tuple(fields[:-1])
        if not mask or len(custom) > 8 or any(not value for value in custom):
            _mask_error(path, line_number, "invalid custom charset or missing mask")
        try:
            compile_mask(mask, custom)
        except (ConfigurationError, MaskSyntaxError) as exc:
            _mask_error(path, line_number, str(exc))
        entries.append(HcmaskEntry(line_number, mask, custom))
    return tuple(entries)


def _mask_error(path: Path, line_number: int, message: str) -> None:
    raise MaskSyntaxError(f"{path}:{line_number}: {message}")


def load_plan(path: Path) -> AttackPlan:
    path = Path(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PlanSchemaError(f"cannot load plan '{path}': {exc}") from exc
    try:
        root = _mapping(payload, "plan")
        _exact(root, {"schema", "name", "stages"}, "plan")
        schema = _integer(root["schema"], "schema")
        if schema != 1:
            raise ValueError("schema must be 1")
        name = _string(root["name"], "name")
        raw_stages = root["stages"]
        if not isinstance(raw_stages, list) or not raw_stages:
            raise ValueError("stages must be a non-empty array")
        stages = tuple(_load_stage(_mapping(raw, "stage"), path.parent) for raw in raw_stages)
        AttackPlan(schema, name, stages)
        if len({stage.id for stage in stages}) != len(stages):
            raise ValueError("stage IDs must be unique")
        return AttackPlan(schema, name, stages)
    except (KeyError, TypeError, ValueError, ConfigurationError) as exc:
        if isinstance(exc, PlanSchemaError):
            raise
        raise PlanSchemaError(str(exc)) from exc


def _load_stage(raw: dict[str, Any], plan_dir: Path):
    if "type" not in raw:
        raise ValueError("stage type is required")
    kind = _string(raw["type"], "stage.type")
    common = {"id", "type"}
    if kind == "dictionary":
        _exact(raw, common | {"wordlist", "encoding", "min_length", "max_length"}, "dictionary")
        return DictionaryStage(
            _string(raw["id"], "stage.id"),
            _path_ref(raw["wordlist"], plan_dir, "wordlist"),
            _optional_string(raw, "encoding", "utf-8"),
            _optional_bound(raw, "min_length"),
            _optional_bound(raw, "max_length"),
        )
    if kind == "rules":
        _exact(raw, common | {"wordlist", "rules", "encoding", "min_length", "max_length"}, "rules")
        rules = raw["rules"]
        if rules == "builtin:smart-rules" or rules == ["builtin:smart-rules"]:
            rules = list(SMART_RULES)
        if (
            not isinstance(rules, list)
            or not rules
            or any(not isinstance(rule, str) or not rule for rule in rules)
        ):
            raise ValueError("rules must be a non-empty array of strings")
        return RulesStage(
            _string(raw["id"], "stage.id"),
            _path_ref(raw["wordlist"], plan_dir, "wordlist"),
            tuple(rules),
            _optional_string(raw, "encoding", "utf-8"),
            _optional_bound(raw, "min_length"),
            _optional_bound(raw, "max_length"),
        )
    if kind == "mask":
        _exact(raw, common | {"mask", "mask_file"}, "mask")
        if ("mask" in raw) == ("mask_file" in raw):
            raise ValueError("mask requires exactly one of mask or mask_file")
        if "mask" in raw:
            return MaskStage(_string(raw["id"], "stage.id"), mask=_string(raw["mask"], "mask"))
        return MaskStage(
            _string(raw["id"], "stage.id"),
            mask_file=_path_ref(raw["mask_file"], plan_dir, "mask_file"),
        )
    if kind == "hybrid":
        _exact(raw, common | {"wordlist", "mask", "direction", "encoding"}, "hybrid")
        return HybridStage(
            _string(raw["id"], "stage.id"),
            _path_ref(raw["wordlist"], plan_dir, "wordlist"),
            _string(raw["mask"], "mask"),
            _string(raw["direction"], "direction"),
            _optional_string(raw, "encoding", "utf-8"),
        )
    if kind == "brute":
        _exact(raw, common | {"charset", "min_length", "max_length"}, "brute")
        return BruteStage(
            _string(raw["id"], "stage.id"),
            _string(raw["charset"], "charset"),
            _bound(raw["min_length"], "min_length"),
            _bound(raw["max_length"], "max_length"),
        )
    raise ValueError(f"unsupported stage type '{kind}'")


def _exact(raw: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(raw) - allowed
    missing = allowed - set(raw)
    # optional fields are the only allowed omissions.
    optional = {"encoding", "min_length", "max_length", "mask", "mask_file"}
    missing -= optional
    if unknown or missing:
        raise ValueError(f"invalid {label} fields")


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _optional_string(raw: dict[str, Any], key: str, default: str) -> str:
    return default if key not in raw else _string(raw[key], key)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    return value


def _bound(value: object, label: str) -> int:
    parsed = _integer(value, label)
    if parsed < 1:
        raise ValueError(f"{label} must be at least 1")
    return parsed


def _optional_bound(raw: dict[str, Any], key: str) -> int | None:
    return None if key not in raw else _bound(raw[key], key)


def _path_ref(value: object, plan_dir: Path, label: str) -> Path:
    ref = _string(value, label)
    if ref == "builtin:wordlist":
        return bundled_wordlist()
    if ref == "builtin:common-masks":
        return Path(__file__).with_name("data") / "common.hcmask"
    if ref == "builtin:smart-rules":
        raise ValueError("builtin:smart-rules is valid only for rules")
    return (plan_dir / ref).resolve()


def compile_plan(plan: AttackPlan, *, base_dir: Path, backend: BackendChoice) -> CompiledPlan:
    backend = BackendChoice(backend)
    compiled: list[CompiledStage] = []
    fingerprint_data: list[dict[str, Any]] = []
    for source in plan.stages:
        stage_items = _compile_stage(source, Path(base_dir), backend)
        compiled.extend(stage_items)
        fingerprint_data.extend(_stage_fingerprint(item) for item in stage_items)
    digest = hashlib.sha256(
        json.dumps(
            {"schema": plan.schema, "name": plan.name, "stages": fingerprint_data},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return CompiledPlan(plan.schema, plan.name, tuple(compiled), digest)


def _compile_stage(source, base_dir: Path, backend: BackendChoice) -> list[CompiledStage]:
    if isinstance(source, DictionaryStage):
        path = _input_path(source.wordlist, base_dir)
        attack = DictionaryAttack(path, source.encoding, source.min_length, source.max_length)
        keyspace = _dictionary_count(path, source.encoding, source.min_length, source.max_length)
        return [_compiled(source.id, attack, keyspace, True, source, backend)]
    if isinstance(source, RulesStage):
        path = _input_path(source.wordlist, base_dir)
        attack = RulesAttack(
            path, source.rules, source.encoding, source.min_length, source.max_length
        )
        keyspace = _dictionary_count(
            path, source.encoding, source.min_length, source.max_length
        ) * len(source.rules)
        compatible = all(rule in _CPU_RULES for rule in source.rules)
        return [_compiled(source.id, attack, keyspace, compatible, source, backend)]
    if isinstance(source, MaskStage):
        if source.mask_file is None:
            attack = MaskAttack(source.mask or "")
            keyspace = MaskSpace.compile(attack.mask).total
            return [_compiled(source.id, attack, keyspace, True, source, backend)]
        entries = parse_hcmask(_input_path(source.mask_file, base_dir))
        return [
            _compiled(
                f"{source.id}:{entry.line_number}",
                MaskAttack(entry.mask, entry.custom_charsets),
                MaskSpace.compile(entry.mask, entry.custom_charsets).total,
                True,
                source,
                backend,
            )
            for entry in entries
        ]
    if isinstance(source, HybridStage):
        path = _input_path(source.wordlist, base_dir)
        attack = HybridAttack(path, source.mask, source.direction, source.encoding)
        keyspace = HybridSpace(
            path, source.encoding, MaskSpace.compile(source.mask), source.direction
        ).total
        return [_compiled(source.id, attack, keyspace, True, source, backend)]
    if isinstance(source, BruteStage):
        attack = BruteAttack(source.charset, source.min_length, source.max_length)
        return [
            _compiled(
                source.id,
                attack,
                BruteSpace.create(source.charset, source.min_length, source.max_length).total,
                True,
                source,
                backend,
            )
        ]
    raise ConfigurationError(f"unsupported stage type: {type(source).__name__}")


_CPU_RULES = frozenset(rule for rule in SMART_RULES if rule not in {"$!", "$@"})


def _compiled(stage_id, attack, keyspace, cpu_compatible, source, backend):
    if backend is BackendChoice.CPU and not cpu_compatible:
        raise ConfigurationError(f"stage '{stage_id}' requires hashcat")
    return CompiledStage(stage_id, attack, keyspace, cpu_compatible, source)


def _input_path(path: Path, base_dir: Path) -> Path:
    value = Path(path)
    return value if value.is_absolute() else (base_dir / value).resolve()


def _dictionary_count(path: Path, encoding: str, minimum: int | None, maximum: int | None) -> int:
    try:
        with path.open(encoding=encoding, errors="strict") as stream:
            return sum(
                1
                for line in stream
                if minimum is None or minimum <= len(line.rstrip("\r\n")) <= maximum
            )
    except (OSError, UnicodeError, LookupError) as exc:
        raise ConfigurationError(f"cannot read wordlist '{path}': {exc}") from exc


def _file_fingerprint(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ConfigurationError(f"cannot read input '{path}': {exc}") from exc


def _stage_fingerprint(compiled: CompiledStage) -> dict[str, Any]:
    attack = compiled.attack
    data: dict[str, Any] = {
        "id": compiled.id,
        "kind": attack.kind.value,
        "keyspace": compiled.keyspace,
    }
    if isinstance(attack, (DictionaryAttack, RulesAttack, HybridAttack)):
        data.update(wordlist=_file_fingerprint(attack.wordlist), encoding=attack.encoding)
    if isinstance(attack, DictionaryAttack):
        data.update(min_length=attack.min_length, max_length=attack.max_length)
    elif isinstance(attack, RulesAttack):
        data.update(rules=attack.rules, min_length=attack.min_length, max_length=attack.max_length)
    elif isinstance(attack, MaskAttack):
        data.update(mask=attack.mask, custom_charsets=attack.custom_charsets)
    elif isinstance(attack, HybridAttack):
        data.update(mask=attack.mask, direction=attack.direction)
    elif isinstance(attack, BruteAttack):
        data.update(
            charset=attack.charset, min_length=attack.min_length, max_length=attack.max_length
        )
    if isinstance(compiled.source, MaskStage) and compiled.source.mask_file is not None:
        data["mask_file"] = _file_fingerprint(compiled.source.mask_file)
    return data


def built_in_plan(
    profile: str, pdf_path: Path, min_length: int, max_length: int, hints_file: Path | None = None
) -> AttackPlan:
    if profile not in {"fast", "balanced", "thorough"}:
        raise ConfigurationError("profile must be fast, balanced, or thorough")
    dictionary = DictionaryStage(
        "wordlist", bundled_wordlist(), min_length=min_length, max_length=max_length
    )
    numeric = (
        MaskStage("pin4", mask="?d?d?d?d"),
        MaskStage("pin6", mask="?d?d?d?d?d?d"),
        MaskStage("pin8", mask="?d?d?d?d?d?d?d?d"),
    )
    stages: list[Any] = [dictionary, *numeric]
    if profile in {"balanced", "thorough"}:
        stages.insert(
            1,
            RulesStage(
                "smart-rules",
                bundled_wordlist(),
                SMART_RULES,
                min_length=min_length,
                max_length=max_length,
            ),
        )
        stages.append(
            MaskStage("common-masks", mask_file=Path(__file__).with_name("data") / "common.hcmask")
        )
        if hints_file is not None:
            hints = Path(hints_file).resolve()
            stages.extend(
                [
                    RulesStage("hint-rules", hints, SMART_RULES),
                    HybridStage("hint-append", hints, "?d?d", "append"),
                    HybridStage("hint-prepend", hints, "?d?d", "prepend"),
                ]
            )
    if profile == "thorough":
        stages.extend(
            (MaskStage("lower-mask", mask="?l?l?l?l"), MaskStage("upper-mask", mask="?u?u?u?u"))
        )
        stages.append(BruteStage("bounded-brute", "alnum", min_length, max_length))
    return AttackPlan(1, f"pdf-recovery-{profile}", tuple(stages))


__all__ = ["HcmaskEntry", "built_in_plan", "compile_plan", "load_plan", "parse_hcmask"]
