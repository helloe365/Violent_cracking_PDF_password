from __future__ import annotations

import argparse
import codecs
import json
import os
import re
import sys
import tempfile
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TextIO

from tqdm import tqdm

from .candidates import BruteSpace, MaskSpace
from .errors import ConfigurationError, RecoveryError
from .events import JsonLineSink
from .models import (
    BackendChoice,
    BruteAttack,
    DictionaryAttack,
    MaskAttack,
    OutcomeStatus,
    Progress,
    RecoveryConfig,
    WorkloadProfile,
)
from .wordlists import iter_wordlist_chunks

_SESSION_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
_DEFAULT_WORKERS = min(8, os.cpu_count() or 1)
_MAX_INTERACTIVE_WORKERS = os.cpu_count() or 1


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ConfigurationError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="pdf-password-recovery",
        description="Recover the password for an authorized local PDF.",
    )
    parser.add_argument("pdf", nargs="?", type=Path, help="encrypted PDF file")
    parser.add_argument(
        "--attack",
        choices=("dictionary", "mask", "brute"),
        help="password search strategy",
    )
    parser.add_argument(
        "--backend",
        choices=("auto", "hashcat", "cpu"),
        default="auto",
        help="execution backend (default: auto)",
    )
    parser.add_argument("--wordlist", type=Path, help="dictionary file")
    parser.add_argument("--mask", help="hashcat-style mask, for example ?u?l?l?d")
    parser.add_argument("--charset", help="brute-force preset or custom characters")
    parser.add_argument("--min-length", type=int, help="minimum brute-force length")
    parser.add_argument("--max-length", type=int, help="maximum brute-force length")
    parser.add_argument("--workers", type=int, help="CPU worker processes")
    parser.add_argument("--encoding", help="dictionary encoding (default: utf-8)")
    parser.add_argument("--session", help="checkpoint/hashcat session name")
    parser.add_argument("--resume", action="store_true", help="resume the named session")
    parser.add_argument("--output", type=Path, help="write the recovered password to this file")
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        dest="assume_yes",
        help="start without confirmation (required when non-interactive)",
    )
    return parser


def parse_config(
    argv: Sequence[str] | None = None,
    *,
    input_fn: Callable[[str], str] = input,
    is_tty: bool | None = None,
) -> RecoveryConfig:
    namespace = build_parser().parse_args(argv)
    tty = sys.stdin.isatty() if is_tty is None else is_tty
    if namespace.attack is None:
        if not tty:
            raise ConfigurationError("--attack is required when stdin is not interactive")
        namespace = _collect_interactive(namespace, input_fn)
    return _config_from_namespace(namespace)


def _collect_interactive(
    namespace: argparse.Namespace, input_fn: Callable[[str], str]
) -> argparse.Namespace:
    if namespace.pdf is None:
        namespace.pdf = Path(_required_prompt(input_fn, "请输入PDF文件的完整路径: "))
    namespace.attack = "brute"
    if namespace.charset is None:
        namespace.charset = "alnum"
    if namespace.min_length is None:
        namespace.min_length = _integer_prompt(input_fn, "请输入最小密码长度，默认为 [4]: ", 4)
    if namespace.max_length is None:
        namespace.max_length = _integer_prompt(input_fn, "请输入最大密码长度，默认为 [6]: ", 6)
    prompted_workers = namespace.workers is None
    if prompted_workers:
        namespace.workers = _integer_prompt(
            input_fn,
            f"请输入使用的进程数 (1-{_MAX_INTERACTIVE_WORKERS}) [{_DEFAULT_WORKERS}]: ",
            _DEFAULT_WORKERS,
        )
    if prompted_workers and namespace.workers > _MAX_INTERACTIVE_WORKERS:
        raise ConfigurationError(f"交互模式的进程数必须在 1-{_MAX_INTERACTIVE_WORKERS} 之间")
    return namespace


def _config_from_namespace(namespace: argparse.Namespace) -> RecoveryConfig:
    if namespace.pdf is None:
        raise ConfigurationError("PDF path is required")
    workers = (os.cpu_count() or 1) if namespace.workers is None else namespace.workers
    if workers < 1:
        raise ConfigurationError("--workers must be at least 1")
    if namespace.session and (
        _SESSION_PATTERN.fullmatch(namespace.session) is None or namespace.session in {".", ".."}
    ):
        raise ConfigurationError("invalid session name")
    if namespace.resume and not namespace.session:
        raise ConfigurationError("--resume requires --session")
    if namespace.attack == "dictionary":
        _reject(namespace, "--mask", "mask")
        _reject(namespace, "--charset", "charset")
        _reject(namespace, "--min-length", "min_length")
        _reject(namespace, "--max-length", "max_length")
        if namespace.wordlist is None:
            raise ConfigurationError("dictionary attack requires --wordlist")
        encoding = "utf-8" if namespace.encoding is None else namespace.encoding
        try:
            codecs.lookup(encoding)
        except LookupError as exc:
            raise ConfigurationError(f"unknown encoding: {encoding}") from exc
        attack = DictionaryAttack(namespace.wordlist.expanduser(), encoding)
    elif namespace.attack == "mask":
        _reject(namespace, "--wordlist", "wordlist")
        _reject(namespace, "--charset", "charset")
        _reject(namespace, "--min-length", "min_length")
        _reject(namespace, "--max-length", "max_length")
        _reject(namespace, "--encoding", "encoding")
        if not namespace.mask:
            raise ConfigurationError("mask attack requires --mask")
        attack = MaskAttack(namespace.mask)
    else:
        _reject(namespace, "--wordlist", "wordlist")
        _reject(namespace, "--mask", "mask")
        _reject(namespace, "--encoding", "encoding")
        minimum = 4 if namespace.min_length is None else namespace.min_length
        maximum = 6 if namespace.max_length is None else namespace.max_length
        if minimum < 1 or maximum < minimum:
            raise ConfigurationError("invalid brute-force length range")
        charset = "alnum" if namespace.charset is None else namespace.charset
        if not charset:
            raise ConfigurationError("charset cannot be empty")
        attack = BruteAttack(charset, minimum, maximum)

    pdf = namespace.pdf.expanduser()
    output = namespace.output.expanduser() if namespace.output else None
    input_paths = {pdf.resolve(strict=False)}
    if isinstance(attack, DictionaryAttack):
        input_paths.add(attack.wordlist.expanduser().resolve(strict=False))
    if output and output.resolve(strict=False) in input_paths:
        raise ConfigurationError("output path must differ from input files")
    return RecoveryConfig(
        pdf_path=pdf,
        attack=attack,
        backend=BackendChoice(namespace.backend),
        workers=workers,
        session=namespace.session,
        resume=namespace.resume,
        output=output,
        assume_yes=namespace.assume_yes,
    )


def _reject(namespace: argparse.Namespace, option: str, attribute: str) -> None:
    if getattr(namespace, attribute) is not None:
        raise ConfigurationError(f"{option} is not valid for {namespace.attack} attack")


def _required_prompt(input_fn: Callable[[str], str], prompt: str) -> str:
    while True:
        value = input_fn(prompt).strip().strip('"')
        if value:
            return value


def _integer_prompt(input_fn: Callable[[str], str], prompt: str, default: int) -> int:
    while True:
        value = input_fn(prompt).strip()
        if not value:
            return default
        try:
            parsed = int(value)
        except ValueError:
            continue
        if parsed >= 1:
            return parsed


def _print_summary(config: RecoveryConfig, output: TextIO) -> None:
    print("\n开始破解密码...", file=output)
    print(f"PDF文件: {config.pdf_path}", file=output)
    print(f"攻击方式: {_attack_label(config)}", file=output)
    if isinstance(config.attack, BruteAttack):
        print(
            f"密码长度: {config.attack.min_length}-{config.attack.max_length}",
            file=output,
        )
    print(f"后端选择: {_requested_backend_label(config.backend)}", file=output)
    print(f"CPU回退进程数: {config.workers}", file=output)
    print(f"可能的组合数: {_search_space(config)}", file=output)


def _attack_label(config: RecoveryConfig) -> str:
    attack = config.attack
    if isinstance(attack, DictionaryAttack):
        return "字典"
    if isinstance(attack, MaskAttack):
        return f"掩码 ({attack.mask})"
    labels = {
        "digits": "纯数字",
        "lower": "纯字母(小写)",
        "upper": "纯字母(大写)",
        "letters": "字母",
        "alnum": "字母和数字",
    }
    return labels.get(attack.charset, "自定义字符集")


def _requested_backend_label(backend: BackendChoice) -> str:
    if backend is BackendChoice.AUTO:
        return "自动（优先 GPU/hashcat，不可用时回退 CPU）"
    if backend is BackendChoice.HASHCAT:
        return "GPU (hashcat)"
    return "CPU"


def _actual_backend_label(backend: str) -> str:
    return "GPU (hashcat)" if backend == "hashcat" else "CPU"


def _search_space(config: RecoveryConfig) -> int:
    attack = config.attack
    if isinstance(attack, DictionaryAttack):
        return sum(
            len(chunk.candidates)
            for chunk in iter_wordlist_chunks(attack.wordlist, encoding=attack.encoding)
        )
    if isinstance(attack, MaskAttack):
        return MaskSpace.compile(attack.mask).total
    return BruteSpace.create(attack.charset, attack.min_length, attack.max_length).total


class _ProgressDisplay:
    def __init__(self, output: TextIO):
        self.output = output
        self.bar = None
        self.tty = bool(getattr(output, "isatty", lambda: False)())

    def __call__(self, progress: Progress) -> None:
        if self.tty:
            if self.bar is None:
                self.bar = tqdm(
                    total=progress.total,
                    initial=progress.completed,
                    desc="尝试密码",
                    unit="个",
                    dynamic_ncols=True,
                    file=self.output,
                )
            self.bar.n = progress.completed
            self.bar.set_postfix_str(
                f"{progress.rate:.1f} 个/秒, {_actual_backend_label(progress.backend)}"
            )
            self.bar.refresh()
            return
        remaining = max(0, progress.total - progress.completed)
        eta = remaining / progress.rate if progress.rate > 0 else float("inf")
        eta_text = f"{eta:.1f}s" if eta != float("inf") else "unknown"
        print(
            f"进度: {progress.completed}/{progress.total} | "
            f"{progress.rate:.1f} 个/秒 | 已用 {progress.elapsed:.1f}秒 | "
            f"预计剩余 {eta_text} | {_actual_backend_label(progress.backend)} "
            f"({progress.workers} 个进程)",
            file=self.output,
        )

    def close(self) -> None:
        if self.bar is not None:
            self.bar.close()


def _progress_printer(output: TextIO) -> _ProgressDisplay:
    return _ProgressDisplay(output)


def _notice_printer(output: TextIO) -> Callable[[str], None]:
    return lambda message: print(f"提示: {message}", file=output)


def _smart_entrypoint(input_fn: Callable[[str], str], output: TextIO) -> int:
    from .smart import SmartOptions, run_smart

    options = SmartOptions(
        Path(_required_prompt(input_fn, "请输入PDF文件的完整路径: ")).expanduser(),
        _integer_prompt(input_fn, "请输入最小密码长度，默认为 [4]: ", 4),
        _integer_prompt(input_fn, "请输入最大密码长度，默认为 [6]: ", 6),
        _integer_prompt(
            input_fn,
            f"请输入使用的进程数 (1-{_MAX_INTERACTIVE_WORKERS}) [{_DEFAULT_WORKERS}]: ",
            _DEFAULT_WORKERS,
        ),
    )
    if options.workers > _MAX_INTERACTIVE_WORKERS:
        raise ConfigurationError(f"交互模式的进程数必须在 1-{_MAX_INTERACTIVE_WORKERS} 之间")
    print("\n智能恢复阶段:", file=output)
    print("1. 常用字典", file=output)
    print("2. 规则变形", file=output)
    print("3. 动态掩码", file=output)
    print("4. 有限穷举", file=output)
    print(f"PDF文件: {options.pdf_path}", file=output)
    print(f"密码长度: {options.min_length}-{options.max_length}", file=output)
    print("后端选择: 自动（优先 GPU/hashcat，不可用时回退 CPU）", file=output)
    print(f"CPU回退进程数: {options.workers}", file=output)
    if input_fn("确认开始恢复? [y/N]: ").strip().lower() not in {"y", "yes"}:
        print("已取消。", file=output)
        return 2

    progress_display = _progress_printer(output)
    try:
        outcome = run_smart(
            options,
            progress=progress_display,
            notice=_notice_printer(output),
            confirm_resume=lambda: (
                input_fn("检测到未完成任务，继续恢复? [Y/n]: ").strip().lower() in {"", "y", "yes"}
            ),
        )
    finally:
        progress_display.close()
    print(f"实际后端: {_actual_backend_label(outcome.backend)}", file=output)
    if outcome.status is OutcomeStatus.INTERRUPTED:
        print("已中断；智能恢复状态已保存。", file=output)
        return 130
    if outcome.status is OutcomeStatus.EXHAUSTED:
        print("全部阶段完成，未找到密码。", file=output)
        return 1
    assert outcome.password is not None
    print(f"密码长度: {len(outcome.password)}", file=output)
    print(f"耗时: {outcome.elapsed:.2f}秒", file=output)
    print(f"\n恢复成功! PDF密码是: {outcome.password}", file=output)
    return 0


def _write_password(path: Path, password: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as destination:
            destination.write(password + "\n")
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def entrypoint(
    argv: Sequence[str] | None = None,
    *,
    input_fn: Callable[[str], str] = input,
    output: TextIO = sys.stdout,
    error: TextIO = sys.stderr,
    is_tty: bool | None = None,
) -> int:
    try:
        effective_argv = tuple(sys.argv[1:] if argv is None else argv)
        tty = sys.stdin.isatty() if is_tty is None else is_tty
        if effective_argv and effective_argv[0] in {"plan", "preflight", "sessions"}:
            return _new_entrypoint(effective_argv, input_fn, output, error, tty)
        if not effective_argv and tty:
            return _smart_entrypoint(input_fn, output)
        config = parse_config(effective_argv, input_fn=input_fn, is_tty=tty)
        if not config.assume_yes and not tty:
            raise ConfigurationError("non-interactive use requires --yes")
        _print_summary(config, output)
        if not config.assume_yes and input_fn("确认开始破解? [y/N]: ").strip().lower() not in {
            "y",
            "yes",
        }:
            print("已取消。", file=output)
            return 2
        from .service import recover

        progress_display = _progress_printer(output)
        try:
            outcome = recover(
                config,
                progress=progress_display,
                notice=_notice_printer(output),
            )
        finally:
            progress_display.close()
        print(f"实际后端: {_actual_backend_label(outcome.backend)}", file=output)
        if outcome.status is OutcomeStatus.INTERRUPTED:
            print("已中断；如配置了会话，检查点已保存。", file=output)
            return 130
        if outcome.status is OutcomeStatus.EXHAUSTED:
            print("搜索完成，未找到密码。", file=output)
            return 1
        assert outcome.password is not None
        if config.output:
            _write_password(config.output, outcome.password)
        print(f"密码长度: {len(outcome.password)}", file=output)
        print(f"密码类型: {_attack_label(config)}", file=output)
        print(f"耗时: {outcome.elapsed:.2f}秒", file=output)
        print(f"\n破解成功! PDF密码是: {outcome.password}", file=output)
        return 0
    except KeyboardInterrupt:
        print("Interrupted.", file=error)
        return 130
    except (RecoveryError, OSError, UnicodeError, EOFError) as exc:
        print(f"Error: {exc}", file=error)
        return 2


def main(argv: Sequence[str] | None = None) -> int:
    return entrypoint(argv)


def _new_entrypoint(
    argv: Sequence[str],
    input_fn: Callable[[str], str],
    output: TextIO,
    error: TextIO,
    tty: bool,
) -> int:
    command = argv[0]
    try:
        if command == "plan":
            return _plan_command(argv[1:], input_fn, output, tty)
        if command == "preflight":
            return _preflight_command(argv[1:], output)
        return _sessions_command(argv[1:], input_fn, output, tty)
    except KeyboardInterrupt:
        return 130
    except (RecoveryError, OSError, UnicodeError, EOFError) as exc:
        print(f"Error: {exc}", file=error)
        return 2


def _common_new_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--backend", choices=("auto", "hashcat", "cpu"), default="auto")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--workload", choices=("quiet", "balanced", "fast"), default="balanced")
    parser.add_argument("--device", default="auto")
    parser.add_argument("--session")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--yes", action="store_true")


def _plan_command(
    argv: Sequence[str], input_fn: Callable[[str], str], output: TextIO, tty: bool
) -> int:
    parser = _Parser(prog="pdf-password-recovery plan")
    parser.add_argument("pdf", type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--profile", choices=("fast", "balanced", "thorough"))
    group.add_argument("--file", type=Path)
    parser.add_argument("--min-length", type=int, default=4)
    parser.add_argument("--max-length", type=int, default=6)
    parser.add_argument("--hints-file", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    _common_new_parser(parser)
    ns = parser.parse_args(argv)
    if ns.workers < 1 or ns.min_length < 1 or ns.max_length < ns.min_length:
        raise ConfigurationError("invalid workers or password length range")
    from .orchestrator import run_plan
    from .plans import built_in_plan, compile_plan, load_plan

    if ns.file is not None:
        plan = load_plan(ns.file)
        base_dir = ns.file.resolve().parent
    else:
        plan = built_in_plan(ns.profile, ns.pdf, ns.min_length, ns.max_length, ns.hints_file)
        base_dir = ns.pdf.resolve().parent
    compiled = compile_plan(plan, base_dir=base_dir, backend=BackendChoice(ns.backend))
    sink = JsonLineSink(output) if ns.json else None
    if ns.dry_run:
        if ns.backend != "cpu":
            from .backends.hashcat_info import run_preflight
            from .events import EventType, RecoveryEvent

            try:
                report = run_preflight(ns.pdf, ns.workload, ns.device)
                if sink is not None:
                    sink.emit(
                        RecoveryEvent(
                            EventType.PREFLIGHT,
                            {
                                "status": "ready",
                                "backend": "hashcat",
                                "device_ids": [device.id for device in report.selected_devices],
                                "tool_version": report.capabilities.version,
                                "workload": report.workload.value,
                                "pdf_mode": report.pdf_mode,
                            },
                            session=ns.session,
                        )
                    )
            except RecoveryError:
                if sink is not None:
                    sink.emit(
                        RecoveryEvent(
                            EventType.PREFLIGHT,
                            {
                                "status": "unavailable",
                                "backend": "hashcat",
                                "device_ids": [],
                                "tool_version": "0.0",
                                "workload": ns.workload,
                            },
                            session=ns.session,
                        )
                    )
                elif not ns.json:
                    print("hashcat 预检不可用，预计时间未知", file=output)
        if ns.json:
            for index, stage in enumerate(compiled.stages):
                sink.emit(
                    RecoveryEvent(
                        EventType.STAGE_STARTED,
                        {
                            "stage_id": stage.id.replace(":", "-"),
                            "stage_index": index,
                            "stage_count": len(compiled.stages),
                            "backend": ns.backend,
                            "workload": ns.workload,
                            "total": stage.keyspace,
                        },
                        session=ns.session,
                    )
                )
        else:
            print(f"计划: {compiled.name}", file=output)
            for stage in compiled.stages:
                print(
                    f"- {stage.id}: {stage.attack.kind.value}, keyspace={stage.keyspace}",
                    file=output,
                )
        return 0
    if not ns.yes and not tty:
        raise ConfigurationError("non-interactive use requires --yes")
    if not ns.yes and input_fn("确认开始恢复? [y/N]: ").strip().lower() not in {"y", "yes"}:
        print("已取消。", file=output)
        return 2
    outcome = run_plan(
        compiled,
        pdf_path=ns.pdf,
        backend=BackendChoice(ns.backend),
        workers=ns.workers,
        workload=WorkloadProfile(ns.workload),
        requested_devices=ns.device,
        session=ns.session,
        output=ns.output,
        event_sink=sink,
    )
    if ns.json:
        return (
            0
            if outcome.status is OutcomeStatus.FOUND
            else 130
            if outcome.status is OutcomeStatus.INTERRUPTED
            else 1
        )
    if outcome.status is OutcomeStatus.FOUND:
        if outcome.password is not None:
            print(f"密码长度: {len(outcome.password)}", file=output)
        print("恢复成功!", file=output)
        return 0
    if outcome.status is OutcomeStatus.INTERRUPTED:
        print("已中断；检查点已保存。", file=output)
        return 130
    print("搜索完成，未找到密码。", file=output)
    return 1


def _preflight_command(argv: Sequence[str], output: TextIO) -> int:
    parser = _Parser(prog="pdf-password-recovery preflight")
    parser.add_argument("pdf", type=Path)
    parser.add_argument("--workload", choices=("quiet", "balanced", "fast"), default="balanced")
    parser.add_argument("--device", default="auto")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--json", action="store_true")
    ns = parser.parse_args(argv)
    from .backends.hashcat_info import run_preflight

    report = run_preflight(ns.pdf, ns.workload, ns.device, ns.refresh)
    if ns.json:
        from .events import EventType, RecoveryEvent

        JsonLineSink(output).emit(
            RecoveryEvent(
                EventType.PREFLIGHT,
                {
                    "status": "ready",
                    "backend": "hashcat",
                    "device_ids": [device.id for device in report.selected_devices],
                    "tool_version": report.capabilities.version,
                    "workload": report.workload.value,
                    "pdf_mode": report.pdf_mode,
                },
            )
        )
    else:
        print(f"hashcat {report.capabilities.version}; PDF mode {report.pdf_mode}", file=output)
        print(f"设备: {', '.join(device.id for device in report.selected_devices)}", file=output)
        print(f"基准速度: {report.benchmark_hps or 'unknown'} H/s", file=output)
    return 0


def _session_json(summary: object) -> str:
    from dataclasses import asdict

    value = asdict(summary)
    value["status"] = value["status"].value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _sessions_command(
    argv: Sequence[str], input_fn: Callable[[str], str], output: TextIO, tty: bool
) -> int:
    parser = _Parser(prog="pdf-password-recovery sessions")
    parser.add_argument("action", choices=("list", "show", "delete", "prune"))
    parser.add_argument("name", nargs="?")
    parser.add_argument("--older-than", type=int, default=0)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--yes", action="store_true")
    ns = parser.parse_args(argv)
    from .orchestrator import _state_root
    from .sessions import SessionStore

    store = SessionStore(_state_root())
    if ns.action == "list":
        values = store.list()
        if ns.json:
            for value in values:
                print(_session_json(value), file=output)
        else:
            for value in values:
                print(
                    f"{value.name}\t{value.status.value}\t{value.completed}/{value.total}",
                    file=output,
                )
        return 0
    if ns.action == "show":
        if not ns.name:
            raise ConfigurationError("sessions show requires NAME")
        value = store.load(ns.name)
        print(
            _session_json(value) if ns.json else f"{value.name}: {value.status.value}", file=output
        )
        return 0
    if not ns.yes and not tty:
        raise ConfigurationError("non-interactive use requires --yes")
    if not ns.yes and input_fn("确认删除会话? [y/N]: ").strip().lower() not in {"y", "yes"}:
        return 2
    if ns.action == "delete":
        if not ns.name:
            raise ConfigurationError("sessions delete requires NAME")
        store.delete(ns.name)
        return 0
    if ns.older_than < 0:
        raise ConfigurationError("--older-than must be non-negative")
    if ns.older_than:
        cutoff = datetime.now(UTC) - timedelta(days=ns.older_than)
        deleted = []
        for summary in store.list():
            if summary.status.value in {"found", "exhausted", "failed"}:
                updated = datetime.fromisoformat(summary.updated_at.removesuffix("Z") + "+00:00")
                if updated < cutoff:
                    store.delete(summary.name)
                    deleted.append(summary.name)
    else:
        deleted = store.prune()
    if ns.json:
        print(json.dumps({"deleted": deleted}, ensure_ascii=False), file=output)
    else:
        print(f"已删除 {len(deleted)} 个会话", file=output)
    return 0
