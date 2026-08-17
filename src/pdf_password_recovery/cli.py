from __future__ import annotations

import argparse
import codecs
import os
import re
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from tqdm import tqdm

from .candidates import BruteSpace, MaskSpace
from .errors import ConfigurationError, RecoveryError
from .models import (
    BackendChoice,
    BruteAttack,
    DictionaryAttack,
    MaskAttack,
    OutcomeStatus,
    Progress,
    RecoveryConfig,
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
