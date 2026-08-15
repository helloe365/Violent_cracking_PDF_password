from __future__ import annotations

import queue
import signal
import time
from collections.abc import Callable, Iterator
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TypeAlias

from pypdf import PdfReader

from ..candidates import BruteSpace, MaskSpace, iter_smart_variants
from ..errors import ConfigurationError, WordlistDecodeError, WorkerExecutionError
from ..models import (
    Cursor,
    CursorKind,
    DictionaryAttack,
    IndexRange,
    MaskAttack,
    OutcomeStatus,
    Progress,
    RecoveryConfig,
    RecoveryOutcome,
)
from ..wordlists import WordlistChunk, iter_wordlist_chunks

INITIAL_CHUNK_SIZE = 256
MIN_CHUNK_SIZE = 64
MAX_CHUNK_SIZE = 65_536
TARGET_CHUNK_SECONDS = 1.0
JOIN_GRACE_SECONDS = 2.0


@dataclass(frozen=True, slots=True)
class IndexedTask:
    seq: int
    indexes: IndexRange


@dataclass(frozen=True, slots=True)
class DictionaryTask:
    seq: int
    lines: IndexRange
    candidates: tuple[str, ...]


class Control(StrEnum):
    STOP = "stop"


Task: TypeAlias = IndexedTask | DictionaryTask


@dataclass(frozen=True, slots=True)
class Ready:
    pid: int


@dataclass(frozen=True, slots=True)
class TaskFinished:
    seq: int
    cursor: Cursor
    attempted: int
    elapsed: float


@dataclass(frozen=True, slots=True)
class PasswordFound:
    seq: int
    password: str
    attempted: int
    elapsed: float


@dataclass(frozen=True, slots=True)
class TaskCancelled:
    seq: int
    attempted: int
    elapsed: float


@dataclass(frozen=True, slots=True)
class WorkerFailed:
    pid: int
    seq: int | None
    error_type: str
    message: str


ResultMessage: TypeAlias = Ready | TaskFinished | PasswordFound | TaskCancelled | WorkerFailed
ProgressCallback: TypeAlias = Callable[[Progress], None]


class _TaskProvider:
    def __init__(self, config: RecoveryConfig, cursor: Cursor):
        self.attack = config.attack
        self.next_value = cursor.value
        self._dictionary: Iterator[WordlistChunk] | None = None
        if isinstance(self.attack, DictionaryAttack):
            self.total = _count_wordlist(self.attack.wordlist, self.attack.encoding)
            chunk_options = {"chunk_candidates": 256} if self.attack.apply_rules else {}
            self._dictionary = iter_wordlist_chunks(
                self.attack.wordlist,
                encoding=self.attack.encoding,
                start_line=cursor.value,
                **chunk_options,
            )
        elif isinstance(self.attack, MaskAttack):
            self.total = MaskSpace.compile(self.attack.mask).total
        else:
            self.total = BruteSpace.create(
                self.attack.charset, self.attack.min_length, self.attack.max_length
            ).total
        if cursor.value > self.total:
            raise ConfigurationError("resume cursor lies outside the search space")

    def next_task(self, seq: int, chunk_size: int) -> Task | None:
        if self._dictionary is not None:
            try:
                chunk = next(self._dictionary)
            except StopIteration:
                return None
            self.next_value = chunk.lines.stop
            return DictionaryTask(
                seq,
                chunk.lines,
                tuple(
                    candidate
                    for word in chunk.candidates
                    for candidate in _dictionary_variants(self.attack, word)
                    if _within_dictionary_bounds(self.attack, candidate)
                ),
            )
        if self.next_value >= self.total:
            return None
        stop = min(self.total, self.next_value + chunk_size)
        task = IndexedTask(seq, IndexRange(self.next_value, stop))
        self.next_value = stop
        return task


def run_cpu(
    config: RecoveryConfig,
    *,
    cursor: Cursor | None = None,
    progress: ProgressCallback | None = None,
) -> RecoveryOutcome:
    expected_kind = (
        CursorKind.LINE if isinstance(config.attack, DictionaryAttack) else CursorKind.INDEX
    )
    start_cursor = cursor or Cursor(expected_kind, 0)
    if start_cursor.kind is not expected_kind:
        raise ConfigurationError("cursor type does not match attack")
    provider = _TaskProvider(config, start_cursor)
    started = time.monotonic()
    if start_cursor.value == provider.total:
        return RecoveryOutcome(OutcomeStatus.EXHAUSTED, None, start_cursor, 0, 0.0, "cpu")

    import multiprocessing

    context = multiprocessing.get_context("spawn")
    stop_event = context.Event()
    task_queue = context.Queue(maxsize=max(1, config.workers * 2))
    result_queue = context.Queue(maxsize=max(4, config.workers * 4))
    processes = [
        context.Process(
            target=_worker_main,
            args=(
                str(config.pdf_path.resolve()),
                config.attack,
                task_queue,
                result_queue,
                stop_event,
            ),
            name=f"pdf-recovery-{index + 1}",
        )
        for index in range(config.workers)
    ]

    attempted = 0
    committed = start_cursor
    completed: dict[int, Cursor] = {}
    next_commit_seq = 0
    next_seq = 0
    in_flight: dict[int, Task] = {}
    source_exhausted = False
    chunk_size = INITIAL_CHUNK_SIZE
    ewma_rate: float | None = None
    outcome_status = OutcomeStatus.EXHAUSTED
    password: str | None = None
    failure: WorkerExecutionError | None = None
    started_processes = []
    completed_normally = False

    try:
        for process in processes:
            process.start()
            started_processes.append(process)
        _wait_until_ready(started_processes, result_queue)

        while True:
            while not source_exhausted and len(in_flight) < config.workers * 2:
                task = provider.next_task(next_seq, chunk_size)
                if task is None:
                    source_exhausted = True
                    break
                task_queue.put(task)
                in_flight[next_seq] = task
                next_seq += 1

            if source_exhausted and not in_flight:
                completed_normally = True
                break

            try:
                message: ResultMessage = result_queue.get(timeout=0.2)
            except queue.Empty:
                dead = [process for process in started_processes if not process.is_alive()]
                if dead:
                    failure = WorkerExecutionError("a CPU worker exited without a result")
                    break
                continue

            if isinstance(message, TaskFinished):
                in_flight.pop(message.seq, None)
                attempted += message.attempted
                completed[message.seq] = message.cursor
                while next_commit_seq in completed:
                    committed = completed.pop(next_commit_seq)
                    next_commit_seq += 1
                if message.attempted:
                    sample = message.attempted / max(message.elapsed, 1e-6)
                    ewma_rate = sample if ewma_rate is None else 0.25 * sample + 0.75 * ewma_rate
                    chunk_size = max(
                        MIN_CHUNK_SIZE,
                        min(MAX_CHUNK_SIZE, round(ewma_rate * TARGET_CHUNK_SECONDS)),
                    )
            elif isinstance(message, PasswordFound):
                in_flight.pop(message.seq, None)
                attempted += message.attempted
                password = message.password
                outcome_status = OutcomeStatus.FOUND
                stop_event.set()
                break
            elif isinstance(message, TaskCancelled):
                in_flight.pop(message.seq, None)
                attempted += message.attempted
            elif isinstance(message, WorkerFailed):
                failure = WorkerExecutionError(
                    f"worker {message.pid} {message.error_type}: {message.message}"
                )
                stop_event.set()
                break

            if progress is not None:
                elapsed = time.monotonic() - started
                progress(
                    Progress(
                        completed=committed.value,
                        total=provider.total,
                        attempted=attempted,
                        elapsed=elapsed,
                        rate=attempted / elapsed if elapsed else 0.0,
                        backend="cpu",
                        workers=config.workers,
                    )
                )
    except KeyboardInterrupt:
        outcome_status = OutcomeStatus.INTERRUPTED
        stop_event.set()
    finally:
        normal = completed_normally and failure is None
        _shutdown(started_processes, task_queue, result_queue, stop_event, normal=normal)

    if failure is not None:
        raise failure
    return RecoveryOutcome(
        outcome_status,
        password,
        committed,
        attempted,
        time.monotonic() - started,
        "cpu",
    )


def _worker_main(pdf_path: str, attack, task_queue, result_queue, stop_event) -> None:
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    import os

    current_seq: int | None = None
    try:
        with Path(pdf_path).open("rb") as stream:
            reader = PdfReader(stream, strict=False)
            if not reader.is_encrypted:
                raise ValueError("PDF is not encrypted")
            space = _candidate_space(attack)
            result_queue.put(Ready(os.getpid()))
            while True:
                task = task_queue.get()
                if task == Control.STOP:
                    return
                current_seq = task.seq
                started = time.monotonic()
                candidates = _task_candidates(task, space)
                attempted = 0
                for attempted, candidate in enumerate(candidates, start=1):
                    if stop_event.is_set():
                        result_queue.put(
                            TaskCancelled(task.seq, attempted - 1, time.monotonic() - started)
                        )
                        break
                    if reader.decrypt(candidate):
                        stop_event.set()
                        result_queue.put(
                            PasswordFound(
                                task.seq, candidate, attempted, time.monotonic() - started
                            )
                        )
                        break
                else:
                    cursor_kind = (
                        CursorKind.LINE if isinstance(task, DictionaryTask) else CursorKind.INDEX
                    )
                    stop = (
                        task.lines.stop if isinstance(task, DictionaryTask) else task.indexes.stop
                    )
                    result_queue.put(
                        TaskFinished(
                            task.seq,
                            Cursor(cursor_kind, stop),
                            attempted,
                            time.monotonic() - started,
                        )
                    )
    except BaseException as exc:
        result_queue.put(
            WorkerFailed(os.getpid(), current_seq, type(exc).__name__, str(exc)[:1000])
        )


def _candidate_space(attack):
    if isinstance(attack, DictionaryAttack):
        return None
    if isinstance(attack, MaskAttack):
        return MaskSpace.compile(attack.mask)
    return BruteSpace.create(attack.charset, attack.min_length, attack.max_length)


def _dictionary_variants(attack: DictionaryAttack, word: str) -> Iterator[str]:
    if attack.apply_rules:
        yield from iter_smart_variants(word)
        return
    yield word


def _within_dictionary_bounds(attack: DictionaryAttack, candidate: str) -> bool:
    return attack.min_length is None or attack.min_length <= len(candidate) <= attack.max_length


def _task_candidates(task: Task, space) -> Iterator[str]:
    if isinstance(task, DictionaryTask):
        yield from task.candidates
        return
    for index in range(task.indexes.start, task.indexes.stop):
        yield space.candidate_at(index)


def _count_wordlist(path: Path, encoding: str) -> int:
    try:
        with path.open("r", encoding=encoding, errors="strict", newline=None) as stream:
            return sum(1 for _ in stream)
    except UnicodeDecodeError as exc:
        raise WordlistDecodeError(f"cannot decode wordlist using {encoding}") from exc
    except LookupError as exc:
        raise ConfigurationError(f"unknown wordlist encoding: {encoding}") from exc


def _wait_until_ready(processes, result_queue) -> None:
    ready = 0
    deadline = time.monotonic() + 15.0
    while ready < len(processes):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WorkerExecutionError("CPU workers did not become ready")
        try:
            message = result_queue.get(timeout=min(0.2, remaining))
        except queue.Empty:
            if any(not process.is_alive() for process in processes):
                raise WorkerExecutionError("CPU worker failed during startup") from None
            continue
        if isinstance(message, Ready):
            ready += 1
        elif isinstance(message, WorkerFailed):
            raise WorkerExecutionError(
                f"worker {message.pid} {message.error_type}: {message.message}"
            )


def _shutdown(
    processes,
    task_queue,
    result_queue,
    stop_event,
    *,
    normal: bool,
) -> None:
    if not normal:
        stop_event.set()
    for _ in processes:
        try:
            task_queue.put_nowait(Control.STOP)
        except queue.Full:
            break
    deadline = time.monotonic() + JOIN_GRACE_SECONDS
    while time.monotonic() < deadline and any(process.is_alive() for process in processes):
        with suppress(queue.Empty):
            result_queue.get_nowait()
        for process in processes:
            process.join(timeout=0.02)
    for process in processes:
        if process.is_alive():
            process.terminate()
        process.join(timeout=1.0)
    for managed_queue in (task_queue, result_queue):
        managed_queue.close()
        managed_queue.join_thread()
