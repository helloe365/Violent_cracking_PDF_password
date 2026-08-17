from __future__ import annotations

import codecs
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .errors import ConfigurationError, WordlistDecodeError
from .models import IndexRange

DEFAULT_CHUNK_CANDIDATES = 4096
MAX_CHUNK_BYTES = 4 * 1024 * 1024
READ_BUFFER_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class WordlistChunk:
    lines: IndexRange
    candidates: tuple[str, ...]


def iter_wordlist_chunks(
    path: Path,
    *,
    encoding: str = "utf-8",
    start_line: int = 0,
    chunk_candidates: int = DEFAULT_CHUNK_CANDIDATES,
    max_chunk_bytes: int = MAX_CHUNK_BYTES,
) -> Iterator[WordlistChunk]:
    if start_line < 0:
        raise ConfigurationError("start line cannot be negative")
    if chunk_candidates < 1:
        raise ConfigurationError("chunk candidate limit must be at least 1")
    if max_chunk_bytes < 1:
        raise ConfigurationError("chunk byte limit must be at least 1")

    try:
        codec = codecs.lookup(encoding)
    except LookupError as exc:
        raise ConfigurationError(f"unknown wordlist encoding: {encoding}") from exc

    candidates: list[str] = []
    chunk_start = start_line
    chunk_bytes = 0

    with path.open("rb") as stream:
        lines = _iter_decoded_lines(
            stream,
            codec,
            encoding=encoding,
            start_line=start_line,
            max_line_bytes=max_chunk_bytes,
        )
        for line_number, candidate, candidate_bytes in lines:
            if candidates and (
                len(candidates) >= chunk_candidates
                or chunk_bytes + candidate_bytes > max_chunk_bytes
            ):
                yield WordlistChunk(IndexRange(chunk_start, line_number), tuple(candidates))
                candidates = []
                chunk_start = line_number
                chunk_bytes = 0

            candidates.append(candidate)
            chunk_bytes += candidate_bytes

    if candidates:
        yield WordlistChunk(
            IndexRange(chunk_start, chunk_start + len(candidates)), tuple(candidates)
        )


def _iter_decoded_lines(
    stream: BinaryIO,
    codec: codecs.CodecInfo,
    *,
    encoding: str,
    start_line: int,
    max_line_bytes: int,
) -> Iterator[tuple[int, str, int]]:
    decoder = codec.incrementaldecoder(errors="strict")
    line_number = 0
    line_chars: list[str] = []
    line_encoder = codec.incrementalencoder(errors="strict")
    line_bytes = 0
    after_carriage_return = False

    def finish_line() -> tuple[int, str, int] | None:
        nonlocal line_number, line_chars, line_encoder, line_bytes
        current_line = line_number
        line_number += 1
        if current_line < start_line:
            return None

        line_bytes += len(line_encoder.encode("", final=True))
        if line_bytes > max_line_bytes:
            raise ConfigurationError(f"wordlist line {current_line + 1} exceeds chunk byte limit")
        candidate = "".join(line_chars)
        line_chars = []
        line_encoder = codec.incrementalencoder(errors="strict")
        candidate_bytes = line_bytes
        line_bytes = 0
        return current_line, candidate, candidate_bytes

    def consume(text: str) -> Iterator[tuple[int, str, int]]:
        nonlocal after_carriage_return, line_bytes
        for character in text:
            if after_carriage_return:
                after_carriage_return = False
                if character == "\n":
                    continue

            if character in "\r\n":
                result = finish_line()
                if result is not None:
                    yield result
                after_carriage_return = character == "\r"
                continue

            if line_number < start_line:
                continue
            line_chars.append(character)
            line_bytes += len(line_encoder.encode(character, final=False))
            if line_bytes > max_line_bytes:
                raise ConfigurationError(
                    f"wordlist line {line_number + 1} exceeds chunk byte limit"
                )

    while raw_bytes := stream.read(READ_BUFFER_BYTES):
        decoder_state = decoder.getstate()
        try:
            decoded = decoder.decode(raw_bytes, final=False)
        except UnicodeDecodeError:
            decoder.setstate(decoder_state)
            for byte in raw_bytes:
                try:
                    decoded = decoder.decode(bytes((byte,)), final=False)
                except UnicodeDecodeError as exc:
                    raise WordlistDecodeError(
                        f"cannot decode wordlist line {line_number + 1} using {encoding}"
                    ) from exc
                yield from consume(decoded)
            raise AssertionError("incremental decoder did not reproduce decode error") from None
        yield from consume(decoded)

    try:
        yield from consume(decoder.decode(b"", final=True))
    except UnicodeDecodeError as exc:
        raise WordlistDecodeError(
            f"cannot decode wordlist line {line_number + 1} using {encoding}"
        ) from exc

    if line_chars:
        result = finish_line()
        if result is not None:
            yield result
