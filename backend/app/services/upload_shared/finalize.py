"""Mechanical core of a chunked-upload finalize: assemble, verify, promote.

This intentionally does NOT own the full finalize state machine. Memory's
original ``finalize_memory_upload_session`` has exception-handling
behaviour specific to its own status/error-code contract (verified by
its test suite) that must not change. Rather than re-derive that control
flow generically -- and risk silently changing it -- this module extracts
only the workflow-agnostic middle section: assemble chunks, verify size
and hash, look up a duplicate, promote atomically, hand off to the
workflow's registration hook, clean up. The caller supplies the
workflow-specific steps (duplicate lookup, status transitions, error
mapping) as callables and keeps its own try/except around this call so
its existing exception-handling behaviour is preserved unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from app.services.upload_shared.hashing import concat_and_hash
from app.services.upload_shared.promotion import atomic_promote


class ChunkedFinalizeError(RuntimeError):
    pass


class ChunkedFinalizeSizeMismatch(ChunkedFinalizeError):
    def __init__(self, actual_bytes: int, expected_bytes: int):
        super().__init__(f"Finalized byte count {actual_bytes} does not match expected {expected_bytes}.")
        self.actual_bytes = actual_bytes
        self.expected_bytes = expected_bytes


class ChunkedFinalizeHashMismatch(ChunkedFinalizeError):
    def __init__(self, actual_sha256: str, expected_sha256: str):
        super().__init__("Finalized SHA-256 does not match the expected hash.")
        self.actual_sha256 = actual_sha256
        self.expected_sha256 = expected_sha256


@dataclass
class ChunkedFinalizeConfig:
    total_chunks: int
    chunk_path_fn: Callable[[int], Path]
    final_path: Path
    assembly_path: Path
    expected_bytes: int
    expected_sha256: str | None = None


@dataclass
class ChunkedFinalizeResult:
    sha256: str
    total_bytes: int
    registered: Any


def run_chunked_finalize(
    config: ChunkedFinalizeConfig,
    *,
    on_verifying: Callable[[], None],
    find_duplicate: Callable[[str, int], Any | None],
    on_duplicate: Callable[[Any], None],
    on_finalizing: Callable[[int, int], None],
    post_promote: Callable[[Path], None],
    register: Callable[[], Any],
    cleanup: Callable[[], None],
) -> ChunkedFinalizeResult:
    """Assemble, verify, promote, and register a completed chunked upload.

    ``on_duplicate`` is expected to raise (it mirrors the caller's own
    duplicate-rejection error); if it returns instead, finalize proceeds
    treating the duplicate as accepted.
    """
    config.final_path.parent.mkdir(parents=True, exist_ok=True)
    on_verifying()

    total_bytes, computed_sha256 = concat_and_hash(
        (config.chunk_path_fn(index) for index in range(config.total_chunks)),
        config.assembly_path,
    )
    if total_bytes != config.expected_bytes:
        raise ChunkedFinalizeSizeMismatch(total_bytes, config.expected_bytes)
    if config.expected_sha256 and computed_sha256 != config.expected_sha256:
        raise ChunkedFinalizeHashMismatch(computed_sha256, config.expected_sha256)

    duplicate = find_duplicate(computed_sha256, total_bytes)
    if duplicate is not None:
        on_duplicate(duplicate)

    on_finalizing(total_bytes, config.total_chunks)
    atomic_promote(config.assembly_path, config.final_path)
    post_promote(config.final_path)
    registered = register()
    cleanup()
    return ChunkedFinalizeResult(sha256=computed_sha256, total_bytes=total_bytes, registered=registered)
