"""Streaming hash primitives shared by chunked upload backends.

Pure functions only: no ORM model coupling, no workflow-specific error
codes. Callers translate failures into their own error types.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Iterable

_BLOCK_SIZE = 1024 * 1024


def concat_and_hash(chunk_paths: Iterable[Path], dest_path: Path) -> tuple[int, str]:
    """Stream-concatenate ``chunk_paths`` in order into ``dest_path``.

    Computes the SHA-256 of the assembled bytes while writing, then
    flushes and fsyncs ``dest_path`` before returning. Does not fsync the
    containing directory or touch ``chunk_paths`` -- callers own cleanup
    and directory-entry durability.

    Returns ``(total_bytes_written, sha256_hex)``.
    """
    digest = hashlib.sha256()
    total_bytes = 0
    with dest_path.open("xb") as target:
        for chunk_path in chunk_paths:
            with chunk_path.open("rb") as source:
                for blob in iter(lambda: source.read(_BLOCK_SIZE), b""):
                    total_bytes += len(blob)
                    digest.update(blob)
                    target.write(blob)
        target.flush()
        os.fsync(target.fileno())
    return total_bytes, digest.hexdigest()
