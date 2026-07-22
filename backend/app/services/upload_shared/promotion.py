"""Atomic promotion of a staged/assembled file into canonical storage.

Extracted from Memory's finalize step, which called ``os.replace``
directly. That is preserved as the fast path here (identical behaviour
on the same filesystem -- the only configuration Memory or Evidence run
in today). A cross-filesystem fallback is added on top: ``os.replace``
raises ``OSError`` across devices, which today would surface as an
unhandled finalize failure. This closes that gap without changing
behaviour for the same-filesystem case.
"""
from __future__ import annotations

import errno
import os
import shutil
from pathlib import Path


def atomic_promote(src: Path, dest: Path) -> None:
    """Move ``src`` to ``dest``, replacing any existing file at ``dest``.

    Same-filesystem: a single atomic rename (unchanged from prior
    behaviour). Cross-filesystem: copy to a temp file beside ``dest``,
    fsync it, atomically rename it into place, then remove ``src``. The
    canonical path never observably contains partial bytes in either case.
    """
    try:
        os.replace(src, dest)
        return
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
    _cross_filesystem_promote(src, dest)


def _cross_filesystem_promote(src: Path, dest: Path) -> None:
    temp_dest = dest.parent / f".{dest.name}.{os.getpid()}.promote-tmp"
    try:
        with src.open("rb") as source, temp_dest.open("xb") as target:
            shutil.copyfileobj(source, target)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temp_dest, dest)
    except BaseException:
        temp_dest.unlink(missing_ok=True)
        raise
    src.unlink(missing_ok=True)


def fsync_directory(path: Path) -> None:
    dir_fd = os.open(str(path), os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
