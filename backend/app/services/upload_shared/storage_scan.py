"""Filesystem scan helpers shared by upload cleanup and reconcile passes."""
from __future__ import annotations

from pathlib import Path


def directory_size(path: Path) -> int:
    total = 0
    for child in path.rglob("*"):
        if child.is_file() and not child.is_symlink():
            total += child.stat().st_size
    return total


def list_orphan_directories(
    staging_root: Path,
    known_names: set[str],
    *,
    mtime_before: float | None = None,
) -> list[Path]:
    """Directories directly under ``staging_root`` with no matching DB row.

    ``mtime_before`` (a POSIX timestamp), when given, excludes directories
    modified at or after that time -- used to avoid racing an in-flight
    session creation that hasn't committed its DB row yet.
    """
    if not staging_root.exists():
        return []
    orphans: list[Path] = []
    for entry in staging_root.iterdir():
        if not entry.is_dir() or entry.is_symlink():
            continue
        if entry.name in known_names:
            continue
        if mtime_before is not None and entry.stat().st_mtime > mtime_before:
            continue
        orphans.append(entry)
    return orphans
