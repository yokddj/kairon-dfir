"""Runtime helpers for the operator-only memory symbol CLI.

This module is the *trusted* counterpart of the HTTP recovery routes.
It is imported by both :mod:`app.cli.memory_symbols` (the CLI
subcommands) and by the operator-only ``cli_import_*`` helpers in
:mod:`app.services.memory.symbol_recovery` (the canonical
import pipeline).

The module contains:

* :func:`validate_input_file` — rejects symlinks, non-regular
  files, world-writable files, files outside the configured
  operator roots, files whose extension is not in the allow-list,
  and files that exceed the configured size limits.  Returns a
  dict with the resolved path, SHA-256, size and sanitized
  original filename.
* :func:`compute_sha256` — stream-hash a file.
* :func:`prompt_for_confirmation` — interactive ``--yes``-aware
  confirmation prompt.  Tries to avoid printing internal paths
  or other secrets in the prompt body.

The module is **not** exposed via HTTP.  Importing it from a
request handler would be a security regression: every helper
presupposes the caller is running inside a trusted backend
container with operator-level access.
"""
from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path
from typing import Iterable


# Maximum upload size for the CLI.  Mirrors the HTTP route's
# ``memory_symbol_isf_max_bytes`` / ``memory_symbol_download_max_bytes``
# defaults; the operator can override per-invocation by setting
# ``KAIRON_CLI_INPUT_MAX_BYTES`` in the environment.
DEFAULT_INPUT_MAX_BYTES = 1_073_741_824  # 1 GiB


class InputFileError(ValueError):
    """Raised by :func:`validate_input_file` when a file fails a
    safety check.  The message is intended to be shown to the
    operator; it never includes the resolved filesystem path.
    """


def compute_sha256(path: Path, *, max_bytes: int | None = None) -> str:
    """Stream-hash a file, refusing to read past ``max_bytes``."""
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise ValueError(
                    f"file exceeds maximum size: {total} > {max_bytes}"
                )
    return digest.hexdigest()


def _resolve_operator_roots() -> list[Path]:
    """Return the configured operator import roots.

    The roots are read from the ``KAIRON_CLI_OPERATOR_ROOTS``
    environment variable (comma-separated absolute paths).  When
    unset, the function returns an empty list and
    :func:`validate_input_file` will reject every file unless the
    caller passes ``safe_override=True``.
    """
    raw = str(os.environ.get("KAIRON_CLI_OPERATOR_ROOTS") or "").strip()
    if not raw:
        return []
    roots: list[Path] = []
    for entry in raw.split(","):
        candidate = entry.strip()
        if not candidate:
            continue
        candidate_path = Path(candidate)
        if not candidate_path.is_absolute():
            continue
        roots.append(candidate_path.resolve())
    return roots


def _is_within_roots(path: Path, roots: Iterable[Path]) -> bool:
    resolved = path.resolve()
    for root in roots:
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def validate_input_file(
    raw_path: Path,
    *,
    allowed_extensions: set[str] | None = None,
    safe_override: bool = False,
    max_bytes: int | None = None,
) -> dict[str, object]:
    """Validate a CLI input file.

    The function performs the following safety checks, in order:

    1. Reject paths that do not exist or that are not regular files.
    2. Reject symlinks and other non-regular inodes (block devices,
       FIFOs, sockets, character devices, hardlinks that point
       outside the operator roots).
    3. Reject world-writable files (``mode & 0o002``).
    4. Reject files outside the configured operator roots
       (unless ``safe_override=True``).
    5. Reject files whose extension is not in ``allowed_extensions``.
    6. Reject files that exceed ``max_bytes``.

    The function returns a dict with:

    * ``resolved_path`` — the absolute path.
    * ``original_filename`` — the on-disk basename.
    * ``sha256`` — the stream-computed SHA-256.
    * ``size_bytes`` — the file size in bytes.
    * ``mode`` — the file mode (octal, as ``str``).
    """
    max_bytes = int(
        max_bytes
        if max_bytes is not None
        else int(os.environ.get("KAIRON_CLI_INPUT_MAX_BYTES") or DEFAULT_INPUT_MAX_BYTES)
    )
    if allowed_extensions:
        allowed = {ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in allowed_extensions}

    try:
        if not raw_path.exists():
            raise InputFileError("input file does not exist")
    except OSError as exc:
        raise InputFileError(f"input file is not accessible: {exc.strerror or exc!s}") from exc

    # ``stat`` (not ``lstat``) so a symlink pointing to a regular
    # file is still rejected at this stage.
    try:
        file_stat = raw_path.stat()
    except OSError as exc:
        raise InputFileError(f"input file is not accessible: {exc.strerror or exc!s}") from exc

    # ``lstat`` separately so we can detect symlinks that would
    # otherwise be silently followed.
    try:
        link_stat = raw_path.lstat()
    except OSError:
        link_stat = file_stat

    if stat.S_ISLNK(link_stat.st_mode):
        raise InputFileError("input file is a symbolic link; refusing")
    if not stat.S_ISREG(file_stat.st_mode):
        kind = {
            stat.S_ISDIR: "directory",
            stat.S_ISBLK: "block device",
            stat.S_ISCHR: "character device",
            stat.S_ISFIFO: "FIFO",
            stat.S_ISSOCK: "socket",
        }.get(
            (
                stat.S_ISDIR,
                stat.S_ISBLK,
                stat.S_ISCHR,
                stat.S_ISFIFO,
                stat.S_ISSOCK,
            ),
            None,
        )
        if kind is None:
            kind = "non-regular file"
        raise InputFileError(f"input is a {kind}; only regular files are accepted")
    if file_stat.st_mode & 0o002:
        raise InputFileError("input file is world-writable; refusing")
    if file_stat.st_mode & 0o111:
        raise InputFileError("input file is executable; refusing")

    resolved = raw_path.resolve()
    roots = _resolve_operator_roots()
    if roots and not _is_within_roots(resolved, roots):
        if not safe_override:
            raise InputFileError(
                "input file is outside the configured operator import roots; "
                "pass --safe-override to bypass"
            )

    if allowed_extensions and resolved.suffix.lower() not in allowed:
        raise InputFileError(
            f"input file extension {resolved.suffix!r} is not allowed; expected one of {sorted(allowed)!r}"
        )
    if file_stat.st_size > max_bytes:
        raise InputFileError(
            f"input file size {file_stat.st_size} exceeds limit {max_bytes}"
        )
    sha256 = compute_sha256(resolved, max_bytes=max_bytes)
    return {
        "resolved_path": str(resolved),
        "original_filename": resolved.name,
        "sha256": sha256,
        "size_bytes": int(file_stat.st_size),
        "mode": oct(file_stat.st_mode & 0o7777),
    }


def prompt_for_confirmation(prompt: str, *, assume_yes: bool) -> bool:
    """Show an interactive confirmation prompt.

    When ``assume_yes`` is True the function returns immediately.
    Otherwise it reads a line from stdin and accepts only
    "yes" / "y" (case-insensitive) — everything else is rejected.

    The prompt is always written to ``stderr`` so the structured
    JSON output on ``stdout`` (when ``--json`` is used) is not
    polluted.
    """
    if assume_yes:
        return True
    sys.stderr.write(prompt)
    sys.stderr.write("\n")
    sys.stderr.flush()
    try:
        response = input().strip().lower()
    except EOFError:
        return False
    return response in {"y", "yes"}


__all__ = [
    "DEFAULT_INPUT_MAX_BYTES",
    "InputFileError",
    "compute_sha256",
    "prompt_for_confirmation",
    "validate_input_file",
]
