"""A UAC collection run by Velociraptor.

Velociraptor's UAC artifacts (Generic.Collection.UAC and the custom variants made from it) run UAC
on the client and upload the archive UAC writes, so the collection ZIP holds that archive under
``uploads/`` (with the ``.log`` UAC writes next to it) plus Velociraptor's own files: the
artifact's ``results/`` (UAC's console output), ``log.json``, ``uploads.json``, ``requests.json``,
``client_info.json`` and ``collection_context.json``.

Velociraptor's artifact discovery only knows Windows artifacts, so such a ZIP must be read as an
archive holding a UAC collection instead: the archive is extracted and its ``uac.log`` decides the
platform. Whether a ``.tar.gz`` is UAC's is read from its first members, not from its name.
"""

from __future__ import annotations

import tarfile
import time
from pathlib import Path, PurePosixPath
from typing import IO

from app.ingest.uac.collection import UAC_LOG_NAME, UAC_OUTPUT_DIRS

# Velociraptor's own files of a collection, at the top of the ZIP.
VELOCIRAPTOR_COLLECTION_FILES = frozenset(
    {
        "client_info.json",
        "collection_context.json",
        "requests.json",
        "log.json",
        "log.json.index",
        "uploads.json",
        "uploads.json.index",
    }
)
_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar")
_PEEK_MAX_MEMBERS = 400
_PEEK_MAX_SECONDS = 20.0


def _normalized(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def is_velociraptor_collection_file(path: str) -> bool:
    """One of Velociraptor's own files of a collection (not something it collected)."""
    normalized = _normalized(path)
    return normalized in VELOCIRAPTOR_COLLECTION_FILES or (normalized.startswith("results/") and normalized.count("/") == 1)


def _archive_stem(path: str) -> str | None:
    lower = path.lower()
    for suffix in _ARCHIVE_SUFFIXES:
        if lower.endswith(suffix):
            return path[: -len(suffix)]
    return None


def tar_stream_is_uac(stream: IO[bytes]) -> bool:
    """Whether the tar (compressed or not) read from ``stream`` is a UAC output: its uac.log and an
    output directory beside it within the first members. Reads only those members."""
    deadline = time.monotonic() + _PEEK_MAX_SECONDS
    logs: set[str] = set()
    outputs: set[str] = set()
    try:
        with tarfile.open(fileobj=stream, mode="r|*") as archive:
            for index, member in enumerate(archive):
                if index >= _PEEK_MAX_MEMBERS or time.monotonic() > deadline:
                    break
                parts = PurePosixPath(_normalized(member.name)).parts
                if not parts:
                    continue
                for depth in range(min(len(parts), 3)):
                    base = "/".join(parts[:depth])
                    if member.isfile() and len(parts) == depth + 1 and parts[depth] == UAC_LOG_NAME:
                        logs.add(base)
                    elif parts[depth] in UAC_OUTPUT_DIRS and len(parts) > depth:
                        outputs.add(base)
                if logs & outputs:
                    return True
    except (tarfile.TarError, OSError, EOFError, ValueError):
        return False
    return False


def uac_archives_in_velociraptor_collection(container, entry_paths: list[str]) -> list[str]:
    """The UAC archives of a Velociraptor collection that holds nothing else: only Velociraptor's own
    files, the archives under uploads/ and the .log UAC writes beside each. Empty otherwise (a
    collection with other artifacts keeps Velociraptor's discovery)."""
    files = [_normalized(path) for path in entry_paths]
    if not any(path in VELOCIRAPTOR_COLLECTION_FILES for path in files):
        return []
    archives = [path for path in files if path.startswith("uploads/") and _archive_stem(path)]
    if not archives:
        return []
    companions = {f"{_archive_stem(path)}.log" for path in archives}
    if any(not is_velociraptor_collection_file(path) and path not in archives and path not in companions for path in files):
        return []
    found = []
    for path in archives:
        original = next((entry for entry in entry_paths if _normalized(entry) == path), path)
        try:
            with container.open_entry(original) as stream:
                if tar_stream_is_uac(stream):
                    found.append(path)
        except Exception:  # noqa: BLE001 - an unreadable member is not UAC's
            continue
    return found


def velociraptor_files_beside_uac(extract_dir: Path, uac_root: Path) -> list[str]:
    """Velociraptor's own files of an extracted collection whose UAC output sits in a nested archive,
    and the .log copy of uac.log beside that archive: relative paths, to leave out of the ingest."""
    try:
        if uac_root.resolve() == extract_dir.resolve() or not any((extract_dir / name).is_file() for name in ("client_info.json", "collection_context.json")):
            return []
    except OSError:
        return []
    found: list[str] = []
    for path in sorted(extract_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(extract_dir).as_posix()
        if relative.startswith("_nested_"):
            continue
        if is_velociraptor_collection_file(relative):
            found.append(relative)
        elif relative.startswith("uploads/") and relative.endswith(".log") and any((path.parent / f"{path.stem}{suffix}").is_file() for suffix in _ARCHIVE_SUFFIXES):
            found.append(relative)
    return sorted(found)

