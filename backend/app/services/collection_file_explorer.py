"""Browse and export files from a collection evidence (a ZIP/7z/TAR archive,
an uploaded folder, an AD1 logical image repacked at registration).

A collection holds files, not a filesystem: there are no volumes, inodes or
deleted entries to show, so it is presented as one volume whose tree comes
from the archive listing. For an AD1 image, the NTFS times, hashes, owner
and attributes FTK recorded at acquisition (kept beside the repack, see
app.ingest.ad1_image.write_ad1_metadata) replace the archive's own
modification time. Answers have the disk explorer's shape so the same page
shows both."""

from __future__ import annotations

from datetime import datetime, timezone
import fnmatch
from functools import lru_cache
import hashlib
import json
from pathlib import Path
from typing import Any

from app.ingest.velociraptor.zip_inventory import EvidenceContainer, is_supported_archive_container, open_evidence_container
from app.models.evidence import Evidence

COLLECTION_VOLUME_ID = "collection"
_CHUNK = 1024 * 1024


class CollectionExplorerError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def _container_path(evidence: Evidence) -> Path | None:
    stored = Path(evidence.stored_path or "")
    if not evidence.stored_path or not stored.exists():
        return None
    if stored.is_dir() or is_supported_archive_container(stored):
        return stored
    return None


def is_collection(evidence: Evidence) -> bool:
    return _container_path(evidence) is not None


def _ad1_source(evidence: Evidence) -> Path | None:
    repacked = (evidence.metadata_json or {}).get("repacked_from") or {}
    if not any(step.get("format") == "ad1" for step in repacked.get("steps") or []):
        return None
    return Path(str(repacked.get("path") or ""))


def _ad1_sidecar(evidence: Evidence) -> Path | None:
    """FTK's per-file metadata file. Written at registration; for an image
    repacked before that existed, rebuilt once from the .ad1 when it is the
    uploaded file itself."""
    from app.core.storage import build_evidence_root
    from app.services.evidence_container_prep import ad1_metadata_path

    source = _ad1_source(evidence)
    if source is None:
        return None
    sidecar = ad1_metadata_path(build_evidence_root(evidence.case_id, evidence.id))
    if not sidecar.is_file() and source.suffix.lower() == ".ad1" and source.is_file():
        from app.ingest.ad1_image import iter_ad1_files, open_ad1, write_ad1_metadata

        try:
            write_ad1_metadata(list(iter_ad1_files(open_ad1(source))), sidecar)
        except Exception:  # noqa: BLE001 - the tree is still browsable without it
            return None
    return sidecar if sidecar.is_file() else None


@lru_cache(maxsize=8)
def _read_sidecar(path: str, _mtime: float) -> dict[str, dict]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8")).get("files") or {}
    except (OSError, ValueError):
        return {}


def _epoch(value: str | None) -> int | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        for pattern in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(str(value), pattern)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


class _Tree:
    """The archive listing as directories (path -> child names) and files."""

    def __init__(self, container: EvidenceContainer, metadata: dict[str, dict]):
        self.container = container
        self.files: dict[str, dict[str, Any]] = {}
        self.children: dict[str, set[str]] = {"/": set()}
        for entry in container.list_entries():
            # Files ingestion skips (empty, desktop.ini, Thumbs.db...) are
            # still part of what was collected, so they are listed here.
            if entry.is_dir:
                continue
            path = "/" + entry.path.replace("\\", "/").strip("/")
            meta = metadata.get(entry.path) or {}
            self.files[path] = {
                "name": path.rsplit("/", 1)[-1],
                "path": path,
                "source": entry.path,
                "kind": "file",
                "status": "allocated",
                "size": entry.size,
                "mtime": meta.get("mtime") or _epoch(entry.mtime),
                "atime": meta.get("atime"),
                "ctime": meta.get("ctime"),
                "crtime": meta.get("crtime"),
                **{key: meta[key] for key in ("md5", "sha1", "owner", "owner_sid", "short_name", "attributes") if key in meta},
            }
            parent, _, name = path.rpartition("/")
            parent = parent or "/"
            self.children.setdefault(parent, set()).add(name)
            while parent != "/":
                grand, _, dirname = parent.rpartition("/")
                grand = grand or "/"
                self.children.setdefault(parent, set())
                known = dirname in self.children.setdefault(grand, set())
                self.children[grand].add(dirname)
                if known:
                    break
                parent = grand

    def entry(self, path: str) -> dict[str, Any] | None:
        if path in self.files:
            return self.files[path]
        if path in self.children and path != "/":
            return {"name": path.rsplit("/", 1)[-1], "path": path, "kind": "dir", "status": "allocated", "size": None, "mtime": None, "atime": None, "ctime": None, "crtime": None}
        return None

    def listing(self, path: str) -> list[dict[str, Any]]:
        if path not in self.children:
            raise CollectionExplorerError(404, "directory_not_found", f"{path} is not a folder in this collection.")
        base = path.rstrip("/")
        entries = [self.entry(f"{base}/{name}") for name in self.children[path]]
        return sorted((item for item in entries if item), key=lambda item: (item["kind"] != "dir", item["name"].lower()))

    def walk(self, path: str):
        prefix = path.rstrip("/") + "/"
        for file_path in sorted(self.files):
            if path == "/" or file_path.startswith(prefix):
                yield self.files[file_path]


def _tree(evidence: Evidence) -> _Tree:
    container_path = _container_path(evidence)
    if container_path is None:
        raise CollectionExplorerError(409, "collection_unavailable", "The collection is no longer stored.")
    sidecar = _ad1_sidecar(evidence)
    return _cached_tree(str(container_path), container_path.stat().st_mtime, str(sidecar or ""), sidecar.stat().st_mtime if sidecar else 0)


@lru_cache(maxsize=4)
def _cached_tree(container_path: str, _mtime: float, sidecar: str, sidecar_mtime: float) -> _Tree:
    metadata = _read_sidecar(sidecar, sidecar_mtime) if sidecar else {}
    return _Tree(open_evidence_container(Path(container_path)), metadata)


def _format(evidence: Evidence) -> str:
    if _ad1_source(evidence):
        return "ad1"
    container_path = _container_path(evidence)
    if container_path is None:
        return "collection"
    return "folder" if container_path.is_dir() else (container_path.suffix.lstrip(".").lower() or "archive")


_FORMAT_LABELS = {"ad1": "AD1 logical image", "zip": "ZIP collection", "folder": "Folder"}


def list_volumes(evidence: Evidence, archive_password: str) -> dict[str, Any]:
    tree = _tree(evidence)
    fmt = _format(evidence)
    return {
        "evidence_id": evidence.id,
        "format": fmt,
        "kind": "collection",
        "image_name": evidence.original_filename,
        "archive_password": archive_password,
        "volumes": [{
            "id": COLLECTION_VOLUME_ID,
            "partition_index": 0,
            "label": evidence.original_filename,
            "filesystem_type": _FORMAT_LABELS.get(fmt, f"{fmt.upper()} collection"),
            "partition_type": None,
            "length_bytes": sum(int(item.get("size") or 0) for item in tree.files.values()),
            "logical_volume": None,
            "browsable": True,
            "unavailable_reason": None,
            "installations": [],
            "file_count": len(tree.files),
        }],
    }


def _check_volume(volume_id: str) -> None:
    if volume_id != COLLECTION_VOLUME_ID:
        raise CollectionExplorerError(404, "volume_not_found", "Volume not found in this collection.")


def list_directory(evidence: Evidence, volume_id: str, *, path: str, max_entries: int) -> dict[str, Any]:
    _check_volume(volume_id)
    every = _tree(evidence).listing(path)
    entries = every[:max_entries]
    return {"path": path, "inode": None, "entries": entries, "total": len(every), "truncated": len(every) > len(entries), "journal": False}


def find_files(evidence: Evidence, volume_id: str, *, pattern: str, path: str, max_results: int = 500) -> dict[str, Any]:
    _check_volume(volume_id)
    raw = pattern.strip()
    if not raw:
        raise CollectionExplorerError(422, "empty_pattern", "Type part of a name or a glob such as *.php.")
    glob = raw.lower() if any(ch in raw for ch in "*?[") else f"*{raw.lower()}*"
    match_path = "/" in raw
    results: list[dict[str, Any]] = []
    scanned = 0
    for entry in _tree(evidence).walk(path):
        scanned += 1
        if fnmatch.fnmatchcase((entry["path"] if match_path else entry["name"]).lower(), glob):
            results.append(entry)
            if len(results) >= max_results:
                return {"results": results, "scanned": scanned, "truncated": True}
    return {"results": results, "scanned": scanned, "truncated": False}


def export_into(evidence: Evidence, volume_id: str, *, items: list[dict[str, Any]], output_dir: Path, max_bytes: int, max_files: int) -> dict[str, Any]:
    """Copy the selected files (folders: every file under them) into
    output_dir/files, with a manifest in the disk explorer's shape."""
    _check_volume(volume_id)
    tree = _tree(evidence)
    files_root = output_dir / "files"
    files_root.mkdir(parents=True, exist_ok=True)
    budget = {"bytes": max_bytes, "files": max_files}
    manifest: list[dict[str, Any]] = []
    truncated = False

    def export(entry: dict[str, Any]) -> None:
        nonlocal truncated
        if budget["files"] <= 0 or budget["bytes"] <= 0:
            truncated = True
            return
        budget["files"] -= 1
        record = {key: entry.get(key) for key in ("path", "size", "mtime", "atime", "ctime", "crtime", "md5", "sha1", "owner")}
        record["status"] = "allocated"
        if int(entry.get("size") or 0) > budget["bytes"]:
            manifest.append({**record, "result": "skipped", "reason": "Over the export size limit."})
            return
        destination = files_root / entry["path"].lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        written = 0
        try:
            with tree.container.open_entry(entry["source"]) as source, destination.open("wb") as target:
                while chunk := source.read(_CHUNK):
                    sha256.update(chunk)
                    md5.update(chunk)
                    target.write(chunk)
                    written += len(chunk)
        except Exception as exc:  # noqa: BLE001
            destination.unlink(missing_ok=True)
            manifest.append({**record, "result": "failed", "reason": f"The file could not be read: {exc}"})
            return
        budget["bytes"] -= written
        result = {**record, "bytes_written": written, "sha256": sha256.hexdigest(), "md5_computed": md5.hexdigest(), "archive_path": destination.relative_to(output_dir).as_posix(), "result": "exported", "reason": ""}
        # FTK's own MD5 from acquisition time, when the image recorded one.
        if entry.get("md5") and entry["md5"].lower() != result["md5_computed"]:
            result["reason"] = "The MD5 differs from the one FTK recorded when the image was acquired."
        manifest.append(result)

    for item in items:
        path = str(item.get("path") or "")
        entry = tree.entry(path)
        if entry is None:
            manifest.append({"path": path, "result": "skipped", "reason": "Not in this collection."})
            continue
        for child in (tree.walk(path) if entry["kind"] == "dir" else [entry]):
            export(child)
            if truncated:
                break
        if truncated:
            break
    return {"manifest": manifest, "truncated": truncated}


def clear_caches() -> None:
    _cached_tree.cache_clear()
    _read_sidecar.cache_clear()
