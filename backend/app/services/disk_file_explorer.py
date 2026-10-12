"""Browse and export files from a processed disk image.

Every filesystem read happens in app.disk_images.file_browser_cli, a child
process killed on a timeout (see that module for why). This module only
decides what may be opened, runs the helper, and packages exports as a ZIP
protected with the customary password "infected", so a recovered binary never
lands on the analyst's machine as a runnable file."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.disk_images.registry import ewf_series_members
from app.models.disk_image import DiskImage, DiskVolume, OSInstallation
from app.models.evidence import Evidence


ARCHIVE_PASSWORD = "infected"
# Formats the helper reads in place. The others (VMDK, VHD, QCOW, VDI) are
# converted to a temporary raw file while processing and that file is gone.
BROWSABLE_FORMATS = {"raw", "ewf"}
_TIMEOUTS = {"list": 60, "find": 300, "export": 1800}


class DiskFileExplorerError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def _image_for(db: Session, evidence: Evidence) -> DiskImage:
    disk_image = db.query(DiskImage).filter(DiskImage.evidence_id == evidence.id).one_or_none()
    if disk_image is None:
        raise DiskFileExplorerError(404, "not_a_disk_image", "This evidence is not a disk image.")
    return disk_image


def _unavailable_reason(evidence: Evidence, disk_image: DiskImage) -> str | None:
    if disk_image.format not in BROWSABLE_FORMATS:
        return f"Browsing is available for raw and E01 images; this one is {disk_image.format.upper()}."
    if not evidence.stored_path or not Path(evidence.stored_path).exists():
        return "The original image is no longer stored."
    return None


def list_volumes(db: Session, evidence: Evidence) -> dict[str, Any]:
    disk_image = _image_for(db, evidence)
    reason = _unavailable_reason(evidence, disk_image)
    volumes = db.query(DiskVolume).filter(DiskVolume.disk_image_id == disk_image.id).order_by(DiskVolume.partition_index).all()
    installs = db.query(OSInstallation).filter(OSInstallation.disk_volume_id.in_([volume.id for volume in volumes])).all() if volumes else []
    items = []
    for volume in volumes:
        volume_reason = reason
        if volume_reason is None and volume.encrypted:
            volume_reason = "The volume is encrypted."
        elif volume_reason is None and not volume.readable:
            volume_reason = "No filesystem Kairon can read was found on this volume."
        items.append({
            "id": volume.id,
            "partition_index": volume.partition_index,
            "label": volume.label,
            "filesystem_type": volume.filesystem_type,
            "partition_type": volume.partition_type,
            "length_bytes": volume.length_bytes,
            "logical_volume": (volume.metadata_json or {}).get("lvm", {}).get("logical_volume"),
            "browsable": volume_reason is None,
            "unavailable_reason": volume_reason,
            "installations": [
                {"platform": item.platform, "hostname": item.hostname, "distro": item.distro, "version": item.version, "root_path": item.root_path}
                for item in installs
                if item.disk_volume_id == volume.id
            ],
        })
    return {"evidence_id": evidence.id, "format": disk_image.format, "image_name": disk_image.original_filename, "volumes": items, "archive_password": ARCHIVE_PASSWORD}


def _volume_request(db: Session, evidence: Evidence, volume_id: str) -> dict[str, Any]:
    disk_image = _image_for(db, evidence)
    volume = db.get(DiskVolume, volume_id)
    if volume is None or volume.disk_image_id != disk_image.id:
        raise DiskFileExplorerError(404, "volume_not_found", "Volume not found in this image.")
    reason = _unavailable_reason(evidence, disk_image)
    if reason is None and (volume.encrypted or not volume.readable):
        reason = "This volume has no readable filesystem."
    if reason:
        raise DiskFileExplorerError(409, "volume_not_browsable", reason)
    stored = Path(evidence.stored_path)
    segments = ewf_series_members(stored) if disk_image.format == "ewf" else [stored]
    return {
        "image": {"format": disk_image.format, "segments": [str(item) for item in segments]},
        "volume": {
            "offset_bytes": volume.offset_bytes,
            "partition_index": volume.partition_index,
            "metadata": volume.metadata_json or {},
            "warnings": volume.warnings_json or [],
        },
        # The journal never changes (the image is read-only), so its index is built once per volume.
        "journal_cache": str(get_settings().backend_temp_dir / "disk-journal-index" / f"{volume.id}.json"),
    }


def _run_helper(request: dict[str, Any]) -> dict[str, Any]:
    timeout = _TIMEOUTS[request["op"]]
    backend_root = Path(__file__).resolve().parents[2]
    env = {**os.environ, "PYTHONPATH": str(backend_root)}
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "app.disk_images.file_browser_cli"],
            input=json.dumps(request),
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(backend_root),
            env=env,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DiskFileExplorerError(504, "explorer_timeout", f"Reading the filesystem took longer than {timeout} s and was stopped.") from exc
    try:
        response = json.loads(completed.stdout or "")
    except json.JSONDecodeError as exc:
        detail = (completed.stderr or "").strip().splitlines()[-1:] or [f"exit code {completed.returncode}"]
        raise DiskFileExplorerError(502, "explorer_failed", f"The filesystem reader stopped unexpectedly ({detail[0]}).") from exc
    if response.get("error"):
        status = 422 if response["error"] in {"empty_pattern", "directory_unreadable"} else 502
        raise DiskFileExplorerError(status, str(response["error"]), str(response.get("message") or response["error"]))
    return response


def list_directory(db: Session, evidence: Evidence, volume_id: str, *, path: str | None, inode: int | None) -> dict[str, Any]:
    request = {**_volume_request(db, evidence, volume_id), "op": "list", "path": _normalize_path(path), "inode": inode, "max_entries": get_settings().disk_file_browser_max_entries}
    return _run_helper(request)


def find_files(db: Session, evidence: Evidence, volume_id: str, *, pattern: str, path: str | None, include_deleted: bool) -> dict[str, Any]:
    request = {**_volume_request(db, evidence, volume_id), "op": "find", "pattern": pattern, "path": _normalize_path(path), "inode": None, "include_deleted": include_deleted, "max_results": 500}
    return _run_helper(request)


def _normalize_path(path: str | None) -> str:
    parts = [part for part in (path or "/").replace("\\", "/").split("/") if part and part != "."]
    if ".." in parts:
        raise DiskFileExplorerError(422, "invalid_path", "Paths may not contain '..'.")
    return "/" + "/".join(parts)


def export_files(db: Session, evidence: Evidence, volume_id: str, *, items: list[dict[str, Any]], include_deleted: bool) -> tuple[Path, dict[str, Any]]:
    """Export to a password-protected ZIP. Returns the archive path (inside a
    temporary directory the caller removes once sent) and the export summary
    that also goes into the archive as kairon-export.json."""
    if not items:
        raise DiskFileExplorerError(422, "nothing_selected", "Select at least one file or folder.")
    settings = get_settings()
    base_request = _volume_request(db, evidence, volume_id)
    work_dir = Path(tempfile.mkdtemp(prefix="disk-export-", dir=_temp_root()))
    try:
        content_dir = work_dir / "content"
        content_dir.mkdir()
        response = _run_helper({
            **base_request,
            "op": "export",
            "items": [_clean_item(item) for item in items],
            "include_deleted": include_deleted,
            "output_dir": str(content_dir),
            "max_bytes": settings.disk_file_export_max_bytes,
            "max_files": settings.disk_file_export_max_files,
        })
        disk_image = _image_for(db, evidence)
        volume = db.get(DiskVolume, volume_id)
        summary = {
            "evidence_id": evidence.id,
            "case_id": evidence.case_id,
            "image": disk_image.original_filename,
            "image_sha256": disk_image.sha256,
            "volume": {"id": volume_id, "partition_index": volume.partition_index, "filesystem_type": volume.filesystem_type, "label": volume.label},
            "files": response.get("manifest") or [],
            "truncated": bool(response.get("truncated")),
        }
        (content_dir / "kairon-export.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
        archive = work_dir / "export.zip"
        completed = subprocess.run(
            ["7z", "a", "-tzip", f"-p{ARCHIVE_PASSWORD}", "-mem=ZipCrypto", "-mx=1", "-bd", "-y", str(archive), "."],
            cwd=str(content_dir),
            capture_output=True,
            text=True,
            timeout=_TIMEOUTS["export"],
            shell=False,
        )
        if completed.returncode != 0 or not archive.exists():
            raise DiskFileExplorerError(500, "archive_failed", "The export archive could not be created.")
        shutil.rmtree(content_dir, ignore_errors=True)
        return archive, summary
    except BaseException:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise


def _temp_root() -> Path:
    root = get_settings().backend_temp_dir / "disk-exports"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _clean_item(item: dict[str, Any]) -> dict[str, Any]:
    """Only the address of the item is taken from the request: the helper
    re-reads its kind, status and times from the filesystem."""
    def as_int(value: Any) -> int | None:
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            raise DiskFileExplorerError(422, "invalid_item", "Inode numbers must be integers.") from None

    path = _normalize_path(str(item.get("path") or ""))
    if path == "/":
        raise DiskFileExplorerError(422, "invalid_item", "Pick files or folders, not the volume root.")
    return {"path": path, "inode": as_int(item.get("inode")), "parent_inode": as_int(item.get("parent_inode"))}
