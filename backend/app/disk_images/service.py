from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

import pytsk3
from sqlalchemy.orm import Session

from app.core.artifact_registry import artifact_registry_entry
from app.core.config import get_settings
from app.core.storage import sanitize_relative_path
from app.disk_images.registry import ewf_series_members, get_image_format_registry
from app.models.disk_image import DiskImage, DiskVolume, OSInstallation
from app.models.evidence import Evidence, EvidencePlatform


settings = get_settings()


@dataclass
class MaterializedDiskImage:
    extract_dir: Path
    extracted_files: list[str]
    manifest_entries: list[dict[str, Any]]
    source_map: dict[str, dict[str, Any]]
    disk_image: DiskImage
    volumes: list[DiskVolume]
    installations: list[OSInstallation]
    warnings: list[str]
    errors: list[dict[str, Any]]


class _PytskFileReader(pytsk3.Img_Info):
    def __init__(self, image_path: Path):
        self._file = image_path.open("rb")
        self._size = image_path.stat().st_size
        super().__init__(url=str(image_path))

    def close(self) -> None:
        try:
            self._file.close()
        except Exception:
            pass

    def read(self, offset: int, size: int) -> bytes:
        self._file.seek(offset)
        return self._file.read(size)

    def get_size(self) -> int:
        return self._size


def _now() -> datetime:
    return datetime.now(UTC)


def _run_tool(command: list[str], *, timeout: int, cwd: Path | None = None) -> dict[str, Any]:
    completed = subprocess.run(command, capture_output=True, text=True, shell=False, timeout=timeout, cwd=str(cwd) if cwd else None)
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
    }


def _tool_version(name: str, version_args: list[str] | None = None) -> str | None:
    args = version_args or ["--version"]
    try:
        completed = subprocess.run([name, *args], capture_output=True, text=True, shell=False, timeout=15)
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    text = (completed.stdout or completed.stderr or "").strip().splitlines()
    return text[0] if text else None


def disk_image_readiness() -> dict[str, Any]:
    registry = get_image_format_registry()
    return {
        "formats": registry.list_capabilities(),
        "tools": {
            "pytsk3": getattr(pytsk3, "__version__", "available"),
            "ewfinfo": _tool_version("ewfinfo"),
            "ewfexport": _tool_version("ewfexport"),
            "mmls": _tool_version("mmls", ["-V"]),
            "fls": _tool_version("fls", ["-V"]),
            "icat": _tool_version("icat", ["-V"]),
            "qemu_img": _tool_version("qemu-img"),
        },
    }


def detect_disk_image_format(path: Path, companions: list[Path] | None = None) -> dict[str, Any] | None:
    return get_image_format_registry().detect(path, companions or [])


def _ewf_companions(path: Path) -> list[Path]:
    if path.suffix.lower() not in {".e01", ".ex01", ".e02", ".e03", ".e04", ".e05"}:
        return [path]
    return ewf_series_members(path)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _filesystem_label(fs_info: pytsk3.FS_Info) -> str | None:
    try:
        return str(getattr(fs_info.info, "ftype", "") or "") or None
    except Exception:
        return None


def _filesystem_type(fs_info: pytsk3.FS_Info) -> str | None:
    try:
        return str(fs_info.info.ftype).split(".")[-1].lower()
    except Exception:
        return None


def _read_image_bytes(image_path: Path, offset: int, length: int = 4096) -> bytes:
    try:
        with image_path.open("rb") as handle:
            handle.seek(max(offset, 0))
            return handle.read(length)
    except OSError:
        return b""


def _detect_encryption_signature(blob: bytes) -> tuple[bool, str | None]:
    if blob.startswith(b"LUKS\xba\xbe"):
        return True, "luks"
    if blob.startswith(b"-FVE-FS-") or b"bitlocker" in blob[:512].lower():
        return True, "bitlocker"
    return False, None


def _read_small_file(fs_info: pytsk3.FS_Info, path: str, limit: int = 32768) -> str:
    try:
        file_obj = fs_info.open(path)
        data = file_obj.read_random(0, limit)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _exists(fs_info: pytsk3.FS_Info, path: str) -> bool:
    try:
        fs_info.open(path)
        return True
    except Exception:
        return False


def _detect_installations(fs_info: pytsk3.FS_Info, volume_id: str) -> list[dict[str, Any]]:
    installations: list[dict[str, Any]] = []
    windows_markers = ["/Windows/System32", "/Windows/System32/config/SYSTEM", "/Windows/System32/config/SOFTWARE", "/Users", "/ProgramData"]
    linux_markers = ["/etc/os-release", "/etc/passwd", "/var/log", "/var/lib/systemd", "/home", "/boot"]
    if sum(1 for marker in windows_markers if _exists(fs_info, marker)) >= 3:
        installations.append(
            {
                "platform": EvidencePlatform.windows.value,
                "hostname": None,
                "version": None,
                "distro": None,
                "root_path": "/",
                "confidence": "high",
                "detection_reasons": windows_markers,
            }
        )
    os_release = _read_small_file(fs_info, "/etc/os-release")
    if os_release or sum(1 for marker in linux_markers if _exists(fs_info, marker)) >= 3:
        hostname = _read_small_file(fs_info, "/etc/hostname", limit=4096).splitlines()[0].strip() if _read_small_file(fs_info, "/etc/hostname", limit=4096) else None
        distro = None
        version = None
        for line in os_release.splitlines():
            if line.startswith("PRETTY_NAME="):
                distro = line.split("=", 1)[1].strip().strip('"')
                version = distro
                break
        installations.append(
            {
                "platform": EvidencePlatform.linux.value,
                "hostname": hostname,
                "version": version,
                "distro": distro,
                "root_path": "/",
                "confidence": "high" if os_release else "medium",
                "detection_reasons": [marker for marker in linux_markers if _exists(fs_info, marker)],
            }
        )
    return installations


def _iter_directory(fs_info: pytsk3.FS_Info, directory_path: str, *, depth: int, max_depth: int):
    if depth > max_depth:
        return
    try:
        directory = fs_info.open_dir(path=directory_path)
    except Exception:
        return
    for entry in directory:
        try:
            name = entry.info.name.name.decode("utf-8", errors="replace")
        except Exception:
            continue
        if name in {".", ".."}:
            continue
        meta = getattr(entry.info, "meta", None)
        full_path = f"{directory_path.rstrip('/')}/{name}" if directory_path != "/" else f"/{name}"
        is_dir = bool(meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR)
        yield full_path, entry, is_dir
        if is_dir:
            yield from _iter_directory(fs_info, full_path, depth=depth + 1, max_depth=max_depth)


def _should_materialize(path: str) -> bool:
    lower_path = path.lower()
    patterns = (
        "/windows/system32/config/system",
        "/windows/system32/config/software",
        "/windows/system32/winevt/logs/",
        "/users/",
        "/programdata/",
        "/etc/passwd",
        "/etc/group",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/cron",
        "/etc/systemd/",
        "/lib/systemd/",
        "/var/log/",
        "/home/",
        "/root/",
        "hostnamectl.txt",
        "/logs/journal",
    )
    return any(pattern in lower_path for pattern in patterns)


def _materialize_volume_installation(
    *,
    fs_info: pytsk3.FS_Info,
    install: OSInstallation,
    disk_image: DiskImage,
    volume: DiskVolume,
    destination_root: Path,
) -> tuple[list[str], list[dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    extracted_files: list[str] = []
    manifest_entries: list[dict[str, Any]] = []
    source_map: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    install_dir = destination_root / f"volume-{volume.partition_index}" / install.platform
    install_dir.mkdir(parents=True, exist_ok=True)
    file_count = 0
    bytes_written = 0
    for full_path, entry, is_dir in _iter_directory(fs_info, install.root_path, depth=0, max_depth=settings.disk_image_max_directory_depth):
        if is_dir or not _should_materialize(full_path):
            continue
        file_count += 1
        if file_count > settings.disk_image_max_files_per_volume:
            warnings.append("max_files_per_volume_exceeded")
            break
        try:
            relative_path = sanitize_relative_path(full_path.lstrip("/"))
        except ValueError:
            warnings.append(f"skipped_invalid_path:{full_path}")
            continue
        if len(str(relative_path)) > settings.disk_image_max_path_length:
            warnings.append(f"skipped_long_path:{full_path}")
            continue
        target = install_dir / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            file_obj = fs_info.open(full_path)
            meta = getattr(entry.info, "meta", None)
            size = int(getattr(meta, "size", 0) or 0)
            data = file_obj.read_random(0, size)
        except Exception:
            warnings.append(f"unreadable_file:{full_path}")
            continue
        bytes_written += len(data)
        if bytes_written > settings.disk_image_max_bytes_per_volume:
            warnings.append("max_bytes_per_volume_exceeded")
            break
        target.write_bytes(data)
        relative_output = str(target.relative_to(destination_root))
        extracted_files.append(relative_output)
        manifest_entries.append({"path": relative_output, "ignored": False, "reason": None, "size": len(data), "status": "extracted", "local_path": str(target)})
        source_map[relative_output] = {
            "disk_image_id": disk_image.id,
            "disk_volume_id": volume.id,
            "os_installation_id": install.id,
            "original_source_path": full_path,
            "logical_source_path": relative_output,
            "acquisition_method": "pytsk3_readonly_materialization",
        }
    return extracted_files, manifest_entries, source_map, warnings


def _discover_raw_volumes(image_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    img = _PytskFileReader(image_path)
    volumes: list[dict[str, Any]] = []
    installs: list[dict[str, Any]] = []
    warnings: list[str] = []
    try:
        try:
            volume_info = pytsk3.Volume_Info(img)
            for index, partition in enumerate(volume_info, start=1):
                desc = getattr(partition, "desc", b"").decode("utf-8", errors="replace").strip() or None
                flags = int(getattr(partition, "flags", 0) or 0)
                start = int(getattr(partition, "start", 0) or 0)
                length = int(getattr(partition, "len", 0) or 0)
                if length <= 0 or flags != 1:
                    continue
                offset_bytes = start * 512
                volume = {
                    "partition_index": index,
                    "offset_bytes": offset_bytes,
                    "length_bytes": length * 512,
                    "partition_type": desc,
                    "filesystem_type": None,
                    "label": None,
                    "uuid": None,
                    "encrypted": False,
                    "readable": False,
                    "status": "discovered",
                    "warnings": [],
                    "error": {},
                    "metadata": {},
                }
                try:
                    fs_info = pytsk3.FS_Info(img, offset=offset_bytes)
                    volume["filesystem_type"] = _filesystem_type(fs_info)
                    volume["label"] = _filesystem_label(fs_info)
                    volume["readable"] = True
                    volume["status"] = "readable"
                    detected = _detect_installations(fs_info, str(index))
                    for install in detected:
                        installs.append({**install, "partition_index": index})
                except Exception as exc:
                    encrypted, encryption_type = _detect_encryption_signature(_read_image_bytes(image_path, offset_bytes))
                    volume["encrypted"] = encrypted
                    volume["metadata"]["encryption_type"] = encryption_type
                    volume["error"] = {"code": "unsupported_filesystem", "message": str(exc)}
                    volume["status"] = "encrypted_volume" if encrypted else "unreadable_volume"
                volumes.append(volume)
        except Exception:
            try:
                fs_info = pytsk3.FS_Info(img)
                volume = {
                    "partition_index": 0,
                    "offset_bytes": 0,
                    "length_bytes": image_path.stat().st_size,
                    "partition_type": "filesystem_image",
                    "filesystem_type": _filesystem_type(fs_info),
                    "label": _filesystem_label(fs_info),
                    "uuid": None,
                    "encrypted": False,
                    "readable": True,
                    "status": "readable",
                    "warnings": [],
                    "error": {},
                    "metadata": {},
                }
                detected = _detect_installations(fs_info, "0")
                for install in detected:
                    installs.append({**install, "partition_index": 0})
                volumes.append(volume)
            except Exception as exc:
                encrypted, encryption_type = _detect_encryption_signature(_read_image_bytes(image_path, 0))
                if encrypted:
                    volumes.append({
                        "partition_index": 0,
                        "offset_bytes": 0,
                        "length_bytes": image_path.stat().st_size,
                        "partition_type": "filesystem_image",
                        "filesystem_type": None,
                        "label": None,
                        "uuid": None,
                        "encrypted": True,
                        "readable": False,
                        "status": "encrypted_volume",
                        "warnings": [],
                        "error": {"code": "encrypted_volume", "message": encryption_type or "encrypted"},
                        "metadata": {"encryption_type": encryption_type},
                    })
                else:
                    warnings.append(f"no_supported_partition_or_filesystem:{exc}")
        return volumes, installs, warnings
    finally:
        img.close()


def upsert_disk_image_record(db: Session, evidence: Evidence, *, format_key: str, original_filename: str, size_bytes: int, sha256: str | None, segment_count: int, status: str, metadata: dict[str, Any], tool_metadata: dict[str, Any], warnings: list[str], error: dict[str, Any]) -> DiskImage:
    disk_image = db.query(DiskImage).filter(DiskImage.evidence_id == evidence.id).one_or_none()
    now = _now().replace(tzinfo=None)
    if disk_image is None:
        disk_image = DiskImage(
            evidence_id=evidence.id,
            original_filename=original_filename,
            format=format_key,
            size_bytes=size_bytes,
            sha256=sha256,
            segment_count=segment_count,
            status=status,
            metadata_json=metadata,
            tool_metadata=tool_metadata,
            warnings_json=warnings,
            error_json=error,
            created_at=now,
            updated_at=now,
        )
        db.add(disk_image)
        db.flush()
    else:
        disk_image.original_filename = original_filename
        disk_image.format = format_key
        disk_image.size_bytes = size_bytes
        disk_image.sha256 = sha256
        disk_image.segment_count = segment_count
        disk_image.status = status
        disk_image.metadata_json = metadata
        disk_image.tool_metadata = tool_metadata
        disk_image.warnings_json = warnings
        disk_image.error_json = error
        disk_image.updated_at = now
        db.flush()
    return disk_image


def materialize_disk_image_sources(db: Session, evidence: Evidence, *, extract_dir: Path, image_path: Path | None = None, progress_cb=None) -> MaterializedDiskImage:
    stored_path = image_path or Path(evidence.stored_path)
    extract_dir.mkdir(parents=True, exist_ok=True)
    registry = get_image_format_registry()
    companions = _ewf_companions(stored_path)
    detected = registry.detect(stored_path, companions)
    if not detected:
        raise ValueError("unknown_format")
    adapter = registry.get(str(detected.get("format") or ""))
    if adapter is None:
        raise ValueError("unknown_format")
    if progress_cb:
        progress_cb({"current_action": "detecting_format"})
    readiness = adapter.readiness()
    validation = adapter.validate_segments(stored_path, companions)
    if not validation.get("valid", True):
        disk_image = upsert_disk_image_record(
            db,
            evidence,
            format_key=adapter.key,
            original_filename=stored_path.name,
            size_bytes=sum(item.stat().st_size for item in companions if item.exists()),
            sha256=evidence.sha256,
            segment_count=len(companions),
            status="failed",
            metadata={"validation": validation},
            tool_metadata={"adapter": adapter.key},
            warnings=[],
            error={"code": validation.get("error"), "validation": validation},
        )
        db.commit()
        raise ValueError(str(validation.get("error") or "invalid_segment_set"))
    if progress_cb:
        progress_cb({"current_action": "hashing"})
    segment_hashes = [{"name": item.name, "sha256": _hash_file(item), "size_bytes": item.stat().st_size} for item in companions]
    combined_sha256 = evidence.sha256 if len(companions) == 1 else hashlib.sha256(json.dumps(segment_hashes, sort_keys=True).encode("utf-8")).hexdigest()
    disk_image = upsert_disk_image_record(
        db,
        evidence,
        format_key=adapter.key,
        original_filename=stored_path.name,
        size_bytes=sum(item.stat().st_size for item in companions if item.exists()),
        sha256=combined_sha256,
        segment_count=len(companions),
        status="inspecting_image",
        metadata={"segments": [item.name for item in companions]},
        tool_metadata={"adapter": adapter.key, "operations": [{"step": "hashing", "segment_hashes": segment_hashes}]},
        warnings=[],
        error={},
    )
    db.flush()
    workspace = extract_dir.parent / f"disk-image-{evidence.id}"
    workspace.mkdir(parents=True, exist_ok=True)
    inspect_metadata = adapter.inspect(stored_path, companions)
    if isinstance(inspect_metadata, dict):
        disk_image.metadata_json = {**(disk_image.metadata_json or {}), **{k: v for k, v in inspect_metadata.items() if k not in {"format", "supported", "path", "validation", "segments"}}}
    context: dict[str, Any] | None = None
    if progress_cb:
        progress_cb({"current_action": "inspecting_image"})
    try:
        context = adapter.expose_readonly(evidence_id=evidence.id, path=stored_path, companions=companions, workspace=workspace)
        if not context.get("supported", True):
            disk_image.status = "failed"
            disk_image.error_json = {"code": context.get("error") or "missing_dependency", "details": context}
            disk_image.tool_metadata = {**(disk_image.tool_metadata or {}), "operations": [*(disk_image.tool_metadata or {}).get("operations", []), {"step": "expose_readonly", **context}]}
            db.commit()
            raise ValueError(str(context.get("error") or "missing_dependency"))
        raw_path = Path(str(context.get("exported_raw_path") or context.get("image_path") or stored_path))
        if progress_cb:
            progress_cb({"current_action": "discovering_volumes"})
        volume_specs, install_specs, warnings = _discover_raw_volumes(raw_path)
        for installation in db.query(OSInstallation).join(DiskVolume, OSInstallation.disk_volume_id == DiskVolume.id).filter(DiskVolume.disk_image_id == disk_image.id).all():
            db.delete(installation)
        for volume in db.query(DiskVolume).filter(DiskVolume.disk_image_id == disk_image.id).all():
            db.delete(volume)
        db.flush()
        persisted_volumes: list[DiskVolume] = []
        persisted_installs: list[OSInstallation] = []
        volume_by_index: dict[int, DiskVolume] = {}
        now = _now().replace(tzinfo=None)
        for spec in volume_specs[: settings.disk_image_max_partitions]:
            volume = DiskVolume(
                disk_image_id=disk_image.id,
                partition_index=int(spec["partition_index"]),
                offset_bytes=int(spec["offset_bytes"]),
                length_bytes=int(spec["length_bytes"]),
                partition_type=spec.get("partition_type"),
                filesystem_type=spec.get("filesystem_type"),
                label=spec.get("label"),
                uuid=spec.get("uuid"),
                encrypted=bool(spec.get("encrypted")),
                readable=bool(spec.get("readable")),
                status=str(spec.get("status") or "discovered"),
                warnings_json=list(spec.get("warnings") or []),
                error_json=dict(spec.get("error") or {}),
                metadata_json=dict(spec.get("metadata") or {}),
                created_at=now,
                updated_at=now,
            )
            db.add(volume)
            db.flush()
            persisted_volumes.append(volume)
            volume_by_index[volume.partition_index] = volume
        for spec in install_specs:
            volume = volume_by_index.get(int(spec["partition_index"]))
            if volume is None:
                continue
            install = OSInstallation(
                disk_volume_id=volume.id,
                platform=str(spec.get("platform") or EvidencePlatform.unknown.value),
                hostname=spec.get("hostname"),
                version=spec.get("version"),
                distro=spec.get("distro"),
                root_path=str(spec.get("root_path") or "/"),
                confidence=str(spec.get("confidence") or "medium"),
                detection_reasons=list(spec.get("detection_reasons") or []),
                metadata_json=dict(spec.get("metadata") or {}),
                created_at=now,
                updated_at=now,
            )
            db.add(install)
            db.flush()
            persisted_installs.append(install)
        db.flush()
        extracted_files: list[str] = []
        manifest_entries: list[dict[str, Any]] = []
        source_map: dict[str, dict[str, Any]] = {}
        image_reader = _PytskFileReader(raw_path)
        try:
            for volume in persisted_volumes:
                if not volume.readable:
                    continue
                try:
                    fs_info = pytsk3.FS_Info(image_reader, offset=int(volume.offset_bytes)) if volume.partition_index != 0 or volume.offset_bytes else pytsk3.FS_Info(image_reader)
                except Exception:
                    continue
                installs_for_volume = [install for install in persisted_installs if install.disk_volume_id == volume.id]
                if not installs_for_volume:
                    continue
                for install in installs_for_volume:
                    volume_files, volume_manifest, volume_map, volume_warnings = _materialize_volume_installation(
                        fs_info=fs_info,
                        install=install,
                        disk_image=disk_image,
                        volume=volume,
                        destination_root=extract_dir,
                    )
                    extracted_files.extend(volume_files)
                    manifest_entries.extend(volume_manifest)
                    source_map.update(volume_map)
                    if volume_warnings:
                        volume.warnings_json = list(dict.fromkeys([*(volume.warnings_json or []), *volume_warnings]))
        finally:
            image_reader.close()
    finally:
        if context is not None:
            adapter.cleanup(context)
        shutil.rmtree(workspace, ignore_errors=True)
    disk_image.status = "discovering_artifacts"
    disk_image.metadata_json = {
        **(disk_image.metadata_json or {}),
        "segments": [item.name for item in companions],
        "volumes": [
            {
                "id": volume.id,
                "partition_index": volume.partition_index,
                "offset_bytes": volume.offset_bytes,
                "length_bytes": volume.length_bytes,
                "partition_type": volume.partition_type,
                "filesystem_type": volume.filesystem_type,
                "label": volume.label,
                "uuid": volume.uuid,
                "encrypted": volume.encrypted,
                "readable": volume.readable,
                "status": volume.status,
                "warnings": list(volume.warnings_json or []),
                "error": dict(volume.error_json or {}),
            }
            for volume in persisted_volumes
        ],
        "installations": [
            {
                "id": install.id,
                "disk_volume_id": install.disk_volume_id,
                "platform": install.platform,
                "hostname": install.hostname,
                "version": install.version,
                "distro": install.distro,
                "root_path": install.root_path,
                "confidence": install.confidence,
                "detection_reasons": list(install.detection_reasons or []),
            }
            for install in persisted_installs
        ],
    }
    disk_image.tool_metadata = {
        **(disk_image.tool_metadata or {}),
        "operations": [
            *(disk_image.tool_metadata or {}).get("operations", []),
            {"step": "validate_segments", "result": validation},
            {"step": "expose_readonly", "result": context},
        ],
        "readiness": disk_image_readiness(),
    }
    disk_image.warnings_json = list(dict.fromkeys(warnings))
    disk_image.error_json = {}
    db.commit()
    return MaterializedDiskImage(
        extract_dir=extract_dir,
        extracted_files=extracted_files,
        manifest_entries=manifest_entries,
        source_map=source_map,
        disk_image=disk_image,
        volumes=persisted_volumes,
        installations=persisted_installs,
        warnings=warnings,
        errors=[],
    )


def inspect_disk_image_readonly(path: Path, *, workspace: Path) -> dict[str, Any]:
    """Read-only preview of a disk image: format, volumes, and OS installations.

    Mirrors the first half of materialize_disk_image_sources (detect -> validate
    -> inspect -> expose_readonly -> discover volumes) but never touches the
    database and never persists a DiskImage/DiskVolume/OSInstallation row. Used
    by the evidence preflight inspection so the wizard can preview a disk image
    before any processing job exists. Caller owns workspace and must remove it
    after use; this function always calls adapter.cleanup() on its own context.
    """
    companions = _ewf_companions(path)
    registry = get_image_format_registry()
    detected = registry.detect(path, companions)
    if not detected:
        return {"supported": False, "error": "unknown_format"}
    adapter = registry.get(str(detected.get("format") or ""))
    if adapter is None:
        return {"supported": False, "error": "unknown_format"}
    validation = adapter.validate_segments(path, companions)
    if not validation.get("valid", True):
        return {"supported": False, "format": adapter.key, "error": validation.get("error"), "validation": validation}
    inspect_metadata = adapter.inspect(path, companions)
    workspace.mkdir(parents=True, exist_ok=True)
    context: dict[str, Any] = {}
    try:
        context = adapter.expose_readonly(evidence_id="preflight", path=path, companions=companions, workspace=workspace)
        if not context.get("supported", True):
            return {"supported": False, "format": adapter.key, "error": context.get("error") or "missing_dependency", "context": context}
        raw_path = Path(str(context.get("exported_raw_path") or context.get("image_path") or path))
        volumes, installs, warnings = _discover_raw_volumes(raw_path)
        return {
            "supported": True,
            "format": adapter.key,
            "inspect_metadata": inspect_metadata,
            "volumes": volumes,
            "installations": installs,
            "warnings": warnings,
        }
    finally:
        if context:
            try:
                adapter.cleanup(context)
            except Exception:  # noqa: BLE001
                pass
        shutil.rmtree(workspace, ignore_errors=True)
