from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.timing import timed_phase


settings = get_settings()


def _qemu_img_exists() -> bool:
    return shutil.which("qemu-img") is not None


def _read_header(path: Path, size: int = 4096) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError:
        return b""


def qemu_img_info(path: Path) -> dict[str, Any] | None:
    if not _qemu_img_exists():
        return None
    completed = subprocess.run(
        ["qemu-img", "info", "--output=json", str(path)],
        capture_output=True, text=True, shell=False, timeout=60,
    )
    if completed.returncode != 0:
        return None
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None


def _format_from_info(info: dict[str, Any] | None, path: Path) -> str | None:
    if info and info.get("format"):
        return str(info["format"]).lower()
    header = _read_header(path, 65536)
    if header:
        if b"KDMV" in header[:4096]:
            return "vmdk"
        if b"conectix" in header[:4096]:
            return "vhd"
        if header[:8] == b"vhdxfile":
            return "vhdx"
        if header[:4] == b"QFI\xfb":
            return "qcow2"
        if header[:4] == b"QFI\xfe":
            return "qcow"
        if b"<<< Oracle VM VirtualBox Disk Image >>>" in header[:4096]:
            return "vdi"
        if b"VMDK" in header[:8192]:
            return "vmdk"
    return None


def _format_size(info: dict[str, Any] | None) -> tuple[int, int, str]:
    physical = 0
    virtual = 0
    allocation = "unknown"
    if info:
        physical = int(info.get("actual-size") or 0)
        virtual = int(info.get("virtual-size") or 0)
        fmt_specific = info.get("format-specific", {}).get("data") or info.get("format-specific") or {}
        allocation = str(fmt_specific.get("allocation-type") or fmt_specific.get("create-type") or "unknown").lower()
    return physical, virtual, allocation


def qemu_img_check(path: Path) -> dict[str, Any]:
    if not _qemu_img_exists():
        return {"valid": False, "error": "missing_dependency", "reason": "qemu-img missing"}
    completed = subprocess.run(
        ["qemu-img", "check", str(path)],
        capture_output=True, text=True, shell=False, timeout=600,
    )
    valid = completed.returncode == 0
    lines = (completed.stdout + completed.stderr).splitlines()
    errors = [line for line in lines if "error" in line.lower() or "leaked" in line.lower()]
    warnings = [line for line in lines if "warning" in line.lower()]
    return {
        "valid": valid,
        "returncode": completed.returncode,
        "errors": errors[:20],
        "warnings": warnings[:20],
        "output_tail": "\n".join(lines[-20:]),
    }


def _check_space_before_convert(virtual_size: int, workspace_dir: Path) -> dict[str, Any]:
    workspace_dir.mkdir(parents=True, exist_ok=True)
    try:
        stat = os.statvfs(str(workspace_dir))
        free = stat.f_frsize * stat.f_bavail
    except OSError:
        free = 0
    estimated_needed = max(virtual_size, 256 * 1024 * 1024)
    reserve = max(getattr(settings, "disk_image_min_free_space_reserve", 0), 256 * 1024 * 1024)
    if free < estimated_needed + reserve:
        return {
            "sufficient": False,
            "free_bytes": free,
            "needed_bytes": estimated_needed,
            "reserve_bytes": reserve,
            "error": "insufficient_free_space",
        }
    return {"sufficient": True, "free_bytes": free, "needed_bytes": estimated_needed}


def _validate_resource_limits(
    *,
    virtual_size: int,
    physical_size: int,
    max_virtual: int | None = None,
    max_ratio: int | None = None,
) -> dict[str, Any]:
    max_v = max_virtual or getattr(settings, "disk_image_virtual_size_max_bytes", 1099511627776)
    max_r = max_ratio or getattr(settings, "disk_image_virtual_physical_ratio_max", 100)
    if virtual_size > max_v:
        return {"valid": False, "error": "virtual_size_limit_exceeded", "virtual_size": virtual_size, "limit": max_v}
    if physical_size > 10_485_760 and virtual_size > 0:
        ratio = virtual_size // max(physical_size, 1)
        if ratio > max_r:
            return {"valid": False, "error": "virtual_physical_ratio_exceeded", "ratio": ratio, "limit": max_r, "physical": physical_size, "virtual": virtual_size}
    return {"valid": True}


def qemu_img_convert_to_raw(
    *,
    input_path: Path,
    output_path: Path,
    evidence_id: str,
    timeout: int = 3600,
) -> dict[str, Any]:
    if not _qemu_img_exists():
        return {"supported": False, "error": "missing_dependency", "reason": "qemu-img missing"}
    command = ["qemu-img", "convert", "-O", "raw", str(input_path), str(output_path)]
    input_size = input_path.stat().st_size if input_path.exists() else 0
    with timed_phase("disk_image.qemu_img_convert_to_raw", input=input_path.name, input_size_bytes=input_size, timeout=timeout):
        completed = subprocess.run(command, capture_output=True, text=True, shell=False, timeout=timeout)
    return {
        "format": "raw",
        "supported": completed.returncode == 0,
        "exported_raw_path": str(output_path) if completed.returncode == 0 else None,
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-2000:],
        "stderr": completed.stderr[-2000:],
        "access_strategy": "qemu_img_convert_to_temporary_raw_readonly",
        "tool": "qemu-img",
        "tool_version": _tool_version("qemu-img") if _qemu_img_exists() else None,
    }


def _tool_version(name: str) -> str | None:
    try:
        completed = subprocess.run([name, "--version"], capture_output=True, text=True, shell=False, timeout=15)
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    text = (completed.stdout or completed.stderr or "").strip().splitlines()
    return text[0] if text else None


def _tool_functional(name: str) -> bool:
    """Check that a tool is available AND can execute a basic command."""
    if not shutil.which(name):
        return False
    try:
        completed = subprocess.run([name, "--version"], capture_output=True, text=True, shell=False, timeout=10)
        return completed.returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return False


def _parse_vmdk_descriptor(descriptor_path: Path) -> dict[str, Any]:
    # Single-file VMDKs (monolithicSparse, streamOptimized) embed a small
    # text descriptor at the start of the same file that also holds the
    # (potentially multi-GB) binary sparse extent data, so this must never
    # read the whole file -- a real descriptor is always a few KB at most.
    header = _read_header(descriptor_path, 1024 * 1024)
    if not header:
        return {"valid": False, "error": "cannot_read_descriptor"}
    content = header.decode("utf-8", errors="replace")
    lines = content.splitlines()
    extents = []
    errors = []
    for line in lines:
        parts = line.strip().split()
        if not parts or parts[0].upper() not in {"RW", "RDONLY", "NOACCESS"}:
            continue
        if len(parts) < 3:
            continue
        extent_type = parts[2].upper()
        if extent_type in {"ZERO"}:
            continue
        if len(parts) < 4:
            continue
        raw_path = parts[3].strip('"').strip("'")
        if not raw_path:
            continue
        if raw_path.startswith("/"):
            errors.append(f"absolute_extent_path_rejected:{raw_path}")
            continue
        if ".." in raw_path.split("/"):
            errors.append(f"path_traversal_rejected:{raw_path}")
            continue
        extents.append(raw_path)
    return {"valid": len(errors) == 0, "extents": extents, "errors": errors}


def _validate_vmdk_extents(
    descriptor_dir: Path,
    extents: list[str],
    *,
    authorized_paths: set[str] | None = None,
) -> dict[str, Any]:
    missing = []
    external = []
    unauthorized = []
    valid = True
    for extent_path in extents:
        full = descriptor_dir / extent_path
        resolved = full.resolve()
        if resolved != full.absolute():
            external.append(extent_path)
            valid = False
            continue
        if authorized_paths is not None and str(resolved) not in authorized_paths:
            unauthorized.append(extent_path)
            valid = False
            continue
        if not resolved.exists() or not resolved.is_file():
            missing.append(extent_path)
            valid = False
    return {"valid": valid, "missing": missing, "external": external, "unauthorized": unauthorized}


def _validate_backing_file(
    info: dict[str, Any] | None,
    parent_dir: Path,
    *,
    authorized_paths: set[str] | None = None,
) -> dict[str, Any]:
    if not info:
        return {"valid": True, "has_backing": False}
    backing = info.get("backing-filename") or info.get("full-backing-filename") or info.get("backing file")
    if not backing:
        return {"valid": True, "has_backing": False}
    backing_path = Path(backing)
    if backing_path.is_absolute():
        return {"valid": False, "error": "external_parent_rejected", "backing_file": str(backing_path)}
    candidate = parent_dir / backing_path
    resolved = candidate.resolve()
    if resolved != candidate.absolute():
        return {"valid": False, "error": "external_parent_rejected", "backing_file": str(backing_path)}
    if authorized_paths is not None and str(resolved) not in authorized_paths:
        return {"valid": False, "error": "parent_not_in_authorized_set", "backing_file": str(backing_path)}
    if not resolved.exists() or not resolved.is_file():
        return {"valid": True, "has_backing": True, "backing_file": str(backing_path), "present": False}
    return {"valid": True, "has_backing": True, "backing_file": str(backing_path), "present": True}


def _build_authorized_set(upload_dir: Path, companions: list[Path] | None = None) -> set[str]:
    authorized = {str(p.resolve()) for p in [upload_dir, *(companions or [])] if p.exists()}
    for p in [upload_dir, *(companions or [])]:
        try:
            for candidate in p.parent.glob("*"):
                if candidate.is_file():
                    authorized.add(str(candidate.resolve()))
        except OSError:
            pass
    return authorized
