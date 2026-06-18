from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from app.core.config import get_settings


DEFAULT_SCAN_LIMIT = 5000
settings = get_settings()


def _allowed_roots() -> list[Path]:
    return [root.resolve() for root in settings.allowed_evidence_roots]


def storage_capabilities() -> dict:
    allowed_roots = [str(root) for root in _allowed_roots()]
    recommended_labels = {
        "/mnt/evidence": "Recommended mount point for large evidence",
        "/data/evidence": "Alternative data volume",
        "/cases": "Case storage mount",
    }
    return {
        "allow_host_path_import": settings.allow_host_path_import,
        "allowed_roots": allowed_roots,
        "max_upload_size": settings.backend_max_upload_size,
        "memory_upload_enabled": settings.memory_upload_enabled,
        "memory_upload_max_bytes": settings.memory_upload_max_bytes,
        "memory_upload_allowed_extensions": sorted(settings.memory_upload_extensions),
        "supports_mounted_path": settings.allow_host_path_import,
        "can_edit_deployment_settings": False,
        "restart_enabled": False,
        "deployment_setting_scope": "backend+worker restart",
        "restart_commands": [
            "docker compose up -d --build backend worker",
        ],
        "enable_instructions": {
            "env": {
                "DFIR_ALLOW_HOST_PATH_IMPORT": "true",
                "DFIR_ALLOWED_EVIDENCE_ROOTS": ",".join(allowed_roots),
            },
            "commands": [
                "docker compose up -d --build backend worker",
            ],
        },
        "allowed_root_details": [
            {
                "path": root,
                "label": recommended_labels.get(root, "Configured allowed evidence root"),
                "example_path": f"{root.rstrip('/')}/case001",
            }
            for root in allowed_roots
        ],
    }


WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
WINDOWS_UNC_RE = re.compile(r"^\\\\[^\\]+\\[^\\]+")


def _classify_path_style(raw: str, allowed_roots: list[str]) -> tuple[str, bool]:
    trimmed = raw.strip()
    normalized = trimmed.replace("\\", "/")
    if not trimmed:
        return "unknown", False
    if WINDOWS_UNC_RE.match(trimmed):
        return "windows_unc", True
    if WINDOWS_DRIVE_RE.match(trimmed):
        return "windows", True
    if trimmed.startswith("/Users/"):
        return "macos", True
    if trimmed.startswith("/home/"):
        return "linux_home", True
    if trimmed.startswith("/"):
        for root in allowed_roots:
            if normalized == root or normalized.startswith(f"{root}/"):
                return "server_absolute", False
        return "server_absolute", False
    if trimmed.startswith("~") or not Path(trimmed).is_absolute():
        return "relative", False
    return "unknown", False


def _path_guidance(*, path_style: str, looks_like_client_path: bool, within_allowed_root: bool, host_path_enabled: bool, allowed_roots: list[str], exists: bool | None = None) -> tuple[str | None, str | None]:
    allowed_roots_text = ", ".join(allowed_roots) if allowed_roots else "configured server-mounted paths"
    if not host_path_enabled:
        return (
            "enable_host_path_import",
            "Server-mounted path import is disabled. Enable DFIR_ALLOW_HOST_PATH_IMPORT and configure DFIR_ALLOWED_EVIDENCE_ROOTS.",
        )
    if path_style == "windows":
        return (
            "upload_file",
            f"This looks like a Windows path from your local computer. The backend cannot access it directly. Use Upload file, or mount/share this folder on the server under an allowed root such as {allowed_roots_text}.",
        )
    if path_style == "windows_unc":
        return (
            "mount_folder",
            f"This looks like a Windows network share path. Mount or share it on the server under an allowed root such as {allowed_roots_text}, then register that server-mounted path.",
        )
    if path_style == "macos":
        return (
            "upload_file",
            f"This looks like a macOS path from your local computer. The backend cannot access it directly. Use Upload file, or mount/share it on the server under {allowed_roots_text}.",
        )
    if path_style == "linux_home" and not within_allowed_root:
        return (
            "use_allowed_root",
            f"This path is outside the allowed evidence roots. Move or mount it under one of: {allowed_roots_text}.",
        )
    if path_style == "relative":
        return (
            "use_allowed_root",
            "Use an absolute server-mounted path under an allowed evidence root.",
        )
    if not within_allowed_root:
        return (
            "use_allowed_root",
            f"This path is outside the allowed evidence roots. Move or mount it under one of: {allowed_roots_text}.",
        )
    if exists is False:
        return (
            "use_allowed_root",
            "Path is under an allowed root but does not exist.",
        )
    if looks_like_client_path:
        return (
            "mount_folder",
            f"This looks like a path from your local computer. The server cannot access it unless it is shared or mounted under an allowed root such as {allowed_roots_text}.",
        )
    return (None, None)


def _resolved_allowed_root(path: Path) -> str | None:
    target = path.resolve(strict=True)
    for root in _allowed_roots():
        try:
            if os.path.commonpath([str(root), str(target)]) == str(root):
                return str(root)
        except ValueError:
            continue
    return None


def _supplied_allowed_root(path: Path) -> str | None:
    raw_target = str(path)
    for root in _allowed_roots():
        try:
            if os.path.commonpath([str(root), raw_target]) == str(root):
                return str(root)
        except ValueError:
            continue
    return None


def _path_stats(path: Path, *, scan_limit: int = DEFAULT_SCAN_LIMIT) -> tuple[int | None, int | None, list[str]]:
    warnings: list[str] = []
    if path.is_file():
        return path.stat().st_size, None, warnings
    file_count = 0
    total_size = 0
    for candidate in path.rglob("*"):
        if not candidate.is_file():
            continue
        file_count += 1
        if file_count <= scan_limit:
            try:
                total_size += candidate.stat().st_size
            except OSError:
                warnings.append("stat_failed")
        if file_count == scan_limit:
            warnings.append("large_directory_scan_limited")
    return None, file_count, list(dict.fromkeys(warnings))


def fingerprint_external_path(path: Path) -> str:
    stat = path.stat()
    digest = hashlib.sha256()
    digest.update(f"external:{path.resolve()}:{stat.st_size}:{int(stat.st_mtime)}".encode("utf-8", "ignore"))
    return digest.hexdigest()


def validate_external_path(path_value: str, *, scan_limit: int = DEFAULT_SCAN_LIMIT) -> dict:
    allowed_roots = [str(root) for root in _allowed_roots()]
    response = {
        "valid": False,
        "exists": False,
        "readable": False,
        "is_directory": False,
        "is_file": False,
        "within_allowed_root": False,
        "allowed_roots": allowed_roots,
        "looks_like_client_path": False,
        "path_style": "unknown",
        "suggested_action": None,
        "message": None,
        "resolved_path": None,
        "size_bytes": None,
        "file_count": None,
        "warnings": [],
        "error": None,
        "path_validation": {
            "exists": False,
            "readable": False,
            "within_allowed_root": False,
            "is_symlink": False,
            "resolved_path": None,
            "warnings": [],
        },
    }
    if not settings.allow_host_path_import:
        response["error"] = "host_path_import_disabled"
        response["suggested_action"], response["message"] = _path_guidance(
            path_style="unknown",
            looks_like_client_path=False,
            within_allowed_root=False,
            host_path_enabled=False,
            allowed_roots=allowed_roots,
        )
        return response

    raw = str(path_value or "").strip()
    if not raw:
        response["error"] = "path_not_found"
        response["suggested_action"], response["message"] = _path_guidance(
            path_style="unknown",
            looks_like_client_path=False,
            within_allowed_root=False,
            host_path_enabled=True,
            allowed_roots=allowed_roots,
        )
        return response

    path_style, looks_like_client_path = _classify_path_style(raw, allowed_roots)
    response["path_style"] = path_style
    response["looks_like_client_path"] = looks_like_client_path

    supplied = Path(raw)
    supplied_allowed_root = _supplied_allowed_root(supplied)
    if supplied_allowed_root:
        response["within_allowed_root"] = True
        response["path_validation"]["within_allowed_root"] = True
    try:
        resolved = supplied.resolve(strict=True)
    except FileNotFoundError:
        response["error"] = "path_not_found"
        response["suggested_action"], response["message"] = _path_guidance(
            path_style=path_style,
            looks_like_client_path=looks_like_client_path,
            within_allowed_root=bool(supplied_allowed_root),
            host_path_enabled=True,
            allowed_roots=allowed_roots,
            exists=False,
        )
        return response

    response["exists"] = True
    response["resolved_path"] = str(resolved)
    response["path_validation"]["exists"] = True
    response["path_validation"]["resolved_path"] = str(resolved)
    response["path_validation"]["is_symlink"] = supplied.is_symlink()

    allowed_root = _resolved_allowed_root(supplied)
    if not allowed_root:
        response["error"] = "symlink_escape" if supplied.is_symlink() else "path_outside_allowed_roots"
        response["suggested_action"], response["message"] = _path_guidance(
            path_style=path_style,
            looks_like_client_path=looks_like_client_path,
            within_allowed_root=False,
            host_path_enabled=True,
            allowed_roots=allowed_roots,
        )
        return response

    response["within_allowed_root"] = True
    response["path_validation"]["within_allowed_root"] = True

    if not (resolved.is_file() or resolved.is_dir()):
        response["error"] = "unsupported_type"
        response["suggested_action"], response["message"] = _path_guidance(
            path_style=path_style,
            looks_like_client_path=looks_like_client_path,
            within_allowed_root=True,
            host_path_enabled=True,
            allowed_roots=allowed_roots,
        )
        return response

    response["is_file"] = resolved.is_file()
    response["is_directory"] = resolved.is_dir()

    readable = os.access(resolved, os.R_OK)
    if readable and resolved.is_dir():
        try:
            next(resolved.iterdir(), None)
        except PermissionError:
            readable = False
    response["readable"] = readable
    response["path_validation"]["readable"] = readable
    if not readable:
        response["error"] = "path_not_readable"
        response["suggested_action"], response["message"] = _path_guidance(
            path_style=path_style,
            looks_like_client_path=looks_like_client_path,
            within_allowed_root=True,
            host_path_enabled=True,
            allowed_roots=allowed_roots,
        )
        return response

    size_bytes, file_count, warnings = _path_stats(resolved, scan_limit=scan_limit)
    response["size_bytes"] = size_bytes
    response["file_count"] = file_count
    response["warnings"] = warnings
    response["path_validation"]["warnings"] = warnings
    response["valid"] = True
    response["allowed_root"] = allowed_root
    response["suggested_action"] = None
    response["message"] = "Path is valid and readable. It can be registered without copying."
    return response
