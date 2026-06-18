from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.services.memory.backend_readiness import get_memory_backend_overview


GIB = 1024 * 1024 * 1024
MIN_NEAR_LIMIT_FREE_BYTES = 12 * GIB
SAFETY_MARGIN_BYTES = 2 * GIB
MAX_SELECTED_SIZE_BYTES = 64 * GIB


def _available_bytes(path: Path) -> int:
    path.mkdir(parents=True, exist_ok=True)
    return int(shutil.disk_usage(path).free)


def _format_gib(value: int) -> str:
    if value % GIB == 0:
        return f"{value // GIB} GiB"
    return f"{value / GIB:.1f} GiB"


def _capacity_requirements(selected_size_bytes: int) -> tuple[int, int]:
    settings = get_settings()
    output_allowance = max(int(settings.memory_plugin_output_max_bytes or 0) * 5, 256 * 1024 * 1024)
    required = (2 * selected_size_bytes) + output_allowance + SAFETY_MARGIN_BYTES
    if selected_size_bytes >= int(settings.memory_upload_max_bytes or 0) * 0.9:
        required = max(required, MIN_NEAR_LIMIT_FREE_BYTES)
    return required, output_allowance


def memory_upload_capacity_for_size(selected_size_bytes: int) -> dict[str, int | bool]:
    settings = get_settings()
    if selected_size_bytes <= 0:
        raise ValueError("selected_size_bytes must be greater than zero")
    if selected_size_bytes > MAX_SELECTED_SIZE_BYTES:
        raise ValueError("selected_size_bytes is too large")
    staging_available = _available_bytes(settings.memory_upload_staging_path)
    canonical_available = _available_bytes(settings.backend_data_dir / "evidence")
    output_root = settings.memory_output_root or (settings.backend_data_dir / "evidence")
    output_available = _available_bytes(output_root)
    available = min(staging_available, canonical_available, output_available)
    required, output_allowance = _capacity_requirements(selected_size_bytes)
    return {
        "staging_available_bytes": staging_available,
        "canonical_storage_available_bytes": canonical_available,
        "memory_output_available_bytes": output_available,
        "available_capacity_bytes": available,
        "required_capacity_bytes": required,
        "output_allowance_bytes": output_allowance,
        "can_accept_selected_size": available >= required,
    }


def assert_memory_upload_capacity(selected_size_bytes: int) -> None:
    capacity = memory_upload_capacity_for_size(selected_size_bytes)
    if not capacity["can_accept_selected_size"]:
        raise RuntimeError("Insufficient storage capacity for memory image upload.")


def get_memory_upload_readiness(case_id: str, selected_size_bytes: int | None = None) -> dict[str, Any]:
    settings = get_settings()
    backend_overview = get_memory_backend_overview()
    volatility = next((item for item in backend_overview.get("backends", []) if item.get("backend") == "volatility3"), {})
    max_upload = int(settings.memory_upload_max_bytes or settings.memory_max_upload_size)
    try:
        staging_available = _available_bytes(settings.memory_upload_staging_path)
        canonical_available = _available_bytes(settings.backend_data_dir / "evidence")
        output_root = settings.memory_output_root or (settings.backend_data_dir / "evidence")
        output_available = _available_bytes(output_root)
        available = min(staging_available, canonical_available, output_available)
        output_allowance = max(int(settings.memory_plugin_output_max_bytes or 0) * 5, 256 * 1024 * 1024)
        recommended_max = max(0, (available - output_allowance - SAFETY_MARGIN_BYTES) // 2)
        selected_capacity = (
            memory_upload_capacity_for_size(selected_size_bytes)
            if selected_size_bytes is not None
            else {
                "required_capacity_bytes": 0,
                "can_accept_selected_size": bool(settings.memory_upload_enabled and recommended_max > 0),
            }
        )
    except Exception:  # noqa: BLE001
        return {
            "case_id": case_id,
            "upload_enabled": bool(settings.memory_upload_enabled),
            "max_upload_bytes": max_upload,
            "max_upload_display": _format_gib(max_upload),
            "allowed_extensions": sorted(settings.memory_upload_extensions),
            "staging_available_bytes": 0,
            "canonical_storage_available_bytes": 0,
            "memory_output_available_bytes": 0,
            "recommended_max_upload_bytes": 0,
            "required_capacity_bytes": 0,
            "can_accept_selected_size": False,
            "analysis_enabled": bool(settings.memory_analysis_enabled),
            "dedicated_worker_online": bool(volatility.get("dedicated_worker_online")),
            "backend_ready": bool(volatility.get("ready")),
            "message": "Memory upload capacity could not be verified safely.",
        }

    enabled = bool(settings.memory_upload_enabled)
    within_limit = selected_size_bytes is None or selected_size_bytes <= max_upload
    can_accept = bool(enabled and within_limit and selected_capacity["can_accept_selected_size"])
    if not enabled:
        message = "Memory image upload is disabled by server configuration."
    elif selected_size_bytes is not None and not within_limit:
        message = f"Selected file exceeds the configured memory upload limit of {_format_gib(max_upload)}."
    elif not can_accept:
        message = "Server storage capacity is below the recommended threshold for the selected memory image."
    elif not volatility.get("ready"):
        message = "Upload is available; memory analysis can be run later when the dedicated memory worker is ready."
    else:
        message = "Memory image upload is available and the dedicated memory worker is ready."

    return {
        "case_id": case_id,
        "upload_enabled": enabled,
        "max_upload_bytes": max_upload,
        "max_upload_display": _format_gib(max_upload),
        "allowed_extensions": sorted(settings.memory_upload_extensions),
        "staging_available_bytes": staging_available,
        "canonical_storage_available_bytes": canonical_available,
        "memory_output_available_bytes": output_available,
        "recommended_max_upload_bytes": min(max_upload, recommended_max),
        "required_capacity_bytes": int(selected_capacity["required_capacity_bytes"]),
        "can_accept_selected_size": can_accept,
        "analysis_enabled": bool(settings.memory_analysis_enabled),
        "dedicated_worker_online": bool(volatility.get("dedicated_worker_online")),
        "backend_ready": bool(volatility.get("ready")),
        "message": message,
    }
