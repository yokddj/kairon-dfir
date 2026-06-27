from __future__ import annotations

from typing import Any

from app.core.database import SessionLocal

from app.core.config import get_settings
from app.services.memory.backend_readiness import get_memory_backend_overview
from app.services.memory.upload_capacity import GIB, MAX_SELECTED_SIZE_BYTES
from app.services.memory.upload_sessions import _capacity_snapshot, _case_memory_usage_bytes


def _format_gib(value: int) -> str:
    if value % GIB == 0:
        return f"{value // GIB} GiB"
    return f"{value / GIB:.1f} GiB"


def memory_upload_capacity_for_size(selected_size_bytes: int) -> dict[str, Any]:
    db = SessionLocal()
    try:
        return _capacity_snapshot(db, expected_bytes=selected_size_bytes)
    finally:
        db.close()


def assert_memory_upload_capacity(selected_size_bytes: int) -> None:
    capacity = memory_upload_capacity_for_size(selected_size_bytes)
    if not bool(capacity["can_accept_selected_size"]):
        raise RuntimeError("Insufficient capacity")


def get_memory_upload_readiness(case_id: str, selected_size_bytes: int | None = None) -> dict[str, Any]:
    settings = get_settings()
    backend_overview = get_memory_backend_overview()
    volatility = next((item for item in backend_overview.get("backends", []) if item.get("backend") == "volatility3"), {})
    max_upload = int(settings.memory_upload_max_bytes or settings.memory_max_upload_size)
    case_quota = int(getattr(settings, "memory_upload_case_quota_bytes", 0) or (max_upload * 10))
    db = SessionLocal()
    try:
        probe = _capacity_snapshot(db, expected_bytes=1)
        staging_available = int(probe["staging_available_bytes"])
        canonical_available = int(probe["canonical_storage_available_bytes"])
        output_available = int(probe["memory_output_available_bytes"])
        recommended_max = max_upload
        case_usage = _case_memory_usage_bytes(db, case_id)
        case_remaining = max(0, case_quota - case_usage)
        selected_capacity = (
            memory_upload_capacity_for_size(selected_size_bytes)
            if selected_size_bytes is not None
            else {
                "required_capacity_bytes": 0,
                "can_accept_selected_size": bool(settings.memory_upload_enabled and recommended_max > 0),
                "finalization_strategy": probe["finalization_strategy"],
            }
        )
    except Exception:  # noqa: BLE001
        return {
            "case_id": case_id,
            "upload_enabled": bool(settings.memory_upload_enabled),
            "max_upload_bytes": max_upload,
            "max_upload_display": _format_gib(max_upload),
            "recommended_chunk_size_bytes": int(getattr(settings, "memory_upload_chunk_size_bytes", 0) or 0),
            "resumable": True,
            "max_parallel_chunks": int(getattr(settings, "memory_upload_max_parallel_chunks", 1) or 1),
            "case_quota_bytes": case_quota,
            "case_quota_remaining_bytes": 0,
            "allowed_extensions": sorted(settings.memory_upload_extensions),
            "staging_available_bytes": 0,
            "canonical_storage_available_bytes": 0,
            "memory_output_available_bytes": 0,
            "recommended_max_upload_bytes": 0,
            "required_capacity_bytes": 0,
            "can_accept_selected_size": False,
            "finalization_strategy": None,
            "analysis_enabled": bool(settings.memory_analysis_enabled),
            "dedicated_worker_online": bool(volatility.get("dedicated_worker_online")),
            "backend_ready": bool(volatility.get("ready")),
            "message": "Memory upload capacity could not be verified safely.",
        }
    finally:
        db.close()

    enabled = bool(settings.memory_upload_enabled)
    within_limit = selected_size_bytes is None or selected_size_bytes <= max_upload
    within_quota = selected_size_bytes is None or selected_size_bytes <= case_remaining
    can_accept = bool(enabled and within_limit and within_quota and selected_capacity["can_accept_selected_size"])
    if not enabled:
        message = "Memory image upload is disabled by server configuration."
    elif selected_size_bytes is not None and not within_limit:
        message = f"Selected file exceeds the configured memory upload limit of {_format_gib(max_upload)}."
    elif selected_size_bytes is not None and not within_quota:
        message = "The selected memory image exceeds the remaining case upload quota."
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
        "recommended_chunk_size_bytes": int(getattr(settings, "memory_upload_chunk_size_bytes", 0) or 0),
        "resumable": True,
        "max_parallel_chunks": int(getattr(settings, "memory_upload_max_parallel_chunks", 1) or 1),
        "case_quota_bytes": case_quota,
        "case_quota_remaining_bytes": case_remaining,
        "allowed_extensions": sorted(settings.memory_upload_extensions),
        "staging_available_bytes": staging_available,
        "canonical_storage_available_bytes": canonical_available,
        "memory_output_available_bytes": output_available,
        "recommended_max_upload_bytes": min(max_upload, recommended_max),
        "required_capacity_bytes": int(selected_capacity["required_capacity_bytes"]),
        "can_accept_selected_size": can_accept,
        "finalization_strategy": selected_capacity.get("finalization_strategy") if selected_size_bytes is not None else str(probe["finalization_strategy"]),
        "analysis_enabled": bool(settings.memory_analysis_enabled),
        "dedicated_worker_online": bool(volatility.get("dedicated_worker_online")),
        "backend_ready": bool(volatility.get("ready")),
        "message": message,
    }
