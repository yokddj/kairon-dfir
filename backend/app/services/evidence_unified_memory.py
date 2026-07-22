"""Unified chunk-index upload path for the Evidence Wizard's memory_dump
intake (feature-flagged: ``settings.unified_upload_evidence_memory_dump``).

Why this exists: the wizard's own upload session model
(``app.services.evidence_upload_session``) is a single-shot, sequential
byte-offset transfer. Memory Overview's model
(``app.services.memory.upload_sessions``) is a mature chunk-index,
parallel, resumable transfer with per-chunk locks and a received-chunk
bitmap. The wizard's memory_dump branch previously only bridged the two
AFTER a full sequential transfer completed (see
``evidence_upload_session.promote_upload_session``'s
``create_memory_upload_session_from_staged_file`` call) -- it never used
the chunk-index protocol for the transfer itself.

This module creates the real chunk-index ``MemoryUpload`` session up
front, at Wizard upload-init time, and keeps the Wizard's own
``EvidenceUploadSession`` row (which Activity Center and the rest of the
Wizard API already key off of) as a thin, continuously-synced projection
of it. The frontend drives the actual transfer against the same
``/memory/uploads/...`` endpoints and the same ``runResumableUpload()``
client engine Memory Overview uses, using the ``memory_upload_id``
returned at init.

Ownership is fixed at creation: a session created here always carries
``metadata_json["backend"] == "unified"`` and a ``memory_upload_id`` that
never changes. Nothing in this module ever routes an unmodified legacy
session through the unified path, or vice versa.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utc_now
from app.models.case import Case
from app.models.evidence import EvidenceType
from app.models.evidence_upload_session import EvidenceUploadSession, EvidenceUploadSessionStatus
from app.models.memory import MemoryUpload
from app.services import evidence_memory_workflow  # noqa: F401 -- registers the "evidence_memory_dump" workflow handler on import
from app.services.evidence_operations import sync_upload_operation
from app.services.evidence_upload_session import UploadSessionError
from app.services.host_resolution import resolve_host
from app.services.memory.upload_lifecycle import get_memory_upload
from app.services.memory.upload_sessions import (
    MemoryUploadSessionError,
    cancel_memory_upload_session,
    create_memory_upload_session,
)

UNIFIED_BACKEND_MARKER = "unified"
UNIFIED_MEMORY_DUMP_KIND = "memory_dump"

# Coarse projection of MemoryUpload's granular status onto the Wizard's
# existing EvidenceUploadSessionStatus enum, so Activity Center's
# state-machine (app.services.evidence_operations.ALLOWED_OPERATION_TRANSITIONS)
# keeps working unmodified. The full-fidelity status is preserved
# separately in metadata_json["unified_status"] for detail display.
_UNIFIED_STATUS_TO_SESSION_STATUS: dict[str, str] = {
    "validating": EvidenceUploadSessionStatus.created.value,
    "created": EvidenceUploadSessionStatus.created.value,
    "uploading": EvidenceUploadSessionStatus.uploading.value,
    "verifying": EvidenceUploadSessionStatus.preflight_running.value,
    "finalizing": EvidenceUploadSessionStatus.preflight_running.value,
    "completed": EvidenceUploadSessionStatus.promoted.value,
    "cancelled": EvidenceUploadSessionStatus.cancelled.value,
    "expired": EvidenceUploadSessionStatus.expired.value,
    "failed": EvidenceUploadSessionStatus.failed.value,
    "inconsistent": EvidenceUploadSessionStatus.failed.value,
    "stale": EvidenceUploadSessionStatus.interrupted.value,
}


@dataclass
class UnifiedUploadInfo:
    memory_upload_id: str
    chunk_size_bytes: int
    total_chunks: int
    default_concurrency: int
    max_concurrency: int


def is_unified_memory_dump_session(session: EvidenceUploadSession) -> bool:
    metadata = session.metadata_json or {}
    return metadata.get("backend") == UNIFIED_BACKEND_MARKER and metadata.get("unified_kind") == UNIFIED_MEMORY_DUMP_KIND


def unified_upload_info(session: EvidenceUploadSession, db: Session) -> UnifiedUploadInfo | None:
    memory_upload_id = (session.metadata_json or {}).get("memory_upload_id")
    if not memory_upload_id:
        return None
    item = get_memory_upload(db, session.case_id, memory_upload_id)
    if item is None:
        return None
    metadata = dict(item.metadata_json or {})
    settings = get_settings()
    return UnifiedUploadInfo(
        memory_upload_id=item.id,
        chunk_size_bytes=int(item.chunk_size_bytes or 0),
        total_chunks=int(item.total_chunks or 0),
        default_concurrency=int(metadata.get("default_concurrency") or settings.memory_upload_default_concurrency or 1),
        max_concurrency=int(metadata.get("max_concurrency") or settings.memory_upload_max_concurrency or 1),
    )


def create_unified_memory_dump_session(
    db: Session,
    case_id: str,
    *,
    filename: str,
    expected_size_bytes: int,
    declared_platform: str | None,
    client_sha256: str | None,
    host_id: str | None,
    provided_host: str | None,
    memory_authorization_acknowledged: bool,
    notes: str | None,
    current_user: Any,
) -> tuple[EvidenceUploadSession, UnifiedUploadInfo]:
    if not db.get(Case, case_id):
        raise UploadSessionError("case_not_found", "Case not found")

    from app.api.routes_evidence import _current_user_id  # actor-id helper only, not a route function

    host_resolution = resolve_host(
        db,
        case_id=case_id,
        evidence_type=EvidenceType.memory_dump,
        host_id=host_id,
        provided_host=provided_host,
        allow_create=True,
    )
    resolved_host_label = (host_resolution.display_name or provided_host or "").strip() or "Unknown host"

    extra_metadata: dict[str, Any] = {
        "workflow": "evidence_memory_dump",
        "provided_platform": declared_platform,
        "uploaded_by_user_id": _current_user_id(current_user),
        "wizard_notes": (notes or "").strip() or None,
        "wizard_host_id": host_resolution.host_id,
        "source_upload_session_kind": "unified_evidence_wizard",
    }
    # MemoryUploadSessionError intentionally propagates unwrapped -- the
    # route layer (routes_evidence_preflight.init_resumable_evidence_upload)
    # catches it separately so codes like MEMORY_UPLOAD_ACTIVE_SESSION_EXISTS
    # and MEMORY_UPLOAD_TOO_LARGE keep their correct 409/413 status codes
    # instead of collapsing to UploadSessionError's generic 400 fallback.
    memory_upload = create_memory_upload_session(
        db,
        case_id=case_id,
        filename=filename,
        expected_size_bytes=expected_size_bytes,
        provided_host=resolved_host_label,
        authorization_acknowledged=memory_authorization_acknowledged,
        expected_sha256=client_sha256,
        upload_mode="resumable",
        extra_metadata=extra_metadata,
    )

    settings = get_settings()
    session = EvidenceUploadSession(
        id=str(uuid4()),
        case_id=case_id,
        status=EvidenceUploadSessionStatus.created.value,
        original_filename=Path(filename or "upload.bin").name,
        staged_path=f"unified-memory-upload:{memory_upload.id}",
        is_folder=False,
        is_server_path=False,
        size_bytes=0,
        expected_size_bytes=expected_size_bytes,
        bytes_received=0,
        client_sha256=client_sha256,
        declared_platform=declared_platform,
        expires_at=utc_now() + timedelta(seconds=max(60, int(settings.evidence_upload_session_ttl_seconds))),
        last_activity_at=utc_now(),
        metadata_json={
            "backend": UNIFIED_BACKEND_MARKER,
            "unified_kind": UNIFIED_MEMORY_DUMP_KIND,
            "memory_upload_id": memory_upload.id,
            "category": "memory_dump",
            "current_stage": "upload",
            "upload_mode": "resumable",
        },
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    sync_upload_operation(db, session)

    info = unified_upload_info(session, db)
    assert info is not None
    return session, info


def sync_unified_session_from_memory_upload(db: Session, session: EvidenceUploadSession) -> EvidenceUploadSession:
    memory_upload_id = (session.metadata_json or {}).get("memory_upload_id")
    if not memory_upload_id:
        return session
    item = get_memory_upload(db, session.case_id, memory_upload_id)
    if item is None:
        return session

    metadata = dict(session.metadata_json or {})
    metadata["unified_status"] = item.status
    metadata["current_stage"] = item.status
    session.metadata_json = metadata
    session.status = _UNIFIED_STATUS_TO_SESSION_STATUS.get(item.status, EvidenceUploadSessionStatus.uploading.value)
    session.bytes_received = int(item.bytes_received or 0)
    session.size_bytes = int(item.bytes_received or 0)
    if item.expected_bytes:
        session.expected_size_bytes = int(item.expected_bytes)
    session.sha256 = item.sha256 or session.sha256
    session.failure_message = item.failure_message or (session.failure_message if item.status not in {"completed"} else None)
    session.last_activity_at = utc_now()
    if item.status == "completed" and item.evidence_id:
        session.promoted_evidence_id = item.evidence_id
    db.add(session)
    db.commit()
    db.refresh(session)
    sync_upload_operation(db, session)
    return session


def cancel_unified_memory_dump_session(db: Session, session: EvidenceUploadSession) -> EvidenceUploadSession:
    memory_upload_id = (session.metadata_json or {}).get("memory_upload_id")
    if memory_upload_id:
        try:
            cancel_memory_upload_session(db, case_id=session.case_id, upload_id=memory_upload_id, reason="Cancelled from Evidence Wizard")
        except MemoryUploadSessionError:
            pass
    session.status = EvidenceUploadSessionStatus.cancelled.value
    db.add(session)
    db.commit()
    db.refresh(session)
    sync_upload_operation(db, session)
    return session
