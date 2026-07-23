"""Unified chunk-index upload path for the Evidence Wizard, shared by every
evidence category migrated onto it (memory_dump first, disk_image next --
see app.services.memory.upload_sessions.ChunkedUploadKindPolicy for how a
category plugs in).

Why this exists: the wizard's own upload session model
(``app.services.evidence_upload_session``) is a single-shot, sequential
byte-offset transfer. Memory Overview's model
(``app.services.memory.upload_sessions``) is a mature chunk-index,
parallel, resumable transfer with per-chunk locks and a received-chunk
bitmap. Before the memory_dump migration, the Wizard's memory_dump branch
only bridged the two AFTER a full sequential transfer completed -- it
never used the chunk-index protocol for the transfer itself.

This module creates the real chunk-index ``MemoryUpload`` session (the
table name is a legacy artifact -- functionally it is now a generic
chunked-upload-session row, see the roadmap note in
``app.services.memory.upload_lifecycle.create_memory_upload``) up front,
at Wizard upload-init time, and keeps the Wizard's own
``EvidenceUploadSession`` row (which Activity Center and the rest of the
Wizard API already key off of) as a thin, continuously-synced projection
of it. The frontend drives the actual transfer against the same
``/memory/uploads/...`` endpoints and the same ``runResumableUpload()``
client engine Memory Overview uses, using the ``memory_upload_id``
returned at init.

Ownership is fixed at creation: a session created here always carries
``metadata_json["backend"] == "unified"`` and a ``memory_upload_id`` that
never changes. Nothing in this module ever routes an unmodified legacy
session through the unified path, or vice versa. This holds regardless of
which ``kind`` (evidence category) the session was created for.
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
from app.services import evidence_archive_workflow  # noqa: F401 -- registers the "archive" workflow handler on import
from app.services import evidence_disk_image_workflow  # noqa: F401 -- registers the "disk_image" workflow handler on import
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


@dataclass(frozen=True)
class UnifiedUploadKindConfig:
    """Registry entry for a category migrated onto the unified backend.

    Adding a category here (and a matching ChunkedUploadKindPolicy in
    app.services.memory.upload_sessions) is the whole integration point --
    routes_evidence_preflight.init_resumable_evidence_upload dispatches
    off this table instead of an if/else per category."""

    workflow: str
    # A real EvidenceType for categories that always produce that type
    # (memory_dump, disk_image); a plain string host-policy key for
    # categories whose real Evidence.evidence_type can only be determined
    # from content after upload (archive -- see host_resolution.EVIDENCE_HOST_POLICIES["generic_archive"]).
    # Either way this field drives host-resolution policy ONLY, at session
    # creation, before the real type is known -- it is never written to the
    # Evidence row itself.
    evidence_type: "EvidenceType | str"
    is_enabled: Any  # Callable[[Settings], bool]
    # memory_dump canonicalizes to a fixed "memory-image{ext}" name (its
    # original behavior, unchanged); disk_image and anything else where the
    # original filename matters for downstream tooling (format/companion
    # detection scans the canonical directory by filename pattern) needs it
    # preserved instead -- see app.services.memory.upload_lifecycle.create_memory_upload.
    preserve_original_filename: bool = False


def _memory_dump_enabled(settings: Any) -> bool:
    return bool(settings.unified_upload_evidence_memory_dump)


def _disk_image_enabled(settings: Any) -> bool:
    return bool(settings.unified_upload_evidence_disk_image)


def _archive_enabled(settings: Any) -> bool:
    return bool(settings.unified_upload_evidence_archive)


UNIFIED_UPLOAD_KINDS: dict[str, UnifiedUploadKindConfig] = {
    "memory_dump": UnifiedUploadKindConfig(workflow="evidence_memory_dump", evidence_type=EvidenceType.memory_dump, is_enabled=_memory_dump_enabled),
    "disk_image": UnifiedUploadKindConfig(workflow="disk_image", evidence_type=EvidenceType.disk_image, is_enabled=_disk_image_enabled, preserve_original_filename=True),
    # "generic_archive" is a host-policy key (host_resolution.EVIDENCE_HOST_POLICIES),
    # not an EvidenceType -- the real Evidence.evidence_type for an archive
    # (velociraptor_zip vs. a generic detected type) is decided by
    # upload_evidence()'s content-based classification post-upload, exactly
    # as it is today for this same category on the legacy path.
    "archive": UnifiedUploadKindConfig(workflow="archive", evidence_type="generic_archive", is_enabled=_archive_enabled, preserve_original_filename=True),
}

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


def is_unified_session(session: EvidenceUploadSession, *, kind: str | None = None) -> bool:
    """True if this session uses the unified chunk-index backend.

    Pass ``kind`` (e.g. "memory_dump", "disk_image") to check for a
    specific category; omit it to match any unified session regardless of
    category (used by discovery/reconciliation, which are category-agnostic
    by design).
    """
    metadata = session.metadata_json or {}
    if metadata.get("backend") != UNIFIED_BACKEND_MARKER:
        return False
    return kind is None or metadata.get("unified_kind") == kind


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


@dataclass
class UnifiedResumeInfo:
    memory_upload_id: str
    chunk_size_bytes: int
    total_chunks: int
    received_chunks: list[int]
    missing_chunks: list[int]
    default_concurrency: int
    max_concurrency: int
    expected_sha256: str | None
    # A previously-received chunk's recorded (index, size, sha256), so the
    # frontend can re-slice the exact same byte range out of a re-selected
    # File and hash it client-side before resuming -- proving byte-identity
    # for at least one already-uploaded region without hashing the whole
    # multi-GB file. Chosen deterministically (lowest received index).
    # Server-side per-chunk hash verification on actual re-upload remains
    # the authoritative check regardless of what the client reports here.
    verification_chunk_index: int | None
    verification_chunk_size: int | None
    verification_chunk_sha256: str | None


def unified_resume_info(session: EvidenceUploadSession, db: Session) -> UnifiedResumeInfo | None:
    memory_upload_id = (session.metadata_json or {}).get("memory_upload_id")
    if not memory_upload_id:
        return None
    item = get_memory_upload(db, session.case_id, memory_upload_id)
    if item is None or item.case_id != session.case_id:
        return None

    from app.services.memory.upload_sessions import upload_status_with_chunks

    status = upload_status_with_chunks(item, db=db)
    received: list[int] = sorted(status.get("received_chunks") or [])
    missing: list[int] = sorted(status.get("missing_chunks") or [])

    verification_index: int | None = None
    verification_size: int | None = None
    verification_sha256: str | None = None
    chunk_metadata = dict((item.metadata_json or {}).get("received_chunks") or {})
    if received:
        verification_index = received[0]
        entry = chunk_metadata.get(str(verification_index)) or {}
        verification_size = int(entry.get("size") or 0) or None
        verification_sha256 = entry.get("sha256") or None

    return UnifiedResumeInfo(
        memory_upload_id=item.id,
        chunk_size_bytes=int(status.get("chunk_size_bytes") or 0),
        total_chunks=int(status.get("total_chunks") or 0),
        received_chunks=received,
        missing_chunks=missing,
        default_concurrency=int(status.get("default_concurrency") or 1),
        max_concurrency=int(status.get("max_concurrency") or 1),
        expected_sha256=item.expected_sha256,
        verification_chunk_index=verification_index,
        verification_chunk_size=verification_size,
        verification_chunk_sha256=verification_sha256,
    )


def create_unified_upload_session(
    db: Session,
    case_id: str,
    *,
    kind: str,
    workflow: str,
    evidence_type: EvidenceType,
    filename: str,
    expected_size_bytes: int,
    declared_platform: str | None,
    client_sha256: str | None,
    host_id: str | None,
    provided_host: str | None,
    authorization_acknowledged: bool,
    notes: str | None,
    current_user: Any,
    canonical_filename: str | None = None,
    file_fingerprint: str | None = None,
    evidence_intent: str | None = None,
    ingest_mode: str | None = None,
    evtx_profile: str | None = None,
) -> tuple[EvidenceUploadSession, UnifiedUploadInfo]:
    """Create a unified chunk-index session for any migrated category.

    ``kind`` is the wizard-facing category string (matches
    ``EvidenceUploadSessionInitRequest.intake_category``, stored as
    ``metadata_json["unified_kind"]``, and read back by ``is_unified_session``).
    ``workflow`` is the registry name ``finalize_memory_upload_session``
    resolves at finalize time (fixed forever once the session is created --
    see ``app.services.memory.upload_sessions.finalize_memory_upload_session``'s
    ``_register()``). ``evidence_type`` drives host-resolution policy only.

    ``file_fingerprint`` is passed straight through to
    ``create_memory_upload_session`` (Memory Overview's own conflict-detail
    UX; unused/None for Wizard-originated sessions).

    ``evidence_intent``/``ingest_mode``/``evtx_profile`` are Wizard Advanced
    Options (WIZARD_ADVANCED_OPTIONS_ENABLED) -- stored as
    ``wizard_evidence_intent``/``wizard_ingest_mode``/``wizard_evtx_profile``
    metadata and consulted only by workflow handlers that already call
    ``upload_evidence()`` (currently: archive). memory_dump/disk_image's
    handlers ignore them.
    """
    if not db.get(Case, case_id):
        raise UploadSessionError("case_not_found", "Case not found")

    if canonical_filename is None:
        kind_config = UNIFIED_UPLOAD_KINDS.get(kind)
        if kind_config is not None and kind_config.preserve_original_filename:
            canonical_filename = Path(filename or "upload.bin").name

    from app.api.routes_evidence import _current_user_id  # actor-id helper only, not a route function

    host_resolution = resolve_host(
        db,
        case_id=case_id,
        evidence_type=evidence_type,
        host_id=host_id,
        provided_host=provided_host,
        allow_create=True,
    )
    resolved_host_label = (host_resolution.display_name or provided_host or "").strip() or "Unknown host"

    extra_metadata: dict[str, Any] = {
        "workflow": workflow,
        "provided_platform": declared_platform,
        "uploaded_by_user_id": _current_user_id(current_user),
        "wizard_notes": (notes or "").strip() or None,
        "wizard_host_id": host_resolution.host_id,
        "source_upload_session_kind": "unified_evidence_wizard",
        "wizard_evidence_intent": evidence_intent,
        "wizard_ingest_mode": ingest_mode,
        "wizard_evtx_profile": evtx_profile,
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
        authorization_acknowledged=authorization_acknowledged,
        expected_sha256=client_sha256,
        upload_mode="resumable",
        file_fingerprint=file_fingerprint,
        extra_metadata=extra_metadata,
        kind=kind,
        canonical_filename=canonical_filename,
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
            "unified_kind": kind,
            "memory_upload_id": memory_upload.id,
            "category": kind,
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


def find_unified_session_for_memory_upload(db: Session, *, case_id: str, memory_upload_id: str) -> EvidenceUploadSession | None:
    """Reverse lookup: given a MemoryUpload id, find its projected
    EvidenceUploadSession, if one was created for it.

    Used by entry points that create/cancel unified sessions outside the
    Wizard's own session-id-keyed API (Memory Overview) to keep the
    projection in sync without a second discovery/cancel implementation --
    not a new projection mechanism, just a way to find the existing one.
    Not indexed by design: case-scoped upload-session counts are small, and
    this is only called on the cancel path, not per-chunk.
    """
    candidates = (
        db.query(EvidenceUploadSession)
        .filter(EvidenceUploadSession.case_id == case_id)
        .order_by(EvidenceUploadSession.updated_at.desc())
        .limit(200)
        .all()
    )
    for candidate in candidates:
        if (candidate.metadata_json or {}).get("memory_upload_id") == memory_upload_id:
            return candidate
    return None


def sync_unified_session(db: Session, session: EvidenceUploadSession) -> EvidenceUploadSession:
    memory_upload_id = (session.metadata_json or {}).get("memory_upload_id")
    if not memory_upload_id:
        return session
    # Ownership check: a unified EvidenceUploadSession must only ever
    # reconcile against the exact MemoryUpload it was created with, scoped
    # to the same case. get_memory_upload already filters by case_id, so an
    # id that resolves to a different case's MemoryUpload (or none) comes
    # back None here -- treated as an ownership mismatch / missing backing
    # session below, never silently adopted.
    item = get_memory_upload(db, session.case_id, memory_upload_id)
    if item is None or item.case_id != session.case_id:
        if session.status not in {EvidenceUploadSessionStatus.cancelled.value, EvidenceUploadSessionStatus.expired.value, EvidenceUploadSessionStatus.promoted.value}:
            session.status = EvidenceUploadSessionStatus.failed.value
            session.failure_message = "The chunk-index upload backing this session is no longer available. Cancel and start a new upload."
            metadata = dict(session.metadata_json or {})
            metadata["unified_status"] = "inconsistent"
            metadata["current_stage"] = "backing_session_missing"
            session.metadata_json = metadata
            db.add(session)
            db.commit()
            db.refresh(session)
            sync_upload_operation(db, session)
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


def cancel_unified_session(db: Session, session: EvidenceUploadSession) -> EvidenceUploadSession:
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
