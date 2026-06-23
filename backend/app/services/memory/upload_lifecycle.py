from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.activity import log_activity
from app.core.config import get_settings
from app.core.database import SessionLocal, utc_now_naive
from app.core.manifest import default_manifest, write_manifest
from app.core.storage import safe_display_filename, sha256_file
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.memory import MemoryUpload
from app.services.memory.upload_capacity import assert_memory_upload_capacity, release_memory_upload_slot_if_owner
from app.services.memory.evidence_access import secure_uploaded_memory_permissions


logger = logging.getLogger(__name__)

# Legacy coarse status (bytes pipeline).  Kept for backwards
# compatibility with existing API consumers; the new
# ``registration_state`` column tracks the post-bytes recovery flow.
ACTIVE_STATUSES = {"validating", "uploading", "verifying", "finalizing", "registration_pending"}
TERMINAL_STATUSES = {"completed", "failed", "inconsistent"}

# Registration lifecycle states (migration v9).  These describe the
# post-bytes flow: the canonical blob is already preserved; we just
# need to record the Evidence row and trigger post-registration
# automation.
# Lifecycle states (v1 stabilization sprint).
#
# The minimal critical path uses 8 states.  Earlier revisions
# (transferring / canonicalizing / registered / preparation_pending)
# are kept as aliases for the migration period but new code should
# only emit the 8 below.
REG_STAGE_UPLOADING = "uploading"            # bytes are being received
REG_STAGE_VERIFYING = "verifying"            # size / hash verification
REG_STAGE_REGISTERING = "registering"        # Evidence INSERT in flight
REG_STAGE_COMPLETED = "completed"            # Evidence row is durable
REG_STAGE_FAILED_UPLOAD = "failed_upload"    # transfer / hash failed
REG_STAGE_FAILED_VERIFICATION = "failed_verification"
REG_STAGE_FAILED_REGISTRATION = "failed_registration"
REG_STAGE_CANCELLED = "cancelled"

# Legacy aliases (kept for the migration period)
REG_STAGE_TRANSFERRING = REG_STAGE_UPLOADING
REG_STAGE_CANONICALIZING = REG_STAGE_VERIFYING
REG_STAGE_REGISTRATION_PENDING = REG_STAGE_REGISTERING
REG_STAGE_REGISTERED = REG_STAGE_COMPLETED
REG_STAGE_PREPARATION_PENDING = REG_STAGE_REGISTERING
REG_STAGE_FAILED_TRANSFER = REG_STAGE_FAILED_UPLOAD
ALL_REG_STAGES = frozenset(
    {
        REG_STAGE_TRANSFERRING,
        REG_STAGE_VERIFYING,
        REG_STAGE_CANONICALIZING,
        REG_STAGE_REGISTRATION_PENDING,
        REG_STAGE_REGISTERED,
        REG_STAGE_PREPARATION_PENDING,
        REG_STAGE_COMPLETED,
        REG_STAGE_FAILED_TRANSFER,
        REG_STAGE_FAILED_VERIFICATION,
        REG_STAGE_FAILED_REGISTRATION,
        REG_STAGE_CANCELLED,
    }
)

# Structured error codes for the registration pipeline.  These
# codes are persisted on the upload row and surfaced through the
# API; they MUST be stable across versions.
ERR_REGISTRATION_FAILED = "MEMORY_EVIDENCE_REGISTRATION_FAILED"
ERR_REGISTRATION_DUPLICATE = "MEMORY_EVIDENCE_DUPLICATE"
ERR_REGISTRATION_DB_CONSTRAINT = "MEMORY_EVIDENCE_DB_CONSTRAINT"
ERR_DETECTION_INITIALIZATION = "MEMORY_DETECTION_INITIALIZATION_FAILED"
ERR_PREPARATION_ENQUEUE = "MEMORY_SYMBOL_PREPARATION_ENQUEUE_FAILED"
ERR_FINALIZATION_INCONSISTENT = "MEMORY_UPLOAD_FINALIZATION_INCONSISTENT"
ERR_INTEGRITY_ERROR = "MEMORY_UPLOAD_INTEGRITY_ERROR"


def normalize_upload_id(value: str | None) -> str:
    if not value:
        return str(uuid4())
    return str(UUID(str(value)))


def create_memory_upload(
    *,
    upload_id: str,
    case_id: str,
    expected_bytes: int,
    display_name: str,
    source_host: str,
    extension: str,
    metadata: dict[str, Any],
    db: Session | None = None,
) -> MemoryUpload:
    upload_id = normalize_upload_id(upload_id)
    evidence_id = str(uuid4())
    staging_name = f"{case_id}-{evidence_id}.memory-upload.part"
    canonical_relative = str(Path("evidence") / case_id / evidence_id / "original" / f"memory-image{extension}")
    owns_session = db is None
    db = db or SessionLocal()
    try:
        existing = db.get(MemoryUpload, upload_id)
        if existing is not None:
            if existing.case_id != case_id or int(existing.expected_bytes) != int(expected_bytes):
                raise ValueError("Upload ID is already associated with a different request.")
            return existing
        item = MemoryUpload(
            id=upload_id,
            case_id=case_id,
            evidence_id=evidence_id,
            status="validating",
            bytes_received=0,
            expected_bytes=expected_bytes,
            display_name=safe_display_filename(display_name),
            source_host=source_host,
            extension=extension,
            staging_name=staging_name,
            canonical_relative_path=canonical_relative,
            lock_token=upload_id,
            metadata_json=dict(metadata),
            progress_at=utc_now_naive(),
            updated_at=utc_now_naive(),
        )
        db.add(item)
        db.commit()
        db.refresh(item)
        if owns_session:
            db.expunge(item)
        return item
    finally:
        if owns_session:
            db.close()


def update_memory_upload(upload_id: str, *, db: Session | None = None, **values: Any) -> MemoryUpload:
    owns_session = db is None
    db = db or SessionLocal()
    try:
        item = db.get(MemoryUpload, upload_id)
        if item is None:
            raise LookupError("Memory upload state was not found.")
        now = utc_now_naive()
        for key, value in values.items():
            if not hasattr(item, key):
                raise ValueError(f"Unsupported memory upload state field: {key}")
            setattr(item, key, value)
        item.updated_at = now
        if any(key in values for key in ("bytes_received", "status")):
            item.progress_at = now
        db.commit()
        db.refresh(item)
        if owns_session:
            db.expunge(item)
        return item
    finally:
        if owns_session:
            db.close()


def get_memory_upload(db: Session, case_id: str, upload_id: str) -> MemoryUpload | None:
    return db.query(MemoryUpload).filter(MemoryUpload.id == normalize_upload_id(upload_id), MemoryUpload.case_id == case_id).one_or_none()


def find_active_memory_upload(db: Session, case_id: str) -> MemoryUpload | None:
    """Return the most recent non-terminal memory upload for a case.

    Used by the API to surface the active upload panel and by the
    new-upload check to refuse overlapping uploads within the same
    case.  Returns ``None`` when there is no active upload.
    """
    from app.models.memory import MemoryUpload as _MU
    return (
        db.query(_MU)
        .filter(
            _MU.case_id == case_id,
            _MU.status.in_(("validating", "uploading", "verifying", "finalizing", "stale")),
        )
        .order_by(_MU.updated_at.desc())
        .first()
    )


def public_memory_upload_status(
    item: MemoryUpload,
    evidence: Evidence | None = None,
    db: Session | None = None,
) -> dict[str, Any]:
    messages = {
        "validating": "Validating memory upload.",
        "uploading": "The transfer reached Kairon; the server is persisting the staged evidence.",
        "verifying": "The file has been transferred. Kairon is verifying the staged evidence.",
        "finalizing": "The file has been transferred. Kairon is finalizing the evidence.",
        "completed": "Memory image uploaded and registered.",
        "failed": item.failure_message or "Memory upload failed.",
        "cancelled": "Memory upload was cancelled by the operator.",
        "stale": item.failure_message or "Memory upload is stale; reconcile or cancel to continue.",
        "inconsistent": item.failure_message or "Memory upload storage is inconsistent and requires review.",
    }
    settings = get_settings()
    stale_after = max(60, int(settings.memory_upload_stale_timeout_seconds))
    is_active = item.status in ACTIVE_STATUSES
    last_heartbeat = item.progress_at
    now = utc_now_naive()
    stale = bool(is_active and last_heartbeat and (now - last_heartbeat).total_seconds() > stale_after)
    resumable = bool(
        item.retryable
        and item.status not in {"completed", "inconsistent"}
        and (item.status != "failed" or bool(item.retryable))
    )
    cancellable = item.status in {"validating", "uploading", "verifying", "finalizing", "stale"}
    # Lookup the Evidence row lazily so existing callers that only
    # pass the upload still get the new fields populated.
    if evidence is None and db is not None:
        evidence = db.get(Evidence, item.evidence_id)
    canonical_exists = _canonical_path(item).exists()
    return {
        "upload_id": item.id,
        "case_id": item.case_id,
        "evidence_id": item.evidence_id if item.status == "completed" else None,
        "status": item.status,
        "stage": getattr(item, "stage", None),
        "registration_state": getattr(item, "registration_state", None),
        "registration_attempts": int(getattr(item, "registration_attempts", 0) or 0),
        "canonical_preserved": bool(getattr(item, "canonical_preserved", None) or canonical_exists),
        "bytes_received": int(item.bytes_received or 0),
        "expected_bytes": int(item.expected_bytes or 0),
        "filename": item.display_name,
        "extension": item.extension,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
        "last_heartbeat": last_heartbeat,
        "stale_after_seconds": stale_after,
        "stale": stale,
        "resumable": resumable,
        "cancellable": cancellable,
        "is_active": is_active,
        "failure_code": item.failure_code,
        "last_registration_error_code": getattr(item, "last_registration_error_code", None),
        "last_registration_error_class": getattr(item, "last_registration_error_class", None),
        "message": messages.get(item.status, "Memory upload state is unavailable."),
        "retryable": bool(item.retryable),
        "evidence_detection_status": evidence.detection_status if evidence is not None else None,
        "evidence_detected_format": evidence.detected_format if evidence is not None else None,
    }


def cancel_memory_upload(
    case_id: str,
    upload_id: str,
    *,
    operator: str | None = None,
    reason: str | None = None,
    db: Session | None = None,
) -> MemoryUpload:
    """Cancel a non-terminal memory upload safely.

    * Idempotent: cancelling an already-cancelled upload is a no-op.
    * Does NOT touch the canonical evidence file when the upload is
      already completed (the caller's responsibility is to check
      ``status != \"completed\"`` before calling).
    * Only deletes the staged (incomplete) file when it exists and
      is not the canonical evidence.
    * Audits the operator, reason and timestamp in
      ``failure_message`` for the audit trail.
    """
    owns_session = db is None
    db = db or SessionLocal()
    try:
        item = get_memory_upload(db, case_id, upload_id)
        if item is None:
            raise LookupError("Memory upload was not found.")
        if item.status == "completed":
            # Refuse to touch completed evidence.
            return _detached_upload(db, item)
        if item.status in {"cancelled", "failed", "inconsistent"}:
            return _detached_upload(db, item)
        # Non-terminal: cancel and release the lock.
        audit_parts = []
        if operator:
            audit_parts.append(f"operator={operator}")
        if reason:
            audit_parts.append(f"reason={reason[:200]}")
        audit_parts.append(f"cancelled_at={utc_now_naive().isoformat()}")
        item.status = "cancelled"
        item.failure_code = "operator_cancelled"
        item.failure_message = " | ".join(audit_parts)
        item.retryable = False
        # Release the upload slot if owned.
        release_memory_upload_slot_if_owner(item.id)
        # Delete only the staged (incomplete) file when safe.
        staging = _staging_path(item)
        canonical = _canonical_path(item)
        try:
            if staging.exists() and not canonical.exists():
                staging.unlink()
        except OSError:
            pass
        db.commit()
        db.refresh(item)
        return _detached_upload(db, item)
    finally:
        if owns_session:
            db.close()


def _canonical_path(item: MemoryUpload) -> Path:
    settings = get_settings()
    root = settings.backend_data_dir.resolve()
    candidate = (settings.backend_data_dir / item.canonical_relative_path).resolve()
    candidate.relative_to(root)
    return candidate


def _staging_path(item: MemoryUpload) -> Path:
    settings = get_settings()
    root = settings.memory_upload_staging_path.resolve()
    candidate = (root / item.staging_name).resolve()
    candidate.relative_to(root)
    return candidate


def _valid_regular_file(path: Path, expected_size: int) -> bool:
    try:
        stat = path.lstat()
        return not path.is_symlink() and path.is_file() and stat.st_size == expected_size
    except OSError:
        return False


def _detached_upload(db: Session, item: MemoryUpload) -> MemoryUpload:
    db.refresh(item)
    db.expunge(item)
    return item


def _build_evidence_from_upload(
    item: MemoryUpload,
    canonical: Path,
) -> Evidence:
    """Build the Evidence row payload for the upload.

    The function does NOT touch the DB; it is a pure factory used
    by the registration transaction.
    """
    metadata = dict(item.metadata_json or {})
    return Evidence(
        id=item.evidence_id,
        case_id=item.case_id,
        original_filename=item.display_name,
        stored_path=str(canonical),
        original_path=str(canonical),
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=EvidenceType.memory_dump,
        sha256=item.sha256,
        size_bytes=int(item.expected_bytes),
        ingest_status=IngestStatus.completed,
        source_tool=None,
        path_validation={},
        ingest_source={
            "mode": EvidenceStorageMode.uploaded.value,
            "original_path": str(canonical),
            "storage_path": str(canonical),
            "copied": True,
            "evidence_intent": metadata.get("evidence_intent", "raw"),
            "packaging": metadata.get("packaging", "single_file"),
            "ingest_mode": metadata.get("ingest_mode"),
            "provided_host": item.source_host,
            "evtx_profile": metadata.get("evtx_profile"),
            "upload_state": "completed",
            "memory_upload": True,
            "memory_upload_id": item.id,
            "memory_authorization_acknowledged": bool(metadata.get("authorization_acknowledged")),
            "canonical_relative_path": item.canonical_relative_path,
        },
        metadata_json={
            "phases": ["uploaded", "registered_memory_metadata"],
            "current_phase": "registered_memory_metadata",
            "progress_pct": 100,
            "display_status": "completed",
            "investigation_ready": False,
            "searchable_documents_count": 0,
            "events_indexed": 0,
            "indexed_events": 0,
            "memory_analysis": {"status": "registered", "profile": "metadata_only"},
            "status_reason": "Memory dump registered metadata-only and isolated from disk ingest.",
            "provided_host": item.source_host,
        },
        error_log={},
        processed_at=utc_now_naive(),
    )


def _persist_evidence_minimal(
    db: Session,
    *,
    item: MemoryUpload,
    canonical: Path,
) -> Evidence:
    """Insert the Evidence row with the minimum amount of work.

    This is the **critical** transaction.  Once this commits, the
    canonical blob is bound to an Evidence row that downstream code
    (catalogue, symbol preparation, run-all) can refer to.

    The function is intentionally narrow: it does NOT call Volatility,
    does NOT open OpenSearch indices, and does NOT enqueue symbol
    acquisition.  All of those are post-registration concerns and
    must not be allowed to invalidate the evidence row.
    """
    secure_uploaded_memory_permissions(canonical, settings=get_settings())
    evidence = _build_evidence_from_upload(item, canonical)
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


def _run_post_registration_automation(
    db: Session,
    *,
    evidence: Evidence,
    canonical: Path,
) -> None:
    """Run all the post-registration side effects.

    A failure here MUST NOT invalidate the evidence row.  Each
    side effect is wrapped in its own try/except block so the
    evidence row stays valid even when the auto-probe or the
    symbol preparation enqueue fails.

    The whole pass is gated by the ``MEMORY_AUTO_PREPARATION``
    setting.  When the flag is off (the v1 default), this
    function returns immediately and the Evidence row is the
    only durable artefact produced by the upload.
    """
    settings = get_settings()
    if not bool(getattr(settings, "memory_auto_preparation", False)):
        logger.info(
            "memory post-registration automation skipped by feature flag "
            "MEMORY_AUTO_PREPARATION=false evidence_id=%s", evidence.id,
        )
        return
    # 1. The read-only memory probe (classify the upload).
    try:
        from app.services.memory.probe import probe_memory_image as _probe
        from app.core.database import utc_now_naive as _now
        probe_result = _probe(Path(canonical))
        evidence.detected_format = probe_result.detected_format
        evidence.detection_status = probe_result.status
        evidence.detection_confidence = probe_result.confidence
        evidence.detection_reason = probe_result.reason
        evidence.probe_version = "memory_probe_v1"
        evidence.probed_at = _now()
        if probe_result.status == "probable_disk":
            evidence.detection_reason = (
                probe_result.reason
                + " Operator can confirm as disk or override as memory."
            )
        db.commit()
    except Exception as probe_exc:  # noqa: BLE001
        logger.warning(
            "memory image probe failed during registration: %s", probe_exc,
        )
        db.rollback()

    # 2. Content identity + symbol preparation.
    try:
        from app.services.memory.symbol_preparation import (
            register_evidence_content_identity,
            find_requirement_by_content_identity,
            link_evidence_to_requirement,
            schedule_preparation,
            mark_preparation,
            PREP_QUEUED,
            PREP_READY,
        )
        from app.core.database import utc_now_naive as _now
        settings = get_settings()
        if bool(getattr(settings, "memory_auto_symbol_probe", True)):
            content = register_evidence_content_identity(db, evidence=evidence)
            reused = find_requirement_by_content_identity(db, evidence=evidence)
            if reused is not None:
                link_evidence_to_requirement(
                    db,
                    evidence=evidence,
                    requirement=reused,
                    link_source="cache_reuse_by_hash",
                    state=PREP_READY,
                )
                content.last_requirement_id = reused.id
                content.last_readiness = PREP_READY
                content.last_checked_at = _now()
                reused.is_shared = True
                mark_preparation(
                    db,
                    evidence=evidence,
                    state=PREP_READY,
                    reason="cache_reuse_by_hash",
                    requirement_id=reused.id,
                )
            else:
                schedule_preparation(
                    db,
                    evidence=evidence,
                    state=PREP_QUEUED,
                    reason="auto_probe_on_upload",
                )
            db.commit()
    except Exception as prep_exc:  # noqa: BLE001
        logger.warning(
            "memory symbol preparation scheduling failed: %s", prep_exc,
        )
        db.rollback()


def register_memory_evidence(upload_id: str, *, db: Session | None = None) -> Evidence:
    """Register a memory upload as an Evidence row.

    v1 stabilization: this is now a thin alias for
    :func:`register_memory_evidence_from_upload`, the minimal
    critical transaction.  It does NOT call Volatility, does NOT
    open OpenSearch indices, and does NOT enqueue symbol
    acquisition.  All of those are post-registration concerns and
    are gated by the ``MEMORY_AUTO_PREPARATION`` setting.
    """
    return register_memory_evidence_from_upload(upload_id, db=db)


def register_preserved_memory_upload(
    upload_id: str,
    *,
    db: Session | None = None,
) -> Evidence:
    """Idempotently register a preserved memory upload.

    Behaviour:

    * If the upload's Evidence row already exists and the canonical
      blob is valid, return it (no work, no error).
    * If the canonical blob is valid but the Evidence row is
      missing, create it in the **critical** transaction.
    * Run the post-registration automation (probe, content identity,
      symbol preparation) in a separate pass so any failure there
      cannot invalidate the evidence row.
    * Track retries through ``registration_attempts`` and surface
      the structured error code in the response.
    """
    owns_session = db is None
    db = db or SessionLocal()
    try:
        item = db.get(MemoryUpload, upload_id)
        if item is None:
            raise LookupError("Memory upload state was not found.")
        canonical = _canonical_path(item)
        # Idempotency: the evidence row already exists.  We verify
        # the canonical blob is still valid; if not, we return a
        # structured failure.
        existing = db.get(Evidence, item.evidence_id)
        if existing is not None:
            if not _valid_regular_file(canonical, int(item.expected_bytes)):
                item.status = "inconsistent"
                item.failure_code = "evidence_file_missing"
                item.failure_message = "Evidence registration exists but canonical storage validation failed."
                item.retryable = False
                item.stage = REG_STAGE_FAILED_VERIFICATION
                item.registration_state = None
                item.canonical_preserved = False
                db.commit()
                raise RuntimeError(item.failure_message)
            # The row is valid; ensure the upload reflects this and
            # schedule any missing post-registration automation.
            item.status = "completed"
            item.stage = REG_STAGE_COMPLETED
            item.registration_state = None
            item.completed_at = item.completed_at or utc_now_naive()
            item.retryable = False
            item.canonical_preserved = True
            db.commit()
            # The evidence row already exists; do not re-run the
            # post-registration automation idempotently.  The
            # caller can opt into a separate "retry preparation"
            # path if needed.
            db.refresh(existing)
            if owns_session:
                db.expunge(existing)
            return existing
        if not item.sha256 or not _valid_regular_file(canonical, int(item.expected_bytes)):
            item.status = "failed"
            item.failure_code = ERR_FINALIZATION_INCONSISTENT
            item.failure_message = "Canonical memory evidence is not ready for registration."
            item.retryable = False
            item.stage = REG_STAGE_FAILED_VERIFICATION
            item.registration_state = None
            item.canonical_preserved = False
            item.registration_attempts = (item.registration_attempts or 0) + 1
            db.commit()
            raise RuntimeError(item.failure_message)
        # The canonical blob is preserved; register the Evidence row
        # in the critical transaction.  We also mark the upload as
        # ``registration_pending`` BEFORE the INSERT so a parallel
        # retry can detect the in-flight registration.
        item.registration_attempts = (item.registration_attempts or 0) + 1
        item.stage = REG_STAGE_REGISTRATION_PENDING
        item.registration_state = "registering"
        item.canonical_preserved = True
        db.commit()
        try:
            evidence = _persist_evidence_minimal(
                db, item=item, canonical=canonical,
            )
        except IntegrityError as integrity_exc:
            # Another retry raced us: the Evidence row was created
            # in between.  We re-read and return the canonical row.
            db.rollback()
            existing = db.get(Evidence, item.evidence_id)
            if existing is not None:
                item.status = "completed"
                item.stage = REG_STAGE_COMPLETED
                item.registration_state = None
                item.canonical_preserved = True
                item.last_registration_error_code = None
                item.last_registration_error_class = None
                db.commit()
                if owns_session:
                    db.expunge(existing)
                return existing
            # The integrity error is real: report it as a structured
            # error and let the operator decide.
            item.status = "failed"
            item.failure_code = ERR_REGISTRATION_DB_CONSTRAINT
            item.failure_message = (
                "Evidence registration failed: a database constraint was violated. "
                "The canonical upload is preserved."
            )
            item.retryable = True
            item.stage = REG_STAGE_FAILED_REGISTRATION
            item.registration_state = None
            item.canonical_preserved = True
            item.last_registration_error_code = ERR_REGISTRATION_DB_CONSTRAINT
            item.last_registration_error_class = type(integrity_exc).__name__
            db.commit()
            raise MemoryUploadRegistrationError(
                ERR_REGISTRATION_DB_CONSTRAINT,
                item.failure_message,
                item_id=item.id,
                evidence_id=item.evidence_id,
                canonical_preserved=True,
            ) from integrity_exc
        except Exception as registration_exc:
            db.rollback()
            item.status = "failed"
            item.failure_code = ERR_REGISTRATION_FAILED
            item.failure_message = (
                "Canonical upload is preserved; evidence registration can be retried."
            )
            item.retryable = True
            item.stage = REG_STAGE_FAILED_REGISTRATION
            item.registration_state = None
            item.canonical_preserved = True
            item.last_registration_error_code = ERR_REGISTRATION_FAILED
            item.last_registration_error_class = type(registration_exc).__name__
            db.commit()
            raise MemoryUploadRegistrationError(
                ERR_REGISTRATION_FAILED,
                item.failure_message,
                item_id=item.id,
                evidence_id=item.evidence_id,
                canonical_preserved=True,
                exception_class=type(registration_exc).__name__,
            ) from registration_exc
        # Critical transaction committed: the Evidence row is durable.
        # The post-registration automation runs in a separate pass
        # and can never invalidate the evidence row.
        item.status = "registration_pending"
        item.stage = REG_STAGE_PREPARATION_PENDING
        item.registration_state = "preparation_pending"
        item.failure_code = None
        item.failure_message = None
        item.retryable = False
        item.last_registration_error_code = None
        item.last_registration_error_class = None
        item.updated_at = utc_now_naive()
        db.commit()
        _run_post_registration_automation(
            db, evidence=evidence, canonical=canonical,
        )
        # The lifecycle is now complete.
        item.status = "completed"
        item.stage = REG_STAGE_COMPLETED
        item.registration_state = None
        item.completed_at = item.completed_at or utc_now_naive()
        item.retryable = False
        item.updated_at = utc_now_naive()
        db.commit()
        # Post-registration audit (manifest + activity log).  This
        # MUST NOT be in the critical transaction; a failure here
        # logs a warning and returns the evidence row anyway.
        try:
            write_manifest(canonical.parents[1] / "manifest.json", default_manifest(evidence))
            log_activity(
                db,
                activity_type="evidence_uploaded",
                title="Memory evidence registered",
                message=(
                    f"Registered authorized memory evidence {evidence.original_filename}. "
                    "External memory analysis was not executed."
                ),
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                metadata={
                    "evidence_type": "memory_dump",
                    "size_bytes": evidence.size_bytes,
                    "upload_id": item.id,
                },
            )
        except Exception:  # noqa: BLE001
            logger.exception(
                "memory upload post-registration audit failed upload_id=%s evidence_id=%s",
                item.id, evidence.id,
            )
        db.refresh(evidence)
        if owns_session:
            db.expunge(evidence)
        return evidence
    finally:
        if owns_session:
            db.close()


class MemoryUploadRegistrationError(RuntimeError):
    """Raised when a memory upload cannot be registered.

    The exception carries the structured error code, the canonical
    blob state and the upload / evidence ids so the API can surface
    a precise response to the analyst.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        item_id: str,
        evidence_id: str,
        canonical_preserved: bool,
        exception_class: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.item_id = item_id
        self.evidence_id = evidence_id
        self.canonical_preserved = canonical_preserved
        self.exception_class = exception_class


def mark_memory_upload_failed(upload_id: str, code: str, message: str, *, retryable: bool, db: Session | None = None) -> MemoryUpload:
    return update_memory_upload(upload_id, db=db, status="failed", failure_code=code, failure_message=message[:512], retryable=retryable)


# ---------------------------------------------------------------------------
# v1 stabilization: minimal critical transaction.
# ---------------------------------------------------------------------------


def register_memory_evidence_from_upload(
    upload_id: str,
    *,
    db: Session | None = None,
) -> Evidence:
    """Register a memory upload as an Evidence row.

    This is the **minimal critical transaction** for the v1
    stabilization sprint.  It performs exactly these steps:

      1. validate the upload exists;
      2. validate the upload is complete (bytes_received ==
         expected_bytes);
      3. validate the size of the canonical file matches
         expected_bytes;
      4. validate the SHA-256 of the canonical file matches the
         upload's recorded SHA-256;
      5. confirm the canonical file exists;
      6. create the Evidence row;
      7. link upload.evidence_id and Evidence.id;
      8. commit;
      9. return the Evidence.

    It does NOT:
      * consult Volatility;
      * consult the symbol cache;
      * call the probe;
      * touch OpenSearch;
      * create a MemoryScanRun;
      * create a batch;
      * materialise processes;
      * enqueue external tasks;
      * enqueue symbol preparation;
      * enqueue content identity registration.

    The post-registration automation is governed by
    ``MEMORY_AUTO_PREPARATION``; when the flag is off (the
    v1 default) the function returns immediately after the
    Evidence INSERT and the upload is marked ``completed``.
    """
    owns_session = db is None
    db = db or SessionLocal()
    try:
        item = db.get(MemoryUpload, upload_id)
        if item is None:
            raise LookupError("Memory upload state was not found.")
        # Idempotency: if the Evidence row already exists and the
        # canonical file is still valid, return the existing row.
        existing = db.get(Evidence, item.evidence_id)
        canonical = _canonical_path(item)
        if existing is not None:
            if not _valid_regular_file(canonical, int(item.expected_bytes)):
                item.status = "inconsistent"
                item.failure_code = "evidence_file_missing"
                item.failure_message = (
                    "Evidence registration exists but canonical "
                    "storage validation failed."
                )
                item.retryable = False
                item.stage = REG_STAGE_FAILED_VERIFICATION
                item.registration_state = None
                item.canonical_preserved = False
                db.commit()
                raise MemoryUploadRegistrationError(
                    "evidence_file_missing",
                    item.failure_message,
                    item_id=item.id,
                    evidence_id=item.evidence_id,
                    canonical_preserved=False,
                    exception_class="FileValidationError",
                )
            item.status = "completed"
            item.stage = REG_STAGE_COMPLETED
            item.registration_state = None
            item.completed_at = item.completed_at or utc_now_naive()
            item.retryable = False
            item.canonical_preserved = True
            db.commit()
            db.refresh(existing)
            if owns_session:
                db.expunge(existing)
            return existing
        # Step 1-5: validate the upload and the canonical file.
        if int(item.bytes_received or 0) != int(item.expected_bytes or 0):
            raise MemoryUploadRegistrationError(
                "evidence_upload_incomplete",
                "Memory upload is incomplete; cannot register evidence.",
                item_id=item.id,
                evidence_id=item.evidence_id,
                canonical_preserved=True,
                exception_class="IncompleteUploadError",
            )
        if not item.sha256:
            raise MemoryUploadRegistrationError(
                "evidence_hash_missing",
                "Memory upload SHA-256 was not recorded; cannot register evidence.",
                item_id=item.id,
                evidence_id=item.evidence_id,
                canonical_preserved=True,
                exception_class="MissingHashError",
            )
        if not _valid_regular_file(canonical, int(item.expected_bytes)):
            raise MemoryUploadRegistrationError(
                "evidence_file_missing",
                "Canonical memory file is missing or has the wrong size.",
                item_id=item.id,
                evidence_id=item.evidence_id,
                canonical_preserved=False,
                exception_class="FileValidationError",
            )
        actual_sha = sha256_file(canonical)
        if actual_sha != item.sha256:
            raise MemoryUploadRegistrationError(
                "evidence_hash_mismatch",
                "Canonical memory file SHA-256 does not match the upload record.",
                item_id=item.id,
                evidence_id=item.evidence_id,
                canonical_preserved=True,
                exception_class="HashMismatchError",
            )
        # Steps 6-8: create the Evidence row in the critical
        # transaction.  We mark the upload as ``registering``
        # first so a parallel retry can detect the in-flight
        # registration.
        item.registration_attempts = (item.registration_attempts or 0) + 1
        item.stage = REG_STAGE_REGISTERING
        item.registration_state = "registering"
        item.canonical_preserved = True
        item.failure_code = None
        item.failure_message = None
        item.last_registration_error_code = None
        item.last_registration_error_class = None
        db.commit()
        try:
            evidence = _persist_evidence_minimal(
                db, item=item, canonical=canonical,
            )
        except IntegrityError as integrity_exc:
            # A parallel retry won the race.
            db.rollback()
            existing = db.get(Evidence, item.evidence_id)
            if existing is not None:
                item.status = "completed"
                item.stage = REG_STAGE_COMPLETED
                item.registration_state = None
                item.canonical_preserved = True
                db.commit()
                if owns_session:
                    db.expunge(existing)
                return existing
            item.status = "failed"
            item.stage = REG_STAGE_FAILED_REGISTRATION
            item.failure_code = ERR_REGISTRATION_DB_CONSTRAINT
            item.failure_message = (
                "Evidence registration failed: a database constraint "
                "was violated. The canonical upload is preserved."
            )
            item.retryable = True
            item.registration_state = None
            item.canonical_preserved = True
            item.last_registration_error_code = ERR_REGISTRATION_DB_CONSTRAINT
            item.last_registration_error_class = type(integrity_exc).__name__
            db.commit()
            raise MemoryUploadRegistrationError(
                ERR_REGISTRATION_DB_CONSTRAINT,
                item.failure_message,
                item_id=item.id,
                evidence_id=item.evidence_id,
                canonical_preserved=True,
                exception_class=type(integrity_exc).__name__,
            ) from integrity_exc
        except Exception as registration_exc:
            db.rollback()
            item.status = "failed"
            item.stage = REG_STAGE_FAILED_REGISTRATION
            item.failure_code = ERR_REGISTRATION_FAILED
            item.failure_message = (
                "Evidence registration failed; the canonical upload is "
                "preserved and the operator can retry without resending bytes."
            )
            item.retryable = True
            item.registration_state = None
            item.canonical_preserved = True
            item.last_registration_error_code = ERR_REGISTRATION_FAILED
            item.last_registration_error_class = type(registration_exc).__name__
            db.commit()
            # Log the FULL exception (no swallowing) so the operator
            # can find the first real cause in the backend logs.
            logger.exception(
                "memory evidence registration failed upload_id=%s evidence_id=%s",
                item.id, item.evidence_id,
            )
            raise MemoryUploadRegistrationError(
                ERR_REGISTRATION_FAILED,
                item.failure_message,
                item_id=item.id,
                evidence_id=item.evidence_id,
                canonical_preserved=True,
                exception_class=type(registration_exc).__name__,
            ) from registration_exc
        # Step 9: commit succeeded, the Evidence row is durable.
        item.status = "completed"
        item.stage = REG_STAGE_COMPLETED
        item.registration_state = None
        item.completed_at = item.completed_at or utc_now_naive()
        item.retryable = False
        item.updated_at = utc_now_naive()
        db.commit()
        # Post-registration audit.  MUST NOT be in the critical
        # transaction.  Failures here only log a warning.
        try:
            write_manifest(canonical.parents[1] / "manifest.json", default_manifest(evidence))
            log_activity(
                db,
                activity_type="evidence_uploaded",
                title="Memory evidence registered",
                message=(
                    f"Registered authorized memory evidence "
                    f"{evidence.original_filename}. External memory analysis "
                    f"was not executed as part of the registration."
                ),
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                metadata={
                    "evidence_type": "memory_dump",
                    "size_bytes": evidence.size_bytes,
                    "upload_id": item.id,
                },
            )
        except Exception:  # noqa: BLE001
            logger.exception(
                "memory upload post-registration audit failed upload_id=%s evidence_id=%s",
                item.id, evidence.id,
            )
        # Post-registration automation (probe, content identity,
        # symbol preparation).  Gated by MEMORY_AUTO_PREPARATION.
        try:
            _run_post_registration_automation(
                db, evidence=evidence, canonical=canonical,
            )
        except Exception:  # noqa: BLE001
            logger.exception(
                "memory post-registration automation failed upload_id=%s evidence_id=%s",
                item.id, evidence.id,
            )
        db.refresh(evidence)
        if owns_session:
            db.expunge(evidence)
        return evidence
    finally:
        if owns_session:
            db.close()


def repair_preserved_memory_uploads(
    case_id: str | None = None,
    *,
    dry_run: bool = True,
    db: Session | None = None,
) -> list[dict[str, Any]]:
    """Admin command: repair preserved-but-orphaned uploads.

    For each memory upload in the case (or globally) that is in a
    retriable state with a preserved canonical blob, attempt to
    re-register the Evidence row without resending bytes.

    ``dry_run=True`` (the default) returns a report describing
    what would be repaired without mutating the database.
    """
    owns_session = db is None
    db = db or SessionLocal()
    try:
        report: list[dict[str, Any]] = []
        query = db.query(MemoryUpload)
        if case_id is not None:
            query = query.filter(MemoryUpload.case_id == case_id)
        rows = query.order_by(MemoryUpload.created_at.desc()).all()
        for item in rows:
            canonical = _canonical_path(item)
            canonical_exists = canonical.exists()
            size_ok = canonical_exists and _valid_regular_file(canonical, int(item.expected_bytes))
            sha_ok = False
            if size_ok and item.sha256:
                sha_ok = sha256_file(canonical) == item.sha256
            evidence_exists = db.get(Evidence, item.evidence_id) is not None
            repairable = (
                size_ok
                and (item.sha256 is None or sha_ok)
                and not evidence_exists
                and item.status in {"failed", "inconsistent", "stale", "cancelled"}
            )
            reason: list[str] = []
            if not canonical_exists:
                reason.append("canonical_missing")
            elif not size_ok:
                reason.append("canonical_size_mismatch")
            if item.sha256 and not sha_ok:
                reason.append("sha256_mismatch")
            if evidence_exists:
                reason.append("evidence_already_registered")
            if item.status == "completed":
                reason.append("already_completed")
            report.append({
                "upload_id": item.id,
                "case_id": item.case_id,
                "filename": item.display_name,
                "expected_bytes": int(item.expected_bytes),
                "received_bytes": int(item.bytes_received),
                "sha256": item.sha256,
                "canonical_exists": canonical_exists,
                "size_ok": size_ok,
                "sha256_ok": sha_ok,
                "evidence_exists": evidence_exists,
                "status": item.status,
                "stage": item.stage,
                "registration_state": item.registration_state,
                "failure_code": item.failure_code,
                "repairable": repairable,
                "reason": reason,
            })
            if not dry_run and repairable:
                try:
                    register_memory_evidence_from_upload(item.id, db=db)
                except MemoryUploadRegistrationError as exc:
                    report[-1]["repair_error"] = {
                        "code": exc.code,
                        "exception_class": exc.exception_class,
                    }
        return report
    finally:
        if owns_session:
            db.close()


def retry_preserved_memory_upload_registration(
    upload_id: str,
    *,
    db: Session | None = None,
) -> dict:
    """Re-attempt evidence registration for a preserved memory upload.

    The canonical blob is already on disk; this function only
    records the Evidence row and runs the post-registration
    automation.  The route handler is responsible for surfacing
    the structured response to the analyst.
    """
    evidence = register_preserved_memory_upload(upload_id, db=db)
    item = db.get(MemoryUpload, upload_id) if db is not None else None
    if item is None:
        # Use a fresh session to look up the item.
        from app.core.database import SessionLocal
        with SessionLocal() as fresh_db:
            item = fresh_db.get(MemoryUpload, upload_id)
    return public_memory_upload_status(item, evidence)


def reconcile_memory_upload_lifecycles(
    db: Session,
    *,
    case_id: str | None = None,
    max_uploads: int = 100,
) -> dict[str, int]:
    """Walk the memory_uploads table and re-queue any upload whose
    canonical blob is durable but whose Evidence row is missing.

    This is the read-only reconciliation pass that the
    ``/memory/uploads/reconcile`` endpoint exposes.  The function
    is idempotent: it only re-queues uploads that are in a
    retriable state with a preserved canonical blob.
    """
    stats = {
        "scanned": 0,
        "requeued": 0,
        "skipped_terminal": 0,
        "skipped_inconsistent": 0,
    }
    query = db.query(MemoryUpload)
    if case_id is not None:
        query = query.filter(MemoryUpload.case_id == case_id)
    rows = query.order_by(MemoryUpload.created_at.desc()).limit(max_uploads).all()
    for item in rows:
        stats["scanned"] += 1
        # If the upload is already in a terminal "completed" state
        # with a valid evidence row, skip.
        evidence = db.get(Evidence, item.evidence_id)
        canonical = _canonical_path(item)
        canonical_exists = canonical.exists()
        size_ok = canonical_exists and _valid_regular_file(canonical, int(item.expected_bytes))
        if evidence is not None and size_ok:
            stats["skipped_terminal"] += 1
            continue
        # If the canonical blob is missing or invalid, we cannot
        # retry: the operator must re-upload.
        if not size_ok:
            stats["skipped_inconsistent"] += 1
            continue
        # Re-queue for registration.
        item.stage = REG_STAGE_REGISTRATION_PENDING
        item.registration_state = "requeued"
        item.canonical_preserved = True
        item.updated_at = utc_now_naive()
        db.commit()
        stats["requeued"] += 1
    return stats


def reconcile_memory_upload(case_id: str, upload_id: str, *, force_stale: bool = False, db: Session | None = None) -> MemoryUpload:
    settings = get_settings()
    owns_session = db is None
    if owns_session:
        with SessionLocal() as _db:
            return reconcile_memory_upload(
                case_id, upload_id, force_stale=force_stale, db=_db,
            )
    item = get_memory_upload(db, case_id, upload_id)
    if item is None:
        raise LookupError("Memory upload state was not found.")
    if item.status == "completed":
        evidence = db.get(Evidence, item.evidence_id)
        if evidence is None or not _valid_regular_file(_canonical_path(item), int(item.expected_bytes)):
            item.status = "inconsistent"
            item.failure_code = "completed_state_invalid"
            item.failure_message = "Completed upload state does not match durable evidence storage."
            item.retryable = False
            db.commit()
        return _detached_upload(db, item)
    stale_before = utc_now_naive() - timedelta(seconds=max(60, int(settings.memory_upload_stale_timeout_seconds)))
    if item.status in ACTIVE_STATUSES and item.progress_at > stale_before and not force_stale:
        db.expunge(item)
        return item
    if item.status in ACTIVE_STATUSES:
        release_memory_upload_slot_if_owner(item.id)
    staging = _staging_path(item)
    canonical = _canonical_path(item)
    staging_exists = staging.exists()
    canonical_exists = canonical.exists()
    evidence = db.get(Evidence, item.evidence_id)
    if evidence is not None and not _valid_regular_file(canonical, int(item.expected_bytes)):
        item.status = "inconsistent"
        item.failure_code = "evidence_file_missing"
        item.failure_message = "Evidence registration exists but canonical storage is missing or invalid."
        item.retryable = False
        db.commit()
        return _detached_upload(db, item)
    if staging_exists and canonical_exists:
        item.status = "inconsistent"
        item.failure_code = "staging_and_canonical_present"
        item.failure_message = "Both staged and canonical memory files exist; automatic overwrite is unsafe."
        item.retryable = False
        db.commit()
        return _detached_upload(db, item)
    if canonical_exists:
        if not _valid_regular_file(canonical, int(item.expected_bytes)):
            item.status = "inconsistent"
            item.failure_code = "canonical_size_mismatch"
            item.failure_message = "Canonical memory file size does not match the accepted upload."
            item.retryable = False
            db.commit()
            return _detached_upload(db, item)
        if not item.sha256:
            item.sha256 = sha256_file(canonical)
        item.status = "finalizing"
        db.commit()
    elif staging_exists:
        if not _valid_regular_file(staging, int(item.expected_bytes)):
            item.status = "failed"
            item.failure_code = "staging_size_mismatch"
            item.failure_message = "Staged memory file is incomplete or invalid."
            item.retryable = False
            db.commit()
            return _detached_upload(db, item)
        if not item.sha256:
            item.sha256 = sha256_file(staging)
        assert_memory_upload_capacity(int(item.expected_bytes), phase="finalization", bytes_already_staged=int(item.expected_bytes))
        canonical.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staging, canonical)
        item.status = "finalizing"
        item.bytes_received = item.expected_bytes
        db.commit()
    else:
        item.status = "failed"
        item.failure_code = "upload_bytes_lost"
        item.failure_message = "Neither staged nor canonical upload bytes are available."
        item.retryable = False
        db.commit()
        return _detached_upload(db, item)
    upload_key = item.id
    register_memory_evidence(upload_key)
    if owns_session:
        return db.get(MemoryUpload, upload_key)
    return item
