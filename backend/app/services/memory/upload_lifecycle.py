from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

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
ACTIVE_STATUSES = {"validating", "uploading", "verifying", "finalizing"}
TERMINAL_STATUSES = {"completed", "failed", "inconsistent"}


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


def public_memory_upload_status(item: MemoryUpload) -> dict[str, Any]:
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
    return {
        "upload_id": item.id,
        "case_id": item.case_id,
        "evidence_id": item.evidence_id if item.status == "completed" else None,
        "status": item.status,
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
        "message": messages.get(item.status, "Memory upload state is unavailable."),
        "retryable": bool(item.retryable),
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


def register_memory_evidence(upload_id: str, *, db: Session | None = None) -> Evidence:
    owns_session = db is None
    db = db or SessionLocal()
    try:
        item = db.get(MemoryUpload, upload_id)
        if item is None:
            raise LookupError("Memory upload state was not found.")
        existing = db.get(Evidence, item.evidence_id)
        canonical = _canonical_path(item)
        if existing is not None:
            if not _valid_regular_file(canonical, int(item.expected_bytes)):
                item.status = "inconsistent"
                item.failure_code = "evidence_file_missing"
                item.failure_message = "Evidence registration exists but canonical storage validation failed."
                item.retryable = False
                db.commit()
                raise RuntimeError(item.failure_message)
            item.status = "completed"
            item.completed_at = item.completed_at or utc_now_naive()
            item.retryable = False
            db.commit()
            db.refresh(existing)
            return existing
        if not item.sha256 or not _valid_regular_file(canonical, int(item.expected_bytes)):
            raise RuntimeError("Canonical memory evidence is not ready for registration.")
        secure_uploaded_memory_permissions(canonical, settings=get_settings())
        metadata = dict(item.metadata_json or {})
        evidence = Evidence(
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
        db.add(evidence)
        # Run the read-only content probe to classify the uploaded
        # memory image.  The probe never blocks the upload; its verdict
        # is stored on the evidence row and surfaced through the UI.
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
                # Down-classify: still registered as memory_dump for
                # compatibility, but the operator must confirm.
                evidence.detection_reason = (
                    probe_result.reason
                    + " Operator can confirm as disk or override as memory."
                )
        except Exception as probe_exc:  # noqa: BLE001
            logger.warning(
                "memory image probe failed during registration: %s",
                probe_exc,
            )
        # Register the content identity and schedule the automatic
        # Windows symbol preparation pipeline.  This is the
        # default behaviour; the operator never has to push "Probe
        # symbol requirements" manually in the normal flow.
        try:
            from app.core.config import get_settings
            from app.services.memory.symbol_preparation import (
                register_evidence_content_identity,
                find_requirement_by_content_identity,
                link_evidence_to_requirement,
                schedule_preparation,
                PREP_QUEUED,
                PREP_READY,
                PREP_IDENTIFIED,
            )
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
                    # Mark the requirement as shared so other
                    # evidences can detect the canonical owner.
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
        except Exception as prep_exc:  # noqa: BLE001
            logger.warning(
                "memory symbol preparation scheduling failed: %s",
                prep_exc,
            )
        item.status = "completed"
        item.failure_code = None
        item.failure_message = None
        item.retryable = False
        item.completed_at = utc_now_naive()
        item.updated_at = utc_now_naive()
        db.commit()
        db.refresh(evidence)
        try:
            write_manifest(canonical.parents[1] / "manifest.json", default_manifest(evidence))
            log_activity(
                db,
                activity_type="evidence_uploaded",
                title="Memory evidence registered",
                message=f"Registered authorized memory evidence {evidence.original_filename}. External memory analysis was not executed.",
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                metadata={"evidence_type": "memory_dump", "size_bytes": evidence.size_bytes, "upload_id": item.id},
            )
        except Exception:  # noqa: BLE001
            logger.exception("memory upload post-registration audit failed upload_id=%s evidence_id=%s", item.id, evidence.id)
        if owns_session:
            db.expunge(evidence)
        return evidence
    except Exception:
        db.rollback()
        raise
    finally:
        if owns_session:
            db.close()


def mark_memory_upload_failed(upload_id: str, code: str, message: str, *, retryable: bool, db: Session | None = None) -> MemoryUpload:
    return update_memory_upload(upload_id, db=db, status="failed", failure_code=code, failure_message=message[:512], retryable=retryable)


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
