"""Post-finalize workflow handler for Evidence Wizard disk_image uploads
routed through the unified chunk-index backend (see
``app.core.config.Settings.unified_upload_evidence_disk_image`` and
``app.services.evidence_unified_upload``).

Registered under the ``"disk_image"`` name in ``app.services.upload_shared.workflow``.
Session ownership is fixed at creation time (same mechanism as
``evidence_memory_dump``): ``create_unified_upload_session`` stamps
``MemoryUpload.metadata_json["workflow"] = "disk_image"`` once, and
``finalize_memory_upload_session`` reads that key to pick the handler.

Scope: single-file disk images only (RAW/DD/IMG, or a single-segment EWF
image) -- matches ``routes_evidence.upload_disk_image``'s ``len(files) == 1``
branch. Multi-segment images (additional ``.E02``/``.002``... companions)
are not resumable even in the legacy path today (only the first segment
ever chunked/resumed there) and are intentionally left on the legacy
multipart path rather than inventing a new multi-file session concept
with no reference implementation to converge on.

This handler is deliberately NOT a thin wrapper around
``routes_evidence.upload_disk_image`` (a FastAPI route function) --
per the same rule the memory_dump handler follows, workflow handlers
call service-level functions, never route functions. The Evidence-row
construction logic that route inlines is reproduced here using the same
underlying primitives (host resolution, custody events, manifest,
activity log, ingest enqueue) it uses.
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.core.activity import log_activity
from app.core.database import utc_now_naive
from app.core.manifest import default_manifest, write_manifest
from app.core.storage import evidence_manifest_path
from app.models.evidence import (
    Evidence,
    EvidenceCustodyEventType,
    EvidenceIntegrityStatus,
    EvidenceStorageMode,
    EvidenceType,
    IngestStatus,
    detect_evidence_platform,
    normalize_evidence_platform,
    resolve_evidence_platform,
)
from app.models.memory import MemoryUpload
from app.ingest.evidence_classifier import EvidenceCategory, get_evidence_classifier
from app.services.evidence_integrity import record_evidence_event
from app.services.host_resolution import assign_evidence_host
from app.services.memory.upload_lifecycle import _canonical_path, _valid_regular_file
from app.services.memory.upload_sessions import MemoryUploadSessionError
from app.services.upload_shared.workflow import register_workflow_handler


def _find_duplicate_disk_image_evidence(db: Session, case_id: str, sha256: str) -> Evidence | None:
    if not sha256:
        return None
    return (
        db.query(Evidence)
        .filter(Evidence.case_id == case_id, Evidence.evidence_type == EvidenceType.disk_image, Evidence.sha256 == sha256)
        .first()
    )


def register_disk_image_evidence(upload_id: str, db: Session) -> Evidence:
    item = db.get(MemoryUpload, upload_id)
    if item is None:
        raise MemoryUploadSessionError("disk_image_upload_missing", f"Unified disk image upload {upload_id} was not found.")

    existing = db.get(Evidence, item.evidence_id)
    if existing is not None:
        return existing

    canonical = _canonical_path(item)
    if not item.sha256 or not _valid_regular_file(canonical, int(item.expected_bytes)):
        raise MemoryUploadSessionError("disk_image_file_missing", "Canonical disk image file is missing or has the wrong size.")

    duplicate = _find_duplicate_disk_image_evidence(db, item.case_id, item.sha256)
    if duplicate is not None:
        item.status = "failed"
        item.failure_code = "MEMORY_EVIDENCE_DUPLICATE"
        item.failure_message = "This disk image is already registered in this case."
        item.retryable = False
        db.commit()
        raise MemoryUploadSessionError(
            "MEMORY_EVIDENCE_DUPLICATE",
            item.failure_message,
            detail={"existing_evidence_id": duplicate.id, "existing_filename": duplicate.original_filename, "duplicate": True},
        )

    from app.api.routes_evidence import _mark_evidence_blocked_before_ingest  # plain helper, not a route function
    from app.core.opensearch import OpenSearchIngestBlockedError
    from app.disk_images.service import detect_disk_image_format
    from app.workers.tasks import enqueue_ingest

    classification = get_evidence_classifier().classify(canonical)
    if classification.category == EvidenceCategory.MEMORY_DUMP:
        raise MemoryUploadSessionError(
            "classification_conflict_memory",
            f"This upload was requested as a disk image, but content detection classified it as memory evidence: {classification.reason}",
            detail={"detected_kind": classification.category.value, "confidence": classification.confidence, "reason": classification.reason, "metadata": classification.metadata},
        )
    if classification.category == EvidenceCategory.AUXILIARY:
        raise MemoryUploadSessionError(
            "classification_conflict_auxiliary",
            f"This upload was requested as a disk image, but content detection classified it as auxiliary: {classification.reason}",
            detail={"detected_kind": classification.category.value, "confidence": classification.confidence, "reason": classification.reason, "metadata": classification.metadata},
        )
    format_probe = detect_disk_image_format(canonical, [canonical])
    if not format_probe:
        raise MemoryUploadSessionError("unknown_format", "Kairon could not recognize this disk image format.")
    if classification.category != EvidenceCategory.DISK_IMAGE and str(format_probe.get("confidence") or "") == "extension":
        raise MemoryUploadSessionError(
            "unknown_format",
            "Kairon found only a raw disk-image extension, not a coherent disk structure.",
            detail={"detected_kind": classification.category.value, "confidence": classification.confidence, "reason": classification.reason, "format_probe": format_probe, "metadata": classification.metadata},
        )
    if not format_probe.get("supported"):
        raise MemoryUploadSessionError("unsupported_format", f"{format_probe.get('format')} is recognized but not supported in this release.")

    metadata = dict(item.metadata_json or {})
    declared_platform = metadata.get("provided_platform")
    original_filename = item.display_name
    normalized_provided_platform = normalize_evidence_platform(declared_platform or "auto")
    detected_platform = detect_evidence_platform(filename=original_filename, evidence_type=EvidenceType.disk_image.value)
    provided_platform, _, effective_platform = resolve_evidence_platform(
        normalized_provided_platform, detected_platform, evidence_type=EvidenceType.disk_image.value,
    )

    segment_entries = [{"path": canonical.name, "ignored": False, "reason": None, "sha256": item.sha256, "size": int(item.expected_bytes)}]
    evidence = Evidence(
        id=item.evidence_id,
        case_id=item.case_id,
        original_filename=original_filename,
        stored_path=str(canonical),
        original_path=str(canonical.parent),
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=EvidenceType.disk_image,
        sha256=item.sha256,
        size_bytes=int(item.expected_bytes),
        detected_type=EvidenceType.disk_image.value,
        provided_platform=provided_platform,
        detected_platform=detected_platform,
        effective_platform=effective_platform,
        uploaded_by_user_id=metadata.get("uploaded_by_user_id"),
        uploaded_at=utc_now_naive(),
        first_seen_at=utc_now_naive(),
        last_processed_at=utc_now_naive(),
        integrity_status=EvidenceIntegrityStatus.unknown,
        notes=(metadata.get("wizard_notes") or None),
        file_count=len(segment_entries),
        ingest_status=IngestStatus.pending,
        source_tool="disk_image",
        path_validation={},
        ingest_source={
            "mode": EvidenceStorageMode.uploaded.value,
            "original_path": str(canonical.parent),
            "storage_path": str(canonical),
            "copied": True,
            "provided_platform": provided_platform,
            "detected_platform": detected_platform,
            "effective_platform": effective_platform,
            "ingest_mode": None,
            "disk_image": True,
            "format_probe": format_probe,
            "segment_count": len(segment_entries),
        },
        metadata_json={
            "phases": ["uploaded"],
            "current_phase": "uploaded",
            "progress_pct": 0,
            "tree": [],
            "detected_artifacts": 0,
            "processed_artifacts": 0,
            "indexed_events": 0,
            "records_processed": 0,
            "events_indexed": 0,
            "artifacts_processed": 0,
            "artifacts_total": 0,
            "disk_image": {"format_probe": format_probe, "segments": segment_entries},
            "provided_platform": provided_platform,
            "detected_platform": detected_platform,
            "effective_platform": effective_platform,
        },
        error_log={},
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    record_evidence_event(
        db, evidence, EvidenceCustodyEventType.uploaded, "Disk image uploaded and registered.",
        actor_user_id=evidence.uploaded_by_user_id,
        details={"original_filename": evidence.original_filename, "size_bytes": evidence.size_bytes, "evidence_type": evidence.evidence_type.value},
    )
    if evidence.sha256:
        record_evidence_event(
            db, evidence, EvidenceCustodyEventType.hash_computed, "SHA-256 computed for uploaded disk image.",
            actor_user_id=evidence.uploaded_by_user_id, details={"sha256": evidence.sha256, "size_bytes": evidence.size_bytes},
        )

    explicit_host_id = metadata.get("wizard_host_id")
    if explicit_host_id:
        evidence = assign_evidence_host(
            db, evidence, host_id=explicit_host_id, actor_user_id=metadata.get("uploaded_by_user_id"),
            actor="evidence_wizard", reason="Assigned during evidence ingestion wizard", method="upload_assignment",
        )
    db.commit()
    db.refresh(evidence)

    write_manifest(evidence_manifest_path(evidence.case_id, evidence.id), default_manifest(evidence))
    log_activity(
        db, activity_type="evidence_uploaded", title="Disk image uploaded",
        message=f"Uploaded disk image evidence {evidence.original_filename}",
        case_id=evidence.case_id, evidence_id=evidence.id,
        metadata={"evidence_type": evidence.evidence_type.value, "format_probe": format_probe, "segment_count": len(segment_entries)},
    )
    try:
        enqueue_ingest(evidence.id)
    except OpenSearchIngestBlockedError as exc:
        _mark_evidence_blocked_before_ingest(db, evidence, exc=exc)

    item.status = "completed"
    item.retryable = False
    db.commit()
    return evidence


register_workflow_handler("disk_image", register_disk_image_evidence)
