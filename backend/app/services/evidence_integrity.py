from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core.database import utc_now_naive
from app.models.evidence import Evidence, EvidenceCustodyEvent, EvidenceCustodyEventType, EvidenceIntegrityStatus


def compute_sha256_stream(path: Path, *, chunk_size: int = 1024 * 1024) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def record_evidence_event(
    db: Session,
    evidence: Evidence,
    event_type: EvidenceCustodyEventType | str,
    summary: str,
    *,
    actor_user_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> EvidenceCustodyEvent:
    event = EvidenceCustodyEvent(
        id=str(uuid4()),
        evidence_id=evidence.id,
        event_type=event_type if isinstance(event_type, EvidenceCustodyEventType) else EvidenceCustodyEventType(str(event_type)),
        actor_user_id=actor_user_id,
        timestamp=utc_now_naive(),
        summary=summary[:512],
        details_json=_sanitize_details(details or {}),
    )
    db.add(event)
    return event


def verify_evidence_integrity(db: Session, evidence: Evidence, *, actor_user_id: str | None = None) -> dict[str, Any]:
    checked_at = utc_now_naive()
    expected_sha256 = str(evidence.sha256 or "").strip().lower() or None
    stored_path = Path(evidence.stored_path)
    details: dict[str, Any] = {"expected_sha256": expected_sha256, "stored_file_present": stored_path.exists()}
    if not stored_path.exists():
        evidence.integrity_status = EvidenceIntegrityStatus.missing_file
        evidence.integrity_checked_at = checked_at
        details["result"] = "missing_file"
        record_evidence_event(db, evidence, EvidenceCustodyEventType.integrity_checked, "Integrity check failed: stored file is missing.", actor_user_id=actor_user_id, details=details)
        return _integrity_payload(evidence, actual_sha256=None, actual_size_bytes=None)
    if not stored_path.is_file():
        evidence.integrity_status = EvidenceIntegrityStatus.error
        evidence.integrity_checked_at = checked_at
        details["result"] = "error"
        details["reason"] = "stored_path_is_not_a_regular_file"
        record_evidence_event(db, evidence, EvidenceCustodyEventType.integrity_checked, "Integrity check failed: stored path is not a regular file.", actor_user_id=actor_user_id, details=details)
        return _integrity_payload(evidence, actual_sha256=None, actual_size_bytes=None)
    try:
        actual_sha256, actual_size = compute_sha256_stream(stored_path)
    except OSError as exc:
        evidence.integrity_status = EvidenceIntegrityStatus.error
        evidence.integrity_checked_at = checked_at
        details["result"] = "error"
        details["error"] = type(exc).__name__
        record_evidence_event(db, evidence, EvidenceCustodyEventType.integrity_checked, "Integrity check failed while reading stored evidence.", actor_user_id=actor_user_id, details=details)
        return _integrity_payload(evidence, actual_sha256=None, actual_size_bytes=None)
    details.update({"actual_sha256": actual_sha256, "actual_size_bytes": actual_size})
    if expected_sha256 and actual_sha256 == expected_sha256:
        evidence.integrity_status = EvidenceIntegrityStatus.verified
        summary = "SHA-256 verified."
        details["result"] = "verified"
    else:
        evidence.integrity_status = EvidenceIntegrityStatus.mismatch
        summary = "Hash mismatch detected."
        details["result"] = "mismatch"
    evidence.integrity_checked_at = checked_at
    record_evidence_event(db, evidence, EvidenceCustodyEventType.integrity_checked, summary, actor_user_id=actor_user_id, details=details)
    return _integrity_payload(evidence, actual_sha256=actual_sha256, actual_size_bytes=actual_size)


def build_evidence_integrity_payload(evidence: Evidence) -> dict[str, Any]:
    return _integrity_payload(evidence, actual_sha256=None, actual_size_bytes=None)


def build_evidence_manifest(evidence: Evidence, events: list[EvidenceCustodyEvent]) -> dict[str, Any]:
    host = evidence.host
    uploaded_by = evidence.uploaded_by
    return {
        "case_id": evidence.case_id,
        "evidence_id": evidence.id,
        "original_filename": evidence.original_filename,
        "sha256": evidence.sha256,
        "size_bytes": evidence.size_bytes,
        "evidence_type": getattr(evidence.evidence_type, "value", evidence.evidence_type),
        "mime_type": evidence.mime_type,
        "detected_type": evidence.detected_type,
        "uploaded_by": _user_label(uploaded_by),
        "uploaded_by_user_id": evidence.uploaded_by_user_id,
        "uploaded_at": _iso(evidence.uploaded_at),
        "case": {"id": evidence.case_id},
        "host": {"id": host.id, "name": host.display_name} if host else None,
        "integrity_status": getattr(evidence.integrity_status, "value", evidence.integrity_status),
        "integrity_checked_at": _iso(evidence.integrity_checked_at),
        "processing_status": getattr(evidence.ingest_status, "value", evidence.ingest_status),
        "last_processed_at": _iso(evidence.last_processed_at or evidence.processed_at),
        "events": [serialize_evidence_event(event) for event in events],
    }


def serialize_evidence_event(event: EvidenceCustodyEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "evidence_id": event.evidence_id,
        "event_type": getattr(event.event_type, "value", event.event_type),
        "actor_user_id": event.actor_user_id,
        "timestamp": _iso(event.timestamp),
        "summary": event.summary,
        "details_json": _sanitize_details(event.details_json or {}),
    }


def _integrity_payload(evidence: Evidence, *, actual_sha256: str | None, actual_size_bytes: int | None) -> dict[str, Any]:
    return {
        "evidence_id": evidence.id,
        "case_id": evidence.case_id,
        "sha256": evidence.sha256,
        "size_bytes": evidence.size_bytes,
        "integrity_status": getattr(evidence.integrity_status, "value", evidence.integrity_status),
        "integrity_checked_at": _iso(evidence.integrity_checked_at),
        "actual_sha256": actual_sha256,
        "actual_size_bytes": actual_size_bytes,
    }


def _sanitize_details(value: dict[str, Any]) -> dict[str, Any]:
    blocked = {"stored_path", "original_path", "storage_path", "path", "absolute_path", "upload_path"}
    sanitized: dict[str, Any] = {}
    for key, item in value.items():
        if key in blocked:
            continue
        if isinstance(item, dict):
            sanitized[key] = _sanitize_details(item)
        elif isinstance(item, list):
            sanitized[key] = [_sanitize_details(entry) if isinstance(entry, dict) else entry for entry in item]
        else:
            sanitized[key] = item
    return sanitized


def _user_label(user: Any) -> str | None:
    if user is None:
        return None
    return str(getattr(user, "display_name", None) or getattr(user, "username", None) or getattr(user, "id", None) or "") or None


def _iso(value: Any) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else value
