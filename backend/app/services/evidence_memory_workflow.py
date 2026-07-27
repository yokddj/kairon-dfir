"""Post-finalize workflow handler for Evidence Wizard memory_dump uploads
routed through the unified chunk-index backend (see
``app.core.config.Settings.unified_upload_evidence_memory_dump`` and
``app.services.evidence_unified_upload`` -- the shared session-creation/
reconciliation layer also used by the disk_image workflow).

Registered under the ``"evidence_memory_dump"`` name in
``app.services.upload_shared.workflow``. Session ownership is fixed at
creation time: ``create_unified_upload_session`` stamps
``MemoryUpload.metadata_json["workflow"] = "evidence_memory_dump"`` once,
and ``finalize_memory_upload_session`` reads that key to pick the handler --
so a session created under this workflow can never be finalized by the
plain ``"memory"`` handler, or vice versa.

Reuses ``register_memory_evidence_from_upload`` -- the exact same critical
registration transaction Memory Overview uses -- for the canonical
Evidence row, host auto-resolution from the free-text hostname, and
custody events (``uploaded``, ``hash_computed``, ``host_assigned``). This
handler only layers the two things that transaction cannot know about
because they are Wizard-only concepts: an explicitly-chosen case host
(as opposed to a free-text hostname string) and Wizard notes.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.ingest.evidence_classifier import EvidenceCategory, get_evidence_classifier
from app.models.evidence import Evidence
from app.models.memory import MemoryUpload
from app.services.host_resolution import assign_evidence_host
from app.services.memory.upload_lifecycle import _canonical_path, _valid_regular_file, register_memory_evidence_from_upload
from app.services.memory.upload_sessions import MemoryUploadSessionError
from app.services.upload_shared.workflow import register_workflow_handler


def register_evidence_memory_dump(upload_id: str, db: Session) -> Evidence:
    item = db.get(MemoryUpload, upload_id)
    if item is None:
        raise MemoryUploadSessionError("memory_upload_missing", f"Unified memory upload {upload_id} was not found.")
    canonical = _canonical_path(item)
    if not item.sha256 or not _valid_regular_file(canonical, int(item.expected_bytes)):
        raise MemoryUploadSessionError("memory_file_missing", "Canonical memory image file is missing or has the wrong size.")
    classification = get_evidence_classifier().classify(canonical)
    if classification.category == EvidenceCategory.DISK_IMAGE:
        raise MemoryUploadSessionError(
            "classification_conflict_disk",
            f"This upload was requested as memory evidence, but content detection classified it as a disk image: {classification.reason}",
            detail={"detected_kind": classification.category.value, "confidence": classification.confidence, "reason": classification.reason, "metadata": classification.metadata},
        )
    if classification.category == EvidenceCategory.AUXILIARY:
        raise MemoryUploadSessionError(
            "classification_conflict_auxiliary",
            f"This upload was requested as memory evidence, but content detection classified it as auxiliary: {classification.reason}",
            detail={"detected_kind": classification.category.value, "confidence": classification.confidence, "reason": classification.reason, "metadata": classification.metadata},
        )
    evidence = register_memory_evidence_from_upload(upload_id, db=db)
    metadata = dict(item.metadata_json or {}) if item is not None else {}

    notes = metadata.get("wizard_notes")
    if notes and evidence.notes != notes:
        evidence.notes = str(notes)[:2048]
        db.add(evidence)
        db.commit()
        db.refresh(evidence)

    explicit_host_id = metadata.get("wizard_host_id")
    if explicit_host_id and evidence.host_id != explicit_host_id:
        evidence = assign_evidence_host(
            db,
            evidence,
            host_id=explicit_host_id,
            actor_user_id=metadata.get("uploaded_by_user_id"),
            actor="evidence_wizard",
            reason="Assigned during evidence ingestion wizard",
            method="upload_assignment",
        )
        db.commit()
        db.refresh(evidence)

    return evidence


register_workflow_handler("evidence_memory_dump", register_evidence_memory_dump)
