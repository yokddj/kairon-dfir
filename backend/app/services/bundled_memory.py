"""Registering a memory image found inside a collection as its own memory evidence.

A collection (a ZIP, a folder upload) sometimes carries a memory capture next to the triage files.
The ingest flags it (app.ingest.bundled_evidence) but does not analyse it with the collection: a
memory image is analysed only as memory evidence. Uploading the same multi-gigabyte file again to
get there is what this avoids: the member is already on the server, extracted.

The registration goes through the path a browser upload takes -- a new upload session whose staged
file is the member (hard-linked, so nothing is copied when it can be avoided), then the worker's
preflight (SHA-256, content classification, kernel scan) and the normal promotion -- so the new
evidence is hashed, classified and processed exactly like any memory upload. It records where it
came from: the source evidence and the member's path inside it.
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.storage import build_evidence_root, sanitize_relative_path
from app.models.evidence import Evidence

logger = logging.getLogger(__name__)


class BundledMemoryError(ValueError):
    """A problem the analyst can act on; the message is safe to show."""


def _listed_member(evidence: Evidence, member_path: str) -> dict[str, Any]:
    for entry in (evidence.metadata_json or {}).get("bundled_evidence") or []:
        if isinstance(entry, dict) and entry.get("path") == member_path:
            if entry.get("kind") != "memory_dump":
                raise BundledMemoryError("Only a memory image found in the collection can be registered as memory evidence.")
            return entry
    raise BundledMemoryError("That file is not listed as a memory image of this evidence.")


def member_file(evidence: Evidence, member_path: str) -> Path:
    """The extracted member on disk, confined to the evidence's extraction directory."""
    root = (build_evidence_root(evidence.case_id, evidence.id) / "extracted").resolve()
    try:
        relative = sanitize_relative_path(member_path)
    except ValueError as exc:
        raise BundledMemoryError("Invalid member path.") from exc
    candidate = (root / relative).resolve()
    if root not in candidate.parents:
        raise BundledMemoryError("Invalid member path.")
    if not candidate.is_file():
        raise BundledMemoryError("The extracted file is no longer on the server (the collection may have been re-indexed or cleaned); upload it on its own.")
    return candidate


def _place(source: Path, target: Path) -> str:
    """Hard-link ``source`` at ``target`` (same file system: instant, no extra space), else copy."""
    target.parent.mkdir(parents=True, exist_ok=True)
    target.unlink(missing_ok=True)
    try:
        os.link(source, target)
        return "hardlink"
    except OSError:
        shutil.copyfile(source, target)
        return "copy"


def _set_member_state(db: Session, evidence: Evidence, member_path: str, **state: Any) -> None:
    db.refresh(evidence)
    metadata = dict(evidence.metadata_json or {})
    listed = []
    for entry in metadata.get("bundled_evidence") or []:
        if isinstance(entry, dict) and entry.get("path") == member_path:
            entry = {**entry, **state}
        listed.append(entry)
    metadata["bundled_evidence"] = listed
    evidence.metadata_json = metadata
    db.add(evidence)
    db.commit()


def start_registration(db: Session, evidence: Evidence, member_path: str, *, host_id: str | None, provided_host: str | None, current_user: Any = None) -> Any:
    """Create the upload session for the member and queue its preflight and promotion."""
    from app.services.evidence_operations import sync_upload_operation
    from app.services.evidence_upload_session import create_resumable_upload_session
    from app.workers.tasks import enqueue_bundled_memory_registration

    entry = _listed_member(evidence, member_path)
    if entry.get("registered_evidence_id"):
        raise BundledMemoryError("This memory image is already registered as its own evidence.")
    if entry.get("registration_status") in {"queued", "running"}:
        raise BundledMemoryError("This memory image is already being registered.")
    if not (host_id or (provided_host or "").strip()):
        raise BundledMemoryError("Choose the host this memory image was captured on.")
    source = member_file(evidence, member_path)
    size = source.stat().st_size
    session = create_resumable_upload_session(db, evidence.case_id, filename=source.name, expected_size_bytes=size, declared_platform=None, reuse_existing=False)
    placement = _place(source, Path(session.staged_path))
    session.bytes_received = session.size_bytes = size
    session.status = "uploading"
    session.metadata_json = {
        **(session.metadata_json or {}),
        "upload_mode": "bundled_member",
        "bundled_source": {"evidence_id": evidence.id, "path": member_path, "placement": placement},
        "bundled_promotion": {
            "host_id": host_id,
            "provided_host": (provided_host or "").strip() or None,
            "user_id": getattr(current_user, "id", None),
        },
    }
    db.add(session)
    db.commit()
    db.refresh(session)
    sync_upload_operation(db, session)
    _set_member_state(db, evidence, member_path, registration_status="queued", registration_session_id=session.id, registration_error=None)
    enqueue_bundled_memory_registration(session.id)
    return session


def run_registration(upload_session_id: str) -> dict[str, Any]:
    """Worker side: preflight the staged member like an upload, then register it as memory."""
    from app.core.database import SessionLocal
    from app.models.evidence_upload_session import EvidenceUploadSession
    from app.models.user import User
    from app.services.evidence_upload_session import promote_upload_session
    from app.workers.tasks import run_evidence_upload_preflight

    with SessionLocal() as db:
        session = db.get(EvidenceUploadSession, upload_session_id)
        if session is None:
            return {"status": "missing_session", "upload_session_id": upload_session_id}
        source = dict((session.metadata_json or {}).get("bundled_source") or {})
        options = dict((session.metadata_json or {}).get("bundled_promotion") or {})
        parent = db.get(Evidence, source.get("evidence_id"))
        member_path = str(source.get("path") or "")
        parent_name = parent.original_filename if parent is not None else str(source.get("evidence_id"))
        if parent is not None:
            _set_member_state(db, parent, member_path, registration_status="running")

    def fail(message: str) -> dict[str, Any]:
        with SessionLocal() as db:
            parent_row = db.get(Evidence, source.get("evidence_id"))
            if parent_row is not None:
                _set_member_state(db, parent_row, member_path, registration_status="failed", registration_error=message)
        logger.warning("bundled memory registration failed", extra={"upload_session_id": upload_session_id, "error": message})
        return {"status": "failed", "upload_session_id": upload_session_id, "error": message}

    try:
        preflight = run_evidence_upload_preflight(upload_session_id)
        with SessionLocal() as db:
            session = db.get(EvidenceUploadSession, upload_session_id)
            category = (session.metadata_json or {}).get("category")
            if session.status != "staged":
                return fail(session.failure_message or f"The inspection did not complete ({preflight.get('status')}).")
            if category != "memory_dump":
                return fail("The inspection did not confirm a memory image (no memory header, firmware tables or kernel found); upload it on its own and choose Memory.")
            user = db.get(User, options.get("user_id")) if options.get("user_id") else None
            evidence = promote_upload_session(
                db,
                session,
                provided_platform=None,
                host_id=options.get("host_id"),
                provided_host=options.get("provided_host"),
                evtx_profile=None,
                memory_authorization_acknowledged=True,
                folder_name=None,
                labels=[],
                notes=f"Memory image found in evidence {parent_name} at {member_path}; registered from the extracted file without uploading it again.",
                current_user=user,
                evidence_intent=None,
                ingest_mode=None,
                forced_evidence_kind=None,
                archive_password=None,
            )
            evidence.metadata_json = {**(evidence.metadata_json or {}), "bundled_source": {"evidence_id": source.get("evidence_id"), "path": member_path}}
            # The memory registration keeps wizard notes elsewhere; the provenance must be visible.
            provenance = f"Memory image found in evidence {parent_name} at {member_path}; registered from the extracted file without uploading it again."
            if provenance not in (evidence.notes or ""):
                evidence.notes = f"{evidence.notes}\n{provenance}".strip() if evidence.notes else provenance
            db.add(evidence)
            db.commit()
            new_id = evidence.id
            parent_row = db.get(Evidence, source.get("evidence_id"))
            if parent_row is not None:
                _set_member_state(db, parent_row, member_path, registration_status="registered", registered_evidence_id=new_id, registration_error=None)
        return {"status": "registered", "upload_session_id": upload_session_id, "evidence_id": new_id}
    except Exception as exc:  # noqa: BLE001
        logger.exception("bundled memory registration crashed", extra={"upload_session_id": upload_session_id})
        message = getattr(exc, "message", None) or str(exc) or exc.__class__.__name__
        return fail(message[:300])
