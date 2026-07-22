"""Post-finalize workflow handler for Evidence Wizard single-file archive
uploads routed through the unified chunk-index backend (see
``app.core.config.Settings.unified_upload_evidence_archive`` and
``app.services.evidence_unified_upload``).

Registered under the ``"archive"`` name in ``app.services.upload_shared.workflow``.
Session ownership is fixed at creation time (same mechanism as
``evidence_memory_dump``/``disk_image``): ``create_unified_upload_session``
stamps ``MemoryUpload.metadata_json["workflow"] = "archive"`` once, and
``finalize_memory_upload_session`` reads that key to pick the handler.

Scope: a single uploaded file whose extension is one of
``.zip .7z .tar .tar.gz .gz .xz`` (see
``app.services.memory.upload_sessions._allowed_archive_extension``, enforced
at session creation so an unsupported archive is rejected before any bytes
transfer). Folder uploads, server-path ingestion, multi-file uploads, and
multi-segment EWF are explicitly out of scope and stay on the legacy
``evidence_upload_session.promote_upload_session`` path, which has no
per-category branch for a plain single-file archive at all -- it falls
through to a bare ``else`` that calls ``routes_evidence.upload_evidence``
directly (see the legacy-backend audit). This handler reproduces that exact
call, unlike the disk_image workflow handler, which reconstructs
``Evidence`` by hand: ``upload_evidence`` already performs the archive
classification (raw-collection vs. generic, via
``is_supported_archive_container``/``detect_evidence_type``) which is
non-trivial and would otherwise have to be duplicated here, and it is the
same function ``promote_upload_session`` already calls today for this exact
category -- calling it directly is more faithful reuse, not less, matching
how ``promote_upload_session`` itself calls ``upload_disk_image``/
``upload_evidence_folder``/``register_evidence_path`` as plain functions.

Extraction is NOT performed here or anywhere in this module.
``upload_evidence`` ends by calling ``enqueue_ingest``, which schedules the
worker's ``ingest_evidence`` task; extraction (``app.ingest.archive.extract_archive``)
happens there, asynchronously, identically for archives uploaded through
this path or through the legacy multipart path -- upload and extraction
were already architecturally separated before this migration, so nothing
new needed to be built to satisfy that requirement.

One real difference from disk_image/memory_dump: ``upload_evidence`` calls
``app.core.storage.save_upload``, which mints its OWN fresh ``evidence_id``
(it has no notion of a pre-reserved id) rather than reusing
``MemoryUpload.evidence_id`` the way the unified backend pre-allocates it at
session creation. So this handler explicitly re-points
``item.evidence_id`` at the real created Evidence's id afterward -- without
that, ``finalize_memory_upload_session``'s already-completed fast path and
``evidence_unified_upload.sync_unified_session`` would keep resolving the
wrong (never-created) id.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.evidence import Evidence
from app.models.memory import MemoryUpload
from app.models.user import User
from app.services.memory.upload_lifecycle import _canonical_path, _valid_regular_file
from app.services.memory.upload_sessions import MemoryUploadSessionError
from app.services.upload_shared.workflow import register_workflow_handler


def register_archive_evidence(upload_id: str, db: Session) -> Evidence:
    from app.api.routes_evidence import upload_evidence  # service-level registration entry point, not a network hop -- see module docstring
    from app.services.evidence_upload_session import _open_staged_upload_file

    item = db.get(MemoryUpload, upload_id)
    if item is None:
        raise MemoryUploadSessionError("archive_upload_missing", f"Unified archive upload {upload_id} was not found.")

    existing = db.get(Evidence, item.evidence_id) if item.evidence_id else None
    if existing is not None:
        return existing

    canonical = _canonical_path(item)
    if not item.sha256 or not _valid_regular_file(canonical, int(item.expected_bytes)):
        raise MemoryUploadSessionError("archive_file_missing", "Canonical archive file is missing or has the wrong size.")

    metadata = dict(item.metadata_json or {})
    current_user = db.get(User, metadata.get("uploaded_by_user_id")) if metadata.get("uploaded_by_user_id") else None

    upload_file = _open_staged_upload_file(canonical, filename=item.display_name, known_sha256=item.sha256)
    try:
        evidence = upload_evidence(
            item.case_id,
            upload_file,
            folder_upload=False,
            folder_name=None,
            evidence_intent="raw",
            packaging=None,
            ingest_mode=None,
            provided_host=None,
            provided_platform=metadata.get("provided_platform"),
            host_id=metadata.get("wizard_host_id"),
            evtx_profile=None,
            memory_authorization_acknowledged=False,
            memory_upload_id=None,
            db=db,
            current_user=current_user,
        )
    finally:
        upload_file.file.close()

    # save_upload() (invoked inside upload_evidence) minted its own
    # evidence_id and moved the canonical bytes under it -- point the
    # unified session at the real id it now lives under. The now-empty
    # original canonical directory (this upload_id's own, never shared
    # with anything else) is tidied up best-effort; leaving it behind
    # would be harmless but untidy, not a correctness issue.
    item.evidence_id = evidence.id
    item.status = "completed"
    item.retryable = False
    db.commit()

    try:
        original_dir = canonical.parent
        if original_dir.is_dir() and not any(original_dir.iterdir()):
            original_dir.rmdir()
            evidence_root = original_dir.parent
            if evidence_root.is_dir() and not any(evidence_root.iterdir()):
                evidence_root.rmdir()
    except OSError:
        pass

    return evidence


register_workflow_handler("archive", register_archive_evidence)
