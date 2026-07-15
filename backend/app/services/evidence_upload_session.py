"""Temporary Upload Session for the ingestion wizard.

Stages an evidence file once, runs Preflight Inspection against the staged
copy (possibly more than once, e.g. after a platform override), and - only
once the analyst confirms Start Processing - promotes the session into a
real Evidence by calling the existing, unmodified upload routes directly
with an UploadFile wrapping the already-staged bytes. The browser never
re-transmits the file for promotion.

This module does not touch app.services.memory.upload_sessions (the
existing resumable/chunked session system for memory dumps) or
app.disk_images.service - both remain exactly as they were. It also never
enqueues a worker job or creates an Evidence row itself; that only happens
inside the real upload_* route functions this module calls at promotion
time, unchanged.

Sessions expire automatically (EVIDENCE_UPLOAD_SESSION_TTL_SECONDS) and are
cleaned up by cleanup_expired_upload_sessions(), mirroring the same expiry
pattern used by MemoryUpload sessions.
"""
from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, BinaryIO
from uuid import uuid4

from fastapi import UploadFile
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utc_now
from app.core.evidence_paths import validate_external_path
from app.core.storage import ensure_within_directory, sanitize_relative_path
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.evidence_upload_session import EvidenceUploadSession, EvidenceUploadSessionStatus
from app.schemas.evidence_preflight import PreflightReport
from app.services.evidence_preflight import run_preflight


class UploadSessionError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class _StagedFile:
    path: Path
    size_bytes: int
    sha256: str


def _session_root(session_id: str) -> Path:
    settings = get_settings()
    return settings.backend_temp_dir / "evidence-upload-sessions" / session_id


def _stage_single_file(upload: UploadFile, root: Path) -> _StagedFile:
    root.mkdir(parents=True, exist_ok=True)
    filename = Path(upload.filename or "upload.bin").name
    target = root / filename
    size = 0
    digest = hashlib.sha256()
    with target.open("wb") as buffer:
        while chunk := upload.file.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
            buffer.write(chunk)
    return _StagedFile(path=target, size_bytes=size, sha256=digest.hexdigest())


def _stage_disk_image_segments(files: list[UploadFile], root: Path) -> tuple[_StagedFile, list[dict[str, str]]]:
    """Stage a multi-segment disk image (split RAW .001/.002/... or EWF .E01/.E02/...).

    The primary (first) segment is staged and returned as the file preflight
    inspects - matching this wizard's historical "preview the first segment"
    behavior. The remaining segments are staged as siblings and their paths
    are returned so promotion can pass the COMPLETE, ordered segment set to
    upload_disk_image; never dropping segments 2..N."""
    primary = _stage_single_file(files[0], root)
    extra_segments: list[dict[str, str]] = []
    for upload in files[1:]:
        filename = Path(upload.filename or "segment.bin").name
        target = root / filename
        with target.open("wb") as buffer:
            while chunk := upload.file.read(1024 * 1024):
                buffer.write(chunk)
        extra_segments.append({"path": str(target), "filename": filename})
    return primary, extra_segments


def _stage_folder(files: list[UploadFile], root: Path) -> _StagedFile:
    folder_root = root / "folder"
    folder_root.mkdir(parents=True, exist_ok=True)
    total_size = 0
    per_file_hashes: list[str] = []
    for upload in sorted(files, key=lambda item: item.filename or ""):
        relative = sanitize_relative_path(upload.filename or "file.bin")
        target = folder_root / relative
        ensure_within_directory(folder_root, target)
        target.parent.mkdir(parents=True, exist_ok=True)
        file_digest = hashlib.sha256()
        size = 0
        with target.open("wb") as buffer:
            while chunk := upload.file.read(1024 * 1024):
                size += len(chunk)
                file_digest.update(chunk)
                buffer.write(chunk)
        total_size += size
        per_file_hashes.append(f"{relative}:{file_digest.hexdigest()}")
    combined = hashlib.sha256()
    combined.update("\n".join(sorted(per_file_hashes)).encode("utf-8"))
    return _StagedFile(path=folder_root, size_bytes=total_size, sha256=combined.hexdigest())


def _hash_existing_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def create_upload_session(
    db: Session,
    case_id: str,
    *,
    files: list[UploadFile] | None = None,
    is_folder: bool = False,
    server_path: str | None = None,
    declared_platform: str | None = None,
    client_sha256: str | None = None,
) -> tuple[EvidenceUploadSession, PreflightReport]:
    if not db.get(Case, case_id):
        raise UploadSessionError("case_not_found", "Case not found")
    if not files and not server_path:
        raise UploadSessionError("no_file", "No file, folder, or server path was provided for preflight inspection.")

    settings = get_settings()
    session_id = str(uuid4())
    expires_at = utc_now() + timedelta(seconds=max(60, int(settings.evidence_upload_session_ttl_seconds)))

    if server_path:
        validation = validate_external_path(server_path)
        if not validation.get("valid"):
            raise UploadSessionError("invalid_server_path", validation.get("message") or "The server path could not be validated for ingestion.")
        staged_path = Path(str(validation["resolved_path"]))
        session = EvidenceUploadSession(
            id=session_id,
            case_id=case_id,
            status=EvidenceUploadSessionStatus.staged.value,
            original_filename=staged_path.name,
            staged_path=str(staged_path),
            is_folder=staged_path.is_dir(),
            is_server_path=True,
            size_bytes=int(validation.get("size_bytes") or (staged_path.stat().st_size if staged_path.is_file() else 0)),
            sha256=_hash_existing_file(staged_path),
            client_sha256=client_sha256,
            declared_platform=declared_platform,
            expires_at=expires_at,
        )
    elif is_folder and files and len(files) > 1:
        staged = _stage_folder(files, _session_root(session_id))
        session = EvidenceUploadSession(
            id=session_id,
            case_id=case_id,
            status=EvidenceUploadSessionStatus.staged.value,
            original_filename=f"{len(files)} files",
            staged_path=str(staged.path),
            is_folder=True,
            is_server_path=False,
            size_bytes=staged.size_bytes,
            sha256=staged.sha256,
            client_sha256=client_sha256,
            declared_platform=declared_platform,
            expires_at=expires_at,
        )
    elif files and len(files) > 1:
        staged, extra_segments = _stage_disk_image_segments(files, _session_root(session_id))
        extra_size = sum(Path(spec["path"]).stat().st_size for spec in extra_segments)
        session = EvidenceUploadSession(
            id=session_id,
            case_id=case_id,
            status=EvidenceUploadSessionStatus.staged.value,
            original_filename=files[0].filename or staged.path.name,
            staged_path=str(staged.path),
            is_folder=False,
            is_server_path=False,
            size_bytes=staged.size_bytes + extra_size,
            sha256=staged.sha256,
            client_sha256=client_sha256,
            declared_platform=declared_platform,
            expires_at=expires_at,
            metadata_json={"extra_segments": extra_segments},
        )
    else:
        assert files is not None
        staged = _stage_single_file(files[0], _session_root(session_id))
        session = EvidenceUploadSession(
            id=session_id,
            case_id=case_id,
            status=EvidenceUploadSessionStatus.staged.value,
            original_filename=files[0].filename or staged.path.name,
            staged_path=str(staged.path),
            is_folder=False,
            is_server_path=False,
            size_bytes=staged.size_bytes,
            sha256=staged.sha256,
            client_sha256=client_sha256,
            declared_platform=declared_platform,
            expires_at=expires_at,
        )

    if client_sha256 and session.sha256 and client_sha256.strip().lower() != session.sha256.lower():
        session.metadata_json = {**(session.metadata_json or {}), "client_sha256_mismatch": True}

    db.add(session)
    db.commit()
    db.refresh(session)

    report = run_preflight(
        Path(session.staged_path),
        token=session.id,
        original_filename=session.original_filename,
        declared_platform=declared_platform,
        tmp_dir=_session_root(session_id) / "scratch",
    )
    session.metadata_json = {**(session.metadata_json or {}), "category": report.classification.category}
    db.add(session)
    db.commit()
    return session, report


def rerun_preflight(session: EvidenceUploadSession, *, declared_platform: str | None) -> PreflightReport:
    return run_preflight(
        Path(session.staged_path),
        token=session.id,
        original_filename=session.original_filename,
        declared_platform=declared_platform,
        tmp_dir=_session_root(session.id) / "scratch",
    )


def _cleanup_storage(session: EvidenceUploadSession) -> None:
    if session.is_server_path:
        return  # never delete the analyst's own file - it was never copied
    root = _session_root(session.id)
    try:
        if root.exists():
            shutil.rmtree(root, ignore_errors=True)
        else:
            path = Path(session.staged_path)
            if path.exists():
                path.unlink(missing_ok=True)
    except OSError:
        pass


def get_active_session(db: Session, case_id: str, session_id: str) -> EvidenceUploadSession:
    session = db.get(EvidenceUploadSession, session_id)
    if session is None or session.case_id != case_id:
        raise UploadSessionError("session_not_found", "Upload session not found.")
    if session.status != EvidenceUploadSessionStatus.staged.value:
        raise UploadSessionError("session_not_active", f"Upload session is '{session.status}', not staged.")
    return session


def cancel_upload_session(db: Session, session: EvidenceUploadSession) -> None:
    _cleanup_storage(session)
    session.status = EvidenceUploadSessionStatus.cancelled.value
    db.add(session)
    db.commit()


def cleanup_expired_upload_sessions(db: Session, *, limit: int = 50) -> dict[str, int]:
    now = utc_now()
    expired = (
        db.query(EvidenceUploadSession)
        .filter(EvidenceUploadSession.status == EvidenceUploadSessionStatus.staged.value, EvidenceUploadSession.expires_at < now)
        .order_by(EvidenceUploadSession.expires_at.asc())
        .limit(limit)
        .all()
    )
    for item in expired:
        _cleanup_storage(item)
        item.status = EvidenceUploadSessionStatus.expired.value
        item.failure_message = "Upload session expired before processing was confirmed."
        db.add(item)
    db.commit()
    return {"expired": len(expired)}


class _StagedUploadFile(UploadFile):
    """An UploadFile wrapping bytes already staged on local disk, so
    save_upload() (app.core.storage) can move rather than re-copy-and-hash
    them. See save_upload's known_sha256/staged_path check."""

    def __init__(self, file: BinaryIO, *, filename: str, size: int, known_sha256: str | None, staged_path: Path):
        super().__init__(file, filename=filename, size=size)
        self._preflight_known_sha256 = known_sha256
        self._preflight_staged_path = staged_path


def _open_staged_upload_file(path: Path, *, filename: str, known_sha256: str | None) -> _StagedUploadFile:
    handle = path.open("rb")
    return _StagedUploadFile(handle, filename=filename, size=path.stat().st_size, known_sha256=known_sha256, staged_path=path)


def promote_upload_session(
    db: Session,
    session: EvidenceUploadSession,
    *,
    provided_platform: str | None,
    host_id: str | None,
    provided_host: str | None,
    evtx_profile: str | None,
    memory_authorization_acknowledged: bool,
    folder_name: str | None,
    labels: list[str] | None,
    notes: str | None,
    current_user: Any,
) -> Evidence:
    from app.api.routes_evidence import RegisterPathRequest, register_evidence_path, upload_disk_image, upload_evidence, upload_evidence_folder

    # NOTE: upload_evidence/upload_disk_image/upload_evidence_folder are
    # FastAPI route functions whose parameter defaults are Form(...)/File(...)
    # sentinel descriptor objects, not usable plain values - those are only
    # resolved by FastAPI's own request handling. Calling them directly here
    # (to reuse their logic without a second HTTP round trip) means every
    # parameter must be passed an explicit, concrete value; relying on any
    # of the functions' own defaults produces a Form(...)/File(...) object
    # instead of None/False and breaks internal string handling.
    case_id = session.case_id
    try:
        if session.is_server_path:
            payload = RegisterPathRequest(
                path=session.staged_path,
                name=None,
                copy_to_storage=True,
                start_ingest=True,
                storage_mode=None,
                artifact_selection=None,
                evidence_intent="mounted",
                packaging="mounted_path",
                ingest_mode=None,
                provided_host=provided_host,
                provided_platform=provided_platform,
                host_id=host_id,
                evtx_profile=evtx_profile,
            )
            evidence = register_evidence_path(case_id, payload, db=db, current_user=current_user)
        elif session.is_folder:
            staged_root = Path(session.staged_path)
            staged_files = sorted(f for f in staged_root.rglob("*") if f.is_file())
            uploads = [
                _open_staged_upload_file(f, filename=str(f.relative_to(staged_root)), known_sha256=None)
                for f in staged_files
            ]
            try:
                evidence = upload_evidence_folder(
                    case_id,
                    uploads,
                    provided_platform=provided_platform,
                    db=db,
                    current_user=current_user,
                )
            finally:
                for upload in uploads:
                    upload.file.close()
        else:
            staged_path = Path(session.staged_path)
            upload = _open_staged_upload_file(staged_path, filename=session.original_filename, known_sha256=session.sha256)
            extra_segment_specs = list((session.metadata_json or {}).get("extra_segments") or [])
            extra_uploads = [
                _open_staged_upload_file(Path(spec["path"]), filename=spec["filename"], known_sha256=None)
                for spec in extra_segment_specs
            ]
            try:
                if session.metadata_json and session.metadata_json.get("category") == "disk_image":
                    evidence = upload_disk_image(
                        case_id,
                        [upload, *extra_uploads],
                        ingest_mode=None,
                        provided_host=provided_host,
                        provided_platform=provided_platform,
                        host_id=host_id,
                        db=db,
                        current_user=current_user,
                    )
                else:
                    evidence = upload_evidence(
                        case_id,
                        upload,
                        folder_upload=False,
                        folder_name=None,
                        evidence_intent="raw",
                        packaging=None,
                        ingest_mode=None,
                        provided_host=provided_host,
                        provided_platform=provided_platform,
                        host_id=host_id,
                        evtx_profile=evtx_profile,
                        memory_authorization_acknowledged=memory_authorization_acknowledged,
                        memory_upload_id=None,
                        db=db,
                        current_user=current_user,
                    )
            finally:
                upload.file.close()
                for extra in extra_uploads:
                    extra.file.close()
    except Exception:
        raise

    session.status = EvidenceUploadSessionStatus.promoted.value
    session.promoted_evidence_id = evidence.id
    db.add(session)
    db.commit()
    _cleanup_storage(session)
    return evidence
