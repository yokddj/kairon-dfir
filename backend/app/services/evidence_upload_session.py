"""Temporary Upload Session for the ingestion wizard.

Stages an evidence file once, runs Preflight Inspection against the staged
copy (possibly more than once, e.g. after a platform override), and - only
once the analyst confirms Start Processing - promotes the session into a
real Evidence by routing to the same canonical backend path used by each
evidence type. The browser never re-transmits the file for promotion.

Generic evidence and disk images still delegate to the existing upload route
functions. Memory dumps delegate to app.services.memory.upload_sessions so the
wizard shares the same canonical registration lifecycle as the memory upload UI.

Sessions expire automatically (EVIDENCE_UPLOAD_SESSION_TTL_SECONDS) and are
cleaned up by cleanup_expired_upload_sessions(), mirroring the same expiry
pattern used by MemoryUpload sessions.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, BinaryIO
from uuid import uuid4

from fastapi import Request, UploadFile
from sqlalchemy.orm import Session
from starlette.requests import ClientDisconnect

from app.core.config import get_settings
from app.core.database import utc_now
from app.core.evidence_paths import validate_external_path
from app.core.storage import ensure_within_directory, sanitize_relative_path
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.evidence_upload_session import EvidenceUploadSession, EvidenceUploadSessionStatus
from app.schemas.evidence_preflight import PreflightReport
from app.services.evidence_operations import sync_upload_operation
from app.services.evidence_preflight import run_preflight

logger = logging.getLogger(__name__)


class UploadSessionError(Exception):
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


@dataclass
class _StagedFile:
    path: Path
    size_bytes: int
    sha256: str


def _session_root(session_id: str) -> Path:
    settings = get_settings()
    return settings.backend_temp_dir / "evidence-upload-sessions" / session_id


def _upload_error_detail(code: str, message: str, **values: Any) -> dict[str, Any]:
    return {"error_code": code, "code": code, "message": message, **values}


def _available_bytes(path: Path) -> int:
    path.mkdir(parents=True, exist_ok=True)
    return shutil.disk_usage(path).free


def _log_upload(event: str, **values: Any) -> None:
    payload = {"timestamp": datetime.now(timezone.utc).isoformat(), **values}
    logger.info("%s %s", event, " ".join(f"{key}={value}" for key, value in payload.items()))


def _preupload_storage_check(*, session_id: str, expected_bytes: int | None, temp_dir: Path, max_bytes: int) -> int:
    started = time.monotonic()
    available = _available_bytes(temp_dir)
    estimated_temp_bytes = expected_bytes or 0
    required_bytes = (expected_bytes or 0) + estimated_temp_bytes
    _log_upload(
        "STORAGE PRECHECK START",
        session_id=session_id,
        expected_bytes=expected_bytes,
        estimated_temp_bytes=estimated_temp_bytes,
        required_bytes=required_bytes,
        available_bytes=available,
        temp_dir=temp_dir,
    )
    if expected_bytes is not None and expected_bytes > max_bytes:
        _log_upload(
            "STORAGE PRECHECK END",
            session_id=session_id,
            status="blocked",
            reason="upload_size_limit",
            duration_s=round(time.monotonic() - started, 3),
            expected_bytes=expected_bytes,
            configured_limit_bytes=max_bytes,
            available_bytes=available,
        )
        raise UploadSessionError(
            "upload_size_limit",
            "Selected evidence exceeds the configured upload limit.",
            _upload_error_detail(
                "upload_size_limit",
                "Selected evidence exceeds the configured upload limit.",
                expected_bytes=expected_bytes,
                configured_limit_bytes=max_bytes,
                available_storage_bytes=available,
                configuration_key="BACKEND_MAX_UPLOAD_SIZE",
                configuration_file="backend/.env",
            ),
        )
    if expected_bytes is not None and available < required_bytes:
        _log_upload(
            "STORAGE PRECHECK END",
            session_id=session_id,
            status="blocked",
            reason="insufficient_storage",
            duration_s=round(time.monotonic() - started, 3),
            expected_bytes=expected_bytes,
            estimated_temp_bytes=estimated_temp_bytes,
            required_bytes=required_bytes,
            available_bytes=available,
        )
        raise UploadSessionError(
            "insufficient_storage",
            "Temporary storage is too low for this upload.",
            _upload_error_detail(
                "insufficient_storage",
                "Temporary storage is too low for this upload.",
                expected_bytes=expected_bytes,
                estimated_temp_storage_bytes=estimated_temp_bytes,
                required_storage_bytes=required_bytes,
                available_storage_bytes=available,
                temp_directory=str(temp_dir),
                configuration_key="BACKEND_TEMP_DIR",
                configuration_file="backend/.env",
            ),
        )
    _log_upload(
        "STORAGE PRECHECK END",
        session_id=session_id,
        status="ok",
        duration_s=round(time.monotonic() - started, 3),
        expected_bytes=expected_bytes,
        estimated_temp_bytes=estimated_temp_bytes,
        required_bytes=required_bytes,
        available_bytes=available,
    )
    return available


def _build_session_from_staged(
    db: Session,
    *,
    case_id: str,
    session_id: str,
    staged: _StagedFile,
    original_filename: str,
    is_folder: bool,
    is_server_path: bool,
    declared_platform: str | None,
    client_sha256: str | None,
    metadata: dict[str, Any] | None = None,
) -> EvidenceUploadSession:
    settings = get_settings()
    expires_at = utc_now() + timedelta(seconds=max(60, int(settings.evidence_upload_session_ttl_seconds)))
    session = EvidenceUploadSession(
        id=session_id,
        case_id=case_id,
        status=EvidenceUploadSessionStatus.staged.value,
        original_filename=original_filename,
        staged_path=str(staged.path),
        is_folder=is_folder,
        is_server_path=is_server_path,
        size_bytes=staged.size_bytes,
        sha256=staged.sha256,
        client_sha256=client_sha256,
        declared_platform=declared_platform,
        expires_at=expires_at,
        metadata_json=metadata or {},
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


def _touch_upload_session(session: EvidenceUploadSession) -> None:
    session.last_activity_at = utc_now()
    settings = get_settings()
    session.expires_at = utc_now() + timedelta(seconds=max(60, int(settings.evidence_upload_session_ttl_seconds)))


def create_resumable_upload_session(
    db: Session,
    case_id: str,
    *,
    filename: str,
    expected_size_bytes: int,
    declared_platform: str | None = None,
    client_sha256: str | None = None,
) -> EvidenceUploadSession:
    if not db.get(Case, case_id):
        raise UploadSessionError("case_not_found", "Case not found")
    if expected_size_bytes <= 0:
        raise UploadSessionError("invalid_size", "Expected upload size must be greater than zero.")
    settings = get_settings()
    session_id = str(uuid4())
    root = _session_root(session_id)
    root.mkdir(parents=True, exist_ok=True)
    target = root / Path(filename or "upload.bin").name
    _preupload_storage_check(session_id=session_id, expected_bytes=expected_size_bytes, temp_dir=settings.backend_temp_dir, max_bytes=int(settings.backend_max_upload_size))
    session = EvidenceUploadSession(
        id=session_id,
        case_id=case_id,
        status=EvidenceUploadSessionStatus.created.value,
        original_filename=target.name,
        staged_path=str(target),
        is_folder=False,
        is_server_path=False,
        size_bytes=0,
        expected_size_bytes=expected_size_bytes,
        bytes_received=0,
        client_sha256=client_sha256,
        declared_platform=declared_platform,
        expires_at=utc_now() + timedelta(seconds=max(60, int(settings.evidence_upload_session_ttl_seconds))),
        last_activity_at=utc_now(),
        metadata_json={"upload_mode": "resumable", "current_stage": "upload"},
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    sync_upload_operation(db, session)
    return session


def get_upload_session(db: Session, case_id: str, session_id: str) -> EvidenceUploadSession:
    session = db.get(EvidenceUploadSession, session_id)
    if session is None or session.case_id != case_id:
        raise UploadSessionError("session_not_found", "Upload session not found.")
    return session


def append_resumable_upload_chunk(
    db: Session,
    session: EvidenceUploadSession,
    *,
    offset: int,
    body: BinaryIO,
) -> EvidenceUploadSession:
    if session.status not in {EvidenceUploadSessionStatus.created.value, EvidenceUploadSessionStatus.uploading.value, EvidenceUploadSessionStatus.interrupted.value}:
        raise UploadSessionError("session_not_uploading", f"Upload session is '{session.status}', not uploadable.")
    target = Path(session.staged_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    current_size = target.stat().st_size if target.exists() else 0
    if offset != current_size or offset != int(session.bytes_received or 0):
        raise UploadSessionError("offset_mismatch", "Upload offset does not match the server-confirmed offset.", {"expected_offset": current_size, "received_offset": offset})
    max_bytes = int(get_settings().backend_max_upload_size)
    written = current_size
    try:
        with target.open("ab") as buffer:
            while chunk := body.read(1024 * 1024):
                next_size = written + len(chunk)
                if next_size > max_bytes or (session.expected_size_bytes is not None and next_size > int(session.expected_size_bytes)):
                    raise UploadSessionError("upload_size_limit", "Upload exceeded the configured size limit.")
                buffer.write(chunk)
                written = next_size
            buffer.flush()
            os.fsync(buffer.fileno())
    except UploadSessionError:
        raise
    except Exception as exc:
        session.status = EvidenceUploadSessionStatus.interrupted.value
        session.failure_message = f"Upload interrupted: {exc.__class__.__name__}"
        session.bytes_received = target.stat().st_size if target.exists() else written
        _touch_upload_session(session)
        db.add(session)
        db.commit()
        sync_upload_operation(db, session)
        raise
    session.bytes_received = written
    session.size_bytes = written
    session.status = EvidenceUploadSessionStatus.uploading.value if session.expected_size_bytes is None or written < int(session.expected_size_bytes) else EvidenceUploadSessionStatus.uploading.value
    session.failure_message = None
    _touch_upload_session(session)
    db.add(session)
    db.commit()
    db.refresh(session)
    sync_upload_operation(db, session)
    return session


def finalize_resumable_upload_session(db: Session, session: EvidenceUploadSession) -> tuple[EvidenceUploadSession, PreflightReport]:
    if session.status == EvidenceUploadSessionStatus.staged.value:
        report = run_preflight(Path(session.staged_path), token=session.id, original_filename=session.original_filename, declared_platform=session.declared_platform, tmp_dir=_session_root(session.id) / "scratch")
        session.metadata_json = {**(session.metadata_json or {}), "category": report.classification.category, "current_stage": "preflight_complete"}
        session.failure_message = None
        _touch_upload_session(session)
        db.add(session)
        db.commit()
        db.refresh(session)
        sync_upload_operation(db, session)
        return session, report
    if session.status not in {EvidenceUploadSessionStatus.uploading.value, EvidenceUploadSessionStatus.interrupted.value, EvidenceUploadSessionStatus.created.value}:
        raise UploadSessionError("session_not_uploading", f"Upload session is '{session.status}', not ready to finalize.")
    path = Path(session.staged_path)
    size = path.stat().st_size if path.exists() else 0
    if session.expected_size_bytes is not None and size != int(session.expected_size_bytes):
        session.status = EvidenceUploadSessionStatus.interrupted.value
        session.bytes_received = size
        session.size_bytes = size
        session.failure_message = "Upload is incomplete. Resume from the confirmed offset before finalizing."
        _touch_upload_session(session)
        db.add(session)
        db.commit()
        sync_upload_operation(db, session)
        raise UploadSessionError("upload_incomplete", session.failure_message, {"bytes_received": size, "expected_bytes": session.expected_size_bytes})
    session.status = EvidenceUploadSessionStatus.preflight_running.value
    session.bytes_received = size
    session.size_bytes = size
    _touch_upload_session(session)
    db.add(session)
    db.commit()
    digest = _hash_existing_file(path)
    session.sha256 = digest
    if session.client_sha256 and digest and session.client_sha256.strip().lower() != digest.lower():
        session.metadata_json = {**(session.metadata_json or {}), "client_sha256_mismatch": True}
    report = run_preflight(path, token=session.id, original_filename=session.original_filename, declared_platform=session.declared_platform, tmp_dir=_session_root(session.id) / "scratch")
    session.status = EvidenceUploadSessionStatus.staged.value
    session.metadata_json = {**(session.metadata_json or {}), "category": report.classification.category, "current_stage": "preflight_complete"}
    session.failure_message = None
    _touch_upload_session(session)
    db.add(session)
    db.commit()
    db.refresh(session)
    sync_upload_operation(db, session)
    return session, report


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


async def _stage_streamed_file(
    request: Request,
    *,
    session_id: str,
    filename: str,
    expected_bytes: int | None,
) -> _StagedFile:
    settings = get_settings()
    root = _session_root(session_id)
    root.mkdir(parents=True, exist_ok=True)
    target = root / Path(filename or "upload.bin").name
    temp_dir = settings.backend_temp_dir
    max_bytes = int(settings.backend_max_upload_size)
    idle_timeout = max(1, int(settings.backend_upload_idle_timeout_seconds))
    available = _preupload_storage_check(session_id=session_id, expected_bytes=expected_bytes, temp_dir=temp_dir, max_bytes=max_bytes)

    started = time.monotonic()
    last_progress = started
    last_log = started
    size = 0
    digest = hashlib.sha256()
    stream = request.stream().__aiter__()
    cleaned = False
    first_byte_logged = False
    next_threshold = 10
    _log_upload(
        "UPLOAD START",
        session_id=session_id,
        filename=target.name,
        expected_bytes=expected_bytes,
        temp_dir=temp_dir,
        available_bytes=available,
    )

    try:
        with target.open("xb") as buffer:
            while True:
                try:
                    chunk = await asyncio.wait_for(stream.__anext__(), timeout=idle_timeout)
                    _log_upload("APP CHUNK", session_id=session_id, chunk_size=len(chunk), total_bytes_before=size, expected_bytes=expected_bytes)
                except StopAsyncIteration:
                    _log_upload("STREAM EXHAUSTED", session_id=session_id, received_bytes=size)
                    break
                except asyncio.TimeoutError as exc:
                    current_size = target.stat().st_size if target.exists() else size
                    last_progress_age = time.monotonic() - last_progress
                    available_now = _available_bytes(temp_dir)
                    _log_upload(
                        "UPLOAD STALLED",
                        session_id=session_id,
                        received_bytes=size,
                        written_bytes=current_size,
                        last_progress_age_s=round(last_progress_age, 3),
                        staged_file_size=current_size,
                        available_bytes=available_now,
                    )
                    raise UploadSessionError(
                        "upload_idle_timeout",
                        f"No upload progress was received for {idle_timeout} seconds.",
                        _upload_error_detail(
                            "upload_idle_timeout",
                            f"No upload progress was received for {idle_timeout} seconds.",
                            received_bytes=size,
                            expected_bytes=expected_bytes,
                            last_progress_age_seconds=round(last_progress_age, 3),
                            available_storage_bytes=available_now,
                            temp_directory=str(temp_dir),
                            configuration_key="BACKEND_UPLOAD_IDLE_TIMEOUT_SECONDS",
                            configuration_file="backend/.env",
                        ),
                    ) from exc
                except ClientDisconnect as exc:
                    current_size = target.stat().st_size if target.exists() else size
                    raise UploadSessionError(
                        "client_disconnected",
                        "The client disconnected before all evidence bytes reached the server.",
                        _upload_error_detail(
                            "client_disconnected",
                            "The client disconnected before all evidence bytes reached the server.",
                            received_bytes=size,
                            expected_bytes=expected_bytes,
                            staged_file_size=current_size,
                        ),
                    ) from exc
                if not chunk:
                    continue
                if not first_byte_logged:
                    first_byte_logged = True
                    _log_upload(
                        "UPLOAD FIRST BYTE",
                        session_id=session_id,
                        duration_s=round(time.monotonic() - started, 3),
                        expected_bytes=expected_bytes,
                        available_bytes=_available_bytes(temp_dir),
                    )
                next_size = size + len(chunk)
                if next_size > max_bytes or (expected_bytes is not None and next_size > expected_bytes):
                    raise UploadSessionError(
                        "upload_size_limit",
                        "Upload exceeded the configured size limit.",
                        _upload_error_detail(
                            "upload_size_limit",
                            "Upload exceeded the configured size limit.",
                            received_bytes=next_size,
                            expected_bytes=expected_bytes,
                            configured_limit_bytes=max_bytes,
                            configuration_key="BACKEND_MAX_UPLOAD_SIZE",
                            configuration_file="backend/.env",
                        ),
                    )
                try:
                    digest.update(chunk)
                    buffer.write(chunk)
                except OSError as exc:
                    available_now = _available_bytes(temp_dir)
                    raise UploadSessionError(
                        "write_failed",
                        "Kairon could not write the upload to temporary storage.",
                        _upload_error_detail(
                            "write_failed",
                            "Kairon could not write the upload to temporary storage.",
                            received_bytes=size,
                            expected_bytes=expected_bytes,
                            available_storage_bytes=available_now,
                            temp_directory=str(temp_dir),
                        ),
                    ) from exc
                size = next_size
                last_progress = time.monotonic()
                elapsed = max(last_progress - started, 0.001)
                if expected_bytes:
                    percent_int = int((size / expected_bytes) * 100)
                    while next_threshold <= 100 and percent_int >= next_threshold:
                        written = target.stat().st_size if target.exists() else size
                        _log_upload(
                            f"UPLOAD {next_threshold}%",
                            session_id=session_id,
                            received_bytes=size,
                            written_bytes=written,
                            percent=next_threshold,
                            duration_s=round(elapsed, 3),
                            available_bytes=_available_bytes(temp_dir),
                        )
                        next_threshold += 10
                if last_progress - last_log >= 5 or (expected_bytes is not None and size == expected_bytes):
                    written = target.stat().st_size if target.exists() else size
                    percent = round((size / expected_bytes) * 100, 2) if expected_bytes else None
                    speed = round((size / 1024 / 1024) / elapsed, 3)
                    _log_upload(
                        "UPLOAD PROGRESS",
                        session_id=session_id,
                        received_bytes=size,
                        written_bytes=written,
                        percent=percent,
                        speed_mib_s=speed,
                        average_speed_mib_s=speed,
                        last_progress_age_s=0,
                        available_bytes=_available_bytes(temp_dir),
                    )
                    last_log = last_progress
            buffer.flush()
            os.fsync(buffer.fileno())
        if expected_bytes is not None and size != expected_bytes:
            raise UploadSessionError(
                "staging_failed",
                "Transferred evidence size did not match the declared size.",
                _upload_error_detail("staging_failed", "Transferred evidence size did not match the declared size.", received_bytes=size, expected_bytes=expected_bytes),
            )
        duration = time.monotonic() - started
        _log_upload(
            "UPLOAD COMPLETE",
            session_id=session_id,
            received_bytes=size,
            written_bytes=target.stat().st_size,
            duration_s=round(duration, 3),
            average_speed_mib_s=round((size / 1024 / 1024) / max(duration, 0.001), 3),
        )
        _log_upload("SHA256 END", session_id=session_id, sha256=digest.hexdigest(), bytes=size, duration_s=round(duration, 3), status="ok")
        return _StagedFile(path=target, size_bytes=size, sha256=digest.hexdigest())
    except Exception:
        if target.exists():
            target.unlink(missing_ok=True)
            cleaned = True
        _log_upload("UPLOAD CLEANUP", session_id=session_id, cleanup_result=cleaned)
        raise


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
    sync_upload_operation(db, session)

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
    sync_upload_operation(db, session)
    return session, report


async def create_streamed_upload_session(
    db: Session,
    case_id: str,
    *,
    request: Request,
    filename: str,
    expected_bytes: int | None,
    declared_platform: str | None = None,
    client_sha256: str | None = None,
) -> tuple[EvidenceUploadSession, PreflightReport]:
    if not db.get(Case, case_id):
        raise UploadSessionError("case_not_found", "Case not found")
    if not filename:
        raise UploadSessionError("no_file", "No file name was provided for upload.")
    session_id = str(uuid4())
    try:
        staged = await _stage_streamed_file(request, session_id=session_id, filename=filename, expected_bytes=expected_bytes)
        settings = get_settings()
        expires_at = utc_now() + timedelta(seconds=max(60, int(settings.evidence_upload_session_ttl_seconds)))
        session = EvidenceUploadSession(
            id=session_id,
            case_id=case_id,
            status=EvidenceUploadSessionStatus.staged.value,
            original_filename=Path(filename).name,
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
            session.metadata_json = {"client_sha256_mismatch": True}
        db.add(session)
        db.commit()
        db.refresh(session)
        sync_upload_operation(db, session)
        return session
    except Exception:
        root = _session_root(session_id)
        if root.exists():
            shutil.rmtree(root, ignore_errors=True)
        raise


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
    sync_upload_operation(db, session)


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
        sync_upload_operation(db, item, commit=False)
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
    from app.api.routes_evidence import RegisterPathRequest, _actor_label, _current_user_id, register_evidence_path, upload_disk_image, upload_evidence, upload_evidence_folder
    from app.models.evidence import EvidenceType
    from app.services.host_resolution import assign_evidence_host as service_assign_evidence_host, resolve_host
    from app.services.memory.upload_sessions import create_memory_upload_session_from_staged_file, finalize_memory_upload_session

    # NOTE: upload_evidence/upload_disk_image/upload_evidence_folder are
    # FastAPI route functions whose parameter defaults are Form(...)/File(...)
    # sentinel descriptor objects, not usable plain values - those are only
    # resolved by FastAPI's own request handling. Calling them directly here
    # (to reuse their logic without a second HTTP round trip) means every
    # parameter must be passed an explicit, concrete value; relying on any
    # of the functions' own defaults produces a Form(...)/File(...) object
    # instead of None/False and breaks internal string handling.
    case_id = session.case_id
    promotion_started = time.monotonic()
    _log_upload(
        "PROMOTION START",
        session_id=session.id,
        case_id=case_id,
        staged_path=session.staged_path,
        bytes=session.size_bytes,
        category=(session.metadata_json or {}).get("category"),
    )
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
                    provided_host=provided_host,
                    host_id=host_id,
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
                category = (session.metadata_json or {}).get("category")
                if category == "disk_image":
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
                elif category == "memory_dump":
                    try:
                        host_resolution = resolve_host(
                            db,
                            case_id=case_id,
                            evidence_type=EvidenceType.memory_dump,
                            host_id=host_id,
                            provided_host=provided_host,
                            allow_create=True,
                        )
                    except Exception as exc:
                        raise UploadSessionError(
                            "MEMORY_UPLOAD_HOST_REQUIRED",
                            "Source host is required for memory evidence registration.",
                        ) from exc
                    host_label = host_resolution.display_name or ""
                    memory_upload = create_memory_upload_session_from_staged_file(
                        db,
                        case_id=case_id,
                        filename=session.original_filename,
                        staged_path=staged_path,
                        expected_size_bytes=int(session.size_bytes or staged_path.stat().st_size),
                        provided_host=host_label,
                        authorization_acknowledged=memory_authorization_acknowledged,
                        expected_sha256=session.sha256,
                        metadata={
                            "evidence_intent": "raw",
                            "packaging": "single_file",
                            "ingest_mode": None,
                            "provided_platform": provided_platform,
                            "evtx_profile": evtx_profile,
                            "authorization_acknowledged": bool(memory_authorization_acknowledged),
                            "uploaded_by_user_id": _current_user_id(current_user),
                            "source_upload_session_id": session.id,
                            "source_upload_session_kind": "unified_evidence_wizard",
                        },
                    )
                    _finalized, evidence = finalize_memory_upload_session(
                        db,
                        case_id=case_id,
                        upload_id=memory_upload.id,
                        expected_sha256=session.sha256,
                    )
                    if evidence is None:
                        raise UploadSessionError("memory_registration_failed", "Memory upload finalization did not create an Evidence row.")
                    if host_resolution.host_id:
                        evidence = service_assign_evidence_host(
                            db,
                            evidence,
                            host_id=host_resolution.host_id,
                            actor_user_id=_current_user_id(current_user),
                            actor=_actor_label(current_user),
                            reason="Assigned during evidence ingestion wizard",
                            method="upload_assignment",
                            host_created=host_resolution.created,
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
    except Exception as exc:
        _log_upload(
            "PROMOTION END",
            session_id=session.id,
            case_id=case_id,
            status="error",
            error_type=type(exc).__name__,
            duration_s=round(time.monotonic() - promotion_started, 3),
        )
        raise

    session.status = EvidenceUploadSessionStatus.promoted.value
    session.promoted_evidence_id = evidence.id
    db.add(session)
    db.commit()
    sync_upload_operation(db, session)
    _cleanup_storage(session)
    _log_upload(
        "PROMOTION END",
        session_id=session.id,
        case_id=case_id,
        evidence_id=evidence.id,
        status="ok",
        duration_s=round(time.monotonic() - promotion_started, 3),
    )
    return evidence
