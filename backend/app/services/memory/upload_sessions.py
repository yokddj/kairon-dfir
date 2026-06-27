from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
from datetime import timedelta
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from fastapi import Request
import redis
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utc_now_naive
from app.core.storage import safe_display_filename
from app.models.evidence import Evidence, EvidenceType
from app.models.memory import MemoryUpload
from app.services.memory.evidence_access import secure_uploaded_memory_permissions
from app.services.memory.upload_lifecycle import (
    ERR_REGISTRATION_DUPLICATE,
    MemoryUploadRegistrationError,
    create_memory_upload,
    get_memory_upload,
    public_memory_upload_status,
    register_memory_evidence,
    update_memory_upload,
    _canonical_path,
    _find_duplicate_memory_evidence,
)


ACTIVE_UPLOAD_SESSION_STATUSES = {"created", "uploading", "verifying", "finalizing"}
TERMINAL_UPLOAD_SESSION_STATUSES = {"completed", "cancelled", "expired", "failed", "inconsistent"}
_CLEANUP_LOCK_KEY = "kairon:memory_uploads:cleanup_lock"
_CLEANUP_INTERVAL_SECONDS = 300


class MemoryUploadSessionError(RuntimeError):
    def __init__(self, code: str, message: str, *, detail: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail or {}


def _session_metadata(item: MemoryUpload) -> dict[str, Any]:
    return dict(item.metadata_json or {})


def _write_session_metadata(item: MemoryUpload, metadata: dict[str, Any]) -> None:
    item.metadata_json = metadata


def _received_chunks(item: MemoryUpload) -> dict[str, dict[str, Any]]:
    metadata = _session_metadata(item)
    chunks = metadata.get("received_chunks")
    if not isinstance(chunks, dict):
        return {}
    return {
        str(key): value
        for key, value in chunks.items()
        if isinstance(value, dict)
    }


def _set_received_chunks(item: MemoryUpload, chunks: dict[str, dict[str, Any]]) -> None:
    metadata = _session_metadata(item)
    metadata["received_chunks"] = chunks
    _write_session_metadata(item, metadata)


def _session_root(item: MemoryUpload) -> Path:
    staging_root = get_settings().memory_upload_staging_path.resolve()
    session_root = (staging_root / item.staging_name).resolve()
    session_root.relative_to(staging_root)
    return session_root


def _chunk_dir(item: MemoryUpload) -> Path:
    return _session_root(item) / "chunks"


def _chunk_path(item: MemoryUpload, chunk_index: int) -> Path:
    return _chunk_dir(item) / f"{chunk_index:08d}.chunk"


def _assembly_temp_path(item: MemoryUpload) -> Path:
    return _session_root(item) / f"assembly-{uuid4()}.part"


def _sanitize_sha256(value: str | None) -> str | None:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return None
    if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
        raise MemoryUploadSessionError("MEMORY_UPLOAD_INVALID_SHA256", "Client-declared SHA-256 is malformed.")
    return normalized


def _allowed_memory_extension(filename: str) -> str:
    extension = Path(filename).suffix.lower()
    if extension not in get_settings().memory_upload_extensions:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_UNSUPPORTED_EXTENSION", "This file extension is not enabled for memory upload.")
    return extension


def _active_upload_reservation_bytes(db: Session, *, exclude_upload_id: str | None = None) -> int:
    query = db.query(MemoryUpload).filter(MemoryUpload.status.in_(tuple(ACTIVE_UPLOAD_SESSION_STATUSES)))
    if exclude_upload_id:
        query = query.filter(MemoryUpload.id != exclude_upload_id)
    return sum(int(item.expected_bytes or 0) for item in query.all())


def _case_memory_usage_bytes(db: Session, case_id: str, *, exclude_upload_id: str | None = None) -> int:
    evidence_total = sum(
        int(item.size_bytes or 0)
        for item in db.query(Evidence)
        .filter(Evidence.case_id == case_id, Evidence.evidence_type == EvidenceType.memory_dump)
        .all()
    )
    upload_query = db.query(MemoryUpload).filter(
        MemoryUpload.case_id == case_id,
        MemoryUpload.status.in_(tuple(ACTIVE_UPLOAD_SESSION_STATUSES)),
    )
    if exclude_upload_id:
        upload_query = upload_query.filter(MemoryUpload.id != exclude_upload_id)
    reserved_total = sum(int(item.expected_bytes or 0) for item in upload_query.all())
    return evidence_total + reserved_total


def _available_bytes(path: Path) -> int:
    path.mkdir(parents=True, exist_ok=True)
    return int(shutil.disk_usage(path).free)


def _capacity_snapshot(db: Session, *, expected_bytes: int, exclude_upload_id: str | None = None) -> dict[str, int | str | bool]:
    settings = get_settings()
    staging_root = settings.memory_upload_staging_path
    final_root = settings.backend_data_dir / "evidence"
    output_root = settings.memory_output_root or final_root
    staging_available = _available_bytes(staging_root)
    final_available = _available_bytes(final_root)
    output_available = _available_bytes(output_root)
    same_fs = staging_root.resolve().stat().st_dev == final_root.resolve().stat().st_dev
    reserved = _active_upload_reservation_bytes(db, exclude_upload_id=exclude_upload_id)
    min_free = int(settings.memory_upload_min_free_space_bytes or 0)
    output_allowance = max(int(settings.memory_plugin_output_max_bytes or 0), 256 * 1024 * 1024)
    staging_required = expected_bytes + min_free + reserved
    final_required = (expected_bytes if not same_fs else 0) + min_free + reserved
    output_required = output_allowance + min_free
    accepted = (
        staging_available >= staging_required
        and final_available >= final_required
        and output_available >= output_required
    )
    return {
        "staging_available_bytes": staging_available,
        "canonical_storage_available_bytes": final_available,
        "memory_output_available_bytes": output_available,
        "required_capacity_bytes": max(staging_required, final_required, output_required),
        "finalization_strategy": "atomic_move" if same_fs else "staged_copy",
        "can_accept_selected_size": accepted,
    }


def _touch_session(item: MemoryUpload) -> None:
    ttl = max(300, int(get_settings().memory_upload_session_ttl_seconds or 86400))
    now = utc_now_naive()
    item.progress_at = now
    item.updated_at = now
    item.expires_at = now + timedelta(seconds=ttl)


def create_memory_upload_session(
    db: Session,
    *,
    case_id: str,
    filename: str,
    expected_size_bytes: int,
    provided_host: str,
    authorization_acknowledged: bool,
    expected_sha256: str | None = None,
) -> MemoryUpload:
    settings = get_settings()
    if not bool(settings.memory_upload_enabled):
        raise MemoryUploadSessionError("MEMORY_UPLOAD_DISABLED", "Memory image upload is disabled by server configuration.")
    if not authorization_acknowledged:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_AUTHORIZATION_REQUIRED", "Authorization acknowledgement is required before uploading RAM evidence.")
    if expected_size_bytes <= 0:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_INVALID_SIZE", "Expected upload size must be greater than zero.")
    max_bytes = int(settings.memory_upload_max_bytes or settings.memory_max_upload_size or 0)
    if expected_size_bytes > max_bytes:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_TOO_LARGE", "Selected file exceeds the configured memory upload size limit.")
    extension = _allowed_memory_extension(filename)
    safe_name = safe_display_filename(filename)
    provided_host = str(provided_host or "").strip()
    if not provided_host:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_HOST_REQUIRED", "Source host is required for memory evidence registration.")

    conflicting = (
        db.query(MemoryUpload)
        .filter(
            MemoryUpload.case_id == case_id,
            MemoryUpload.display_name == safe_name,
            MemoryUpload.status.in_(tuple(ACTIVE_UPLOAD_SESSION_STATUSES)),
        )
        .order_by(MemoryUpload.created_at.desc())
        .first()
    )
    if conflicting is not None:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_CONFLICT", "Another upload session for this memory image is already active.")

    case_quota = int(settings.memory_upload_case_quota_bytes or 0)
    case_usage = _case_memory_usage_bytes(db, case_id)
    if case_usage + expected_size_bytes > case_quota:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_CASE_QUOTA_EXCEEDED", "This case has reached its configured memory upload quota.")

    capacity = _capacity_snapshot(db, expected_bytes=expected_size_bytes)
    if not bool(capacity["can_accept_selected_size"]):
        raise MemoryUploadSessionError("MEMORY_UPLOAD_INSUFFICIENT_SPACE", "Server storage capacity is below the safe threshold for this memory image.")

    chunk_size = max(1024 * 1024, int(settings.memory_upload_chunk_size_bytes or 0))
    total_chunks = max(1, math.ceil(expected_size_bytes / chunk_size))
    upload = create_memory_upload(
        upload_id=str(uuid4()),
        case_id=case_id,
        expected_bytes=expected_size_bytes,
        display_name=safe_name,
        source_host=provided_host,
        extension=extension,
        metadata={
            "received_chunks": {},
            "resumable": True,
            "provided_host": provided_host,
        },
        db=db,
        initial_status="created",
        chunk_size_bytes=chunk_size,
        total_chunks=total_chunks,
        expected_sha256=_sanitize_sha256(expected_sha256),
        staging_name=str(uuid4()),
    )
    upload.received_chunk_count = 0
    upload.bytes_received = 0
    _touch_session(upload)
    db.add(upload)
    db.commit()
    db.refresh(upload)
    _chunk_dir(upload).mkdir(parents=True, exist_ok=True)
    return upload


async def store_memory_upload_chunk(
    db: Session,
    *,
    case_id: str,
    upload_id: str,
    chunk_index: int,
    request: Request,
) -> MemoryUpload:
    item = get_memory_upload(db, case_id, upload_id)
    if item is None:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_NOT_FOUND", "Memory upload session was not found.")
    if item.status in TERMINAL_UPLOAD_SESSION_STATUSES:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_TERMINAL", "This upload session is already in a terminal state.")
    if chunk_index < 0 or chunk_index >= int(item.total_chunks or 0):
        raise MemoryUploadSessionError("MEMORY_UPLOAD_INVALID_CHUNK_INDEX", "Chunk index is outside the upload session range.")
    if item.expires_at and item.expires_at < utc_now_naive():
        item.status = "expired"
        item.failure_code = "MEMORY_UPLOAD_SESSION_EXPIRED"
        item.failure_message = "This upload session expired before the chunk was received."
        db.commit()
        raise MemoryUploadSessionError(item.failure_code, item.failure_message)

    expected_size = int(item.expected_bytes or 0)
    chunk_size = int(item.chunk_size_bytes or 0)
    expected_length = min(chunk_size, expected_size - (chunk_index * chunk_size))
    content_length = request.headers.get("content-length")
    if content_length is not None and int(content_length) != expected_length:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_INVALID_CHUNK_LENGTH", "Chunk length does not match the expected byte range.")

    declared_chunk_sha = _sanitize_sha256(request.headers.get("x-kairon-chunk-sha256"))
    chunks = _received_chunks(item)
    existing = chunks.get(str(chunk_index))
    if existing is not None:
        existing_size = int(existing.get("size") or 0)
        existing_sha = str(existing.get("sha256") or "")
        if existing_size == expected_length and (not declared_chunk_sha or existing_sha == declared_chunk_sha):
            return item

    target_dir = _chunk_dir(item)
    target_dir.mkdir(parents=True, exist_ok=True)
    temp_path = target_dir / f"{chunk_index:08d}.{uuid4()}.part"
    final_path = _chunk_path(item, chunk_index)
    digest = hashlib.sha256()
    bytes_written = 0

    with temp_path.open("xb") as handle:
        async for chunk in request.stream():
            if not chunk:
                continue
            bytes_written += len(chunk)
            if bytes_written > expected_length:
                handle.close()
                temp_path.unlink(missing_ok=True)
                raise MemoryUploadSessionError("MEMORY_UPLOAD_CHUNK_TOO_LARGE", "Chunk payload exceeds the configured chunk size.")
            digest.update(chunk)
            handle.write(chunk)
        handle.flush()
        os.fsync(handle.fileno())

    computed_sha = digest.hexdigest()
    if bytes_written != expected_length:
        temp_path.unlink(missing_ok=True)
        raise MemoryUploadSessionError("MEMORY_UPLOAD_INVALID_CHUNK_LENGTH", "Chunk payload is incomplete.")
    if declared_chunk_sha and declared_chunk_sha != computed_sha:
        temp_path.unlink(missing_ok=True)
        raise MemoryUploadSessionError("MEMORY_UPLOAD_CHUNK_HASH_MISMATCH", "Chunk integrity verification failed.")

    if final_path.exists():
        existing_meta = chunks.get(str(chunk_index)) or {}
        if int(existing_meta.get("size") or 0) == bytes_written and str(existing_meta.get("sha256") or "") == computed_sha:
            temp_path.unlink(missing_ok=True)
            return item
        temp_path.unlink(missing_ok=True)
        raise MemoryUploadSessionError("MEMORY_UPLOAD_CHUNK_CONFLICT", "Chunk data conflicts with bytes already stored for this upload session.")

    os.replace(temp_path, final_path)
    dir_fd = os.open(str(target_dir), os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)

    chunks[str(chunk_index)] = {"size": bytes_written, "sha256": computed_sha}
    _set_received_chunks(item, chunks)
    item.received_chunk_count = len(chunks)
    item.bytes_received = sum(int(chunk.get("size") or 0) for chunk in chunks.values())
    item.status = "uploading"
    item.failure_code = None
    item.failure_message = None
    _touch_session(item)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def _cleanup_session_storage(item: MemoryUpload) -> None:
    session_root = _session_root(item)
    if session_root.exists() and not session_root.is_symlink():
        shutil.rmtree(session_root, ignore_errors=True)


def finalize_memory_upload_session(
    db: Session,
    *,
    case_id: str,
    upload_id: str,
    expected_sha256: str | None = None,
) -> tuple[MemoryUpload, Evidence | None]:
    item = get_memory_upload(db, case_id, upload_id)
    if item is None:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_NOT_FOUND", "Memory upload session was not found.")
    if item.status in {"completed", "cancelled", "expired", "inconsistent"}:
        return item, db.get(Evidence, item.evidence_id) if item.status == "completed" else None

    expected_client_sha = _sanitize_sha256(expected_sha256 or item.expected_sha256)
    chunks = _received_chunks(item)
    missing_chunks = [index for index in range(int(item.total_chunks or 0)) if str(index) not in chunks]
    if missing_chunks:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_CHUNKS_MISSING", "Upload session is missing one or more chunks.", detail={"missing_chunks": missing_chunks})

    capacity = _capacity_snapshot(db, expected_bytes=int(item.expected_bytes or 0), exclude_upload_id=item.id)
    if not bool(capacity["can_accept_selected_size"]):
        raise MemoryUploadSessionError("MEMORY_UPLOAD_INSUFFICIENT_SPACE", "Server storage capacity is below the safe threshold for finalization.")

    final_path = _canonical_path(item)
    final_path.parent.mkdir(parents=True, exist_ok=True)
    assembly_path = _assembly_temp_path(item)
    digest = hashlib.sha256()
    total_bytes = 0
    item.status = "verifying"
    item.failure_code = None
    item.failure_message = None
    _touch_session(item)
    db.add(item)
    db.commit()

    try:
        with assembly_path.open("xb") as target:
            for index in range(int(item.total_chunks or 0)):
                chunk_path = _chunk_path(item, index)
                with chunk_path.open("rb") as source:
                    for blob in iter(lambda: source.read(1024 * 1024), b""):
                        total_bytes += len(blob)
                        digest.update(blob)
                        target.write(blob)
            target.flush()
            os.fsync(target.fileno())

        computed_sha = digest.hexdigest()
        if total_bytes != int(item.expected_bytes or 0):
            raise MemoryUploadSessionError("MEMORY_UPLOAD_FINAL_SIZE_MISMATCH", "Finalized byte count does not match the declared upload size.")
        if expected_client_sha and computed_sha != expected_client_sha:
            raise MemoryUploadSessionError("MEMORY_UPLOAD_SHA256_MISMATCH", "Finalized SHA-256 does not match the client integrity hint.")

        item.sha256 = computed_sha
        duplicate = _find_duplicate_memory_evidence(db, item)
        if duplicate is not None:
            _cleanup_session_storage(item)
            final_root = final_path.parent.parent
            if final_root.exists() and not final_root.is_symlink():
                shutil.rmtree(final_root, ignore_errors=True)
            item.status = "failed"
            item.failure_code = ERR_REGISTRATION_DUPLICATE
            item.failure_message = "This memory image is already registered in this case."
            item.retryable = False
            _touch_session(item)
            metadata = _session_metadata(item)
            metadata["duplicate"] = {
                "existing_evidence_id": duplicate.id,
                "existing_filename": duplicate.original_filename,
            }
            _write_session_metadata(item, metadata)
            db.add(item)
            db.commit()
            raise MemoryUploadSessionError(
                ERR_REGISTRATION_DUPLICATE,
                item.failure_message,
                detail={
                    "existing_evidence_id": duplicate.id,
                    "existing_filename": duplicate.original_filename,
                    "duplicate": True,
                },
            )

        item.status = "finalizing"
        item.finalized_at = utc_now_naive()
        item.bytes_received = total_bytes
        item.received_chunk_count = int(item.total_chunks or 0)
        _touch_session(item)
        db.add(item)
        db.commit()

        os.replace(assembly_path, final_path)
        secure_uploaded_memory_permissions(final_path, settings=get_settings())
        dir_fd = os.open(str(final_path.parent), os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

        evidence = register_memory_evidence(item.id, db=db)
        _cleanup_session_storage(item)
        db.refresh(item)
        return item, evidence
    except MemoryUploadRegistrationError as exc:
        raise MemoryUploadSessionError(exc.code, exc.message, detail={
            "duplicate": exc.code == ERR_REGISTRATION_DUPLICATE,
            "existing_evidence_id": exc.existing_evidence_id,
            "existing_filename": exc.existing_filename,
        }) from exc
    except Exception as exc:
        if assembly_path.exists() and not assembly_path.is_symlink():
            assembly_path.unlink(missing_ok=True)
        item.status = "failed"
        item.failure_code = getattr(exc, "code", None) or "MEMORY_UPLOAD_FINALIZATION_FAILED"
        item.failure_message = str(exc)[:512]
        item.retryable = True
        _touch_session(item)
        db.add(item)
        db.commit()
        raise


def cancel_memory_upload_session(db: Session, *, case_id: str, upload_id: str, reason: str | None = None) -> MemoryUpload:
    item = get_memory_upload(db, case_id, upload_id)
    if item is None:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_NOT_FOUND", "Memory upload session was not found.")
    if item.status == "completed":
        raise MemoryUploadSessionError("MEMORY_UPLOAD_ALREADY_COMPLETED", "Completed uploads cannot be cancelled.")
    if item.status in {"cancelled", "expired", "failed", "inconsistent"}:
        return item
    _cleanup_session_storage(item)
    item.status = "cancelled"
    item.retryable = False
    item.failure_code = "MEMORY_UPLOAD_CANCELLED"
    item.failure_message = (reason or "Operator requested cancel")[:512]
    _touch_session(item)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def cleanup_expired_memory_upload_sessions(db: Session, *, limit: int = 50) -> dict[str, int]:
    now = utc_now_naive()
    cleanup_age = max(60, int(get_settings().memory_upload_cleanup_age_seconds or 86400))
    expired = (
        db.query(MemoryUpload)
        .filter(
            MemoryUpload.status.in_(tuple(ACTIVE_UPLOAD_SESSION_STATUSES)),
            MemoryUpload.expires_at.isnot(None),
            MemoryUpload.expires_at < now,
        )
        .order_by(MemoryUpload.expires_at.asc())
        .limit(limit)
        .all()
    )
    removed = 0
    for item in expired:
        _cleanup_session_storage(item)
        item.status = "expired"
        item.failure_code = "MEMORY_UPLOAD_SESSION_EXPIRED"
        item.failure_message = "Upload session expired without receiving the remaining chunks."
        item.retryable = False
        item.updated_at = now
        db.add(item)
        removed += 1

    terminal_cutoff = now - timedelta(seconds=cleanup_age)
    stale_terminal = (
        db.query(MemoryUpload)
        .filter(
            MemoryUpload.status.in_(("cancelled", "failed", "expired")),
            MemoryUpload.updated_at < terminal_cutoff,
        )
        .order_by(MemoryUpload.updated_at.asc())
        .limit(limit)
        .all()
    )
    purged = 0
    for item in stale_terminal:
        _cleanup_session_storage(item)
        purged += 1

    db.commit()
    return {"expired": removed, "purged": purged}


def schedule_periodic_cleanup_if_needed() -> bool:
    try:
        redis_conn = redis.Redis.from_url(get_settings().redis_url)
    except Exception:
        return False
    acquired = redis_conn.set(_CLEANUP_LOCK_KEY, "1", nx=True, ex=_CLEANUP_INTERVAL_SECONDS)
    if not acquired:
        return False
    try:
        from app.workers.tasks import _enqueue_memory_upload_cleanup

        _enqueue_memory_upload_cleanup()
        return True
    except Exception:
        redis_conn.delete(_CLEANUP_LOCK_KEY)
        return False


def run_periodic_cleanup() -> str:
    from app.core.database import SessionLocal

    db = SessionLocal()
    try:
        stats = cleanup_expired_memory_upload_sessions(db)
        return json.dumps(stats, sort_keys=True)
    finally:
        db.close()


def upload_status_with_chunks(item: MemoryUpload, *, db: Session | None = None) -> dict[str, Any]:
    payload = public_memory_upload_status(item, db=db)
    total_chunks = int(item.total_chunks or 0)
    received = sorted(int(index) for index in _received_chunks(item).keys())
    missing = [index for index in range(total_chunks) if index not in set(received)]
    payload.update(
        {
            "case_id": item.case_id,
            "expected_sha256": item.expected_sha256,
            "chunk_size_bytes": int(item.chunk_size_bytes or 0),
            "total_chunks": total_chunks,
            "received_chunk_count": int(item.received_chunk_count or len(received)),
            "received_chunks": received,
            "missing_chunks": missing,
            "progress_percent": int((int(item.bytes_received or 0) * 100) / max(1, int(item.expected_bytes or 1))),
            "created_at": item.created_at,
            "expires_at": item.expires_at,
            "finalized_at": item.finalized_at,
            "failure_message": item.failure_message,
        }
    )
    duplicate = _session_metadata(item).get("duplicate")
    if isinstance(duplicate, dict):
        payload["duplicate"] = duplicate
    return payload
