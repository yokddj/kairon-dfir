from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import shutil
import time
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any, AsyncIterable, Iterable, Mapping
from uuid import uuid4

from fastapi import Request, UploadFile
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
_LOCK_TTL_SECONDS = 1800

logger = logging.getLogger(__name__)


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


def _session_upload_mode(item: MemoryUpload) -> str:
    mode = str(_session_metadata(item).get("upload_mode") or "resumable").strip().lower()
    return mode if mode in {"direct", "resumable"} else "resumable"


def _active_chunk_indices(item: MemoryUpload) -> list[int]:
    active = _session_metadata(item).get("active_chunks")
    if not isinstance(active, list):
        return []
    indices: list[int] = []
    for value in active:
        try:
            index = int(value)
        except (TypeError, ValueError):
            continue
        if index >= 0:
            indices.append(index)
    return sorted(set(indices))


def _set_active_chunk(item: MemoryUpload, chunk_index: int, active: bool) -> None:
    metadata = _session_metadata(item)
    current = set(_active_chunk_indices(item))
    if active:
        current.add(int(chunk_index))
    else:
        current.discard(int(chunk_index))
    metadata["active_chunks"] = sorted(current)
    _write_session_metadata(item, metadata)


@contextmanager
def _redis_upload_lock(key: str, *, ttl: int = _LOCK_TTL_SECONDS):
    token = str(uuid4())
    redis_conn: redis.Redis | None = None
    acquired = False
    try:
        redis_conn = redis.Redis.from_url(get_settings().redis_url)
        acquired = bool(redis_conn.set(key, token, nx=True, ex=ttl))
    except Exception:  # noqa: BLE001 - tests commonly run without Redis
        if "PYTEST_CURRENT_TEST" not in os.environ:
            raise MemoryUploadSessionError("MEMORY_UPLOAD_LOCK_UNAVAILABLE", "Upload locking backend is unavailable. Retry later.")
        acquired = True
        redis_conn = None
    if not acquired:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_LOCKED", "This upload session is busy. Retry shortly.")
    try:
        yield
    finally:
        if redis_conn is not None:
            try:
                script = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"
                redis_conn.eval(script, 1, key, token)
            except Exception:  # noqa: BLE001
                logger.warning("memory upload lock release failed", extra={"lock_key": key})


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
    upload_mode: str | None = None,
    file_fingerprint: str | None = None,
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
            MemoryUpload.expected_bytes == expected_size_bytes,
            MemoryUpload.status.in_(tuple(ACTIVE_UPLOAD_SESSION_STATUSES)),
        )
        .order_by(MemoryUpload.created_at.desc())
        .first()
    )
    if conflicting is not None:
        received = sorted(int(index) for index in _received_chunks(conflicting).keys())
        conflicting_fingerprint = (_session_metadata(conflicting).get("file_fingerprint") or None)
        raise MemoryUploadSessionError(
            "MEMORY_UPLOAD_ACTIVE_SESSION_EXISTS",
            "Another upload session for this memory image is already active.",
            detail={
                "existing_upload_id": str(conflicting.id),
                "filename": conflicting.display_name,
                "expected_bytes": int(conflicting.expected_bytes or 0),
                "received_bytes": int(conflicting.bytes_received or 0),
                "received_chunk_count": int(conflicting.received_chunk_count or len(received)),
                "total_chunks": int(conflicting.total_chunks or 0),
                "status": conflicting.status,
                "resumable": True,
                "expires_at": conflicting.expires_at.isoformat() if conflicting.expires_at else None,
                "cancellable": conflicting.status in {"created", "validating", "uploading", "verifying", "finalizing"},
                "file_fingerprint": conflicting_fingerprint,
            },
        )

    case_quota = int(settings.memory_upload_case_quota_bytes or 0)
    case_usage = _case_memory_usage_bytes(db, case_id)
    if case_usage + expected_size_bytes > case_quota:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_CASE_QUOTA_EXCEEDED", "This case has reached its configured memory upload quota.")

    capacity = _capacity_snapshot(db, expected_bytes=expected_size_bytes)
    if not bool(capacity["can_accept_selected_size"]):
        raise MemoryUploadSessionError("MEMORY_UPLOAD_INSUFFICIENT_SPACE", "Server storage capacity is below the safe threshold for this memory image.")

    threshold = int(getattr(settings, "memory_upload_direct_threshold_bytes", 1073741824) or 1073741824)
    selected_mode = str(upload_mode or "resumable").strip().lower()
    if selected_mode not in {"direct", "resumable"}:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_INVALID_MODE", "Upload mode must be direct or resumable.")
    if selected_mode == "direct" and expected_size_bytes > threshold:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_DIRECT_TOO_LARGE", "Direct upload is only allowed below the configured threshold.")
    if selected_mode == "direct":
        chunk_size = expected_size_bytes
    else:
        chunk_size = max(
            int(settings.memory_upload_chunk_size_min_bytes or 1048576),
            min(
                int(settings.memory_upload_chunk_size_max_bytes or 268435456),
                int(settings.memory_upload_chunk_size_bytes or 67108864),
            ),
        )
    total_chunks = max(1, math.ceil(expected_size_bytes / chunk_size))
    sampled_fingerprint = _sanitize_sha256(file_fingerprint)
    upload = create_memory_upload(
        upload_id=str(uuid4()),
        case_id=case_id,
        expected_bytes=expected_size_bytes,
        display_name=safe_name,
        source_host=provided_host,
        extension=extension,
        metadata={
            "received_chunks": {},
            "active_chunks": [],
            "upload_mode": selected_mode,
            "resumable": selected_mode == "resumable",
            "provided_host": provided_host,
            "direct_threshold_bytes": threshold,
            "file_fingerprint": sampled_fingerprint,
            "default_concurrency": min(
                int(getattr(settings, "memory_upload_default_concurrency", 2) or 2),
                int(getattr(settings, "memory_upload_max_concurrency", 4) or 4),
            ),
            "max_concurrency": int(getattr(settings, "memory_upload_max_concurrency", 4) or 4),
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
    expected_mode: str = "resumable",
) -> MemoryUpload:
    return await store_memory_upload_chunk_stream(
        db,
        case_id=case_id,
        upload_id=upload_id,
        chunk_index=chunk_index,
        chunks=request.stream(),
        headers=request.headers,
        content_length_is_payload=True,
        expected_mode=expected_mode,
    )


async def iter_upload_file_chunks(upload_file: UploadFile, *, block_size: int = 1024 * 1024) -> AsyncIterable[bytes]:
    while True:
        chunk = await upload_file.read(block_size)
        if not chunk:
            break
        yield chunk


async def store_memory_upload_chunk_stream(
    db: Session,
    *,
    case_id: str,
    upload_id: str,
    chunk_index: int,
    chunks: AsyncIterable[bytes],
    headers: Mapping[str, str],
    content_length_is_payload: bool,
    expected_mode: str = "resumable",
) -> MemoryUpload:
    request_started = time.monotonic()
    item = get_memory_upload(db, case_id, upload_id)
    if item is None:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_NOT_FOUND", "Memory upload session was not found.")
    if item.status in TERMINAL_UPLOAD_SESSION_STATUSES:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_TERMINAL", "This upload session is already in a terminal state.")
    if item.status in {"verifying", "finalizing"}:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_FINALIZING", "Upload finalization is already in progress.")
    if _session_upload_mode(item) != expected_mode:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_MODE_CONFLICT", "Upload endpoint does not match this session mode.")
    if chunk_index < 0 or chunk_index >= int(item.total_chunks or 0):
        raise MemoryUploadSessionError("MEMORY_UPLOAD_INVALID_CHUNK_INDEX", "Chunk index is outside the upload session range.")
    if item.expires_at and item.expires_at < utc_now_naive():
        item.status = "expired"
        item.failure_code = "MEMORY_UPLOAD_SESSION_EXPIRED"
        item.failure_message = "This upload session expired before the chunk was received."
        db.commit()
        raise MemoryUploadSessionError(item.failure_code, item.failure_message)

    integrity = check_memory_upload_staging_integrity(item)
    integrity_status = integrity["integrity_status"]
    if integrity_status not in (_STAGING_INTEGRITY_HEALTHY, _STAGING_INTEGRITY_EXTRA_CHUNKS):
        item.status = "failed"
        item.failure_code = "MEMORY_UPLOAD_STAGING_INCONSISTENT"
        item.failure_message = f"Staging integrity check failed: {integrity_status}. Restart the upload from the beginning."
        item.retryable = True
        item.failure_code = f"MEMORY_UPLOAD_STAGING_{integrity_status.upper()}"
        db.add(item)
        db.commit()
        raise MemoryUploadSessionError(
            item.failure_code,
            item.failure_message,
            detail={"integrity_status": integrity_status, "missing_chunks": integrity.get("missing_db_chunks_on_disk", [])},
        )

    expected_size = int(item.expected_bytes or 0)
    chunk_size = int(item.chunk_size_bytes or 0)
    expected_length = min(chunk_size, expected_size - (chunk_index * chunk_size))
    content_length = headers.get("content-length") if content_length_is_payload else None
    if content_length is not None and int(content_length) != expected_length:
        raise MemoryUploadSessionError("MEMORY_UPLOAD_INVALID_CHUNK_LENGTH", "Chunk length does not match the expected byte range.")

    declared_chunk_sha = _sanitize_sha256(headers.get("x-kairon-chunk-sha256"))
    received_chunks = _received_chunks(item)
    existing = received_chunks.get(str(chunk_index))
    if existing is not None:
        existing_size = int(existing.get("size") or 0)
        existing_sha = str(existing.get("sha256") or "")
        chunk_path = _chunk_path(item, chunk_index)
        file_exists = chunk_path.exists() and chunk_path.is_file() and not chunk_path.is_symlink()
        if existing_size == expected_length and file_exists and (not declared_chunk_sha or existing_sha == declared_chunk_sha):
            return item

    with _redis_upload_lock(f"kairon:memory_upload:{upload_id}:chunk:{chunk_index}"):
        db.refresh(item)
        if item.status in TERMINAL_UPLOAD_SESSION_STATUSES or item.status in {"verifying", "finalizing"}:
            raise MemoryUploadSessionError("MEMORY_UPLOAD_FINALIZING", "Upload finalization or cancellation is already in progress.")
        received_chunks = _received_chunks(item)
        existing = received_chunks.get(str(chunk_index))
        if existing is not None:
            existing_size = int(existing.get("size") or 0)
            existing_sha = str(existing.get("sha256") or "")
            chunk_path = _chunk_path(item, chunk_index)
            file_exists = chunk_path.exists() and chunk_path.is_file() and not chunk_path.is_symlink()
            if existing_size == expected_length and file_exists and (not declared_chunk_sha or existing_sha == declared_chunk_sha):
                return item
        _set_active_chunk(item, chunk_index, True)
        db.add(item)
        db.commit()

        try:
            target_dir = _chunk_dir(item)
            target_dir.mkdir(parents=True, exist_ok=True)
            temp_path = target_dir / f"{chunk_index:08d}.{uuid4()}.part"
            final_path = _chunk_path(item, chunk_index)
            digest = hashlib.sha256()
            bytes_written = 0
            receive_hash_write_ms = 0
            file_fsync_ms = 0
            dir_fsync_ms = 0

            with temp_path.open("xb") as handle:
                phase_started = time.monotonic()
                async for chunk in chunks:
                    if not chunk:
                        continue
                    bytes_written += len(chunk)
                    if bytes_written > expected_length:
                        handle.close()
                        temp_path.unlink(missing_ok=True)
                        raise MemoryUploadSessionError("MEMORY_UPLOAD_CHUNK_TOO_LARGE", "Chunk payload exceeds the configured chunk size.")
                    digest.update(chunk)
                    handle.write(chunk)
                receive_hash_write_ms = int((time.monotonic() - phase_started) * 1000)
                handle.flush()
                fsync_started = time.monotonic()
                os.fsync(handle.fileno())
                file_fsync_ms = int((time.monotonic() - fsync_started) * 1000)

            computed_sha = digest.hexdigest()
            if bytes_written != expected_length:
                temp_path.unlink(missing_ok=True)
                raise MemoryUploadSessionError("MEMORY_UPLOAD_INVALID_CHUNK_LENGTH", "Chunk payload is incomplete.")
            if declared_chunk_sha and declared_chunk_sha != computed_sha:
                temp_path.unlink(missing_ok=True)
                raise MemoryUploadSessionError("MEMORY_UPLOAD_CHUNK_HASH_MISMATCH", "Chunk integrity verification failed.")

            if final_path.exists():
                existing_meta = received_chunks.get(str(chunk_index)) or {}
                existing_db_size = int(existing_meta.get("size") or 0)
                existing_db_sha = str(existing_meta.get("sha256") or "")
                if existing_db_size == bytes_written and existing_db_sha == computed_sha:
                    temp_path.unlink(missing_ok=True)
                    return item
                if not existing_meta:
                    try:
                        disk_size = final_path.stat().st_size
                        if disk_size != bytes_written:
                            temp_path.unlink(missing_ok=True)
                            raise MemoryUploadSessionError(
                                "MEMORY_UPLOAD_CHUNK_SIZE_MISMATCH",
                                "Existing chunk file size does not match the uploaded chunk size.",
                                detail={
                                    "upload_id": upload_id,
                                    "chunk_index": chunk_index,
                                    "expected_size": bytes_written,
                                    "existing_size": disk_size,
                                    "action": "verify_session_identity",
                                },
                            )
                        file_digest = hashlib.sha256()
                        with final_path.open("rb") as fh:
                            while True:
                                data = fh.read(1 << 22)
                                if not data:
                                    break
                                file_digest.update(data)
                        if file_digest.hexdigest() == computed_sha:
                            temp_path.unlink(missing_ok=True)
                            received_chunks[str(chunk_index)] = {"size": bytes_written, "sha256": computed_sha}
                            _set_received_chunks(item, received_chunks)
                            item.received_chunk_count = len(received_chunks)
                            item.bytes_received = sum(int(c.get("size") or 0) for c in received_chunks.values())
                            item.failure_code = None
                            item.failure_message = None
                            _touch_session(item)
                            db.add(item)
                            db.commit()
                            db.refresh(item)
                            return item
                    except OSError:
                        pass
                temp_path.unlink(missing_ok=True)
                raise MemoryUploadSessionError(
                    "MEMORY_UPLOAD_CHUNK_CONTENT_MISMATCH",
                    "Chunk data does not match previously stored bytes for this chunk index.",
                    detail={
                        "upload_id": upload_id,
                        "chunk_index": chunk_index,
                        "expected_start": chunk_index * chunk_size,
                        "expected_size": expected_length,
                        "existing_db_size": existing_db_size,
                        "action": "verify_session_identity",
                    },
                )

            os.replace(temp_path, final_path)
            dir_fd = os.open(str(target_dir), os.O_DIRECTORY)
            try:
                fsync_started = time.monotonic()
                os.fsync(dir_fd)
                dir_fsync_ms = int((time.monotonic() - fsync_started) * 1000)
            finally:
                os.close(dir_fd)

            received_chunks[str(chunk_index)] = {"size": bytes_written, "sha256": computed_sha}
            _set_received_chunks(item, received_chunks)
            item.received_chunk_count = len(received_chunks)
            item.bytes_received = sum(int(chunk.get("size") or 0) for chunk in received_chunks.values())
            item.status = "uploading"
            item.failure_code = None
            item.failure_message = None
            _touch_session(item)
            db.add(item)
            db_started = time.monotonic()
            db.commit()
            db_commit_ms = int((time.monotonic() - db_started) * 1000)
            db.refresh(item)
        finally:
            try:
                db.refresh(item)
                _set_active_chunk(item, chunk_index, False)
                db.add(item)
                db.commit()
                db.refresh(item)
            except Exception:  # noqa: BLE001
                logger.warning("memory upload active chunk cleanup failed", extra={"upload_id": upload_id, "chunk_index": chunk_index})
    logger.info(
        "memory upload chunk stored",
        extra={
            "upload_id": upload_id,
            "chunk_index": chunk_index,
            "chunk_size_bytes": bytes_written,
            "receive_hash_write_ms": receive_hash_write_ms,
            "file_fsync_ms": file_fsync_ms,
            "dir_fsync_ms": dir_fsync_ms,
            "db_commit_ms": db_commit_ms,
            "total_ms": int((time.monotonic() - request_started) * 1000),
        },
    )
    return item


_STAGING_INTEGRITY_HEALTHY = "healthy"
_STAGING_INTEGRITY_STAGING_MISSING = "staging_missing"
_STAGING_INTEGRITY_MISSING_CHUNKS = "missing_chunks_on_disk"
_STAGING_INTEGRITY_EXTRA_CHUNKS = "extra_chunks_on_disk"
_STAGING_INTEGRITY_SIZE_MISMATCH = "size_mismatch"
_STAGING_INTEGRITY_HASH_MISMATCH = "hash_mismatch"


def check_memory_upload_staging_integrity(
    item: MemoryUpload,
    *,
    verify_hashes: bool = False,
) -> dict[str, Any]:
    session_root = _session_root(item)
    if not session_root.exists() or not session_root.is_dir():
        return {
            "integrity_status": _STAGING_INTEGRITY_STAGING_MISSING,
            "resumable": False,
            "repairable": False,
            "expected_chunks": int(item.total_chunks or 0),
            "db_received_chunks": int(item.received_chunk_count or 0),
            "disk_chunks": 0,
            "missing_db_chunks_on_disk": [],
            "extra_disk_chunks": [],
            "size_mismatches": [],
            "hash_mismatches": [],
        }

    chunks_dir = _chunk_dir(item)
    db_chunks = _received_chunks(item)
    db_indices = sorted(int(k) for k in db_chunks.keys())
    disk_indices: list[int] = []
    missing_db_chunks_on_disk: list[int] = []
    size_mismatches: list[int] = []
    hash_mismatches: list[int] = []

    if not chunks_dir.exists() or not chunks_dir.is_dir():
        return {
            "integrity_status": _STAGING_INTEGRITY_STAGING_MISSING,
            "resumable": False,
            "repairable": False,
            "expected_chunks": int(item.total_chunks or 0),
            "db_received_chunks": int(item.received_chunk_count or 0),
            "disk_chunks": 0,
            "missing_db_chunks_on_disk": db_indices,
            "extra_disk_chunks": [],
            "size_mismatches": [],
            "hash_mismatches": [],
        }

    for entry in sorted(chunks_dir.iterdir()):
        if not entry.is_file() or entry.is_symlink():
            continue
        if entry.name.endswith(".part"):
            continue
        name = entry.name
        if not name.endswith(".chunk"):
            continue
        try:
            index = int(name.split(".")[0])
        except (ValueError, IndexError):
            continue
        disk_indices.append(index)

    disk_indices.sort()

    for index in db_indices:
        chunk_path = _chunk_path(item, index)
        if not chunk_path.exists() or not chunk_path.is_file():
            missing_db_chunks_on_disk.append(index)
            continue
        chunk_meta = db_chunks.get(str(index), {})
        expected_size = int(chunk_meta.get("size") or 0)
        actual_size = int(chunk_path.stat().st_size)
        if expected_size != 0 and actual_size != expected_size:
            size_mismatches.append(index)
            continue
        if verify_hashes:
            expected_sha = str(chunk_meta.get("sha256") or "")
            if expected_sha:
                actual_sha = _sha256_file(chunk_path)
                if actual_sha != expected_sha:
                    hash_mismatches.append(index)

    extra_disk_chunks = sorted(set(disk_indices) - set(db_indices))
    disk_chunk_count = len(disk_indices)

    if missing_db_chunks_on_disk:
        status = _STAGING_INTEGRITY_MISSING_CHUNKS
        resumable = False
        repairable = False
    elif size_mismatches:
        status = _STAGING_INTEGRITY_SIZE_MISMATCH
        resumable = False
        repairable = False
    elif hash_mismatches:
        status = _STAGING_INTEGRITY_HASH_MISMATCH
        resumable = False
        repairable = False
    elif extra_disk_chunks:
        status = _STAGING_INTEGRITY_EXTRA_CHUNKS
        resumable = True
        repairable = True
    else:
        status = _STAGING_INTEGRITY_HEALTHY
        resumable = True
        repairable = True

    return {
        "integrity_status": status,
        "resumable": resumable,
        "repairable": repairable,
        "expected_chunks": int(item.total_chunks or 0),
        "db_received_chunks": int(item.received_chunk_count or 0),
        "disk_chunks": disk_chunk_count,
        "missing_db_chunks_on_disk": missing_db_chunks_on_disk,
        "extra_disk_chunks": extra_disk_chunks,
        "size_mismatches": size_mismatches,
        "hash_mismatches": hash_mismatches,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for blob in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(blob)
    return digest.hexdigest()


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
    with _redis_upload_lock(f"kairon:memory_upload:{upload_id}:finalize"):
        item = get_memory_upload(db, case_id, upload_id)
        if item is None:
            raise MemoryUploadSessionError("MEMORY_UPLOAD_NOT_FOUND", "Memory upload session was not found.")
        if item.status in {"completed", "cancelled", "expired", "inconsistent"}:
            return item, db.get(Evidence, item.evidence_id) if item.status == "completed" else None
        active_chunks = _active_chunk_indices(item)
        if active_chunks:
            raise MemoryUploadSessionError("MEMORY_UPLOAD_CHUNKS_ACTIVE", "Cannot finalize while chunk uploads are still active.", detail={"active_chunks": active_chunks})

        integrity = check_memory_upload_staging_integrity(item, verify_hashes=True)
        integrity_status = integrity["integrity_status"]
        if integrity_status != _STAGING_INTEGRITY_HEALTHY:
            item.status = "failed"
            item.failure_code = "MEMORY_UPLOAD_STAGING_INCONSISTENT"
            item.failure_message = f"Cannot finalize: staging integrity is {integrity_status}."
            item.retryable = True
            db.add(item)
            db.commit()
            raise MemoryUploadSessionError(
                "MEMORY_UPLOAD_STAGING_INCONSISTENT",
                item.failure_message,
                detail={"integrity_status": integrity_status, "missing_chunks": integrity.get("missing_db_chunks_on_disk", []), "size_mismatches": integrity.get("size_mismatches", []), "hash_mismatches": integrity.get("hash_mismatches", [])},
            )

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
    item.status = "cancelled"
    item.retryable = False
    item.failure_code = "MEMORY_UPLOAD_CANCELLED"
    item.failure_message = (reason or "Operator requested cancel")[:512]
    _touch_session(item)
    db.add(item)
    db.commit()
    _cleanup_session_storage(item)
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
        purged += 1

    db.commit()

    for item in expired:
        _cleanup_session_storage(item)
    for item in stale_terminal:
        _cleanup_session_storage(item)

    return {"expired": removed, "purged": purged}


def reconcile_memory_upload_storage(
    db: Session,
    *,
    case_id: str | None = None,
    upload_id: str | None = None,
    older_than_hours: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Classify DB/filesystem drift without mutating data."""
    settings = get_settings()
    staging_root = settings.memory_upload_staging_path.resolve()
    staging_root.mkdir(parents=True, exist_ok=True)
    query = db.query(MemoryUpload)
    if case_id:
        query = query.filter(MemoryUpload.case_id == case_id)
    if upload_id:
        query = query.filter(MemoryUpload.id == upload_id)
    if older_than_hours is not None:
        query = query.filter(MemoryUpload.updated_at < utc_now_naive() - timedelta(hours=max(0, int(older_than_hours))))
    if limit is not None:
        query = query.limit(max(1, int(limit)))
    uploads = query.all()
    by_staging = {item.staging_name: item for item in uploads}
    findings: list[dict[str, Any]] = []
    for item in uploads:
        root = _session_root(item)
        integrity = check_memory_upload_staging_integrity(item) if item.status != "completed" else {"integrity_status": "completed"}
        if item.status != "completed" and not root.exists():
            findings.append({"upload_id": item.id, "classification": "db_session_staging_missing", "status": item.status})
        if item.status == "completed" and not db.get(Evidence, item.evidence_id):
            findings.append({"upload_id": item.id, "classification": "completed_session_evidence_missing", "status": item.status})
        if item.status != "completed" and integrity.get("integrity_status") not in {"healthy", "completed"}:
            findings.append({"upload_id": item.id, "classification": "chunk_metadata_differs_from_filesystem", "integrity_status": integrity.get("integrity_status")})
    if not upload_id:
        for entry in staging_root.iterdir() if staging_root.exists() else []:
            if not entry.is_dir() or entry.is_symlink():
                continue
            if entry.name not in by_staging:
                findings.append({"staging_name": entry.name, "classification": "staging_exists_db_session_missing"})
    return {"uploads_inspected": len(uploads), "reconciliation_findings": findings, "findings": findings, "repair_actions": ["cancel_upload", "retry_registration", "manual_review"]}


def cleanup_memory_upload_staging(
    db: Session,
    *,
    dry_run: bool = True,
    case_id: str | None = None,
    upload_id: str | None = None,
    older_than_hours: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Administrative cleanup for terminal/orphan staging.

    Active sessions are skipped.  ``dry_run`` reports reclaimable bytes;
    ``apply`` removes only orphan or non-completed terminal session staging.
    """
    settings = get_settings()
    staging_root = settings.memory_upload_staging_path.resolve()
    staging_root.mkdir(parents=True, exist_ok=True)
    cutoff = utc_now_naive() - timedelta(hours=max(0, int(older_than_hours))) if older_than_hours is not None else None
    query = db.query(MemoryUpload)
    if case_id:
        query = query.filter(MemoryUpload.case_id == case_id)
    if upload_id:
        query = query.filter(MemoryUpload.id == upload_id)
    if cutoff is not None:
        query = query.filter(MemoryUpload.updated_at < cutoff)
    if limit is not None:
        query = query.limit(max(1, int(limit)))
    uploads = query.all()
    by_staging = {item.staging_name: item for item in uploads}
    inspected = len(uploads)
    active_skipped = 0
    expired_sessions = 0
    orphan_dirs = 0
    missing_staging = 0
    completed_with_staging = 0
    errors: list[str] = []
    bytes_reclaimable = 0
    bytes_removed = 0

    def dir_size(path: Path) -> int:
        total = 0
        for child in path.rglob("*"):
            if child.is_file() and not child.is_symlink():
                total += child.stat().st_size
        return total

    candidates: list[Path] = []
    now = utc_now_naive()
    for item in uploads:
        root = _session_root(item)
        if item.status in ACTIVE_UPLOAD_SESSION_STATUSES or _active_chunk_indices(item):
            if root.exists():
                active_skipped += 1
            continue
        if item.expires_at and item.expires_at < now and item.status != "completed":
            expired_sessions += 1
        if not root.exists():
            if item.status != "completed":
                missing_staging += 1
            continue
        if item.status == "completed":
            completed_with_staging += 1
            size = dir_size(root)
            bytes_reclaimable += size
            candidates.append(root)
            continue
        if item.status in TERMINAL_UPLOAD_SESSION_STATUSES:
            size = dir_size(root)
            bytes_reclaimable += size
            candidates.append(root)

    if not upload_id:
        for entry in staging_root.iterdir() if staging_root.exists() else []:
            if not entry.is_dir() or entry.is_symlink():
                continue
            if entry.name in by_staging:
                continue
            if cutoff is not None and entry.stat().st_mtime > cutoff.timestamp():
                continue
            orphan_dirs += 1
            size = dir_size(entry)
            bytes_reclaimable += size
            candidates.append(entry)

    candidates = candidates[: max(1, int(limit))] if limit is not None else candidates
    if not dry_run:
        for entry in candidates:
            try:
                size = dir_size(entry)
                shutil.rmtree(entry, ignore_errors=False)
                bytes_removed += size
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{entry.name}: {exc}")

    return {
        "dry_run": dry_run,
        "sessions_inspected": inspected,
        "active_sessions_skipped": active_skipped,
        "skipped_active_sessions": active_skipped,
        "expired_sessions": expired_sessions,
        "orphan_directories": orphan_dirs,
        "missing_staging": missing_staging,
        "completed_with_staging": completed_with_staging,
        "bytes_reclaimable": bytes_reclaimable,
        "bytes_removed": bytes_removed,
        "reconciliation_findings": [],
        "errors": errors,
    }
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
    integrity = check_memory_upload_staging_integrity(item)
    meta = _session_metadata(item)
    is_completed_with_evidence = item.status == "completed" and bool(item.evidence_id)
    corrupted = (
        integrity["integrity_status"] != _STAGING_INTEGRITY_HEALTHY
        and not (is_completed_with_evidence and integrity["integrity_status"] == _STAGING_INTEGRITY_STAGING_MISSING)
    )
    payload = public_memory_upload_status(
        item,
        db=db,
        integrity_status=integrity["integrity_status"] if corrupted else None,
    )
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
            "upload_mode": _session_upload_mode(item),
            "default_concurrency": int(meta.get("default_concurrency") or get_settings().memory_upload_default_concurrency or 1),
            "max_concurrency": int(meta.get("max_concurrency") or get_settings().memory_upload_max_concurrency or 1),
            "active_chunks": _active_chunk_indices(item),
            "fallback_to_sequential": bool(meta.get("fallback_to_sequential")),
            "file_fingerprint": meta.get("file_fingerprint") or None,
            "created_at": item.created_at,
            "expires_at": item.expires_at,
            "finalized_at": item.finalized_at,
            "failure_message": item.failure_message,
        }
    )
    if corrupted:
        payload["integrity_status"] = integrity["integrity_status"]
        payload["resumable"] = False
        payload["repairable"] = integrity.get("repairable", False)
        payload["failure_code"] = payload.get("failure_code") or f"MEMORY_UPLOAD_STAGING_{integrity['integrity_status'].upper()}"
        payload["failure_message"] = payload.get("failure_message") or f"Upload staging is {integrity['integrity_status']}. Restart the upload from the beginning."
    duplicate = _session_metadata(item).get("duplicate")
    if isinstance(duplicate, dict):
        payload["duplicate"] = duplicate
    return payload
