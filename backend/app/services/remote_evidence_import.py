"""Worker side of importing evidence from a remote store (S3, Azure Blob...).

Each source creates an ordinary resumable upload session for the object and queues a job; the job
calls ``download_into_session`` with a function that opens the exact object picked. Streaming,
progress, cancellation, the size check and failure bookkeeping live here, once, so every source
behaves the same; afterwards the session goes through the same preflight a browser upload gets
(run_evidence_upload_preflight), and from there everything is the normal upload flow.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PROGRESS_EVERY_SECONDS = 2.0


class RemoteImportError(ValueError):
    """A problem the analyst can act on; the message is safe to show."""


def download_into_session(
    upload_session_id: str,
    *,
    source_key: str,
    label: str,
    require_enabled: Callable[[], None],
    open_stream: Callable[[Any, dict[str, Any]], Iterable[bytes]],
    describe_error: Callable[[Exception], Exception],
) -> dict[str, Any]:
    """Download the object recorded under ``metadata_json[source_key]`` into the session's staged
    file, then run the normal preflight.

    ``open_stream(db, source)`` returns the object's bytes as chunks; ``describe_error`` turns a
    client exception into one whose message has no credentials or internals; ``label`` names the
    source in messages ("S3", "Azure Blob").
    """
    from app.core.database import SessionLocal
    from app.models.evidence_upload_session import EvidenceUploadSession
    from app.services.evidence_operations import get_upload_operation, sync_upload_operation, transition_operation
    from app.services.evidence_upload_session import _touch_upload_session
    from app.workers.tasks import run_evidence_upload_preflight

    stage = f"{source_key.removesuffix('_source')}_download_failed"
    with SessionLocal() as db:
        session = db.get(EvidenceUploadSession, upload_session_id)
        if session is None:
            return {"status": "missing_session", "upload_session_id": upload_session_id}
        source = (session.metadata_json or {}).get(source_key) or {}
        if session.status not in {"created", "uploading", "interrupted"}:
            return {"status": "not_downloading", "upload_session_id": upload_session_id, "reason": session.status}
        target = Path(session.staged_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        expected = int(session.expected_size_bytes or 0)
        written = 0
        try:
            require_enabled()
            chunks: Iterator[bytes] = iter(open_stream(db, source))
            session.status = "uploading"
            db.commit()
            last_report = time.monotonic()
            with target.open("wb") as out:
                for chunk in chunks:
                    if not chunk:
                        continue
                    written += len(chunk)
                    if expected and written > expected:
                        raise RemoteImportError("The object grew while it was being downloaded; import it again.")
                    out.write(chunk)
                    if time.monotonic() - last_report >= PROGRESS_EVERY_SECONDS:
                        last_report = time.monotonic()
                        db.refresh(session)
                        if session.status == "cancelled":
                            return {"status": "cancelled", "upload_session_id": upload_session_id}
                        session.bytes_received = session.size_bytes = written
                        _touch_upload_session(session)
                        db.commit()
                        sync_upload_operation(db, session)
                out.flush()
            if expected and written != expected:
                raise RemoteImportError(f"The download stopped at {written} of {expected} bytes; import it again.")
        except Exception as exc:  # noqa: BLE001
            known = isinstance(exc, RemoteImportError)
            error = exc if known else describe_error(exc)
            logger.warning(f"{label} import failed", extra={"upload_session_id": upload_session_id, "error": str(error)}, exc_info=not known)
            db.rollback()
            session = db.get(EvidenceUploadSession, upload_session_id)
            session.status = "failed"
            session.failure_message = f"{label} download failed: {error}"
            session.bytes_received = session.size_bytes = written
            db.commit()
            operation = get_upload_operation(db, session)
            transition_operation(operation, "failed", stage=stage, owner="worker", error=str(error), force=True)
            db.add(operation)
            db.commit()
            target.unlink(missing_ok=True)
            return {"status": "failed", "upload_session_id": upload_session_id, "error": str(error)}
        session.bytes_received = session.size_bytes = written
        db.commit()
        sync_upload_operation(db, session)
    return run_evidence_upload_preflight(upload_session_id)


def read_chunks(body: Any, chunk_size: int) -> Iterator[bytes]:
    """Chunks of a file-like ``read(n)`` body."""
    while chunk := body.read(chunk_size):
        yield chunk
