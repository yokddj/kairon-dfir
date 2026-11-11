"""A crash-dump copy of a memory image Volatility cannot read, made only when the analyst asks.

Some raw captures defeat Volatility: its page-map scan finds no page tables (DTB), so it builds no
memory layer and every plugin fails (INVALID_MEMORY_LAYER). MemProcFS finds the DTB its own way and
can write the memory it reconstructed as a Windows full crash dump, whose header carries the DTB;
Volatility reads that. The copy is about the size of the image, so it is never written on its own:
a run that hits the error marks the evidence, the evidence page offers the copy with its size, and
the memory worker writes it on request (run_volatility_view). From then on Volatility, the symbol
probe and the preparation read the copy; MemProcFS's own plugins keep reading the image. The copy
can be removed again, and goes with the evidence or its case.

The state lives in ``evidence.metadata_json["volatility_view"]``:
``queued`` -> ``running`` -> ``created`` | ``failed`` | ``skipped_disk_space``; ``removing``.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.core.config import get_settings
from app.core.database import utc_now_naive
from app.models.evidence import Evidence

logger = logging.getLogger(__name__)

# The crash dump covers the whole physical address space, gaps included: a 4 GB image gave 6 GB.
SIZE_FACTOR = 1.2
_ACTIVE = {"queued", "running", "removing"}


class VolatilityViewError(ValueError):
    """A request the analyst can act on; the message is safe to show."""


def _now() -> str:
    return utc_now_naive().isoformat(timespec="seconds") + "Z"


def _set(db: Session, evidence: Evidence, key: str, value: Any) -> None:
    metadata = dict(evidence.metadata_json or {})
    if value is None:
        metadata.pop(key, None)
    else:
        metadata[key] = value
    evidence.metadata_json = metadata
    flag_modified(evidence, "metadata_json")
    db.add(evidence)
    db.commit()


def mark_volatility_layer_missing(db: Session, evidence: Evidence, *, run_id: str, plugin: str) -> None:
    """Record that Volatility found no memory layer in this image (the page offers the copy)."""
    if (evidence.metadata_json or {}).get("volatility_layer_missing"):
        return
    _set(db, evidence, "volatility_layer_missing", {"run_id": run_id, "plugin": plugin, "at": _now()})


def estimated_bytes(evidence: Evidence) -> int:
    return int(int(evidence.size_bytes or 0) * SIZE_FACTOR)


def status(evidence: Evidence) -> dict[str, Any]:
    metadata = evidence.metadata_json or {}
    view = dict(metadata.get("volatility_view") or {})
    settings = get_settings()
    return {
        "evidence_id": evidence.id,
        # The page shows nothing unless Volatility could not read the image, or a copy exists.
        "needed": bool(metadata.get("volatility_layer_missing")),
        "enabled": bool(settings.memory_volatility_crashdump_view_enabled),
        "status": view.get("status") or "none",
        "estimated_bytes": estimated_bytes(evidence),
        "bytes": view.get("bytes"),
        "message": view.get("message"),
        "updated_at": view.get("updated_at"),
    }


def request_copy(db: Session, evidence: Evidence, *, user: str | None) -> dict[str, Any]:
    from app.workers.tasks import enqueue_volatility_view

    if not get_settings().memory_volatility_crashdump_view_enabled:
        raise VolatilityViewError("Crash-dump copies are disabled on this instance (MEMORY_VOLATILITY_CRASHDUMP_VIEW_ENABLED=false).")
    current = (evidence.metadata_json or {}).get("volatility_view") or {}
    if current.get("status") in _ACTIVE:
        raise VolatilityViewError("The copy is already being made or removed.")
    if current.get("status") == "created":
        raise VolatilityViewError("The copy already exists.")
    _set(db, evidence, "volatility_view", {"status": "queued", "requested_by": user, "updated_at": _now()})
    enqueue_volatility_view(evidence.id, "create")
    return status(evidence)


def request_removal(db: Session, evidence: Evidence, *, user: str | None) -> dict[str, Any]:
    from app.workers.tasks import enqueue_volatility_view

    current = (evidence.metadata_json or {}).get("volatility_view") or {}
    if current.get("status") in _ACTIVE:
        raise VolatilityViewError("The copy is already being made or removed.")
    _set(db, evidence, "volatility_view", {"status": "removing", "requested_by": user, "updated_at": _now()})
    enqueue_volatility_view(evidence.id, "remove")
    return status(evidence)


def run_volatility_view(evidence_id: str, action: str) -> dict[str, Any]:
    """Memory worker: write or remove the copy (only this worker can write its output directory)."""
    from app.core.database import SessionLocal
    from app.services.memory.evidence_access import validate_current_process_evidence_access
    from app.services.memory.memprocfs_runner import run_crashdump
    from app.services.memory.storage import volatility_view_path
    from app.services.memory.volatility_runner import VolatilityRunnerError

    settings = get_settings()
    with SessionLocal() as db:
        evidence = db.get(Evidence, evidence_id)
        if evidence is None:
            return {"status": "missing_evidence"}
        target = volatility_view_path(evidence.case_id, evidence.id)

        def finish(**view: Any) -> dict[str, Any]:
            _set(db, evidence, "volatility_view", {**view, "updated_at": _now()} if view else None)
            return view or {"status": "removed"}

        if action == "remove":
            target.unlink(missing_ok=True)
            target.with_name(target.name + ".partial").unlink(missing_ok=True)
            return finish()
        try:
            source = validate_current_process_evidence_access(evidence, settings=settings).path
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            free = shutil.disk_usage(target.parent).free
        except Exception as exc:  # noqa: BLE001
            return finish(status="failed", message=f"The memory worker cannot prepare the copy: {type(exc).__name__}.")
        needed = estimated_bytes(evidence) + int(settings.memory_upload_min_free_space_bytes or 0)
        if free < needed:
            return finish(status="skipped_disk_space", message=f"Not enough free space: about {needed / 2**30:.0f} GiB needed (the copy plus the reserve kept free), {free / 2**30:.0f} GiB available.")
        _set(db, evidence, "volatility_view", {"status": "running", "updated_at": _now()})
        try:
            written = run_crashdump(Path(source), target, target.parent, timeout_seconds=int(settings.memory_volatility_crashdump_timeout_seconds))
        except VolatilityRunnerError as exc:
            target.unlink(missing_ok=True)
            logger.warning("crash-dump copy for Volatility failed", extra={"evidence_id": evidence_id, "code": exc.code})
            return finish(status="failed", message=exc.message)
        return finish(status="created", bytes=written, source="MemProcFS \\memory.dmp")
