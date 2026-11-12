"""What the memory evidence page says about Volatility reading the image, and old crash-dump copies.

When Volatility's own scan finds no page tables in an image (INVALID_MEMORY_LAYER), it reads it
through a memory layer pinned to the page-table base MemProcFS finds
(app.services.memory.volatility_layer). The page only speaks when even that fails: the run marks
the evidence (``volatility_layer_missing``).

Earlier versions instead had MemProcFS write the whole memory as a crash dump for Volatility. That
did not help (Volatility ignores the page-table base in a crash dump's header and scans again),
so no copy is made any more; one already made can be removed from the page to free its space.
Its state lives in ``evidence.metadata_json["volatility_view"]``: ``created`` -> ``removing``.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.core.database import utc_now_naive
from app.models.evidence import Evidence

logger = logging.getLogger(__name__)

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
    """Record that Volatility found no memory layer in this image, even with MemProcFS's help."""
    if (evidence.metadata_json or {}).get("volatility_layer_missing"):
        return
    _set(db, evidence, "volatility_layer_missing", {"run_id": run_id, "plugin": plugin, "at": _now()})


def status(evidence: Evidence) -> dict[str, Any]:
    from app.services.memory.volatility_layer import recorded

    metadata = evidence.metadata_json or {}
    view = dict(metadata.get("volatility_view") or {})
    layer = recorded(evidence)
    copy_status = view.get("status") or "none"
    return {
        "evidence_id": evidence.id,
        # The page shows nothing unless Volatility could not read the image, or an old copy exists.
        "needed": bool(metadata.get("volatility_layer_missing")) and layer is None,
        "layer": {"page_map_offset": hex(int(layer["page_map_offset"])), "source": layer.get("source") or "MemProcFS"} if layer else None,
        # Copies an earlier version made, still taking space ("failed" left nothing behind).
        "status": copy_status if copy_status in {"created", "removing"} else "none",
        "bytes": view.get("bytes"),
        "message": view.get("message"),
        "updated_at": view.get("updated_at"),
    }


def request_removal(db: Session, evidence: Evidence, *, user: str | None) -> dict[str, Any]:
    from app.workers.tasks import enqueue_volatility_view

    current = (evidence.metadata_json or {}).get("volatility_view") or {}
    if current.get("status") in _ACTIVE:
        raise VolatilityViewError("The copy is already being removed.")
    _set(db, evidence, "volatility_view", {"status": "removing", "requested_by": user, "updated_at": _now()})
    enqueue_volatility_view(evidence.id, "remove")
    return status(evidence)


def run_volatility_view(evidence_id: str, action: str) -> dict[str, Any]:
    """Memory worker: remove an old copy (only this worker can write its output directory)."""
    from app.core.database import SessionLocal
    from app.services.memory.storage import volatility_view_path

    with SessionLocal() as db:
        evidence = db.get(Evidence, evidence_id)
        if evidence is None:
            return {"status": "missing_evidence"}
        if action != "remove":
            return {"status": "unsupported_action"}
        target = volatility_view_path(evidence.case_id, evidence.id)
        target.unlink(missing_ok=True)
        target.with_name(target.name + ".partial").unlink(missing_ok=True)
        _set(db, evidence, "volatility_view", None)
        return {"status": "removed"}
