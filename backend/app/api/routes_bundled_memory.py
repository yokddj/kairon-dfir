"""Register a memory image found inside a collection as its own memory evidence
(app.services.bundled_memory), from the file already extracted on the server."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.evidence import Evidence
from app.models.user import User
from app.services import bundled_memory
from app.services.audit import log_audit
from app.services.auth_dependencies import get_optional_user

router = APIRouter(tags=["evidence"])


class BundledMemoryRequest(BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    host_id: str | None = Field(default=None, max_length=64)
    provided_host: str | None = Field(default=None, max_length=255)

    model_config = {"extra": "forbid"}


@router.post("/api/cases/{case_id}/evidences/{evidence_id}/bundled-memory", status_code=202)
def register_bundled_memory(case_id: str, evidence_id: str, payload: BundledMemoryRequest, db: Session = Depends(get_db), user: User | None = Depends(get_optional_user)) -> dict:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.case_id != case_id:
        raise HTTPException(status_code=404, detail="Evidence not found")
    try:
        session = bundled_memory.start_registration(db, evidence, payload.path, host_id=payload.host_id, provided_host=payload.provided_host, current_user=user)
    except bundled_memory.BundledMemoryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_audit(
        "bundled_memory_registration_started",
        actor_user_id=getattr(user, "id", None),
        case_id=case_id,
        resource_type="evidence",
        resource_id=evidence_id,
        metadata={"path": payload.path, "upload_session_id": session.id},
    )
    return {"status": "queued", "upload_session_id": session.id}
