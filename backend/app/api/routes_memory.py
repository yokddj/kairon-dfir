from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db, utc_now_naive
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType
from app.models.memory import MemoryScanRun
from app.schemas.memory import MemoryBackendOverviewRead, MemoryEvidenceRead, MemoryOverviewRead, MemoryScanRunRead, MemoryStartScanRequest, MemoryStartScanResponse
from app.services.memory.backend_readiness import get_memory_backend_overview
from app.services.memory.overview import get_case_memory_overview, list_memory_evidences


router = APIRouter(prefix="/api", tags=["memory"])
settings = get_settings()


def _require_case(db: Session, case_id: str) -> None:
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")


@router.get("/memory/backends", response_model=MemoryBackendOverviewRead)
def get_memory_backends() -> dict:
    return get_memory_backend_overview()


@router.get("/cases/{case_id}/memory", response_model=MemoryOverviewRead)
def get_memory_overview(case_id: str, db: Session = Depends(get_db)) -> dict:
    _require_case(db, case_id)
    return get_case_memory_overview(db, case_id)


@router.get("/cases/{case_id}/memory/evidences", response_model=list[MemoryEvidenceRead])
def get_memory_evidences(case_id: str, db: Session = Depends(get_db)) -> list[Evidence]:
    _require_case(db, case_id)
    return list_memory_evidences(db, case_id)


@router.get("/cases/{case_id}/memory/runs", response_model=list[MemoryScanRunRead])
def get_memory_runs(case_id: str, db: Session = Depends(get_db)) -> list[MemoryScanRun]:
    _require_case(db, case_id)
    return (
        db.query(MemoryScanRun)
        .filter(MemoryScanRun.case_id == case_id)
        .order_by(MemoryScanRun.created_at.desc())
        .all()
    )


@router.post("/evidences/{evidence_id}/memory/scan", response_model=MemoryStartScanResponse)
def start_memory_scan(evidence_id: str, payload: MemoryStartScanRequest | None = None, db: Session = Depends(get_db)) -> MemoryStartScanResponse:
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if evidence.evidence_type != EvidenceType.memory_dump:
        raise HTTPException(status_code=400, detail="Memory scan registration is only supported for memory_dump evidence.")
    if not settings.memory_analysis_enabled:
        return MemoryStartScanResponse(
            accepted=False,
            evidence_id=evidence.id,
            status="disabled",
            message="Memory Analysis is currently disabled. Enable memory analysis in backend configuration before registering authorized RAM evidence for analysis.",
        )
    run = MemoryScanRun(
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        backend=(payload.backend if payload else None),
        profile=(payload.profile if payload else "metadata_only") or "metadata_only",
        status="ready",
        plugin_count=0,
        plugins_completed=0,
        plugins_failed=0,
        started_at=None,
        completed_at=utc_now_naive(),
        metadata_json={
            "message": "Memory evidence registered. External analysis is not enabled in this build.",
            "external_tool_execution_enabled": False,
        },
        error_log={},
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return MemoryStartScanResponse(
        accepted=True,
        evidence_id=evidence.id,
        run_id=run.id,
        status=run.status,
        message="Memory evidence registered. External analysis is not enabled in this build.",
        run=MemoryScanRunRead.model_validate(run),
    )
