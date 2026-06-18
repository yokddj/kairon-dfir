from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType
from app.models.memory import MemoryScanRun
from app.schemas.memory import MemoryBackendOverviewRead, MemoryEvidenceRead, MemoryOverviewRead, MemoryRunDetailRead, MemoryScanRunRead, MemoryStartScanRequest, MemoryStartScanResponse, MemorySystemInfoRead
from app.services.memory.backend_readiness import get_memory_backend_overview
from app.services.memory.execution import active_run_for_evidence, create_memory_metadata_run, mark_run_queued
from app.services.memory.overview import get_case_memory_overview, list_memory_evidences
from app.services.memory.validation import MemoryExecutionValidationError, validate_memory_execution_request
from app.workers.tasks import enqueue_memory_metadata_scan


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


@router.post("/evidences/{evidence_id}/memory/scan", response_model=MemoryStartScanResponse, status_code=status.HTTP_202_ACCEPTED)
def start_memory_scan(evidence_id: str, payload: MemoryStartScanRequest | None = None, db: Session = Depends(get_db)) -> MemoryStartScanResponse:
    profile = (payload.profile if payload else "metadata_only") or "metadata_only"
    if profile != "metadata_only":
        raise HTTPException(status_code=400, detail="Only metadata_only memory analysis is supported.")
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
    if not settings.memory_allow_external_tool_execution:
        raise HTTPException(status_code=403, detail="External memory-tool execution is disabled by server configuration.")
    backend_overview = get_memory_backend_overview()
    volatility_status = next((item for item in backend_overview.get("backends", []) if item.get("backend") == "volatility3"), None)
    if not volatility_status or not volatility_status.get("ready"):
        raise HTTPException(status_code=503, detail=(volatility_status or {}).get("message") or "Volatility 3 backend is not ready.")
    try:
        validate_memory_execution_request(db, evidence.id)
    except MemoryExecutionValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc
    existing = active_run_for_evidence(db, evidence.id, profile)
    if existing:
        raise HTTPException(status_code=409, detail=f"An active metadata analysis run already exists for this memory evidence: {existing.id}")

    run = create_memory_metadata_run(db, evidence.id)
    try:
        worker_task_id = enqueue_memory_metadata_scan(run.id)
    except Exception as exc:  # noqa: BLE001
        run.status = "failed"
        run.error_log = {"code": "ENQUEUE_FAILED", "message": "Failed to enqueue memory metadata analysis."}
        db.commit()
        raise HTTPException(status_code=500, detail="Failed to enqueue memory metadata analysis.") from exc
    run = mark_run_queued(db, run.id, worker_task_id) or run
    return MemoryStartScanResponse(
        accepted=True,
        evidence_id=evidence.id,
        run_id=run.id,
        status=run.status,
        message="Memory metadata analysis queued for windows.info.",
        run=MemoryScanRunRead.model_validate(run),
    )


@router.get("/memory/runs/{run_id}", response_model=MemoryRunDetailRead)
def get_memory_run(run_id: str, db: Session = Depends(get_db)) -> MemoryScanRun:
    run = db.get(MemoryScanRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Memory run not found")
    return run


@router.get("/memory/runs/{run_id}/system-info", response_model=MemorySystemInfoRead)
def get_memory_run_system_info(run_id: str, db: Session = Depends(get_db)) -> dict:
    run = db.get(MemoryScanRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Memory run not found")
    system_info = (run.metadata_json or {}).get("system_info")
    if not isinstance(system_info, dict):
        raise HTTPException(status_code=404, detail="Memory system information is not available for this run.")
    return system_info


@router.get("/cases/{case_id}/memory/system-info", response_model=list[MemorySystemInfoRead])
def get_case_memory_system_info(case_id: str, db: Session = Depends(get_db)) -> list[dict]:
    _require_case(db, case_id)
    runs = (
        db.query(MemoryScanRun)
        .filter(MemoryScanRun.case_id == case_id, MemoryScanRun.status.in_(["completed", "completed_with_errors"]))
        .order_by(MemoryScanRun.completed_at.desc().nullslast(), MemoryScanRun.created_at.desc())
        .all()
    )
    results: list[dict] = []
    for run in runs:
        system_info = (run.metadata_json or {}).get("system_info")
        if isinstance(system_info, dict):
            results.append(system_info)
    return results
