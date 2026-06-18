from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType
from app.models.memory import MemoryScanRun
from app.schemas.memory import MemoryBackendOverviewRead, MemoryEvidenceRead, MemoryOverviewRead, MemoryProcessListRead, MemoryProcessTreeRead, MemoryRunDetailRead, MemoryScanRunRead, MemoryStartScanRequest, MemoryStartScanResponse, MemorySystemInfoRead
from app.services.memory.backend_readiness import get_memory_backend_overview
from app.services.memory.execution import active_run_for_evidence, create_memory_metadata_run, mark_run_queued, resolve_profile_plugins
from app.services.memory.indexing import get_memory_document, search_memory_edges, search_memory_processes
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
    try:
        resolved_plugins = resolve_profile_plugins(profile)
    except MemoryExecutionValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc
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
    if not payload or not payload.authorization_acknowledged:
        raise HTTPException(
            status_code=400,
            detail="Authorization acknowledgement is required before analyzing RAM evidence.",
        )
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

    run = create_memory_metadata_run(db, evidence.id, profile)
    run.metadata_json = {
        **(run.metadata_json or {}),
        "authorization_acknowledged": True,
        "authorization_acknowledged_at": datetime.now(UTC).isoformat(),
    }
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
        message=f"Memory analysis queued for {profile}: {', '.join(resolved_plugins)}.",
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


@router.get("/memory/runs/{run_id}/processes", response_model=MemoryProcessListRead)
def get_memory_run_processes(
    run_id: str,
    pid: int | None = Query(default=None),
    ppid: int | None = Query(default=None),
    process_name: str | None = Query(default=None),
    source_plugin: str | None = Query(default=None),
    present_in_pslist: bool | None = Query(default=None),
    present_in_psscan: bool | None = Query(default=None),
    has_command_line: bool | None = Query(default=None),
    active: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict:
    run = db.get(MemoryScanRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Memory run not found")
    if source_plugin and source_plugin not in {"windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline"}:
        raise HTTPException(status_code=400, detail="Unsupported memory process source plugin filter.")
    return search_memory_processes(run.case_id, run_id=run.id, pid=pid, ppid=ppid, process_name=process_name, source_plugin=source_plugin, present_in_pslist=present_in_pslist, present_in_psscan=present_in_psscan, has_command_line=has_command_line, active=active, page=page, page_size=page_size)


@router.get("/cases/{case_id}/memory/processes", response_model=MemoryProcessListRead)
def get_case_memory_processes(
    case_id: str,
    evidence_id: str | None = Query(default=None),
    run_id: str | None = Query(default=None),
    pid: int | None = Query(default=None),
    ppid: int | None = Query(default=None),
    process_name: str | None = Query(default=None),
    source_plugin: str | None = Query(default=None),
    present_in_pslist: bool | None = Query(default=None),
    present_in_psscan: bool | None = Query(default=None),
    has_command_line: bool | None = Query(default=None),
    active: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict:
    _require_case(db, case_id)
    if source_plugin and source_plugin not in {"windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline"}:
        raise HTTPException(status_code=400, detail="Unsupported memory process source plugin filter.")
    if run_id:
        run = db.get(MemoryScanRun, run_id)
        if not run or run.case_id != case_id:
            raise HTTPException(status_code=404, detail="Memory run not found")
    return search_memory_processes(case_id, run_id=run_id, evidence_id=evidence_id, pid=pid, ppid=ppid, process_name=process_name, source_plugin=source_plugin, present_in_pslist=present_in_pslist, present_in_psscan=present_in_psscan, has_command_line=has_command_line, active=active, page=page, page_size=page_size)


@router.get("/memory/runs/{run_id}/process-tree", response_model=MemoryProcessTreeRead)
def get_memory_process_tree(run_id: str, db: Session = Depends(get_db)) -> dict:
    run = db.get(MemoryScanRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Memory run not found")
    processes = search_memory_processes(run.case_id, run_id=run.id, page=1, page_size=200)["items"]
    edges = search_memory_edges(run.case_id, run_id=run.id)
    pids = {item.get("process", {}).get("pid") for item in processes}
    orphan_count = len([edge for edge in edges if edge.get("parent_pid") not in pids])
    child_pids = {edge.get("child_pid") for edge in edges}
    root_count = len([item for item in processes if item.get("process", {}).get("pid") not in child_pids])
    return {"run_id": run.id, "nodes": processes, "edges": edges, "orphan_count": orphan_count, "root_count": root_count, "warnings": [], "source_plugins": sorted({plugin for item in processes for plugin in item.get("plugins", [])}), "total_process_count": search_memory_processes(run.case_id, run_id=run.id, page=1, page_size=1)["total"]}


@router.get("/memory/processes/{document_id}")
def get_memory_process_document(document_id: str, case_id: str = Query(...), db: Session = Depends(get_db)) -> dict:
    _require_case(db, case_id)
    document = get_memory_document(case_id, document_id)
    if not document or document.get("memory_artifact_type") != "memory_process":
        raise HTTPException(status_code=404, detail="Memory process document not found")
    return document
