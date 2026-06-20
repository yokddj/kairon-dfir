from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType
from app.models.memory import MemoryScanRun, MemorySymbolAcquisition
from app.schemas.memory import MemoryBackendOverviewRead, MemoryEvidenceRead, MemoryEvidenceReadinessRead, MemoryOverviewRead, MemoryProcessEntityDetailRead, MemoryProcessEntityListRead, MemoryProcessListRead, MemoryProcessTreeEntityRead, MemoryProcessTreeRead, MemoryRenormalizeSummaryRead, MemoryRunDetailRead, MemoryRunOptionsRead, MemoryRunSelectorRead, MemoryScanRunRead, MemoryStartScanRequest, MemoryStartScanResponse, MemorySymbolAcquireRequest, MemorySymbolAcquireResponse, MemorySymbolCacheStatusRead, MemorySymbolRequestCreateRequest, MemorySymbolRequestCreateResponse, MemorySymbolRequestStatusRead, MemorySystemInfoRead, MemoryUploadReadinessRead, MemoryUploadStatusRead
from app.services.memory.backend_readiness import check_volatility3_backend, get_memory_backend_overview
from app.services.memory.execution import active_run_for_evidence, create_memory_metadata_run, mark_run_queued, resolve_profile_plugins
from app.services.memory.evidence_access import evidence_readiness
from app.services.memory.indexing import get_memory_document, search_memory_edges, search_memory_processes
from app.services.memory.overview import get_case_memory_overview, list_memory_evidences
from app.services.memory.symbol_control import SymbolControlError, acquisition_gate, cache_status, evidence_symbol_readiness, latest_symbols_failure, queue_symbol_acquisition, request_status_dict, request_symbol_acquisition_awaiting_approval
from app.models.memory import MemorySymbolAcquisition, MemorySymbolAcquisitionRequest
from app.services.memory.upload_readiness import MAX_SELECTED_SIZE_BYTES, get_memory_upload_readiness
from app.services.memory.upload_lifecycle import get_memory_upload, public_memory_upload_status, reconcile_memory_upload
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


@router.get("/cases/{case_id}/memory/evidences/{evidence_id}/readiness", response_model=MemoryEvidenceReadinessRead)
def get_memory_evidence_readiness(case_id: str, evidence_id: str, db: Session = Depends(get_db)) -> dict:
    _require_case(db, case_id)
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.case_id != case_id or evidence.evidence_type != EvidenceType.memory_dump:
        raise HTTPException(status_code=404, detail="Memory evidence was not found.")
    backend = check_volatility3_backend()
    result = evidence_readiness(evidence)
    result["worker_online"] = bool(backend.get("dedicated_worker_online"))
    result["backend_ready"] = bool(backend.get("ready"))
    result["can_analyze"] = bool(result["can_analyze"] and result["worker_online"] and result["backend_ready"])
    if not result["worker_online"]:
        result["error_code"] = "MEMORY_WORKER_OFFLINE"
        result["sanitized_message"] = "The dedicated memory worker is offline."
    elif not result["backend_ready"] and result["error_code"] is None:
        result["error_code"] = "MEMORY_BACKEND_UNAVAILABLE"
        result["sanitized_message"] = "The memory analysis backend is not ready."
    result.update(evidence_symbol_readiness(db, case_id, evidence_id))
    return result


@router.get("/memory/symbols/cache", response_model=MemorySymbolCacheStatusRead)
def get_memory_symbol_cache_status(db: Session = Depends(get_db)) -> dict:
    return cache_status(db=db)


@router.get("/memory/symbols/requests/{request_id}", response_model=MemorySymbolRequestStatusRead)
def get_memory_symbol_request(request_id: str, db: Session = Depends(get_db)) -> dict:
    item = db.get(MemorySymbolAcquisitionRequest, request_id)
    if item is None:
        # Fall back to legacy MemorySymbolAcquisition id for backward compat.
        legacy = db.get(MemorySymbolAcquisition, request_id)
        if legacy is None:
            raise HTTPException(status_code=404, detail="Symbol acquisition request was not found.")
        return request_status_dict(
            MemorySymbolAcquisitionRequest(
                id=legacy.id,
                requirement_id=legacy.requirement_id,
                case_id="",
                evidence_id="",
                status=legacy.status,
                source_category=legacy.source_category,
                requirement_fingerprint="",
                downloaded_bytes=legacy.downloaded_bytes,
            ),
            approval=legacy,
        )
    acquisition = (
        db.query(MemorySymbolAcquisition)
        .filter(MemorySymbolAcquisition.requirement_id == item.requirement_id)
        .order_by(MemorySymbolAcquisition.created_at.desc())
        .first()
    )
    return request_status_dict(item, approval=acquisition)


@router.post(
    "/cases/{case_id}/memory/evidences/{evidence_id}/symbols/request",
    response_model=MemorySymbolRequestCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_symbol_acquisition_request(
    case_id: str,
    evidence_id: str,
    payload: MemorySymbolRequestCreateRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Create or return the pending symbol acquisition request.

    The request is created in ``awaiting_network_isolation`` or
    ``awaiting_operator_approval`` depending on the deployment state.  It
    is NOT queued for download.  Only the local CLI can approve and queue
    the request.
    """
    _require_case(db, case_id)
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.case_id != case_id or evidence.evidence_type != EvidenceType.memory_dump:
        raise HTTPException(status_code=404, detail="Memory evidence was not found.")
    if not payload.authorization_acknowledged:
        raise HTTPException(status_code=400, detail="Evidence authorization acknowledgement is required.")
    if latest_symbols_failure(db, case_id, evidence_id) is None:
        raise HTTPException(status_code=409, detail="No unresolved Windows symbol requirement is recorded for this evidence.")
    available, error_code, message = acquisition_gate()
    if not available and error_code in {"SYMBOL_ACQUISITION_DISABLED"}:
        raise HTTPException(status_code=409, detail={"error_code": error_code, "message": message})
    try:
        request = request_symbol_acquisition_awaiting_approval(db, case_id=case_id, evidence_id=evidence_id)
    except Exception as exc:  # noqa: BLE001
        from app.services.memory.symbol_approval import ApprovalError
        if isinstance(exc, ApprovalError):
            raise HTTPException(status_code=409, detail={"error_code": exc.code, "message": exc.message}) from exc
        raise
    return {
        "request_id": request.id,
        "status": request.status,
        "source_category": request.source_category,
        "pending_request_id": request.id,
        "requirement_fingerprint": request.requirement_fingerprint,
        "error_code": None,
        "message": request.sanitized_message or "A symbol acquisition request was recorded.",
    }


@router.post(
    "/cases/{case_id}/memory/evidences/{evidence_id}/symbols/acquire",
    response_model=MemorySymbolAcquireResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def acquire_memory_symbols(
    case_id: str,
    evidence_id: str,
    payload: MemorySymbolAcquireRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Queue a managed acquisition.

    This endpoint is reserved for the local operator workflow.  It refuses
    if no active approval exists for the request.  In ordinary UI flows
    use POST /symbols/request to create the pending request; queueing
    requires the local CLI.
    """
    _require_case(db, case_id)
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.case_id != case_id or evidence.evidence_type != EvidenceType.memory_dump:
        raise HTTPException(status_code=404, detail="Memory evidence was not found.")
    if not payload.authorization_acknowledged:
        raise HTTPException(status_code=400, detail="Evidence authorization acknowledgement is required.")
    if latest_symbols_failure(db, case_id, evidence_id) is None:
        raise HTTPException(status_code=409, detail="No unresolved Windows symbol requirement is recorded for this evidence.")
    available, error_code, message = acquisition_gate()
    if not available:
        raise HTTPException(status_code=503, detail={"error_code": error_code, "message": message})
    try:
        request = queue_symbol_acquisition(db, case_id, evidence_id)
    except SymbolControlError as exc:
        raise HTTPException(status_code=503, detail={"error_code": exc.code, "message": exc.message}) from exc
    return {
        "request_id": request.id,
        "status": request.status,
        "symbol_mode": "managed_download",
        "source": "official_microsoft_symbols",
        "error_code": None,
        "message": "The required Windows symbols are queued for controlled acquisition." if request.status != "completed" else "The required Windows symbols are already cached.",
    }


@router.get("/cases/{case_id}/memory/upload-readiness", response_model=MemoryUploadReadinessRead)
def get_memory_upload_readiness_endpoint(
    case_id: str,
    selected_size_bytes: int | None = Query(default=None, gt=0, le=MAX_SELECTED_SIZE_BYTES),
    db: Session = Depends(get_db),
) -> dict:
    _require_case(db, case_id)
    return get_memory_upload_readiness(case_id, selected_size_bytes=selected_size_bytes)


@router.get("/cases/{case_id}/memory/uploads/{upload_id}", response_model=MemoryUploadStatusRead)
def get_memory_upload_status(case_id: str, upload_id: str, db: Session = Depends(get_db)) -> dict:
    _require_case(db, case_id)
    try:
        item = get_memory_upload(db, case_id, upload_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Memory upload was not found.") from exc
    if item is None:
        raise HTTPException(status_code=404, detail="Memory upload was not found.")
    return public_memory_upload_status(item)


@router.post("/cases/{case_id}/memory/uploads/{upload_id}/reconcile", response_model=MemoryUploadStatusRead)
def reconcile_memory_upload_endpoint(case_id: str, upload_id: str, db: Session = Depends(get_db)) -> dict:
    _require_case(db, case_id)
    item = get_memory_upload(db, case_id, upload_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Memory upload was not found.")
    if item.status in {"failed", "inconsistent"} and not item.retryable:
        return public_memory_upload_status(item)
    try:
        reconciled = reconcile_memory_upload(case_id, upload_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Memory upload was not found.") from exc
    except Exception as exc:
        raise HTTPException(status_code=409, detail="Memory upload could not be reconciled safely.") from exc
    return public_memory_upload_status(reconciled)


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


# ---------------------------------------------------------------------------
# Canonical memory process entity endpoints
# ---------------------------------------------------------------------------

from app.services.memory import process_entities as canonical_entities  # noqa: E402
from pydantic import BaseModel as _BaseModel  # noqa: E402


class _RenormalizeRequest(_BaseModel):
    run_id: str
    dry_run: bool = True


def _resolve_run(db: Session, case_id: str, run_id: str | None, profile: str | None) -> MemoryScanRun:
    query = db.query(MemoryScanRun).filter(MemoryScanRun.case_id == case_id)
    if run_id:
        run = query.filter(MemoryScanRun.id == run_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="Memory run not found")
        return run
    if profile:
        run = (
            query.filter(MemoryScanRun.profile == profile, MemoryScanRun.status.in_(["completed", "completed_with_errors"]))
            .order_by(MemoryScanRun.completed_at.desc().nullslast(), MemoryScanRun.created_at.desc())
            .first()
        )
        if not run:
            raise HTTPException(status_code=404, detail=f"No completed {profile} run was found for this case.")
        return run
    run = (
        query.filter(MemoryScanRun.status.in_(["completed", "completed_with_errors"]))
        .order_by(MemoryScanRun.completed_at.desc().nullslast(), MemoryScanRun.created_at.desc())
        .first()
    )
    if not run:
        raise HTTPException(status_code=404, detail="No completed memory run was found for this case.")
    return run


def _is_process_profile(profile: str | None) -> bool:
    return bool(profile) and profile in {"processes_basic", "processes_extended"}


@router.get("/cases/{case_id}/memory/runs/options", response_model=MemoryRunSelectorRead)
def get_memory_run_options(case_id: str, db: Session = Depends(get_db)) -> dict:
    _require_case(db, case_id)
    runs = (
        db.query(MemoryScanRun)
        .filter(MemoryScanRun.case_id == case_id)
        .order_by(MemoryScanRun.created_at.desc())
        .all()
    )
    completed_process = next(
        (
            r
            for r in runs
            if _is_process_profile(r.profile) and r.status in ("completed", "completed_with_errors")
        ),
        None,
    )
    options: list[dict] = []
    for r in runs:
        if not _is_process_profile(r.profile) and r.profile != "metadata_only":
            continue
        options.append(
            {
                "run_id": r.id,
                "profile": r.profile,
                "status": r.status,
                "created_at": r.created_at,
                "completed_at": r.completed_at,
                "plugin_count": r.plugin_count,
                "plugins_completed": r.plugins_completed,
                "plugins_failed": r.plugins_failed,
                "selected": bool(completed_process and r.id == completed_process.id),
            }
        )
    default = completed_process.id if completed_process else None
    return {
        "runs": options,
        "default_run_id": default,
        "combined_historical_available": sum(1 for r in runs if _is_process_profile(r.profile)) > 1,
    }


@router.get("/cases/{case_id}/memory/process-entities/summary", response_model=MemoryRenormalizeSummaryRead)
def get_canonical_process_summary(
    case_id: str,
    run_id: str | None = Query(default=None),
    profile: str | None = Query(default=None, pattern="^(processes_basic|processes_extended)$"),
    db: Session = Depends(get_db),
) -> dict:
    _require_case(db, case_id)
    run = _resolve_run(db, case_id, run_id, profile)
    summary = canonical_entities.fetch_canonical_summary(case_id, run_id=run.id)
    return {
        "case_id": case_id,
        "evidence_id": run.evidence_id,
        "run_id": run.id,
        "source_documents": 0,
        "candidate_entities": summary["total_entities"],
        "observation_count": 0,
        "duplicate_groups_collapsed": 0,
        "invalid_records": 0,
        "ambiguous_pid_groups": 0,
        "expected_edges": 0,
        "tree_metrics": {
            "total_nodes": summary["total_entities"],
            "roots": summary["roots"],
            "orphans": summary["orphans"],
            "unknown_parent": summary["unknown_parent"],
            "cycles": summary["cycles"],
            "self_parent": summary["self_parent"],
            "hidden_candidates": summary["hidden_candidate"],
            "scan_only": summary["scan_only"],
            "terminated": summary["terminated"],
            "pid_zero_count": summary["pid_zero"],
            "pid_4_count": summary["pid_4"],
        },
        "normalization_version": canonical_entities.NORMALIZATION_VERSION,
        "materialization_status": "applied",
    }


@router.get("/cases/{case_id}/memory/process-entities/renormalize", response_model=MemoryRenormalizeSummaryRead)
def renormalize_canonical_entities_get_redirect() -> dict:
    raise HTTPException(
        status_code=405,
        detail="Renormalize is a POST endpoint. Use POST /api/cases/{case_id}/memory/process-entities/renormalize.",
    )


@router.get("/cases/{case_id}/memory/process-entities", response_model=MemoryProcessEntityListRead)
def get_canonical_process_entities(
    case_id: str,
    run_id: str | None = Query(default=None),
    profile: str | None = Query(default=None, pattern="^(processes_basic|processes_extended)$"),
    evidence_id: str | None = Query(default=None),
    visibility: str | None = Query(default=None, pattern="^(listed|scan_only|terminated|unknown|hidden_candidate)$"),
    source_plugin: str | None = Query(default=None, pattern="^(windows\\.pslist|windows\\.psscan|windows\\.pstree|windows\\.cmdline)$"),
    process_name: str | None = Query(default=None),
    pid: int | None = Query(default=None, ge=0),
    ppid: int | None = Query(default=None, ge=0),
    has_command_line: bool | None = Query(default=None),
    interesting_only: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict:
    _require_case(db, case_id)
    run = _resolve_run(db, case_id, run_id, profile)
    result = canonical_entities.fetch_canonical_entities(
        case_id,
        run_id=run.id,
        visibility=visibility,
        source_plugin=source_plugin,
        process_name=process_name,
        pid=pid,
        ppid=ppid,
        has_command_line=has_command_line,
        interesting_only=interesting_only,
        page=page,
        page_size=page_size,
    )
    items = result["items"]
    total_observations = sum(item.get("observation_count", 0) for item in items)
    return {
        "items": items,
        "total": result["total"],
        "page": result["page"],
        "page_size": result["page_size"],
        "selected_run": run.id,
        "normalization_version": canonical_entities.NORMALIZATION_VERSION,
        "total_observations": total_observations,
        "facets": {},
    }


@router.get("/cases/{case_id}/memory/process-entities/{entity_id}", response_model=MemoryProcessEntityDetailRead)
def get_canonical_process_entity_detail(
    case_id: str,
    entity_id: str,
    run_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict:
    _require_case(db, case_id)
    run = _resolve_run(db, case_id, run_id, profile="processes_extended")
    entity = canonical_entities.fetch_canonical_entity(case_id, run_id=run.id, entity_id=entity_id)
    if entity is None:
        # Try basic profile too
        run2 = _resolve_run(db, case_id, None, profile="processes_basic")
        entity = canonical_entities.fetch_canonical_entity(case_id, run_id=run2.id, entity_id=entity_id)
        if entity is None:
            raise HTTPException(status_code=404, detail="Memory process entity was not found.")
        run = run2
    observations = canonical_entities.fetch_canonical_observations(case_id, run_id=run.id, entity_id=entity_id)
    alternate_command_lines: list[str] = []
    for obs in observations:
        cl = (obs.get("observed") or {}).get("command_line")
        if cl and cl != entity.get("process", {}).get("command_line") and cl not in alternate_command_lines:
            alternate_command_lines.append(cl)
    parent = None
    children: list[dict] = []
    parent_id = entity.get("parent_entity_id")
    if parent_id:
        parent = canonical_entities.fetch_canonical_entity(case_id, run_id=run.id, entity_id=parent_id)
    # Fetch children
    children_page = canonical_entities.fetch_canonical_entities(
        case_id, run_id=run.id, page=1, page_size=200
    )
    for child in children_page["items"]:
        if child.get("parent_entity_id") == entity_id:
            children.append(child)
    tree_path: list[str] = []
    cursor = parent_id
    while cursor:
        tree_path.append(cursor)
        ancestor = canonical_entities.fetch_canonical_entity(case_id, run_id=run.id, entity_id=cursor)
        cursor = ancestor.get("parent_entity_id") if ancestor else None
    source_record_refs = [obs.get("source_record_id", "") for obs in observations if obs.get("source_record_id")]
    return {
        "entity": entity,
        "observations": observations,
        "parent": parent,
        "children": children,
        "tree_path": tree_path,
        "alternate_command_lines": alternate_command_lines,
        "findings": entity.get("findings", []),
        "source_record_refs": source_record_refs,
    }


@router.get("/cases/{case_id}/memory/process-tree-canonical", response_model=MemoryProcessTreeEntityRead)
def get_canonical_process_tree(
    case_id: str,
    run_id: str | None = Query(default=None),
    profile: str | None = Query(default=None, pattern="^(processes_basic|processes_extended)$"),
    root_pid: int | None = Query(default=None, ge=0),
    root_entity_id: str | None = Query(default=None, max_length=128),
    depth: int = Query(default=3, ge=1, le=10),
    max_nodes: int | None = Query(default=None, ge=1, le=2000),
    visibility: str | None = Query(default=None, pattern="^(listed|scan_only|terminated|unknown|hidden_candidate)$"),
    interesting_only: bool | None = Query(default=None),
    include_ancestors: bool = Query(default=False),
    orphans_only: bool = Query(default=False),
    search: str | None = Query(default=None, max_length=128),
    db: Session = Depends(get_db),
) -> dict:
    _require_case(db, case_id)
    run = _resolve_run(db, case_id, run_id, profile)
    return canonical_entities.fetch_canonical_tree(
        case_id,
        run_id=run.id,
        root_pid=root_pid,
        root_entity_id=root_entity_id,
        depth=depth,
        max_nodes=max_nodes,
        visibility=visibility,
        interesting_only=interesting_only,
        include_ancestors=include_ancestors,
        orphans_only=orphans_only,
        search=search,
    )


@router.post("/cases/{case_id}/memory/process-entities/renormalize", response_model=MemoryRenormalizeSummaryRead)
def renormalize_canonical_entities(
    case_id: str,
    payload: _RenormalizeRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Reconcile legacy per-plugin memory_process documents into canonical entities.

    The legacy documents (one per plugin-row) are preserved; the
    canonical entities, observations and edges are written alongside
    them, keyed by the same run id.  ``dry_run=True`` returns the
    summary without writing to OpenSearch.
    """
    _require_case(db, case_id)
    run = db.get(MemoryScanRun, payload.run_id)
    if not run or run.case_id != case_id:
        raise HTTPException(status_code=404, detail="Memory run not found for this case.")
    if not _is_process_profile(run.profile):
        raise HTTPException(status_code=400, detail="Renormalization is only supported for processes_basic/processes_extended runs.")
    evidence = db.get(Evidence, run.evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Memory evidence not found for this run.")
    raw_documents = canonical_entities.fetch_legacy_process_documents(case_id, run_id=run.id)
    result = canonical_entities.renormalize_documents(
        raw_documents,
        case_id=case_id,
        evidence_id=run.evidence_id,
        run_id=run.id,
        materialize=not payload.dry_run,
    )
    summary = result["summary"]
    summary["materialization_status"] = "applied" if not payload.dry_run else "dry_run"
    return summary
