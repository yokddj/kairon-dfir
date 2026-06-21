from datetime import UTC, datetime
import json
import logging
from datetime import datetime, date
from typing import Any


logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType
from app.models.memory import MemoryArtifactSummary, MemoryPluginRun, MemoryScanRun, MemorySymbolAcquisition
from app.schemas.memory import MemoryArtifactDetailRead, MemoryArtifactListRead, MemoryArtifactOverviewRead, MemoryBackendOverviewRead, MemoryEvidenceRead, MemoryEvidenceReadinessRead, MemoryOverviewRead, MemoryProcessEntityDetailRead, MemoryProcessEntityListRead, MemoryProcessListRead, MemoryProcessTreeEntityRead, MemoryProcessTreeRead, MemoryRenormalizeSummaryRead, MemoryRunDetailRead, MemoryRunOptionsRead, MemoryRunSelectorRead, MemoryScanRunRead, MemoryStartScanRequest, MemoryStartScanResponse, MemorySymbolAcquireRequest, MemorySymbolAcquireResponse, MemorySymbolCacheStatusRead, MemorySymbolRequestCreateRequest, MemorySymbolRequestCreateResponse, MemorySymbolRequestStatusRead, MemorySystemInfoRead, MemoryUploadReadinessRead, MemoryUploadStatusRead
from app.services.memory.artifact_indexing import (
    get_artifact_document,
    link_process_entities,
    search_artifact_documents,
)
from app.services.memory.volatility_runner import network_basic_available
from app.services.memory.backend_readiness import check_volatility3_backend, get_memory_backend_overview
from app.services.memory.execution import active_run_for_evidence, create_memory_metadata_run, mark_run_queued, resolve_profile_plugins
from app.services.memory.evidence_access import evidence_readiness
from app.services.memory.indexing import ensure_memory_index, get_memory_document, get_opensearch_client, search_memory_edges, search_memory_processes
from app.services.memory.normalizers import normalize_windows_info
from app.services.memory.storage import memory_run_dir
from app.services.memory.overview import get_case_memory_overview, get_evidence_landing, list_memory_evidences
from app.services.memory.active_result import resolve_active_memory_result, list_families as _list_artifact_families
from app.services.memory.catalogue import build_analysis_catalogue, MemoryProfileUnavailableError
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


def _require_evidence_for_case(db: Session, case_id: str, evidence_id: str) -> Evidence:
    """Validate that the given evidence_id belongs to the case and is a
    memory dump.  Returns the Evidence row.  Raises 400 when the
    evidence_id is missing (evidence-scope required) and 404 when the
    evidence does not exist or does not belong to the case.
    """
    if not evidence_id or not isinstance(evidence_id, str):
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "MEMORY_EVIDENCE_SCOPE_REQUIRED",
                "message": "evidence_id is required for this memory read endpoint.",
            },
        )
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.case_id != case_id or evidence.evidence_type != EvidenceType.memory_dump:
        raise HTTPException(status_code=404, detail="Memory evidence was not found for this case.")
    return evidence


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


@router.get(
    "/cases/{case_id}/memory/landing",
    response_model=None,
)
def get_memory_evidence_landing(case_id: str, db: Session = Depends(get_db)) -> dict:
    """Per-evidence landing for the memory case page.  Each entry
    includes the evidence metadata and a per-family status snapshot
    (Ready / Not analyzed / Completed / Running / Latest attempt
    failed / Unavailable).
    """
    _require_case(db, case_id)
    items = get_evidence_landing(db, case_id)
    return {
        "case_id": case_id,
        "items": items,
    }


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


@router.get(
    "/cases/{case_id}/memory/evidences/{evidence_id}/active-result",
    response_model=None,
)
def get_memory_active_result(
    case_id: str,
    evidence_id: str,
    family: str = Query(...),
    run_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict:
    """Return the active scan run for a single artifact family of an
    evidence.  ``family`` must be one of the supported artifact
    families (system_info, processes, network, modules, handles,
    kernel_modules, drivers, suspicious_regions, raw_observations).

    When ``run_id`` is provided the function validates that the run
    belongs to this evidence + case and returns it as a historical
    override.  When ``run_id`` is not provided the function returns
    the latest successful run for the family plus a snapshot of the
    latest attempt (which may have failed).
    """
    _require_case(db, case_id)
    _require_evidence_for_case(db, case_id, evidence_id)
    if family not in _list_artifact_families():
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "MEMORY_FAMILY_UNKNOWN",
                "message": f"Unknown artifact family '{family}'.",
            },
        )
    return resolve_active_memory_result(
        db,
        case_id=case_id,
        evidence_id=evidence_id,
        family=family,
        preferred_run_id=run_id,
    )


@router.get(
    "/cases/{case_id}/memory/evidences/{evidence_id}/catalogue",
    response_model=None,
)
def get_memory_evidence_catalogue(
    case_id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
) -> dict:
    """Return the 8-profile analysis catalogue for an evidence.

    The catalogue is the single source of truth for the "Run
    analysis" modal in the UI.  The network profile is always
    rendered as Unavailable in the current Volatility runtime.
    """
    _require_case(db, case_id)
    _require_evidence_for_case(db, case_id, evidence_id)
    items = build_analysis_catalogue(
        db,
        case_id=case_id,
        evidence_id=evidence_id,
    )
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "items": items,
    }


@router.post(
    "/cases/{case_id}/memory/evidences/{evidence_id}/run-all",
    response_model=None,
    status_code=status.HTTP_201_CREATED,
)
def post_run_all_batch(
    case_id: str,
    evidence_id: str,
    payload: dict | None = None,
    db: Session = Depends(get_db),
) -> dict:
    """Create a ``MemoryAnalysisBatch`` that orchestrates the
    ``missing_or_failed`` (default) or ``rerun_all`` profiles for an
    evidence.  The batch enqueues only the first profile; the
    remaining profiles are advanced by the worker when each run
    finishes.
    """
    from app.services.memory.batch import (
        MemoryBatchError,
        create_run_all_batch,
        plan_run_all,
        serialize_batch,
    )
    from app.workers.tasks import enqueue_memory_metadata_scan

    _require_case(db, case_id)
    _require_evidence_for_case(db, case_id, evidence_id)
    payload = payload or {}
    if not bool(payload.get("authorization_acknowledged", False)):
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "MEMORY_BATCH_AUTHORIZATION_REQUIRED",
                "message": "authorization_acknowledged must be true to start a run-all batch.",
            },
        )
    mode = (payload.get("mode") or "missing_or_failed").strip()
    continue_on_failure = bool(payload.get("continue_on_failure", True))
    try:
        result = create_run_all_batch(
            db,
            case_id=case_id,
            evidence_id=evidence_id,
            mode=mode,
            authorization_acknowledged=True,
            continue_on_failure=continue_on_failure,
            enqueue_fn=enqueue_memory_metadata_scan,
        )
    except MemoryBatchError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"error_code": exc.code, "message": exc.message}) from exc

    batch = result["batch"]
    first_run = result["first_run"]
    plan = result["plan"]
    payload_out = serialize_batch(batch)
    payload_out["plan"] = plan
    if first_run is not None:
        payload_out["first_run_id"] = first_run.id
    return payload_out


@router.get(
    "/cases/{case_id}/memory/evidences/{evidence_id}/run-all/preview",
    response_model=None,
)
def get_run_all_preview(
    case_id: str,
    evidence_id: str,
    mode: str = Query(default="missing_or_failed"),
    db: Session = Depends(get_db),
) -> dict:
    """Return the plan for a run-all batch without creating it.

    The UI calls this endpoint to populate the confirmation modal
    with the ordered list of profiles, the skipped profiles and the
    excluded profiles.
    """
    from app.services.memory.batch import (
        MemoryBatchError,
        plan_run_all,
    )

    _require_case(db, case_id)
    _require_evidence_for_case(db, case_id, evidence_id)
    try:
        plan = plan_run_all(db, case_id=case_id, evidence_id=evidence_id, mode=mode)
    except MemoryBatchError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"error_code": exc.code, "message": exc.message}) from exc
    return {"case_id": case_id, "evidence_id": evidence_id, "mode": mode, **plan}


@router.get(
    "/cases/{case_id}/memory/evidences/{evidence_id}/analysis-batches/active",
    response_model=None,
)
def get_active_analysis_batch(
    case_id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
) -> dict:
    """Return the in-flight batch (queued or running) for the evidence.

    The frontend polls this endpoint while a batch is running.  The
    endpoint returns 404 when no active batch exists.

    NOTE: this route must be declared before the
    ``/{batch_id}`` route so the literal segment ``active`` does
    not get captured as a batch id.
    """
    from app.services.memory.batch import find_active_batch, serialize_batch

    _require_case(db, case_id)
    _require_evidence_for_case(db, case_id, evidence_id)
    batch = find_active_batch(db, case_id=case_id, evidence_id=evidence_id)
    if batch is None:
        raise HTTPException(status_code=404, detail="No active batch for this evidence.")
    return serialize_batch(batch)


@router.get(
    "/cases/{case_id}/memory/evidences/{evidence_id}/analysis-batches/{batch_id}",
    response_model=None,
)
def get_analysis_batch(
    case_id: str,
    evidence_id: str,
    batch_id: str,
    db: Session = Depends(get_db),
) -> dict:
    """Return the state of a single batch."""
    from app.services.memory.batch import get_batch, serialize_batch

    _require_case(db, case_id)
    _require_evidence_for_case(db, case_id, evidence_id)
    batch = get_batch(db, batch_id=batch_id)
    if batch is None or batch.case_id != case_id or batch.evidence_id != evidence_id:
        raise HTTPException(status_code=404, detail="Memory analysis batch not found.")
    return serialize_batch(batch)


@router.post(
    "/cases/{case_id}/memory/evidences/{evidence_id}/analysis-batches/{batch_id}/cancel",
    response_model=None,
)
def cancel_analysis_batch(
    case_id: str,
    evidence_id: str,
    batch_id: str,
    db: Session = Depends(get_db),
) -> dict:
    """Request cancellation of a batch.  The currently running scan
    is left to finish (we never kill an in-flight plugin) but no
    new profile is enqueued.
    """
    from app.services.memory.batch import cancel_batch, get_batch, serialize_batch

    _require_case(db, case_id)
    _require_evidence_for_case(db, case_id, evidence_id)
    batch = get_batch(db, batch_id=batch_id)
    if batch is None or batch.case_id != case_id or batch.evidence_id != evidence_id:
        raise HTTPException(status_code=404, detail="Memory analysis batch not found.")
    updated = cancel_batch(db, batch_id=batch_id) or batch
    return serialize_batch(updated)


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
def get_memory_runs(
    case_id: str,
    evidence_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[MemoryScanRun]:
    _require_case(db, case_id)
    query = db.query(MemoryScanRun).filter(MemoryScanRun.case_id == case_id)
    if evidence_id:
        _require_evidence_for_case(db, case_id, evidence_id)
        query = query.filter(MemoryScanRun.evidence_id == evidence_id)
    return query.order_by(MemoryScanRun.created_at.desc()).all()


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
    if profile == "network_basic":
        available, reason = network_basic_available()
        if not available:
            raise HTTPException(
                status_code=400,
                detail={"error_code": "MEMORY_PROFILE_UNAVAILABLE", "message": reason},
            )
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


@router.post("/cases/{case_id}/memory/system-info/reindex", response_model=list[MemorySystemInfoRead])
def reindex_system_info(case_id: str, db: Session = Depends(get_db)) -> list[dict]:
    """Re-normalize windows.info results from the existing raw output.

    The previous normalizer only inspected the first row of the
    windows.info output, which produced documents with every OS /
    memory field set to ``null``.  This endpoint re-runs the
    normalizer on the existing raw ``windows.info.json`` files
    on disk, without re-running Volatility or rewriting other
    indices, and updates the run's ``system_info`` payload in
    PostgreSQL plus the OpenSearch document.
    """
    _require_case(db, case_id)
    runs = (
        db.query(MemoryScanRun)
        .filter(MemoryScanRun.case_id == case_id, MemoryScanRun.status.in_(["completed", "completed_with_errors"]))
        .order_by(MemoryScanRun.completed_at.desc().nullslast(), MemoryScanRun.created_at.desc())
        .all()
    )
    settings = get_settings()
    results: list[dict] = []
    for run in runs:
        primary_dir = memory_run_dir(run.case_id, run.evidence_id, run.id)
        # The actual raw output may live under the configured
        # output root even if the primary resolver returns the
        # generic evidence directory.  Probe both locations.
        candidate_paths = [
            primary_dir / "windows.info.json",
            settings.backend_data_dir / "memory-output" / "evidence" / run.case_id / run.evidence_id / "memory" / "runs" / run.id / "windows.info.json",
        ]
        raw_path = next((path for path in candidate_paths if path.exists()), None)
        if raw_path is None:
            continue
        try:
            payload = json.loads(raw_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        plugin_run = (
            db.query(MemoryPluginRun)
            .filter(MemoryPluginRun.memory_scan_run_id == run.id, MemoryPluginRun.plugin == "windows.info")
            .order_by(MemoryPluginRun.created_at.desc())
            .first()
        )
        plugin_run_id = plugin_run.id if plugin_run else ""
        system_info = normalize_windows_info(
            payload,
            case_id=run.case_id,
            evidence_id=run.evidence_id,
            memory_run_id=run.id,
            memory_plugin_run_id=plugin_run_id,
            backend_version=run.backend_version,
        )
        # Ensure all datetimes are ISO strings for JSON / OpenSearch.
        system_info = _jsonify_system_info(system_info)
        metadata = dict(run.metadata_json or {})
        metadata["system_info"] = system_info
        run.metadata_json = metadata
        db.commit()
        # Update the OpenSearch document as well.
        try:
            index = ensure_memory_index(run.case_id)
            client = get_opensearch_client()
            doc_id = f"{run.id}:memory_system_info"
            client.index(
                index=index,
                id=doc_id,
                body={
                    **system_info,
                    "document_type": "memory_system_info",
                    "document_id": doc_id,
                },
                refresh=True,
            )
        except Exception:  # noqa: BLE001
            logger.warning("Failed to update OpenSearch system info doc", extra={"run_id": run.id})
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
    run_id: str | None = None
    dry_run: bool = True


def _jsonify_system_info(value):
    """Recursively convert datetime/date values to ISO strings."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _jsonify_system_info(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonify_system_info(item) for item in value]
    return value


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


_ARTIFACT_PROFILES_API = {
    "network_basic",
    "modules_basic",
    "handles_basic",
    "kernel_basic",
    "suspicious_memory",
}


def _is_visible_profile(profile: str | None) -> bool:
    """Profile is exposed in the run picker when it is a process
    profile, metadata_only, or one of the new artifact profiles.
    """
    if not profile:
        return False
    if _is_process_profile(profile):
        return True
    if profile == "metadata_only":
        return True
    return profile in _ARTIFACT_PROFILES_API


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
        if not _is_visible_profile(r.profile):
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
    if evidence_id:
        _require_evidence_for_case(db, case_id, evidence_id)
    run = _resolve_run(db, case_id, run_id, profile)
    result = canonical_entities.fetch_canonical_entities(
        case_id,
        run_id=run.id,
        evidence_id=evidence_id,
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


@router.post(
    "/cases/{case_id}/memory/runs/{run_id}/rematerialize-canonical",
    response_model=MemoryRenormalizeSummaryRead,
)
def rematerialize_canonical(
    case_id: str,
    run_id: str,
    payload: _RenormalizeRequest | None = None,
    db: Session = Depends(get_db),
) -> dict:
    """Repair canonical materialization for an existing process run.

    The run already has raw ``memory_process`` documents in OpenSearch.
    This endpoint re-runs the canonical pipeline (without re-executing
    Volatility): it pulls the raw documents, deduplicates them, indexes
    the canonical entities / observations / edges and updates the run's
    ``canonical_materialization_status`` to ``completed``.

    The operation is **idempotent**: re-running it over the same raw
    documents produces the same OpenSearch document IDs (the
    ``document_id`` is derived from the run id + identity hash) and
    the same counts.
    """
    from app.services.memory.execution import _run_canonical_materialization
    from app.services.memory.canonical_entities import fetch_legacy_process_documents

    _require_case(db, case_id)
    run = db.get(MemoryScanRun, run_id)
    if not run or run.case_id != case_id:
        raise HTTPException(status_code=404, detail="Memory run not found for this case.")
    if not _is_process_profile(run.profile):
        raise HTTPException(
            status_code=400,
            detail="Repair is only supported for processes_basic/processes_extended runs.",
        )
    payload = payload or _RenormalizeRequest(dry_run=False)  # type: ignore[call-arg]
    raw_documents = fetch_legacy_process_documents(case_id, run_id=run.id)
    if not raw_documents:
        raise HTTPException(
            status_code=409,
            detail="No raw memory_process documents found for this run. "
                   "Re-run the Volatility profile to populate raw observations first.",
        )
    if payload.dry_run:
        result = canonical_entities.renormalize_documents(
            raw_documents,
            case_id=case_id,
            evidence_id=run.evidence_id,
            run_id=run.id,
            materialize=False,
        )
        summary = result["summary"]
        summary["materialization_status"] = "dry_run"
        return summary
    _run_canonical_materialization(db, run, documents=raw_documents)
    db.refresh(run)
    return {
        "case_id": case_id,
        "evidence_id": run.evidence_id,
        "run_id": run.id,
        "source_documents": len(raw_documents),
        "candidate_entities": run.canonical_entity_count,
        "observation_count": run.canonical_observation_count,
        "duplicate_groups_collapsed": max(0, len(raw_documents) - run.canonical_entity_count),
        "invalid_records": 0,
        "ambiguous_pid_groups": 0,
        "expected_edges": 0,
        "tree_metrics": {
            "roots": run.canonical_root_count,
            "orphans": run.canonical_orphan_count,
            "scan_only": run.canonical_scan_only_count,
        },
        "normalization_version": run.canonical_materialization_version,
        "materialization_status": "applied",
    }


@router.post(
    "/cases/{case_id}/memory/process-entities/recompute-tree",
    response_model=MemoryRenormalizeSummaryRead,
)
def recompute_canonical_tree(
    case_id: str,
    payload: _RenormalizeRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Recompute the tree / parent linkage for the canonical entities of a run.

    The legacy normalizer computed the parent chain in a way that
    lost the canonical ``tree.is_root`` flag on certain entities
    (notably System when PID 0 is present).  This endpoint pulls
    the existing canonical entities from OpenSearch, rebuilds the
    parent map, and re-applies ``build_tree_metrics`` in place.
    It does not touch the raw plugin records, the evidence, the
    symbol cache, the workers or the disk index.
    """
    _require_case(db, case_id)
    run = db.get(MemoryScanRun, payload.run_id)
    if not run or run.case_id != case_id:
        raise HTTPException(status_code=404, detail="Memory run not found for this case.")
    if not _is_process_profile(run.profile):
        raise HTTPException(status_code=400, detail="Recompute-tree is only supported for processes_basic/processes_extended runs.")
    # Fetch all canonical entities for the run in pages.
    page = 1
    page_size = 200
    all_entities: list[dict[str, Any]] = []
    while True:
        result = canonical_entities.fetch_canonical_entities(
            case_id, run_id=run.id, page=page, page_size=page_size
        )
        items = result["items"]
        all_entities.extend(items)
        if len(items) < page_size:
            break
        page += 1
    metrics = canonical_entities.build_tree_metrics(all_entities)
    # Persist updated tree + parent_entity_id back to OpenSearch.
    from app.core.opensearch import get_memory_index, get_opensearch_client
    index = get_memory_index(case_id)
    client = get_opensearch_client()
    for ent in all_entities:
        try:
            client.index(
                index=index,
                id=ent["document_id"],
                body={
                    **ent,
                    "document_id": ent["document_id"],
                    "document_type": "memory_process_entity",
                },
                refresh=False,
            )
        except Exception:  # noqa: BLE001
            logger.warning("Failed to update canonical tree doc", extra={"entity_id": ent.get("process_entity_id")})
    if all_entities:
        client.indices.refresh(index=index)
    return {
        "case_id": case_id,
        "evidence_id": run.evidence_id,
        "run_id": run.id,
        "source_documents": len(all_entities),
        "candidate_entities": len(all_entities),
        "observation_count": sum(int(e.get("observation_count") or 0) for e in all_entities),
        "duplicate_groups_collapsed": 0,
        "invalid_records": 0,
        "ambiguous_pid_groups": 0,
        "expected_edges": sum(1 for e in all_entities if e.get("parent_entity_id")),
        "tree_metrics": metrics,
        "normalization_version": canonical_entities.NORMALIZATION_VERSION,
        "materialization_status": "applied",
    }


# ---------------------------------------------------------------------------
# Core memory artifact endpoints
# ---------------------------------------------------------------------------


_ARTIFACT_DOC_TYPES = {
    "memory_network_connection",
    "memory_process_module",
    "memory_handle",
    "memory_kernel_module",
    "memory_driver",
    "memory_suspicious_region",
}


def _resolve_run(db: Session, case_id: str, run_id: str | None, profile: str | None = None) -> MemoryScanRun | None:
    """Resolve a memory run for a case.

    The 4-arg signature (``profile``) is kept as an optional parameter
    for the canonical process-entity endpoints.  When ``run_id`` is
    provided, the function returns the matching run for the case (or
    ``None`` when the run does not exist).  When ``run_id`` is
    ``None``, the function falls back to a profile-based lookup that
    returns the latest completed run of the requested profile.
    """
    if run_id:
        run = db.get(MemoryScanRun, run_id)
        if run is None or run.case_id != case_id:
            return None
        return run
    if not profile:
        return None
    query = db.query(MemoryScanRun).filter(MemoryScanRun.case_id == case_id)
    return (
        query.filter(
            MemoryScanRun.profile == profile,
            MemoryScanRun.status.in_(["completed", "completed_with_errors"]),
        )
        .order_by(MemoryScanRun.completed_at.desc().nullslast(), MemoryScanRun.created_at.desc())
        .first()
    )


def _artifact_list(
    case_id: str,
    *,
    document_type: str,
    run_id: str | None,
    evidence_id: str | None = None,
    page: int,
    page_size: int,
    filters: dict[str, Any] | None = None,
    sort: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    ensure_memory_index(case_id)
    payload = search_artifact_documents(
        case_id,
        document_type=document_type,
        run_id=run_id,
        evidence_id=evidence_id,
        page=page,
        page_size=page_size,
        filters=filters,
        sort=sort,
    )
    facets = _artifact_facets(case_id, document_type=document_type, run_id=run_id, evidence_id=evidence_id)
    return {
        "document_type": document_type,
        "selected_run": run_id,
        "evidence_id": evidence_id,
        "total": payload["total"],
        "page": payload["page"],
        "page_size": payload["page_size"],
        "items": payload["items"],
        "facets": facets,
        "normalization_version": payload["normalization_version"],
    }


def _artifact_facets(case_id: str, *, document_type: str, run_id: str | None, evidence_id: str | None = None) -> dict[str, Any]:
    """Compute lightweight aggregation facets for the artifact list.

    Avoids the cost of running a full OpenSearch aggregation by
    reusing the ``MemoryArtifactSummary`` table when the data is local.
    """
    return {}


def _artifact_overview(
    case_id: str,
    db: Session,
    run_id: str | None,
    evidence_id: str | None = None,
) -> dict[str, Any]:
    """Return the per-family artifact overview.

    The function uses the unified
    :func:`app.services.memory.counts.get_memory_family_count` so
    the numbers are consistent with the catalogue and the Overview.
    """
    from app.services.memory.counts import (
        FAMILY_TO_DOCUMENT_TYPE,
        get_memory_family_count,
    )

    run = _resolve_run(db, case_id, run_id)
    selected_run = run.id if run else None
    run_status = run.status if run else None
    profile = run.profile if run else None
    evidence_id_value = evidence_id or (run.evidence_id if run else None)
    if not evidence_id_value:
        return {
            "case_id": case_id,
            "selected_run": selected_run,
            "run_status": run_status,
            "profile": profile,
            "evidence_id": None,
            "network_connections": {"count": 0},
            "process_modules": {"count": 0},
            "module_discrepancies": 0,
            "kernel_modules": {"count": 0},
            "drivers": {"count": 0},
            "handles": {"count": 0},
            "suspicious_regions": {"count": 0},
            "facets": {},
            "normalization_version": "memory_artifact_canonical_v1",
        }
    ensure_memory_index(case_id)
    counts: dict[str, int] = {}
    for family, doc_type in FAMILY_TO_DOCUMENT_TYPE.items():
        payload = get_memory_family_count(
            case_id=case_id,
            evidence_id=evidence_id_value,
            family=family,
            active_run_id=selected_run,
            db=db,
        )
        counts[family] = int(payload["total"])
    facets: dict[str, Any] = {}
    module_discrepancies = 0
    if selected_run:
        summary_rows = (
            db.query(MemoryArtifactSummary)
            .filter(MemoryArtifactSummary.memory_run_id == selected_run, MemoryArtifactSummary.memory_artifact_type == "memory_process_module")
            .all()
        )
        # The merge step persists the discrepancy count in the summary
        # metadata_json only when merging happened; 0 otherwise.
    return {
        "case_id": case_id,
        "evidence_id": evidence_id_value,
        "selected_run": selected_run,
        "run_status": run_status,
        "profile": profile,
        "network_connections": {"count": counts["network"]},
        "process_modules": {"count": counts["modules"]},
        "module_discrepancies": module_discrepancies,
        "kernel_modules": {"count": counts["kernel_modules"]},
        "drivers": {"count": counts["drivers"]},
        "handles": {"count": counts["handles"]},
        "suspicious_regions": {"count": counts["suspicious_regions"]},
        "facets": facets,
        "normalization_version": "memory_artifact_canonical_v1",
    }


@router.get("/cases/{case_id}/memory/artifacts/overview", response_model=MemoryArtifactOverviewRead)
def get_case_memory_artifacts_overview(
    case_id: str,
    run_id: str | None = Query(default=None),
    evidence_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    _require_case(db, case_id)
    if evidence_id is not None:
        _require_evidence_for_case(db, case_id, evidence_id)
    return _artifact_overview(case_id, db, run_id, evidence_id=evidence_id)


@router.post("/cases/{case_id}/memory/artifacts/relink/{run_id}")
def relink_artifact_process_entities(
    case_id: str,
    run_id: str,
    db: Session = Depends(get_db),
) -> dict[str, int]:
    """Re-link artifact documents to canonical process entities for the
    given run.  Idempotent: re-running with the same input is a no-op.
    """
    _require_case(db, case_id)
    if not _resolve_run(db, case_id, run_id):
        raise HTTPException(status_code=404, detail="Memory run not found.")
    linked = 0
    for doc_type in ("memory_process_module", "memory_handle", "memory_network_connection"):
        try:
            linked += int(link_process_entities(case_id, scan_run_id=run_id, document_type=doc_type))
        except Exception as exc:  # noqa: BLE001
            logger.warning("artifact re-link failed for %s: %s", doc_type, exc)
    return {"linked": linked}


@router.get("/cases/{case_id}/memory/network", response_model=MemoryArtifactListRead)
def list_memory_network_connections(
    case_id: str,
    evidence_id: str = Query(...),
    run_id: str | None = Query(default=None),
    protocol: str | None = Query(default=None),
    local_address: str | None = Query(default=None),
    local_port: int | None = Query(default=None),
    remote_address: str | None = Query(default=None),
    remote_port: int | None = Query(default=None),
    state: str | None = Query(default=None),
    pid: int | None = Query(default=None),
    process_name: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    _require_evidence_for_case(db, case_id, evidence_id)
    _require_run_or_any(case_id, run_id)
    filters: dict[str, Any] = {
        "protocol": protocol,
        "local_address": local_address,
        "local_port": local_port,
        "remote_address": remote_address,
        "remote_port": remote_port,
        "state": state,
        "pid": pid,
        "process_name": process_name,
    }
    return _artifact_list(
        case_id,
        document_type="memory_network_connection",
        run_id=run_id,
        evidence_id=evidence_id,
        page=page,
        page_size=page_size,
        filters=filters,
    )


@router.get("/cases/{case_id}/memory/modules", response_model=MemoryArtifactListRead)
def list_memory_process_modules(
    case_id: str,
    evidence_id: str = Query(...),
    run_id: str | None = Query(default=None),
    pid: int | None = Query(default=None),
    process_name: str | None = Query(default=None),
    module_name: str | None = Query(default=None),
    path: str | None = Query(default=None),
    load_state: str | None = Query(default=None),
    discrepancy_only: bool = Query(default=False),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    _require_evidence_for_case(db, case_id, evidence_id)
    _require_run_or_any(case_id, run_id)
    filters: dict[str, Any] = {
        "pid": pid,
        "process_name": process_name,
        "module_name": module_name,
        "path": path,
        "load_state": load_state,
    }
    sort: list[dict[str, Any]] | None = None
    if discrepancy_only:
        # "discrepancy_only" is implemented as an exists filter on the
        # ``findings`` keyword field.  The sort uses the same field so
        # that documents with the most findings are surfaced first.
        filters["findings"] = "module_list_discrepancy"
    return _artifact_list(
        case_id,
        document_type="memory_process_module",
        run_id=run_id,
        evidence_id=evidence_id,
        page=page,
        page_size=page_size,
        filters=filters,
        sort=sort,
    )


@router.get("/cases/{case_id}/memory/handles", response_model=MemoryArtifactListRead)
def list_memory_handles(
    case_id: str,
    evidence_id: str = Query(...),
    run_id: str | None = Query(default=None),
    pid: int | None = Query(default=None),
    process_name: str | None = Query(default=None),
    object_type: str | None = Query(default=None),
    object_name: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    _require_evidence_for_case(db, case_id, evidence_id)
    _require_run_or_any(case_id, run_id)
    filters: dict[str, Any] = {
        "pid": pid,
        "process_name": process_name,
        "object_type": object_type,
        "object_name": object_name,
    }
    return _artifact_list(
        case_id,
        document_type="memory_handle",
        run_id=run_id,
        evidence_id=evidence_id,
        page=page,
        page_size=page_size,
        filters=filters,
    )


@router.get("/cases/{case_id}/memory/kernel-modules", response_model=MemoryArtifactListRead)
def list_memory_kernel_modules(
    case_id: str,
    evidence_id: str = Query(...),
    run_id: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    _require_evidence_for_case(db, case_id, evidence_id)
    _require_run_or_any(case_id, run_id)
    return _artifact_list(
        case_id,
        document_type="memory_kernel_module",
        run_id=run_id,
        evidence_id=evidence_id,
        page=page,
        page_size=page_size,
    )


@router.get("/cases/{case_id}/memory/drivers", response_model=MemoryArtifactListRead)
def list_memory_drivers(
    case_id: str,
    evidence_id: str = Query(...),
    run_id: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    _require_evidence_for_case(db, case_id, evidence_id)
    _require_run_or_any(case_id, run_id)
    return _artifact_list(
        case_id,
        document_type="memory_driver",
        run_id=run_id,
        evidence_id=evidence_id,
        page=page,
        page_size=page_size,
    )


@router.get("/cases/{case_id}/memory/suspicious-regions", response_model=MemoryArtifactListRead)
def list_memory_suspicious_regions(
    case_id: str,
    evidence_id: str = Query(...),
    run_id: str | None = Query(default=None),
    pid: int | None = Query(default=None),
    process_name: str | None = Query(default=None),
    protection: str | None = Query(default=None),
    review_status: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    _require_evidence_for_case(db, case_id, evidence_id)
    _require_run_or_any(case_id, run_id)
    filters: dict[str, Any] = {
        "pid": pid,
        "process_name": process_name,
        "protection": protection,
        "review_status": review_status,
    }
    return _artifact_list(
        case_id,
        document_type="memory_suspicious_region",
        run_id=run_id,
        evidence_id=evidence_id,
        page=page,
        page_size=page_size,
        filters=filters,
    )


@router.get("/cases/{case_id}/memory/artifacts/{document_type}/{document_id}", response_model=MemoryArtifactDetailRead)
def get_memory_artifact_detail(
    case_id: str,
    document_type: str,
    document_id: str,
    db: Session = Depends(get_db),
):
    _require_case(db, case_id)
    if document_type not in _ARTIFACT_DOC_TYPES:
        raise HTTPException(status_code=400, detail="Unsupported artifact document type.")
    document = get_artifact_document(case_id, document_id)
    if not document or document.get("document_type") != document_type:
        raise HTTPException(status_code=404, detail="Artifact document not found.")
    return {
        "document_type": document_type,
        "document_id": document_id,
        "fields": document,
        "provenance": document.get("provenance", {}),
    }


def _require_run_or_any(case_id: str, run_id: str | None) -> None:
    """Light validation: the index may not exist yet, so we only check
    the run_id shape.  The search helpers tolerate missing indexes.
    """
    if run_id is not None and not isinstance(run_id, str):
        raise HTTPException(status_code=400, detail="run_id must be a string.")
