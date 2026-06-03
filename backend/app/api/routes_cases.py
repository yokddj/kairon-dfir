from copy import deepcopy
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
import json
import logging
import time
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.analysis.semi_auto import build_case_semi_auto_analysis, render_case_semi_auto_markdown, render_case_semi_auto_text
from app.core.activity import log_activity
from app.core.config import get_settings
from app.core.database import get_db, utc_now_naive
from app.core.opensearch import delete_case_index, get_events_index, get_index_health, get_opensearch_client, index_exists, is_index_queryable, resolve_aggregatable_field
from app.core.storage import case_storage_root, safe_remove
from app.models.activity import AppActivityEvent
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.case_analysis_job import CaseAnalysisJob, CaseAnalysisJobStatus
from app.models.detection_result import DetectionResult
from app.models.event_marking import EventMarking
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.incident_timeline_draft import IncidentTimelineDraft
from app.models.case_report import CaseReport
from app.models.rule import Rule
from app.models.rule_run import RuleRun
from app.models.rule_set import RuleSet
from app.models.tag import Tag
from app.schemas.debug_export import DebugExportRequest
from app.services.debug_export import build_execution_story, build_process_tree_bundle, build_process_tree_expansion, build_process_tree_focused, generate_debug_pack
from app.services.host_attribution import build_host_attribution
from app.services.host_identity import build_case_host_candidates, get_case_hosts
from app.services.case_state import build_case_next_actions, derive_case_investigation_state
from app.services.indexing_profiles import evidence_has_active_indexing
from app.services.stats_service import count_detections, count_events, count_findings
from app.services.validation_matrix import get_validation_matrix, render_validation_matrix_markdown, validation_matrix_visibility
from app.schemas.case import CaseCreate, CaseRead, CaseUpdate
from app.workers.tasks import enqueue_semi_auto_analysis


router = APIRouter(prefix="/api/cases", tags=["cases"])
logger = logging.getLogger(__name__)
_SUMMARY_CACHE_TTL = 10.0
_SUMMARY_CACHE: dict[str, tuple[float, dict]] = {}
_SEMI_AUTO_PHASES = [
    "fetching_events",
    "building_activities",
    "deduplicating",
    "correlating_execution",
    "correlating_file_access",
    "correlating_lnk",
    "correlating_registry",
    "correlating_browser",
    "correlating_execution_artifacts",
    "correlating_srum",
    "correlating_scheduled_tasks",
    "correlating_defender",
    "building_timeline",
    "completed",
]


def _apply_case_counts(db: Session, item: Case) -> Case:
    item.detections_count = count_detections(db, item.id)
    item.findings_count = count_findings(db, item.id)
    return item


def _summary_cache_get(case_id: str) -> dict | None:
    item = _SUMMARY_CACHE.get(case_id)
    if not item:
        return None
    expires_at, value = item
    if expires_at < time.monotonic():
        _SUMMARY_CACHE.pop(case_id, None)
        return None
    return deepcopy(value)


def _summary_cache_put(case_id: str, value: dict) -> dict:
    _SUMMARY_CACHE[case_id] = (time.monotonic() + _SUMMARY_CACHE_TTL, deepcopy(value))
    return value


def _empty_summary(db: Session, case_id: str) -> dict:
    event_count = count_events(case_id)
    detections_count = count_detections(db, case_id)
    findings_count = count_findings(db, case_id)
    return {
        "total_events": event_count["count"],
        "event_count_info": event_count,
        "counts": {
            "detections": detections_count,
            "findings": findings_count,
        },
        "events_by_category": {},
        "events_by_severity": {},
        "top_hosts": [],
        "top_users": [],
        "top_processes": [],
        "top_executables": [],
        "top_domains": [],
        "top_source_ips": [],
        "top_destination_ips": [],
        "service_install_events": 0,
        "scheduled_task_events": 0,
        "failed_logons": 0,
        "successful_logons": 0,
        "rdp_events": 0,
        "deleted_files": 0,
        "suspicious_events": 0,
        "detections_count": detections_count,
        "findings_count": findings_count,
        "recent_high_severity_events": [],
        "suspicious_process_events": [],
        "persistence_events": [],
        "deleted_file_events": [],
        "powershell_events": [],
    }


def _normalized_analysis_params(time_from: str | None, time_to: str | None) -> dict:
    return {
        "time_from": time_from or None,
        "time_to": time_to or None,
    }


def _matching_analysis_job(db: Session, case_id: str, *, time_from: str | None, time_to: str | None) -> CaseAnalysisJob | None:
    params = _normalized_analysis_params(time_from, time_to)
    jobs = (
        db.query(CaseAnalysisJob)
        .filter(CaseAnalysisJob.case_id == case_id, CaseAnalysisJob.analysis_type == "semi_auto")
        .order_by(CaseAnalysisJob.created_at.desc())
        .all()
    )
    for job in jobs:
        if dict(job.parameters_json or {}) == params:
            return job
    return None


def _timeline_curation_counts(db: Session, case_id: str) -> dict[str, int]:
    draft = (
        db.query(IncidentTimelineDraft)
        .filter(IncidentTimelineDraft.case_id == case_id)
        .order_by(IncidentTimelineDraft.updated_at.desc())
        .first()
    )
    if not draft:
        return {"official": 0, "candidate": 0, "needs_review": 0, "dismissed": 0}
    payload = dict(draft.payload or {})
    curation = dict(payload.get("curation") or {})
    by_status = dict(curation.get("by_status") or {})
    if by_status:
        return {
            "official": int(by_status.get("accepted") or curation.get("official_count") or 0),
            "candidate": int(by_status.get("candidate") or curation.get("candidate_count") or 0),
            "needs_review": int(by_status.get("needs_review") or curation.get("needs_review_count") or 0),
            "dismissed": int(by_status.get("dismissed") or curation.get("dismissed_count") or 0),
        }
    counts = {"official": 0, "candidate": 0, "needs_review": 0, "dismissed": 0}
    for item in payload.get("items") or []:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "candidate")
        if status == "accepted":
            counts["official"] += 1
        elif status == "needs_review":
            counts["needs_review"] += 1
        elif status == "dismissed":
            counts["dismissed"] += 1
        else:
            counts["candidate"] += 1
    return counts


def _serialize_analysis_job(job: CaseAnalysisJob | None) -> dict:
    if not job:
        return {
            "status": "idle",
            "progress_pct": 0,
            "current_phase": None,
            "phases": _SEMI_AUTO_PHASES,
            "parameters": {},
            "metrics": {},
            "result": None,
            "error_message": None,
            "cancel_requested": False,
            "job_id": None,
            "started_at": None,
            "finished_at": None,
            "created_at": None,
            "updated_at": None,
        }
    metrics = dict(job.metrics_json or {})
    elapsed = metrics.get("elapsed_seconds")
    if elapsed is None and job.started_at:
        finished = job.finished_at or utc_now_naive()
        elapsed = round(max((finished - job.started_at).total_seconds(), 0.0), 2)
        metrics["elapsed_seconds"] = elapsed
    if job.status in {CaseAnalysisJobStatus.running, CaseAnalysisJobStatus.queued} and elapsed is not None and job.progress_pct > 0:
        metrics.setdefault("estimated_remaining_seconds", round(max((elapsed / job.progress_pct) * (100 - job.progress_pct), 0.0), 2))
    return {
        "id": job.id,
        "status": job.status.value,
        "progress_pct": job.progress_pct,
        "current_phase": job.current_phase,
        "phases": job.phases or _SEMI_AUTO_PHASES,
        "parameters": dict(job.parameters_json or {}),
        "metrics": metrics,
        "result": job.result_json,
        "error_message": job.error_message,
        "cancel_requested": job.cancel_requested,
        "job_id": job.job_id,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "updated_at": job.updated_at.isoformat() if job.updated_at else None,
    }


def _build_case_context(db: Session, case_id: str) -> dict:
    item = db.get(Case, case_id)
    if not item:
        raise HTTPException(status_code=404, detail="Case not found")

    summary = get_investigation_summary(case_id, db)
    evidences = (
        db.query(Evidence)
        .filter(Evidence.case_id == case_id)
        .order_by(Evidence.created_at.desc())
        .all()
    )
    artifacts = db.query(Artifact).filter(Artifact.case_id == case_id).all()
    findings = db.query(Finding).filter(Finding.case_id == case_id).all()

    artifact_counts_by_evidence: dict[str, int] = {}
    artifact_record_counts_by_type: dict[str, int] = {}
    for artifact in artifacts:
        artifact_counts_by_evidence[artifact.evidence_id] = artifact_counts_by_evidence.get(artifact.evidence_id, 0) + int(artifact.record_count or 0)
        artifact_record_counts_by_type[artifact.artifact_type] = artifact_record_counts_by_type.get(artifact.artifact_type, 0) + int(artifact.record_count or 0)

    parser_errors_by_evidence: dict[str, int] = {}
    active_jobs: list[dict] = []
    investigation_ready_evidence_count = 0
    for evidence in evidences:
        errors_blob = dict(evidence.error_log or {})
        parser_errors = errors_blob.get("parser_errors")
        parser_errors_by_evidence[evidence.id] = len(parser_errors) if isinstance(parser_errors, list) else int(bool(parser_errors))
        display_status = str((evidence.metadata_json or {}).get("display_status") or evidence.ingest_status.value)
        indexed_for_evidence = int(artifact_counts_by_evidence.get(evidence.id, 0) or 0)
        if display_status in {"completed", "completed_with_warnings", "completed_with_errors"} or indexed_for_evidence > 0:
            investigation_ready_evidence_count += 1
        active, active_job = evidence_has_active_indexing(dict(evidence.metadata_json or {}), evidence.ingest_status)
        active_job_payload = dict(active_job or {})
        active_status = str(active_job_payload.get("status") or "").lower()
        has_active_run = bool(active_job_payload.get("run_id"))
        if active and (active_status != "pending" or has_active_run):
            active_jobs.append(
                {
                    **active_job_payload,
                    "evidence_id": evidence.id,
                    "evidence_name": evidence.original_filename,
                }
            )

    host_attribution = build_host_attribution(
        case_id,
        evidences=evidences,
        findings=findings,
        top_host_counts={str(bucket.get("key") or ""): int(bucket.get("count") or 0) for bucket in summary.get("top_hosts", []) if str(bucket.get("key") or "").strip()},
    )
    observed_host_rows = host_attribution["hosts"]
    evidence_summaries = host_attribution["evidence_summaries"]
    changed = False
    for evidence in evidences:
        summary_row = evidence_summaries.get(evidence.id) or {}
        primary_host = summary_row.get("primary_host")
        if primary_host and evidence.detected_host != primary_host:
            evidence.detected_host = primary_host
            metadata = dict(evidence.metadata_json or {})
            metadata["host_attribution"] = {
                "primary_host": primary_host,
                "primary_host_source": summary_row.get("primary_host_source"),
                "primary_host_confidence": summary_row.get("primary_host_confidence"),
                "aliases": summary_row.get("aliases") or [],
                "rejected": summary_row.get("rejected") or [],
            }
            evidence.metadata_json = metadata
            changed = True
    if changed:
        db.commit()

    warnings: list[str] = []
    if any(evidence.ingest_status.value == "failed" for evidence in evidences):
        warnings.append("failed_evidence_present")
    if any(parser_errors_by_evidence.values()):
        warnings.append("parser_errors_present")
    if len([entry for entry in observed_host_rows if entry["host"] != "unknown"]) > 1:
        warnings.append("multi_host_case")
    if host_attribution.get("host_candidates"):
        warnings.append("host_aliases_present")
    if host_attribution.get("rejected_host_candidates"):
        warnings.append("host_attribution_rejections_present")
    canonical_hosts = get_case_hosts(db, case_id)
    host_candidates = build_case_host_candidates(db, case_id)

    serialized_case = CaseRead.model_validate(_apply_case_counts(db, item)).model_dump(mode="json")
    settings = get_settings()
    visibility = validation_matrix_visibility(
        case_id,
        getattr(item, "mode", None),
        validation_mode_enabled=settings.validation_features_enabled,
        demo_cases_enabled=settings.demo_cases_enabled,
    )
    timeline_counts = _timeline_curation_counts(db, case_id)
    marked_events_count = db.query(EventMarking).filter(EventMarking.case_id == case_id).count()
    reports_count = db.query(CaseReport).filter(CaseReport.case_id == case_id).count()
    indexed_docs = int(summary.get("total_events") or 0)
    state_payload = derive_case_investigation_state(
        evidence_count=len(evidences),
        investigation_ready_evidence_count=investigation_ready_evidence_count,
        indexed_docs=indexed_docs,
        active_jobs=active_jobs,
        findings_count=len(findings),
        official_timeline_count=timeline_counts["official"],
        candidate_timeline_count=timeline_counts["candidate"],
        marked_events_count=marked_events_count,
        parser_errors=sum(parser_errors_by_evidence.values()),
        warnings=warnings,
    )
    first_evidence_id = evidences[0].id if evidences else None
    next_actions = build_case_next_actions(
        case_id,
        state_payload,
        demo_metadata_enabled=settings.demo_cases_enabled,
        first_evidence_id=first_evidence_id,
        defender_docs_count=artifact_record_counts_by_type.get("defender", 0),
    )
    return {
        "case": serialized_case,
        "hosts": canonical_hosts,
        "host_candidates": host_candidates,
        "rejected_host_candidates": host_attribution.get("rejected_host_candidates") or [],
        "evidences": [
            {
                "id": evidence.id,
                "name": evidence.original_filename,
                "status": str((evidence.metadata_json or {}).get("display_status") or evidence.ingest_status.value),
                "storage_mode": evidence.storage_mode.value,
                "is_external": evidence.is_external,
                "events_indexed": artifact_counts_by_evidence.get(evidence.id, 0),
                "parser_errors": parser_errors_by_evidence.get(evidence.id, 0),
                "detected_host": (evidence_summaries.get(evidence.id) or {}).get("primary_host") or evidence.detected_host,
                "detected_host_source": (evidence_summaries.get(evidence.id) or {}).get("primary_host_source"),
                "detected_host_confidence": (evidence_summaries.get(evidence.id) or {}).get("primary_host_confidence"),
            }
            for evidence in evidences
        ],
        "summary": {
            "events_indexed": int(summary.get("total_events") or 0),
            "findings_total": int(summary.get("findings_count") or 0),
            "findings_high": sum(1 for finding in findings if str(finding.severity) in {"high", "critical"}),
            "parser_errors": sum(parser_errors_by_evidence.values()),
            "warnings": warnings,
            "investigation_state": {
                **state_payload,
                "reports_count": reports_count,
                "timeline_needs_review_count": timeline_counts["needs_review"],
                "timeline_dismissed_count": timeline_counts["dismissed"],
                "defender_docs": int(artifact_record_counts_by_type.get("defender", 0) or 0),
                "startup_persistence_docs": int(artifact_record_counts_by_type.get("startup_persistence", 0) or 0),
            },
            "next_actions": next_actions,
            "host_attribution": {
                "primary_host": host_attribution.get("primary_host"),
                "accepted_hosts": len(canonical_hosts),
                "alias_candidates": len(host_candidates),
                "rejected_candidates": len(host_attribution.get("rejected_host_candidates") or []),
            },
            "validation_matrix": visibility,
        },
    }


@router.get("", response_model=list[CaseRead])
def list_cases(db: Session = Depends(get_db)) -> list[Case]:
    return [_apply_case_counts(db, item) for item in db.query(Case).order_by(Case.created_at.desc()).all()]


@router.post("", response_model=CaseRead, status_code=status.HTTP_201_CREATED)
def create_case(payload: CaseCreate, db: Session = Depends(get_db)) -> Case:
    item = Case(**payload.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    log_activity(
        db,
        activity_type="case_created",
        title="Case created",
        message=f"Created case {item.name}",
        case_id=item.id,
        metadata={"case_name": item.name},
    )
    return _apply_case_counts(db, item)


@router.get("/{case_id}", response_model=CaseRead)
def get_case(case_id: str, db: Session = Depends(get_db)) -> Case:
    item = db.get(Case, case_id)
    if not item:
        raise HTTPException(status_code=404, detail="Case not found")
    return _apply_case_counts(db, item)


@router.get("/{case_id}/context")
def get_case_context(case_id: str, db: Session = Depends(get_db)) -> dict:
    return _build_case_context(db, case_id)


@router.get("/{case_id}/validation-matrix")
def get_case_validation_matrix(
    case_id: str,
    host: str | None = Query(default=None),
    phase: str | None = Query(default=None),
    result: str | None = Query(default=None),
    source_part: str | None = Query(default=None),
    memory_required: bool | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    settings = get_settings()
    visibility = validation_matrix_visibility(
        case_id,
        getattr(case, "mode", None),
        validation_mode_enabled=settings.validation_features_enabled,
        demo_cases_enabled=settings.demo_cases_enabled,
    )
    if visibility["show_validation_matrix"]:
        matrix = get_validation_matrix(
            case_id,
            host=host,
            phase=phase,
            result=result,
            source_part=source_part,
            memory_required=memory_required,
        )
    else:
        matrix = get_validation_matrix("__validation_features_disabled__")
        matrix["case_id"] = case_id
        matrix["warnings"] = ["Validation matrix is disabled for this investigation mode case."]
    matrix["visibility"] = visibility
    return matrix


@router.get("/{case_id}/validation-matrix/export")
def export_case_validation_matrix(case_id: str, db: Session = Depends(get_db)) -> Response:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    settings = get_settings()
    visibility = validation_matrix_visibility(
        case_id,
        getattr(case, "mode", None),
        validation_mode_enabled=settings.validation_features_enabled,
        demo_cases_enabled=settings.demo_cases_enabled,
    )
    if not visibility["show_validation_matrix"]:
        raise HTTPException(status_code=403, detail="Validation matrix is disabled for this case")
    matrix = get_validation_matrix(case_id)
    content = render_validation_matrix_markdown(matrix)
    filename = f"validation-matrix-{case_id}.md"
    return Response(
        content=content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.patch("/{case_id}", response_model=CaseRead)
def update_case(case_id: str, payload: CaseUpdate, db: Session = Depends(get_db)) -> Case:
    item = db.get(Case, case_id)
    if not item:
        raise HTTPException(status_code=404, detail="Case not found")
    for key, value in payload.model_dump(exclude_none=True).items():
        setattr(item, key, value)
    db.commit()
    db.refresh(item)
    return _apply_case_counts(db, item)


@router.delete("/{case_id}")
def delete_case(case_id: str, db: Session = Depends(get_db)) -> dict:
    item = db.get(Case, case_id)
    if not item:
        raise HTTPException(status_code=404, detail="Case not found")
    try:
        db.query(AppActivityEvent).filter(AppActivityEvent.case_id == case_id).delete(synchronize_session=False)
        db.query(DetectionResult).filter(DetectionResult.case_id == case_id).delete(synchronize_session=False)
        db.query(Finding).filter(Finding.case_id == case_id).delete(synchronize_session=False)
        db.query(RuleRun).filter(RuleRun.case_id == case_id).delete(synchronize_session=False)
        db.query(Artifact).filter(Artifact.case_id == case_id).delete(synchronize_session=False)
        db.query(Evidence).filter(Evidence.case_id == case_id).delete(synchronize_session=False)
        db.query(Rule).filter(Rule.case_id == case_id).delete(synchronize_session=False)
        db.query(RuleSet).filter(RuleSet.case_id == case_id).delete(synchronize_session=False)
        db.query(Tag).filter(Tag.case_id == case_id).delete(synchronize_session=False)
        db.query(Case).filter(Case.id == case_id).delete(synchronize_session=False)
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Could not delete case %s from database", case_id)
        raise HTTPException(status_code=500, detail=f"Could not delete case from database: {exc.__class__.__name__}") from exc

    _SUMMARY_CACHE.pop(case_id, None)
    index_deleted = delete_case_index(case_id)
    storage_deleted = False
    cleanup_error = None
    try:
        case_root = case_storage_root(case_id)
        storage_deleted = case_root.exists()
        safe_remove(case_root)
    except Exception as exc:  # noqa: BLE001
        cleanup_error = str(exc)
        logger.warning("Could not remove storage for case %s: %s", case_id, exc)
    return {
        "status": "deleted",
        "case_id": case_id,
        "cleanup": {
            "index_deleted": index_deleted,
            "storage_deleted": storage_deleted,
            "cleanup_error": cleanup_error,
        },
    }


@router.post("/{case_id}/debug-export")
def export_debug_pack(case_id: str, payload: DebugExportRequest, db: Session = Depends(get_db)) -> Response:
    try:
        zip_bytes, filename = generate_debug_pack(db, case_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("Debug export failed for case %s", case_id)
        raise HTTPException(status_code=500, detail=f"Debug export failed: {exc.__class__.__name__}: {exc}") from exc
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


@router.get("/{case_id}/debug-export/download")
def download_debug_pack(
    case_id: str,
    scope: str = Query(default="case"),
    evidence_id: str | None = Query(default=None),
    artifact_types: str | None = Query(default=None),
    include_raw_samples: bool = Query(default=False),
    include_raw_xml: bool = Query(default=False),
    include_source_paths: bool = Query(default=True),
    include_full_raw: bool = Query(default=False),
    max_events_per_type: int = Query(default=25, ge=1, le=250),
    max_field_length: int = Query(default=2000, ge=200, le=20000),
    redact_secrets: bool = Query(default=True),
    include_cached_semiauto: bool = Query(default=True),
    rebuild_semiauto_for_export: bool = Query(default=False),
    ui_context_json: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> Response:
    ui_context = {"transport": "download_get", "scope": scope, "case_id": case_id}
    if ui_context_json:
        try:
            parsed_ui_context = json.loads(ui_context_json)
            if isinstance(parsed_ui_context, dict):
                ui_context.update(parsed_ui_context)
        except Exception:  # noqa: BLE001
            ui_context["ui_context_parse_error"] = True
    payload = DebugExportRequest(
        scope=scope,
        evidence_id=evidence_id,
        artifact_types=[item for item in (artifact_types or "").split(",") if item],
        include_raw_samples=include_raw_samples,
        include_raw_xml=include_raw_xml,
        include_source_paths=include_source_paths,
        include_full_raw=include_full_raw,
        max_events_per_type=max_events_per_type,
        max_field_length=max_field_length,
        redact_secrets=redact_secrets,
        include_cached_semiauto=include_cached_semiauto,
        rebuild_semiauto_for_export=rebuild_semiauto_for_export,
        ui_context=ui_context,
    )
    try:
        zip_bytes, filename = generate_debug_pack(db, case_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("Debug export download failed for case %s", case_id)
        raise HTTPException(status_code=500, detail=f"Debug export failed: {exc.__class__.__name__}: {exc}") from exc
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


@router.get("/{case_id}/process-tree")
def get_process_tree(
    case_id: str,
    scope: str = Query(default="case"),
    evidence_id: str | None = Query(default=None),
    host: str | None = Query(default=None),
    pid: int | None = Query(default=None),
    process_name: str | None = Query(default=None),
    entity_id: str | None = Query(default=None),
    include_activity: bool = Query(default=False),
    aggregate_activity: bool = Query(default=True),
    edge_types: str | None = Query(default=None),
    max_nodes: int = Query(default=50, ge=1, le=500),
    max_activity_per_process: int = Query(default=10, ge=1, le=500),
    only_suspicious: bool = Query(default=False),
    only_marked: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> dict:
    item = db.get(Case, case_id)
    if not item:
        raise HTTPException(status_code=404, detail="Case not found")
    if scope not in {"case", "evidence"}:
        raise HTTPException(status_code=400, detail="scope must be 'case' or 'evidence'")

    evidences_query = db.query(Evidence).filter(Evidence.case_id == case_id)
    if scope == "evidence":
        if not evidence_id:
            raise HTTPException(status_code=400, detail="evidence_id is required when scope=evidence")
        evidences_query = evidences_query.filter(Evidence.id == evidence_id)
    evidences = evidences_query.order_by(Evidence.created_at.asc()).all()
    if scope == "evidence" and not evidences:
        raise HTTPException(status_code=404, detail="Evidence not found for this case")

    try:
        return build_process_tree_bundle(
            item,
            evidences,
            scope=scope,
            evidence_id=evidence_id,
            host=host,
            pid=pid,
            process_name=process_name,
            entity_id=entity_id,
            include_activity=include_activity,
            aggregate_activity=aggregate_activity,
            edge_types=[item.strip() for item in str(edge_types or "").split(",") if item.strip()] or None,
            max_nodes=max_nodes,
            max_activity_per_process=max_activity_per_process,
            only_suspicious=only_suspicious,
            only_marked=only_marked,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Process tree build failed for case %s", case_id)
        raise HTTPException(status_code=500, detail=f"Process tree build failed: {exc.__class__.__name__}: {exc}") from exc


@router.get("/{case_id}/process-tree/expand")
def expand_process_tree(
    case_id: str,
    scope: str = Query(default="case"),
    evidence_id: str | None = Query(default=None),
    host: str | None = Query(default=None),
    node_id: str | None = Query(default=None),
    process_guid: str | None = Query(default=None),
    process_pid: int | None = Query(default=None),
    process_name: str | None = Query(default=None),
    timestamp: str | None = Query(default=None),
    expansion_type: str = Query(default="children"),
    depth: int = Query(default=1, ge=1, le=5),
    time_window_before: int = Query(default=1800, ge=0, le=604800),
    time_window_after: int = Query(default=1800, ge=0, le=604800),
    max_nodes: int = Query(default=50, ge=1, le=500),
    max_activity: int = Query(default=25, ge=1, le=500),
    edge_types: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict:
    item = db.get(Case, case_id)
    if not item:
        raise HTTPException(status_code=404, detail="Case not found")
    if scope not in {"case", "evidence"}:
        raise HTTPException(status_code=400, detail="scope must be 'case' or 'evidence'")

    evidences_query = db.query(Evidence).filter(Evidence.case_id == case_id)
    if scope == "evidence":
        if not evidence_id:
            raise HTTPException(status_code=400, detail="evidence_id is required when scope=evidence")
        evidences_query = evidences_query.filter(Evidence.id == evidence_id)
    evidences = evidences_query.order_by(Evidence.created_at.asc()).all()
    if scope == "evidence" and not evidences:
        raise HTTPException(status_code=404, detail="Evidence not found for this case")

    try:
        return build_process_tree_expansion(
            item,
            evidences,
            scope=scope,
            evidence_id=evidence_id,
            host=host,
            node_id=node_id,
            process_guid=process_guid,
            process_pid=process_pid,
            process_name=process_name,
            timestamp=timestamp,
            expansion_type=expansion_type,
            depth=depth,
            time_window_before=time_window_before,
            time_window_after=time_window_after,
            max_nodes=max_nodes,
            max_activity=max_activity,
            edge_types=[item.strip() for item in str(edge_types or "").split(",") if item.strip()] or None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("Process tree expansion failed for case %s", case_id)
        raise HTTPException(status_code=500, detail=f"Process tree expansion failed: {exc.__class__.__name__}: {exc}") from exc


@router.get("/{case_id}/process-tree/focused")
def get_focused_process_tree(
    case_id: str,
    scope: str = Query(default="case"),
    evidence_id: str | None = Query(default=None),
    host: str | None = Query(default=None),
    pid: int | None = Query(default=None),
    process_guid: str | None = Query(default=None),
    source_event_id: str | None = Query(default=None),
    process_name: str | None = Query(default=None),
    timestamp: str | None = Query(default=None),
    parent_depth: int = Query(default=2, ge=0, le=5),
    child_depth: int = Query(default=2, ge=0, le=5),
    include_siblings: bool = Query(default=True),
    include_activity: bool = Query(default=False),
    time_window_before: int = Query(default=1800, ge=0, le=604800),
    time_window_after: int = Query(default=1800, ge=0, le=604800),
    max_nodes: int = Query(default=100, ge=1, le=500),
    max_activity: int = Query(default=25, ge=1, le=500),
    db: Session = Depends(get_db),
) -> dict:
    item = db.get(Case, case_id)
    if not item:
        raise HTTPException(status_code=404, detail="Case not found")
    if scope not in {"case", "evidence"}:
        raise HTTPException(status_code=400, detail="scope must be 'case' or 'evidence'")
    if pid is None and not process_guid and not source_event_id and not process_name:
        raise HTTPException(status_code=400, detail="pid, process_guid, source_event_id, or process_name is required")

    evidences_query = db.query(Evidence).filter(Evidence.case_id == case_id)
    if scope == "evidence":
        if not evidence_id:
            raise HTTPException(status_code=400, detail="evidence_id is required when scope=evidence")
        evidences_query = evidences_query.filter(Evidence.id == evidence_id)
    evidences = evidences_query.order_by(Evidence.created_at.asc()).all()
    if scope == "evidence" and not evidences:
        raise HTTPException(status_code=404, detail="Evidence not found for this case")

    try:
        return build_process_tree_focused(
            item,
            evidences,
            scope=scope,
            evidence_id=evidence_id,
            host=host,
            pid=pid,
            process_guid=process_guid,
            source_event_id=source_event_id,
            process_name=process_name,
            timestamp=timestamp,
            parent_depth=parent_depth,
            child_depth=child_depth,
            include_siblings=include_siblings,
            include_activity=include_activity,
            time_window_before=time_window_before,
            time_window_after=time_window_after,
            max_nodes=max_nodes,
            max_activity=max_activity,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Focused process tree build failed for case %s", case_id)
        raise HTTPException(status_code=500, detail=f"Focused process tree build failed: {exc.__class__.__name__}: {exc}") from exc


@router.get("/{case_id}/execution-story")
def get_execution_story(
    case_id: str,
    scope: str = Query(default="case"),
    evidence_id: str | None = Query(default=None),
    host: str | None = Query(default=None),
    pid: int | None = Query(default=None),
    process_guid: str | None = Query(default=None),
    source_event_id: str | None = Query(default=None),
    q: str | None = Query(default=None),
    timestamp: str | None = Query(default=None),
    parent_depth: int = Query(default=3, ge=0, le=5),
    child_depth: int = Query(default=2, ge=0, le=5),
    include_activity: bool = Query(default=True),
    time_window_before: int = Query(default=1800, ge=0, le=604800),
    time_window_after: int = Query(default=1800, ge=0, le=604800),
    max_nodes: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> dict:
    item = db.get(Case, case_id)
    if not item:
        raise HTTPException(status_code=404, detail="Case not found")
    if scope not in {"case", "evidence"}:
        raise HTTPException(status_code=400, detail="scope must be 'case' or 'evidence'")
    if pid is None and not process_guid and not source_event_id and not q:
        raise HTTPException(status_code=400, detail="pid, process_guid, source_event_id, or q is required")

    evidences_query = db.query(Evidence).filter(Evidence.case_id == case_id)
    if scope == "evidence":
        if not evidence_id:
            raise HTTPException(status_code=400, detail="evidence_id is required when scope=evidence")
        evidences_query = evidences_query.filter(Evidence.id == evidence_id)
    evidences = evidences_query.order_by(Evidence.created_at.asc()).all()
    if scope == "evidence" and not evidences:
        raise HTTPException(status_code=404, detail="Evidence not found for this case")

    try:
        return build_execution_story(
            item,
            evidences,
            scope=scope,
            evidence_id=evidence_id,
            host=host,
            pid=pid,
            process_guid=process_guid,
            source_event_id=source_event_id,
            q=q,
            timestamp=timestamp,
            parent_depth=parent_depth,
            child_depth=child_depth,
            include_activity=include_activity,
            time_window_before=time_window_before,
            time_window_after=time_window_after,
            max_nodes=max_nodes,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Execution story build failed for case %s", case_id)
        raise HTTPException(status_code=500, detail=f"Execution story build failed: {exc.__class__.__name__}: {exc}") from exc


@router.get("/{case_id}/investigation-summary")
def get_investigation_summary(case_id: str, db: Session = Depends(get_db)) -> dict:
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    client = get_opensearch_client()
    index = get_events_index(case_id)
    cached = _summary_cache_get(case_id)
    if cached is not None:
        return cached
    if not index_exists(client, index):
        return _summary_cache_put(case_id, _empty_summary(db, case_id))
    health = get_index_health(client, index)
    if not is_index_queryable(client, index):
        logger.warning("Skipping investigation summary for %s because index health is %s", case_id, health)
        return _summary_cache_put(case_id, _empty_summary(db, case_id))

    aggregatable_fields = {
        "top_hosts": resolve_aggregatable_field(client, index, "host.name"),
        "top_users": resolve_aggregatable_field(client, index, "user.name"),
        "top_processes": resolve_aggregatable_field(client, index, "process.name"),
        "top_executables": resolve_aggregatable_field(client, index, "process.path"),
        "top_domains": resolve_aggregatable_field(client, index, "network.domain"),
        "top_source_ips": resolve_aggregatable_field(client, index, "network.source_ip"),
        "top_destination_ips": resolve_aggregatable_field(client, index, "network.destination_ip"),
    }

    body = {
        "size": 0,
        "aggs": {
            "events_by_category": {"terms": {"field": "event.category", "size": 20}},
            "events_by_severity": {"terms": {"field": "event.severity", "size": 10}},
            "service_install_events": {"filter": {"terms": {"event.type": ["service_installed"]}}},
            "scheduled_task_events": {"filter": {"terms": {"event.type": ["scheduled_task", "scheduled_task_created", "scheduled_task_updated", "scheduled_task_definition", "scheduled_task_com_handler"]}}},
            "failed_logons": {"filter": {"term": {"event.type": "logon_failed"}}},
            "successful_logons": {"filter": {"term": {"event.type": "logon_success"}}},
            "rdp_events": {"filter": {"term": {"tags": "rdp"}}},
            "deleted_files": {"filter": {"term": {"event.type": "file_deleted"}}},
            "suspicious_events": {"filter": {"terms": {"event.severity": ["high", "critical"]}}},
        },
    }
    for agg_name, field_name in aggregatable_fields.items():
        if field_name:
            body["aggs"][agg_name] = {"terms": {"field": field_name, "size": 10}}
    try:
        result = client.search(index=index, body=body, params={"ignore_unavailable": "true"})
    except Exception as exc:  # noqa: BLE001
        logger.warning("Investigation summary failed for case %s: %s", case_id, exc)
        return _summary_cache_put(case_id, _empty_summary(db, case_id))

    def bucket_map(name: str) -> dict:
        return {item["key"]: item["doc_count"] for item in result.get("aggregations", {}).get(name, {}).get("buckets", [])}

    def bucket_list(name: str) -> list[dict]:
        return [{"key": item["key"], "count": item["doc_count"]} for item in result.get("aggregations", {}).get(name, {}).get("buckets", [])]

    def top_events(query: dict) -> list[dict]:
        try:
            response = client.search(index=index, body={"size": 5, "query": query, "sort": [{"@timestamp": {"order": "desc", "missing": "_last"}}]}, params={"ignore_unavailable": "true"})
            return [{"id": hit["_id"], **hit["_source"]} for hit in response.get("hits", {}).get("hits", [])]
        except Exception as exc:  # noqa: BLE001
            logger.warning("Top events subquery failed for case %s: %s", case_id, exc)
            return []

    event_count = count_events(case_id)
    total_events = event_count["count"]
    detections_count = count_detections(db, case_id)
    findings_count = count_findings(db, case_id)
    return _summary_cache_put(case_id, {
        "total_events": total_events,
        "event_count_info": event_count,
        "counts": {
            "detections": detections_count,
            "findings": findings_count,
        },
        "events_by_category": bucket_map("events_by_category"),
        "events_by_severity": bucket_map("events_by_severity"),
        "top_hosts": bucket_list("top_hosts"),
        "top_users": bucket_list("top_users"),
        "top_processes": bucket_list("top_processes"),
        "top_executables": bucket_list("top_executables"),
        "top_powershell_commands": len(top_events({"term": {"tags": "powershell"}})),
        "top_domains": bucket_list("top_domains"),
        "top_source_ips": bucket_list("top_source_ips"),
        "top_destination_ips": bucket_list("top_destination_ips"),
        "service_install_events": result["aggregations"]["service_install_events"]["doc_count"],
        "scheduled_task_events": result["aggregations"]["scheduled_task_events"]["doc_count"],
        "failed_logons": result["aggregations"]["failed_logons"]["doc_count"],
        "successful_logons": result["aggregations"]["successful_logons"]["doc_count"],
        "rdp_events": result["aggregations"]["rdp_events"]["doc_count"],
        "deleted_files": result["aggregations"]["deleted_files"]["doc_count"],
        "suspicious_events": result["aggregations"]["suspicious_events"]["doc_count"],
        "detections_count": detections_count,
        "findings_count": findings_count,
        "recent_high_severity_events": top_events({"terms": {"event.severity": ["high", "critical"]}}),
        "suspicious_process_events": top_events({"term": {"tags": "suspicious_process"}}),
        "persistence_events": top_events({"term": {"tags": "persistence"}}),
        "deleted_file_events": top_events({"term": {"event.type": "file_deleted"}}),
        "powershell_events": top_events({"term": {"tags": "powershell"}}),
    })


@router.get("/{case_id}/analysis/semi-auto")
def get_case_semi_auto_analysis(
    case_id: str,
    time_from: str | None = None,
    time_to: str | None = None,
    db: Session = Depends(get_db),
) -> dict:
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    try:
        return build_case_semi_auto_analysis(case_id, time_from=time_from, time_to=time_to)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Semi-automatic analysis failed for case %s", case_id)
        raise HTTPException(status_code=500, detail=f"Semi-automatic analysis failed: {exc}") from exc


@router.get("/{case_id}/analysis/semi-auto/status")
def get_case_semi_auto_analysis_status(
    case_id: str,
    time_from: str | None = None,
    time_to: str | None = None,
    db: Session = Depends(get_db),
) -> dict:
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    run = _matching_analysis_job(db, case_id, time_from=time_from, time_to=time_to)
    return _serialize_analysis_job(run)


@router.post("/{case_id}/analysis/semi-auto/start")
def start_case_semi_auto_analysis(
    case_id: str,
    time_from: str | None = None,
    time_to: str | None = None,
    db: Session = Depends(get_db),
) -> dict:
    item = db.get(Case, case_id)
    if not item:
        raise HTTPException(status_code=404, detail="Case not found")
    existing = _matching_analysis_job(db, case_id, time_from=time_from, time_to=time_to)
    if existing and existing.status in {CaseAnalysisJobStatus.queued, CaseAnalysisJobStatus.running}:
        return _serialize_analysis_job(existing)

    run = CaseAnalysisJob(
        case_id=case_id,
        analysis_type="semi_auto",
        status=CaseAnalysisJobStatus.queued,
        progress_pct=0,
        current_phase="queued",
        phases=_SEMI_AUTO_PHASES,
        parameters_json=_normalized_analysis_params(time_from, time_to),
        metrics_json={},
        result_json=None,
        cancel_requested=False,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    enqueue_semi_auto_analysis(run.id)
    log_activity(
        db,
        activity_type="semi_auto_analysis_started",
        title="Semi-automatic analysis started",
        message=f"Started semi-automatic analysis for case {item.name}",
        case_id=case_id,
        metadata={"analysis_job_id": run.id, **dict(run.parameters_json or {})},
    )
    db.refresh(run)
    return _serialize_analysis_job(run)


@router.post("/{case_id}/analysis/semi-auto/stop")
def stop_case_semi_auto_analysis(
    case_id: str,
    time_from: str | None = None,
    time_to: str | None = None,
    db: Session = Depends(get_db),
) -> dict:
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    run = _matching_analysis_job(db, case_id, time_from=time_from, time_to=time_to)
    if not run:
        return _serialize_analysis_job(None)
    if run.status in {CaseAnalysisJobStatus.completed, CaseAnalysisJobStatus.failed, CaseAnalysisJobStatus.cancelled}:
        return _serialize_analysis_job(run)
    run.cancel_requested = True
    if run.status == CaseAnalysisJobStatus.queued:
        run.status = CaseAnalysisJobStatus.cancelled
        run.current_phase = "cancelled"
        run.finished_at = utc_now_naive()
        run.progress_pct = 0
    db.commit()
    return _serialize_analysis_job(run)


@router.get("/{case_id}/analysis/semi-auto/export-markdown")
def export_case_semi_auto_markdown(
    case_id: str,
    time_from: str | None = None,
    time_to: str | None = None,
    db: Session = Depends(get_db),
) -> Response:
    item = db.get(Case, case_id)
    if not item:
        raise HTTPException(status_code=404, detail="Case not found")
    try:
        cached = _matching_analysis_job(db, case_id, time_from=time_from, time_to=time_to)
        analysis = cached.result_json if cached and cached.status == CaseAnalysisJobStatus.completed and cached.result_json else build_case_semi_auto_analysis(case_id, time_from=time_from, time_to=time_to)
        content = render_case_semi_auto_markdown(analysis, case_name=item.name)
        filename = f"semi-auto-analysis-{item.name.replace(' ', '-').lower()}-{case_id}.md"
        return Response(
            content=content,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Semi-automatic analysis markdown export failed for case %s", case_id)
        raise HTTPException(status_code=500, detail=f"Semi-automatic analysis export failed: {exc}") from exc


@router.get("/{case_id}/analysis/semi-auto/export-pdf")
def export_case_semi_auto_pdf(
    case_id: str,
    time_from: str | None = None,
    time_to: str | None = None,
    db: Session = Depends(get_db),
) -> Response:
    item = db.get(Case, case_id)
    if not item:
        raise HTTPException(status_code=404, detail="Case not found")
    try:
        from io import BytesIO

        from reportlab.lib.pagesizes import A4
        from reportlab.pdfbase.pdfmetrics import stringWidth
        from reportlab.pdfgen import canvas

        cached = _matching_analysis_job(db, case_id, time_from=time_from, time_to=time_to)
        analysis = cached.result_json if cached and cached.status == CaseAnalysisJobStatus.completed and cached.result_json else build_case_semi_auto_analysis(case_id, time_from=time_from, time_to=time_to)
        content = render_case_semi_auto_text(analysis, case_name=item.name)
        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        left_margin = 40
        right_margin = 40
        top_margin = 40
        bottom_margin = 40
        max_width = width - left_margin - right_margin
        line_height = 14
        y = height - top_margin

        def draw_line(text: str, font_name: str = "Helvetica", font_size: int = 10) -> None:
            nonlocal y
            if y <= bottom_margin:
                pdf.showPage()
                y = height - top_margin
            pdf.setFont(font_name, font_size)
            words = text.split(" ")
            current = ""
            for word in words:
                candidate = word if not current else f"{current} {word}"
                if stringWidth(candidate, font_name, font_size) <= max_width:
                    current = candidate
                    continue
                pdf.drawString(left_margin, y, current)
                y -= line_height
                if y <= bottom_margin:
                    pdf.showPage()
                    y = height - top_margin
                    pdf.setFont(font_name, font_size)
                current = word
            pdf.drawString(left_margin, y, current or text)
            y -= line_height

        for raw_line in content.splitlines():
            if not raw_line.strip():
                y -= line_height // 2
                continue
            if raw_line == raw_line.upper() and len(raw_line) < 80 and not raw_line.startswith("  "):
                draw_line(raw_line, "Helvetica-Bold", 12)
            elif raw_line.startswith("Semi-Automatic Analysis Report"):
                draw_line(raw_line, "Helvetica-Bold", 16)
            else:
                draw_line(raw_line)

        pdf.save()
        buffer.seek(0)
        filename = f"semi-auto-analysis-{item.name.replace(' ', '-').lower()}-{case_id}.pdf"
        return Response(
            content=buffer.getvalue(),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Semi-automatic analysis PDF export failed for case %s", case_id)
        raise HTTPException(status_code=500, detail=f"Semi-automatic analysis PDF export failed: {exc}") from exc
