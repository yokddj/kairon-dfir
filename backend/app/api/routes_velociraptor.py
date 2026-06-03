from pathlib import Path

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.activity import log_activity
from app.core.config import get_settings
from app.core.database import get_db
from app.core.manifest import default_manifest, write_manifest
from app.core.opensearch import OpenSearchIngestBlockedError
from app.core.storage import (
    evidence_manifest_path,
    save_folder_uploads,
    save_upload,
    sha256_file,
)
from app.ingest.velociraptor import discover_velociraptor_evidences, open_evidence_container
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType, IngestStatus
from app.schemas.evidence import EvidenceRead
from app.services.evidence_runs import mark_opensearch_infrastructure_block, merge_evidence_metadata
from app.services.host_identity import is_invalid_host_value
from app.services.ingest_plan import build_plan, persist_plan
from app.services.usable_ingest import ingest_mode_metadata, normalize_ingest_mode
from app.workers.tasks import enqueue_ingest


router = APIRouter(tags=["velociraptor"])
settings = get_settings()


def _mark_evidence_blocked_before_ingest(db: Session, evidence: Evidence, exc: OpenSearchIngestBlockedError) -> None:
    metadata = mark_opensearch_infrastructure_block(
        evidence.metadata_json or {},
        reason=str(exc),
        preflight=getattr(exc, "details", None),
    )
    evidence.ingest_status = IngestStatus.failed
    evidence.error_log = dict(metadata.get("error_log") or {})
    evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
    db.commit()
    db.refresh(evidence)


class VelociraptorParseRequest(BaseModel):
    evidence_id: str
    selected_candidate_ids: list[str] = []
    categories: list[str] = []
    parse_all: bool = False
    ingest_mode: str | None = None
    provided_host: str | None = None
    evtx_profile: str | None = None


class VelociraptorDiscoverPathRequest(BaseModel):
    case_id: str
    collection_path: str


def _apply_velociraptor_selection_metadata(metadata: dict, candidates: list[dict], selected: list[dict]) -> dict:
    selected_ids = {str(candidate.get("id")) for candidate in selected}
    selected_categories = sorted({str(candidate.get("category") or "") for candidate in selected if candidate.get("category")})
    not_selected_by_category: dict[str, int] = {}
    updated_candidates: list[dict] = []
    for candidate in candidates:
        candidate_copy = dict(candidate)
        is_selected = str(candidate.get("id")) in selected_ids
        candidate_copy["selected_for_extraction"] = is_selected
        if not is_selected:
            category = str(candidate.get("category") or "other")
            not_selected_by_category[category] = not_selected_by_category.get(category, 0) + 1
            candidate_copy["parser_status"] = "skipped_not_selected"
        updated_candidates.append(candidate_copy)

    discovery = dict(metadata.get("velociraptor_discovery") or {})
    discovery["candidates"] = updated_candidates
    metadata["velociraptor_discovery"] = discovery
    metadata["velociraptor_selected_candidate_ids"] = [candidate["id"] for candidate in selected]
    metadata["velociraptor_selected_categories"] = selected_categories
    metadata["selected_artifact_types"] = selected_categories
    metadata["not_selected_candidates_count_by_category"] = not_selected_by_category
    return metadata


def _initial_metadata(extra: dict | None = None) -> dict:
    return {
        "phases": ["uploaded", "indexing_zip", "discovering_candidates", "waiting_selection", "extracting_selected", "parsing", "indexing_events"],
        "current_phase": "indexing_zip",
        "progress_pct": 10,
        "tree": [],
        "detected_artifacts": 0,
        "processed_artifacts": 0,
        "indexed_events": 0,
        "records_processed": 0,
        "events_indexed": 0,
        "artifacts_processed": 0,
        "artifacts_total": 0,
        "raw_artifacts_detected": 0,
        "raw_artifacts_not_parsed": 0,
        "source_type": "velociraptor_collection",
        **(extra or {}),
    }


def _generic_archive_fallback_metadata(extra: dict | None = None) -> dict:
    return {
        "phases": ["uploaded", "extracting", "detecting", "parsing", "indexing"],
        "current_phase": "uploaded",
        "progress_pct": 0,
        "tree": [],
        "detected_artifacts": 0,
        "processed_artifacts": 0,
        "indexed_events": 0,
        "records_processed": 0,
        "events_indexed": 0,
        "artifacts_processed": 0,
        "artifacts_total": 0,
        "raw_artifacts_detected": 0,
        "raw_artifacts_not_parsed": 0,
        **(extra or {}),
    }


def _normalize_provided_host(value: str | None) -> str | None:
    normalized = str(value or "").strip()
    if is_invalid_host_value(normalized):
        return None
    return normalized or None


def _require_provided_host(value: str | None) -> str:
    normalized = _normalize_provided_host(value)
    if not normalized:
        raise HTTPException(status_code=400, detail="Host name is required for evidence indexing.")
    return normalized


def _ensure_browser_folder_upload_allowed(files: list[UploadFile]) -> None:
    if not settings.backend_enable_experimental_folder_upload:
        raise HTTPException(
            status_code=403,
            detail="Browser folder upload is disabled. Compress the folder into ZIP/TAR/7z or use Register server-mounted path.",
        )
    file_count = len(files)
    total_bytes = sum(int(upload.size or 0) for upload in files)
    if file_count > settings.backend_experimental_folder_upload_max_files:
        raise HTTPException(
            status_code=413,
            detail=(
                "Browser folder upload limit exceeded: "
                f"{file_count} files > {settings.backend_experimental_folder_upload_max_files}. "
                "Use ZIP/TAR/7z or Register server-mounted path for large folders."
            ),
        )
    if total_bytes > settings.backend_experimental_folder_upload_max_total_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                "Browser folder upload size limit exceeded: "
                f"{total_bytes} bytes > {settings.backend_experimental_folder_upload_max_total_bytes}. "
                "Use ZIP/TAR/7z or Register server-mounted path for large folders."
            ),
        )


def _write_initial_manifest(evidence: Evidence) -> None:
    write_manifest(evidence_manifest_path(evidence.case_id, evidence.id), default_manifest(evidence))


def _finalize_discovery(db: Session, evidence: Evidence) -> dict:
    stored_path = Path(evidence.stored_path)
    container = open_evidence_container(stored_path)
    inventory_entries = container.list_entries()
    discovery = discover_velociraptor_evidences(container).as_dict()
    manifest = default_manifest(evidence)
    manifest["files"] = [
        {
            "path": entry.path,
            "size": entry.size,
            "sha256": None,
            "extension": Path(entry.path).suffix.lower(),
            "ignored": entry.ignored,
            "reason": entry.reason,
        }
        for entry in inventory_entries
    ]
    manifest["stats"]["total_files"] = len(inventory_entries)
    manifest["stats"]["processed_files"] = 0
    manifest["stats"]["ignored_files"] = sum(1 for entry in inventory_entries if entry.ignored)
    manifest["stats"]["detected_artifacts"] = discovery["summary"]["total_candidates"]
    write_manifest(evidence_manifest_path(evidence.case_id, evidence.id), manifest)

    metadata = dict(evidence.metadata_json or {})
    metadata.update(
        {
            "current_phase": "waiting_selection",
            "progress_pct": 20,
            "tree": [],
            "detected_artifacts": discovery["summary"]["total_candidates"],
            "artifacts_total": discovery["summary"]["total_candidates"],
            "velociraptor_discovery": discovery,
            "folder_entries": [{"path": entry.path, "ignored": entry.ignored, "reason": entry.reason} for entry in inventory_entries],
            "total_zip_entries": len(inventory_entries),
            "ignored_entries": sum(1 for entry in inventory_entries if entry.ignored),
            "candidate_files": discovery["summary"]["total_candidates"],
        }
    )
    recommended_ids = [str(candidate.get("id") or "") for candidate in discovery.get("candidates") or [] if candidate.get("supported")]
    metadata = persist_plan(
        metadata,
        build_plan(
            evidence,
            metadata,
            discovery_mode="updated_discovery",
            selected_candidate_ids=recommended_ids,
            disabled_candidate_ids=[],
            selected_reason="recommended",
        ),
    )
    evidence.metadata_json = metadata
    evidence.source_tool = "velociraptor"
    evidence.evidence_type = EvidenceType.velociraptor_zip
    db.commit()
    db.refresh(evidence)
    return {
        "evidence": EvidenceRead.model_validate(evidence).model_dump(mode="json"),
        "discovery": {**discovery, "collection_id": evidence.id},
    }


def _fallback_to_generic_archive(db: Session, evidence: Evidence, discovery: dict) -> dict:
    existing_metadata = dict(evidence.metadata_json or {})
    existing_source = dict(evidence.ingest_source or {})
    requested_ingest_mode = normalize_ingest_mode(existing_metadata.get("ingest_mode") or existing_source.get("ingest_mode"))
    requested_provided_host = _normalize_provided_host(existing_metadata.get("provided_host") or existing_source.get("provided_host"))
    evidence.evidence_type = EvidenceType.unknown
    evidence.source_tool = None
    evidence.metadata_json = _generic_archive_fallback_metadata(
        {
            **ingest_mode_metadata(requested_ingest_mode),
            "velociraptor_discovery": discovery,
            "velociraptor_fallback": True,
            "velociraptor_fallback_reason": "not_a_velociraptor_zip",
            "provided_host": requested_provided_host,
        }
    )
    evidence.ingest_source = {
        **existing_source,
        "ingest_mode": requested_ingest_mode,
        "provided_host": requested_provided_host,
    }
    db.commit()
    db.refresh(evidence)
    try:
        enqueue_ingest(evidence.id)
    except OpenSearchIngestBlockedError as exc:
        _mark_evidence_blocked_before_ingest(db, evidence, exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    log_activity(
        db,
        activity_type="evidence_uploaded",
        title="Archive uploaded as generic evidence",
        message=f"Velociraptor discovery did not match {evidence.original_filename}; processing as generic archive.",
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        metadata={"fallback_mode": "generic_archive"},
    )
    return {
        "evidence": EvidenceRead.model_validate(evidence).model_dump(mode="json"),
        "discovery": {**discovery, "collection_id": evidence.id},
        "fallback_supported": True,
        "fallback_mode": "generic_archive",
        "message": "Not a Velociraptor ZIP. Processing the archive as generic evidence instead.",
    }


@router.post("/api/cases/{case_id}/velociraptor/discover-zip", status_code=status.HTTP_201_CREATED)
def discover_velociraptor_zip(
    case_id: str,
    file: UploadFile = File(...),
    ingest_mode: str | None = Form(None),
    provided_host: str | None = Form(None),
    evtx_profile: str | None = Form(None),
    db: Session = Depends(get_db),
) -> dict:
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    normalized_provided_host = _require_provided_host(provided_host)
    evidence_id, stored_path, size = save_upload(case_id, file)
    normalized_ingest_mode = normalize_ingest_mode(ingest_mode)
    normalized_evtx_profile = str(evtx_profile or "").strip() or None
    evidence = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename=file.filename or stored_path.name,
        stored_path=str(stored_path),
        evidence_type=EvidenceType.velociraptor_zip,
        sha256=sha256_file(stored_path),
        size_bytes=size,
        ingest_status=IngestStatus.pending,
        source_tool="velociraptor",
        ingest_source={
            "mode": "uploaded",
            "original_path": str(stored_path),
            "storage_path": str(stored_path),
            "copied": True,
            "ingest_mode": normalized_ingest_mode,
            "provided_host": normalized_provided_host,
            "evtx_profile": normalized_evtx_profile,
        },
        metadata_json=_initial_metadata({**ingest_mode_metadata(normalized_ingest_mode), "provided_host": normalized_provided_host, "evtx_profile": normalized_evtx_profile}),
        error_log={},
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    _write_initial_manifest(evidence)
    try:
        result = _finalize_discovery(db, evidence)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported archive or invalid Velociraptor ZIP. Use a ZIP/TAR/7z generic archive upload instead. Details: {exc}",
        ) from exc
    if int(result["discovery"].get("summary", {}).get("total_candidates") or 0) <= 0:
        return _fallback_to_generic_archive(db, evidence, result["discovery"])
    log_activity(
        db,
        activity_type="evidence_uploaded",
        title="Velociraptor collection discovered",
        message=f"Discovered evidences in {evidence.original_filename}",
        case_id=case_id,
        evidence_id=evidence.id,
        metadata={"source_type": "velociraptor_collection", "ingest_mode": normalized_ingest_mode},
    )
    return result


@router.post("/api/cases/{case_id}/velociraptor/discover-folder", status_code=status.HTTP_201_CREATED)
def discover_velociraptor_folder(
    case_id: str,
    files: list[UploadFile] = File(...),
    ingest_mode: str | None = Form(None),
    provided_host: str | None = Form(None),
    evtx_profile: str | None = Form(None),
    db: Session = Depends(get_db),
) -> dict:
    _ensure_browser_folder_upload_allowed(files)
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    normalized_provided_host = _require_provided_host(provided_host)
    evidence_id, folder_path, total_size, folder_sha256, folder_entries, folder_label = save_folder_uploads(case_id, files)
    normalized_ingest_mode = normalize_ingest_mode(ingest_mode)
    normalized_evtx_profile = str(evtx_profile or "").strip() or None
    evidence = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename=folder_label,
        stored_path=str(folder_path),
        evidence_type=EvidenceType.velociraptor_zip,
        sha256=folder_sha256,
        size_bytes=total_size,
        ingest_status=IngestStatus.pending,
        source_tool="velociraptor",
        ingest_source={
            "mode": "uploaded",
            "original_path": str(folder_path),
            "storage_path": str(folder_path),
            "copied": True,
            "ingest_mode": normalized_ingest_mode,
            "provided_host": normalized_provided_host,
            "evtx_profile": normalized_evtx_profile,
        },
        metadata_json=_initial_metadata({**ingest_mode_metadata(normalized_ingest_mode), "folder_entries": folder_entries, "provided_host": normalized_provided_host, "evtx_profile": normalized_evtx_profile}),
        error_log={},
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    _write_initial_manifest(evidence)
    result = _finalize_discovery(db, evidence)
    return result


@router.post("/api/velociraptor/discover")
def discover_velociraptor_path(payload: VelociraptorDiscoverPathRequest, db: Session = Depends(get_db)) -> dict:
    if not db.get(Case, payload.case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    source_path = Path(payload.collection_path)
    if not source_path.exists():
        raise HTTPException(status_code=404, detail="Collection path not found")
    evidence = Evidence(
        case_id=payload.case_id,
        original_filename=source_path.name,
        stored_path=str(source_path),
        evidence_type=EvidenceType.velociraptor_zip,
        sha256=sha256_file(source_path) if source_path.is_file() else "folder",
        size_bytes=source_path.stat().st_size if source_path.is_file() else 0,
        ingest_status=IngestStatus.pending,
        source_tool="velociraptor",
        metadata_json=_initial_metadata(),
        error_log={},
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    _write_initial_manifest(evidence)
    return _finalize_discovery(db, evidence)


@router.post("/api/velociraptor/parse")
def parse_velociraptor_selection(payload: VelociraptorParseRequest, db: Session = Depends(get_db)) -> dict:
    evidence = db.get(Evidence, payload.evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    discovery = dict((evidence.metadata_json or {}).get("velociraptor_discovery") or {})
    candidates = discovery.get("candidates") or []
    if not candidates:
        raise HTTPException(status_code=400, detail="No discovery data found for this collection")

    selected_ids = set(payload.selected_candidate_ids)
    if payload.parse_all and not selected_ids:
        selected_ids = {candidate["id"] for candidate in candidates if candidate.get("supported")}
    if payload.categories:
        category_set = {category.lower() for category in payload.categories}
        selected_ids.update(
            candidate["id"]
            for candidate in candidates
            if candidate.get("supported") and str(candidate.get("category", "")).lower() in category_set
        )
    selected = [candidate for candidate in candidates if candidate.get("id") in selected_ids and candidate.get("supported")]
    if not selected:
        raise HTTPException(status_code=400, detail="No supported candidates selected")

    selected_files = {
        str(path)
        for candidate in selected
        for path in [candidate.get("original_path"), *(candidate.get("companion_files") or [])]
        if path
    }
    existing_metadata = dict(evidence.metadata_json or {})
    requested_ingest_mode = normalize_ingest_mode(payload.ingest_mode or existing_metadata.get("ingest_mode"))
    requested_provided_host = _normalize_provided_host(payload.provided_host) or _normalize_provided_host(existing_metadata.get("provided_host"))
    if not requested_provided_host:
        raise HTTPException(status_code=400, detail="Host name is required for evidence indexing.")
    requested_evtx_profile = str(payload.evtx_profile or existing_metadata.get("evtx_profile") or "").strip() or None
    metadata = _apply_velociraptor_selection_metadata(existing_metadata, candidates, selected)
    metadata.update(ingest_mode_metadata(requested_ingest_mode))
    metadata["ingest_mode"] = requested_ingest_mode
    metadata["provided_host"] = requested_provided_host
    metadata["evtx_profile"] = requested_evtx_profile
    metadata["current_phase"] = "extracting_selected"
    metadata["progress_pct"] = 25
    metadata["selected_candidates"] = len(selected)
    metadata["selected_files_total"] = len(selected_files)
    metadata["selected_files_extracted"] = 0
    metadata["current_item"] = None
    plan = build_plan(
        evidence,
        metadata,
        discovery_mode="manual",
        selected_candidate_ids=[str(candidate.get("id") or "") for candidate in selected],
        disabled_candidate_ids=[str(candidate.get("id") or "") for candidate in candidates if str(candidate.get("id") or "") not in selected_ids],
        parser_options={"ingest_mode": requested_ingest_mode, "evtx_profile": requested_evtx_profile},
        selected_reason="selected_by_user",
    )
    metadata = persist_plan(metadata, plan)
    adjusted_selected_ids = {str(candidate.get("candidate_id") or "") for candidate in plan.get("selected_candidates") or [] if candidate.get("candidate_id")}
    discovery = dict(metadata.get("velociraptor_discovery") or {})
    adjusted_candidates: list[dict] = []
    deferred_ids = {str(item.get("artifact_id") or "") for item in metadata.get("evtx_deferred_files") or []}
    for candidate in candidates:
        candidate_copy = dict(candidate)
        candidate_id = str(candidate.get("id") or "")
        candidate_copy["selected_for_extraction"] = candidate_id in adjusted_selected_ids
        if candidate_id in deferred_ids:
            candidate_copy["parser_status"] = "evtx_profile_deferred"
        adjusted_candidates.append(candidate_copy)
    discovery["candidates"] = adjusted_candidates
    metadata["velociraptor_discovery"] = discovery
    metadata["velociraptor_selected_candidate_ids"] = sorted(adjusted_selected_ids)
    metadata["selected_candidates"] = len(adjusted_selected_ids)
    evidence.metadata_json = metadata
    evidence.ingest_source = {
        **(evidence.ingest_source or {}),
        "ingest_mode": requested_ingest_mode,
        "provided_host": requested_provided_host,
        "evtx_profile": metadata.get("evtx_profile"),
    }
    evidence.ingest_status = IngestStatus.pending
    evidence.error_log = {}
    db.commit()
    db.refresh(evidence)
    try:
        enqueue_ingest(evidence.id)
    except OpenSearchIngestBlockedError as exc:
        _mark_evidence_blocked_before_ingest(db, evidence, exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "evidence": EvidenceRead.model_validate(evidence).model_dump(mode="json"),
        "selected_candidate_ids": metadata["velociraptor_selected_candidate_ids"],
        "selected_count": len(adjusted_selected_ids),
        "job": "queued",
    }
