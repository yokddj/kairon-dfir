from __future__ import annotations

from datetime import UTC, datetime
import hashlib
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.ingest.csv_json import list_generic_artifacts
from app.models.artifact import Artifact
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services.evidence_runs import merge_evidence_metadata
from app.services.evtx_profile import apply_evtx_profile_to_selection, evtx_channel


INGEST_PLAN_VERSION = 1
EVTX_PLAN_METADATA_KEYS = (
    "evtx_profile",
    "evtx_profile_reason",
    "evtx_selected_files",
    "evtx_deferred_files",
    "evtx_high_value_channels",
    "evtx_deferred_count",
    "evtx_fast_limits",
    "evtx_partial_files",
    "evtx_partial_count",
    "evtx_coverage_status",
    "evtx_parser_backend",
)


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def source_kind_for_evidence(evidence: Evidence, metadata: dict[str, Any] | None = None) -> str:
    metadata = metadata or {}
    source_type = str(metadata.get("source_type") or "")
    if source_type == "raw_collection":
        return "raw_archive" if Path(str(evidence.stored_path or "")).is_file() else "mounted_path"
    if evidence.storage_mode in {EvidenceStorageMode.mounted_path, EvidenceStorageMode.shared_path}:
        return "mounted_path"
    if evidence.evidence_type == EvidenceType.velociraptor_zip:
        return "raw_archive"
    if evidence.evidence_type in {EvidenceType.evtx, EvidenceType.txt, EvidenceType.unknown}:
        return "raw_file"
    if evidence.evidence_type in {EvidenceType.parsed_folder, EvidenceType.kape_archive, EvidenceType.csv, EvidenceType.json, EvidenceType.jsonl}:
        return "parsed_archive" if Path(str(evidence.stored_path or "")).suffix.lower() in {".zip", ".7z", ".tar", ".gz", ".bz2", ".xz"} else "parsed_file"
    return "parsed_file"


def candidate_parser_name(candidate: dict[str, Any]) -> str:
    return str(candidate.get("parser") or candidate.get("planned_parser") or candidate.get("artifact_type") or "unknown")


def candidate_fingerprint(candidate: dict[str, Any]) -> str:
    blob = "|".join(
        [
            str(candidate.get("id") or ""),
            str(candidate.get("original_path") or ""),
            str(candidate.get("artifact_type") or ""),
            candidate_parser_name(candidate),
            str(candidate.get("size") or ""),
            str(candidate.get("mtime") or ""),
        ]
    )
    return hashlib.sha1(blob.encode("utf-8", errors="ignore"), usedforsecurity=False).hexdigest()


def candidate_plan_entry(
    candidate: dict[str, Any],
    *,
    enabled: bool,
    reason: str,
    status: str = "available",
) -> dict[str, Any]:
    return {
        "candidate_id": str(candidate.get("id") or ""),
        "source_path": str(candidate.get("original_path") or ""),
        "relative_path": str(candidate.get("original_path") or ""),
        "artifact_type": str(candidate.get("artifact_type") or ""),
        "parser": candidate_parser_name(candidate),
        "enabled": enabled,
        "reason": reason,
        "fingerprint": candidate_fingerprint(candidate),
        "size": candidate.get("size"),
        "mtime": candidate.get("mtime"),
        "status": status,
        "supported": bool(candidate.get("supported")),
        "warnings": list(candidate.get("warnings") or []),
        "display_name": candidate.get("display_name"),
        "category": candidate.get("category"),
    }


def _stable_candidate_id(*parts: object) -> str:
    blob = "|".join(str(part or "") for part in parts)
    return f"artifact-{hashlib.sha1(blob.encode('utf-8', errors='ignore'), usedforsecurity=False).hexdigest()[:16]}"


def _normalized_source_path(value: object | None) -> str:
    return str(value or "").replace("\\", "/").strip().lower()


def _candidate_lookup(metadata: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    discovery = dict(metadata.get("velociraptor_discovery") or {})
    by_id: dict[str, dict[str, Any]] = {}
    by_path: dict[str, list[dict[str, Any]]] = {}
    for candidate in discovery.get("candidates") or []:
        candidate_id = str(candidate.get("id") or "")
        if candidate_id:
            by_id[candidate_id] = dict(candidate)
        normalized_path = _normalized_source_path(candidate.get("original_path") or candidate.get("source_path"))
        if normalized_path:
            by_path.setdefault(normalized_path, []).append(dict(candidate))
    return by_id, by_path


def _match_candidate_for_artifact(artifact: Artifact, path_candidates: dict[str, list[dict[str, Any]]]) -> dict[str, Any] | None:
    matches = path_candidates.get(_normalized_source_path(artifact.source_path), [])
    if not matches:
        return None
    if len(matches) == 1:
        return matches[0]
    parser = str(artifact.parser or "").lower()
    artifact_type = str(artifact.artifact_type or "").lower()
    for candidate in matches:
        candidate_parser = candidate_parser_name(candidate).lower()
        if candidate_parser == parser or str(candidate.get("artifact_type") or "").lower() == artifact_type:
            return candidate
    return matches[0]


def artifact_plan_entry(
    artifact: Artifact,
    *,
    candidate: dict[str, Any] | None = None,
    enabled: bool,
    reason: str,
    status: str = "available",
) -> dict[str, Any]:
    artifact_path = str(artifact.source_path or "")
    return {
        "candidate_id": str(candidate.get("id") or "") if candidate else _stable_candidate_id(artifact_path, artifact.artifact_type, artifact.parser),
        "source_path": artifact_path,
        "relative_path": artifact_path,
        "artifact_type": str(artifact.artifact_type or ""),
        "parser": str(artifact.parser or ""),
        "enabled": enabled,
        "reason": reason,
        "fingerprint": str(candidate_fingerprint(candidate) if candidate else _stable_candidate_id(artifact_path, artifact.artifact_type, artifact.parser, artifact.name)),
        "size": candidate.get("size") if candidate else None,
        "mtime": candidate.get("mtime") if candidate else None,
        "status": status,
        "supported": bool(candidate.get("supported")) if candidate is not None else True,
        "warnings": list(candidate.get("warnings") or []) if candidate is not None else [],
        "display_name": candidate.get("display_name") if candidate is not None else artifact.name,
        "category": candidate.get("category") if candidate is not None else None,
    }


def _discovery_summary(metadata: dict[str, Any]) -> dict[str, Any]:
    discovery = dict(metadata.get("velociraptor_discovery") or {})
    return {
        "collection_root": discovery.get("collection_root"),
        "hostname": discovery.get("hostname"),
        "summary": dict(discovery.get("summary") or {}),
        "warnings": list(discovery.get("warnings") or []),
        "total_files_scanned": int(discovery.get("total_files_scanned") or 0),
    }


def plan_summary_counts(candidates: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    by_artifact_type: dict[str, int] = {}
    by_parser: dict[str, int] = {}
    for item in candidates:
        artifact_type = str(item.get("artifact_type") or "unknown")
        parser_name = str(item.get("parser") or "unknown")
        by_artifact_type[artifact_type] = by_artifact_type.get(artifact_type, 0) + 1
        by_parser[parser_name] = by_parser.get(parser_name, 0) + 1
    return {
        "selected_by_artifact_type": dict(sorted(by_artifact_type.items())),
        "selected_by_parser": dict(sorted(by_parser.items())),
    }


def build_single_file_ingest_plan(
    evidence: Evidence,
    metadata: dict[str, Any],
    *,
    discovery_mode: str = "single_file_detected",
) -> dict[str, Any] | None:
    path = Path(str(evidence.stored_path or ""))
    if not path.is_file():
        return None
    if resolve_public_single_file_type(evidence) != EvidenceType.evtx:
        return None
    try:
        artifacts = list_generic_artifacts(path)
    except Exception:  # noqa: BLE001
        return None
    if not artifacts:
        return None
    artifact = artifacts[0]
    selected_candidates = [
        {
            "candidate_id": _stable_candidate_id(path.name, artifact.get("artifact_type"), artifact.get("parser")),
            "source_path": path.name,
            "relative_path": path.name,
            "artifact_type": str(artifact.get("artifact_type") or ""),
            "parser": str(artifact.get("parser") or ""),
            "enabled": True,
            "reason": "single_evtx_file_detected",
            "fingerprint": _stable_candidate_id(path.name, artifact.get("artifact_type"), artifact.get("parser"), evidence.sha256),
            "size": evidence.size_bytes,
            "mtime": int(path.stat().st_mtime) if path.exists() else None,
            "status": "available",
            "supported": True,
            "warnings": [],
            "display_name": path.name,
            "category": "evtx",
        }
    ]
    previous = dict(metadata.get("ingest_plan") or {})
    return {
        "evidence_id": evidence.id,
        "case_id": evidence.case_id,
        "created_at": previous.get("created_at") or _utcnow(),
        "updated_at": _utcnow(),
        "plan_version": INGEST_PLAN_VERSION,
        "source_kind": source_kind_for_evidence(evidence, metadata),
        "discovery_mode": discovery_mode,
        "selected_candidates": selected_candidates,
        "disabled_candidates": [],
        "parser_options": dict(previous.get("parser_options") or {}),
        "original_discovery_summary": {
            "collection_root": str(path.parent),
            "hostname": None,
            "summary": {
                "total_candidates": 1,
                "supported_candidates": 1,
            },
            "warnings": [],
            "total_files_scanned": 1,
        },
        "last_reprocess_summary": dict(previous.get("last_reprocess_summary") or {}),
        **plan_summary_counts(selected_candidates),
    }


def resolve_public_single_file_type(evidence: Evidence) -> EvidenceType:
    if isinstance(evidence.evidence_type, EvidenceType):
        return evidence.evidence_type
    try:
        return EvidenceType(str(evidence.evidence_type or "unknown"))
    except ValueError:
        return EvidenceType.unknown


def build_plan(
    evidence: Evidence,
    metadata: dict[str, Any],
    *,
    discovery_mode: str,
    selected_candidate_ids: list[str] | None = None,
    disabled_candidate_ids: list[str] | None = None,
    parser_options: dict[str, Any] | None = None,
    selected_reason: str = "selected_by_user",
) -> dict[str, Any]:
    now = _utcnow()
    discovery = dict(metadata.get("velociraptor_discovery") or {})
    candidates = list(discovery.get("candidates") or [])
    previous = dict(metadata.get("ingest_plan") or {})
    effective_parser_options = parser_options or dict(previous.get("parser_options") or {})
    profile_result = apply_evtx_profile_to_selection(
        candidates,
        selected_candidate_ids,
        ingest_mode=effective_parser_options.get("ingest_mode") or metadata.get("ingest_mode"),
        requested_profile=effective_parser_options.get("evtx_profile") or metadata.get("evtx_profile"),
    )
    selected_set = set(profile_result.get("selected_candidate_ids") or [])
    disabled_set = set(disabled_candidate_ids or [])
    deferred_by_id = {
        str(item.get("artifact_id") or ""): dict(item)
        for item in profile_result.get("evtx_deferred_files") or []
        if str(item.get("artifact_id") or "")
    }
    selected_candidates = [
        candidate_plan_entry(candidate, enabled=True, reason=selected_reason)
        for candidate in candidates
        if str(candidate.get("id") or "") in selected_set
    ]
    disabled_candidates = []
    for candidate in candidates:
        candidate_id = str(candidate.get("id") or "")
        if candidate_id not in disabled_set and candidate_id in selected_set:
            continue
        if candidate_id in deferred_by_id:
            deferred_entry = candidate_plan_entry(candidate, enabled=False, reason="evtx_profile_deferred", status="deferred")
            deferred_entry.update(
                {
                    "profile": deferred_by_id[candidate_id].get("profile"),
                    "can_run_later": True,
                    "suggested_action": deferred_by_id[candidate_id].get("suggested_action"),
                    "evtx_channel": evtx_channel(candidate),
                }
            )
            disabled_candidates.append(deferred_entry)
            continue
        disabled_candidates.append(
            candidate_plan_entry(
                candidate,
                enabled=False,
                reason="not_selected",
                status="unsupported" if not candidate.get("supported") else "available",
            )
        )
    return {
        "evidence_id": evidence.id,
        "case_id": evidence.case_id,
        "created_at": previous.get("created_at") or now,
        "updated_at": now,
        "plan_version": INGEST_PLAN_VERSION,
        "source_kind": source_kind_for_evidence(evidence, metadata),
        "discovery_mode": discovery_mode,
        "selected_candidates": selected_candidates,
        "disabled_candidates": disabled_candidates,
        "parser_options": {
            **effective_parser_options,
            "evtx_profile": profile_result.get("evtx_profile"),
            "evtx_fast_limits": profile_result.get("evtx_fast_limits") or {},
        },
        "evtx_parser_backend": str(effective_parser_options.get("evtx_parser_backend") or metadata.get("evtx_parser_backend") or "auto"),
        "evtx_profile": profile_result.get("evtx_profile"),
        "evtx_profile_reason": profile_result.get("evtx_profile_reason"),
        "evtx_fast_limits": profile_result.get("evtx_fast_limits") or {},
        "evtx_selected_files": profile_result.get("evtx_selected_files") or [],
        "evtx_deferred_files": profile_result.get("evtx_deferred_files") or [],
        "evtx_high_value_channels": profile_result.get("evtx_high_value_channels") or [],
        "evtx_deferred_count": int(profile_result.get("evtx_deferred_count") or 0),
        "evtx_partial_files": profile_result.get("evtx_partial_files") or [],
        "evtx_partial_count": int(profile_result.get("evtx_partial_count") or 0),
        "evtx_coverage_status": profile_result.get("evtx_coverage_status") or "full",
        "original_discovery_summary": _discovery_summary(metadata),
        "last_reprocess_summary": dict(previous.get("last_reprocess_summary") or {}),
        **plan_summary_counts(selected_candidates),
    }


def build_plan_from_artifacts(
    evidence: Evidence,
    metadata: dict[str, Any],
    *,
    artifacts: list[Artifact],
    discovery_mode: str,
    plan_source: str,
) -> dict[str, Any] | None:
    if not artifacts:
        return None
    previous = dict(metadata.get("ingest_plan") or {})
    _, candidates_by_path = _candidate_lookup(metadata)
    deduped: dict[tuple[str, str, str], Artifact] = {}
    for artifact in artifacts:
        key = (
            _normalized_source_path(artifact.source_path),
            str(artifact.artifact_type or "").lower(),
            str(artifact.parser or "").lower(),
        )
        deduped.setdefault(key, artifact)
    selected_candidates = [
        artifact_plan_entry(
            artifact,
            candidate=_match_candidate_for_artifact(artifact, candidates_by_path),
            enabled=True,
            reason="previous_plan" if previous else "selected_by_user",
        )
        for artifact in sorted(deduped.values(), key=lambda item: (str(item.source_path or "").lower(), str(item.parser or "").lower()))
    ]
    selected_ids = {str(item.get("candidate_id") or "") for item in selected_candidates if item.get("candidate_id")}
    discovery = dict(metadata.get("velociraptor_discovery") or {})
    disabled_candidates = [
        candidate_plan_entry(
            candidate,
            enabled=False,
            reason="not_selected",
            status="unsupported" if not candidate.get("supported") else "available",
        )
        for candidate in discovery.get("candidates") or []
        if str(candidate.get("id") or "") not in selected_ids
    ]
    plan = {
        "evidence_id": evidence.id,
        "case_id": evidence.case_id,
        "created_at": previous.get("created_at") or _utcnow(),
        "updated_at": _utcnow(),
        "plan_version": INGEST_PLAN_VERSION,
        "source_kind": source_kind_for_evidence(evidence, metadata),
        "discovery_mode": previous.get("discovery_mode") or discovery_mode,
        "plan_source": plan_source,
        "selected_candidates": selected_candidates,
        "disabled_candidates": disabled_candidates,
        "parser_options": dict(previous.get("parser_options") or {}),
        "original_discovery_summary": _discovery_summary(metadata),
        "last_reprocess_summary": dict(previous.get("last_reprocess_summary") or {}),
        **plan_summary_counts(selected_candidates),
    }
    return plan


def rebuild_ingest_plan_from_last_run(
    db: Session,
    evidence: Evidence,
    metadata: dict[str, Any],
    *,
    persist: bool = False,
) -> dict[str, Any] | None:
    artifacts = db.query(Artifact).filter(Artifact.evidence_id == evidence.id).order_by(Artifact.created_at.asc()).all()
    plan = build_plan_from_artifacts(
        evidence,
        metadata,
        artifacts=artifacts,
        discovery_mode="previous_selection",
        plan_source="reconstructed_from_last_ingest",
    )
    if not plan:
        return None
    if persist:
        updated_metadata = persist_plan(metadata, plan)
        updated_metadata["ingest_plan_reconstructed"] = True
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, updated_metadata)
        db.add(evidence)
        db.commit()
        db.refresh(evidence)
    return plan


def legacy_plan_from_metadata(evidence: Evidence, metadata: dict[str, Any]) -> dict[str, Any] | None:
    current = metadata.get("ingest_plan")
    if isinstance(current, dict) and current:
        return current
    discovery = dict(metadata.get("velociraptor_discovery") or {})
    candidates = list(discovery.get("candidates") or [])
    selected_ids = [str(item) for item in (metadata.get("velociraptor_selected_candidate_ids") or []) if item]
    if not candidates:
        return None
    return build_plan(
        evidence,
        metadata,
        discovery_mode="previous_selection",
        selected_candidate_ids=selected_ids,
        disabled_candidate_ids=[str(candidate.get("id") or "") for candidate in candidates if str(candidate.get("id") or "") not in set(selected_ids)],
        selected_reason="previous_plan",
    )


def get_last_successful_plan(evidence: Evidence, metadata: dict[str, Any]) -> dict[str, Any] | None:
    current = metadata.get("last_successful_ingest_plan")
    if isinstance(current, dict) and current:
        return current
    current = metadata.get("ingest_plan")
    ingest_status = getattr(evidence, "ingest_status", IngestStatus.completed)
    if isinstance(current, dict) and current and ingest_status in {IngestStatus.completed, IngestStatus.completed_with_errors}:
        return current
    return legacy_plan_from_metadata(evidence, metadata)


def get_requested_plan(metadata: dict[str, Any]) -> dict[str, Any] | None:
    current = metadata.get("requested_ingest_plan")
    if isinstance(current, dict) and current:
        return current
    current = metadata.get("ingest_plan")
    if isinstance(current, dict) and current:
        return current
    return None


def persist_plan(metadata: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    metadata = dict(metadata or {})
    metadata["ingest_plan"] = plan
    metadata["ingest_plan_updated_at"] = plan.get("updated_at")
    for key in EVTX_PLAN_METADATA_KEYS:
        if key in plan:
            metadata[key] = plan.get(key)
    return metadata


def persist_requested_plan(metadata: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    metadata = dict(metadata or {})
    metadata["requested_ingest_plan"] = plan
    metadata["ingest_plan"] = plan
    metadata["ingest_plan_updated_at"] = plan.get("updated_at")
    for key in EVTX_PLAN_METADATA_KEYS:
        if key in plan:
            metadata[key] = plan.get(key)
    return metadata


def persist_successful_plan(metadata: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    metadata = dict(metadata or {})
    metadata["last_successful_ingest_plan"] = plan
    metadata["ingest_plan"] = plan
    metadata["ingest_plan_updated_at"] = plan.get("updated_at")
    for key in EVTX_PLAN_METADATA_KEYS:
        if key in plan:
            metadata[key] = plan.get(key)
    metadata.pop("requested_ingest_plan", None)
    return metadata


def append_plan_snapshot(
    metadata: dict[str, Any],
    *,
    plan: dict[str, Any],
    phase: str,
    summary: dict[str, Any],
) -> dict[str, Any]:
    metadata = dict(metadata or {})
    snapshots = list(metadata.get("ingest_plan_snapshots") or [])
    snapshots.append(
        {
            "recorded_at": _utcnow(),
            "phase": phase,
            "plan_used": plan,
            "used_candidates": list(plan.get("selected_candidates") or []),
            "discovery_result": plan.get("original_discovery_summary") or {},
            "selected_count": len(plan.get("selected_candidates") or []),
            "parsed_count": int(summary.get("parsed_count") or 0),
            "failed_count": int(summary.get("failed_count") or 0),
            "skipped_count": int(summary.get("skipped_count") or 0),
            "warnings": list(summary.get("warnings") or []),
            "summary": summary,
        }
    )
    metadata["ingest_plan_snapshots"] = snapshots[-20:]
    return metadata


def candidate_map_from_discovery(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    discovery = dict(metadata.get("velociraptor_discovery") or {})
    return {str(candidate.get("id") or ""): dict(candidate) for candidate in discovery.get("candidates") or [] if candidate.get("id")}


def build_reprocess_preview(
    evidence: Evidence,
    *,
    metadata: dict[str, Any],
    mode: str,
    current_metadata: dict[str, Any],
) -> dict[str, Any]:
    previous_plan = get_last_successful_plan(evidence, metadata)
    current_candidates = candidate_map_from_discovery(current_metadata)
    current_supported = [candidate for candidate in current_candidates.values() if candidate.get("supported")]
    previous_selected = list((previous_plan or {}).get("selected_candidates") or [])
    previous_selected_ids = {str(item.get("candidate_id") or "") for item in previous_selected if item.get("candidate_id")}
    previous_all_ids = {
        *(str(item.get("candidate_id") or "") for item in (previous_plan or {}).get("selected_candidates") or []),
        *(str(item.get("candidate_id") or "") for item in (previous_plan or {}).get("disabled_candidates") or []),
    }

    selected_rows: list[dict[str, Any]] = []
    missing_rows: list[dict[str, Any]] = []
    changed_rows: list[dict[str, Any]] = []
    new_rows: list[dict[str, Any]] = []
    warnings: list[str] = []

    if not previous_plan:
        warnings.append("No previous ingest plan is stored for this evidence.")

    for entry in previous_selected:
        candidate_id = str(entry.get("candidate_id") or "")
        current = current_candidates.get(candidate_id)
        if not current:
            missing_rows.append({**entry, "status": "missing"})
            continue
        current_entry = candidate_plan_entry(current, enabled=True, reason="previous_plan")
        if current_entry["fingerprint"] != entry.get("fingerprint"):
            current_entry["status"] = "changed"
            changed_rows.append(current_entry)
        else:
            current_entry["status"] = "available"
        selected_rows.append(current_entry)

    for candidate in current_supported:
        candidate_id = str(candidate.get("id") or "")
        if candidate_id in previous_all_ids:
            continue
        new_entry = candidate_plan_entry(candidate, enabled=True, reason="recommended", status="new")
        new_rows.append(new_entry)
        if mode == "full_rediscovery":
            selected_rows.append(new_entry)

    if mode == "full_rediscovery":
        selected_rows = [candidate_plan_entry(candidate, enabled=True, reason="recommended", status="available") for candidate in current_supported]

    summary = {
        "previous_selected": len(previous_selected),
        "available_again": sum(1 for row in selected_rows if row.get("status") == "available"),
        "missing": len(missing_rows),
        "changed": len(changed_rows),
        "new_candidates": len(new_rows),
        "unsupported": sum(1 for candidate in current_candidates.values() if not candidate.get("supported")),
        **plan_summary_counts(selected_rows),
    }
    return {
        "evidence_id": evidence.id,
        "previous_plan_available": previous_plan is not None,
        "mode": mode,
        "summary": summary,
        "selected_candidates": selected_rows,
        "missing_candidates": missing_rows,
        "new_candidates": new_rows,
        "changed_candidates": changed_rows,
        "warnings": warnings,
        "previous_plan": previous_plan,
    }


def apply_last_reprocess_summary(plan: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    updated = dict(plan or {})
    updated["updated_at"] = _utcnow()
    updated["last_reprocess_summary"] = summary
    return updated
