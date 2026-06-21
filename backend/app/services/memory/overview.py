from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.opensearch import count_documents, get_events_index
from app.models.evidence import Evidence, EvidenceType
from app.models.memory import MemoryArtifactSummary, MemoryScanRun
from app.services.memory.active_result import FAMILY_RESOLUTION, list_families, resolve_active_memory_result
from app.services.memory.catalogue import build_analysis_catalogue
from app.services.memory.volatility_runner import network_basic_available


settings = get_settings()


def _safe_disk_event_count(case_id: str) -> int:
    try:
        result = count_documents(get_events_index(case_id))
        return int(result.get("count") or 0)
    except Exception:  # noqa: BLE001
        return 0


def list_memory_evidences(db: Session, case_id: str) -> list[Evidence]:
    return (
        db.query(Evidence)
        .filter(Evidence.case_id == case_id, Evidence.evidence_type == EvidenceType.memory_dump)
        .order_by(Evidence.created_at.desc())
        .all()
    )


def _has_memory_results(db: Session, case_id: str) -> bool:
    run_count = (
        db.query(func.count(MemoryScanRun.id))
        .filter(
            MemoryScanRun.case_id == case_id,
            ~MemoryScanRun.status.in_(["pending", "disabled"]),
            MemoryScanRun.plugin_count > 0,
        )
        .scalar()
        or 0
    )
    if int(run_count) > 0:
        return True
    summary_count = (
        db.query(func.count(MemoryArtifactSummary.id))
        .filter(MemoryArtifactSummary.case_id == case_id, MemoryArtifactSummary.count > 0)
        .scalar()
        or 0
    )
    return int(summary_count) > 0


def infer_case_evidence_mode(db: Session, case_id: str) -> dict:
    has_memory_evidence = bool(list_memory_evidences(db, case_id))
    has_disk_events = _safe_disk_event_count(case_id) > 0
    if has_disk_events and has_memory_evidence:
        mode = "hybrid"
    elif has_memory_evidence:
        mode = "memory_only"
    elif has_disk_events:
        mode = "disk_only"
    else:
        mode = "empty"
    return {
        "has_memory_evidence": has_memory_evidence,
        "has_disk_events": has_disk_events,
        "mode": mode,
    }


def _message_for_mode(*, enabled: bool, mode: str, has_results: bool) -> str:
    if not enabled:
        return "Memory Analysis is currently disabled. Kairon can still work with disk artifacts only. Enable memory analysis in backend configuration when you are ready to analyze authorized RAM evidence."
    if mode == "empty":
        return "No disk events or memory evidence found for this case. Kairon can work with disk artifacts only, memory artifacts only, or both."
    if mode == "disk_only":
        return "This case currently has disk artifacts only. Authorized RAM evidence can be registered separately when available."
    if mode == "memory_only" and not has_results:
        return "Authorized memory evidence is present, but no external memory analysis has been executed in this build."
    if mode == "memory_only":
        return "This case currently has isolated memory evidence results only."
    return "This case has both disk events and memory evidence. Memory results remain isolated from Search, Timeline, Detections, Findings, Reports, and SIEM in this build."


def get_case_memory_overview(db: Session, case_id: str) -> dict:
    evidences = list_memory_evidences(db, case_id)
    runs = (
        db.query(MemoryScanRun)
        .filter(MemoryScanRun.case_id == case_id)
        .order_by(MemoryScanRun.created_at.desc())
        .all()
    )
    mode_info = infer_case_evidence_mode(db, case_id)
    has_results = _has_memory_results(db, case_id)
    enabled = bool(settings.memory_analysis_enabled)
    return {
        "case_id": case_id,
        "memory_analysis_enabled": enabled,
        "memory_process_profile_enabled": bool(settings.memory_process_profile_enabled),
        "has_memory_evidence": bool(mode_info["has_memory_evidence"]),
        "has_memory_results": has_results,
        "has_disk_events": bool(mode_info["has_disk_events"]),
        "mode": mode_info["mode"],
        "evidences": evidences,
        "runs": runs,
        "message": _message_for_mode(enabled=enabled, mode=str(mode_info["mode"]), has_results=has_results),
    }


def get_evidence_landing(db: Session, case_id: str) -> list[dict]:
    """Return a per-evidence summary for the memory case landing page.

    Each entry includes the evidence metadata, a per-family status
    (Ready / Not analyzed / Completed / Running / Latest attempt
    failed / Unavailable) and a list of completed runs.
    """
    from app.services.memory.counts import get_memory_family_count

    evidences = list_memory_evidences(db, case_id)
    network_unavailable = not network_basic_available()[0]
    items: list[dict] = []
    for evidence in evidences:
        families: list[dict] = []
        for family in list_families():
            rules = FAMILY_RESOLUTION[family]
            if family == "network" and network_unavailable:
                families.append(
                    {
                        "family": family,
                        "state": "unavailable",
                        "title": _family_title(family),
                        "active_run": None,
                        "latest_attempt": None,
                        "selection_reason": "runtime_plugin_missing",
                        "using_fallback": False,
                        "historical_override": False,
                        "availability_reason": "No compatible Windows network plugin is available in the installed Volatility runtime.",
                        "count": 0,
                        "document_type": "memory_network_connection",
                        "count_source": "no_active_run",
                    }
                )
                continue
            resolved = resolve_active_memory_result(
                db,
                case_id=case_id,
                evidence_id=evidence.id,
                family=family,
            )
            active_run = resolved.get("active_run") or {}
            active_run_id = active_run.get("id") if isinstance(active_run, dict) else None
            count_payload = get_memory_family_count(
                case_id=case_id,
                evidence_id=evidence.id,
                family=family,
                active_run_id=active_run_id,
                db=db,
            )
            families.append(
                {
                    "family": family,
                    "state": resolved["analysis_state"],
                    "title": _family_title(family),
                    "active_run": resolved["active_run"],
                    "latest_attempt": resolved["latest_attempt"],
                    "selection_reason": resolved["selection_reason"],
                    "using_fallback": resolved["using_fallback"],
                    "historical_override": resolved["historical_override"],
                    "availability_reason": None,
                    "count": int(count_payload["total"]),
                    "document_type": count_payload["document_type"],
                    "count_source": count_payload["count_source"],
                }
            )
        runs = (
            db.query(MemoryScanRun)
            .filter(MemoryScanRun.evidence_id == evidence.id)
            .order_by(MemoryScanRun.created_at.desc())
            .all()
        )
        items.append(
            {
                "evidence_id": evidence.id,
                "case_id": evidence.case_id,
                "filename": evidence.original_filename,
                "detected_host": evidence.detected_host,
                "size_bytes": evidence.size_bytes,
                "created_at": evidence.created_at.isoformat() if evidence.created_at else None,
                "processed_at": evidence.processed_at.isoformat() if evidence.processed_at else None,
                "ingest_status": evidence.ingest_status.value if evidence.ingest_status else None,
                "metadata": evidence.metadata_json or {},
                "families": families,
                "run_count": len(runs),
                "latest_run_id": runs[0].id if runs else None,
                "latest_run_status": runs[0].status if runs else None,
            }
        )
    return items


def _family_title(family: str) -> str:
    return {
        "system_info": "System metadata",
        "processes": "Processes",
        "network": "Network connections",
        "modules": "Process modules",
        "handles": "Process handles",
        "kernel_modules": "Kernel modules",
        "drivers": "Drivers",
        "suspicious_regions": "Suspicious memory regions",
        "raw_observations": "Raw observations",
    }.get(family, family)
