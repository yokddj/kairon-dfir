"""What the case report says about the memory images: one entry per image.

For each memory evidence: the system it came from (from Volatility's system
information, or the Linux kernel banner), what was analysed and how much each
analysis found, and the Find Evil triage -- the processes the analyst marked
suspicious or important, with their indicators, and how many are still to
review. Only facts already shown in the Memory views; nothing is judged here.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.memory import MemoryScanRun
from app.services.memory.overview import get_evidence_landing

logger = logging.getLogger(__name__)

# Marks that put a process in the report, and the ones that close it.
REPORTED_MARKS = {"suspicious", "important"}
SETTLED_MARKS = {"reviewed", "not_relevant", "false_positive"}


def _system(evidence_metadata: dict[str, Any], runs: list[MemoryScanRun]) -> dict[str, Any]:
    for run in runs:
        info = (run.metadata_json or {}).get("system_info")
        if not isinstance(info, dict):
            continue
        os_info = info.get("os") or {}
        fields = (info.get("raw") or {}).get("fields") or {}
        family = str(os_info.get("family") or "")
        if family == "windows":
            label = "Windows"
            if os_info.get("kernel_version"):
                label += f" {os_info['kernel_version']}"
            if os_info.get("windows_build"):
                label += f" (build {os_info['windows_build']})"
        else:
            label = " ".join(str(part) for part in (family.capitalize(), os_info.get("kernel_version")) if part)
        return {
            "system": label or None,
            "architecture": os_info.get("machine_type"),
            "captured_at": fields.get("SystemTime"),
        }
    kernel = evidence_metadata.get("linux_kernel") or {}
    if kernel.get("kernel_release"):
        return {"system": f"Linux {kernel['kernel_release']}", "architecture": kernel.get("architecture"), "captured_at": None}
    return {"system": None, "architecture": None, "captured_at": None}


def _find_evil(db: Session, *, case_id: str, evidence_id: str, run_id: str) -> dict[str, Any]:
    from app.services.memory.findevil_triage import findevil_processes

    try:
        processes = findevil_processes(db, case_id=case_id, evidence_id=evidence_id, run_id=run_id)
    except Exception:  # noqa: BLE001 -- the report still renders without the index
        logger.warning("memory report: Find Evil processes unavailable", exc_info=True)
        return {"available": False}
    priorities = {"high": 0, "medium": 0, "low": 0}
    for process in processes:
        for priority, count in (process.get("priority_counts") or {}).items():
            priorities[priority] = priorities.get(priority, 0) + int(count or 0)
    marked = [
        {
            "process": process.get("process_name"),
            "pid": process.get("pid"),
            "mark": process["marking"]["status"],
            "note": process["marking"].get("note"),
            "top_priority": process.get("top_priority"),
            "indicator_count": process.get("indicator_count"),
            "indicator_types": [item["value"] for item in process.get("indicator_types") or []],
        }
        for process in processes
        if process.get("marking") and process["marking"].get("status") in REPORTED_MARKS
    ]
    settled = sum(1 for process in processes if process.get("marking") and process["marking"].get("status") in SETTLED_MARKS)
    return {
        "available": True,
        "process_count": len(processes),
        "indicator_counts": priorities,
        "marked_processes": marked,
        "settled_count": settled,
        "unreviewed_count": sum(1 for process in processes if not process.get("marking")),
    }


def build_memory_report_context(db: Session, case_id: str, *, evidence_id: str | None = None, host_matches=None) -> list[dict[str, Any]]:
    """One entry per memory image in the case (``host_matches`` filters by host name)."""
    try:
        landing = get_evidence_landing(db, case_id)
    except Exception:  # noqa: BLE001 -- e.g. OpenSearch down: no memory section rather than no report
        logger.warning("memory report: evidence landing unavailable", exc_info=True)
        return []
    entries: list[dict[str, Any]] = []
    for item in landing:
        if evidence_id and item["evidence_id"] != evidence_id:
            continue
        metadata = item.get("metadata") or {}
        host = item.get("detected_host") or metadata.get("provided_host")
        if host_matches is not None and not host_matches(host):
            continue
        runs = (
            db.query(MemoryScanRun)
            .filter(MemoryScanRun.evidence_id == item["evidence_id"])
            .order_by(MemoryScanRun.created_at.desc())
            .all()
        )
        analyses = [
            {"family": family["family"], "title": family["title"], "state": family["state"], "count": family["count"]}
            for family in item.get("families") or []
            if family.get("state") not in {None, "not_analyzed", "unavailable"}
        ]
        find_evil_family = next((family for family in item.get("families") or [] if family.get("family") == "find_evil"), None)
        find_evil_run = (find_evil_family or {}).get("active_run") or {}
        findings = (
            db.query(Finding)
            .filter(Finding.case_id == case_id, or_(Finding.linked_evidence_id == item["evidence_id"], Finding.evidence_id == item["evidence_id"]))
            .count()
        )
        entries.append({
            "evidence_id": item["evidence_id"],
            "filename": item.get("filename"),
            "host": host,
            "size_bytes": item.get("size_bytes"),
            "format": item.get("detected_format"),
            **_system(metadata, runs),
            "analyses": analyses,
            "find_evil": _find_evil(db, case_id=case_id, evidence_id=item["evidence_id"], run_id=str(find_evil_run["id"])) if find_evil_run.get("id") else None,
            "findings_count": findings,
        })
    return entries
