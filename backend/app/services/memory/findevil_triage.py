"""Find Evil triage by process.

Find Evil reports indicators one by one, and a single process (a browser,
a JIT runtime, an injected process) often carries many of them. Triage is
done per process: each process with indicators is one row, with its
indicators counted by priority and its indicator types, and the analyst
marks the process reviewed, suspicious or not relevant.

The mark is an EventMarking keyed by a run-independent identity (evidence,
PID, process name), so it survives re-running Find Evil and counts with the
case's other marked events.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote

from sqlalchemy.orm import Session

from app.core.opensearch import get_memory_index, get_opensearch_client
from app.models.event_marking import EventMarking
from app.services.memory.artifact_indexing import _aggregatable_field

MARKING_ARTIFACT_TYPE = "memory_findevil_process"
PRIORITIES = ("high", "medium", "low")
MAX_PROCESSES = 2000


def process_marking_id(evidence_id: str, pid: int | None, process_name: str | None) -> str:
    # The name is escaped: it is part of a URL path segment (Linux names such
    # as "kworker/0:1" carry a slash).
    return f"memory-findevil-process:{evidence_id}:{'' if pid is None else pid}:{quote(process_name or '', safe='')}"


def _priority_rank(counts: dict[str, int]) -> int:
    for rank, priority in enumerate(PRIORITIES):
        if counts.get(priority):
            return rank
    return len(PRIORITIES)


def findevil_processes(db: Session, *, case_id: str, evidence_id: str, run_id: str) -> list[dict[str, Any]]:
    """One entry per process with Find Evil indicators in ``run_id``, most
    important first (highest priority, then most indicators)."""
    client = get_opensearch_client()
    index = get_memory_index(case_id)
    name_field = _aggregatable_field(client, index, "process_name")
    priority_field = _aggregatable_field(client, index, "review_priority")
    type_field = _aggregatable_field(client, index, "indicator_type")
    body = {
        "size": 0,
        "timeout": "10s",
        "query": {"bool": {"filter": [
            {"term": {"document_type": "memory_findevil"}},
            {"term": {"scan_run_id.keyword": run_id}},
            {"term": {"evidence_id": evidence_id}},
        ]}},
        "aggs": {"pids": {
            # Indicators without a PID (e.g. kernel-wide ones) form their own group.
            "terms": {"field": "pid", "size": MAX_PROCESSES, "missing": -1},
            "aggs": {"names": {
                "terms": {"field": name_field, "size": 5, "missing": ""},
                "aggs": {
                    "priorities": {"terms": {"field": priority_field, "size": 10}},
                    "types": {"terms": {"field": type_field, "size": 50}},
                },
            }},
        }},
    }
    response = client.search(index=index, body=body, params={"ignore_unavailable": "true"})
    buckets = (((response.get("aggregations") or {}).get("pids") or {}).get("buckets")) or []

    processes: list[dict[str, Any]] = []
    for pid_bucket in buckets:
        raw_pid = pid_bucket.get("key")
        pid = None if raw_pid in (None, -1) else int(raw_pid)
        for name_bucket in (pid_bucket.get("names") or {}).get("buckets") or []:
            name = str(name_bucket.get("key") or "") or None
            counts = {str(b["key"]).lower(): int(b.get("doc_count") or 0) for b in (name_bucket.get("priorities") or {}).get("buckets") or []}
            types = [{"value": str(b["key"]), "count": int(b.get("doc_count") or 0)} for b in (name_bucket.get("types") or {}).get("buckets") or []]
            processes.append({
                "triage_id": process_marking_id(evidence_id, pid, name),
                "pid": pid,
                "process_name": name,
                "indicator_count": int(name_bucket.get("doc_count") or 0),
                "priority_counts": {p: counts.get(p, 0) for p in PRIORITIES},
                "top_priority": PRIORITIES[_priority_rank(counts)] if _priority_rank(counts) < len(PRIORITIES) else None,
                "indicator_types": types,
                "marking": None,
            })

    markings = {
        m.event_id: m
        for m in db.query(EventMarking).filter(
            EventMarking.case_id == case_id,
            EventMarking.artifact_type == MARKING_ARTIFACT_TYPE,
            EventMarking.event_id.in_([p["triage_id"] for p in processes] or [""]),
        )
    }
    for process in processes:
        marking = markings.get(process["triage_id"])
        if marking is not None:
            process["marking"] = {"id": marking.id, "status": marking.status, "note": marking.note}
    processes.sort(key=lambda p: (_priority_rank(p["priority_counts"]), -p["priority_counts"]["high"], -p["priority_counts"]["medium"], -p["indicator_count"], p["pid"] if p["pid"] is not None else 1 << 31))
    return processes
