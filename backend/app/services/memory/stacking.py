"""Stacking (frequency analysis) of memory artifacts.

A memory image holds tens of thousands of module and handle records, most
of them the same few values seen in every process (the system DLLs every
process loads, the handles every process opens). Stacking groups a
family's records by value and counts in how many processes each value
appears; the values seen in few processes come first. It hides nothing --
every value is listed with its counts -- it only orders by rarity, which
needs no list of "known good" names and works the same on any platform.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.core.opensearch import get_memory_index, get_opensearch_client
from app.services.memory.artifact_indexing import _aggregatable_field

MAX_VALUES = 10000


@dataclass(frozen=True)
class StackSpec:
    document_type: str
    field: str
    # Optional field shown next to each value and usable as a filter.
    group_field: str | None = None


STACK_SPECS: dict[str, StackSpec] = {
    # Modules by full path: the same DLL name from an unusual folder is a separate value.
    "modules": StackSpec("memory_process_module", "path"),
    # Handles by object name (unnamed handles are not stacked), with their object type.
    "handles": StackSpec("memory_handle", "object_name", group_field="object_type"),
}


def stack_family(
    case_id: str,
    *,
    family: str,
    run_id: str,
    evidence_id: str,
    q: str | None = None,
    group_value: str | None = None,
    order: str = "rare",
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    spec = STACK_SPECS[family]
    client = get_opensearch_client()
    index = get_memory_index(case_id)
    value_field = _aggregatable_field(client, index, spec.field)
    group_field = _aggregatable_field(client, index, spec.group_field) if spec.group_field else None
    name_field = _aggregatable_field(client, index, "process_name")

    base: list[dict[str, Any]] = [
        {"term": {"document_type": spec.document_type}},
        {"term": {"scan_run_id.keyword": run_id}},
        {"term": {"evidence_id": evidence_id}},
    ]
    filters = list(base)
    if q and q.strip():
        needle = q.strip().replace("*", "").replace("?", "")
        filters.append({"wildcard": {value_field: {"value": f"*{needle}*", "case_insensitive": True}}})
    if group_field and group_value:
        filters.append({"term": {group_field: group_value}})

    value_aggs: dict[str, Any] = {
        "processes": {"cardinality": {"field": "pid"}},
        "names": {"terms": {"field": name_field, "size": 5}},
    }
    if group_field:
        value_aggs["groups"] = {"terms": {"field": group_field, "size": 3}}
    body = {
        "size": 0,
        "timeout": "15s",
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "values": {"terms": {"field": value_field, "size": MAX_VALUES}, "aggs": value_aggs},
            "run_processes": {"global": {}, "aggs": {"scoped": {"filter": {"bool": {"filter": base}}, "aggs": {"n": {"cardinality": {"field": "pid"}}}}}},
        },
    }
    response = client.search(index=index, body=body, params={"ignore_unavailable": "true"})
    aggs = response.get("aggregations") or {}
    values_agg = aggs.get("values") or {}
    rows: list[dict[str, Any]] = []
    for bucket in values_agg.get("buckets") or []:
        value = str(bucket.get("key") or "")
        if not value.strip():
            continue
        rows.append({
            "value": value,
            "group": next((str(b["key"]) for b in (bucket.get("groups") or {}).get("buckets") or []), None),
            "occurrences": int(bucket.get("doc_count") or 0),
            "process_count": int((bucket.get("processes") or {}).get("value") or 0),
            "process_names": [str(b["key"]) for b in (bucket.get("names") or {}).get("buckets") or []],
        })
    if order == "common":
        rows.sort(key=lambda r: (-r["process_count"], -r["occurrences"], r["value"].lower()))
    else:
        rows.sort(key=lambda r: (r["process_count"], r["occurrences"], r["value"].lower()))
    page = max(int(page), 1)
    page_size = min(max(int(page_size), 1), 200)
    start = (page - 1) * page_size
    return {
        "family": family,
        "field": spec.field,
        "group_field": spec.group_field,
        "order": "common" if order == "common" else "rare",
        "total_values": len(rows),
        # More distinct values than one aggregation returns: the rarest are
        # still complete only when this is false.
        "truncated": bool(values_agg.get("sum_other_doc_count")),
        "run_process_count": int((((aggs.get("run_processes") or {}).get("scoped") or {}).get("n") or {}).get("value") or 0),
        "page": page,
        "page_size": page_size,
        "items": rows[start:start + page_size],
    }
