"""Idempotent materialization and querying of the new memory artifacts.

The 5 artifact profiles (network, modules, handles, kernel, suspicious)
each write a *separate* document type into the same
``dfir-memory-{case_id}`` index.  All writes are idempotent: documents
are upserted by their ``document_id`` field, so re-running the same
plugin against the same run produces zero duplicates and preserves the
last successful payload.

Mappings
--------
Mappings are added on first index creation.  The function is safe to
call multiple times: OpenSearch will not overwrite a mapping that
already exists.  If a future deployment adds a new property, the
index can be reindexed with the updated mapping (operator action).
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

from app.core.opensearch import get_memory_index, get_opensearch_client


logger = logging.getLogger(__name__)


# Extra fields that are NOT in the base mapping but are commonly added
# by the canonical entity normalizer; we keep the mapping permissive
# with ``dynamic: true`` but declare the most common fields.
ARTIFACT_MAPPING = {
    "mappings": {
        "dynamic": True,
        "properties": {
            "case_id": {"type": "keyword"},
            "evidence_id": {"type": "keyword"},
            "scan_run_id": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
            "plugin_run_id": {"type": "keyword"},
            "document_type": {"type": "keyword"},
            "document_id": {"type": "keyword"},
            "normalization_version": {"type": "keyword"},
            "confidence": {"type": "keyword"},
            "source_plugin": {"type": "keyword"},
            "source_plugins": {"type": "keyword"},
            "provenance": {
                "properties": {
                    "case_id": {"type": "keyword"},
                    "evidence_id": {"type": "keyword"},
                    "scan_run_id": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                    "plugin_run_id": {"type": "keyword"},
                    "source_plugin": {"type": "keyword"},
                    "normalization_version": {"type": "keyword"},
                }
            },
            # Network
            "protocol": {"type": "keyword"},
            "local_address": {"type": "ip", "ignore_malformed": True},
            "local_port": {"type": "integer"},
            "remote_address": {"type": "ip", "ignore_malformed": True},
            "remote_port": {"type": "integer"},
            "state": {"type": "keyword"},
            "pid": {"type": "integer"},
            "process_name": {"type": "keyword", "fields": {"text": {"type": "text"}}},
            "process_entity_id": {"type": "keyword"},
            "create_time": {"type": "date", "ignore_malformed": True},
            "unresolved_process_reference": {"type": "boolean"},
            # Modules
            "module_name": {"type": "keyword", "fields": {"text": {"type": "text"}}},
            "path": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
            "base_address": {"type": "long"},
            "size": {"type": "long"},
            "load_state": {"type": "keyword"},
            "in_load": {"type": "boolean"},
            "in_init": {"type": "boolean"},
            "in_memory": {"type": "boolean"},
            "findings": {"type": "keyword"},
            # Handles
            "handle_value": {"type": "long"},
            "object_type": {"type": "keyword"},
            "object_name": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
            "granted_access": {"type": "long"},
            # Kernel
            "driver_name": {"type": "keyword", "fields": {"text": {"type": "text"}}},
            "service_key": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
            "start_address": {"type": "long"},
            "visibility": {"properties": {
                "listed": {"type": "boolean"},
                "scan_only": {"type": "boolean"},
                "terminated": {"type": "boolean"},
                "unknown": {"type": "boolean"},
            }},
            # Suspicious
            "end_address": {"type": "keyword"},
            "protection": {"type": "keyword"},
            "tag": {"type": "keyword"},
            "commit_charge": {"type": "long"},
            "private_memory": {"type": "boolean"},
            "hexdump_preview_bounded": {"type": "text", "index": False},
            "disassembly_preview_bounded": {"type": "text", "index": False},
            "review_status": {"type": "keyword"},
        },
    }
}


def ensure_memory_index(case_id: str) -> str:
    """Ensure the memory index for the case exists.  Idempotent."""
    client = get_opensearch_client()
    index = get_memory_index(case_id)
    if not client.indices.exists(index=index):
        client.indices.create(index=index, body=ARTIFACT_MAPPING)
    return index


def index_artifact_documents(case_id: str, documents: list[dict[str, Any]]) -> dict[str, Any]:
    """Idempotent bulk index.  Re-running with the same ``document_id``
    overwrites the existing document (preserves the latest
    normalization result and prevents duplicates).
    """
    if not documents:
        return {"indexed": 0}
    index = ensure_memory_index(case_id)
    client = get_opensearch_client()
    body: list[dict[str, Any]] = []
    for doc in documents:
        doc_id = doc.get("document_id")
        if not doc_id:
            continue
        body.append({"index": {"_index": index, "_id": doc_id}})
        body.append(doc)
    response = client.bulk(body=body, refresh=False)
    if response.get("errors"):
        # Log and count; never raise for partial failures so a single
        # bad document does not poison the entire run.
        for item in response.get("items", []):
            result = item.get("index", {})
            if result.get("error"):
                logger.warning("artifact index error: %s", result.get("error"))
    client.indices.refresh(index=index)
    indexed = sum(1 for item in response.get("items", []) if not item.get("index", {}).get("error"))
    return {"indexed": indexed, "errors": len(response.get("items", [])) - indexed}


# ---------------------------------------------------------------------------
# Search helpers
# ---------------------------------------------------------------------------


def search_artifact_documents(
    case_id: str,
    *,
    document_type: str,
    run_id: str | None = None,
    page: int = 1,
    page_size: int = 50,
    filters: dict[str, Any] | None = None,
    sort: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    page_size = min(max(int(page_size), 1), 200)
    page = max(int(page), 1)
    query_filters: list[dict[str, Any]] = [{"term": {"document_type": document_type}}]
    if run_id:
        # scan_run_id is mapped as text with a keyword sub-field; use the
        # keyword form for an exact match.
        query_filters.append({"term": {"scan_run_id.keyword": run_id}})
    if filters:
        for key, value in filters.items():
            if value is None:
                continue
            if isinstance(value, bool):
                query_filters.append({"term": {f"{key}": value}})
            elif isinstance(value, (int, float)):
                query_filters.append({"term": {f"{key}": value}})
            elif isinstance(value, str) and value.strip():
                # IP-shaped values use the exact field; everything else
                # is a keyword/text match.
                query_filters.append({"term": {f"{key}.keyword": value}})
    body = {
        "query": {"bool": {"filter": query_filters}},
        "from": (page - 1) * page_size,
        "size": page_size,
        "timeout": "5s",
        "sort": sort or [{"pid": {"order": "asc", "missing": "_last"}}, {"document_id": {"order": "asc"}}],
    }
    client = get_opensearch_client()
    response = client.search(index=get_memory_index(case_id), body=body, params={"ignore_unavailable": "true"})
    hits = response.get("hits", {})
    total = hits.get("total", {})
    total_value = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
    items = [hit.get("_source", {}) | {"document_id": hit.get("_id")} for hit in hits.get("hits", [])]
    return {
        "items": items,
        "total": total_value,
        "page": page,
        "page_size": page_size,
        "selected_run": run_id,
        "normalization_version": "memory_artifact_canonical_v1",
        "document_type": document_type,
    }


def count_artifact_documents(
    case_id: str,
    *,
    document_type: str,
    run_id: str | None = None,
    extra_filters: list[dict[str, Any]] | None = None,
) -> int:
    client = get_opensearch_client()
    filters: list[dict[str, Any]] = [{"term": {"document_type": document_type}}]
    if run_id:
        # scan_run_id is mapped as text with a keyword sub-field; use the
        # keyword form for an exact match.
        filters.append({"term": {"scan_run_id.keyword": run_id}})
    if extra_filters:
        filters.extend(extra_filters)
    body = {"query": {"bool": {"filter": filters}}}
    response = client.count(index=get_memory_index(case_id), body=body, params={"ignore_unavailable": "true"})
    return int(response.get("count", 0))


def get_artifact_document(case_id: str, document_id: str) -> dict[str, Any] | None:
    client = get_opensearch_client()
    try:
        response = client.get(index=get_memory_index(case_id), id=document_id)
    except Exception:  # noqa: BLE001
        return None
    source = response.get("_source")
    if isinstance(source, dict):
        source["document_id"] = response.get("_id")
        return source
    return None


def link_process_entities(
    case_id: str,
    *,
    scan_run_id: str,
    document_type: str,
    pid_field: str = "pid",
) -> int:
    """Resolve ``process_entity_id`` for every artifact document of
    ``document_type`` in the given run, using the canonical
    ``memory_process_entity`` index.  The link is in-place (upsert
    by ``document_id``) and only updates documents whose PID resolves
    to a single canonical entity.  When PID reuse is ambiguous the
    artifact keeps ``process_entity_id=null`` and the
    ``unresolved_process_reference`` flag stays ``true``.
    """
    client = get_opensearch_client()
    index = get_memory_index(case_id)
    body = {
        "size": 10000,
        "query": {"bool": {"filter": [
            {"term": {"document_type": document_type}},
            {"term": {"scan_run_id.keyword": scan_run_id}},
        ]}},
    }
    response = client.search(index=index, body=body, params={"ignore_unavailable": "true"})
    hits = response.get("hits", {}).get("hits", [])
    if not hits:
        return 0
    pids = sorted({int(h.get("_source", {}).get(pid_field)) for h in hits if h.get("_source", {}).get(pid_field) is not None})
    if not pids:
        return 0
    ent_body = {
        "size": 10000,
        "query": {"bool": {"filter": [
            {"term": {"document_type": "memory_process_entity"}},
            {"term": {"scan_run_id.keyword": scan_run_id}},
            {"terms": {"process.pid": pids}},
        ]}},
        "_source": ["process_entity_id", "process.pid", "process.create_time"],
    }
    ent_resp = client.search(index=index, body=ent_body, params={"ignore_unavailable": "true"})
    pid_to_entities: dict[int, list[dict[str, Any]]] = {}
    for hit in ent_resp.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        ent_id = src.get("process_entity_id")
        proc = src.get("process", {})
        pid = proc.get("pid")
        if ent_id is None or pid is None:
            continue
        pid_to_entities.setdefault(int(pid), []).append({
            "process_entity_id": ent_id,
            "create_time": proc.get("create_time"),
        })
    bulk: list[dict[str, Any]] = []
    linked = 0
    for hit in hits:
        src = hit.get("_source", {})
        doc_id = hit.get("_id")
        if not doc_id:
            continue
        pid = src.get(pid_field)
        candidates = pid_to_entities.get(int(pid), []) if pid is not None else []
        if len(candidates) == 1:
            ent_id = candidates[0]["process_entity_id"]
            new_src = dict(src)
            new_src["process_entity_id"] = ent_id
            new_src["unresolved_process_reference"] = False
            bulk.append({"index": {"_index": index, "_id": doc_id}})
            bulk.append(new_src)
            linked += 1
        else:
            new_src = dict(src)
            new_src["unresolved_process_reference"] = True
            bulk.append({"index": {"_index": index, "_id": doc_id}})
            bulk.append(new_src)
    if bulk:
        client.bulk(body=bulk, refresh=False)
        client.indices.refresh(index=index)
    return linked
