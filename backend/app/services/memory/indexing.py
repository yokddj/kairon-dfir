from __future__ import annotations

import logging
from typing import Any

from app.core.opensearch import get_memory_index, get_opensearch_client
from app.services.memory.pids import normalize_pid


logger = logging.getLogger(__name__)


MEMORY_SYSTEM_INFO_MAPPING = {
    "mappings": {
        "dynamic": True,
        "properties": {
            "case_id": {"type": "keyword"},
            "evidence_id": {"type": "keyword"},
            "memory_run_id": {"type": "keyword"},
            "memory_plugin_run_id": {"type": "keyword"},
            "source_layer": {"type": "keyword"},
            "memory_artifact_type": {"type": "keyword"},
            "backend": {"type": "keyword"},
            "plugin": {"type": "keyword"},
            "plugins": {"type": "keyword"},
            "document_id": {"type": "keyword"},
            "process": {
                "properties": {
                    "pid": {"type": "integer"},
                    "ppid": {"type": "integer"},
                    "name": {"type": "keyword", "fields": {"text": {"type": "text"}}},
                    "command_line": {"type": "text"},
                    "create_time": {"type": "date", "ignore_malformed": True},
                    "exit_time": {"type": "date", "ignore_malformed": True},
                }
            },
            "visibility": {"properties": {"pslist": {"type": "boolean"}, "psscan": {"type": "boolean"}, "pstree": {"type": "boolean"}}},
            "state": {"properties": {"active_candidate": {"type": "boolean"}, "terminated_candidate": {"type": "boolean"}, "hidden_candidate": {"type": "boolean"}}},
            "parent_pid": {"type": "integer"},
            "child_pid": {"type": "integer"},
            "os": {
                "properties": {
                    "family": {"type": "keyword"},
                    "kernel_version": {"type": "keyword"},
                    "machine_type": {"type": "keyword"},
                }
            },
            "memory": {"properties": {"system_time": {"type": "date", "ignore_malformed": True}}},
            "parsed_at": {"type": "date"},
        },
    }
}


def ensure_memory_index(case_id: str) -> str:
    client = get_opensearch_client()
    index = get_memory_index(case_id)
    if not client.indices.exists(index=index):
        client.indices.create(index=index, body=MEMORY_SYSTEM_INFO_MAPPING)
    return index


def index_memory_system_info(case_id: str, document: dict[str, Any]) -> dict[str, Any]:
    index = ensure_memory_index(case_id)
    client = get_opensearch_client()
    response = client.index(index=index, id=f"{document['memory_plugin_run_id']}:memory_system_info", body=document, refresh=True)
    logger.info("memory system info indexed", extra={"case_id": case_id, "run_id": document.get("memory_run_id"), "index": index})
    return {"index": index, "id": response.get("_id"), "result": response.get("result")}


def index_memory_documents(case_id: str, documents: list[dict[str, Any]]) -> dict[str, Any]:
    index = ensure_memory_index(case_id)
    client = get_opensearch_client()
    indexed = 0
    errors = 0
    for document in documents:
        sanitized = sanitize_memory_process_document(document)
        doc_id = sanitized.get("document_id")
        try:
            response = client.index(index=index, id=doc_id, body=sanitized, refresh=False)
        except Exception as exc:  # noqa: BLE001
            errors += 1
            logger.warning("memory process index error: id=%s error=%s", doc_id, exc)
            continue
        if response.get("result") in {"created", "updated"}:
            indexed += 1
    if documents:
        client.indices.refresh(index=index)
    return {"index": index, "indexed": indexed, "errors": errors}


def sanitize_memory_process_document(document: dict[str, Any]) -> dict[str, Any]:
    """Last-mile guard before writing PID fields to the memory index."""
    safe = dict(document)
    process = safe.get("process")
    if isinstance(process, dict):
        process = dict(process)
        process["pid"] = normalize_pid(process.get("pid"))
        process["ppid"] = normalize_pid(process.get("ppid"))
        safe["process"] = process
    if "parent_pid" in safe:
        safe["parent_pid"] = normalize_pid(safe.get("parent_pid"))
    if "child_pid" in safe:
        safe["child_pid"] = normalize_pid(safe.get("child_pid"))
    return safe


def search_memory_processes(case_id: str, *, run_id: str | None = None, evidence_id: str | None = None, pid: int | None = None, ppid: int | None = None, process_name: str | None = None, source_plugin: str | None = None, present_in_pslist: bool | None = None, present_in_psscan: bool | None = None, has_command_line: bool | None = None, active: bool | None = None, page: int = 1, page_size: int = 50) -> dict[str, Any]:
    page_size = min(max(int(page_size), 1), 200)
    page = max(int(page), 1)
    filters: list[dict[str, Any]] = [{"term": {"memory_artifact_type": "memory_process"}}]
    if run_id:
        filters.append({"term": {"memory_run_id": run_id}})
    if evidence_id:
        filters.append({"term": {"evidence_id": evidence_id}})
    if pid is not None:
        filters.append({"term": {"process.pid": pid}})
    if ppid is not None:
        filters.append({"term": {"process.ppid": ppid}})
    if source_plugin:
        filters.append({"term": {"plugins": source_plugin}})
    if present_in_pslist is not None:
        filters.append({"term": {"visibility.pslist": present_in_pslist}})
    if present_in_psscan is not None:
        filters.append({"term": {"visibility.psscan": present_in_psscan}})
    if active is not None:
        filters.append({"term": {"state.active_candidate": active}})
    if has_command_line is True:
        filters.append({"exists": {"field": "process.command_line"}})
    if has_command_line is False:
        filters.append({"bool": {"must_not": [{"exists": {"field": "process.command_line"}}]}})
    must: list[dict[str, Any]] = []
    if process_name:
        safe_name = str(process_name).strip()[:128]
        if safe_name:
            must.append({"match_phrase_prefix": {"process.name.text": safe_name}})
    body = {
        "query": {"bool": {"filter": filters, "must": must}},
        "sort": [{"process.pid": {"order": "asc", "missing": "_last"}}, {"process.create_time": {"order": "asc", "missing": "_last"}}, {"document_id": {"order": "asc"}}],
        "from": (page - 1) * page_size,
        "size": page_size,
        "timeout": "5s",
    }
    client = get_opensearch_client()
    response = client.search(index=get_memory_index(case_id), body=body, params={"ignore_unavailable": "true"})
    hits = response.get("hits", {})
    total = hits.get("total", {})
    total_value = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
    return {"items": [hit.get("_source", {}) | {"document_id": hit.get("_id")} for hit in hits.get("hits", [])], "total": total_value, "page": page, "page_size": page_size}


def search_memory_edges(case_id: str, *, run_id: str) -> list[dict[str, Any]]:
    body = {"query": {"bool": {"filter": [{"term": {"memory_artifact_type": "memory_process_edge"}}, {"term": {"memory_run_id": run_id}}]}}, "size": 10000, "sort": [{"parent_pid": "asc"}, {"child_pid": "asc"}], "timeout": "5s"}
    client = get_opensearch_client()
    response = client.search(index=get_memory_index(case_id), body=body, params={"ignore_unavailable": "true"})
    return [hit.get("_source", {}) | {"document_id": hit.get("_id")} for hit in response.get("hits", {}).get("hits", [])]


def get_memory_document(case_id: str, document_id: str) -> dict[str, Any] | None:
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
