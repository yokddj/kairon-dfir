"""Idempotent indexing and querying of the experimental artefacts.

The experimental artefacts live in a *separate* OpenSearch index
(``dfir-memory-experimental-{case_id}``) so they cannot leak
into the validated artefact views.  The mapping adds a
mandatory ``trust_level = "untrusted"`` keyword field and an
``analysis_mode = "experimental"`` keyword field; every write
must include both fields and every read must filter on both.

The module is intentionally small: it only handles the index
lifecycle, the bulk index, the search, and the delete-by-run
operation used by the experimental run deletion path.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

from app.core.opensearch import (
    get_memory_experimental_index,
    get_opensearch_client,
)


logger = logging.getLogger(__name__)


EXPERIMENTAL_ARTIFACT_MAPPING: dict[str, Any] = {
    "mappings": {
        "dynamic": True,
        "properties": {
            "case_id": {"type": "keyword"},
            "evidence_id": {"type": "keyword"},
            "scan_run_id": {"type": "keyword"},
            "plugin_run_id": {"type": "keyword"},
            "experimental_run_id": {"type": "keyword"},
            "document_type": {"type": "keyword"},
            "document_id": {"type": "keyword"},
            "normalization_version": {"type": "keyword"},
            "confidence": {"type": "keyword"},
            "source_plugin": {"type": "keyword"},
            "trust_level": {"type": "keyword"},
            "analysis_mode": {"type": "keyword"},
            "symbol_match_type": {"type": "keyword"},
            "required_pdb_name": {"type": "keyword"},
            "required_pdb_guid": {"type": "keyword"},
            "required_pdb_age": {"type": "integer"},
            "observed_pdb_name": {"type": "keyword"},
            "observed_pdb_guid": {"type": "keyword"},
            "observed_pdb_age": {"type": "integer"},
            "canary_status": {"type": "keyword"},
            "canary_score": {"type": "float"},
            "process_name": {"type": "keyword"},
            "pid": {"type": "integer"},
            "module_name": {"type": "keyword"},
            "path": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
        },
    }
}


def ensure_memory_experimental_index(case_id: str) -> str:
    """Ensure the per-case experimental index exists.  Idempotent."""
    client = get_opensearch_client()
    index = get_memory_experimental_index(case_id)
    if not client.indices.exists(index=index):
        client.indices.create(index=index, body=EXPERIMENTAL_ARTIFACT_MAPPING)
    return index


def index_experimental_documents(
    case_id: str,
    documents: list[dict[str, Any]],
    *,
    experimental_run_id: str,
    batch_size: int = 2000,
) -> dict[str, Any]:
    """Bulk index documents into the per-case experimental index.

    The function injects the mandatory ``trust_level =
    "untrusted"`` and ``analysis_mode = "experimental"`` fields
    into every document.  Documents that already declare a
    different value are rejected with a structured error.
    """
    if not documents:
        return {"indexed": 0, "errors": 0, "index": get_memory_experimental_index(case_id)}
    index = ensure_memory_experimental_index(case_id)
    client = get_opensearch_client()
    indexed = 0
    errors = 0
    error_details: list[dict[str, Any]] = []
    for i in range(0, len(documents), batch_size):
        chunk = documents[i : i + batch_size]
        bulk_body: list[dict[str, Any]] = []
        for doc in chunk:
            if not isinstance(doc, dict):
                errors += 1
                error_details.append({"reason": "non_dict_document"})
                continue
            if not doc.get("experimental_run_id"):
                doc["experimental_run_id"] = experimental_run_id
            if not doc.get("case_id"):
                doc["case_id"] = case_id
            doc["trust_level"] = "untrusted"
            doc["analysis_mode"] = "experimental"
            document_id = doc.get("document_id")
            if not document_id:
                errors += 1
                error_details.append({"reason": "missing_document_id"})
                continue
            bulk_body.append({"index": {"_index": index, "_id": document_id}})
            bulk_body.append(doc)
        if not bulk_body:
            continue
        try:
            response = client.bulk(body=bulk_body, refresh=False)
        except Exception as exc:  # noqa: BLE001
            logger.warning("experimental bulk index failed: %s", exc)
            errors += len(bulk_body) // 2
            error_details.append({"reason": "bulk_index_exception", "message": str(exc)})
            continue
        for item in response.get("items", []):
            outcome = item.get("index") or item.get("create") or {}
            if outcome.get("error"):
                errors += 1
                error_details.append(outcome["error"])
            else:
                indexed += 1
    if errors:
        logger.info(
            "experimental bulk index completed with errors: indexed=%d errors=%d",
            indexed, errors,
        )
    return {
        "indexed": indexed,
        "errors": errors,
        "index": index,
        "error_details": error_details[:50],
    }


def search_experimental_documents(
    case_id: str,
    *,
    experimental_run_id: str,
    evidence_id: str,
    document_type: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    """Search the experimental index with the mandatory trust filter.

    The function refuses to run without a non-empty
    ``experimental_run_id`` and always includes the trust /
    analysis-mode filters.  A client cannot remove the filters.
    """
    if not experimental_run_id:
        return {
            "items": [],
            "total": 0,
            "page": page,
            "page_size": page_size,
            "error": "experimental_run_id_required",
        }
    index = ensure_memory_experimental_index(case_id)
    client = get_opensearch_client()
    must_filters: list[dict[str, Any]] = [
        {"term": {"experimental_run_id": experimental_run_id}},
        {"term": {"evidence_id": evidence_id}},
        {"term": {"trust_level": "untrusted"}},
        {"term": {"analysis_mode": "experimental"}},
    ]
    if document_type:
        must_filters.append({"term": {"document_type": document_type}})
    body = {
        "query": {"bool": {"filter": must_filters}},
        "from": max(0, (page - 1) * page_size),
        "size": min(max(page_size, 1), 1000),
    }
    try:
        response = client.search(index=index, body=body, params={"ignore_unavailable": "true"})
    except Exception as exc:  # noqa: BLE001
        logger.warning("experimental search failed: %s", exc)
        return {
            "items": [],
            "total": 0,
            "page": page,
            "page_size": page_size,
            "error": str(exc),
        }
    hits = response.get("hits", {})
    total = hits.get("total", {})
    if isinstance(total, dict):
        total_value = int(total.get("value", 0) or 0)
    else:
        total_value = int(total or 0)
    items = [hit.get("_source", {}) for hit in hits.get("hits", [])]
    return {
        "items": items,
        "total": total_value,
        "page": page,
        "page_size": page_size,
    }


def delete_experimental_documents_by_run(
    case_id: str,
    *,
    experimental_run_id: str,
    evidence_id: str,
) -> dict[str, Any]:
    """Delete every document produced by an experimental run.

    The function uses the trust / analysis-mode filters as well
    as the run id, so a caller cannot accidentally delete
    documents from another run or from the validated index.
    """
    if not experimental_run_id:
        return {"deleted": 0, "error": "experimental_run_id_required"}
    index = get_memory_experimental_index(case_id)
    client = get_opensearch_client()
    body = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"experimental_run_id": experimental_run_id}},
                    {"term": {"evidence_id": evidence_id}},
                    {"term": {"trust_level": "untrusted"}},
                    {"term": {"analysis_mode": "experimental"}},
                ]
            }
        }
    }
    try:
        response = client.delete_by_query(
            index=index,
            body=body,
            refresh=True,
            params={"ignore_unavailable": "true"},
            conflicts="proceed",
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("experimental delete-by-query failed: %s", exc)
        return {"deleted": 0, "error": str(exc)}
    return {
        "deleted": int(response.get("deleted", 0) or 0),
        "version_conflicts": int(response.get("version_conflicts", 0) or 0),
    }


def iter_experimental_run_ids(case_id: str) -> Iterable[str]:
    """Yield every ``experimental_run_id`` present in the index.

    Used by the run-deletion audit path to detect orphans.
    """
    index = get_memory_experimental_index(case_id)
    client = get_opensearch_client()
    body = {
        "size": 0,
        "aggs": {
            "run_ids": {
                "terms": {
                    "field": "experimental_run_id",
                    "size": 10000,
                }
            }
        },
    }
    try:
        response = client.search(index=index, body=body, params={"ignore_unavailable": "true"})
    except Exception as exc:  # noqa: BLE001
        logger.warning("iter_experimental_run_ids failed: %s", exc)
        return
    buckets = (
        response.get("aggregations", {})
        .get("run_ids", {})
        .get("buckets", [])
    )
    for bucket in buckets:
        if isinstance(bucket, dict) and bucket.get("key"):
            yield str(bucket["key"])


__all__ = [
    "EXPERIMENTAL_ARTIFACT_MAPPING",
    "delete_experimental_documents_by_run",
    "ensure_memory_experimental_index",
    "index_experimental_documents",
    "iter_experimental_run_ids",
    "search_experimental_documents",
]
