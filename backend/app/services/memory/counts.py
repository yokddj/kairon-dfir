"""Single source of truth for per-family artifact counts.

Every component that needs a per-family count (landing, catalogue,
Overview, active-result endpoint, run-all plan, Runs badges) MUST go
through :func:`get_memory_family_count`.  No caller is allowed to
issue its own ad-hoc query against the OpenSearch index or the
``MemoryArtifactSummary`` table.

Counting rules:

* Counts are scoped to a single ``case_id`` and ``evidence_id``.
* Counts are filtered by a single ``document_type``.
* Counts are NOT combined across document types.
* Counts are NOT combined across runs; the caller passes the
  ``active_run_id`` that was resolved by the per-family active
  result resolver.  When ``active_run_id`` is None, the function
  returns 0 — the caller is responsible for picking the right run.
* The function tolerates mappings that do not have all fields
  indexed (no sorting on missing fields, no queries that require
  dynamic mappings).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from opensearchpy.exceptions import NotFoundError, RequestError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Family → document_type mapping.
#
# This is the authoritative list.  ``drivers`` and ``kernel_modules``
# are intentionally NOT combined: ``memory_driver`` documents come
# from windows.driverscan and ``memory_kernel_module`` documents come
# from windows.modules / windows.ldrmodules.
# ---------------------------------------------------------------------------
FAMILY_TO_DOCUMENT_TYPE: dict[str, str] = {
    "system_info": "memory_system_info",
    "processes": "memory_process",
    "modules": "memory_process_module",
    "handles": "memory_handle",
    "kernel_modules": "memory_kernel_module",
    "drivers": "memory_driver",
    "suspicious_regions": "memory_suspicious_region",
    "network": "memory_network_connection",
    "raw_observations": "memory_process_observation",
}


# Ordered list used by the Overview and the catalogue.
FAMILY_ORDER: tuple[str, ...] = (
    "system_info",
    "processes",
    "modules",
    "handles",
    "kernel_modules",
    "drivers",
    "suspicious_regions",
    "network",
    "raw_observations",
)


FAMILY_TITLE: dict[str, str] = {
    "system_info": "System metadata",
    "processes": "Processes",
    "modules": "Modules and DLLs",
    "handles": "Handles",
    "kernel_modules": "Kernel modules",
    "drivers": "Drivers",
    "suspicious_regions": "Suspicious memory regions",
    "network": "Network connections",
    "raw_observations": "Raw observations",
}


def _opensearch_client():
    # Lazy import to avoid a hard dependency on the search stack at
    # module import time (the service is also used by the API which
    # has the dependency available).
    from app.core.opensearch import get_opensearch_client

    return get_opensearch_client()


def _memory_index(case_id: str) -> str:
    from app.core.opensearch import get_memory_index

    return get_memory_index(case_id)


def get_memory_family_count(
    *,
    case_id: str,
    evidence_id: str,
    family: str,
    active_run_id: str | None,
    db=None,
) -> dict[str, Any]:
    """Return the per-family artifact count.

    Parameters
    ----------
    case_id
        The case that owns the evidence.
    evidence_id
        The evidence being analyzed.  The count is scoped to this
        evidence_id; cross-evidence state is never counted.
    family
        One of the keys in :data:`FAMILY_TO_DOCUMENT_TYPE`.  The
        function refuses to combine families; an invalid family
        raises ``ValueError``.
    active_run_id
        The run that the per-family active-result resolver selected.
        When None the count is 0 (the resolver has not found a
        successful run yet).
    db
        Optional SQLAlchemy session.  When provided, the function
        uses the ``MemoryArtifactSummary`` table as a fast local
        source when OpenSearch is unreachable.  When None, the
        function uses OpenSearch directly.

    Returns
    -------
    dict
        ``family``, ``document_type``, ``active_run_id``, ``total``,
        ``count_source`` ("opensearch" or "summary"), ``calculated_at``
        (UTC ISO 8601).
    """
    if family not in FAMILY_TO_DOCUMENT_TYPE:
        raise ValueError(f"Unknown memory family: {family!r}")
    document_type = FAMILY_TO_DOCUMENT_TYPE[family]
    if not active_run_id:
        return _empty_count(family, document_type, active_run_id, reason="no_active_run")

    # Fast path: ask OpenSearch.  The filter is fully scoped to
    # (case_id, evidence_id, scan_run_id, document_type); there is
    # no aggregation and no risky sort.
    try:
        client = _opensearch_client()
        body = {
            "query": {
                "bool": {
                    "filter": [
                        {"bool": {"should": [
                            {"term": {"document_type": document_type}},
                            {"term": {"memory_artifact_type": document_type}},
                        ], "minimum_should_match": 1}},
                        {"bool": {"should": [
                            {"term": {"scan_run_id.keyword": active_run_id}},
                            {"term": {"memory_run_id": active_run_id}},
                        ], "minimum_should_match": 1}},
                        {"term": {"evidence_id": evidence_id}},
                    ]
                }
            }
        }
        response = client.count(
            index=_memory_index(case_id),
            body=body,
            params={"ignore_unavailable": "true", "allow_no_indices": "true"},
        )
        total = int(response.get("count", 0))
        return {
            "family": family,
            "document_type": document_type,
            "active_run_id": active_run_id,
            "total": total,
            "count_source": "opensearch",
            "calculated_at": datetime.now(timezone.utc).isoformat() + "Z",
        }
    except (NotFoundError, RequestError) as exc:
        logger.warning(
            "memory family count from OpenSearch failed: case=%s evidence=%s family=%s run=%s: %s",
            case_id, evidence_id, family, active_run_id, exc,
        )
        if db is None:
            return _empty_count(family, document_type, active_run_id, reason="opensearch_error")
        return _summary_count(db, case_id, evidence_id, family, document_type, active_run_id)

    # If the index is unavailable (e.g. a fresh deployment without
    # OpenSearch writes yet), fall back to the DB summary.
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "memory family count fallback: case=%s evidence=%s family=%s run=%s: %s",
            case_id, evidence_id, family, active_run_id, exc,
        )
        if db is None:
            return _empty_count(family, document_type, active_run_id, reason="opensearch_error")
        return _summary_count(db, case_id, evidence_id, family, document_type, active_run_id)


def _summary_count(
    db,
    case_id: str,
    evidence_id: str,
    family: str,
    document_type: str,
    active_run_id: str,
) -> dict[str, Any]:
    from app.models.memory import MemoryArtifactSummary

    summary = (
        db.query(MemoryArtifactSummary)
        .filter(
            MemoryArtifactSummary.case_id == case_id,
            MemoryArtifactSummary.evidence_id == evidence_id,
            MemoryArtifactSummary.memory_run_id == active_run_id,
            MemoryArtifactSummary.memory_artifact_type == document_type,
        )
        .first()
    )
    total = int(summary.count) if summary is not None else 0
    return {
        "family": family,
        "document_type": document_type,
        "active_run_id": active_run_id,
        "total": total,
        "count_source": "summary",
        "calculated_at": datetime.now(timezone.utc).isoformat() + "Z",
    }


def _empty_count(
    family: str,
    document_type: str,
    active_run_id: str | None,
    *,
    reason: str,
) -> dict[str, Any]:
    return {
        "family": family,
        "document_type": document_type,
        "active_run_id": active_run_id,
        "total": 0,
        "count_source": reason,
        "calculated_at": datetime.now(timezone.utc).isoformat() + "Z",
    }


def list_family_counts(
    *,
    case_id: str,
    evidence_id: str,
    active_run_ids: dict[str, str | None],
) -> list[dict[str, Any]]:
    """Return the per-family counts for every family.

    ``active_run_ids`` maps family → active run id.  Families with
    a None active run id are returned with total=0 and the
    ``no_active_run`` count_source.
    """
    results: list[dict[str, Any]] = []
    for family in FAMILY_ORDER:
        results.append(
            get_memory_family_count(
                case_id=case_id,
                evidence_id=evidence_id,
                family=family,
                active_run_id=active_run_ids.get(family),
            )
        )
    return results


def resolve_active_run_ids(
    db: Any,
    *,
    case_id: str,
    evidence_id: str,
) -> dict[str, str | None]:
    """Resolve the active run id for every family.

    This is the single place that knows how to combine the
    active-result resolver with the per-family counting.  The result
    is a dict ``{family: active_run_id or None}``.
    """
    from app.services.memory.active_result import resolve_active_memory_result, list_families

    result: dict[str, str | None] = {}
    for family in list_families():
        resolved = resolve_active_memory_result(
            db, case_id=case_id, evidence_id=evidence_id, family=family,
        )
        active_run = resolved.get("active_run") or {}
        result[family] = active_run.get("id") if isinstance(active_run, dict) else None
    return result
