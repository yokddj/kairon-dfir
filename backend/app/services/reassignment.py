import logging
from typing import Any

from sqlalchemy.orm import Session

from app.core.opensearch import get_events_index, get_opensearch_client, search_documents
from app.models.case_host import CaseHost
from app.models.evidence import Evidence

logger = logging.getLogger(__name__)


def execute_host_reassignment(
    db: Session,
    evidence_id: str,
    new_host_id: str,
    *,
    actor: str = "analyst",
    reason: str | None = None,
    confidence: str = "high",
) -> dict[str, Any]:
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise ValueError("Evidence not found")
    old_host_id = evidence.host_id
    from app.services.host_resolution import assign_evidence_host

    evidence = assign_evidence_host(
        db,
        evidence,
        host_id=new_host_id,
        actor_user_id=None,
        actor=actor,
        reason=reason or "Analyst reassigned",
        method="analyst_reassigned",
        confidence=confidence,
    )

    return {
        "evidence_id": evidence.id,
        "host_id": evidence.host_id,
        "status": "confirmed",
        "previous_host_id": old_host_id,
        "new_host_id": new_host_id,
    }


def backfill_evidence_documents(db: Session, evidence_id: str) -> dict[str, Any]:
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        return {"updated": 0, "error": "evidence not found"}

    client = get_opensearch_client()
    index = get_events_index(evidence.case_id)
    if not index:
        return {"updated": 0, "error": "no index"}

    host_id = evidence.host_id
    host_name = None
    if host_id:
        host_row = db.get(CaseHost, host_id)
        if host_row:
            host_name = host_row.canonical_name

    script_parts = []
    script_params = {}
    if host_id:
        script_parts.append("ctx._source.host.evidence_host_id = params.evidence_host_id")
        script_params["evidence_host_id"] = host_id
    else:
        script_parts.append("if (ctx._source.host != null) { ctx._source.host.remove('evidence_host_id') }")
    if host_name:
        script_parts.append("ctx._source.host.canonical = params.canonical")
        script_params["canonical"] = host_name
    elif not host_id:
        script_parts.append("if (ctx._source.host != null) { ctx._source.host.remove('canonical') }")
    script_parts.append(
        "ctx._source.host.assignment_status = params.assignment_status"
    )
    script_params["assignment_status"] = evidence.host_assignment_status or "confirmed"

    if not script_parts:
        return {"updated": 0, "reason": "no host assignment"}

    script_source = "; ".join(script_parts)

    try:
        response = client.update_by_query(
            index=index,
            body={
                "query": {"term": {"evidence_id": evidence_id}},
                "script": {
                    "source": script_source,
                    "params": script_params,
                },
            },
            conflicts="proceed",
            refresh=True,
        )
        updated = int(response.get("updated", 0))
        return {"updated": updated, "total": response.get("total", 0)}
    except Exception:
        logger.exception("update_by_query failed for evidence %s", evidence_id)
        return {"updated": 0, "error": "update_by_query failed"}


def invalidate_host_caches(evidence_id: str, host_id: str) -> None:
    logger.info(
        "cache invalidation needed for evidence_id=%s host_id=%s",
        evidence_id,
        host_id,
    )
