"""Host Identity Backfill Service.

Idempotent backfill that propagates Evidence.host_id to OpenSearch documents
and findings metadata without creating fake assignment history or rerunning parsers.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.opensearch import get_opensearch_client, get_events_index
from app.models.evidence import Evidence
from app.models.finding import Finding

logger = logging.getLogger(__name__)

BACKFILL_BATCH_SIZE = 1000
BACKFILL_MAX_DOCS = 100000


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def backfill_evidence_host_id(
    db: Session,
    *,
    evidence_id: str,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Backfill OpenSearch documents for one Evidence with its host_id."""
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        return {"error": "evidence_not_found", "evidence_id": evidence_id}

    host_id = str(evidence.host_id or "").strip()
    if not host_id:
        return {
            "evidence_id": evidence_id,
            "host_id": None,
            "status": "skipped",
            "reason": "evidence_unassigned",
            "documents_updated": 0,
            "documents_skipped": 0,
            "findings_updated": 0,
        }

    from app.models.case_host import CaseHost

    host = db.get(CaseHost, host_id)
    canonical = host.canonical_name if host else ""
    assignment_status = evidence.host_assignment_status or "confirmed"

    index = get_events_index(evidence.case_id)
    client = get_opensearch_client(timeout_seconds=120)

    # Count documents
    try:
        count_result = client.count(
            index=index,
            body={"query": {"term": {"evidence_id": evidence_id}}},
        )
        total_docs = int(count_result.get("count") or 0)
    except Exception:
        total_docs = 0

    if total_docs == 0:
        return {
            "evidence_id": evidence_id,
            "host_id": host_id,
            "status": "skipped",
            "reason": "no_documents",
            "documents_updated": 0,
            "documents_skipped": 0,
            "findings_updated": 0,
        }

    if dry_run:
        return {
            "evidence_id": evidence_id,
            "host_id": host_id,
            "canonical": canonical,
            "status": "dry_run",
            "would_update": total_docs,
            "documents_matched": total_docs,
            "documents_updated": 0,
            "documents_skipped": 0,
            "findings_updated": 0,
        }

    # Update documents via update_by_query
    script = {
        "source": """
            ctx._source.host.evidence_host_id = params.evidence_host_id;
            if (params.canonical != null && params.canonical != '') {
                ctx._source.host.canonical = params.canonical;
            }
            ctx._source.host.assignment_status = params.assignment_status;
        """,
        "params": {
            "evidence_host_id": host_id,
            "canonical": canonical,
            "assignment_status": assignment_status,
        },
        "lang": "painless",
    }

    try:
        result = client.update_by_query(
            index=index,
            body={
                "query": {"term": {"evidence_id": evidence_id}},
                "script": script,
            },
            conflicts="proceed",
            wait_for_completion=False,
            refresh=False,
        )
        task_id = result.get("task")
        updated = 0
        version_conflicts = 0
        if not task_id:
            updated = int(result.get("updated") or 0)
            version_conflicts = int(result.get("version_conflicts") or 0)
    except Exception as exc:
        logger.exception("backfill update_by_query failed for evidence %s", evidence_id)
        return {
            "evidence_id": evidence_id,
            "host_id": host_id,
            "status": "failed",
            "error": str(exc),
            "documents_matched": total_docs,
            "documents_updated": 0,
            "documents_skipped": total_docs,
            "findings_updated": 0,
        }

    # Update findings for this evidence
    findings_updated = 0
    try:
        findings = db.query(Finding).filter(Finding.case_id == evidence.case_id).all()
        for finding in findings:
            if not hasattr(finding, "primary_host_id") or not hasattr(finding, "related_host_ids") or not hasattr(finding, "host_scope"):
                continue
            evidence_ids = _finding_evidence_ids(finding)
            if evidence_id not in evidence_ids:
                continue
            if not finding.primary_host_id:
                finding.primary_host_id = host_id
            related = list(finding.related_host_ids or [])
            if host_id not in related:
                related.append(host_id)
            finding.related_host_ids = related
            unique_hosts = set(related)
            if len(unique_hosts) == 1:
                finding.host_scope = "single_host"
            elif len(unique_hosts) > 1:
                finding.host_scope = "cross_host"
            else:
                finding.host_scope = "single_host"
            findings_updated += 1
        if findings_updated > 0:
            db.commit()
    except Exception:
        db.rollback()
        logger.exception("backfill findings update failed for evidence %s", evidence_id)

    return {
        "evidence_id": evidence_id,
        "host_id": host_id,
        "canonical": canonical,
        "status": "submitted" if task_id else "completed",
        "task_id": task_id,
        "documents_matched": total_docs,
        "documents_updated": updated,
        "documents_skipped": total_docs - updated + version_conflicts,
        "version_conflicts": version_conflicts,
        "findings_updated": findings_updated,
    }


def backfill_case_hosts(
    db: Session,
    *,
    case_id: str,
    evidence_id: str | None = None,
    dry_run: bool = False,
    batch_size: int = BACKFILL_BATCH_SIZE,
) -> dict[str, Any]:
    """Backfill all evidences in a case (or one evidence) with host identity."""
    query = db.query(Evidence).filter(Evidence.case_id == case_id)
    if evidence_id:
        query = query.filter(Evidence.id == evidence_id)

    evidences = query.all()
    results: list[dict[str, Any]] = []
    total_updated = 0
    total_matched = 0
    total_skipped = 0
    total_findings_updated = 0
    errors: list[str] = []

    for evidence in evidences:
        try:
            result = backfill_evidence_host_id(db, evidence_id=evidence.id, dry_run=dry_run)
            results.append(result)
            if result.get("status") == "completed":
                total_updated += int(result.get("documents_updated") or 0)
                total_matched += int(result.get("documents_matched") or 0)
                total_skipped += int(result.get("documents_skipped") or 0)
                total_findings_updated += int(result.get("findings_updated") or 0)
            elif result.get("status") == "skipped" or result.get("status") == "dry_run":
                total_matched += int(result.get("documents_matched") or int(result.get("would_update") or 0))
            elif result.get("status") == "failed":
                errors.append(str(result.get("error") or f"backfill failed for {evidence.id}"))
        except Exception as exc:
            errors.append(str(exc))

    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "dry_run": dry_run,
        "evidences_scanned": len(evidences),
        "evidences_assigned": sum(1 for e in evidences if e.host_id),
        "evidences_unassigned": sum(1 for e in evidences if not e.host_id),
        "documents_matched": total_matched,
        "documents_updated": total_updated,
        "documents_skipped": total_skipped,
        "findings_updated": total_findings_updated,
        "errors": errors,
        "results": results,
    }


def _finding_evidence_ids(finding: Finding) -> set[str]:
    """Extract evidence IDs from a finding's events or related data."""
    evidence_ids: set[str] = set()
    if finding.evidence_id:
        evidence_ids.add(finding.evidence_id)
    events = getattr(finding, "events", None) or []
    if isinstance(events, list):
        for event in events:
            if isinstance(event, dict):
                eid = str(event.get("evidence_id") or "")
                if eid:
                    evidence_ids.add(eid)
    return evidence_ids


def get_host_document_counts(
    db: Session,
    *,
    case_id: str | None = None,
) -> dict[str, Any]:
    """Get counts of documents with/without host.evidence_host_id."""
    counts: dict[str, Any] = {"by_case": {}}

    cases_to_check = [case_id] if case_id else []
    if not cases_to_check:
        from app.models.case import Case
        cases = db.query(Case).all()
        cases_to_check = [c.id for c in cases]

    client = get_opensearch_client()

    for cid in cases_to_check:
        index = get_events_index(cid)
        case_counts: dict[str, Any] = {"total": 0, "with_host_id": 0, "without_host_id": 0}
        try:
            total = client.count(index=index, body={"query": {"match_all": {}}})
            case_counts["total"] = int(total.get("count") or 0)
        except Exception:
            pass
        try:
            with_host = client.count(
                index=index,
                body={"query": {"exists": {"field": "host.evidence_host_id"}}},
            )
            case_counts["with_host_id"] = int(with_host.get("count") or 0)
        except Exception:
            pass
        try:
            without_host = client.count(
                index=index,
                body={"query": {"bool": {"must_not": [{"exists": {"field": "host.evidence_host_id"}}]}}},
            )
            case_counts["without_host_id"] = int(without_host.get("count") or 0)
        except Exception:
            pass
        counts["by_case"][cid] = case_counts

    return counts
