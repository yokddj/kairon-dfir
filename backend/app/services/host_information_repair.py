"""Rebuild the derived Host Information layers for a case already ingested.

Host Facts and Host User Facts are derived during ingest. When a case was
ingested by a version that missed them on some path, or an artifact failed its
aggregation, re-ingesting the evidence is a heavy and lossy way to recover:
it costs hours and changes ingest timestamps in the forensic record.

This rebuilds them from the events already indexed instead. It reads only what
OpenSearch has, runs the same extractors ingest uses, and writes through the
same observation services, so a repaired case is indistinguishable from one
that was ingested correctly. It never touches the events themselves.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.core.database import utc_now
from app.core.opensearch import get_events_index, get_opensearch_client, index_exists
from app.ingest.host_facts_extraction import extract_host_fact_documents
from app.ingest.host_user_extraction import extract_host_user_documents
from app.models.case_host import CaseHost
from app.models.evidence import Evidence
from app.services.host_facts import create_host_fact_observations
from app.services.host_users import create_host_user_fact_observations

logger = logging.getLogger(__name__)

# Read in pages: a case can hold millions of events, and only a handful of
# artifact families ever produce Host Information.
SCAN_PAGE_SIZE = 1000
SCAN_MAX_DOCUMENTS = 200_000


def rebuild_host_information(db: Session, case_id: str) -> dict[str, Any]:
    """Re-derive Host Facts and Host User Facts for every host in the case."""
    client = get_opensearch_client()
    index = get_events_index(case_id)
    if not index_exists(client, index):
        return {
            "case_id": case_id,
            "scanned_events": 0,
            "host_facts_created": 0,
            "host_user_facts_created": 0,
            "warnings": ["This case has no indexed events, so there is nothing to rebuild."],
        }

    evidence_hosts = {
        row.id: row.host_id
        for row in db.query(Evidence).filter(Evidence.case_id == case_id).all()
    }
    fallback_host_id = _sole_host_id(db, case_id)

    scanned = 0
    host_facts_created = 0
    host_user_facts_created = 0
    warnings: list[str] = []

    for batch in _scan_candidate_documents(client, index, case_id):
        scanned += len(batch)
        for (evidence_id, artifact_id), documents in _group_by_artifact(batch).items():
            host_id = evidence_hosts.get(evidence_id) or fallback_host_id
            observed_at = utc_now()

            fact_documents = extract_host_fact_documents(documents)
            if fact_documents:
                created, warning = _apply(
                    db,
                    create_host_fact_observations,
                    case_id=case_id,
                    evidence_id=evidence_id,
                    artifact_id=artifact_id,
                    host_id=host_id,
                    observed_at=observed_at,
                    documents=fact_documents,
                )
                host_facts_created += created
                if warning:
                    warnings.append(f"host_facts: {warning}")

            user_documents = extract_host_user_documents(documents)
            if user_documents:
                created, warning = _apply(
                    db,
                    create_host_user_fact_observations,
                    case_id=case_id,
                    evidence_id=evidence_id,
                    artifact_id=artifact_id,
                    host_id=host_id,
                    observed_at=observed_at,
                    documents=user_documents,
                )
                host_user_facts_created += created
                if warning:
                    warnings.append(f"host_user_facts: {warning}")

        if scanned >= SCAN_MAX_DOCUMENTS:
            warnings.append(
                f"Stopped after {SCAN_MAX_DOCUMENTS} events to bound the scan; "
                "run it again if this case is unusually large."
            )
            break

    return {
        "case_id": case_id,
        "scanned_events": scanned,
        "host_facts_created": host_facts_created,
        "host_user_facts_created": host_user_facts_created,
        "warnings": warnings,
    }


def _sole_host_id(db: Session, case_id: str) -> str | None:
    """When a case has exactly one host, evidence with no host still belongs to it."""
    hosts = db.query(CaseHost).filter(CaseHost.case_id == case_id).limit(2).all()
    return hosts[0].id if len(hosts) == 1 else None


def _scan_candidate_documents(client, index: str, case_id: str):
    """Page through the events that could carry Host Information.

    The extractors decide what qualifies, so this filter only has to be
    generous, not exact: it exists to avoid reading millions of unrelated
    events, not to duplicate the extractors' own judgement.
    """
    query = {
        "bool": {
            "filter": [{"term": {"case_id": case_id}}],
            "should": [
                {"exists": {"field": "host_user_fact"}},
                {"exists": {"field": "host_fact"}},
                {"terms": {"artifact.type": sorted(CANDIDATE_ARTIFACT_TYPES)}},
            ],
            "minimum_should_match": 1,
        }
    }
    search_after = None
    while True:
        body: dict[str, Any] = {
            "size": SCAN_PAGE_SIZE,
            "query": query,
            "sort": [{"_id": "asc"}],
        }
        if search_after:
            body["search_after"] = search_after
        try:
            result = client.search(index=index, body=body, params={"ignore_unavailable": "true"})
        except Exception as exc:  # noqa: BLE001
            logger.warning("Host Information rebuild scan failed: %s", exc)
            return
        hits = result.get("hits", {}).get("hits", []) or []
        if not hits:
            return
        yield [dict(hit.get("_source") or {}) for hit in hits]
        search_after = hits[-1].get("sort")
        if not search_after:
            return


# Families that have ever produced a Host Fact or Host User Fact. Being listed
# here only means "worth reading"; the extractors still decide what qualifies.
CANDIDATE_ARTIFACT_TYPES = {
    "windows_sam_identity",
    "windows_profile_list",
    "windows_os_info",
    "windows_timezone",
    "windows_network",
    "registry_event",
    "linux_identity",
    "linux_os_info",
    "linux_timezone",
    "linux_network",
    "linux_lastlog",
    "linux_shell_history",
    "linux_auth",
}


def _group_by_artifact(documents: list[dict]) -> dict[tuple[str, str], list[dict]]:
    """Extractors run per artifact, exactly as they do during ingest."""
    grouped: dict[tuple[str, str], list[dict]] = {}
    for document in documents:
        key = (
            str(document.get("evidence_id") or ""),
            str((document.get("artifact") or {}).get("id") or document.get("artifact_id") or ""),
        )
        grouped.setdefault(key, []).append(document)
    return grouped


def _apply(db: Session, create, **kwargs) -> tuple[int, str | None]:
    """Write one artifact's observations, tolerating a failure of any one.

    Each artifact is committed on its own so a single bad document cannot
    discard the work already done for the rest of the case.
    """
    try:
        # Both services return the rows they created, not a count.
        created = create(db, **kwargs)
        db.commit()
        return len(created or []), None
    except Exception as exc:  # noqa: BLE001 - one artifact must not sink the rebuild
        db.rollback()
        logger.warning("Host Information rebuild failed for one artifact: %s", exc)
        return 0, str(exc)
