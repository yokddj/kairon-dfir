"""Per-host artefact coverage.

An investigation can only answer questions about the evidence it actually
indexed, and the most damaging gaps are the silent ones: an evidence that
ingests cleanly, reports no error, and simply contains nothing for a whole
artefact family. Nothing in the product contrasted hosts against each other, so
a case where three hosts had ~200k filesystem entries and the fourth had zero
looked entirely healthy -- until an analyst noticed by hand that a question
could not be answered.

This module compares each host in a case against the families its peers have,
so "this host has no filesystem at all" becomes a visible fact rather than
something to be discovered late.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.opensearch import get_events_index, get_opensearch_client, index_exists
from app.services.host_identity import get_case_hosts


# Families a Windows triage is normally expected to yield. Kept deliberately
# small and high level: the point is to spot a whole missing capability, not to
# audit every parser. Each entry maps a display name to the artifact.type values
# that satisfy it.
EXPECTED_ARTIFACT_FAMILIES: dict[str, tuple[str, ...]] = {
    "Filesystem (MFT)": ("mft", "usn"),
    "Event logs": ("windows_event", "evtx"),
    "Process execution": ("process", "prefetch", "amcache", "shimcache"),
    "PowerShell": ("powershell",),
    "Registry": ("registry", "registry_event", "registry_persistence"),
    "Persistence": ("registry_persistence", "scheduled_task", "service"),
    "User activity": ("lnk", "jumplist", "userassist", "recentdocs"),
    "Browser": ("browser",),
}

# Families whose absence is worth flagging loudly rather than noting. A host
# with no filesystem or no event logs cannot answer most questions asked of it.
CRITICAL_FAMILIES = ("Filesystem (MFT)", "Event logs")


def _artifact_type_counts_by_host(case_id: str) -> dict[str, dict[str, int]]:
    """artifact.type doc counts per host, straight from the events index."""
    client = get_opensearch_client()
    index = get_events_index(case_id)
    if not index_exists(client, index):
        return {}
    body = {
        "size": 0,
        "query": {"bool": {"filter": [{"term": {"case_id": case_id}}]}},
        "aggs": {
            "hosts": {
                "terms": {"field": "host.name", "size": 200},
                "aggs": {"types": {"terms": {"field": "artifact.type", "size": 100}}},
            }
        },
    }
    try:
        result = client.search(index=index, body=body, params={"ignore_unavailable": "true"})
    except Exception:  # noqa: BLE001 - coverage must never break the page it annotates
        return {}
    counts: dict[str, dict[str, int]] = {}
    for host_bucket in result.get("aggregations", {}).get("hosts", {}).get("buckets", []):
        host_name = str(host_bucket.get("key") or "").strip()
        if not host_name:
            continue
        counts[host_name.lower()] = {
            str(type_bucket.get("key")): int(type_bucket.get("doc_count") or 0)
            for type_bucket in host_bucket.get("types", {}).get("buckets", [])
        }
    return counts


def build_case_host_coverage(db: Session, case_id: str) -> dict[str, Any]:
    """Coverage per host, plus the gaps worth acting on."""
    counts_by_host = _artifact_type_counts_by_host(case_id)
    hosts = get_case_hosts(db, case_id)

    rows: list[dict[str, Any]] = []
    # A family is only "expected" when at least one host in the case has it:
    # that keeps the signal relative to the collection actually performed
    # instead of complaining about, say, Browser on a server nobody browsed on.
    families_present_somewhere: set[str] = set()
    per_host_families: dict[str, dict[str, int]] = {}

    for host in hosts:
        names = {str(name).strip().lower() for name in (host.get("all_names") or []) if str(name).strip()}
        names.add(str(host.get("canonical_name") or "").strip().lower())
        merged: dict[str, int] = {}
        for name in names:
            for artifact_type, count in (counts_by_host.get(name) or {}).items():
                merged[artifact_type] = merged.get(artifact_type, 0) + count
        family_counts: dict[str, int] = {}
        for family, artifact_types in EXPECTED_ARTIFACT_FAMILIES.items():
            total = sum(merged.get(artifact_type, 0) for artifact_type in artifact_types)
            family_counts[family] = total
            if total > 0:
                families_present_somewhere.add(family)
        per_host_families[str(host.get("id"))] = family_counts

    for host in hosts:
        host_id = str(host.get("id"))
        family_counts = per_host_families.get(host_id, {})
        missing = [
            family
            for family, total in family_counts.items()
            if total == 0 and family in families_present_somewhere
        ]
        rows.append(
            {
                "host_id": host_id,
                "host": host.get("display_name") or host.get("canonical_name"),
                "event_count": host.get("event_count"),
                "families": family_counts,
                "missing_families": missing,
                "missing_critical_families": [family for family in missing if family in CRITICAL_FAMILIES],
            }
        )

    rows.sort(key=lambda row: str(row.get("host") or "").lower())
    warnings = [
        f"{row['host']} has no {family} data while other hosts in this case do. "
        "Questions that depend on it cannot be answered for this host."
        for row in rows
        for family in row["missing_critical_families"]
    ]
    return {
        "case_id": case_id,
        "expected_families": [family for family in EXPECTED_ARTIFACT_FAMILIES if family in families_present_somewhere],
        "hosts": rows,
        "warnings": warnings,
    }
