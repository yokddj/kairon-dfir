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

# Telemetry: the live records an investigation leans on, identified by the
# normalized event.type so they read the same on every platform (Sysmon and
# Security 4688 on Windows, auditd on Linux...). A host can have event logs and
# still lack one of these -- a workstation without Sysmon or process auditing
# has no record of which processes ran, only traces (prefetch, memory).
EXPECTED_TELEMETRY: dict[str, tuple[str, ...]] = {
    "Process creation log": ("sysmon_process_created", "process_start", "process_created", "execve", "process_exec"),
    "Network connection log": ("sysmon_network_connection", "network_connection", "network_connection_allowed", "network_connection_blocked"),
    "Logon records": ("logon_success", "logon_failed", "explicit_credentials_logon", "login_success", "login_failure", "session_open", "authentication_failure"),
    "Script and command logging": ("script_block", "pipeline_execution", "command_observed", "powershell_script_block_observed"),
}

# Records of an event log being cleared. Windows: Security 1102 and System 104
# from the Eventlog provider; other platforms add their normalized types here.
LOG_CLEARED_EVENT_TYPES = ("audit_log_cleared", "log_cleared")

# Families whose absence is worth flagging loudly rather than noting. A host
# with no filesystem or no event logs cannot answer most questions asked of it,
# and one without process creation records cannot say what ran or who ran it.
CRITICAL_FAMILIES = ("Filesystem (MFT)", "Event logs", "Process creation log", "Logon records")


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
                "aggs": {
                    "types": {"terms": {"field": "artifact.type", "size": 100}},
                    "event_types": {
                        "terms": {"field": "event.type", "size": 300},
                        "aggs": {"first": {"min": {"field": "@timestamp"}}},
                    },
                    "log_clears": {
                        "filter": {"bool": {"should": [
                            {"terms": {"event.type": list(LOG_CLEARED_EVENT_TYPES)}},
                            {"bool": {"filter": [
                                {"terms": {"windows.event_id": [1102, 104]}},
                                {"term": {"windows.provider": "Microsoft-Windows-Eventlog"}},
                            ]}},
                        ], "minimum_should_match": 1}},
                        "aggs": {"events": {"top_hits": {"size": 50, "sort": [{"@timestamp": {"order": "asc"}}], "_source": ["@timestamp", "windows.channel", "windows.event_data.SubjectUserName", "windows.event_data.SubjectDomainName", "windows.event_data.Channel", "user.name"]}}},
                    },
                },
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
        # Event types share the counts map under an "event:" prefix so a
        # family can be defined by either kind of signal; "first:" keeps the
        # earliest record of each, for the telemetry window.
        for type_bucket in host_bucket.get("event_types", {}).get("buckets", []):
            counts[host_name.lower()][f"event:{type_bucket.get('key')}"] = int(type_bucket.get("doc_count") or 0)
            first = (type_bucket.get("first") or {}).get("value_as_string")
            if first:
                counts[host_name.lower()][f"first:{type_bucket.get('key')}"] = first  # type: ignore[assignment]
        clears = [hit.get("_source") or {} for hit in host_bucket.get("log_clears", {}).get("events", {}).get("hits", {}).get("hits", [])]
        if clears:
            counts[host_name.lower()]["log_clears"] = clears  # type: ignore[assignment]
    return counts


def _log_clear_summary(source: dict[str, Any]) -> dict[str, Any]:
    windows = source.get("windows") or {}
    event_data = windows.get("event_data") or {}
    user = event_data.get("SubjectUserName")
    domain = event_data.get("SubjectDomainName")
    return {
        "timestamp": str(source.get("@timestamp") or "")[:19].replace("T", " "),
        "user": f"{domain}\\{user}" if user and domain else (user or (source.get("user") or {}).get("name")),
        "log": event_data.get("Channel") or windows.get("channel"),
    }


def _expected_families() -> dict[str, tuple[str, ...]]:
    return {**EXPECTED_ARTIFACT_FAMILIES, **{name: tuple(f"event:{value}" for value in values) for name, values in EXPECTED_TELEMETRY.items()}}


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
    per_host_windows: dict[str, tuple[dict[str, str], list[dict[str, Any]]]] = {}

    for host in hosts:
        names = {str(name).strip().lower() for name in (host.get("all_names") or []) if str(name).strip()}
        names.add(str(host.get("canonical_name") or "").strip().lower())
        merged: dict[str, int] = {}
        for name in names:
            for artifact_type, count in (counts_by_host.get(name) or {}).items():
                if isinstance(count, int):
                    merged[artifact_type] = merged.get(artifact_type, 0) + count
        family_counts: dict[str, int] = {}
        first_seen: dict[str, str] = {}
        log_clears: list[dict[str, Any]] = []
        for name in names:
            host_counts = counts_by_host.get(name) or {}
            log_clears.extend(host_counts.get("log_clears") or [])  # type: ignore[arg-type]
            for family, values in EXPECTED_TELEMETRY.items():
                for value in values:
                    first = host_counts.get(f"first:{value}")
                    if isinstance(first, str) and (family not in first_seen or first < first_seen[family]):
                        first_seen[family] = first
        per_host_windows[str(host.get("id"))] = (first_seen, sorted(log_clears, key=lambda item: str(item.get("@timestamp") or "")))
        for family, artifact_types in _expected_families().items():
            total = sum(merged.get(artifact_type, 0) for artifact_type in artifact_types if isinstance(merged.get(artifact_type, 0), int))
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
                "telemetry_first_seen": per_host_windows.get(host_id, ({}, []))[0],
                "log_clears": [_log_clear_summary(item) for item in per_host_windows.get(host_id, ({}, []))[1]],
            }
        )

    rows.sort(key=lambda row: str(row.get("host") or "").lower())
    warnings = [
        f"{row['host']} has no {family} data while other hosts in this case do. "
        "Questions that depend on it cannot be answered for this host."
        for row in rows
        for family in row["missing_critical_families"]
    ]
    for row in rows:
        clears = row["log_clears"]
        if not clears:
            continue
        first, last = clears[0], clears[-1]
        who = sorted({item["user"] for item in clears if item.get("user")})
        when = first["timestamp"] if first["timestamp"] == last["timestamp"] else f"{first['timestamp']} to {last['timestamp']}"
        process_from = row["telemetry_first_seen"].get("Process creation log")
        warnings.append(
            f"{row['host']}: event logs were cleared {when}"
            + (f" by {', '.join(who)}" if who else "")
            + f" ({len(clears)} records). Activity on this host before then is missing from those logs"
            + (f"; its process creation records begin {process_from[:19].replace('T', ' ')}." if process_from else ".")
        )
    return {
        "case_id": case_id,
        "expected_families": [family for family in _expected_families() if family in families_present_somewhere],
        "hosts": rows,
        "warnings": warnings,
    }
