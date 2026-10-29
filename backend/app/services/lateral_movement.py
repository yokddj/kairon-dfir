"""Lateral movement: remote authentications between machines, on any platform.

One row per (target host, source address, account, method): when the source
first and last authenticated, how many attempts succeeded or failed. Built at
read time from the normalized authentication events every parser already
writes -- Windows logons (4624/4625: network, cleartext and Remote Desktop
logon types) and Linux logins (sshd and other PAM services, wtmp/btmp) -- so
it needs no re-ingest.

The source address is resolved to a case host through the observed host-local
addresses (app.services.host_network). An address seen on several hosts is
reported with every candidate, never resolved to one. The workstation name a
Windows logon reports is shown next to it; when it names a different case host
than the address does, the row says so -- a lead (renamed host, NAT, a tool
that sets its own name), not a conclusion.

Routine traffic (machine accounts, anonymous and built-in service logons) is
flagged with the reason so the view can hide it, never dropped.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.core.opensearch import get_events_index, get_opensearch_client, index_exists, is_index_queryable, resolve_aggregatable_field
from app.models.case_host import CaseHost
from app.services.host_network import get_host_network_observations

logger = logging.getLogger(__name__)

SUCCESS_TYPES = ("logon_success", "login_success")
FAILURE_TYPES = ("logon_failed", "login_failure", "invalid_user", "authentication_failure")
# Windows logon types that come from another machine: network (SMB, WinRM,
# PsExec, WMI...), network cleartext and Remote Desktop. Interactive,
# service, batch and unlock logons are local.
REMOTE_WINDOWS_LOGON_TYPES = ("3", "8", "10")
WINDOWS_LOGON_TYPE_LABELS = {
    "3": "Network logon (type 3: SMB, WinRM, PsExec, WMI...)",
    "8": "Network cleartext logon (type 8)",
    "10": "Remote Desktop (type 10)",
}
MAX_BUCKETS = 5000
MAX_HOSTS_FOR_INVENTORY = 200
_NOT_AN_ADDRESS = {"", "-", "::", "0.0.0.0", "127.0.0.1", "::1", "localhost", "local"}
_BUILTIN_ACCOUNTS = {"system", "local service", "network service", "anonymous logon", "anonymous", "-"}

_DIMENSIONS = (
    ("target", "host.name"),
    ("source_ip", "network.source_ip"),
    ("user", "user.name"),
    ("domain", "user.domain"),
    ("logon_type", "windows.logon_type"),
    ("auth_method", "linux.auth_method"),
    ("service", "linux.service"),
    ("event_type", "event.type"),
)


def routine_reason(user: str | None) -> str | None:
    """Why an authentication is routine background traffic, or None."""
    name = str(user or "").strip()
    lowered = name.lower()
    if not name or lowered in _BUILTIN_ACCOUNTS:
        return "built-in or anonymous account"
    if name.endswith("$"):
        return "machine account"
    if lowered.startswith(("dwm-", "umfd-")):
        return "built-in or anonymous account"
    return None


def method_label(logon_type: str | None, service: str | None, auth_method: str | None) -> str:
    if logon_type:
        return WINDOWS_LOGON_TYPE_LABELS.get(str(logon_type), f"Logon type {logon_type}")
    parts = [str(service or "").strip() or "remote login"]
    if auth_method:
        parts.append(f"({auth_method})")
    return " ".join(parts)


def _is_remote_address(value: str | None) -> bool:
    text = str(value or "").strip().lower()
    if text in _NOT_AN_ADDRESS:
        return False
    try:
        address = ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return True  # a hostname (wtmp records one when DNS resolved)
    return not (address.is_loopback or address.is_unspecified)


def _short(name: str | None) -> str:
    return str(name or "").strip().split(".")[0].upper()


def _host_inventory(db: Session, case_id: str) -> tuple[dict[str, list[str]], dict[str, str]]:
    """{address: [host names]} from observed host-local addresses, and
    {short name or alias: host name} for matching workstation names."""
    hosts = db.query(CaseHost).filter(CaseHost.case_id == case_id).limit(MAX_HOSTS_FOR_INVENTORY).all()
    by_address: dict[str, list[str]] = {}
    names: dict[str, str] = {}
    for host in hosts:
        display = host.display_name or host.canonical_name
        for alias in [host.canonical_name, host.display_name, *(getattr(alias, "alias", None) for alias in getattr(host, "aliases", None) or [])]:
            if alias:
                names.setdefault(_short(alias), display)
        try:
            addresses = get_host_network_observations(db, case_id=case_id, host_id=host.id)["addresses"]
        except Exception:  # noqa: BLE001 -- the view still lists the raw addresses
            logger.warning("lateral movement: addresses of host %s unavailable", host.id, exc_info=True)
            continue
        for entry in addresses:
            if entry.get("is_loopback") or entry.get("is_link_local") or entry.get("is_unspecified"):
                continue
            holders = by_address.setdefault(str(entry["ip"]), [])
            if display not in holders:
                holders.append(display)
    return by_address, names


def _composite_buckets(client, index: str, case_id: str) -> list[dict[str, Any]]:
    sources = []
    for name, field in _DIMENSIONS:
        resolved = resolve_aggregatable_field(client, index, field)
        if resolved:
            sources.append({name: {"terms": {"field": resolved, "missing_bucket": True}}})
    if not any("source_ip" in item for item in sources) or not any("target" in item for item in sources):
        return []
    logon_type_field = resolve_aggregatable_field(client, index, "windows.logon_type") or "windows.logon_type"
    query = {"bool": {"filter": [
        {"term": {"case_id": case_id}},
        {"terms": {"event.type": [*SUCCESS_TYPES, *FAILURE_TYPES]}},
        {"exists": {"field": "network.source_ip"}},
        {"bool": {"should": [
            {"terms": {logon_type_field: list(REMOTE_WINDOWS_LOGON_TYPES)}},
            {"bool": {"must_not": [{"exists": {"field": logon_type_field}}]}},
        ], "minimum_should_match": 1}},
    ]}}
    buckets: list[dict[str, Any]] = []
    after = None
    while len(buckets) < MAX_BUCKETS:
        composite: dict[str, Any] = {"size": 1000, "sources": sources}
        if after:
            composite["after"] = after
        body = {
            "size": 0,
            "query": query,
            "aggs": {"edges": {"composite": composite, "aggs": {
                "first_seen": {"min": {"field": "@timestamp"}},
                "last_seen": {"max": {"field": "@timestamp"}},
                "workstation": {"terms": {"field": resolve_aggregatable_field(client, index, "source.hostname") or "source.hostname", "size": 3}},
            }}},
        }
        response = client.search(index=index, body=body, params={"ignore_unavailable": "true"})
        aggregation = (response.get("aggregations") or {}).get("edges") or {}
        page = aggregation.get("buckets") or []
        buckets.extend(page)
        after = aggregation.get("after_key")
        if not after or not page:
            break
    return buckets


def _time(bucket: dict[str, Any], name: str) -> str | None:
    value = bucket.get(name) or {}
    return value.get("value_as_string") or None


def get_lateral_movement(db: Session, case_id: str) -> dict[str, Any]:
    client = get_opensearch_client()
    index = get_events_index(case_id)
    if not index_exists(client, index) or not is_index_queryable(client, index):
        return {"case_id": case_id, "edges": [], "addresses": [], "truncated": False}
    buckets = _composite_buckets(client, index, case_id)
    by_address, host_names = _host_inventory(db, case_id)

    edges: dict[tuple, dict[str, Any]] = {}
    for bucket in buckets:
        key = bucket.get("key") or {}
        source_ip = str(key.get("source_ip") or "").strip()
        target = str(key.get("target") or "").strip()
        if not target or not _is_remote_address(source_ip):
            continue
        source_hosts = list(by_address.get(source_ip, []))
        target_name = host_names.get(_short(target), target)
        if source_hosts == [target_name]:
            continue  # the host authenticating to itself through its own address
        user = str(key.get("user") or "").strip() or None
        logon_type = str(key.get("logon_type") or "").strip() or None
        method = method_label(logon_type, key.get("service"), key.get("auth_method"))
        edge_key = (target_name, source_ip, (user or "").lower(), method)
        edge = edges.setdefault(edge_key, {
            "target_host": target_name,
            "source_ip": source_ip,
            "source_hosts": source_hosts,
            "source_workstations": [],
            "user": user,
            "domain": str(key.get("domain") or "").strip() or None,
            "method": method,
            "logon_type": logon_type,
            "successes": 0,
            "failures": 0,
            "first_seen": None,
            "last_seen": None,
            "routine_reason": routine_reason(user),
        })
        count = int(bucket.get("doc_count") or 0)
        if key.get("event_type") in SUCCESS_TYPES:
            edge["successes"] += count
        else:
            edge["failures"] += count
        first, last = _time(bucket, "first_seen"), _time(bucket, "last_seen")
        edge["first_seen"] = min(filter(None, [edge["first_seen"], first]), default=None)
        edge["last_seen"] = max(filter(None, [edge["last_seen"], last]), default=None)
        for item in ((bucket.get("workstation") or {}).get("buckets") or []):
            name = str(item.get("key") or "").strip()
            if name and name != "-" and name not in edge["source_workstations"]:
                edge["source_workstations"].append(name)

    rows = []
    for edge in edges.values():
        # Remote Desktop logons record the target's own name as the workstation.
        edge["source_workstations"] = [name for name in edge["source_workstations"] if host_names.get(_short(name), name) != edge["target_host"]]
        named = sorted({host_names[_short(name)] for name in edge["source_workstations"] if _short(name) in host_names})
        edge["workstation_hosts"] = named
        # The logon names a machine other than the one holding the address.
        edge["workstation_mismatch"] = bool(edge["source_workstations"]) and bool(edge["source_hosts"]) and not set(named) & set(edge["source_hosts"])
        edge["source_ambiguous"] = len(edge["source_hosts"]) > 1
        rows.append(edge)
    rows.sort(key=lambda row: (row["first_seen"] or "", row["target_host"], row["source_ip"]))
    return {
        "case_id": case_id,
        "edges": rows,
        "addresses": [{"ip": ip, "hosts": hosts, "ambiguous": len(hosts) > 1} for ip, hosts in sorted(by_address.items())],
        "truncated": len(buckets) >= MAX_BUCKETS,
    }
