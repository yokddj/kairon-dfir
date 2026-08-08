"""Host Network Observations: real, host-local IP addresses observed in
already-indexed evidence.

This deliberately does NOT reuse app.services.host_facts / HostFact.
resolve_host_facts() collapses every observation of a fact_type down to
ONE preferred value, treating disagreement as a "conflict" to be resolved
by source priority -- correct for a fact_type like host.timezone (a host
genuinely has exactly one), but wrong for IP addresses: a host can
legitimately hold several simultaneous, equally real addresses (multiple
interfaces, DHCP renewals over time), and collapsing them to one
"preferred" address would silently discard the rest instead of
representing them.

It also does NOT introduce a new persisted table. Every source this module
reads is *already* fully indexed (OpenSearch events index, OpenSearch
memory index) with everything needed -- the raw value, its timestamp, and
its evidence/artifact provenance. A write-time extraction pipeline plus a
Postgres table would duplicate that data, need a migration, and need a
backfill job before it could show anything for evidence already ingested
before this feature existed. Computing the aggregation at read time avoids
all of that and always reflects the current index state.

Only sources where the underlying field's semantics are verified to mean
"this host's own address" are used. Anything whose semantics are
ambiguous or mean "the remote/peer address" is deliberately excluded, even
when it superficially looks like it could be a host IP -- seeing why is
the point of the comments on each source function below. Nothing here
invents gateway, DNS, MAC, or interface information; those are only ever
surfaced when a source function itself provides them.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone

from opensearchpy import OpenSearch
from sqlalchemy.orm import Session

from app.core.opensearch import (
    get_events_index,
    get_memory_index,
    get_opensearch_client,
    index_exists,
    is_index_queryable,
    resolve_aggregatable_field,
)
from app.models.case_host import CaseHost
from app.models.evidence import Evidence
from app.services.host_identity import expand_host_filter

logger = logging.getLogger(__name__)

# Source kinds, each corresponding to exactly one function below. Kept as
# constants so the API response and tests never depend on a string literal
# typed out twice.
SOURCE_SYSMON_NETWORK_CONNECTION = "sysmon_network_connection"
SOURCE_LINUX_DHCLIENT = "linux_dhclient_bound"
SOURCE_MEMORY_NETSCAN = "memory_windows_netscan"

SOURCE_LABELS: dict[str, str] = {
    SOURCE_SYSMON_NETWORK_CONNECTION: "Sysmon network connection (Event ID 3)",
    SOURCE_LINUX_DHCLIENT: "Linux dhclient DHCP lease log",
    SOURCE_MEMORY_NETSCAN: "Memory analysis (Volatility3 windows.netscan)",
}

# Sysmon Event ID 3's own schema: "Source" always identifies the endpoint
# owned by the process being monitored (i.e. this host), and "Destination"
# always identifies the remote peer -- regardless of the Initiated flag,
# which only records connection direction, not which side is local. See
# app.ingest.artifact_normalizers._apply_sysmon_event_normalization, which
# writes exactly this field only for genuine Sysmon-channel events (its own
# channel/provider guard keeps it from ever firing for a Security-channel
# event that happens to share the same numeric event_id).
_SYSMON_MAX_IPS = 200

# dhclient's own log line format for a successful lease
# ("bound to <ip>" / "bound to <ip> -- renewal in <n> seconds.") is
# unambiguous: it is dhclient itself asserting the address it just
# configured on a local interface, never a peer address. Matched with a
# search (not an anchored match) because some already-indexed lines carry
# a leading "MMM D HH:MM:SS dhclient: " syslog prefix that a carved/raw
# source did not strip. DHCPACK/DHCPOFFER/DHCPREQUEST lines are
# deliberately NOT parsed here: those name the DHCP *server*'s address (or,
# for DHCPREQUEST, an address whose "local vs. still-being-negotiated"
# status varies across dhclient versions), which is exactly the kind of
# ambiguous semantics this module refuses to guess about.
_DHCLIENT_BOUND_RE = re.compile(r"\bbound to (?P<ip>[0-9a-fA-F.:]+)")
_DHCLIENT_MAX_MESSAGES = 500

# windows.netscan (and windows.netstat) report local_address/remote_address
# as genuinely distinct, unambiguous fields -- local_address is the
# process's own endpoint on the imaged machine, remote_address is the peer.
# remote_address is never read here. 0.0.0.0 / "::" / "*" mean "listening
# on every interface", not a real assigned address, and are excluded
# outright rather than classified as "unspecified" -- they are not an
# observation of the host's own address at all.
_MEMORY_WILDCARDS = {"0.0.0.0", "::", "*", ""}
_MEMORY_MAX_ADDRESSES = 200


def classify_ip(value: str) -> dict | None:
    """Canonicalize and classify one IP literal, or None if not a valid IP.

    ``classification`` is a single, mutually-exclusive label matching the
    exact vocabulary the UI needs (private/public/loopback/link-local);
    the individual booleans are kept alongside for callers that want the
    less common categories (multicast/unspecified) too.
    """
    candidate = str(value or "").strip().rstrip(".")
    if not candidate:
        return None
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    is_loopback = addr.is_loopback
    is_link_local = addr.is_link_local
    is_multicast = addr.is_multicast
    is_unspecified = addr.is_unspecified
    # ipaddress.is_private is True for loopback/link-local too (both are
    # IANA "special use" ranges) -- classification below picks exactly one
    # label, in priority order, so a loopback address is never also shown
    # as "private".
    is_private = addr.is_private and not is_loopback and not is_link_local and not is_multicast and not is_unspecified
    if is_loopback:
        classification = "loopback"
    elif is_link_local:
        classification = "link-local"
    elif is_multicast:
        classification = "multicast"
    elif is_unspecified:
        classification = "unspecified"
    elif is_private:
        classification = "private"
    else:
        classification = "public"
    return {
        "ip": str(addr),
        "ip_version": 4 if addr.version == 4 else 6,
        "classification": classification,
        "is_private": is_private,
        "is_public": classification == "public",
        "is_loopback": is_loopback,
        "is_link_local": is_link_local,
        "is_multicast": is_multicast,
        "is_unspecified": is_unspecified,
    }


def _iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    text = str(value).strip()
    return text or None


def _host_scope_filter(db: Session, host: CaseHost) -> dict:
    """The exact host-scoping filter shape already used by Search/Artifact
    Views (app.api.routes_search) -- see expand_host_filter/CaseHost usage
    there. Reused as-is rather than re-derived, so this module can never
    silently drift out of sync with what "belongs to this host" means
    everywhere else in the product.
    """
    expanded = list(expand_host_filter(db, host.case_id, host.canonical_name))
    return {
        "bool": {
            "should": [
                {"term": {"host.evidence_host_id": host.id}},
                {"term": {"host.identity_id": host.id}},
                {"terms": {"host.canonical": expanded}},
                {"terms": {"host.name": expanded}},
            ],
            "minimum_should_match": 1,
        }
    }


def _query_sysmon_network(client: OpenSearch, index: str, *, case_id: str, host_filter: dict) -> list[dict]:
    if not index_exists(client, index) or not is_index_queryable(client, index):
        return []
    ip_field = resolve_aggregatable_field(client, index, "network.source_ip")
    if not ip_field:
        return []
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"case_id": case_id}},
                    {"term": {"event.action": SOURCE_SYSMON_NETWORK_CONNECTION}},
                    {"exists": {"field": ip_field}},
                    host_filter,
                ]
            }
        },
        "aggs": {
            "ips": {
                "terms": {"field": ip_field, "size": _SYSMON_MAX_IPS},
                "aggs": {
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "sample": {"top_hits": {"size": 1, "_source": ["evidence_id", "artifact_id"], "sort": [{"@timestamp": "desc"}]}},
                },
            }
        },
    }
    try:
        response = client.search(index=index, body=body)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Sysmon network observation query failed on %s: %s", index, exc)
        return []
    observations = []
    for bucket in response.get("aggregations", {}).get("ips", {}).get("buckets", []):
        hits = bucket.get("sample", {}).get("hits", {}).get("hits", [])
        sample_source = hits[0]["_source"] if hits else {}
        observations.append(
            {
                "raw_value": bucket.get("key"),
                "source_kind": SOURCE_SYSMON_NETWORK_CONNECTION,
                "observation_count": bucket.get("doc_count", 0),
                "first_seen": _iso(bucket.get("first_seen", {}).get("value_as_string") or bucket.get("first_seen", {}).get("value")),
                "last_seen": _iso(bucket.get("last_seen", {}).get("value_as_string") or bucket.get("last_seen", {}).get("value")),
                "evidence_id": sample_source.get("evidence_id"),
                "artifact_id": sample_source.get("artifact_id"),
            }
        )
    return observations


def _query_linux_dhclient(client: OpenSearch, index: str, *, case_id: str, host_filter: dict) -> list[dict]:
    if not index_exists(client, index) or not is_index_queryable(client, index):
        return []
    body = {
        "size": _DHCLIENT_MAX_MESSAGES,
        "sort": [{"@timestamp": "asc"}],
        "_source": ["@timestamp", "event.message", "evidence_id", "artifact_id"],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"case_id": case_id}},
                    {"term": {"artifact.type": "linux_syslog"}},
                    host_filter,
                ],
                "must": [{"match_phrase": {"event.message": "bound to"}}],
            }
        },
    }
    try:
        response = client.search(index=index, body=body)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Linux dhclient observation query failed on %s: %s", index, exc)
        return []
    grouped: dict[str, dict] = {}
    for hit in response.get("hits", {}).get("hits", []):
        source = hit.get("_source", {})
        message = str((source.get("event") or {}).get("message") or "")
        match = _DHCLIENT_BOUND_RE.search(message)
        if not match:
            continue
        classified = classify_ip(match.group("ip"))
        if not classified:
            continue
        ts = source.get("@timestamp")
        if not ts:
            # A message without its own timestamp cannot contribute to
            # first/last seen -- skipped rather than guessed at.
            continue
        entry = grouped.setdefault(
            classified["ip"],
            {"raw_value": classified["ip"], "source_kind": SOURCE_LINUX_DHCLIENT, "observation_count": 0, "first_seen": None, "last_seen": None, "evidence_id": None, "artifact_id": None},
        )
        entry["observation_count"] += 1
        if entry["first_seen"] is None or ts < entry["first_seen"]:
            entry["first_seen"] = ts
        if entry["last_seen"] is None or ts >= entry["last_seen"]:
            entry["last_seen"] = ts
            entry["evidence_id"] = source.get("evidence_id")
            entry["artifact_id"] = source.get("artifact_id")
    for entry in grouped.values():
        entry["first_seen"] = _iso(entry["first_seen"])
        entry["last_seen"] = _iso(entry["last_seen"])
    return list(grouped.values())


def _query_memory_netscan(client: OpenSearch, memory_index: str, *, evidence_map: dict[str, Evidence]) -> list[dict]:
    """windows.netscan local endpoints for evidence already known (via
    Evidence.host_id, resolved by the caller) to belong to this host.
    Never inspects host/canonical fields inside the memory index itself --
    those are not populated there; scoping instead happens through the
    evidence_id set the caller already resolved from Postgres, so a memory
    dump can only ever contribute observations to the host its own
    Evidence row is assigned to.
    """
    if not evidence_map or not index_exists(client, memory_index) or not is_index_queryable(client, memory_index):
        return []
    doc_type_field = resolve_aggregatable_field(client, memory_index, "document_type")
    address_field = resolve_aggregatable_field(client, memory_index, "local_address")
    if not doc_type_field or not address_field:
        return []
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {doc_type_field: "memory_network_connection"}},
                    {"terms": {"evidence_id": list(evidence_map.keys())}},
                ]
            }
        },
        "aggs": {
            "by_evidence": {
                "terms": {"field": "evidence_id", "size": len(evidence_map)},
                "aggs": {
                    "addresses": {
                        "terms": {"field": address_field, "size": _MEMORY_MAX_ADDRESSES},
                        "aggs": {"latest_create_time": {"max": {"field": "create_time"}}},
                    }
                },
            }
        },
    }
    try:
        response = client.search(index=memory_index, body=body)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Memory netscan observation query failed on %s: %s", memory_index, exc)
        return []
    observations = []
    for evidence_bucket in response.get("aggregations", {}).get("by_evidence", {}).get("buckets", []):
        evidence_id = evidence_bucket.get("key")
        evidence = evidence_map.get(evidence_id)
        # Volatility3 cannot recover a connection's original wall-clock
        # time for every record (closed/historical connections often carry
        # no timestamp of their own) -- the memory image's own acquisition
        # time is used as the single point-in-time this observation was
        # made, which is honest about what memory forensics can actually
        # assert here, never invented.
        fallback_seen = _iso(evidence.uploaded_at) if evidence else None
        for address_bucket in evidence_bucket.get("addresses", {}).get("buckets", []):
            raw_address = str(address_bucket.get("key") or "")
            if raw_address in _MEMORY_WILDCARDS:
                continue
            classified = classify_ip(raw_address)
            if not classified:
                continue
            create_time = address_bucket.get("latest_create_time", {}).get("value_as_string")
            seen_at = _iso(create_time) or fallback_seen
            observations.append(
                {
                    "raw_value": classified["ip"],
                    "source_kind": SOURCE_MEMORY_NETSCAN,
                    "observation_count": address_bucket.get("doc_count", 0),
                    "first_seen": seen_at,
                    "last_seen": seen_at,
                    "evidence_id": evidence_id,
                    "artifact_id": None,
                }
            )
    return observations


def _min_ts(a: str | None, b: str | None) -> str | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if a < b else b


def _max_ts(a: str | None, b: str | None) -> str | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if a > b else b


def get_host_network_observations(db: Session, *, case_id: str, host_id: str) -> dict:
    """Real, host-local IP addresses observed for one host, merged across
    every validated source, most-recently-seen first.

    Returns {"case_id", "host_id", "addresses": [...]}. Each address entry
    merges every source that reported it (never collapsed to one
    "preferred" value -- see the module docstring) and keeps each source's
    own first_seen/last_seen/observation_count/evidence_id intact under
    ``sources`` so the UI can show or expand full provenance.
    """
    host = db.get(CaseHost, host_id)
    if not host or host.case_id != case_id:
        return {"case_id": case_id, "host_id": host_id, "addresses": []}

    client = get_opensearch_client()
    events_index = get_events_index(case_id)
    memory_index = get_memory_index(case_id)
    host_filter = _host_scope_filter(db, host)

    evidence_rows = db.query(Evidence).filter(Evidence.host_id == host_id).all()
    evidence_map = {evidence.id: evidence for evidence in evidence_rows}

    raw_observations: list[dict] = []
    raw_observations.extend(_query_sysmon_network(client, events_index, case_id=case_id, host_filter=host_filter))
    raw_observations.extend(_query_linux_dhclient(client, events_index, case_id=case_id, host_filter=host_filter))
    raw_observations.extend(_query_memory_netscan(client, memory_index, evidence_map=evidence_map))

    merged: dict[str, dict] = {}
    for observation in raw_observations:
        classified = classify_ip(observation["raw_value"])
        if not classified:
            continue
        key = classified["ip"]
        entry = merged.setdefault(
            key,
            {
                **classified,
                "first_seen": None,
                "last_seen": None,
                "observation_count": 0,
                "sources": [],
            },
        )
        entry["first_seen"] = _min_ts(entry["first_seen"], observation["first_seen"])
        entry["last_seen"] = _max_ts(entry["last_seen"], observation["last_seen"])
        entry["observation_count"] += observation["observation_count"]
        entry["sources"].append(
            {
                "source_kind": observation["source_kind"],
                "source_label": SOURCE_LABELS.get(observation["source_kind"], observation["source_kind"]),
                "observation_count": observation["observation_count"],
                "first_seen": observation["first_seen"],
                "last_seen": observation["last_seen"],
                "evidence_id": observation.get("evidence_id"),
                "artifact_id": observation.get("artifact_id"),
            }
        )

    addresses = sorted(merged.values(), key=lambda entry: entry["last_seen"] or "", reverse=True)
    return {"case_id": case_id, "host_id": host_id, "addresses": addresses}
