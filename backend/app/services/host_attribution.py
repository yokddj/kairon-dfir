from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
from typing import Any

from app.core.opensearch import get_events_index, get_index_health, get_opensearch_client, index_exists, is_index_queryable, resolve_aggregatable_field
from app.ingest.host_detection import COLLECTION_RE, normalize_hostname


_REJECTED_DRIVER_OR_FILTER_NAMES = {
    "applockerfltr",
    "bfs",
    "cldflt",
    "wdfilter",
    "filecrypt",
    "fileinfo",
    "npsvctrig",
    "sysmondrv",
    "ucpd",
    "luafv",
    "wcifs",
    "wimmount",
    "wof",
    "bindflt",
    "storqosflt",
    "fltmgr",
    "ntfs",
    "tcpip",
    "afd",
    "mpsdrv",
    "srvnet",
    "srv2",
}
_REMOTE_DOMAIN_SUFFIXES = (
    ".windows.com",
    ".microsoft.com",
    ".live.com",
    ".akadns.net",
    ".msftncsi.com",
    ".trafficmanager.net",
)
_HOSTNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


def classify_host_candidate(
    value: str | None,
    *,
    source: str = "inferred",
    provider: str | None = None,
    channel: str | None = None,
) -> dict[str, Any]:
    raw_value = str(value or "").strip()
    raw_lower = raw_value.strip().strip('"').strip("'").rstrip(".").lower()
    provider_lower = str(provider or "").strip().lower()
    channel_lower = str(channel or "").strip().lower()
    if raw_lower in _REJECTED_DRIVER_OR_FILTER_NAMES:
        return {
            "value": raw_value,
            "normalized": raw_lower,
            "accepted": False,
            "confidence": "low",
            "source": source,
            "rejected_reason": "driver_or_filter_name",
        }
    if any(raw_lower.endswith(suffix) for suffix in _REMOTE_DOMAIN_SUFFIXES):
        return {
            "value": raw_value,
            "normalized": raw_lower,
            "accepted": False,
            "confidence": "low",
            "source": source,
            "rejected_reason": "remote_domain",
        }
    if "filtermanager" in provider_lower and channel_lower == "system":
        return {
            "value": raw_value,
            "normalized": raw_lower or None,
            "accepted": False,
            "confidence": "low",
            "source": source,
            "rejected_reason": "driver_or_filter_name",
        }
    normalized = normalize_hostname(raw_value)
    if not normalized:
        return {
            "value": raw_value,
            "normalized": None,
            "accepted": False,
            "confidence": "low",
            "source": source,
            "rejected_reason": "invalid_host_value",
        }
    if not _HOSTNAME_RE.fullmatch(normalized):
        return {
            "value": raw_value or normalized,
            "normalized": normalized,
            "accepted": False,
            "confidence": "low",
            "source": source,
            "rejected_reason": "invalid_host_pattern",
        }
    confidence = "low"
    if source in {"evtx_computer", "collection_metadata", "manifest", "explicit_field"}:
        confidence = "high"
    elif source in {"collection_filename"}:
        confidence = "medium"
    elif source in {"event_host_agg"}:
        return {
            "value": raw_value or normalized,
            "normalized": normalized,
            "accepted": False,
            "confidence": "low",
            "source": source,
            "rejected_reason": "untrusted_host_source",
        }
    return {
        "value": raw_value or normalized,
        "normalized": normalized,
        "accepted": True,
        "confidence": confidence,
        "source": source,
        "rejected_reason": None,
    }


def extract_collection_hostname_candidate(value: str | None) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    for candidate_name in [text, Path(text).name, Path(text).stem]:
        match = COLLECTION_RE.search(candidate_name)
        if match:
            classified = classify_host_candidate(match.group(1), source="collection_filename")
            if classified["accepted"]:
                return str(classified["normalized"])
    return None


def choose_primary_host(
    *,
    collection_candidate: str | None = None,
    host_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    counts = {
        str(candidate): int(count or 0)
        for candidate, count in (host_counts or {}).items()
        if classify_host_candidate(candidate, source="evtx_computer")["accepted"]
    }
    collection_classification = classify_host_candidate(collection_candidate, source="collection_filename") if collection_candidate else None
    if collection_classification and collection_classification["accepted"]:
        corroborated = counts.get(str(collection_classification["normalized"]), 0) > 0
        return {
            "host": str(collection_classification["normalized"]),
            "source": "collection_metadata|evtx_computer" if corroborated else "collection_filename",
            "confidence": "high" if corroborated else "medium",
        }
    if counts:
        ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        return {
            "host": ordered[0][0],
            "source": "evtx_computer",
            "confidence": "high",
        }
    return {
        "host": None,
        "source": "unknown",
        "confidence": "low",
    }


def aggregate_host_counts(case_id: str, *, evidence_id: str | None = None, size: int = 25) -> dict[str, int]:
    try:
        client = get_opensearch_client()
        index = get_events_index(case_id)
        if not index_exists(client, index) or not is_index_queryable(client, index):
            return {}
        field = resolve_aggregatable_field(client, index, "host.name")
        if not field:
            return {}
        filters: list[dict[str, Any]] = [{"term": {"case_id": case_id}}]
        if evidence_id:
            filters.append({"term": {"evidence_id": evidence_id}})
        response = client.search(
            index=index,
            body={
                "size": 0,
                "query": {"bool": {"filter": filters}},
                "aggs": {"hosts": {"terms": {"field": field, "size": size}}},
            },
            params={"ignore_unavailable": "true"},
        )
        return {
            str(bucket.get("key") or ""): int(bucket.get("doc_count") or 0)
            for bucket in (((response.get("aggregations") or {}).get("hosts") or {}).get("buckets") or [])
            if str(bucket.get("key") or "").strip()
        }
    except Exception:  # noqa: BLE001
        return {}


def sample_host_events(case_id: str, host_value: str, *, evidence_id: str | None = None, size: int = 5) -> list[dict[str, Any]]:
    try:
        client = get_opensearch_client()
        index = get_events_index(case_id)
        if not index_exists(client, index) or not is_index_queryable(client, index):
            return []
        filters: list[dict[str, Any]] = [{"term": {"case_id": case_id}}, {"term": {"host.name": host_value}}]
        if evidence_id:
            filters.append({"term": {"evidence_id": evidence_id}})
        response = client.search(
            index=index,
            body={
                "size": size,
                "_source": [
                    "artifact.type",
                    "artifact.parser",
                    "event.type",
                    "source_file",
                "windows.channel",
                "windows.provider",
                "windows.computer",
                "windows.event_data",
                "host.name",
                "host.source",
                "source.ip",
                "source.hostname",
                "destination.hostname",
                "dns.domain",
                "network.domain",
                "url.domain",
                    "service.name",
                    "windows.service_name",
                ],
                "query": {"bool": {"filter": filters}},
                "sort": [{"@timestamp": {"order": "desc", "missing": "_last"}}],
            },
            params={"ignore_unavailable": "true"},
        )
        return [hit.get("_source") or {} for hit in response.get("hits", {}).get("hits", [])]
    except Exception:  # noqa: BLE001
        return []


def infer_host_source_from_samples(host_value: str, samples: list[dict[str, Any]]) -> tuple[str, str]:
    normalized = normalize_hostname(host_value)
    for sample in samples:
        windows_computer = normalize_hostname(((sample.get("windows") or {}).get("computer")))
        if normalized and windows_computer == normalized:
            return "evtx_computer", "high"
    return "event_host_agg", "medium"


def classify_host_samples_against_primary(
    host_value: str,
    samples: list[dict[str, Any]],
    *,
    primary_host: str | None,
) -> tuple[bool, str | None]:
    normalized = normalize_hostname(host_value)
    primary_normalized = normalize_hostname(primary_host)
    if not normalized or not primary_normalized or normalized == primary_normalized:
        return False, None

    matched_samples = 0
    remote_workstation_hits = 0
    for sample in samples:
        windows = sample.get("windows") or {}
        event_data = windows.get("event_data") or {}
        candidate_values = {
            normalize_hostname(event_data.get("WorkstationName")),
            normalize_hostname(event_data.get("ClientMachine")),
            normalize_hostname(event_data.get("ClientName")),
            normalize_hostname(event_data.get("Workstation")),
        }
        if normalized not in {value for value in candidate_values if value}:
            continue
        matched_samples += 1
        target_values = {
            normalize_hostname(event_data.get("TargetDomainName")),
            normalize_hostname(event_data.get("TargetServerName")),
            normalize_hostname(event_data.get("ComputerName")),
        }
        source_ip = str(
            event_data.get("IpAddress")
            or event_data.get("SourceAddress")
            or event_data.get("ClientIP")
            or event_data.get("Address")
            or event_data.get("SourceNetworkAddress")
            or event_data.get("ClientAddress")
            or ""
        ).strip()
        logon_type = str(event_data.get("LogonType") or "").strip()
        if primary_normalized in {value for value in target_values if value} or (logon_type == "3" and source_ip not in {"", "-", "127.0.0.1", "::1"}):
            remote_workstation_hits += 1
    if matched_samples and remote_workstation_hits == matched_samples:
        return True, "remote_workstation_name"
    return False, None


def build_host_attribution(
    case_id: str,
    *,
    evidences: list[Any],
    findings: list[Any],
    top_host_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    overall_counts = dict(top_host_counts or aggregate_host_counts(case_id))
    primary_hosts: list[dict[str, Any]] = []
    alias_candidates: dict[str, dict[str, Any]] = {}
    rejected_candidates: dict[str, dict[str, Any]] = {}
    evidence_summaries: dict[str, dict[str, Any]] = {}
    accepted_counts: dict[str, int] = defaultdict(int)

    for evidence in evidences:
        collection_candidate = extract_collection_hostname_candidate(
            getattr(evidence, "original_filename", None) or getattr(evidence, "stored_path", None) or getattr(evidence, "original_path", None)
        )
        evidence_counts = aggregate_host_counts(case_id, evidence_id=getattr(evidence, "id", None))
        if not evidence_counts:
            metadata = dict(getattr(evidence, "metadata_json", {}) or {})
            evidence_counts = {
                str(key): int(value or 0)
                for key, value in dict(metadata.get("detected_host_counts") or {}).items()
                if str(key).strip()
            }
            if not evidence_counts and getattr(evidence, "detected_host", None):
                evidence_counts = {str(getattr(evidence, "detected_host")): 1}
        primary = choose_primary_host(collection_candidate=collection_candidate, host_counts=evidence_counts)
        primary_host = primary.get("host")
        if primary_host:
            accepted_counts[primary_host] += evidence_counts.get(primary_host, 0)
        aliases: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        for value, count in evidence_counts.items():
            if primary_host and normalize_hostname(value) == normalize_hostname(primary_host):
                continue
            samples = sample_host_events(case_id, value, evidence_id=getattr(evidence, "id", None))
            sample_rejected, sample_rejected_reason = classify_host_samples_against_primary(
                value,
                samples,
                primary_host=primary_host,
            )
            if sample_rejected:
                rejected_item = {
                    "value": value,
                    "reason": sample_rejected_reason,
                    "events_count": count,
                }
                rejected.append(rejected_item)
                rejected_candidates[value] = rejected_item
                continue
            source, confidence = infer_host_source_from_samples(value, samples)
            sample_windows = (samples[0].get("windows") or {}) if samples else {}
            classified = classify_host_candidate(
                value,
                source=source,
                provider=sample_windows.get("provider"),
                channel=sample_windows.get("channel"),
            )
            if classified["accepted"]:
                alias = {
                    "value": classified["normalized"],
                    "confidence": confidence if confidence != "medium" else classified["confidence"],
                    "source": source,
                    "events_count": count,
                    "classification": "possible_alias",
                }
                aliases.append(alias)
                alias_candidates[str(classified["normalized"])] = alias
                accepted_counts[str(classified["normalized"])] += count
            else:
                rejected_item = {
                    "value": value,
                    "reason": classified["rejected_reason"],
                    "events_count": count,
                }
                rejected.append(rejected_item)
                rejected_candidates[value] = rejected_item
        evidence_summaries[getattr(evidence, "id", "")] = {
            "primary_host": primary_host,
            "primary_host_source": primary.get("source"),
            "primary_host_confidence": primary.get("confidence"),
            "aliases": sorted(aliases, key=lambda item: (-int(item["events_count"]), str(item["value"]))),
            "rejected": sorted(rejected, key=lambda item: (-int(item["events_count"]), str(item["value"]))),
            "collection_candidate": collection_candidate,
            "raw_host_counts": evidence_counts,
        }

    primary_name = next(
        (
            summary["primary_host"]
            for summary in evidence_summaries.values()
            if summary.get("primary_host")
        ),
        None,
    )

    for value, count in overall_counts.items():
        if value in rejected_candidates or value in alias_candidates or value in accepted_counts:
            continue
        if primary_name and normalize_hostname(value) == normalize_hostname(primary_name):
            continue
        samples = sample_host_events(case_id, value)
        sample_rejected, sample_rejected_reason = classify_host_samples_against_primary(
            value,
            samples,
            primary_host=primary_name,
        )
        if sample_rejected:
            rejected_candidates[value] = {
                "value": value,
                "reason": sample_rejected_reason,
                "events_count": count,
            }
            continue
        source, confidence = infer_host_source_from_samples(value, samples)
        sample_windows = (samples[0].get("windows") or {}) if samples else {}
        classified = classify_host_candidate(
            value,
            source=source,
            provider=sample_windows.get("provider"),
            channel=sample_windows.get("channel"),
        )
        if classified["accepted"]:
            accepted_counts[str(classified["normalized"])] += count
        else:
            rejected_candidates[value] = {
                "value": value,
                "reason": classified["rejected_reason"],
                "events_count": count,
            }

    if primary_name and primary_name not in accepted_counts:
        accepted_counts[primary_name] = 0
    for host_name, events_count in sorted(accepted_counts.items(), key=lambda item: (-item[1], item[0])):
        source = "evtx_computer"
        confidence = "high"
        is_primary = host_name == primary_name
        is_alias = not is_primary
        primary_hosts.append(
            {
                "host": host_name,
                "confidence": confidence,
                "source": source if not is_primary else (next((summary["primary_host_source"] for summary in evidence_summaries.values() if summary.get("primary_host") == host_name), source)),
                "is_primary": is_primary,
                "is_alias": is_alias,
                "events_count": events_count,
                "findings_count": 0,
                "high_risk_count": 0,
                "evidence_ids": [evidence_id for evidence_id, summary in evidence_summaries.items() if summary.get("primary_host") == host_name or any(alias.get("value") == host_name for alias in summary.get("aliases", []))],
                "first_seen": None,
                "last_seen": None,
            }
        )

    accepted_lookup = {item["host"]: item for item in primary_hosts}
    for finding in findings:
        finding_hosts = [normalize_hostname(str(host)) for host in (getattr(finding, "related_hosts", None) or [])]
        for host_name in {host for host in finding_hosts if host and host in accepted_lookup}:
            accepted_lookup[host_name]["findings_count"] += 1
            if str(getattr(finding, "severity", "")) in {"high", "critical"} or int(getattr(finding, "risk_score", 0) or 0) >= 70:
                accepted_lookup[host_name]["high_risk_count"] += 1

    return {
        "primary_host": primary_name,
        "hosts": primary_hosts or [{
            "host": "unknown",
            "confidence": "low",
            "source": "unknown",
            "is_primary": True,
            "is_alias": False,
            "events_count": 0,
            "findings_count": 0,
            "high_risk_count": 0,
            "evidence_ids": [getattr(evidence, "id", None) for evidence in evidences if getattr(evidence, "id", None)],
            "first_seen": None,
            "last_seen": None,
        }],
        "host_candidates": sorted(alias_candidates.values(), key=lambda item: (-int(item["events_count"]), str(item["value"]))),
        "rejected_host_candidates": sorted(rejected_candidates.values(), key=lambda item: (-int(item["events_count"]), str(item["value"]))),
        "evidence_summaries": evidence_summaries,
        "top_raw_host_values": {key: overall_counts[key] for key in sorted(overall_counts, key=lambda item: (-overall_counts[item], item))},
    }


def build_host_attribution_report(case_id: str, *, evidences: list[Any], findings: list[Any]) -> dict[str, Any]:
    attribution = build_host_attribution(case_id, evidences=evidences, findings=findings)
    evidence_id = getattr(evidences[0], "id", None) if len(evidences) == 1 else None
    primary_summary = next(iter(attribution["evidence_summaries"].values()), {})
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "primary_host": primary_summary.get("primary_host") or attribution.get("primary_host"),
        "primary_host_source": primary_summary.get("primary_host_source") or "unknown",
        "primary_host_confidence": primary_summary.get("primary_host_confidence") or "low",
        "hosts_accepted": attribution.get("hosts") or [],
        "host_alias_candidates": attribution.get("host_candidates") or [],
        "host_candidates_rejected": attribution.get("rejected_host_candidates") or [],
        "top_raw_host_values": attribution.get("top_raw_host_values") or {},
        "events_with_rewritten_host": 0,
        "events_with_removed_host": 0,
        "events_without_host": 0,
        "warnings": ["host_aliases_present"] if attribution.get("host_candidates") else [],
    }
