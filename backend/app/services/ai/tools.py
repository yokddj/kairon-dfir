"""Read-only tools the assistant can call to look at the case.

The whole point of this layer is that the model never sees the event store. A
case holds millions of events; a context window holds a few thousand tokens of
them. So every tool here answers with an *aggregate first* -- how many matched,
broken down by host, artifact type and risk -- and only then a small sample of
representative rows. That is what lets "is there persistence on this host?" be
answered from a 700k-event case without the model ever reading 700k events.

Each tool wraps a service the product already uses for its own screens, so what
the assistant sees is what the analyst would see in the UI, filters and all.
Nothing here writes: the assistant can look, never touch.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.models.case_host import CaseHost

logger = logging.getLogger(__name__)

# A tool result is capped twice: by row count, so the model gets a sample rather
# than a dump, and by serialized size, because one pathological event with a
# 40 KB command line would otherwise blow the context on its own.
MAX_ROWS = 20
MAX_ROWS_HARD = 50
MAX_FIELD_CHARS = 600
MAX_RESULT_CHARS = 12000


class ToolError(RuntimeError):
    """A tool could not answer. The message is shown to the model, so keep it useful."""


def _resolve_host(db: Session, case_id: str, value: Any) -> CaseHost | None:
    """Find the host a model meant, by id, name or alias.

    Models pass whatever the analyst said -- "WS01", "this host", a UUID from a
    previous result. Host ids are UUID columns, so feeding an arbitrary string
    into a query aborts the transaction. Everything is resolved here, once, and
    an unresolvable value becomes an error that names the real hosts instead of
    a database exception.
    """
    text = str(value or "").strip()
    if not text:
        return None

    hosts = db.query(CaseHost).filter(CaseHost.case_id == case_id).all()
    if not hosts:
        raise ToolError("This case has no hosts recorded yet, so it cannot be filtered by host.")

    # An exact id match first: unambiguous, and what list_hosts hands back.
    for host in hosts:
        if host.id == text:
            return host

    target = _normalize_host_name(text)
    for host in hosts:
        names = {_normalize_host_name(host.display_name), _normalize_host_name(host.canonical_name)}
        if target in names - {""}:
            return host

    alias_host_id = _host_id_for_alias(db, case_id, target)
    if alias_host_id:
        for host in hosts:
            if host.id == alias_host_id:
                return host

    available = ", ".join(sorted({h.display_name for h in hosts})[:20])
    raise ToolError(
        f"No host called '{text}' in this case. Known hosts: {available}. "
        "Call list_hosts and use a name or host_id from it, or omit the host to search them all."
    )


def _normalize_host_name(value: Any) -> str:
    name = str(value or "").strip().lower()
    return name[:-6] if name.endswith(".local") else name


def _host_id_for_alias(db: Session, case_id: str, normalized: str) -> str | None:
    """Hosts are renamed and re-observed; aliases keep old names resolvable."""
    try:
        from app.models.case_host_alias import CaseHostAlias

        row = (
            db.query(CaseHostAlias)
            .filter(
                CaseHostAlias.case_id == case_id,
                CaseHostAlias.normalized_alias == normalized,
            )
            .first()
        )
        return row.case_host_id if row else None
    except Exception:  # noqa: BLE001 - aliases are a nicety, not a requirement
        logger.debug("Alias lookup failed; falling back to direct host names", exc_info=True)
        _recover_session(db)
        return None


def _clip(value: Any, limit: int = MAX_FIELD_CHARS) -> Any:
    if not isinstance(value, str):
        return value
    value = value.strip()
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _rows(items: list[dict], keys: tuple[str, ...], limit: int) -> list[dict]:
    """Project rows down to the fields that carry meaning for an analyst."""
    out = []
    for item in items[:limit]:
        row = {k: _clip(item.get(k)) for k in keys if item.get(k) not in (None, "", [], {})}
        if row:
            out.append(row)
    return out


def _limit(value: Any) -> int:
    try:
        return max(1, min(int(value), MAX_ROWS_HARD))
    except (TypeError, ValueError):
        return MAX_ROWS


# --------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------

EVENT_KEYS = (
    "id", "timestamp", "host", "user", "artifact_type", "parser",
    "event_type", "severity", "risk_score", "title", "summary",
)


def tool_search_events(db: Session, case_id: str, args: dict) -> dict:
    from app.services.search_service import build_search_v2_params, search_events_v2

    host = _resolve_host(db, case_id, args.get("host_id") or args.get("host"))
    params = build_search_v2_params(
        q=str(args.get("query") or "").strip(),
        host_id=host.id if host else None,
        time_from=args.get("time_from") or None,
        time_to=args.get("time_to") or None,
        risk_min=args.get("risk_min"),
        artifact_type=args.get("artifact_type"),
        page_size=_limit(args.get("limit")),
        page=1,
        include_highlights=False,
        include_facets=True,
    )
    total, rows, warnings, facets = search_events_v2(case_id, params, db=db)
    limit = _limit(args.get("limit"))
    returned = min(len(rows), limit)
    return {
        "total_matches": total,
        "returned": returned,
        # Counted over the returned sample only, NOT the full match set -- the
        # search service computes facets per page. Naming it plainly stops the
        # model from reporting a sample count as if it described the case.
        "sample_breakdown": _compact_facets(facets),
        "events": _rows(rows, EVENT_KEYS, limit),
        "warnings": warnings or [],
        "note": (
            f"{total} events matched this query; {returned} are shown below. "
            "The breakdown counts only those shown. To characterise the rest, "
            "run narrower queries and read their total_matches."
        ) if total > returned else None,
        # A zero is ambiguous on its own: the activity may be absent, or the
        # artifact that would record it may never have been collected. Saying
        # which is the difference between an answer and a misleading one.
        "zero_result_guidance": _zero_guidance(db, case_id) if total == 0 else None,
    }


def _zero_guidance(db: Session, case_id: str) -> str:
    """Explain what a zero actually means in this case."""
    try:
        described = tool_describe_case(db, case_id, {})
    except Exception:  # noqa: BLE001 - guidance is a bonus, never a failure
        _recover_session(db)
        return (
            "Nothing matched. Before reporting this as absence, confirm with describe_case "
            "that the artifact that would record it was collected."
        )
    if not described.get("indexed"):
        return "Nothing matched because this case has no indexed events at all."
    present = ", ".join(sorted(described.get("artifact_types") or {})) or "none"
    return (
        "Nothing matched this query. This case contains only these artifact types: "
        f"{present}. If the activity you are looking for would be recorded by an artifact "
        "that is not in that list, the correct answer is that the evidence needed to "
        "decide was never collected -- not that the activity did not happen."
    )


def _compact_facets(facets: dict) -> dict:
    """Keep the top few values per facet of the returned sample."""
    out: dict[str, dict] = {}
    for name, counts in (facets or {}).items():
        if not isinstance(counts, dict) or not counts:
            continue
        top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:8]
        out[name] = {str(k): int(v) for k, v in top}
    return out


PERSISTENCE_KEYS = (
    "host", "type", "name", "command_or_target", "source_artifact",
    "risk_score", "enabled", "timestamp", "reasons",
)


def tool_list_persistence(db: Session, case_id: str, args: dict) -> dict:
    """Autoruns, services, scheduled tasks, run keys -- the product's own detector."""
    from app.services.startup_persistence import list_startup_persistence_items

    limit = _limit(args.get("limit"))
    host = _resolve_host(db, case_id, args.get("host") or args.get("host_id"))
    result = list_startup_persistence_items(
        db,
        case_id,
        {
            # This service filters by name, so hand it the canonical one.
            "host": [host.display_name] if host else None,
            "type": args.get("type") or None,
            "q": args.get("query") or None,
            "suspicious_only": bool(args.get("suspicious_only")),
            "risk_min": args.get("risk_min"),
            "page": 1,
            "page_size": limit,
        },
    )
    counts = result.get("counts") or result.get("summary") or {}
    return {
        "summary": counts,
        "items": _rows(result.get("items") or [], PERSISTENCE_KEYS, limit),
        "warnings": result.get("warnings") or [],
    }


FINDING_KEYS = (
    "id", "title", "severity", "status", "confidence",
    "finding_type", "description", "created_at",
)


def tool_list_findings(db: Session, case_id: str, args: dict) -> dict:
    from app.services.search_service import build_search_v2_params, search_findings_v2

    limit = _limit(args.get("limit"))
    params = build_search_v2_params(
        q=str(args.get("query") or "").strip(),
        severity=args.get("severity"),
        status=args.get("status"),
        page_size=limit,
        page=1,
    )
    total, rows, _objects, warnings = search_findings_v2(db, case_id, params)
    return {
        "total_matches": total,
        "findings": _rows(rows, FINDING_KEYS, limit),
        "warnings": warnings or [],
    }


def tool_list_hosts(db: Session, case_id: str, args: dict) -> dict:
    """Which machines are in this case, and how much data each one has."""
    hosts = (
        db.query(CaseHost)
        .filter(CaseHost.case_id == case_id)
        .order_by(CaseHost.event_count.desc())
        .limit(MAX_ROWS_HARD)
        .all()
    )
    return {
        "host_count": len(hosts),
        "hosts": [
            {
                "host_id": h.id,
                "name": h.display_name,
                "events": h.event_count,
                "evidence_items": h.evidence_count,
                "first_seen": h.first_seen,
                "last_seen": h.last_seen,
            }
            for h in hosts
        ],
    }


TIMELINE_KEYS = (
    "id", "timestamp", "host", "title", "summary",
    "artifact_type", "event_type", "severity", "risk_score",
)


def tool_get_timeline(db: Session, case_id: str, args: dict) -> dict:
    """A window of the case timeline, in order."""
    from app.services.timeline_service import build_lightweight_timeline_response

    limit = _limit(args.get("limit"))
    host = _resolve_host(db, case_id, args.get("host_id") or args.get("host"))
    params = {
        "q": str(args.get("query") or "").strip(),
        "host_id": host.id if host else None,
        "time_from": args.get("time_from") or None,
        "time_to": args.get("time_to") or None,
        "page": 1,
        "page_size": limit,
    }
    result = build_lightweight_timeline_response(db, case_id, params)
    items = result.get("items") or result.get("events") or []
    return {
        "total": result.get("total"),
        "entries": _rows(items, TIMELINE_KEYS, limit),
    }


def tool_describe_case(db: Session, case_id: str, args: dict) -> dict:
    """What data this case actually holds, counted over the whole index.

    Without this the model guesses field values -- searching for .crdownload
    files in a case that never ingested a filesystem artifact -- and then reads
    the resulting zero as proof that nothing was downloaded. Knowing which
    artifact types, parsers and event types exist, and how many events each has,
    is what turns a blind keyword hunt into an actual search strategy.
    """
    from app.core.opensearch import get_events_index, get_opensearch_client, index_exists

    client = get_opensearch_client()
    index = get_events_index(case_id)
    if not index_exists(client, index):
        return {
            "indexed": False,
            "message": "No events are indexed for this case yet, so no search will return anything.",
        }

    facets = {
        "artifact_type": "artifact.type",
        "parser": "artifact.parser",
        "event_type": "event.type",
        "host": "host.name",
        "severity": "event.severity",
    }
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": [{"term": {"case_id": case_id}}]}},
        "aggs": {
            name: {"terms": {"field": field, "size": 30}} for name, field in facets.items()
        },
    }
    try:
        result = client.search(index=index, body=body, params={"ignore_unavailable": "true"})
    except Exception as exc:  # noqa: BLE001
        raise ToolError(f"Could not summarise the case index: {exc}") from exc

    total_meta = result.get("hits", {}).get("total", 0)
    total = int(total_meta.get("value", 0) if isinstance(total_meta, dict) else total_meta)
    aggs = result.get("aggregations") or {}

    def buckets(name: str) -> dict[str, int]:
        raw = (aggs.get(name) or {}).get("buckets") or []
        return {str(b.get("key")): int(b.get("doc_count") or 0) for b in raw if b.get("key") is not None}

    present = buckets("artifact_type")
    return {
        "indexed": True,
        "total_events": total,
        # These counts cover the whole case, unlike a search's sample_breakdown.
        "artifact_types": present,
        "parsers": buckets("parser"),
        "event_types": buckets("event_type"),
        "hosts": buckets("host"),
        "severities": buckets("severity"),
        "how_to_read_this": (
            "Only the artifact types listed here exist in this case. A query filtering on "
            "anything absent from this list returns zero because the data was never "
            "collected -- which is NOT evidence that the activity did not happen. Say so "
            "explicitly when it applies."
        ),
    }


DOWNLOAD_KEYS = (
    "file_name", "file_path", "host", "timestamp", "zone", "zone_id",
    "host_url", "referrer_url", "source", "risk_score", "file_extension",
)


def tool_list_downloads(db: Session, case_id: str, args: dict) -> dict:
    """Files downloaded from the internet, via Mark of the Web.

    Windows records where a downloaded file came from in the Zone.Identifier
    alternate data stream, and Kairon correlates that with Sysmon event 15 and
    browser history. That is the artifact that answers "what was downloaded",
    far more reliably than guessing at .crdownload extensions or a Downloads
    folder path that may never have been collected.
    """
    from app.services.motw import list_motw_items

    limit = _limit(args.get("limit"))
    host = _resolve_host(db, case_id, args.get("host") or args.get("host_id"))
    result = list_motw_items(
        db,
        case_id,
        {
            "host": [host.display_name] if host else None,
            "q": args.get("query") or None,
            "extension": args.get("extension") or None,
            "risk_min": args.get("risk_min"),
            "page": 1,
            "page_size": limit,
        },
    )
    motw_total = int(result.get("total") or 0)
    motw_rows = _rows(result.get("items") or [], DOWNLOAD_KEYS, limit)

    # Mark of the Web needs a filesystem or Sysmon artifact. Browser history
    # records downloads independently, and a case can easily have one without
    # the other, so both are asked and the answer says which source it came
    # from -- otherwise "no downloads" would really mean "no MFT was collected".
    browser = _browser_downloads(db, case_id, host, limit)

    total = motw_total + browser["total"]
    return {
        "total_downloads": total,
        "by_source": {
            "mark_of_the_web": motw_total,
            "browser_history": browser["total"],
        },
        "summary": result.get("summary") or {},
        "downloads": (motw_rows + browser["rows"])[:limit],
        "warnings": (result.get("warnings") or []) + browser["warnings"],
        "note": (
            "No download evidence was recovered from Mark of the Web or browser history. "
            "Check describe_case: if neither a filesystem artifact (mft/ntfs), Sysmon nor "
            "browser history was ingested, the evidence needed to answer was never "
            "collected -- which is not the same as nothing having been downloaded."
        ) if total == 0 else None,
    }


BROWSER_DOWNLOAD_KEYS = (
    "id", "timestamp", "host", "user", "title", "summary",
    "artifact_type", "parser", "event_type", "risk_score",
)


def _browser_downloads(db: Session, case_id: str, host, limit: int) -> dict:
    """Download events recorded by browser history parsers."""
    from app.services.search_service import build_search_v2_params, search_events_v2

    params = build_search_v2_params(
        q="event.type:file_downloaded",
        host_id=host.id if host else None,
        page_size=limit,
        page=1,
        include_highlights=False,
        include_facets=False,
    )
    try:
        total, rows, warnings, _facets = search_events_v2(case_id, params, db=db)
    except Exception as exc:  # noqa: BLE001 - one source failing must not hide the other
        logger.info("Browser download lookup failed: %s", exc)
        _recover_session(db)
        return {"total": 0, "rows": [], "warnings": [f"Browser history lookup failed: {exc}"]}
    return {
        "total": total,
        "rows": _rows(rows, BROWSER_DOWNLOAD_KEYS, limit),
        "warnings": list(warnings or []),
    }


# The dotted paths worth surfacing on a single event, mirroring the fields
# analysts can actually search on (app.search.query_syntax.FIELD_SPECS). Using
# the same list means a value the model quotes from this tool is one an
# analyst can paste straight back into Search to reproduce the citation.
EVENT_DETAIL_FIELDS = (
    "host.name", "user.name", "user.sid",
    "artifact.type", "artifact.parser",
    "event.type", "event.action",
    "risk_score", "severity", "status",
    "process.name", "process.path", "process.command_line",
    "process.parent.name", "process.parent.path", "process.parent.command_line",
    "file.name", "file.path", "file.extension", "file.size",
    "folder.path",
    "registry.key_path", "registry.value_name", "registry.value_data",
    "dns.domain",
    "url.full", "url.domain",
    "source.ip", "destination.ip", "network.direction",
    "email.message_id", "email.subject", "email.from.address",
    "email.from.domain", "email.to.addresses", "email.attachments.file_name",
    "ntfs.reason", "ntfs.zone_id", "ntfs.host_url", "ntfs.referrer_url",
    "windows_search.indexed_path",
    "notification.title", "notification.body_preview",
    "office.alert_text", "office.document_path",
    "rule.id", "rule.name", "rule.title",
    "detection.source",
)


def _dotted_get(source: dict, dotted: str) -> Any:
    node: Any = source
    for part in dotted.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def tool_get_event_detail(db: Session, case_id: str, args: dict) -> dict:
    """Read one event in full before citing specifics from it.

    search_events and list_downloads return summarised rows -- enough to find
    a candidate, not enough to responsibly quote a registry path or a URL from.
    This is the tool that closes that gap: the full set of searchable fields
    for one event, plus whether an analyst has already recorded a finding or
    detection against it, so a citation points at something verified rather
    than a row skimmed from a list.
    """
    from app.core.opensearch import fetch_event_by_id
    from app.services.search_service import event_context

    event_id = str(args.get("event_id") or args.get("source_event_id") or "").strip()
    if not event_id:
        raise ToolError("event_id is required.")

    raw = fetch_event_by_id(case_id, event_id, event_index=None, opensearch_id=event_id) or fetch_event_by_id(
        case_id, event_id, event_index=None, opensearch_id=None
    )
    if not raw:
        return {
            "found": False,
            "event_id": event_id,
            "note": "No event with this id was found in this case. It may belong to a different case, "
            "or the id was misremembered -- re-run the search that produced it rather than guessing a fix.",
        }

    fields = {}
    for dotted in EVENT_DETAIL_FIELDS:
        value = _clip(_dotted_get(raw, dotted))
        if value not in (None, "", [], {}):
            fields[dotted] = value

    context = event_context(db, case_id, event_id)

    return {
        "found": True,
        "event_id": event_id,
        "timestamp": raw.get("@timestamp"),
        "evidence_id": raw.get("evidence_id"),
        "fields": fields,
        "related_findings": context.get("related_findings") or [],
        "related_detections": context.get("related_detections") or [],
        "note": (
            "An analyst has already recorded findings and/or detections against this event -- "
            "check them before drawing a new conclusion that might duplicate or contradict one."
            if (context.get("counts") or {}).get("related_findings")
            or (context.get("counts") or {}).get("related_detections")
            else None
        ),
    }


# --------------------------------------------------------------------------
# Schemas advertised to the model
# --------------------------------------------------------------------------

QUERY_HELP_CONSTRAINTS = (
    "Wildcards may not lead a term (`*\\Downloads` matches nothing and is not an error), "
    "backslashes in Windows paths must be escaped or the path quoted, and an unknown field "
    "name silently matches nothing. When a query returns zero, confirm with describe_case "
    "that the artifact type behind that field exists before reading the zero as an answer."
)

QUERY_HELP = (
    "Search syntax: field:value pairs combined with spaces, quotes for phrases, "
    "and >=/<= on numbers. Fields include host.name, user.name, process.name, "
    "process.command_line, process.parent.name, file.name, file.path, "
    "file.extension, registry.key_path, registry.value_data, dns.domain, "
    "url.full, url.domain, source.ip, destination.ip, artifact.type, "
    "artifact.parser, event.type, event.action, risk_score, severity, "
    "rule.name, detection.source. "
    'Examples: \'process.name:powershell.exe EncodedCommand\', '
    "'artifact.type:ntfs risk_score>=70', 'url.domain:*.example.com'."
)

TOOL_SPECS: list[dict] = [
    {
        "name": "describe_case",
        "description": (
            "Report which artifact types, parsers, event types and hosts actually exist in "
            "this case, with counts over every indexed event. CALL THIS FIRST for any "
            "question about whether something happened. It tells you which searches can "
            "possibly return anything: a filter on an artifact type absent from this list "
            "returns zero because that data was never collected, which is not evidence the "
            "activity did not occur."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "list_downloads",
        "description": (
            "List files downloaded from the internet. It asks two independent sources "
            "and reports which found what: Mark of the Web (the Zone.Identifier alternate "
            "data stream, plus Sysmon event 15), which needs a filesystem artifact, and "
            "browser history download records, which do not. This is the right tool for "
            "any question about downloads -- use it instead of guessing at Downloads "
            "folder paths or .crdownload extensions, which only work if a filesystem "
            "artifact happened to be collected."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Restrict to one host. A name or a host_id both work."},
                "query": {"type": "string", "description": "Free-text filter over file name, path and URL."},
                "extension": {"type": "string", "description": "Filter by file extension, e.g. exe."},
                "risk_min": {"type": "integer", "description": "Minimum risk score, 0-100."},
                "limit": {"type": "integer", "description": f"Max entries, 1-{MAX_ROWS_HARD}."},
            },
            "required": [],
        },
    },
    {
        "name": "get_event_detail",
        "description": (
            "Read one event in full, by its id. Returns every searchable field the event has "
            "(process, file, registry, url, dns, network, email fields as applicable) plus "
            "whether an analyst has already recorded a finding or detection against it. Call "
            "this before quoting a specific field value -- a path, a URL, a hash, a command "
            "line -- that only appeared in a summarised row from search_events or "
            "list_downloads; those rows are for finding the event, not for citing from."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string", "description": "The event's id, from a prior tool result."},
            },
            "required": ["event_id"],
        },
    },
    {
        "name": "list_hosts",
        "description": (
            "List the hosts in this case with their event and evidence counts. "
            "Call this first when the analyst refers to 'the host' without naming one, "
            "or whenever you need a host_id for another tool."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "search_events",
        "description": (
            "Search the case's parsed events. Returns total_matches -- the number of "
            "events in the whole case matching this query -- plus a small sample of them. "
            "total_matches is the reliable number to quote. sample_breakdown describes "
            "ONLY the sampled rows, never the full match set, so never present it as a "
            "case-wide count. To count a subset, run a narrower query and read its "
            "total_matches. "
            + QUERY_HELP
            + " "
            + QUERY_HELP_CONSTRAINTS
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query using the syntax above."},
                "host_id": {"type": "string", "description": "Restrict to one host. A host name or a host_id from list_hosts both work."},
                "time_from": {"type": "string", "description": "ISO 8601 lower bound."},
                "time_to": {"type": "string", "description": "ISO 8601 upper bound."},
                "risk_min": {"type": "integer", "description": "Only events at or above this risk score (0-100)."},
                "limit": {"type": "integer", "description": f"Sample size, 1-{MAX_ROWS_HARD}. Default {MAX_ROWS}."},
            },
            "required": ["query"],
        },
    },
    {
        "name": "list_persistence",
        "description": (
            "List startup and persistence mechanisms found on the case's hosts: run keys, "
            "services, scheduled tasks, startup folders and similar. Returns counts by host, "
            "by type and by source artifact, plus the entries themselves with a risk score. "
            "This is the right tool for any question about persistence or autoruns."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Restrict to one host. A host name or a host_id from list_hosts both work."},
                "query": {"type": "string", "description": "Free-text filter over name and command."},
                "suspicious_only": {"type": "boolean", "description": "Only entries flagged suspicious."},
                "risk_min": {"type": "integer", "description": "Minimum risk score, 0-100."},
                "limit": {"type": "integer", "description": f"Max entries, 1-{MAX_ROWS_HARD}."},
            },
            "required": [],
        },
    },
    {
        "name": "list_findings",
        "description": (
            "List findings already recorded in the case by the analyst or by detection rules. "
            "Use it to see what has been concluded before you add to it."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Free-text filter."},
                "severity": {"type": "string", "description": "critical, high, medium, low or info."},
                "status": {"type": "string", "description": "Finding status filter."},
                "limit": {"type": "integer", "description": f"Max findings, 1-{MAX_ROWS_HARD}."},
            },
            "required": [],
        },
    },
    {
        "name": "get_timeline",
        "description": (
            "Read a window of the case timeline in chronological order. Use it to see what "
            "happened around a moment you found with search_events."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Optional filter, same syntax as search_events."},
                "host_id": {"type": "string", "description": "Restrict to one host. A host name or a host_id from list_hosts both work."},
                "time_from": {"type": "string", "description": "ISO 8601 lower bound."},
                "time_to": {"type": "string", "description": "ISO 8601 upper bound."},
                "limit": {"type": "integer", "description": f"Max entries, 1-{MAX_ROWS_HARD}."},
            },
            "required": [],
        },
    },
]

HANDLERS: dict[str, Callable[[Session, str, dict], dict]] = {
    "describe_case": tool_describe_case,
    "get_event_detail": tool_get_event_detail,
    "list_downloads": tool_list_downloads,
    "list_hosts": tool_list_hosts,
    "search_events": tool_search_events,
    "list_persistence": tool_list_persistence,
    "list_findings": tool_list_findings,
    "get_timeline": tool_get_timeline,
}


def run_tool(db: Session, case_id: str, name: str, args: dict) -> dict:
    """Execute one tool. Never raises: the model gets the error and can adapt.

    A failure always rolls the session back. Postgres marks a transaction as
    aborted after any error, and every later statement on that connection then
    fails too -- so without this, one bad argument would silently break every
    remaining lookup in the conversation rather than just its own.
    """
    handler = HANDLERS.get(name)
    if handler is None:
        return {"error": f"Unknown tool '{name}'. Available: {', '.join(sorted(HANDLERS))}."}
    try:
        result = handler(db, case_id, args if isinstance(args, dict) else {})
    except ToolError as exc:
        _recover_session(db)
        return {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - surfaced to the model, not swallowed
        _recover_session(db)
        detail = getattr(exc, "detail", None)
        return {
            "error": f"{name} failed: {detail or exc}",
            "recoverable": True,
            "hint": "The session was reset; you can safely try a different query.",
        }
    return _enforce_size(result)


def _recover_session(db: Session | None) -> None:
    """Return the session to a usable state after a failed statement."""
    if db is None:
        return
    try:
        db.rollback()
    except Exception:  # noqa: BLE001 - nothing useful left to do
        logger.exception("Could not roll back the session after a tool failure")


def _enforce_size(result: dict) -> dict:
    """Last-resort guard so one enormous row cannot blow the context window."""
    import json

    encoded = json.dumps(result, default=str)
    if len(encoded) <= MAX_RESULT_CHARS:
        return result
    for key in ("events", "items", "findings", "entries", "hosts"):
        rows = result.get(key)
        if isinstance(rows, list) and len(rows) > 3:
            result[key] = rows[: max(3, len(rows) // 2)]
            result["truncated"] = "Result was too large; showing fewer rows. Narrow your query."
            return _enforce_size(result)
    return result
