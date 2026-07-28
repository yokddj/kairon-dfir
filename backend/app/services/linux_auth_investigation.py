from __future__ import annotations

import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from app.core.opensearch import get_events_index, get_opensearch_client

_PORT_RE = re.compile(r"\bport\s+(\d{1,5})\b", re.I)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_INVALID_RE = re.compile(r"invalid\s+user\s+(\S+)", re.I)
_FAILED_INVALID_RE = re.compile(r"Failed\s+\S+\s+for\s+invalid\s+user\s+(\S+)", re.I)
_FAILED_RE = re.compile(r"Failed\s+\S+\s+for\s+(\S+)", re.I)
_ACCEPTED_RE = re.compile(r"Accepted\s+\S+\s+for\s+(\S+)", re.I)
_PAM_MORE_RE = re.compile(r"PAM\s+(\d+)\s+more\s+authentication\s+failures?", re.I)
_PAM_SESSION_USER_RE = re.compile(r"session\s+(?:opened|closed)\s+for\s+user\s+(\S+)", re.I)
_PAM_USER_RE = re.compile(r"\buser=([^\s;]+)", re.I)
_RHOST_RE = re.compile(r"\brhost=([^\s;]+)", re.I)
_TTY_RE = re.compile(r"\btty=([^\s;]+)", re.I)
_AUTH_SOURCE_NAMES = {"auth.log", "secure", "wtmp", "btmp", "lastlog"}


def _is_auth_source(doc: dict) -> bool:
    source = str(doc.get("source_file") or _field(doc, "source_file", "") or "")
    if not source:
        return True
    parts = [part for part in source.replace("\\", "/").split("/") if part]
    return any(part in _AUTH_SOURCE_NAMES for part in parts)


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def _message(doc: dict) -> str:
    linux = doc.get("linux") or {}
    event = doc.get("event") or {}
    return str(linux.get("message") or doc.get("message") or event.get("message") or "")


def _field(doc: dict, key: str, default: Any = None) -> Any:
    linux = doc.get("linux") or {}
    return linux.get(key, default)


def _source_ip(doc: dict, message: str) -> str:
    value = _field(doc, "source_ip", "") or ""
    if value:
        return str(value)
    rhost = _RHOST_RE.search(message)
    if rhost and rhost.group(1).strip():
        return rhost.group(1).strip()
    match = _IP_RE.search(message)
    return match.group(1) if match else ""


def _source_port(doc: dict, message: str) -> int | None:
    value = _field(doc, "source_port")
    if value not in (None, ""):
        try:
            return int(value)
        except (TypeError, ValueError):
            pass
    match = _PORT_RE.search(message)
    return int(match.group(1)) if match else None


def _attempted_user(doc: dict, message: str) -> str:
    value = _field(doc, "attempted_username", "") or ""
    if value and value != "invalid":
        return str(value).strip("`',.;")
    for regex in (_FAILED_INVALID_RE, _INVALID_RE, _FAILED_RE, _ACCEPTED_RE):
        match = regex.search(message)
        if match:
            user = match.group(1).strip("`',.;")
            if user != "invalid":
                return user
    session_match = _PAM_SESSION_USER_RE.search(message)
    if session_match:
        return session_match.group(1).strip("`',.;")
    user_match = _PAM_USER_RE.search(message)
    if user_match:
        return user_match.group(1).strip("`',.;")
    value = _field(doc, "username", "") or ((doc.get("user") or {}).get("name") if isinstance(doc.get("user"), dict) else "") or ""
    return str(value).strip("`',.;")


def _auth_type(doc: dict, message: str) -> str:
    value = str(_field(doc, "auth_event_type", "") or "")
    if value:
        return value
    action = str(_field(doc, "event_action", "") or ((doc.get("event") or {}).get("action") or ""))
    lower = f"{action} {message}".lower()
    if "accepted" in lower:
        return "login_success"
    if "failed password" in lower or "failed none" in lower:
        return "login_failure"
    if "invalid user" in lower:
        return "invalid_user"
    if "session opened" in lower:
        return "session_open"
    if "session closed" in lower:
        return "session_close"
    if "authentication failure" in lower or "more authentication failures" in lower:
        return "authentication_failure"
    return "other"


def _event_from_doc(doc: dict) -> dict:
    message = _message(doc)
    host = ((doc.get("host") or {}).get("name") if isinstance(doc.get("host"), dict) else None) or _field(doc, "hostname", "") or _field(doc, "detected_host", "") or ""
    service = str(_field(doc, "service", "") or _field(doc, "process", "") or "")
    auth_type = _auth_type(doc, message)
    username = _attempted_user(doc, message)
    pam_more = _PAM_MORE_RE.search(message)
    aggregate_count = int(pam_more.group(1)) if pam_more else None
    explicit_failure = auth_type in {"login_failure", "invalid_user"} and message.lower().startswith("failed")
    return {
        "id": doc.get("event_id") or doc.get("id") or doc.get("_id"),
        "case_id": doc.get("case_id"),
        "evidence_id": doc.get("evidence_id"),
        "host_id": ((doc.get("host") or {}).get("evidence_host_id") if isinstance(doc.get("host"), dict) else None),
        "event_time": _iso(_parse_time(doc.get("@timestamp") or doc.get("timestamp"))),
        "_dt": _parse_time(doc.get("@timestamp") or doc.get("timestamp")),
        "event_type": auth_type,
        "authentication_result": "success" if auth_type in {"login_success", "session_open", "session_close"} else "failure" if auth_type in {"login_failure", "invalid_user", "authentication_failure"} else "unknown",
        "service": service,
        "process": str(_field(doc, "process", "") or service),
        "username": username,
        "attempted_username": username,
        "source_ip": _source_ip(doc, message),
        "source_port": _source_port(doc, message),
        "destination_host": host,
        "terminal": str(_field(doc, "terminal", "") or (_TTY_RE.search(message).group(1) if _TTY_RE.search(message) else "")),
        "pid": _field(doc, "pid"),
        "uid": _field(doc, "uid"),
        "message": message,
        "source_file": doc.get("source_file") or _field(doc, "source_file", ""),
        "artifact_type": _field(doc, "artifact_type", "") or ((doc.get("artifact") or {}).get("type") if isinstance(doc.get("artifact"), dict) else ""),
        "aggregate_failure_count": aggregate_count,
        "explicit_failure_count": 1 if explicit_failure else 0,
        "effective_failure_count": 1 if explicit_failure else 0,
    }


def _fetch_auth_docs(case_id: str) -> list[dict]:
    client = get_opensearch_client()
    body = {
        "size": 10000,
        "query": {"bool": {"filter": [{"term": {"case_id": case_id}}, {"terms": {"artifact.type": ["linux_auth", "linux_lastlog"]}}]}},
        "sort": [{"@timestamp": {"order": "asc", "missing": "_last"}}, {"_id": "asc"}],
    }
    result = client.search(index=get_events_index(), body=body, params={"ignore_unavailable": "true"})
    return [{"_id": hit.get("_id"), **dict(hit.get("_source") or {})} for hit in result.get("hits", {}).get("hits", [])]


def _apply_filters(events: list[dict], filters: dict[str, Any]) -> list[dict]:
    def ok(event: dict) -> bool:
        for key in ("username", "attempted_username", "source_ip", "service", "evidence_id", "host_id"):
            if filters.get(key) and str(event.get(key) or "") != str(filters[key]):
                return False
        if filters.get("source_port") is not None and event.get("source_port") != filters["source_port"]:
            return False
        if filters.get("result") and event.get("authentication_result") != filters["result"]:
            return False
        if filters.get("time_from") and event.get("_dt") and event["_dt"] < filters["time_from"]:
            return False
        if filters.get("time_to") and event.get("_dt") and event["_dt"] > filters["time_to"]:
            return False
        return True
    return [event for event in events if ok(event)]


def _reconstruct_sessions(events: list[dict]) -> list[dict]:
    accepted = [event for event in events if event["event_type"] == "login_success" and event.get("process") == "sshd"]
    opens = [event for event in events if event["event_type"] == "session_open" and event.get("service") == "sshd"]
    closes = [event for event in events if event["event_type"] == "session_close" and event.get("service") == "sshd"]
    used_close_ids: set[str] = set()
    sessions: list[dict] = []
    for success in accepted:
        username = success.get("username") or ""
        pid = success.get("pid")
        start_candidates = [item for item in opens if item.get("username") == username and item.get("pid") == pid and item.get("_dt") and success.get("_dt") and item["_dt"] >= success["_dt"]]
        start = min(start_candidates, key=lambda item: item["_dt"], default=success)
        close_candidates = [item for item in closes if item.get("username") == username and item.get("pid") == pid and item.get("_dt") and start.get("_dt") and item["_dt"] >= start["_dt"] and str(item.get("id")) not in used_close_ids]
        end = min(close_candidates, key=lambda item: item["_dt"], default=None)
        if end:
            used_close_ids.add(str(end.get("id")))
        duration_seconds = int((end["_dt"] - start["_dt"]).total_seconds()) if end and start.get("_dt") else None
        sessions.append({
            "id": f"session-{success.get('id')}",
            "username": username,
            "source_ip": success.get("source_ip"),
            "source_port": success.get("source_port"),
            "service": success.get("service") or success.get("process"),
            "start": _iso(start.get("_dt")),
            "end": _iso(end.get("_dt")) if end else None,
            "duration_seconds": duration_seconds,
            "status": "complete" if end else "accepted_without_pam_session" if start is success else "open_without_close",
            "confidence": "reconstructed" if end else "incomplete",
            "evidence_sources": sorted({success.get("source_file"), start.get("source_file"), end.get("source_file") if end else None} - {None, ""}),
        })
    return sorted(sessions, key=lambda item: item.get("start") or "")


def _brute_force_groups(events: list[dict]) -> list[dict]:
    failure_events = [event for event in events if event["event_type"] in {"login_failure", "invalid_user", "authentication_failure"}]
    explicit_by_pid_source: dict[tuple[Any, str], tuple[str, int | None]] = {}
    explicit_by_pid: dict[Any, tuple[str, str, int | None]] = {}
    for event in failure_events:
        if event.get("explicit_failure_count") and event.get("attempted_username"):
            explicit_by_pid_source[(event.get("pid"), event.get("source_ip") or "")] = (str(event.get("attempted_username")), event.get("source_port"))
            explicit_by_pid[event.get("pid")] = (str(event.get("attempted_username")), str(event.get("source_ip") or ""), event.get("source_port"))
    for event in failure_events:
        if event["event_type"] == "authentication_failure" and (not event.get("attempted_username") or not event.get("source_ip")):
            inferred = explicit_by_pid_source.get((event.get("pid"), event.get("source_ip") or ""))
            if inferred:
                event["attempted_username"] = inferred[0]
                event["username"] = inferred[0]
                if event.get("source_port") is None:
                    event["source_port"] = inferred[1]
            else:
                inferred_by_pid = explicit_by_pid.get(event.get("pid"))
                if inferred_by_pid:
                    event["attempted_username"] = inferred_by_pid[0]
                    event["username"] = inferred_by_pid[0]
                    event["source_ip"] = event.get("source_ip") or inferred_by_pid[1]
                    if event.get("source_port") is None:
                        event["source_port"] = inferred_by_pid[2]
    successes = [event for event in events if event["event_type"] == "login_success"]
    buckets: dict[tuple[str, str, str, str], list[dict]] = defaultdict(list)
    for event in failure_events:
        if not event.get("_dt"):
            continue
        username = event.get("attempted_username") or event.get("username") or "unknown"
        source_ip = event.get("source_ip") or "unknown"
        service = event.get("service") or event.get("process") or "unknown"
        window = str(math.floor(event["_dt"].timestamp() / 900))
        buckets[(username, source_ip, service, window)].append(event)
    groups: list[dict] = []
    for (username, source_ip, service, _window), items in buckets.items():
        explicit_items = [item for item in items if item.get("explicit_failure_count")]
        by_pid_port: dict[tuple[Any, Any], list[dict]] = defaultdict(list)
        for item in items:
            by_pid_port[(item.get("pid"), item.get("source_port"))].append(item)
        effective = 0
        pam_total = 0
        for subitems in by_pid_port.values():
            explicit = sum(int(item.get("explicit_failure_count") or 0) for item in subitems)
            pam_base = sum(1 for item in subitems if item["event_type"] == "authentication_failure" and item.get("aggregate_failure_count") is None)
            pam_more = sum(int(item.get("aggregate_failure_count") or 0) for item in subitems)
            pam_effective = pam_base + pam_more
            pam_total += pam_effective
            effective += max(explicit, pam_effective)
        first = min((item["_dt"] for item in items if item.get("_dt")), default=None)
        last = max((item["_dt"] for item in items if item.get("_dt")), default=None)
        following = [item for item in successes if item.get("_dt") and last and item["_dt"] >= last and (not source_ip or item.get("source_ip") == source_ip)]
        success = min(following, key=lambda item: item["_dt"], default=None)
        if effective < 3:
            continue
        if username == "unknown" and source_ip == "unknown":
            continue
        groups.append({
            "id": f"bf-{username}-{source_ip}-{service}-{int(first.timestamp()) if first else 0}",
            "target_account": username,
            "source_ip": source_ip,
            "service": service,
            "first_seen": _iso(first),
            "last_seen": _iso(last),
            "explicit_failed_events": sum(int(item.get("explicit_failure_count") or 0) for item in items),
            "pam_aggregate_failures": pam_total,
            "effective_attempts": effective,
            "distinct_usernames": sorted({str(item.get("attempted_username") or item.get("username") or "unknown") for item in items}),
            "distinct_source_ips": sorted({str(item.get("source_ip") or "unknown") for item in items}),
            "followed_by_success": bool(success),
            "successful_username": success.get("username") if success else None,
            "time_to_success_seconds": int((success["_dt"] - last).total_seconds()) if success and last else None,
            "status": "suspected",
        })
    return sorted(groups, key=lambda item: item.get("effective_attempts") or 0, reverse=True)


def build_linux_auth_investigation(case_id: str, filters: dict[str, Any] | None = None) -> dict:
    filters = filters or {}
    docs = [doc for doc in _fetch_auth_docs(case_id) if _is_auth_source(doc)]
    all_events = [_event_from_doc(doc) for doc in docs]
    events = _apply_filters(all_events, filters)
    sessions = _reconstruct_sessions(events)
    failures = [event for event in events if event["event_type"] in {"login_failure", "invalid_user", "authentication_failure"}]
    brute_force = _brute_force_groups(events)
    successes = [event for event in events if event["event_type"] == "login_success"]
    last_success = max(successes, key=lambda event: event.get("_dt") or datetime.min.replace(tzinfo=timezone.utc), default=None)
    lastlog = [event for event in events if event.get("artifact_type") == "lastlog"]
    for event in events:
        event.pop("_dt", None)
    return {
        "case_id": case_id,
        "overview": {
            "successful_logins": len(successes),
            "failed_attempts": sum(int(item.get("explicit_failure_count") or 0) for item in failures),
            "effective_failed_attempts": sum(group["effective_attempts"] for group in brute_force) if brute_force else sum(int(item.get("explicit_failure_count") or 0) for item in failures),
            "reconstructed_sessions": len(sessions),
            "suspected_brute_force_groups": len(brute_force),
            "distinct_source_ips": len({event.get("source_ip") for event in events if event.get("source_ip")}),
            "last_successful_login": last_success,
            "lastlog_source_ip_count": len({event.get("source_ip") for event in lastlog if event.get("source_ip")}),
            "lastlog_supported": bool(lastlog),
        },
        "sessions": sessions,
        "failed_authentication": sorted(failures, key=lambda item: item.get("event_time") or ""),
        "brute_force": brute_force,
        "last_login": sorted(lastlog, key=lambda item: item.get("event_time") or "", reverse=True),
        "events": events,
    }
