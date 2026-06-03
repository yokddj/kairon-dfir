from __future__ import annotations

from collections import Counter
import hashlib
import re
from typing import Any
from urllib.parse import quote_plus, urlparse

from sqlalchemy.orm import Session

from app.services.host_identity import normalize_host_alias
from app.services.indicator_resolution import extract_indicators
from app.services.search_service import search_events_v2


MAIL_STORE_EXT_RE = re.compile(r"\.(?:ost|pst|nst|olm|mbox|dbx)(?=$|[\s:;,'\")\]])", re.IGNORECASE)
MESSAGE_FILE_EXT_RE = re.compile(r"\.(?:msg|eml)(?=$|[\s:;,'\")\]])", re.IGNORECASE)
EMAIL_HINT_RE = re.compile(r"([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})", re.IGNORECASE)
WEBMAIL_DOMAINS = {
    "outlook.office.com",
    "office.com",
    "live.com",
    "outlook.live.com",
    "gmail.com",
    "mail.google.com",
}
FILE_SHARING_DOMAINS = {"file.io", "mega.nz", "mediafire.com", "wetransfer.com", "dropbox.com", "drive.google.com"}
ATTACHMENT_CACHE_RE = re.compile(r"(?:content\.outlook|outlook secure temp|\\attachments\\)", re.IGNORECASE)
GENERIC_CACHE_RE = re.compile(r"(?:inetcache|temporary internet files)", re.IGNORECASE)
OUTLOOK_PATH_RE = re.compile(r"\\microsoft\\outlook\\|\\documents\\outlook files\\|content\.outlook|outlook secure temp", re.IGNORECASE)
WINDOWS_MAIL_RE = re.compile(r"microsoft\.windowscommunicationsapps", re.IGNORECASE)
THUNDERBIRD_RE = re.compile(r"\\thunderbird\\", re.IGNORECASE)
MAIL_DOMAIN_RE = re.compile(r"(?:^|[./?&=:_-])(?:owa|webmail|mail)(?:[./?&=:_-]|$)", re.IGNORECASE)
TECHNICAL_TRACE_EXT_RE = re.compile(r"\.(?:etl|log|tmp|cache|dat)(?=$|[\s:;,'\")\]])", re.IGNORECASE)
MAIL_QUERY = ".ost OR .pst OR .msg OR .eml OR Content.Outlook OR outlook.office.com OR file.io"


def list_email_artifacts(db: Session, case_id: str, params: dict[str, Any]) -> dict[str, Any]:
    page = max(1, int(params.get("page") or 1))
    page_size = max(1, min(int(params.get("page_size") or 50), 200))
    host_filter = _as_list(params.get("host"))
    host_filter_normalized = {normalize_host_alias(host).lower() for host in host_filter if str(host).strip()}
    type_filter = {str(item).strip().lower() for item in _as_list(params.get("artifact_type")) if str(item).strip()}
    client_filter = {str(item).strip().lower() for item in _as_list(params.get("client")) if str(item).strip()}
    q = str(params.get("q") or "").strip()
    risk_min = _int_or_none(params.get("risk_min"))
    interesting_only = bool(params.get("interesting_only"))
    include_technical = bool(params.get("include_technical")) or "technical_trace" in type_filter

    warnings: list[str] = []
    rows: list[tuple[str, dict[str, Any]]] = []
    if q:
        rows.extend(_search_source(db, case_id, "mft", ["mft"], q, [], 160, warnings))
        rows.extend(_search_source(db, case_id, "browser", ["browser", "browser_download"], q, [], 80, warnings))
        rows.extend(_search_source(db, case_id, "dns", ["windows_event", "dns"], q, [], 80, warnings))
        rows.extend(_search_source(db, case_id, "user_activity", ["recentdocs", "opensavemru", "userassist", "lnk", "jumplist"], q, [], 80, warnings))
        rows.extend(_search_source(db, case_id, "motw", ["motw", "zone_identifier"], q, [], 50, warnings))
        rows.extend(_search_source(db, case_id, "motw", [], f"{q} Zone.Identifier", [], 25, warnings))
    else:
        rows.extend(_search_source_many(db, case_id, "mft", ["mft"], [".ost", ".pst", ".msg", ".eml", "Content.Outlook", "Outlook Secure Temp", "microsoft.windowscommunicationsapps", "Thunderbird"], [], 40, warnings))
        rows.extend(_search_source_many(db, case_id, "browser", ["browser", "browser_download"], ["outlook.office.com", "office.com/mail", "gmail", "mail.google.com", "webmail", "owa"], [], 25, warnings))
        rows.extend(_search_source_many(db, case_id, "dns", ["windows_event", "dns"], ["outlook.office.com", "mail.google.com", "webmail", "owa"], [], 25, warnings))
        rows.extend(_search_source_many(db, case_id, "user_activity", ["recentdocs", "opensavemru", "userassist", "lnk", "jumplist"], ["Content.Outlook", "Outlook", "Attachments", "sample.iso", ".msg", ".eml"], [], 25, warnings))
        rows.extend(_search_source_many(db, case_id, "motw", ["motw", "zone_identifier"], ["outlook.office.com", "mail.google.com", "webmail", "Content.Outlook", "Outlook Secure Temp"], [], 25, warnings))
        rows.extend(_search_source_many(db, case_id, "motw", [], ["Zone.Identifier", ":Zone.Identifier"], [], 25, warnings))

    items = _group_windows_mail_presence(_dedupe_items([item for item in (_normalize_row(case_id, source, row) for source, row in rows) if item]))
    hidden_technical_count = sum(1 for item in items if item.get("email_artifact_type") == "technical_trace")
    filtered: list[dict[str, Any]] = []
    for item in items:
        if not include_technical and item.get("email_artifact_type") == "technical_trace":
            continue
        if host_filter_normalized and normalize_host_alias(str(item.get("host") or "")).lower() not in host_filter_normalized:
            continue
        if type_filter and str(item.get("email_artifact_type") or "").lower() not in type_filter:
            continue
        if client_filter and str(item.get("client") or "").lower() not in client_filter:
            continue
        if risk_min is not None and int(item.get("risk_score") or 0) < risk_min:
            continue
        if interesting_only and int(item.get("risk_score") or 0) < 30:
            continue
        filtered.append(item)

    _attach_related_context(filtered)
    filtered.sort(key=lambda item: (-(int(item.get("risk_score") or 0)), str(item.get("host") or ""), str(item.get("timestamp") or "")))
    start = (page - 1) * page_size
    page_items = filtered[start : start + page_size]
    summary = _summary(filtered)
    summary["advanced_technical_traces"] = hidden_technical_count
    return {
        "case_id": case_id,
        "total": len(filtered),
        "page": page,
        "page_size": page_size,
        "total_pages": (len(filtered) + page_size - 1) // page_size if filtered else 0,
        "items": page_items,
        "summary": summary,
        "warnings": warnings,
        "limitations": [
            "Mail stores are detected, but OST/PST message content is not parsed in this version.",
            "Account hints are inferred from filenames or paths and are not credentials.",
            "Mail artifact presence does not prove malicious email content.",
            "Windows Mail package internals are grouped as app presence; ETL/cache technical traces are hidden by default.",
        ],
        "attachment_cache_status": "present" if summary["by_type"].get("attachment_cache") else "no_data",
    }


def build_email_artifacts_report_context(db: Session, case_id: str, filters: dict[str, Any]) -> dict[str, Any]:
    result = list_email_artifacts(
        db,
        case_id,
        {
            "host": filters.get("host"),
            "page_size": int(filters.get("max_email_items") or 25),
            "interesting_only": True,
        },
    )
    return {"items": result["items"], "counts": result["summary"], "warnings": result.get("warnings") or [], "limitations": result.get("limitations") or []}


def render_email_artifacts_markdown(items: list[dict[str, Any]]) -> str:
    caveat = "Mail store presence does not prove malicious email content. OST/PST content is not parsed in this version."
    if not items:
        return f"{caveat}\n\nNo email artifacts matched the report filters."
    rows = [["Host", "Type", "Client", "Account hint", "Path / URL", "Parsed", "Related"]]
    for item in items[:50]:
        related = []
        if item.get("related_downloads"):
            related.append("downloads")
        if item.get("related_motw"):
            related.append("MOTW")
        if item.get("related_user_activity"):
            related.append("user activity")
        rows.append(
            [
                str(item.get("host") or "-"),
                str(item.get("email_artifact_type") or "-"),
                str(item.get("client") or "-"),
                str(item.get("account_hint") or "-"),
                _clip(str(item.get("file_path") or item.get("url") or "-"), 100),
                "yes" if item.get("content_parsed") else "no",
                ", ".join(related) or "-",
            ]
        )
    return caveat + "\n\n" + _markdown_table(rows)


def _search_source(db: Session, case_id: str, source: str, artifact_types: list[str], query: str, host_filter: list[str], limit: int, warnings: list[str]) -> list[tuple[str, dict[str, Any]]]:
    try:
        total, rows, _search_warnings, _facets = search_events_v2(
            case_id,
            {
                "q": query,
                "artifact_type": artifact_types,
                "host": host_filter,
                "page_size": limit,
                "sort": "timestamp_desc",
                "include_facets": False,
                "include_highlights": False,
            },
            db=db,
        )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"{source}: {exc}")
        return []
    if total > len(rows):
        warnings.append(f"{source}: showing first {len(rows)} of {total} source matches")
    return [(source, row) for row in rows]


def _search_source_many(db: Session, case_id: str, source: str, artifact_types: list[str], queries: list[str], host_filter: list[str], limit: int, warnings: list[str]) -> list[tuple[str, dict[str, Any]]]:
    rows: list[tuple[str, dict[str, Any]]] = []
    for query in queries:
        rows.extend(_search_source(db, case_id, source, artifact_types, query, host_filter, limit, warnings))
    return rows


def _normalize_row(case_id: str, source: str, row: dict[str, Any]) -> dict[str, Any] | None:
    raw = _obj(row.get("raw"))
    merged = {**raw, **row}
    file = _obj(raw.get("file") or row.get("file"))
    browser = _obj(raw.get("browser") or row.get("browser"))
    event = _obj(raw.get("event") or row.get("event"))
    host = normalize_host_alias(str(_obj(raw.get("host") or row.get("host")).get("name") or row.get("host") or ""))
    file_path = _first(file.get("path"), merged.get("file_path"), merged.get("path"), merged.get("source_file"), row.get("summary"))
    file_name = _first(file.get("name"), _basename(file_path))
    ntfs = _obj(raw.get("ntfs") or row.get("ntfs"))
    download = _obj(raw.get("download") or row.get("download"))
    url = _first(
        browser.get("url"),
        browser.get("domain"),
        merged.get("url"),
        merged.get("host_url"),
        ntfs.get("host_url"),
        ntfs.get("referrer_url"),
        download.get("url"),
        download.get("referrer_url"),
    )
    text = " ".join(str(value or "") for value in (file_path, file_name, url, event.get("message"), row.get("summary"), merged.get("search_text")))
    if not url:
        url = _extract_webmail_reference(text)
    relation_reason, relation_confidence = _email_relation_for_motw(source, file_path, url, text, raw, row)
    email_type = "related_email_download" if relation_reason else classify_email_artifact(text, source)
    if not email_type:
        return None
    client = classify_email_client(text, url)
    account_hint = extract_account_hint(file_name, file_path, text)
    size = _int_or_none(_first(file.get("size"), file.get("size_bytes"), merged.get("size"), merged.get("size_bytes"))) or 0
    timestamp = _first(row.get("timestamp"), merged.get("@timestamp"), file.get("modified"), file.get("created"))
    risk_score, risk_reasons = score_email_item(email_type, client, text, url)
    indicator_input = {"source": {"file_path": file_path, "file_name": file_name, "url": url, "account_hint": account_hint}}
    item = {
        "id": _stable_id(case_id, source, str(row.get("id") or file_path or url or text)),
        "case_id": case_id,
        "evidence_id": merged.get("evidence_id") or row.get("evidence_id"),
        "host": host,
        "artifact_type": "email",
        "email_artifact_type": email_type,
        "client": client,
        "account_hint": account_hint,
        "file_path": file_path if email_type != "webmail_activity" or source not in {"browser", "dns", "network"} else "",
        "file_name": file_name if email_type != "webmail_activity" or source not in {"browser", "dns", "network"} else "",
        "url": url if email_type == "webmail_activity" and source in {"browser", "dns", "network"} else "",
        "extension": _extension(file_name or file_path),
        "size": size,
        "created": _first(file.get("created"), merged.get("created")),
        "modified": _first(file.get("modified"), merged.get("modified"), timestamp),
        "accessed": _first(file.get("accessed"), merged.get("accessed")),
        "timestamp": timestamp,
        "source_artifact": source,
        "source_event_id": str(row.get("id") or merged.get("event_id") or ""),
        "confidence": relation_confidence or ("high" if email_type in {"store", "message_file", "attachment_cache"} and file_path else "medium"),
        "relation_reason": relation_reason,
        "content_parsed": False,
        "risk_score": risk_score,
        "risk_reasons": risk_reasons,
        "related_indicators": (extract_indicators(indicator_input).get("indicators") or [])[:12],
        "related_downloads": [],
        "related_motw": [],
        "related_user_activity": [],
        "search_url": _search_url(case_id, host, url or file_path or file_name),
        "timeline_url": _timeline_url(case_id, host, timestamp, url or file_path or file_name),
        "raw": raw or row,
    }
    return item


def classify_email_artifact(text: str, source: str = "") -> str | None:
    value = str(text or "")
    lower = value.lower()
    source_key = str(source or "").lower()
    if MAIL_STORE_EXT_RE.search(value):
        return "store"
    if MESSAGE_FILE_EXT_RE.search(value):
        return "message_file"
    if ATTACHMENT_CACHE_RE.search(value):
        return "attachment_cache"
    if WINDOWS_MAIL_RE.search(value):
        if TECHNICAL_TRACE_EXT_RE.search(value):
            return "technical_trace"
        return "app_presence"
    if source_key == "motw":
        return None
    if _has_webmail_context(lower) and (not source_key or source_key in {"browser", "browser_download", "network", "dns"}):
        return "webmail_activity"
    if source_key in {"browser", "network", "dns"} and MAIL_DOMAIN_RE.search(lower):
        return "webmail_activity"
    if source_key == "browser" and GENERIC_CACHE_RE.search(value) and _has_webmail_context(lower):
        return "webmail_activity"
    if OUTLOOK_PATH_RE.search(value) or THUNDERBIRD_RE.search(value):
        return "profile"
    return None


def classify_email_client(text: str, url: str = "") -> str:
    blob = f"{text or ''} {url or ''}".lower()
    if "thunderbird" in blob:
        return "thunderbird"
    if "windowscommunicationsapps" in blob or "windows mail" in blob:
        return "windows_mail"
    if "outlook" in blob or "office.com" in blob or "microsoft\\outlook" in blob:
        return "outlook"
    if any(domain in blob for domain in WEBMAIL_DOMAINS) or "webmail" in blob or "gmail" in blob:
        return "browser_webmail"
    return "unknown"


def extract_account_hint(file_name: str = "", file_path: str = "", text: str = "") -> str:
    for value in (file_name, file_path, text):
        candidate = re.sub(r"\.(?:ost|pst|nst|olm|mbox|dbx|tmp)$", "", str(value or ""), flags=re.IGNORECASE)
        candidate = re.sub(r"\.(?:ost|pst|nst|olm|mbox|dbx|tmp)$", "", candidate, flags=re.IGNORECASE)
        match = EMAIL_HINT_RE.search(candidate)
        if match:
            return match.group(1)
    return ""


def score_email_item(email_type: str, client: str, text: str, url: str = "") -> tuple[int, list[str]]:
    score = 5 if email_type in {"app_presence", "technical_trace"} else 10
    reasons: list[str] = []
    lower = f"{text or ''} {url or ''}".lower()
    if email_type == "store":
        score += 25
        reasons.append("mail_store_detected")
    if email_type == "message_file":
        score += 25
        reasons.append("standalone_message_file")
    if email_type == "attachment_cache":
        score += 25
        reasons.append("mail_attachment_cache_path")
    if email_type == "webmail_activity":
        score += 20
        reasons.append("webmail_activity")
    if email_type == "related_email_download":
        score += 15
        reasons.append("related_email_download")
    if email_type == "app_presence":
        reasons.append("mail_app_presence")
    if email_type == "technical_trace":
        reasons.append("mail_app_technical_trace")
    if email_type not in {"app_presence", "technical_trace"} and any(domain in lower for domain in FILE_SHARING_DOMAINS):
        score += 25
        reasons.append("file_sharing_activity")
    if email_type not in {"app_presence", "technical_trace"} and re.search(r"\.(?:iso|zip|7z|rar|exe|dll|ps1|lnk|docm|xlsm)(?:$|\\|/|:|\\s)", lower):
        score += 20
        reasons.append("download_or_attachment_extension_of_interest")
    if client in {"outlook", "thunderbird", "windows_mail", "browser_webmail"}:
        reasons.append(f"{client}_artifact")
    if not reasons:
        reasons.append("email_related_artifact")
    return min(score, 100), reasons


def _attach_related_context(items: list[dict[str, Any]]) -> None:
    downloads = [item for item in items if item["email_artifact_type"] == "webmail_activity"]
    motw = [item for item in items if item["email_artifact_type"] == "related_email_download" and item["source_artifact"] == "motw"]
    user_activity = [item for item in items if item["source_artifact"] == "user_activity"]
    for item in items:
        if item["email_artifact_type"] in {"store", "profile", "app_presence"}:
            item["related_downloads"] = _summaries(downloads[:5])
            item["related_motw"] = _summaries(motw[:5])
            item["related_user_activity"] = _summaries(user_activity[:5])
        elif item["email_artifact_type"] == "webmail_activity":
            item["related_motw"] = _summaries(motw[:5])
            item["related_user_activity"] = _summaries(user_activity[:5])


def _summaries(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": item.get("id"),
            "host": item.get("host"),
            "timestamp": item.get("timestamp"),
            "label": item.get("file_name") or item.get("file_path") or item.get("url") or item.get("source_artifact"),
            "search_url": item.get("search_url"),
            "relation_reason": item.get("relation_reason") or "",
            "confidence": item.get("confidence") or "",
        }
        for item in items
    ]


def _summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    by_host = Counter(str(item.get("host") or "unknown") for item in items)
    by_type = Counter(str(item.get("email_artifact_type") or "unknown") for item in items)
    by_client = Counter(str(item.get("client") or "unknown") for item in items)
    by_source = Counter(str(item.get("source_artifact") or "unknown") for item in items)
    return {
        "total": len(items),
        "stores": by_type.get("store", 0),
        "message_files": by_type.get("message_file", 0),
        "attachment_cache": by_type.get("attachment_cache", 0),
        "webmail_activity": by_type.get("webmail_activity", 0),
        "related_email_downloads": by_type.get("related_email_download", 0),
        "app_presence": by_type.get("app_presence", 0),
        "technical_traces": by_type.get("technical_trace", 0),
        "interesting": sum(1 for item in items if int(item.get("risk_score") or 0) >= 30),
        "by_host": dict(sorted(by_host.items())),
        "by_type": dict(sorted(by_type.items())),
        "by_client": dict(sorted(by_client.items())),
        "by_source": dict(sorted(by_source.items())),
    }


def _dedupe_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for item in items:
        key = "|".join(str(item.get(field) or "").lower() for field in ("host", "email_artifact_type", "file_path", "url", "source_event_id"))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _group_windows_mail_presence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    result: list[dict[str, Any]] = []
    for item in items:
        if item.get("email_artifact_type") != "app_presence" or item.get("client") != "windows_mail":
            result.append(item)
            continue
        host = str(item.get("host") or "unknown")
        user = _windows_user_from_path(str(item.get("file_path") or ""))
        key = (host.lower(), user.lower(), "windows_mail")
        existing = grouped.get(key)
        if existing:
            existing["grouped_source_count"] = int(existing.get("grouped_source_count") or 1) + 1
            if not existing.get("timestamp") and item.get("timestamp"):
                existing["timestamp"] = item.get("timestamp")
            continue
        display_user = user or "system-wide"
        grouped_item = {**item}
        grouped_item.update(
            {
                "id": _stable_id(str(item.get("case_id") or ""), "windows_mail_app_presence", "|".join(key)),
                "email_artifact_type": "app_presence",
                "client": "windows_mail",
                "account_hint": user,
                "file_path": f"Windows Mail package presence ({display_user})",
                "file_name": "microsoft.windowscommunicationsapps",
                "extension": "",
                "confidence": "low",
                "risk_score": 5,
                "risk_reasons": ["windows_mail_app_presence_grouped"],
                "grouped_source_count": 1,
                "search_url": _search_url(str(item.get("case_id") or ""), host, "microsoft.windowscommunicationsapps"),
                "timeline_url": _timeline_url(str(item.get("case_id") or ""), host, item.get("timestamp"), "microsoft.windowscommunicationsapps"),
            }
        )
        grouped[key] = grouped_item
        result.append(grouped_item)
    return result


def _windows_user_from_path(path: str) -> str:
    match = re.search(r"(?:^|[\\/])users[\\/]([^\\/]+)", str(path or ""), re.IGNORECASE)
    return match.group(1) if match else ""


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, tuple | set):
        return [str(item) for item in value if str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _int_or_none(value: Any) -> int | None:
    try:
        if value in {None, ""}:
            return None
        return int(value)
    except Exception:
        return None


def _basename(path: str) -> str:
    text = str(path or "").replace("/", "\\").rstrip("\\")
    return text.rsplit("\\", 1)[-1] if text else ""


def _extension(path: str) -> str:
    name = _basename(path)
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1].lower()


def _domain(url: str) -> str:
    parsed = urlparse(str(url or ""))
    return (parsed.netloc or parsed.path.split("/", 1)[0]).lower()


def _has_webmail_context(text: str) -> bool:
    lower = str(text or "").lower()
    if "outlook.office.com" in lower or "outlook.live.com" in lower or "mail.google.com" in lower:
        return True
    if "office.com" in lower and re.search(r"(?:/|%2f|\b)(?:mail|outlook)(?:/|\b|%2f)", lower):
        return True
    if "gmail.com" in lower and re.search(r"(?:/|\b)mail(?:/|\b)", lower):
        return True
    return bool(MAIL_DOMAIN_RE.search(lower))


def _extract_webmail_reference(text: str) -> str:
    lower = str(text or "").lower()
    for domain in ("outlook.office.com", "outlook.live.com", "mail.google.com"):
        if domain in lower:
            return domain
    if "office.com" in lower and re.search(r"(?:/|%2f|\b)(?:mail|outlook)(?:/|\b|%2f)", lower):
        return "office.com"
    match = re.search(r"\b(?:owa|webmail|mail)(?:\.[a-z0-9.-]+\.[a-z]{2,})?\b", lower)
    return match.group(0) if match else ""


def _email_relation_for_motw(source: str, file_path: str, url: str, text: str, raw: dict[str, Any], row: dict[str, Any]) -> tuple[str, str]:
    if str(source or "").lower() != "motw":
        return "", ""
    path_blob = str(file_path or "")
    if ATTACHMENT_CACHE_RE.search(path_blob):
        return "MOTW base path is inside Outlook attachment cache.", "high"
    ntfs = _obj(raw.get("ntfs") or row.get("ntfs"))
    download = _obj(raw.get("download") or row.get("download"))
    event = _obj(raw.get("event") or row.get("event"))
    urls = " ".join(
        str(value or "")
        for value in (
            url,
            ntfs.get("host_url"),
            ntfs.get("referrer_url"),
            download.get("url"),
            download.get("referrer_url"),
            raw.get("host_url"),
            raw.get("referrer_url"),
            event.get("message"),
            text,
        )
    )
    if _has_webmail_context(urls):
        return "Zone.Identifier HostUrl or ReferrerUrl points to an explicit webmail/mail domain.", "high"
    return "", ""


def _stable_id(case_id: str, source: str, material: str) -> str:
    return "email-" + hashlib.sha1(f"{case_id}|{source}|{material}".encode("utf-8", errors="ignore")).hexdigest()[:24]


def _search_url(case_id: str, host: str, query: str) -> str:
    params = [f"q={quote_plus(str(query or ''))}"]
    if host:
        params.append(f"host={quote_plus(host)}")
    return f"/cases/{case_id}/search?{'&'.join(params)}"


def _timeline_url(case_id: str, host: str, timestamp: Any, query: str) -> str:
    params = [f"q={quote_plus(str(query or ''))}", "view=timeline"]
    if host:
        params.append(f"host={quote_plus(host)}")
    if timestamp:
        params.append(f"time_anchor={quote_plus(str(timestamp))}")
    return f"/cases/{case_id}/search?{'&'.join(params)}"


def _markdown_table(rows: list[list[str]]) -> str:
    if not rows:
        return ""
    header = "| " + " | ".join(rows[0]) + " |"
    divider = "| " + " | ".join("---" for _ in rows[0]) + " |"
    body = ["| " + " | ".join(str(cell).replace("|", "\\|") for cell in row) + " |" for row in rows[1:]]
    return "\n".join([header, divider, *body])


def _clip(value: str, limit: int) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"
