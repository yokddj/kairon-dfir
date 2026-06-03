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


ZONE_ADS_SUFFIX_RE = re.compile(r":Zone\.Identifier$", re.IGNORECASE)
ZONE_ID_RE = re.compile(r"^\s*ZoneId\s*=\s*(\d+)\s*$", re.IGNORECASE | re.MULTILINE)
HOST_URL_RE = re.compile(r"^\s*HostUrl\s*=\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
REFERRER_URL_RE = re.compile(r"^\s*ReferrerUrl\s*=\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
LAST_WRITER_RE = re.compile(r"^\s*LastWriterPackageFamilyName\s*=\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
USER_WRITABLE_RE = re.compile(r"\\(?:users\\[^\\]+\\(?:downloads|desktop|appdata)|users\\public|programdata|temp|windows\\temp)\\", re.IGNORECASE)
DOWNLOAD_EXT_RE = re.compile(r"\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|lnk|scr|pif|msi|iso|zip|7z|rar|cab)(?:$|:)", re.IGNORECASE)
FILE_SHARING_DOMAINS = {"file.io", "mega.nz", "mediafire.com", "dropbox.com", "drive.google.com", "onedrive.live.com", "wetransfer.com"}

ZONE_NAMES = {
    0: "Local Machine",
    1: "Local Intranet",
    2: "Trusted Sites",
    3: "Internet",
    4: "Restricted Sites",
}


def parse_zone_identifier_content(content: str | None) -> dict[str, Any]:
    text = str(content or "")
    zone_match = ZONE_ID_RE.search(text)
    host_match = HOST_URL_RE.search(text)
    referrer_match = REFERRER_URL_RE.search(text)
    writer_match = LAST_WRITER_RE.search(text)
    zone_id = int(zone_match.group(1)) if zone_match else None
    return {
        "zone_id": zone_id,
        "zone_name": zone_name(zone_id),
        "host_url": host_match.group(1).strip() if host_match else "",
        "referrer_url": referrer_match.group(1).strip() if referrer_match else "",
        "last_writer_package_family_name": writer_match.group(1).strip() if writer_match else "",
        "raw_content": text,
    }


def zone_name(zone_id: int | None) -> str:
    if zone_id is None:
        return "Unknown"
    return ZONE_NAMES.get(int(zone_id), "Unknown")


def base_file_from_ads(path: str) -> str:
    return ZONE_ADS_SUFFIX_RE.sub("", str(path or ""))


def list_motw_items(db: Session, case_id: str, params: dict[str, Any]) -> dict[str, Any]:
    page = max(1, int(params.get("page") or 1))
    page_size = max(1, min(int(params.get("page_size") or 50), 200))
    host_filter = _as_list(params.get("host"))
    q = str(params.get("q") or "").strip()
    zone_id_filter = {int(item) for item in _as_list(params.get("zone_id")) if str(item).isdigit()}
    extension_filter = {("." + str(item).lstrip(".").lower()) for item in _as_list(params.get("extension")) if str(item).strip()}
    source_filter = {str(item).strip().lower() for item in _as_list(params.get("source")) if str(item).strip()}
    risk_min = _int_or_none(params.get("risk_min"))

    fetched: list[dict[str, Any]] = []
    warnings: list[str] = []
    if not source_filter or "mft_ads" in source_filter:
        fetched.extend(_search_source(db, case_id, "mft_ads", ["mft"], q or "Zone.Identifier", host_filter, 75, warnings))
    if not source_filter or "sysmon_15" in source_filter:
        fetched.extend(_search_source(db, case_id, "sysmon_15", ["windows_event", "sysmon"], q or "Zone.Identifier", host_filter, 75, warnings))
    if q and (not source_filter or "browser_correlation" in source_filter):
        fetched.extend(_search_source(db, case_id, "browser_correlation", ["browser", "browser_download"], q, host_filter, 30, warnings))

    items = _dedupe_items([item for item in (_normalize_row(case_id, row, source) for source, row in fetched) if item])
    filtered: list[dict[str, Any]] = []
    for item in items:
        if zone_id_filter and item.get("zone_id") not in zone_id_filter:
            continue
        if extension_filter and str(item.get("file_extension") or "").lower() not in extension_filter:
            continue
        if risk_min is not None and int(item.get("risk_score") or 0) < risk_min:
            continue
        filtered.append(item)

    filtered.sort(key=lambda item: (-(int(item.get("risk_score") or 0)), str(item.get("timestamp") or ""), str(item.get("file_path") or "")), reverse=False)
    start = (page - 1) * page_size
    page_items = filtered[start : start + page_size]
    summary = _summary(filtered)
    return {
        "case_id": case_id,
        "total": len(filtered),
        "page": page,
        "page_size": page_size,
        "total_pages": (len(filtered) + page_size - 1) // page_size if filtered else 0,
        "items": page_items,
        "summary": summary,
        "warnings": warnings,
    }


def build_motw_report_context(db: Session, case_id: str, filters: dict[str, Any]) -> dict[str, Any]:
    result = list_motw_items(
        db,
        case_id,
        {
            "host": filters.get("host"),
            "page_size": int(filters.get("max_motw_items") or 25),
            "risk_min": filters.get("risk_min") or 30,
        },
    )
    return {"items": result["items"], "counts": result["summary"], "warnings": result.get("warnings") or []}


def render_motw_markdown(items: list[dict[str, Any]]) -> str:
    if not items:
        return "No Mark-of-the-Web / Zone.Identifier items matched the report filters."
    rows = [["Host", "File", "Zone", "HostUrl", "ReferrerUrl", "Risk", "Source"]]
    for item in items[:50]:
        rows.append(
            [
                str(item.get("host") or "-"),
                _clip(str(item.get("file_path") or item.get("file_name") or "-"), 100),
                f"{item.get('zone_id') if item.get('zone_id') is not None else '-'} {item.get('zone_name') or ''}".strip(),
                _clip(str(item.get("host_url") or item.get("source_url") or "-"), 80),
                _clip(str(item.get("referrer_url") or "-"), 80),
                str(item.get("risk_score") or 0),
                str(item.get("source_artifact") or "-"),
            ]
        )
    return _markdown_table(rows)


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


def _normalize_row(case_id: str, row: dict[str, Any], source: str) -> dict[str, Any] | None:
    raw = _obj(row.get("raw"))
    event = _obj(raw.get("event") or row.get("event"))
    artifact = _obj(raw.get("artifact") or row.get("artifact"))
    file = _obj(raw.get("file") or row.get("file"))
    windows = _obj(raw.get("windows") or row.get("windows"))
    sysmon = _obj(raw.get("sysmon") or row.get("sysmon"))
    host = normalize_host_alias(str(_obj(raw.get("host") or row.get("host")).get("name") or row.get("host") or ""))
    message = " ".join(str(value or "") for value in (event.get("message"), raw.get("raw_summary"), row.get("summary"), raw.get("search_text")))
    event_data = _obj(windows.get("event_data") or raw.get("event_data") or event.get("data"))
    target = _first(
        event_data.get("TargetFilename"),
        event_data.get("targetfilename"),
        file.get("path"),
        raw.get("file_path"),
        row.get("source_file"),
    )
    contents = _first(event_data.get("Contents"), event_data.get("contents"), raw.get("zone_identifier_content"), message if "[ZoneTransfer]" in message else "")
    parsed = parse_zone_identifier_content(contents)
    urls = URL_RE.findall(" ".join(str(value or "") for value in (contents, message, event_data)))
    host_url = parsed["host_url"] or _first(event_data.get("HostUrl"), event_data.get("hosturl"))
    referrer_url = parsed["referrer_url"] or _first(event_data.get("ReferrerUrl"), event_data.get("referrerurl"))
    if not host_url and urls:
        host_url = urls[0].rstrip(".,);]")
    zone_path = target if ZONE_ADS_SUFFIX_RE.search(target) else _first(file.get("path"), target)
    base_path = base_file_from_ads(zone_path)
    if source == "browser_correlation":
        base_path = _first(file.get("path"), raw.get("download", {}).get("target_path") if isinstance(raw.get("download"), dict) else "", row.get("summary"))
        zone_path = f"{base_path}:Zone.Identifier" if base_path else ""
        host_url = host_url or _first(_obj(raw.get("download")).get("url"), raw.get("url"))
    if not ZONE_ADS_SUFFIX_RE.search(zone_path) and "zone.identifier" not in message.lower() and source != "browser_correlation":
        return None
    zone_id = parsed["zone_id"]
    risk_score, risk_reasons = _score_motw(base_path, zone_id, host_url, referrer_url, message)
    file_name = _basename(base_path)
    item = {
        "id": _stable_id(case_id, source, str(row.get("id") or raw.get("event_id") or zone_path or base_path)),
        "case_id": case_id,
        "evidence_id": raw.get("evidence_id") or row.get("evidence_id"),
        "host": host,
        "artifact_type": "motw",
        "file_path": base_path,
        "file_name": file_name,
        "file_extension": _extension(file_name),
        "zone_identifier_path": zone_path,
        "zone_id": zone_id,
        "zone_name": parsed["zone_name"],
        "host_url": host_url,
        "referrer_url": referrer_url,
        "source_url": host_url or referrer_url,
        "browser_download_id": str(raw.get("browser_download_id") or ""),
        "timestamp": row.get("timestamp") or raw.get("@timestamp") or row.get("@timestamp"),
        "source_artifact": source,
        "source_event_id": str(row.get("id") or raw.get("event_id") or ""),
        "hashes": _hashes(event_data, sysmon, raw),
        "raw_content": parsed["raw_content"],
        "risk_score": risk_score,
        "risk_reasons": risk_reasons,
        "linked": _linked(case_id, host, base_path, host_url, row.get("timestamp") or raw.get("@timestamp")),
        "indicator_resolution": (extract_indicators({"source": {"file_path": base_path, "zone_identifier_path": zone_path, "host_url": host_url, "referrer_url": referrer_url}}).get("indicators") or [])[:12],
        "search_url": _search_url(case_id, host, base_path or zone_path),
        "timeline_url": _timeline_url(case_id, host, row.get("timestamp") or raw.get("@timestamp"), base_path or zone_path),
        "raw": raw or row,
    }
    return item


def _score_motw(base_path: str, zone_id: int | None, host_url: str, referrer_url: str, message: str) -> tuple[int, list[str]]:
    score = 10
    reasons: list[str] = []
    if zone_id in {3, 4}:
        score += 20 if zone_id == 3 else 30
        reasons.append("internet_or_restricted_zone")
    if DOWNLOAD_EXT_RE.search(base_path):
        score += 25
        reasons.append("downloaded_executable_script_archive_or_iso")
    if USER_WRITABLE_RE.search(base_path):
        score += 20
        reasons.append("user_writable_download_path")
    domain = _domain(host_url)
    if domain and any(domain == item or domain.endswith(f".{item}") for item in FILE_SHARING_DOMAINS):
        score += 20
        reasons.append("file_sharing_host_url")
    if referrer_url and _domain(referrer_url) and _domain(referrer_url) != domain:
        score += 10
        reasons.append("external_referrer")
    if "filecreatestreamhash" in message.lower():
        reasons.append("sysmon_file_create_stream_hash")
    if not reasons:
        reasons.append("mark_of_the_web")
    return min(score, 100), reasons


def _linked(case_id: str, host: str, base_path: str, host_url: str, timestamp: Any) -> dict[str, Any]:
    basename = _basename(base_path)
    return {
        "base_file_search": _search_url(case_id, host, base_path or basename),
        "browser_search": _search_url(case_id, host, host_url or basename),
        "user_activity_search": f"/cases/{case_id}/search?artifact_type=recentdocs&artifact_type=opensavemru&artifact_type=lnk&q={quote_plus(basename)}" + (f"&host={quote_plus(host)}" if host else ""),
        "execution_search": f"/cases/{case_id}/command-history?q={quote_plus(basename)}" + (f"&host={quote_plus(host)}" if host else ""),
        "timeline_around": _timeline_url(case_id, host, timestamp, base_path or basename),
    }


def _dedupe_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for item in items:
        key = "|".join(str(item.get(part) or "").lower() for part in ("host", "file_path", "zone_identifier_path", "source_artifact", "source_event_id"))
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "total": len(items),
        "suspicious": sum(1 for item in items if int(item.get("risk_score") or 0) >= 40),
        "high_risk": sum(1 for item in items if int(item.get("risk_score") or 0) >= 70),
        "by_host": dict(Counter(str(item.get("host") or "unknown") for item in items)),
        "by_zone": dict(Counter(str(item.get("zone_id") if item.get("zone_id") is not None else "unknown") for item in items)),
        "by_source": dict(Counter(str(item.get("source_artifact") or "unknown") for item in items)),
        "by_extension": dict(Counter(str(item.get("file_extension") or "unknown") for item in items)),
    }


def _hashes(*sources: Any) -> dict[str, str]:
    text = " ".join(str(source or "") for source in sources)
    result: dict[str, str] = {}
    for algo, length in (("md5", 32), ("sha1", 40), ("sha256", 64)):
        match = re.search(rf"\b[A-Fa-f0-9]{{{length}}}\b", text)
        if match:
            result[algo] = match.group(0).lower()
    return result


def _as_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]


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
        if value is None or value == "":
            return None
        return int(value)
    except Exception:
        return None


def _basename(path: str) -> str:
    base = base_file_from_ads(str(path or ""))
    return base.replace("/", "\\").rsplit("\\", 1)[-1]


def _extension(name: str) -> str:
    text = str(name or "")
    if "." not in text:
        return ""
    return "." + text.rsplit(".", 1)[-1].lower()


def _domain(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        return parsed.netloc.lower()
    except Exception:
        return ""


def _stable_id(case_id: str, source: str, value: Any) -> str:
    material = f"{case_id}|{source}|{value}"
    return "motw-" + hashlib.sha1(material.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _search_url(case_id: str, host: str, query: str) -> str:
    params = []
    if host:
        params.append(f"host={quote_plus(host)}")
    if query:
        params.append(f"q={quote_plus(_clip(query, 180))}")
    return f"/cases/{case_id}/search" + (f"?{'&'.join(params)}" if params else "")


def _timeline_url(case_id: str, host: str, timestamp: Any, query: str) -> str:
    params = ["view=timeline"]
    if host:
        params.append(f"host={quote_plus(host)}")
    if query:
        params.append(f"q={quote_plus(_clip(str(query), 180))}")
    if timestamp:
        params.append(f"timestamp={quote_plus(str(timestamp))}")
    return f"/cases/{case_id}/search?{'&'.join(params)}"


def _clip(value: str, limit: int) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[: limit - 1] + "..."


def _markdown_table(rows: list[list[str]]) -> str:
    if not rows:
        return ""
    header = rows[0]
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    for row in rows[1:]:
        lines.append("| " + " | ".join(str(cell).replace("|", "\\|").replace("\n", " ") for cell in row) + " |")
    return "\n".join(lines)
