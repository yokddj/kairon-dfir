from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PureWindowsPath
import re
from urllib.parse import parse_qs, unquote, urlparse

from dateutil import parser as date_parser

from app.analysis.suspicious import detect_suspicious_path, is_suspicious_double_extension
from app.ingest.identity_extraction import extract_user_from_path


SEARCH_ENGINES = {
    "google.": ("Google", "q"),
    "bing.com": ("Bing", "q"),
    "duckduckgo.com": ("DuckDuckGo", "q"),
    "search.yahoo.com": ("Yahoo", "p"),
    "yandex.": ("Yandex", "text"),
}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".msi"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".img"}
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}
SUSPICIOUS_EXECUTABLE_KEYWORDS = {"payload", "update", "invoice", "document", "setup", "installer", "crack", "keygen"}
TRUSTED_BROWSER_DOMAINS = {
    "windowsupdate.com",
    "download.windowsupdate.com",
    "update.microsoft.com",
    "microsoft.com",
    "microsoftonline.com",
    "office.com",
    "live.com",
    "defender.microsoft.com",
    "windows.com",
}
SUSPICIOUS_DOWNLOAD_TOKENS = ["ngrok", "pastebin", "githubusercontent", "discord", "telegram", "mega", "mediafire", "transfer.sh", "file.io", "anonfiles", "rclone", "anydesk", "teamviewer"]
PASTE_SITES = ["pastebin", "paste.ee", "ghostbin", "paste.rs"]
REMOTE_ACCESS_TOOLS = ["anydesk", "teamviewer", "screenconnect", "connectwise", "splashtop", "rustdesk"]
FILE_SHARING_DOMAINS = ["mega", "mediafire", "transfer.sh", "file.io", "anonfiles", "githubusercontent", "discord"]
SUSPICIOUS_NAME_TOKENS = ["password", "credentials", "cred", "secret", "token", "key", "backup", "dump", "mimikatz", "procdump", "rclone", "anydesk", "teamviewer", "ngrok", "plink", "psexec"]


def first_value(row: dict, candidates: list[str]) -> str | None:
    candidate_map = {str(key).lower(): value for key, value in row.items()}
    for candidate in candidates:
        value = candidate_map.get(candidate.lower())
        if value not in (None, ""):
            return str(value)
    return None


@dataclass
class BrowserAudit:
    records_read: int = 0
    records_parsed: int = 0
    history_count: int = 0
    download_count: int = 0
    search_count: int = 0
    suspicious_download_count: int = 0
    executable_download_count: int = 0
    archive_download_count: int = 0
    missing_timestamp: int = 0
    missing_url: int = 0
    missing_path: int = 0
    top_domains: Counter | None = None
    top_download_extensions: Counter | None = None
    browsers_seen: Counter | None = None
    profiles_seen: Counter | None = None

    def __post_init__(self) -> None:
        self.top_domains = self.top_domains or Counter()
        self.top_download_extensions = self.top_download_extensions or Counter()
        self.browsers_seen = self.browsers_seen or Counter()
        self.profiles_seen = self.profiles_seen or Counter()

    def as_dict(self, *, artifact_name: str, parser_name: str = "browser_csv", bulk_index_errors: int = 0) -> dict:
        return {
            "artifact": artifact_name,
            "parser": parser_name,
            "artifact_type": "browser",
            "records_read": self.records_read,
            "records_parsed": self.records_parsed,
            "events_indexed": self.records_parsed,
            "records_indexed": self.records_parsed,
            "records_failed": 0,
            "history_count": self.history_count,
            "download_count": self.download_count,
            "search_count": self.search_count,
            "suspicious_download_count": self.suspicious_download_count,
            "executable_download_count": self.executable_download_count,
            "archive_download_count": self.archive_download_count,
            "missing_timestamp": self.missing_timestamp,
            "missing_url": self.missing_url,
            "missing_path": self.missing_path,
            "top_domains": dict(self.top_domains.most_common(15)),
            "top_download_extensions": dict(self.top_download_extensions.most_common(15)),
            "browsers_seen": dict(self.browsers_seen.most_common(10)),
            "profiles_seen": dict(self.profiles_seen.most_common(10)),
            "bulk_index_errors": bulk_index_errors,
        }


def _clean(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if text in {"", "-", "--", "N/A", "n/a", "null", "None"}:
        return None
    return text


def _first(row: dict, names: list[str]) -> str | None:
    return _clean(first_value(row, names))


def _looks_like_windows_path(value: str | None) -> bool:
    if not value:
        return False
    return bool(re.match(r"^[A-Za-z]:\\", value)) or value.startswith("\\\\")


def _normalize_windows_path(value: str | None) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    for _ in range(3):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    text = text.replace("/", "\\").strip()
    return _clean(text)


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    cleaned = _normalize_windows_path(path) or str(path)
    try:
        return PureWindowsPath(cleaned).name or cleaned.split("/")[-1]
    except Exception:  # noqa: BLE001
        return cleaned.split("\\")[-1].split("/")[-1]


def _suffix(path: str | None) -> str | None:
    name = _basename(path)
    if not name or "." not in name:
        return None
    suffix = "." + name.split(".")[-1]
    return suffix.lower()


def _derive_browser_name(raw_name: str | None, source_path: str | None, artifact_name: str | None, profile_path: str | None) -> str:
    candidates = [raw_name, source_path, artifact_name, profile_path]
    for candidate in candidates:
        text = str(candidate or "").lower()
        if "brave" in text:
            return "Brave"
        if "firefox" in text or "places.sqlite" in text:
            return "Firefox"
        if "msedge" in text or "edge" in text:
            return "Edge"
        if "iexplore" in text or "internet explorer" in text or "webcache" in text:
            return "Internet Explorer"
        if "chrome" in text:
            return "Chrome"
    return "Unknown"


def _derive_profile(row: dict, source_path: str | None, profile_path: str | None) -> str | None:
    explicit = _first(row, ["Profile", "ProfileName"])
    if explicit:
        return explicit
    for candidate in [profile_path, source_path]:
        text = str(candidate or "")
        match = re.search(r"(Default|Profile \d+|Guest Profile|System Profile|[A-Za-z0-9._-]{6,}\.default-release)", text, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def _infer_user(row: dict, source_path: str | None, profile_path: str | None, file_path: str | None) -> str | None:
    for candidate in [_first(row, ["User", "Username"]), source_path, profile_path, file_path]:
        normalized_candidate = _normalize_windows_path(candidate) if candidate else None
        user = extract_user_from_path(normalized_candidate or candidate) if candidate else None
        if user:
            return user
    return None


def _parse_browser_timestamp(value: str | None) -> tuple[str | None, str]:
    cleaned = _clean(value)
    if not cleaned:
        return None, "unknown"
    try:
        parsed = date_parser.parse(cleaned)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.isoformat(), "exact"
    except Exception:  # noqa: BLE001
        pass
    if cleaned.isdigit():
        raw = int(cleaned)
        try:
            if raw > 10000000000000000:
                seconds = (raw / 1_000_000) - 11644473600
                parsed = datetime.fromtimestamp(seconds, tz=UTC)
                return parsed.isoformat(), "windows_filetime"
            if raw > 100000000000000:
                parsed = datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=raw)
                return parsed.isoformat(), "webkit"
            if raw > 1000000000000:
                parsed = datetime.fromtimestamp(raw / 1000, tz=UTC)
                return parsed.isoformat(), "unix_millis"
            if raw > 1000000000:
                parsed = datetime.fromtimestamp(raw, tz=UTC)
                return parsed.isoformat(), "unix_seconds"
        except Exception:  # noqa: BLE001
            return None, "unknown"
    return None, "unknown"


def _timestamp_out_of_range(timestamp: str | None) -> bool:
    if not timestamp:
        return False
    try:
        parsed = date_parser.parse(timestamp)
    except Exception:  # noqa: BLE001
        return True
    return parsed.year < 1990 or parsed.year > 2100


def _to_int(value: object | None) -> int | None:
    cleaned = _clean(value)
    if not cleaned:
        return None
    try:
        return int(float(cleaned))
    except Exception:  # noqa: BLE001
        return None


def _normalize_download_state(value: str | None) -> str:
    cleaned = str(_clean(value) or "").strip().lower()
    if cleaned in {"complete", "completed", "downloaded"}:
        return "complete"
    if cleaned in {"in_progress", "in progress", "progress", "transferring"}:
        return "in_progress"
    if cleaned in {"interrupted", "interrupt"}:
        return "interrupted"
    if cleaned in {"cancelled", "canceled"}:
        return "cancelled"
    return "unknown"


def _is_trusted_browser_domain(domain: str | None) -> bool:
    lowered = str(domain or "").lower().strip(".")
    if not lowered:
        return False
    return any(lowered == root or lowered.endswith(f".{root}") for root in TRUSTED_BROWSER_DOMAINS)


def _is_user_writable_path(path: str | None) -> bool:
    lowered = str(path or "").replace("/", "\\").lower()
    return any(
        token in lowered
        for token in [
            "\\users\\",
            "\\downloads\\",
            "\\desktop\\",
            "\\appdata\\local\\temp\\",
            "\\appdata\\roaming\\",
            "\\users\\public\\",
            "\\startup\\",
        ]
    )


def _canonical_browser_parser(*, parser: str | None, subtype: str, browser_name: str, source_format: str | None, source_file: str | None) -> str:
    lowered_parser = str(parser or "").lower()
    lowered_source = str(source_file or "").replace("/", "\\").lower()
    lowered_format = str(source_format or "").lower()
    if lowered_parser in {"browser_chromium_history", "browser_chromium_downloads", "browser_firefox_places", "browser_json", "browser_jsonl", "browser_csv"}:
        return lowered_parser
    if lowered_parser in {"browserhistoryview", "browser_history_view", "generic_browser", "generic_csv"}:
        return "browser_csv"
    if lowered_format == "json":
        return "browser_json"
    if lowered_format == "jsonl":
        return "browser_jsonl"
    if lowered_format == "csv":
        return "browser_csv"
    if lowered_parser in {"sqlite_chromium"}:
        return "browser_chromium_downloads" if subtype == "download" else "browser_chromium_history"
    if lowered_parser in {"sqlite_firefox"}:
        return "browser_firefox_places"
    if lowered_format == "sqlite" or lowered_source.endswith("\\history") or lowered_source.endswith("\\places.sqlite"):
        if "firefox" in browser_name.lower() or lowered_source.endswith("\\places.sqlite"):
            return "browser_firefox_places"
        return "browser_chromium_downloads" if subtype == "download" else "browser_chromium_history"
    return "browser_csv"


def _extract_primary_download_url(parsed_url: dict, final_url: str | None) -> str | None:
    return parsed_url.get("full") or _parse_url(final_url).get("full")


def _derive_download_filename(download_path: str | None, remote_url: str | None) -> str | None:
    if download_path:
        return _basename(download_path)
    parsed = _parse_url(remote_url)
    return _basename(parsed.get("path"))


def _parse_url(value: str | None) -> dict:
    cleaned = _clean(value)
    if not cleaned:
        return {"full": None, "domain": None, "scheme": None, "path": None, "query": None}
    parsed = urlparse(cleaned)
    domain = parsed.netloc or None
    if domain and ":" in domain:
        domain = domain.lower()
    return {
        "full": cleaned,
        "domain": domain.lower() if domain else None,
        "scheme": parsed.scheme.lower() if parsed.scheme else None,
        "path": parsed.path or None,
        "query": parsed.query or None,
    }


def _extract_search_terms(term: str | None, url: str | None) -> tuple[str | None, str | None]:
    explicit = _clean(term)
    parsed = _parse_url(url)
    domain = str(parsed.get("domain") or "")
    query = str(parsed.get("query") or "")
    for needle, (engine, param) in SEARCH_ENGINES.items():
        if needle in domain:
            values = parse_qs(query).get(param) or []
            if explicit:
                return explicit, engine
            if values:
                return values[0], engine
            return explicit, engine
    if explicit:
        return explicit, None
    return None, None


def _looks_like_history(row: dict, artifact_meta: dict) -> bool:
    subtype = str(artifact_meta.get("browser_artifact_type") or "")
    artifact_hint = str(_first(row, ["ArtifactType"]) or "").lower()
    if subtype == "history" or artifact_hint in {"browser_history", "browser_visit", "history"}:
        return True
    return bool(_first(row, ["Visit Time", "VisitTime", "Last Visit Time", "LastVisitTime", "LastVisited", "Visit URL", "VisitURL", "Page Title", "PageTitle", "Web Site", "WebSite", "Url", "URL"]))


def _looks_like_download(row: dict, artifact_meta: dict) -> bool:
    subtype = str(artifact_meta.get("browser_artifact_type") or "")
    artifact_hint = str(_first(row, ["ArtifactType"]) or "").lower()
    if subtype == "download" or artifact_hint in {"browser_download", "download"}:
        return True
    return bool(_first(row, ["Target Path", "TargetPath", "Download Path", "DownloadPath", "Full Path", "FullPath", "Local Path", "LocalPath", "Filename", "FileName", "Download URL", "DownloadURL", "Final URL", "FinalUrl", "Download Start Time", "DownloadStartTime", "Start Time", "StartTime", "Download End Time", "DownloadEndTime", "End Time", "EndTime"]))


def _looks_like_search_term(row: dict, artifact_meta: dict) -> bool:
    subtype = str(artifact_meta.get("browser_artifact_type") or "")
    artifact_hint = str(_first(row, ["ArtifactType"]) or "").lower()
    if subtype == "search_term" or artifact_hint in {"browser_search", "browser_search_term", "search_term"}:
        return True
    return bool(_first(row, ["Search Term", "SearchTerm", "Search Terms", "SearchTerms", "Query", "Keyword", "Term"]))


def _parse_browser_timestamp_for_source(value: str | None, *, browser_name: str, source_file: str | None, parser_name: str | None) -> tuple[str | None, str]:
    cleaned = _clean(value)
    if not cleaned:
        return None, "unknown"
    lowered_browser = str(browser_name or "").lower()
    lowered_source = str(source_file or "").replace("/", "\\").lower()
    lowered_parser = str(parser_name or "").lower()
    if cleaned.isdigit() and (
        lowered_browser == "firefox"
        or "firefox" in lowered_source
        or lowered_source.endswith("\\places.sqlite")
        or lowered_parser == "browser_firefox_places"
    ):
        try:
            parsed = datetime.fromtimestamp(int(cleaned) / 1_000_000, tz=UTC)
            return parsed.isoformat(), "firefox_prtime"
        except Exception:  # noqa: BLE001
            return None, "unknown"
    return _parse_browser_timestamp(cleaned)


def _is_raw_ip_domain(domain: str | None) -> bool:
    return bool(domain and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?", domain))


def _is_double_extension(name: str | None) -> bool:
    return is_suspicious_double_extension(name)


def _apply_download_suspicion(*, document: dict, url_domain: str | None, url_full: str | None, file_path: str | None, file_name: str | None) -> None:
    tags = set(document.get("tags", []))
    reasons = set(document.get("suspicious_reasons", []))
    extension = (_suffix(file_path) or _suffix(file_name) or "").lower()
    lower_url = str(url_full or "").lower()
    lower_domain = str(url_domain or "").lower()
    if extension in EXECUTABLE_EXTENSIONS:
        tags.update({"suspicious", "suspicious_download", "executable_download"})
        reasons.add("Browser downloaded executable")
    if extension in SCRIPT_EXTENSIONS:
        tags.update({"suspicious", "suspicious_download", "script_download"})
        reasons.add("Browser downloaded script")
    if extension in ARCHIVE_EXTENSIONS:
        tags.update({"archive_download"})
        reasons.add("Browser downloaded archive")
        if any(token in lower_domain or token in lower_url for token in FILE_SHARING_DOMAINS):
            tags.update({"suspicious", "suspicious_download"})
            reasons.add("Archive downloaded from file sharing service")
    if _is_double_extension(file_name):
        tags.update({"suspicious", "suspicious_download"})
        reasons.add("Browser download has double extension")
    if _is_raw_ip_domain(url_domain):
        tags.update({"suspicious", "suspicious_download"})
        reasons.add("Browser URL uses direct IP")
    if any(token in lower_domain or token in lower_url for token in SUSPICIOUS_DOWNLOAD_TOKENS):
        tags.add("suspicious")
        if any(token in lower_domain or token in lower_url for token in ["mega", "mediafire", "transfer.sh", "file.io", "anonfiles", "githubusercontent", "discord"]):
            tags.add("cloud_storage")
    if any(token in lower_domain or token in lower_url for token in REMOTE_ACCESS_TOOLS):
        tags.add("remote_access_tool")
    if file_path:
        path_reasons = detect_suspicious_path(file_path)
        if path_reasons:
            tags.update({"suspicious", "suspicious_path"})
            reasons.update(f"Browser download to suspicious path: {reason}" for reason in path_reasons)
        if _is_user_writable_path(file_path):
            tags.add("user_writable_path")
            reasons.add("Browser download to user-writable path")
    document["tags"] = sorted(tags)
    document["suspicious_reasons"] = sorted(reasons)


def _apply_history_suspicion(document: dict, *, domain: str | None, url_full: str | None) -> None:
    tags = set(document.get("tags", []))
    reasons = set(document.get("suspicious_reasons", []))
    lower_domain = str(domain or "").lower()
    lower_url = str(url_full or "").lower()
    if _is_raw_ip_domain(domain):
        tags.update({"suspicious", "raw_ip"})
        reasons.add("Visit to raw IP address")
    if any(token in lower_domain or token in lower_url for token in PASTE_SITES):
        tags.add("paste_site")
    if any(token in lower_domain or token in lower_url for token in REMOTE_ACCESS_TOOLS):
        tags.add("remote_access_tool")
    if any(token in lower_domain or token in lower_url for token in ["dropbox", "drive.google", "onedrive", "mega", "mediafire", "box.com", "wetransfer"]):
        tags.add("cloud_storage")
    document["tags"] = sorted(tags)
    document["suspicious_reasons"] = sorted(reasons)


def _update_search_text(document: dict, *extra_values: str | None) -> None:
    parts: list[str] = []
    for value in [
        document.get("raw_summary"),
        ((document.get("event") or {}).get("message")),
        ((document.get("browser") or {}).get("name")),
        ((document.get("browser") or {}).get("profile")),
        ((document.get("browser") or {}).get("artifact_type")),
        ((document.get("browser") or {}).get("url")),
        ((document.get("browser") or {}).get("final_url")),
        ((document.get("browser") or {}).get("referrer")),
        ((document.get("browser") or {}).get("tab_url")),
        ((document.get("browser") or {}).get("domain")),
        ((document.get("browser") or {}).get("title")),
        ((document.get("browser") or {}).get("search_terms")),
        ((document.get("browser") or {}).get("search_engine")),
        ((document.get("browser") or {}).get("source_file")),
        ((document.get("url") or {}).get("full")),
        ((document.get("download") or {}).get("url")),
        ((document.get("download") or {}).get("final_url")),
        ((document.get("download") or {}).get("target_path")),
        ((document.get("download") or {}).get("file_name")),
        ((document.get("file") or {}).get("path")),
        ((document.get("file") or {}).get("name")),
        ((document.get("user") or {}).get("name")),
        *extra_values,
        " ".join(document.get("tags", [])),
        " ".join(document.get("suspicious_reasons", [])),
    ]:
        cleaned = _clean(value)
        if cleaned:
            parts.append(cleaned)
    document["search_text"] = " | ".join(parts)[:8192]


def normalize_browser_event(document: dict, row: dict, artifact_meta: dict, audit: BrowserAudit | None = None) -> dict:
    audit = audit or BrowserAudit()
    audit.records_read += 1
    source_file = _first(row, ["SourceFile", "SourceFilename"]) or str(artifact_meta.get("source_path") or artifact_meta.get("name") or "")
    profile_path = _first(row, ["Profile Path", "ProfilePath"])
    browser_name = _derive_browser_name(_first(row, ["Browser", "Application"]), source_file, str(artifact_meta.get("name") or ""), profile_path)
    profile = _derive_profile(row, source_file, profile_path)
    url_value = _first(row, ["URL", "Url", "Visit URL", "VisitURL", "Web Site", "WebSite", "Download URL", "DownloadURL"])
    final_url = _first(row, ["Final URL", "FinalUrl"])
    parsed_url = _parse_url(final_url or url_value)
    download_path = _normalize_windows_path(_first(row, ["Target Path", "TargetPath", "Download Path", "DownloadPath", "Full Path", "FullPath", "Local Path", "LocalPath", "Path"]))
    file_name = _first(row, ["Filename", "FileName"]) or _derive_download_filename(download_path, final_url or url_value)
    user_name = _infer_user(row, source_file, profile_path, download_path)
    artifact_subtype = "browser_generic"
    if _looks_like_download(row, artifact_meta):
        artifact_subtype = "download"
    elif _looks_like_search_term(row, artifact_meta):
        artifact_subtype = "search_term"
    elif _looks_like_history(row, artifact_meta):
        artifact_subtype = "history"
    visit_ts, _visit_precision = _parse_browser_timestamp_for_source(
        _first(row, ["Visit Time", "VisitTime", "Last Visit Time", "LastVisitTime", "LastVisited"]),
        browser_name=browser_name,
        source_file=source_file,
        parser_name=str(artifact_meta.get("parser") or ""),
    )
    download_start_ts, _ = _parse_browser_timestamp_for_source(
        _first(row, ["Download Start Time", "DownloadStartTime", "Start Time", "StartTime"]),
        browser_name=browser_name,
        source_file=source_file,
        parser_name=str(artifact_meta.get("parser") or ""),
    )
    download_end_ts, _ = _parse_browser_timestamp_for_source(
        _first(row, ["Download End Time", "DownloadEndTime", "End Time", "EndTime", "CompletionTime"]),
        browser_name=browser_name,
        source_file=source_file,
        parser_name=str(artifact_meta.get("parser") or ""),
    )
    source_mtime, _ = _parse_browser_timestamp_for_source(
        _first(row, ["SourceMtime", "SourceMTime", "SourceModifiedTime"]) or _clean(artifact_meta.get("mtime")),
        browser_name=browser_name,
        source_file=source_file,
        parser_name=str(artifact_meta.get("parser") or ""),
    )
    if artifact_subtype == "download":
        document["@timestamp"] = download_end_ts or download_start_ts or source_mtime
        document["timestamp_precision"] = "browser_download_end_time" if download_end_ts else "browser_download_start_time" if download_start_ts else "source_file_mtime" if source_mtime else "unknown"
    else:
        document["@timestamp"] = visit_ts or source_mtime
        document["timestamp_precision"] = "browser_visit_time" if visit_ts else "source_file_mtime" if source_mtime else "unknown"
    if _timestamp_out_of_range(document.get("@timestamp")):
        document["@timestamp"] = None
        document["timestamp_precision"] = "unknown"
    if not document.get("@timestamp"):
        audit.missing_timestamp += 1
    if not (parsed_url.get("full") or final_url):
        audit.missing_url += 1
    if artifact_subtype == "download" and not download_path:
        audit.missing_path += 1

    document["artifact"]["type"] = "browser"
    document["artifact"]["parser"] = _canonical_browser_parser(
        parser=str(artifact_meta.get("parser") or ""),
        subtype=artifact_subtype,
        browser_name=browser_name,
        source_format=str(artifact_meta.get("source_format") or ""),
        source_file=source_file,
    )
    document["source_file"] = source_file
    document["source_tool"] = str(artifact_meta.get("source_tool") or ("native_browser" if document["artifact"]["parser"] in {"browser_chromium_history", "browser_chromium_downloads", "browser_firefox_places"} else "browser"))
    document["source_format"] = str(artifact_meta.get("source_format") or ("sqlite" if document["artifact"]["parser"] in {"browser_chromium_history", "browser_chromium_downloads", "browser_firefox_places"} else Path(str(artifact_meta.get("name") or "")).suffix.lower().lstrip(".") or "csv"))
    document["browser"].update(
        {
            "browser": browser_name.lower() if browser_name and browser_name != "Unknown" else "unknown",
            "name": browser_name.lower() if browser_name and browser_name != "Unknown" else "unknown",
            "profile": profile,
            "profile_path": profile_path,
            "artifact_type": artifact_subtype,
            "url": parsed_url.get("full"),
            "final_url": final_url,
            "referrer": _first(row, ["Referrer URL", "ReferrerURL", "Referrer"]),
            "tab_url": _first(row, ["Tab URL", "TabUrl"]),
            "domain": parsed_url.get("domain"),
            "title": _first(row, ["Title", "Page Title", "PageTitle"]),
            "visit_count": _first(row, ["Visit Count", "VisitCount"]),
            "typed_count": _first(row, ["Typed Count", "TypedCount"]),
            "transition": _first(row, ["Transition"]),
            "download_start_time": download_start_ts,
            "download_end_time": download_end_ts,
            "download_state": _normalize_download_state(_first(row, ["State", "Download State", "DownloadState"])),
            "danger_type": _first(row, ["Danger Type", "DangerType"]),
            "interrupt_reason": _first(row, ["Interrupt Reason", "InterruptReason"]),
            "source_file": source_file,
        }
    )
    search_terms, search_engine = _extract_search_terms(_first(row, ["Search Term", "SearchTerm", "Search Terms", "SearchTerms", "Query", "Keyword", "Term"]), parsed_url.get("full"))
    document["browser"]["search_terms"] = search_terms
    document["browser"]["search_engine"] = search_engine or _first(row, ["Search Engine"])
    document["url"].update(parsed_url)
    document["user"]["name"] = user_name or document["user"].get("name")
    document["file"]["source_path"] = source_file
    document["execution"].update(
        {
            "source": "browser",
            "is_execution_confirmed": False,
            "confidence": "low",
            "interpretation": "Browser history/download artifacts indicate web activity or file download, not execution by itself",
        }
    )
    document["tags"] = sorted(set(document.get("tags", [])) | {"browser"})

    if artifact_subtype == "history":
        audit.history_count += 1
        document["event"].update(
            {
                "category": "web",
                "type": "browser_visit",
                "action": "browser_url_visited",
                "severity": "info",
                "timeline_include": True,
                "message": f"Browser visit: {parsed_url.get('domain') or parsed_url.get('full') or 'unknown'} {_first(row, ['Title', 'Page Title']) or parsed_url.get('full') or 'unknown'}",
            }
        )
        document["network"]["url"] = parsed_url.get("full")
        document["network"]["domain"] = parsed_url.get("domain")
        document["network"]["direction"] = "outbound"
        document["network"]["application"] = document["browser"]["name"]
        _apply_history_suspicion(document, domain=parsed_url.get("domain"), url_full=parsed_url.get("full"))
    elif artifact_subtype == "download":
        audit.download_count += 1
        if (_suffix(file_name) or "").lower() in EXECUTABLE_EXTENSIONS:
            audit.executable_download_count += 1
        if (_suffix(file_name) or "").lower() in ARCHIVE_EXTENSIONS:
            audit.archive_download_count += 1
        document["event"].update(
            {
                "category": "download",
                "type": "file_downloaded",
                "action": "browser_download_observed",
                "severity": "info",
                "timeline_include": True,
                "message": f"Browser download: {file_name or 'unknown file'} from {parsed_url.get('domain') or _parse_url(final_url).get('domain') or 'unknown'}",
            }
        )
        document["download"] = {
            "url": _extract_primary_download_url(parsed_url, final_url),
            "final_url": final_url,
            "referrer": _first(row, ["Referrer URL", "ReferrerURL", "Referrer"]),
            "target_path": download_path,
            "file_name": file_name,
            "mime_type": _first(row, ["MIME Type", "MimeType", "ContentType"]),
            "total_bytes": _to_int(_first(row, ["Total Bytes", "File Size", "TotalBytes"])),
            "received_bytes": _to_int(_first(row, ["Received Bytes", "ReceivedBytes"])),
            "state": _normalize_download_state(_first(row, ["State", "Download State", "DownloadState"])),
        }
        document["file"].update(
            {
                "path": download_path,
                "name": file_name,
                "extension": _suffix(file_name or download_path),
                "size": _to_int(_first(row, ["Total Bytes", "File Size", "TotalBytes"])),
            }
        )
        document["network"]["url"] = parsed_url.get("full")
        document["network"]["domain"] = parsed_url.get("domain")
        document["network"]["direction"] = "download"
        document["network"]["bytes_received"] = _to_int(_first(row, ["Received Bytes", "ReceivedBytes"]))
        document["network"]["bytes_total"] = _to_int(_first(row, ["Total Bytes", "File Size", "TotalBytes"]))
        document["network"]["application"] = document["browser"]["name"]
        _apply_download_suspicion(document=document, url_domain=parsed_url.get("domain"), url_full=parsed_url.get("full") or final_url, file_path=download_path, file_name=file_name)
        if "suspicious_download" in set(document.get("tags", [])):
            audit.suspicious_download_count += 1
        if document["file"].get("extension"):
            audit.top_download_extensions[str(document["file"]["extension"]).lower()] += 1
    elif artifact_subtype == "search_term":
        audit.search_count += 1
        terms, engine = _extract_search_terms(_first(row, ["Search Term", "Search Terms", "Query", "Keyword", "Term"]), parsed_url.get("full"))
        document["browser"]["search_terms"] = terms or document["browser"].get("search_terms")
        document["browser"]["search_engine"] = engine or document["browser"].get("search_engine") or _first(row, ["Search Engine"])
        document["event"].update(
            {
                "category": "web",
                "type": "browser_search",
                "action": "browser_search_observed",
                "severity": "info",
                "timeline_include": True,
                "message": f"Browser search: {document['browser'].get('search_terms') or 'unknown'}",
            }
        )
        document["network"]["url"] = parsed_url.get("full")
        document["network"]["domain"] = parsed_url.get("domain")
        document["network"]["direction"] = "outbound"
        document["network"]["application"] = document["browser"]["name"]
        _apply_history_suspicion(document, domain=parsed_url.get("domain"), url_full=parsed_url.get("full"))
    else:
        document["event"].update(
            {
                "category": "web",
                "type": "browser_generic",
                "action": "browser_observed",
                "severity": "info",
                "timeline_include": bool(document.get("@timestamp")),
                "message": f"Browser record: {parsed_url.get('domain') or parsed_url.get('full') or file_name or 'unknown'}",
            }
        )

    reasons = set(document.get("suspicious_reasons", []))
    tags = set(document.get("tags", []))
    domain = parsed_url.get("domain")
    lower_url = str(parsed_url.get("full") or final_url or "").lower()
    lower_path = str(download_path or "").lower()
    extension = (_suffix(file_name) or "").lower()
    is_trusted = _is_trusted_browser_domain(domain)
    if artifact_subtype == "download":
        if domain and not is_trusted:
            reasons.add("Browser download from external domain")
        if parsed_url.get("scheme") == "http" and extension in EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS | ARCHIVE_EXTENSIONS:
            reasons.add("Browser download over HTTP")
        if any(keyword in lower_url or keyword in lower_path for keyword in SUSPICIOUS_EXECUTABLE_KEYWORDS):
            reasons.add("Browser URL contains suspicious keywords")
        danger_type = str(document["browser"].get("danger_type") or "").strip().lower()
        if danger_type and danger_type not in {"safe", "notdangerous", "not_dangerous", "unknown"}:
            reasons.add("Browser danger type indicates suspicious download")
        if document["download"].get("state") == "interrupted":
            reasons.add("Browser interrupted download")
        if "\\startup\\" in lower_path:
            reasons.add("Browser download to Startup folder")
        if is_trusted and extension not in EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS:
            reasons.discard("Browser download from external domain")
            reasons.discard("Browser download to user-writable path")
            reasons.discard("Browser URL contains suspicious keywords")
            tags.discard("suspicious")
            tags.discard("suspicious_download")

    risk_score = 0
    if artifact_subtype == "download":
        if "Browser download from external domain" in reasons:
            risk_score += 15
        if "Browser downloaded executable" in reasons:
            risk_score += 25
        if "Browser downloaded script" in reasons:
            risk_score += 30
        if "Browser downloaded archive" in reasons:
            risk_score += 15
        if "Browser download to user-writable path" in reasons:
            risk_score += 20
        if "Browser download to Startup folder" in reasons:
            risk_score += 25
        if "Browser download over HTTP" in reasons:
            risk_score += 20
        if "Browser URL uses direct IP" in reasons:
            risk_score += 20
        if "Browser download has double extension" in reasons:
            risk_score += 25
        if "Browser danger type indicates suspicious download" in reasons:
            risk_score += 15
        if "Browser URL contains suspicious keywords" in reasons:
            risk_score += 10
    elif artifact_subtype in {"history", "search_term"}:
        risk_score = 0
        if "Visit to raw IP address" in reasons:
            risk_score += 20

    risk_score = min(100, risk_score)
    if artifact_subtype == "download" and risk_score >= 40:
        tags.update({"suspicious", "suspicious_download"})
    if reasons:
        tags.add("download" if artifact_subtype == "download" else "browser_history" if artifact_subtype == "history" else "browser_search")
    if artifact_subtype == "download" and "Browser download to user-writable path" in reasons:
        tags.add("user_writable_path")
    if profile is None:
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"browser_profile_unknown"})
    if source_mtime and not (visit_ts or download_start_ts or download_end_ts):
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"timestamp_source_file_only"})
    if _timestamp_out_of_range(document.get("@timestamp")):
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"browser_timestamp_out_of_range"})

    document["tags"] = sorted(tags)
    document["suspicious_reasons"] = sorted(reasons)
    document["risk_score"] = risk_score
    document["_preserve_risk_score"] = True

    if _clean(parsed_url.get("domain")):
        audit.top_domains[str(parsed_url.get("domain")).lower()] += 1
    if _clean(browser_name):
        audit.browsers_seen[str(browser_name)] += 1
    if profile:
        audit.profiles_seen[profile] += 1
    for token in SUSPICIOUS_NAME_TOKENS:
        if token in str(file_name or "").lower():
            document["tags"] = sorted(set(document.get("tags", [])) | {"suspicious"})
            document["suspicious_reasons"] = sorted(set(document.get("suspicious_reasons", [])) | {f"Interesting downloaded filename contains '{token}'"})
            document["risk_score"] = min(100, int(document.get("risk_score") or 0) + 10)
            break
    _update_search_text(
        document,
        _first(row, ["SourceFile", "SourceFilename"]),
        _first(row, ["URL", "Visit URL", "Download URL"]),
        _first(row, ["Final URL"]),
        _first(row, ["Referrer URL", "Referrer"]),
        _first(row, ["Title", "Page Title"]),
        _first(row, ["Target Path", "Download Path", "Full Path"]),
        _first(row, ["Search Term", "Search Terms", "Query", "Keyword", "Term"]),
    )
    audit.records_parsed += 1
    return document
