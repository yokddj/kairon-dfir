from datetime import UTC, datetime, timedelta
from pathlib import Path, PureWindowsPath
import json
import re
import csv

from dateutil import parser as date_parser


DEFENDER_NAME_HINTS = (
    "defender",
    "windowsdefender",
    "microsoftdefender",
    "detectionhistory",
    "detection_history",
    "mplog",
    "mpdetection",
    "mpscanskip",
    "mpdevicecontrol",
    "threat",
    "quarantine",
)
DEFENDER_HEADER_HINTS = {
    "artifacttype",
    "threatname",
    "threatid",
    "timecreated",
    "timestamp",
    "detectiontime",
    "initialdetectiontime",
    "lastthreatstatuschangetime",
    "resource",
    "resources",
    "path",
    "filepath",
    "processname",
    "action",
    "remediation",
    "severity",
    "category",
    "status",
    "detectionsource",
    "sid",
    "usersid",
    "domain",
    "productname",
    "engineversion",
    "signatureversion",
    "currentthreatexecutionstatus",
    "threattrackingid",
}
DEFENDER_STRONG_HEADER_HINTS = {
    "threatname",
    "threatid",
    "detectiontime",
    "initialdetectiontime",
    "lastthreatstatuschangetime",
    "detectionsource",
    "productname",
    "engineversion",
    "signatureversion",
    "currentthreatexecutionstatus",
    "threattrackingid",
}
DEFENDER_USER_WRITABLE_HINTS = ("\\downloads\\", "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\", "\\desktop\\")
DEFENDER_SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}
DEFENDER_EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".msi", ".com"} | DEFENDER_SCRIPT_EXTENSIONS


def clean_text(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip().strip("\x00")
    if text in {"", "-", "--", "N/A", "n/a", "null", "None"}:
        return None
    return text


def canonicalize_header(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def normalize_windows_path(value: str | None) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    text = (
        text.replace("/", "\\")
        .replace("containerfile:_", "")
        .replace("containerfile:", "")
        .replace("file:_", "")
        .replace("file:", "")
        .strip('"')
    )
    return text


def read_text_with_fallbacks(path: Path) -> tuple[str, str]:
    encodings = ("utf-8-sig", "utf-8", "utf-16", "utf-16-le", "utf-16-be", "latin-1")
    last_text = ""
    for encoding in encodings:
        try:
            text = path.read_text(encoding=encoding, errors="ignore")
        except Exception:  # noqa: BLE001
            continue
        if text is not None:
            return text, encoding
    return last_text, "latin-1"


def parse_defender_timestamp(value: str | None) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    digits = re.sub(r"\D", "", text)
    if digits.isdigit() and text.strip().isdigit():
        number = int(digits)
        try:
            if len(digits) == 18:
                base = datetime(1601, 1, 1, tzinfo=UTC)
                parsed = base + timedelta(microseconds=number)
                return parsed.isoformat()
            if len(digits) >= 16:
                parsed = datetime.fromtimestamp(number / 1_000_000, tz=UTC)
                return parsed.isoformat()
            if len(digits) >= 13:
                parsed = datetime.fromtimestamp(number / 1_000, tz=UTC)
                return parsed.isoformat()
            if len(digits) >= 10:
                parsed = datetime.fromtimestamp(number, tz=UTC)
                return parsed.isoformat()
        except Exception:  # noqa: BLE001
            pass
    try:
        parsed = date_parser.parse(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.isoformat()
    except Exception:  # noqa: BLE001
        return None


def normalize_defender_severity(value: str | None) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    lowered = text.lower()
    mapping = {
        "informational": "low",
        "info": "low",
        "low": "low",
        "moderate": "medium",
        "medium": "medium",
        "high": "high",
        "severe": "critical",
        "critical": "critical",
        "unknown": "medium",
    }
    return mapping.get(lowered, lowered)


def normalize_defender_action(value: str | None) -> tuple[str | None, str]:
    text = clean_text(value)
    if not text:
        return None, "defender_observed"
    lowered = text.lower()
    if any(token in lowered for token in ["quarantine", "quarantined"]):
        return text, "threat_quarantined"
    if any(token in lowered for token in ["remove", "removed", "cleaned", "remediated"]):
        return text, "threat_removed" if "remove" in lowered or "removed" in lowered else "remediation_completed"
    if "block" in lowered:
        return text, "threat_blocked"
    if "allow" in lowered:
        return text, "threat_allowed"
    if "detect" in lowered:
        return text, "threat_detected"
    if "fail" in lowered:
        return text, "remediation_failed"
    if "scan started" in lowered:
        return text, "scan_started"
    if "scan finished" in lowered or "scan completed" in lowered:
        return text, "scan_completed"
    return text, "defender_observed"


def normalize_defender_status(value: str | None) -> str | None:
    text = clean_text(value)
    return text.lower() if text else None


def normalize_threat_name(value: str | None) -> str | None:
    return clean_text(value)


def _extract_first_windows_path(text: str) -> str | None:
    match = re.search(r'([A-Za-z]:\\[^"\r\n]+)', text)
    if match:
        return normalize_windows_path(match.group(1).rstrip(".,;"))
    return None


def extract_paths_from_defender_resource(value: str | None) -> tuple[str | None, str | None]:
    text = clean_text(value)
    if not text:
        return None, None
    container_match = re.search(r"containerfile:?_?([A-Za-z]:\\[^,\r\n]+)", text, flags=re.IGNORECASE)
    container_file = normalize_windows_path(container_match.group(1)) if container_match else None
    file_path = _extract_first_windows_path(text)
    return file_path, container_file


def extract_hashes_from_defender_text(value: str | None) -> dict[str, str | None]:
    text = clean_text(value) or ""
    normalized = text.lower()
    matches = {
        "md5": re.search(r"\b[a-f0-9]{32}\b", normalized),
        "sha1": re.search(r"\b[a-f0-9]{40}\b", normalized),
        "sha256": re.search(r"\b[a-f0-9]{64}\b", normalized),
    }
    return {key: (match.group(0) if match else None) for key, match in matches.items()}


def parse_text_record_blocks(text: str) -> list[dict[str, str]]:
    blocks = re.split(r"\n\s*\n+", text)
    records: list[dict[str, str]] = []
    for block in blocks:
        row: dict[str, str] = {}
        for line in block.splitlines():
            line = line.strip().strip("\x00")
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            cleaned_key = key.strip()
            cleaned_value = value.strip()
            if cleaned_key and cleaned_value:
                row[cleaned_key] = cleaned_value
        if row:
            records.append(row)
    return records


def parse_json_loose(text: str) -> list[dict]:
    try:
        payload = json.loads(text)
    except Exception:  # noqa: BLE001
        return []
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def parse_jsonl_loose(text: str) -> list[dict]:
    rows: list[dict] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def _delimiter_score(lines: list[str], delimiter: str) -> int:
    counts = [line.count(delimiter) for line in lines if line.strip()]
    if not counts or max(counts) <= 0:
        return 0
    positive = [count for count in counts if count > 0]
    if not positive:
        return 0
    return sum(positive) + len(positive) * 5


def choose_delimiter(text: str) -> tuple[str | None, str | None]:
    lines = [line for line in text.splitlines() if line.strip()][:12]
    if not lines:
        return None, None
    try:
        sniffed = csv.Sniffer().sniff("\n".join(lines[:5]), delimiters=",;\t|")
        if sniffed and getattr(sniffed, "delimiter", None):
            return str(sniffed.delimiter), "delimiter_autodetected"
    except Exception:  # noqa: BLE001
        pass
    scores = {delimiter: _delimiter_score(lines, delimiter) for delimiter in (",", ";", "\t", "|")}
    best = max(scores.items(), key=lambda item: item[1])
    if best[1] > 0:
        return best[0], "delimiter_fallback_used"
    return None, None


def basename_windows(path: str | None) -> str | None:
    text = normalize_windows_path(path)
    if not text:
        return None
    try:
        return PureWindowsPath(text).name or text
    except Exception:  # noqa: BLE001
        return Path(text.replace("\\", "/")).name or text


def extension_windows(path: str | None) -> str | None:
    name = basename_windows(path)
    if not name or "." not in name:
        return None
    return "." + name.split(".")[-1].lower()


def infer_user_from_path(path: str | None) -> str | None:
    text = normalize_windows_path(path)
    if not text:
        return None
    match = re.search(r"\\Users\\([^\\]+)\\", text, flags=re.IGNORECASE)
    return match.group(1) if match else None


def looks_like_defender_artifact(path: Path, headers: list[str] | None = None) -> bool:
    lower_name = path.name.lower()
    if any(token in lower_name for token in DEFENDER_NAME_HINTS):
        return True
    header_set = {canonicalize_header(header) for header in (headers or []) if header}
    matched = header_set & DEFENDER_HEADER_HINTS
    if not matched:
        return False
    if matched & DEFENDER_STRONG_HEADER_HINTS:
        return True
    return len(matched) >= 3


def looks_like_defender_event_row(row: dict, artifact_meta: dict | None = None) -> bool:
    channel = clean_text(row.get("Channel") or row.get("LogName") or row.get("channel"))
    provider = clean_text(row.get("Provider") or row.get("ProviderName") or row.get("SourceName") or row.get("provider"))
    event_id = clean_text(row.get("EventID") or row.get("EventId") or row.get("event_id"))
    channel_lower = str(channel or "").lower()
    provider_lower = str(provider or "").lower()
    if "windows defender" in channel_lower or "windows defender" in provider_lower:
        return True
    if event_id in {"1116", "1117", "1118", "1119", "1120", "1006", "1007", "1015", "5007", "5013", "5010", "5011"}:
        return "windows defender" in channel_lower or "windows defender" in provider_lower
    if artifact_meta:
        defender_type = str(artifact_meta.get("defender_artifact_type") or "").lower()
        if defender_type == "defender_evtx":
            return True
    return False


def defender_suspicion(path: str | None, threat_name: str | None, category: str | None, action: str | None) -> tuple[list[str], list[str], int]:
    tags = {"defender", "detection", "security_product"}
    reasons = {"Microsoft Defender detected threat"}
    score = 55
    normalized_path = normalize_windows_path(path)
    extension = extension_windows(normalized_path)
    lower_blob = " ".join(item for item in [clean_text(threat_name), clean_text(category), clean_text(action), normalized_path] if item).lower()
    if action:
        lowered_action = action.lower()
        if "quarantine" in lowered_action:
            tags.add("quarantined")
            reasons.add("Threat was quarantined")
            score += 5
        if "allow" in lowered_action:
            tags.add("allowed")
            reasons.add("Threat was allowed")
            score += 20
        if "remove" in lowered_action or "clean" in lowered_action or "remediat" in lowered_action:
            tags.add("removed")
        if "fail" in lowered_action:
            tags.add("remediation_failed")
            reasons.add("Threat remediation failed")
            score += 25
        if "block" in lowered_action:
            tags.add("blocked")
    if "hacktool" in lower_blob:
        tags.add("hacktool")
        reasons.add("HackTool/PUA detected")
        score += 15
    if "pua" in lower_blob:
        tags.add("pua")
        reasons.add("HackTool/PUA detected")
        score += 10
    if any(token in lower_blob for token in ["trojan", "ransom", "exploit", "credential", "behavior"]):
        tags.add("malware")
        score += 15
    if normalized_path:
        if any(token in normalized_path.lower() for token in DEFENDER_USER_WRITABLE_HINTS):
            tags.update({"suspicious_path"})
        if "\\downloads\\" in normalized_path.lower():
            tags.add("downloaded_file")
            reasons.add("Detected file located in Downloads")
        if "\\appdata\\" in normalized_path.lower():
            tags.add("appdata_path")
        if "\\temp\\" in normalized_path.lower():
            tags.add("temp_path")
        if extension in DEFENDER_SCRIPT_EXTENSIONS:
            tags.add("script")
            reasons.add("Detected script in user-writable path")
        if extension in DEFENDER_EXECUTABLE_EXTENSIONS:
            tags.add("executable")
        if extension in {".zip", ".rar", ".7z", ".iso", ".img"}:
            tags.add("archive")
    return sorted(tags), sorted(reasons), min(score, 95)
