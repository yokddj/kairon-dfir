from __future__ import annotations

import json
import re
from pathlib import Path, PureWindowsPath
from urllib.parse import urlparse

from app.analysis.suspicious import normalize_windows_path_for_classification
from app.ingest.eztools.base import read_delimited_rows


BITS_NAME_HINTS = (
    "bits",
    "bitsparser",
    "qmgr",
    "bitsadmin",
)
BITS_HEADER_HINTS = {
    "artifacttype",
    "jobid",
    "jobguid",
    "displayname",
    "description",
    "owner",
    "ownersid",
    "state",
    "type",
    "priority",
    "remotename",
    "localname",
    "remoteurl",
    "localfile",
    "localpath",
    "notifycmdline",
    "notifycommandline",
    "creationtime",
    "modificationtime",
    "transfercompletiontime",
    "errordescription",
    "bytestotal",
    "bytestransferred",
}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".msi", ".com"}
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z"}
LOLBIN_TOKENS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wscript.exe",
    "cscript.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "schtasks.exe",
    "msiexec.exe",
}
SUSPICIOUS_REMOTE_TOKENS = (
    "pastebin",
    "raw.githubusercontent",
    "gist.github",
    "discord",
    "cdn.discordapp",
    "anonfiles",
    "mega",
    "dropbox",
    "transfer.sh",
)
SUSPICIOUS_KEYWORDS = (
    "payload",
    "update",
    "invoice",
    "document",
    "installer",
    "setup",
    "crack",
    "keygen",
    "runme",
    "mimikatz",
    "rclone",
    "anydesk",
    "teamviewer",
    "ngrok",
    "dump",
    "credentials",
    "lsass",
)
MICROSOFT_BENIGN_TOKENS = ("windows update", "microsoft", "store", "edge", "office", "defender")
MICROSOFT_BENIGN_DOMAINS = (
    "windowsupdate.com",
    "download.windowsupdate.com",
    "update.microsoft.com",
    "microsoft.com",
    "microsoftonline.com",
    "officecdn.microsoft.com",
    "storeedgefd.dsx.mp.microsoft.com",
    "delivery.mp.microsoft.com",
)
MICROSOFT_BENIGN_PATH_PATTERNS = (
    "\\windows\\softwaredistribution\\download\\",
    "\\programdata\\microsoft\\windows defender\\",
    "\\program files\\windows defender\\",
    "\\program files\\microsoft defender\\",
    "\\program files\\windowsapps\\microsoft",
)
USER_WRITABLE_PATH_TOKENS = (
    "\\users\\",
    "\\appdata\\",
    "\\temp\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\public\\",
)
PROGRAMDATA_SUSPICIOUS_TOKEN = "\\programdata\\"


def canonicalize_header(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def normalize_windows_path(value: str | None) -> str | None:
    if value in (None, ""):
        return None
    normalized = normalize_windows_path_for_classification(str(value).strip().strip('"'))
    if normalized is None:
        return None
    normalized = normalized.replace("/", "\\")
    if normalized.lower() in {"-", "--", "n/a", "na", "(null)", "null", "none", "unknown"}:
        return None
    return normalized


def basename_windows(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    try:
        return PureWindowsPath(normalized).name or normalized
    except Exception:  # noqa: BLE001
        return Path(normalized.replace("\\", "/")).name or normalized


def suffix_windows(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    try:
        suffix = PureWindowsPath(normalized).suffix.lower()
        return suffix or None
    except Exception:  # noqa: BLE001
        suffix = Path(normalized.replace("\\", "/")).suffix.lower()
        return suffix or None


def infer_bits_user_from_path(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    match = re.search(r"\\users\\(?P<user>[^\\]+)\\", normalized, re.IGNORECASE)
    return match.group("user") if match else None


def looks_like_bits_artifact(path: Path, headers: list[str] | None = None) -> bool:
    suffix = path.suffix.lower()
    lower_name = path.name.lower()

    if suffix not in {".csv", ".json", ".jsonl", ".txt"}:
        return False

    if suffix == ".txt":
        return "bitsadmin" in lower_name

    if any(token in lower_name for token in BITS_NAME_HINTS):
        return True

    header_set = {canonicalize_header(header) for header in (headers or []) if header}
    if {"jobid", "jobguid", "remoteurl", "localpath", "notifycmdline", "bytestransferred"} <= header_set:
        return True
    return len(header_set & BITS_HEADER_HINTS) >= 4


def read_bits_csv_rows(path: Path) -> list[dict]:
    return list(read_delimited_rows(path))


def read_bits_json_rows(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    if path.suffix.lower() == ".jsonl":
        rows: list[dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            if isinstance(payload, dict):
                rows.append(payload)
        return rows
    payload = json.loads(text)
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        if isinstance(payload.get("rows"), list):
            return [item for item in payload["rows"] if isinstance(item, dict)]
        if isinstance(payload.get("jobs"), list):
            return [item for item in payload["jobs"] if isinstance(item, dict)]
        return [payload]
    return []


def normalize_bits_state(value: str | None) -> str:
    normalized = str(value or "").strip().lower().replace(" ", "_")
    mapping = {
        "queued": "queued",
        "connecting": "connecting",
        "transferring": "transferring",
        "suspended": "suspended",
        "error": "error",
        "transient_error": "transient_error",
        "transienterror": "transient_error",
        "transferred": "transferred",
        "acknowledged": "acknowledged",
        "cancelled": "cancelled",
        "canceled": "cancelled",
    }
    return mapping.get(normalized, "unknown")


def normalize_bits_download_state(value: str | None) -> str:
    state = normalize_bits_state(value)
    if state in {"transferred", "acknowledged"}:
        return "complete"
    if state in {"transferring", "connecting", "queued"}:
        return "in_progress"
    if state in {"error", "transient_error"}:
        return "error"
    if state == "cancelled":
        return "cancelled"
    if state == "suspended":
        return "interrupted"
    return "unknown"


def normalize_bits_type(value: str | None) -> str:
    normalized = str(value or "").strip().lower().replace(" ", "_")
    mapping = {
        "download": "download",
        "upload": "upload",
        "upload_reply": "upload_reply",
        "uploadreply": "upload_reply",
    }
    return mapping.get(normalized, "unknown")


def parse_bits_url(value: str | None) -> dict[str, str | None]:
    url = str(value or "").strip()
    if not url:
        return {"full": None, "domain": None, "scheme": None, "path": None, "query": None}
    parsed = urlparse(url)
    return {
        "full": url,
        "domain": parsed.hostname,
        "scheme": parsed.scheme or None,
        "path": parsed.path or None,
        "query": parsed.query or None,
    }


def is_direct_ip_url(url: str | None) -> bool:
    hostname = parse_bits_url(url).get("domain")
    if not hostname:
        return False
    return re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname) is not None


def infer_bits_direction(job_type: str | None, remote_url: str | None, local_path: str | None) -> str:
    normalized_type = normalize_bits_type(job_type)
    if normalized_type in {"upload", "upload_reply"}:
        return "upload"
    if remote_url and local_path:
        return "download"
    return "unknown"


def _has_double_extension(path: str | None) -> bool:
    name = basename_windows(path)
    if not name:
        return False
    parts = name.lower().split(".")
    if len(parts) < 3:
        return False
    return parts[-1] in {ext.lstrip(".") for ext in EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS} and parts[-2] in {
        "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"
    }


def looks_user_writable_path(path: str | None) -> bool:
    normalized = (normalize_windows_path(path) or "").lower()
    if not normalized:
        return False
    if any(token in normalized for token in USER_WRITABLE_PATH_TOKENS):
        return True
    if PROGRAMDATA_SUSPICIOUS_TOKEN in normalized and "\\programdata\\microsoft\\" not in normalized:
        return True
    return False


def is_known_benign_bits_path(path: str | None) -> bool:
    normalized = (normalize_windows_path(path) or "").lower()
    return any(token in normalized for token in MICROSOFT_BENIGN_PATH_PATTERNS)


def is_known_benign_bits_domain(domain: str | None) -> bool:
    normalized = str(domain or "").lower().strip()
    return any(normalized == item or normalized.endswith(f".{item}") for item in MICROSOFT_BENIGN_DOMAINS)


def split_command_line(command_line: str | None) -> tuple[str | None, str | None]:
    text = str(command_line or "").strip()
    if not text:
        return None, None
    if text[0] == '"':
        match = re.match(r'^"([^"]+)"\s*(.*)$', text)
        if match:
            return normalize_windows_path(match.group(1)), (match.group(2).strip() or None)
    match = re.match(r"^(\S+)(?:\s+(.*))?$", text)
    if not match:
        return None, None
    arguments = match.group(2)
    return normalize_windows_path(match.group(1)), (arguments.strip() or None) if arguments else None


def extract_bits_notify_process(command_line: str | None) -> tuple[str | None, str | None]:
    executable, arguments = split_command_line(command_line)
    if not executable:
        return None, arguments
    lowered = executable.lower()
    if "\\" not in executable and not re.search(r"\.[a-z0-9]{2,4}$", lowered):
        executable = f"C:\\Windows\\System32\\{executable}.exe"
    elif "\\" not in executable:
        executable = f"C:\\Windows\\System32\\{executable}"
    return normalize_windows_path(executable), arguments


def infer_file_name(local_path: str | None, remote_url: str | None) -> str | None:
    local_name = basename_windows(local_path)
    if local_name:
        return local_name
    parsed = parse_bits_url(remote_url)
    remote_path = parsed.get("path") or ""
    name = Path(remote_path).name
    return name or None


def classify_bits_job(
    *,
    remote_url: str | None,
    local_path: str | None,
    notify_cmd_line: str | None,
    display_name: str | None,
    description: str | None,
    owner: str | None,
    owner_sid: str | None,
    job_type: str | None,
    state: str | None,
) -> tuple[set[str], list[str], int]:
    tags = {"bits"}
    reasons: list[str] = []
    risk = 0
    remote = str(remote_url or "").lower()
    local = (normalize_windows_path(local_path) or "").lower()
    notify = str(notify_cmd_line or "").lower()
    name = str(display_name or "").lower()
    description_text = str(description or "").lower()
    state_norm = normalize_bits_state(state)
    direction = infer_bits_direction(job_type, remote_url, local_path)
    parsed_url = parse_bits_url(remote_url)
    domain = parsed_url.get("domain")
    ext = suffix_windows(local_path)
    is_exec = ext in EXECUTABLE_EXTENSIONS
    is_script = ext in SCRIPT_EXTENSIONS
    is_archive = ext in ARCHIVE_EXTENSIONS
    benign_candidate = (
        any(token in remote or token in name or token in description_text for token in MICROSOFT_BENIGN_TOKENS)
        or is_known_benign_bits_domain(domain)
        or is_known_benign_bits_path(local_path)
    )
    user_writable = looks_user_writable_path(local_path)
    notify_executable, _ = extract_bits_notify_process(notify_cmd_line)
    notify_executable_name = basename_windows(notify_executable)
    notify_is_lolbin = str(notify_executable_name or "").lower() in LOLBIN_TOKENS

    if direction == "upload":
        tags.add("bits_upload")
    elif direction == "download":
        tags.update({"bits_download", "download"})
    tags.add("bits_job")
    if owner_sid == "S-1-5-18" or str(owner or "").upper() == "SYSTEM":
        tags.add("system_owned")
    if user_writable:
        tags.add("user_writable_path")
    interactive_owner = bool(owner) and str(owner).upper() != "SYSTEM" and owner_sid != "S-1-5-18"

    if remote and not benign_candidate and domain:
        reasons.append("BITS transfer from external domain")
        risk = max(risk, 20)
    if remote.startswith("http://") and not benign_candidate:
        tags.add("cleartext_http")
        reasons.append("BITS download over HTTP")
        risk = max(risk, 35)
    if is_direct_ip_url(remote_url):
        tags.add("direct_ip_url")
        reasons.append("BITS URL uses direct IP")
        risk = max(risk, 45)
    if any(token in remote for token in SUSPICIOUS_REMOTE_TOKENS):
        tags.update({"suspicious_download", "possible_bits_abuse"})
        reasons.append("BITS transfer from external domain")
        risk = max(risk, 60)
    if user_writable and not benign_candidate:
        reasons.append("BITS download to user-writable path")
        risk = max(risk, 40 if not notify_cmd_line else 60)
    if "\\startup\\" in local:
        reasons.append("BITS download to Startup folder")
        risk = max(risk, 80)
    if is_exec or is_script:
        tags.update({"suspicious_download", "possible_bits_abuse"})
        tags.add("executable_download" if is_exec else "script_download")
        reasons.append("BITS downloaded executable" if is_exec else "BITS downloaded script")
        risk = max(risk, 50 if user_writable else 30)
    elif is_archive:
        tags.add("archive_download")
        reasons.append("BITS downloaded archive")
        risk = max(risk, 15)
    if not benign_candidate and any(token in local or token in remote or token in name or token in description_text for token in SUSPICIOUS_KEYWORDS):
        tags.update({"possible_bits_abuse", "suspicious_download"})
        reasons.append("BITS suspicious display name")
        risk = max(risk, 74)
    if _has_double_extension(local_path) or _has_double_extension(remote_url):
        reasons.append("BITS download has double extension")
        risk = max(risk, 78)
    if notify_cmd_line:
        tags.update({"bits_notify_cmd", "persistence", "deferred_execution"})
        reasons.append("BITS job has notify command")
        reasons.append("BITS notify command may execute downloaded file")
        risk = max(risk, 55)
    if notify_cmd_line and notify_is_lolbin:
        tags.add("lolbin")
        reasons.append("BITS NotifyCmdLine uses LOLBin")
        risk = max(risk, 75)
    if "powershell" in notify or "pwsh" in notify:
        tags.add("powershell")
        reasons.append("BITS NotifyCmdLine uses PowerShell")
        risk = max(risk, 80)
    if "-executionpolicy bypass" in notify or "executionpolicy bypass" in notify or " bypass" in notify:
        reasons.append("BITS NotifyCmdLine uses execution policy bypass")
        risk = max(risk, 85)
    if "-windowstyle hidden" in notify or "-w hidden" in notify or " hidden" in notify:
        reasons.append("BITS NotifyCmdLine uses hidden window")
        risk = max(risk, 85)
    if any(token in notify for token in ["-enc", "encodedcommand", "frombase64string", "iex", "downloadstring", "invoke-webrequest", "iwr"]):
        reasons.append("BITS NotifyCmdLine uses PowerShell")
        risk = max(risk, 88)
    if notify_executable and looks_user_writable_path(notify_executable):
        reasons.append("BITS NotifyCmdLine references user-writable path")
        risk = max(risk, 85)
    if state_norm in {"suspended", "error", "transient_error"}:
        tags.add("stale_bits_job")
        risk = max(risk, 12)
        if (is_exec or is_script or is_archive) and not benign_candidate:
            reasons.append("BITS transfer error on suspicious file")
            risk = max(risk, 55)
    if interactive_owner:
        reasons.append("BITS owner is interactive user")
        risk = max(risk, 20 if not benign_candidate else 0)
    if benign_candidate and not reasons and not notify_cmd_line:
        risk = 0
    return tags, sorted(set(reasons)), min(risk, 100)


__all__ = [
    "basename_windows",
    "canonicalize_header",
    "classify_bits_job",
    "extract_bits_notify_process",
    "infer_bits_direction",
    "infer_bits_user_from_path",
    "infer_file_name",
    "is_direct_ip_url",
    "is_known_benign_bits_domain",
    "is_known_benign_bits_path",
    "looks_like_bits_artifact",
    "looks_user_writable_path",
    "normalize_bits_state",
    "normalize_bits_download_state",
    "normalize_bits_type",
    "normalize_windows_path",
    "parse_bits_url",
    "read_bits_csv_rows",
    "read_bits_json_rows",
    "split_command_line",
    "suffix_windows",
]
