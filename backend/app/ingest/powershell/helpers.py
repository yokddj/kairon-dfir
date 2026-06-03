from base64 import b64decode
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
import json
import re

from dateutil import parser as date_parser

from app.analysis.suspicious import detect_suspicious_path


POWERSHELL_NAME_HINTS = (
    "consolehost_history",
    "psreadline",
    "powershell_transcript",
    "windowspowershell_transcript",
    "transcript",
    "scriptblock",
    "powershell",
)
POWERSHELL_TEXT_HINTS = (
    "powershell transcript start",
    "start time:",
    "username:",
    "runas user:",
    "machine:",
    "host application:",
    "command start time:",
    "ps>",
)
POWERSHELL_USER_WRITABLE_HINTS = ("\\downloads\\", "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\", "\\desktop\\")
POWERSHELL_SCRIPT_EXTENSIONS = {".ps1", ".psm1", ".psd1"}
POWERSHELL_REMOTE_TOOL_TOKENS = ("anydesk", "teamviewer", "rclone", "ngrok", "plink", "psexec")
POWERSHELL_CREDENTIAL_TOKENS = ("mimikatz", "sekurlsa", "lsass", "procdump", "comsvcs.dll")
POWERSHELL_RECON_TOKENS = (
    "whoami",
    "hostname",
    "ipconfig",
    "net user",
    "net localgroup",
    "nltest",
    "quser",
    "query user",
    "systeminfo",
    "tasklist",
    "get-process",
    "get-service",
    "get-localuser",
    "get-aduser",
)
POWERSHELL_PERSISTENCE_TOKENS = (
    "new-scheduledtask",
    "register-scheduledtask",
    "schtasks",
    "reg add",
    "\\software\\microsoft\\windows\\currentversion\\run",
    "new-service",
    "sc.exe create",
    "commandlineeventconsumer",
    "eventfilter",
)
POWERSHELL_DEFENDER_TOKENS = (
    "set-mppreference",
    "add-mppreference",
    "disablerealtimemonitoring",
    "exclusionpath",
    "exclusionprocess",
    "submitsamplesconsent",
    "mapsreporting",
)
POWERSHELL_LOLBIN_TOKENS = ("rundll32", "regsvr32", "mshta", "wscript", "cscript", "certutil", "bitsadmin", "curl", "wget")
POWERSHELL_BENIGN_HISTORY_PREFIXES = (
    "cd",
    "set-location",
    "pwd",
    "ls",
    "dir",
    "get-childitem",
    "get-process",
    "get-service",
    "whoami",
    "hostname",
    "ipconfig",
    "help",
    "man",
    "wsl --install",
    "winget install ",
)
DIRECT_IP_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)", flags=re.IGNORECASE)
BASE64_TOKEN_RE = re.compile(r"(?i)(?:-enc|-encodedcommand|/enc)\s+([A-Za-z0-9+/=]{16,})")
URL_RE = re.compile(r"https?://[^\s'\"<>]+", flags=re.IGNORECASE)
WINDOWS_PATH_RE = re.compile(r"([A-Za-z]:\\[^\"'\r\n]+|\\\\[^\"'\r\n]+)")
REGISTRY_PATH_RE = re.compile(r"(?i)(HKLM|HKCU|HKCR|HKU|HKCC):?\\[^\s\"']+")


def clean_text(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip().strip("\x00")
    if text in {"", "-", "--", "N/A", "n/a", "null", "None"}:
        return None
    return text


def canonicalize_header(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def read_text_with_fallbacks(path: Path) -> str:
    encodings = ("utf-8-sig", "utf-8", "utf-16le", "utf-16", "latin-1")
    last_error: Exception | None = None
    for encoding in encodings:
        try:
            return path.read_text(encoding=encoding, errors="ignore")
        except Exception as exc:  # noqa: BLE001
            last_error = exc
    if last_error:
        raise last_error
    return ""


def looks_like_powershell_artifact(path: Path, headers: list[str] | None = None, text_sample: str | None = None) -> bool:
    lower_name = path.name.lower()
    if any(token in lower_name for token in POWERSHELL_NAME_HINTS):
        return True
    if path.suffix.lower() in POWERSHELL_SCRIPT_EXTENSIONS:
        return True
    header_set = {canonicalize_header(header) for header in (headers or []) if header}
    if {"command", "scriptblocktext", "hostapplication", "username"} & header_set:
        return True
    blob = (text_sample or "").lower()
    return any(token in blob for token in POWERSHELL_TEXT_HINTS)


def normalize_windows_path(value: str | None) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    return text.replace("/", "\\").strip('"')


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


def parse_powershell_timestamp(value: str | None) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    try:
        parsed = date_parser.parse(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.isoformat()
    except Exception:  # noqa: BLE001
        return None


def source_file_mtime_iso(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat()


def extract_urls(command: str | None) -> list[str]:
    text = clean_text(command) or ""
    return sorted(set(match.rstrip("',);") for match in URL_RE.findall(text)))


def merge_indicator_text(*values: str | None) -> str:
    parts: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = clean_text(value)
        if not text:
            continue
        if text in seen:
            continue
        seen.add(text)
        parts.append(text)
    return "\n".join(parts)


def extract_domains(command: str | None) -> list[str]:
    domains: set[str] = set()
    for url in extract_urls(command):
        try:
            domain = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/", 1)[0].split(":", 1)[0]
            if domain:
                domains.add(domain.lower())
        except Exception:  # noqa: BLE001
            continue
    return sorted(domains)


def extract_windows_paths(command: str | None) -> list[str]:
    text = clean_text(command) or ""
    paths = [normalize_windows_path(match.rstrip("',);")) for match in WINDOWS_PATH_RE.findall(text)]
    return sorted({item for item in paths if item})


def extract_registry_paths(command: str | None) -> list[str]:
    text = clean_text(command) or ""
    return sorted(set(item.rstrip("',);") for item in REGISTRY_PATH_RE.findall(text)))


def extract_hashes(command: str | None) -> dict[str, str | None]:
    text = (clean_text(command) or "").lower()
    return {
        "md5": re.search(r"\b[a-f0-9]{32}\b", text).group(0) if re.search(r"\b[a-f0-9]{32}\b", text) else None,
        "sha1": re.search(r"\b[a-f0-9]{40}\b", text).group(0) if re.search(r"\b[a-f0-9]{40}\b", text) else None,
        "sha256": re.search(r"\b[a-f0-9]{64}\b", text).group(0) if re.search(r"\b[a-f0-9]{64}\b", text) else None,
    }


def detect_encoded_command(command: str | None) -> str | None:
    text = clean_text(command) or ""
    match = BASE64_TOKEN_RE.search(text)
    return match.group(1) if match else None


def try_decode_powershell_encoded_command(command: str | None) -> tuple[str | None, str | None]:
    encoded = detect_encoded_command(command)
    if not encoded:
        return None, None
    try:
        decoded = b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
        preview = decoded.decode("utf-16le", errors="ignore").strip()
        return encoded, preview[:1024] if preview else None
    except Exception as exc:  # noqa: BLE001
        return encoded, None


def detect_powershell_download(command: str | None) -> bool:
    text = (clean_text(command) or "").lower()
    return any(
        token in text
        for token in (
            "invoke-webrequest",
            "iwr ",
            "wget ",
            "curl ",
            "invoke-restmethod",
            " irm ",
            "new-object net.webclient",
            "downloadstring",
            "downloadfile",
            "start-bitstransfer",
            "system.net.webclient",
            "http://",
            "https://",
        )
    )


def detect_iex(command: str | None) -> bool:
    text = (clean_text(command) or "").lower()
    return any(token in text for token in ("invoke-expression", "iex(", "iex ", "| iex"))


def detect_execution_policy_bypass(command: str | None) -> bool:
    text = (clean_text(command) or "").lower()
    if "executionpolicy bypass" in text or "-executionpolicy bypass" in text or " -ep bypass" in text:
        return True
    if "set-executionpolicy unrestricted" in text or "executionpolicy unrestricted" in text:
        return True
    return False


def detect_execution_policy_weakened(command: str | None) -> bool:
    text = (clean_text(command) or "").lower()
    return (
        "set-executionpolicy unrestricted" in text
        or "executionpolicy unrestricted" in text
        or detect_execution_policy_bypass(text)
    )


def detect_defender_tampering(command: str | None) -> bool:
    text = (clean_text(command) or "").lower()
    return any(token in text for token in POWERSHELL_DEFENDER_TOKENS)


def detect_persistence_keywords(command: str | None) -> bool:
    text = (clean_text(command) or "").lower()
    return any(token in text for token in POWERSHELL_PERSISTENCE_TOKENS)


def _extract_indicators(command: str | None) -> set[str]:
    text = (clean_text(command) or "").lower()
    indicators: set[str] = set()
    if detect_encoded_command(text):
        indicators.add("encoded_command")
    if detect_powershell_download(text):
        indicators.add("download_cradle")
    if detect_iex(text):
        indicators.add("invoke_expression")
    if detect_execution_policy_weakened(text):
        indicators.add("execution_policy_bypass")
    if detect_defender_tampering(text):
        indicators.add("defender_tampering")
    if detect_persistence_keywords(text):
        indicators.add("persistence")
    if any(token in text for token in POWERSHELL_RECON_TOKENS):
        indicators.add("recon")
    if any(token in text for token in POWERSHELL_CREDENTIAL_TOKENS):
        indicators.add("credential_access")
    if any(token in text for token in POWERSHELL_LOLBIN_TOKENS):
        indicators.add("lolbin")
    if any(token in text for token in POWERSHELL_REMOTE_TOOL_TOKENS):
        indicators.add("remote_tool")
    if DIRECT_IP_URL_RE.search(text):
        indicators.add("raw_ip_url")
    if "pastebin" in text:
        indicators.add("paste_site")
    return indicators


def powershell_suspicion(command: str | None, *, file_path: str | None = None, is_script: bool = False) -> tuple[list[str], list[str], int]:
    tags = {"powershell"}
    reasons: set[str] = set()
    risk = 0
    text = clean_text(command) or ""
    lower = text.lower()
    indicators = _extract_indicators(text)
    if is_script:
        tags.add("script")
        risk = max(risk, 10)
    elif lower.startswith(POWERSHELL_BENIGN_HISTORY_PREFIXES):
        risk = 0
    if "encoded_command" in indicators:
        tags.update({"suspicious", "encoded_command"})
        reasons.add("PowerShell EncodedCommand")
        risk = max(risk, 85)
    if "download_cradle" in indicators:
        tags.update({"suspicious", "download_cradle"})
        reasons.add("PowerShell download cradle")
        risk = max(risk, 72)
    if "invoke_expression" in indicators:
        tags.update({"suspicious", "invoke_expression"})
        reasons.add("PowerShell Invoke-Expression")
        risk = max(risk, 74)
    if "execution_policy_bypass" in indicators:
        tags.update({"suspicious", "execution_policy_bypass"})
        if "bypass" in lower:
            reasons.add("PowerShell ExecutionPolicy Bypass")
            risk = max(risk, 68)
        if "unrestricted" in lower or "bypass" in lower:
            reasons.add("PowerShell execution policy weakened")
            risk = max(risk, 35 if "unrestricted" in lower and "encoded_command" not in indicators and "download_cradle" not in indicators and "invoke_expression" not in indicators else risk)
    if "defender_tampering" in indicators:
        tags.update({"suspicious", "defender_tampering"})
        reasons.add("PowerShell Defender tampering")
        risk = max(risk, 90)
    if "persistence" in indicators:
        tags.update({"suspicious", "persistence"})
        reasons.add("PowerShell persistence command")
        risk = max(risk, 76)
    if "recon" in indicators:
        tags.add("recon")
        risk = max(risk, 5 if not reasons else 38)
    if "credential_access" in indicators:
        tags.update({"suspicious", "credential_access"})
        reasons.add("PowerShell command references credential access or LSASS")
        risk = max(risk, 88)
    if "lolbin" in indicators:
        tags.update({"suspicious", "lolbin"})
        reasons.add("PowerShell uses LOLBin")
        risk = max(risk, 70)
    if "remote_tool" in indicators:
        tags.update({"suspicious", "remote_access_tool"})
        reasons.add("PowerShell command references remote access or transfer tool")
        risk = max(risk, 76)
    if "raw_ip_url" in indicators:
        tags.update({"suspicious", "raw_ip_url"})
        reasons.add("PowerShell command downloads from raw IP")
        risk = max(risk, 72)
    if "paste_site" in indicators:
        tags.update({"suspicious", "paste_site"})
        reasons.add("PowerShell command references paste site")
        risk = max(risk, 70)
    effective_paths = extract_windows_paths(text)
    if file_path:
        effective_paths.insert(0, file_path)
    for path in effective_paths:
        path_reasons = detect_suspicious_path(path)
        if path_reasons:
            tags.update({"suspicious", "suspicious_path"})
            if any(token in path.lower() for token in POWERSHELL_USER_WRITABLE_HINTS):
                reasons.add("PowerShell writes to user-writable path")
            reasons.update(path_reasons)
            risk = max(risk, 64)
        ext = extension_windows(path)
        if ext in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}:
            tags.add("script")
            if any(token in path.lower() for token in POWERSHELL_USER_WRITABLE_HINTS):
                reasons.add("PowerShell script in user-writable path")
            risk = max(risk, 72)
    if len(detect_encoded_command(text) or "") > 120:
        tags.update({"suspicious", "encoded_command"})
        reasons.add("PowerShell EncodedCommand")
        risk = max(risk, 86)
    if not reasons:
        tags.discard("suspicious")
        tags.discard("encoded_command")
        tags.discard("download_cradle")
        tags.discard("invoke_expression")
        tags.discard("execution_policy_bypass")
        tags.discard("defender_tampering")
        tags.discard("persistence")
        tags.discard("lolbin")
        tags.discard("remote_access_tool")
        tags.discard("raw_ip_url")
        tags.discard("paste_site")
        tags.discard("suspicious_path")
    return sorted(tags), sorted(reasons), risk


def preview_command(command: str | None, limit: int = 240) -> str | None:
    text = clean_text(command)
    if not text:
        return None
    compact = re.sub(r"\s+", " ", text).strip()
    return compact[: limit - 3] + "..." if len(compact) > limit else compact


def extract_primary_download_target(command: str | None, paths: list[str] | None = None) -> str | None:
    text = clean_text(command) or ""
    path_candidates = [normalize_windows_path(item) for item in (paths or [])]
    path_candidates = [item for item in path_candidates if item]
    out_file_match = re.search(r"(?i)-(?:outfile|destination|literalpath|filepath)\s+([A-Za-z]:\\[^\r\n\"']+|\"[^\"]+\"|'[^']+')", text)
    if out_file_match:
        return normalize_windows_path(out_file_match.group(1).strip("\"'"))
    if path_candidates:
        script_exts = {".ps1", ".psm1", ".psd1", ".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".hta", ".zip", ".cab"}
        for candidate in reversed(path_candidates):
            if extension_windows(candidate) in script_exts:
                return candidate
        return path_candidates[-1]
    return None


def parse_transcript_header(text: str) -> dict:
    header: dict[str, str | None] = {
        "transcript_start_time": None,
        "transcript_end_time": None,
        "username": None,
        "run_as": None,
        "machine": None,
        "host_application": None,
        "process_id": None,
        "ps_version": None,
        "os": None,
    }
    patterns = {
        "transcript_start_time": r"(?im)^Start time:\s*(.+)$",
        "transcript_end_time": r"(?im)^End time:\s*(.+)$",
        "username": r"(?im)^Username:\s*(.+)$",
        "run_as": r"(?im)^RunAs User:\s*(.+)$",
        "machine": r"(?im)^Machine:\s*(.+)$",
        "host_application": r"(?im)^Host Application:\s*(.+)$",
        "process_id": r"(?im)^Process ID:\s*(.+)$",
        "ps_version": r"(?im)^PSVersion:\s*(.+)$",
        "os": r"(?im)^OS:\s*(.+)$",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, text)
        if match:
            header[key] = clean_text(match.group(1))
    return header


def dumps_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False)
