from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
import re

from app.analysis.suspicious import is_suspicious_double_extension, normalize_windows_path_for_classification


SCHEDULED_TASK_NAME_HINTS = (
    "scheduledtasks",
    "scheduledtask",
    "taskscheduler",
    "scheduled_task",
)

SCHEDULED_TASK_HEADER_HINTS = {
    "taskname",
    "taskpath",
    "author",
    "description",
    "uri",
    "command",
    "arguments",
    "workingdirectory",
    "enabled",
    "principal",
    "userid",
    "runlevel",
    "triggers",
    "actions",
    "registrationinfo",
    "sourcefile",
}

TASK_LOLBIN_HINTS = {
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
    "curl.exe",
    "wget.exe",
    "schtasks.exe",
}

TASK_SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}

KNOWN_SID_NAMES = {
    "s-1-5-18": r"NT AUTHORITY\SYSTEM",
    "s-1-5-19": r"NT AUTHORITY\LOCAL SERVICE",
    "s-1-5-20": r"NT AUTHORITY\NETWORK SERVICE",
    "s-1-5-4": "INTERACTIVE",
}

KNOWN_MICROSOFT_TASK_PREFIXES = (
    "\\microsoft\\windows\\consentux\\",
    "\\microsoft\\windows\\windowsai\\",
    "\\microsoft\\windows\\usb\\",
    "\\microsoft\\windows\\flighting\\",
    "\\microsoft\\windows\\diagnosis\\",
    "\\microsoft\\windows\\management\\",
    "\\microsoft\\windows\\textservicesframework\\",
    "\\microsoft\\windows\\updateorchestrator\\",
    "\\microsoft\\windows\\waasmedic\\",
    "\\microsoft\\windows\\defrag\\",
    "\\microsoft\\windows\\diskcleanup\\",
    "\\microsoft\\windows\\application experience\\",
    "\\microsoft\\windows\\customer experience improvement program\\",
)


def clean_text(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if text in {"", "-", "--", "N/A", "n/a", "null", "None"}:
        return None
    return text


def canonicalize_header(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def normalize_windowsish_path(value: str | None) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    return normalize_windows_path_for_classification(text.replace("/", "\\"))


def parse_bool(value: object | None) -> bool | None:
    text = clean_text(value)
    if not text:
        return None
    lowered = text.lower()
    if lowered in {"true", "yes", "1", "enabled"}:
        return True
    if lowered in {"false", "no", "0", "disabled"}:
        return False
    return None


def parse_isoish_timestamp(value: object | None) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        try:
            from dateutil import parser as date_parser

            parsed = date_parser.parse(text)
        except Exception:  # noqa: BLE001
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.isoformat()


def basename_windows(path: str | None) -> str | None:
    normalized = normalize_windowsish_path(path)
    if not normalized:
        return None
    try:
        return PureWindowsPath(normalized).name or normalized
    except Exception:  # noqa: BLE001
        return Path(normalized.replace("\\", "/")).name or normalized


def extension_windows(path: str | None) -> str | None:
    name = basename_windows(path)
    if not name or "." not in name:
        return None
    return "." + name.split(".")[-1].lower()


def infer_task_identity_from_filesystem_path(path: str) -> tuple[str | None, str | None]:
    normalized = normalize_windowsish_path(path)
    if not normalized:
        return None, None
    lowered = normalized.lower()
    for marker in ("\\windows\\system32\\tasks\\", "\\windows\\tasks\\"):
        index = lowered.find(marker)
        if index == -1:
            continue
        relative = normalized[index + len(marker) :].strip("\\")
        if not relative:
            return None, None
        task_path = "\\" + relative
        return task_path, basename_windows(relative)
    return None, basename_windows(normalized)


def looks_like_scheduled_task_xml_path(path: Path) -> bool:
    lower_name = path.name.lower()
    if lower_name in {"desktop.ini"}:
        return False
    normalized = str(path).replace("/", "\\").lower()
    return (
        "\\windows\\system32\\tasks\\" in normalized
        or "\\system32\\tasks\\" in normalized
        or "\\windows\\tasks\\" in normalized
    )


def looks_like_scheduled_task_artifact(path: Path, headers: list[str] | None = None) -> bool:
    lower_name = path.name.lower()
    if any(token in lower_name for token in SCHEDULED_TASK_NAME_HINTS):
        return True
    if path.suffix.lower() == ".csv":
        header_set = {canonicalize_header(header) for header in (headers or []) if header}
        return len(header_set & SCHEDULED_TASK_HEADER_HINTS) >= 4
    if path.suffix.lower() == ".xml":
        return looks_like_scheduled_task_xml_path(path)
    return looks_like_scheduled_task_xml_path(path)


def resolve_known_windows_sid(value: str | None) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    return KNOWN_SID_NAMES.get(text.lower())


def is_known_microsoft_task_path(task_path: str | None) -> bool:
    text = clean_text(task_path)
    if not text:
        return False
    lowered = text.replace("/", "\\").strip().lower()
    if not lowered.startswith("\\"):
        lowered = f"\\{lowered.lstrip('\\')}"
    return lowered.startswith("\\microsoft\\windows\\") or lowered.startswith(KNOWN_MICROSOFT_TASK_PREFIXES)


def task_name_looks_suspicious(name: str | None, *, task_path: str | None = None) -> bool:
    text = (name or "").strip()
    if not text:
        return True
    if is_known_microsoft_task_path(task_path):
        return False
    lowered = text.lower()
    if any(ord(char) < 32 for char in text) or any(char in text for char in ("\u202e", "\u200f", "\u200e")):
        return True
    if re.search(r"\s{2,}", text):
        return True
    if is_suspicious_double_extension(text):
        return True
    if re.fullmatch(r"\{?[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\}?", lowered):
        return True
    if re.fullmatch(r"[a-z0-9]{12,}", lowered):
        return True
    if any(token in lowered for token in ["updtae", "windwos", "microsofft", "svch0st", "exp1orer", "cons0nt", "policyy"]):
        return True
    return False
