from __future__ import annotations

import csv
from datetime import UTC
from pathlib import Path, PureWindowsPath
import re
import shlex
from urllib.parse import urlparse

from dateutil import parser as date_parser


AUTORUNS_NAME_HINTS = (
    "autoruns",
    "autorunsc",
    "autostart",
    "asep",
)
AUTORUNS_HEADER_HINTS = {
    "artifacttype",
    "time",
    "entrylocation",
    "entry",
    "enabled",
    "category",
    "profile",
    "description",
    "publisher",
    "imagepath",
    "launchstring",
    "md5",
    "sha1",
    "sha256",
    "pesha1",
    "pesha256",
    "company",
    "version",
    "signer",
    "vtdetection",
    "vtlink",
    "virustotal",
    "commandline",
    "keypath",
    "valuename",
    "valuedata",
    "lastwritetime",
    "path",
    "command",
    "sourcefile",
    "hive",
    "user",
    "sid",
    "wow64",
    "runkey",
    "taskname",
    "servicename",
}
USER_WRITABLE_TOKENS = (
    "\\users\\",
    "\\appdata\\",
    "\\temp\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\start menu\\programs\\startup\\",
)
SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".scr", ".msi"}
LOLBIN_HINTS = {
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
    "reg.exe",
    "sc.exe",
    "installutil.exe",
    "msiexec.exe",
}
SUSPICIOUS_COMMAND_TOKENS = {
    "-enc": "Autorun entry contains encoded PowerShell",
    "encodedcommand": "Autorun entry contains encoded PowerShell",
    "bypass": "Autorun entry contains suspicious PowerShell flags",
    "hidden": "Autorun entry contains suspicious PowerShell flags",
    "downloadstring": "Autorun entry downloads remote content",
    "invoke-expression": "Autorun entry contains suspicious PowerShell execution",
    "iex": "Autorun entry contains suspicious PowerShell execution",
    "iwr": "Autorun entry downloads remote content",
    "irm": "Autorun entry downloads remote content",
    "frombase64string": "Autorun entry contains encoded PowerShell",
    "http://": "Autorun entry downloads remote content",
    "https://": "Autorun entry downloads remote content",
    "\\\\": "Autorun entry references UNC path",
}
URL_RE = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"'>,;]+")
UNC_RE = re.compile(r"\\\\[A-Za-z0-9_.-]+\\[^\s\"'>,;]+")


def canonicalize_header(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def first_nonempty(row: dict, *names: str) -> str | None:
    lowered = {str(key).lower(): value for key, value in row.items()}
    canon = {canonicalize_header(key): value for key, value in row.items()}
    for name in names:
        for candidate in (name, name.lower(), canonicalize_header(name)):
            value = lowered.get(candidate) if candidate in lowered else canon.get(candidate)
            if value not in (None, ""):
                return str(value)
    return None


def clean_value(value: str | None) -> str | None:
    if value in (None, ""):
        return None
    cleaned = str(value).strip().strip('"').strip("'")
    if cleaned.lower() in {"-", "--", "n/a", "na", "(null)", "null", "none", "unknown"}:
        return None
    return cleaned


def normalize_windows_path(value: str | None) -> str | None:
    cleaned = clean_value(value)
    if not cleaned:
        return None
    return cleaned.replace("/", "\\")


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


def looks_like_autoruns_artifact(path: Path, headers: list[str] | None = None) -> bool:
    suffix = path.suffix.lower()
    if suffix not in {".csv", ".tsv", ".xml", ".json", ".jsonl"}:
        return False
    lower_name = path.name.lower()
    if any(token in lower_name for token in AUTORUNS_NAME_HINTS):
        return True
    header_set = {canonicalize_header(header) for header in (headers or []) if header}
    if "artifacttype" in header_set and (
        {"keypath", "valuename", "valuedata"} <= header_set
        or {"entrylocation", "entry", "launchstring"} <= header_set
        or ("lastwritetime" in header_set and {"keypath", "valuedata"} & header_set)
    ):
        return True
    if (
        {"keypath", "valuename", "valuedata"} <= header_set
        or {"entrylocation", "entry", "launchstring"} <= header_set
    ):
        return True
    if "startup" in lower_name and {"path", "command"} <= header_set:
        return True
    return len(header_set & AUTORUNS_HEADER_HINTS) >= 4


def _entry_blob(category: str | None, entry_location: str | None, image_path: str | None, launch_string: str | None) -> str:
    return " ".join(str(part or "") for part in [category, entry_location, image_path, launch_string]).lower()


def classify_autoruns_entry(entry_location: str | None, category: str | None, image_path: str | None, launch_string: str | None) -> tuple[str, str]:
    blob = _entry_blob(category, entry_location, image_path, launch_string)
    if "ifeo" in blob or "image file execution options" in blob or "debugger" in blob:
        return "ifeo_debugger", "ifeo_debugger"
    if "winlogon" in blob and "userinit" in blob:
        return "winlogon_userinit", "winlogon"
    if "winlogon" in blob and "shell" in blob:
        return "winlogon_shell", "winlogon"
    if "winlogon" in blob:
        return "winlogon_shell", "winlogon"
    if "appinit" in blob:
        return "appinit_dll", "appinit_dll"
    if "appcert" in blob:
        return "appcert_dll", "appcert_dll"
    if "known dll" in blob or "knowndll" in blob:
        return "known_dll", "known_dll"
    if "authentication packages" in blob or "security packages" in blob or "notification packages" in blob or "control\\lsa" in blob:
        return "lsa_package", "lsa_package"
    if "print monitor" in blob or "\\print\\monitors" in blob:
        return "print_monitor", "print_monitor"
    if "active setup" in blob:
        return "active_setup", "active_setup"
    if "bootexecute" in blob:
        return "bootexecute", "bootexecute"
    if "browser helper object" in blob or "bho" in blob:
        return "browser_helper_object", "browser_helper_object"
    if "office" in blob:
        return "office_addin", "office_addin"
    if "wmi" in blob:
        return "wmi", "wmi_persistence"
    if "driver" in blob:
        return "driver", "driver"
    if "service" in blob:
        return "service", "service"
    if "scheduled task" in blob or "task" in blob:
        return "scheduled_task", "scheduled_task"
    if "startup" in blob:
        return "startup_folder", "startup_folder"
    if "runonce" in blob:
        return "runonce_key", "run_key"
    if "run" in blob or "\\run" in blob:
        return "run_key", "run_key"
    if "shell extension" in blob or "explorer" in blob:
        return "shell_extension", "shell_extension"
    return "autoruns_generic", "autorun"


def parse_boolish(value: str | None) -> bool | None:
    cleaned = clean_value(value)
    if not cleaned:
        return None
    lowered = cleaned.lower()
    if lowered in {"true", "yes", "1", "enabled", "signed", "verified", "in use"}:
        return True
    if lowered in {"false", "no", "0", "disabled", "unsigned", "unverified"}:
        return False
    return None


def parse_timestamp(value: str | None) -> str | None:
    cleaned = clean_value(value)
    if not cleaned:
        return None
    try:
        parsed = date_parser.parse(cleaned)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.isoformat()
    except Exception:  # noqa: BLE001
        return None


def parse_hash(value: str | None, expected_lengths: set[int]) -> str | None:
    cleaned = clean_value(value)
    if not cleaned:
        return None
    normalized = re.sub(r"[^0-9a-fA-F]", "", cleaned).lower()
    if len(normalized) in expected_lengths:
        return normalized
    return None


def parse_vt_detection(value: str | None) -> int | None:
    cleaned = clean_value(value)
    if not cleaned:
        return None
    match = re.search(r"(\d+)", cleaned)
    return int(match.group(1)) if match else None


def extract_executable_path_from_launch_string(value: str | None) -> str | None:
    cleaned = clean_value(value)
    if not cleaned:
        return None
    quoted = re.match(r'^\s*"([^"]+)"', cleaned)
    if quoted:
        return normalize_windows_path(quoted.group(1))
    try:
        parts = shlex.split(cleaned, posix=False)
    except Exception:  # noqa: BLE001
        parts = [cleaned]
    if parts:
        candidate = normalize_windows_path(parts[0])
        if candidate and (":\\" in candidate or candidate.startswith("\\\\")):
            return candidate
    path_match = PATH_RE.search(cleaned) or UNC_RE.search(cleaned)
    return normalize_windows_path(path_match.group(0)) if path_match else None


def extract_arguments_from_launch_string(value: str | None) -> str | None:
    cleaned = clean_value(value)
    if not cleaned:
        return None
    executable = extract_executable_path_from_launch_string(cleaned)
    if not executable:
        return None
    lower_cleaned = cleaned.lower()
    lower_executable = executable.lower()
    if lower_cleaned.startswith(f'"{lower_executable}"'):
        remainder = cleaned[len(executable) + 2 :].strip()
        return remainder or None
    if lower_cleaned.startswith(lower_executable):
        remainder = cleaned[len(executable) :].strip()
        return remainder or None
    return None


def detect_user_writable_path(path: str | None) -> bool:
    normalized = normalize_windows_path(path)
    if not normalized:
        return False
    lower = normalized.lower()
    return any(token in lower for token in USER_WRITABLE_TOKENS)


def detect_lolbin(command_line: str | None, image_path: str | None) -> str | None:
    blob = f"{clean_value(command_line) or ''} {basename_windows(image_path) or ''}".lower()
    for token in LOLBIN_HINTS:
        if token in blob:
            return token
    return None


def detect_encoded_powershell(command_line: str | None) -> bool:
    blob = str(command_line or "").lower()
    return "-enc" in blob or "encodedcommand" in blob or "frombase64string" in blob


def detect_suspicious_extension(path: str | None) -> bool:
    return suffix_windows(path) in SUSPICIOUS_EXTENSIONS


def detect_missing_or_invalid_path(path: str | None) -> bool:
    normalized = normalize_windows_path(path)
    if not normalized:
        return True
    return not (":\\" in normalized or normalized.startswith("\\\\"))


def extract_urls_domains_paths(*values: str | None) -> dict[str, list[str]]:
    urls: list[str] = []
    domains: list[str] = []
    paths: list[str] = []
    for value in values:
        if not value:
            continue
        text = str(value)
        for match in URL_RE.findall(text):
            if match not in urls:
                urls.append(match)
            domain = urlparse(match).hostname
            if domain and domain not in domains:
                domains.append(domain)
        for match in UNC_RE.findall(text):
            normalized = normalize_windows_path(match)
            if normalized and normalized not in paths:
                paths.append(normalized)
        for match in PATH_RE.findall(text):
            normalized = normalize_windows_path(match)
            if normalized and normalized not in paths:
                paths.append(normalized)
    return {"urls": urls, "domains": domains, "paths": paths}


def classify_autoruns_suspicion(
    *,
    mechanism: str,
    image_path: str | None,
    command_line: str | None,
    signed: bool | None,
    verified: bool | None,
    publisher: str | None,
    vt_detection: int | None,
) -> tuple[set[str], list[str], int]:
    tags = {"autoruns", "persistence", "asep", mechanism}
    reasons: list[str] = []
    risk = 10
    lower_command = str(command_line or "").lower()
    lower_path = str(image_path or "").lower()
    extension = suffix_windows(image_path)
    trusted_microsoft_onedrive = (
        signed is True
        and verified is True
        and "microsoft" in str(publisher or "").lower()
        and lower_path.endswith("\\microsoft\\onedrive\\onedrive.exe")
    )

    if detect_user_writable_path(image_path) and not trusted_microsoft_onedrive:
        tags.add("user_writable_path")
        reasons.append("Autorun points to user-writable path")
        risk = max(risk, 60)
    if detect_suspicious_extension(image_path):
        tags.add("suspicious_autorun")
        risk = max(risk, 55)
        if extension in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"}:
            reasons.append("Autorun launches script")
        elif extension in {".exe", ".dll", ".msi", ".scr"} and "startup" in lower_path:
            reasons.append("Autorun launches executable from Startup folder")
    lolbin = detect_lolbin(command_line, image_path)
    if lolbin:
        tags.update({"lolbin", "suspicious_autorun"})
        if "powershell" in lolbin:
            reasons.append("Autorun uses PowerShell")
        else:
            reasons.append("Autorun uses LOLBin")
        risk = max(risk, 70)
    if detect_encoded_powershell(command_line):
        tags.update({"encoded_powershell", "suspicious_autorun"})
        reasons.append("Autorun uses encoded PowerShell")
        risk = max(risk, 80)
    for token, reason in SUSPICIOUS_COMMAND_TOKENS.items():
        if token in lower_command:
            if "download" in reason.lower():
                tags.add("download_command")
            if token == "bypass":
                reasons.append("Autorun uses execution policy bypass")
            elif token == "hidden":
                reasons.append("Autorun command has hidden window")
            elif "powershell" not in reason.lower():
                reasons.append(reason.replace("Autorun entry ", "Autorun ").replace("contains suspicious PowerShell flags", "uses PowerShell"))
            risk = max(risk, 72 if "download" in reason.lower() else 68)
    if command_line and "powershell" in lower_command and "Autorun uses PowerShell" not in reasons:
        reasons.append("Autorun uses PowerShell")
    if (
        "powershell" in lower_command
        and (
            "encodedcommand" in lower_command
            or "-enc " in lower_command
            or "-executionpolicy bypass" in lower_command
            or "-windowstyle hidden" in lower_command
            or " -w hidden" in lower_command
        )
    ):
        risk = max(risk, 95)
    if signed is False:
        tags.add("unsigned")
        reasons.append("Autorun unsigned or unverified binary")
        risk = max(risk, 65)
    if verified is False:
        tags.add("unverified")
        if "Autorun unsigned or unverified binary" not in reasons:
            reasons.append("Autorun unsigned or unverified binary")
        risk = max(risk, 58)
    if not publisher:
        tags.add("unknown_publisher")
    if vt_detection and vt_detection > 0:
        tags.update({"suspicious_autorun", "vt_detection"})
        reasons.append("VirusTotal detection reported for autorun target")
        risk = max(risk, 75)
    if mechanism == "run_key":
        if not trusted_microsoft_onedrive:
            reasons.append("Run key persistence")
            risk = max(risk, 35)
        else:
            risk = max(risk, 10)
    if mechanism == "runonce_key":
        reasons.append("RunOnce persistence")
        risk = max(risk, 40)
    if mechanism == "startup_folder":
        reasons.append("Startup folder persistence")
        risk = max(risk, 60)
        if extension in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"}:
            risk = max(risk, 70)
    if mechanism in {"ifeo_debugger", "winlogon_shell", "winlogon_userinit", "appinit_dll", "appcert_dll", "lsa_package", "print_monitor"}:
        tags.add("persistence_candidate")
        mapped_reason = {
            "ifeo_debugger": "IFEO debugger persistence",
            "winlogon_shell": "Winlogon autorun modified",
            "winlogon_userinit": "Winlogon autorun modified",
            "appinit_dll": "AppInit DLL persistence",
            "appcert_dll": "AppInit DLL persistence",
            "lsa_package": "LSA package persistence",
            "print_monitor": "Print Monitor persistence",
        }.get(mechanism)
        if mapped_reason:
            reasons.append(mapped_reason)
        risk = max(risk, 85 if mechanism in {"ifeo_debugger", "winlogon_shell", "winlogon_userinit", "lsa_package"} else 80)
    if extension and re.search(r"\.[^.]+\.(exe|scr|js|vbs|bat|cmd|ps1)$", lower_path):
        reasons.append("Autorun double extension")
        risk = max(risk, 75)
    if any(token in lower_path or token in lower_command for token in {"payload", "update", "invoice", "loader", "beacon", "crack", "keygen"}):
        reasons.append("Autorun suspicious filename keyword")
        risk = max(risk, 70)
    if trusted_microsoft_onedrive:
        tags.discard("user_writable_path")
        tags.discard("suspicious_autorun")
        reasons = [reason for reason in reasons if reason != "Autorun points to user-writable path"]
        risk = min(risk, 10)
    return tags, list(dict.fromkeys(reasons)), risk


def sniff_delimiter(sample: str, *, default: str = ",") -> str:
    if "\t" in sample and sample.count("\t") >= sample.count(","):
        return "\t"
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except Exception:  # noqa: BLE001
        return default
