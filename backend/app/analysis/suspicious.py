from pathlib import Path
import re

DECOY_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".xlsm", ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    ".svg", ".zip", ".rar", ".7z", ".iso", ".csv", ".xml", ".json",
    ".html", ".htm",
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".jse", ".wsf", ".msi", ".dll", ".com", ".lnk", ".pif", ".cpl",
}


SUSPICIOUS_POWERSHELL_TOKENS = {
    "-enc": "powershell_encoded",
    "-encodedcommand": "powershell_encoded",
    "frombase64string": "base64_decode",
    "iex": "invoke_expression",
    "invoke-expression": "invoke_expression",
    "downloadstring": "download",
    "invoke-webrequest": "download",
    "iwr": "download",
    "curl": "download",
    "wget": "download",
    "start-bitstransfer": "download",
    "add-mppreference": "defender_tamper",
    "set-mppreference": "defender_tamper",
    "executionpolicy bypass": "execution_policy_bypass",
    "-nop": "no_profile",
    "-w hidden": "hidden_window",
    "net.webclient": "download",
    "rundll32": "lolbin",
    "regsvr32": "lolbin",
    "mshta": "lolbin",
}

SUSPICIOUS_PATH_PATTERNS = [
    (r"\\appdata\\", "appdata_path"),
    (r"\\temp\\", "temp_path"),
    (r"\\downloads\\", "downloads_path"),
    (r"\\desktop\\", "desktop_path"),
    (r"\\users\\public\\", "public_path"),
    (r"\\programdata\\", "programdata_path"),
    (r"\$recycle\.bin", "recycle_bin_path"),
    (r"^\\\\", "unc_path"),
]


def normalize_windows_path_for_classification(path: str | None) -> str | None:
    if not path:
        return None
    normalized = str(path).strip().replace("/", "\\")
    if not normalized:
        return None
    if normalized.startswith("\\\\?\\UNC\\"):
        return "\\\\" + normalized.removeprefix("\\\\?\\UNC\\")
    if normalized.startswith("\\??\\UNC\\"):
        return "\\\\" + normalized.removeprefix("\\??\\UNC\\")
    if normalized.startswith("\\\\?\\Volume{"):
        return "\\" + normalized.removeprefix("\\\\?\\")
    if normalized.startswith("\\\\?\\") and re.match(r"^[A-Za-z]:\\", normalized.removeprefix("\\\\?\\")):
        return normalized.removeprefix("\\\\?\\")
    if normalized.startswith("\\??\\") and re.match(r"^[A-Za-z]:\\", normalized.removeprefix("\\??\\")):
        return normalized.removeprefix("\\??\\")
    if normalized.startswith("\\\\.\\") and re.match(r"^[A-Za-z]:\\", normalized.removeprefix("\\\\.\\")):
        return normalized.removeprefix("\\\\.\\")
    return normalized


def is_windows_unc_path(path: str | None) -> bool:
    normalized = normalize_windows_path_for_classification(path)
    return bool(normalized and normalized.startswith("\\\\"))


def detect_suspicious_powershell(text: str | None) -> list[str]:
    if not text:
        return []
    lower = text.lower()
    reasons = []
    for token, reason in SUSPICIOUS_POWERSHELL_TOKENS.items():
        if token in lower:
            reasons.append(reason)
    return sorted(set(reasons))


def is_suspicious_double_extension(filename: str | None) -> bool:
    name = Path(str(filename or "")).name.lower().strip()
    if not name:
        return False
    suffixes = Path(name).suffixes
    if len(suffixes) < 2:
        return False
    final_ext = suffixes[-1]
    previous_ext = suffixes[-2]
    return final_ext in EXECUTABLE_EXTENSIONS and previous_ext in DECOY_EXTENSIONS


def detect_suspicious_path(path: str | None) -> list[str]:
    normalized_path = normalize_windows_path_for_classification(path)
    if not normalized_path:
        return []
    lower = normalized_path.lower()
    reasons = [reason for pattern, reason in SUSPICIOUS_PATH_PATTERNS if re.search(pattern, lower)]
    name = Path(normalized_path).name.lower()
    if is_suspicious_double_extension(name):
        reasons.append("double_extension")
    if any(token in lower for token in ["\\downloads\\", "\\desktop\\", "\\temp\\"]) and any(name.endswith(suffix) for suffix in [".ps1", ".cmd", ".bat", ".vbs", ".js", ".jse", ".hta"]):
        reasons.append("script_execution_from_user_folder")
    return sorted(set(reasons))
