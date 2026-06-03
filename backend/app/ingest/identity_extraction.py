import re

from app.ingest.host_detection import normalize_hostname


HOST_FIELDS = [
    "Hostname",
    "ComputerName",
    "MachineName",
    "Fqdn",
    "Host",
    "WorkstationName",
    "SourceHostName",
    "DestinationHostName",
    "ClientHostname",
    "SystemName",
    "DeviceName",
    "Computer",
]

USER_PATH_RE = re.compile(r"[A-Za-z]:\\Users\\([^\\]+)\\", re.IGNORECASE)
SID_RE = re.compile(r"^S-\d-\d+-(\d+-){1,14}\d+$", re.IGNORECASE)
INVALID_USERNAME_VALUES = {"", "-", "n/a", "na", "unknown", "null", "none"}
SYSTEM_USERS = {"system", "local service", "network service"}
NON_PERSON_PATH_USERS = {"public", "default", "default user", "all users"}
INVALID_HOST_VALUES = {"", "unknown", "n/a", "na", "none", "localhost"}


def is_valid_hostname(value: str | None) -> bool:
    candidate = normalize_hostname(value)
    return bool(candidate and re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,62}", candidate))


def is_valid_username(value: str | None) -> bool:
    if value is None:
        return False
    candidate = str(value).strip().strip('"').strip("'")
    lower = candidate.lower()
    if not candidate or lower in INVALID_USERNAME_VALUES:
        return False
    if len(candidate) > 64:
        return False
    if any(token in candidate for token in ["=", ",", "\\", "/", ":"]):
        return False
    if candidate.lower().endswith((".csv", ".json", ".zip", ".7z", ".txt", ".evtx")):
        return False
    if SID_RE.match(candidate):
        return False
    if re.fullmatch(r"[0-9a-fA-F-]{32,}", candidate):
        return False
    if " " in candidate and lower not in SYSTEM_USERS:
        return False
    return True


def extract_user_from_path(path: str | None) -> str | None:
    if not path:
        return None
    match = USER_PATH_RE.search(path)
    if not match:
        return None
    candidate = match.group(1)
    if candidate.strip().lower() in NON_PERSON_PATH_USERS:
        return None
    return candidate if is_valid_username(candidate) else None


def extract_host(row: dict, artifact_meta: dict) -> str | None:
    for field in HOST_FIELDS:
        for key, value in row.items():
            if str(key or "").lower() == field.lower() and is_valid_hostname(str(value)):
                return normalize_hostname(str(value))
    host_from_meta = artifact_meta.get("detected_host")
    if is_valid_hostname(host_from_meta):
        return normalize_hostname(str(host_from_meta))
    return None


def extract_user(row: dict, artifact_meta: dict, event_context: dict | None = None) -> str | None:
    context = event_context or {}
    artifact_type = str(artifact_meta.get("artifact_type") or "")
    parser = str(artifact_meta.get("parser") or "")
    event_id = context.get("event_id")

    if event_id in {4624, 4625}:
        candidate = row.get("TargetUserName")
        return str(candidate).strip() if is_valid_username(str(candidate)) else None
    if event_id == 4648:
        candidate = row.get("SubjectUserName")
        return str(candidate).strip() if is_valid_username(str(candidate)) else None
    if event_id == 4688:
        candidate = row.get("SubjectUserName")
        return str(candidate).strip() if is_valid_username(str(candidate)) else None

    if artifact_type in {"browser", "lnk", "jumplist", "shellbags"}:
        for path_value in [
            row.get("Path"),
            row.get("FilePath"),
            row.get("FullPath"),
            row.get("TargetPath"),
            artifact_meta.get("source_path"),
        ]:
            candidate = extract_user_from_path(str(path_value) if path_value else None)
            if candidate:
                return candidate

    if artifact_type in {"mft", "prefetch", "amcache", "shimcache", "process", "network"}:
        if row.get("Owner") and is_valid_username(str(row.get("Owner"))):
            return str(row.get("Owner")).strip()
        return None

    if parser in {"hayabusa", "zimmerman", "generic_csv"}:
        for key in ["UserId", "User", "UserName", "TargetUserName", "SubjectUserName"]:
            value = row.get(key)
            if value and is_valid_username(str(value)):
                return str(value).strip()
    return None
