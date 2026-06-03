import re
from pathlib import Path


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
]
INVALID_HOST_VALUES = {"", "unknown", "n/a", "na", "none"}
INVALID_HOST_PATTERNS = (".zip", ".7z", ".csv", ".json", ".jsonl", ".txt", ".evtx", ".xml", ".dat")
INVALID_HOST_EXACT = {
    "ntuser.dat",
    "usrclass.dat",
    "system",
    "software",
    "security",
    "sam",
    "srudb.dat",
    "qmgr0.dat",
    "qmgr1.dat",
    "scheduled_task_regression.xml",
}
REJECTED_DRIVER_OR_FILTER_NAMES = {
    "applockerfltr",
    "cldflt",
    "wdfilter",
    "filecrypt",
    "fileinfo",
    "npsvctrig",
    "luafv",
    "wcifs",
    "bindflt",
    "storqosflt",
    "fltmgr",
    "ntfs",
    "tcpip",
    "afd",
    "mpsdrv",
    "srvnet",
    "srv2",
}
REMOTE_DOMAIN_SUFFIXES = (
    ".windows.com",
    ".microsoft.com",
    ".live.com",
    ".akadns.net",
    ".msftncsi.com",
    ".trafficmanager.net",
)
COLLECTION_RE = re.compile(r"Collection-([A-Za-z0-9._-]+)-\d{4}-\d{2}-\d{2}T")


def normalize_hostname(value: str | None) -> str | None:
    if value is None:
        return None
    candidate = str(value).strip().strip('"').strip("'")
    if not candidate:
        return None
    if candidate.lower() in INVALID_HOST_VALUES:
        return None
    if candidate.lower() in INVALID_HOST_EXACT:
        return None
    if candidate.lower() in REJECTED_DRIVER_OR_FILTER_NAMES:
        return None
    if len(candidate) > 64:
        return None
    if "/" in candidate or "\\" in candidate:
        return None
    if any(candidate.lower().endswith(suffix) for suffix in INVALID_HOST_PATTERNS):
        return None
    if "collection-" in candidate.lower():
        match = COLLECTION_RE.search(candidate)
        if match:
            candidate = match.group(1)
        else:
            return None
    candidate = candidate.rstrip(".")
    if not candidate:
        return None
    if any(candidate.lower().endswith(suffix) for suffix in REMOTE_DOMAIN_SUFFIXES):
        return None
    return candidate.lower()


def is_probable_hostname(value: str | None) -> bool:
    candidate = normalize_hostname(value)
    if not candidate:
        return False
    if re.search(r"\d{4}-\d{2}-\d{2}", candidate):
        return False
    return bool(re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,62}", candidate))


def detect_host_from_row(row: dict) -> str | None:
    for field in HOST_FIELDS:
        for key, value in row.items():
            if str(key or "").lower() == field.lower() and is_probable_hostname(str(value)):
                return normalize_hostname(str(value))
    return None


def detect_host_from_artifacts(artifacts: list[dict]) -> str | None:
    for artifact in artifacts:
        candidate = artifact.get("detected_host")
        if is_probable_hostname(candidate):
            return normalize_hostname(candidate)
    return None


def detect_host_from_velociraptor_collection(root: Path) -> str | None:
    candidates = [root.name, root.parent.name]
    for candidate_name in candidates:
        match = COLLECTION_RE.search(candidate_name)
        if match:
            candidate = normalize_hostname(match.group(1))
            if is_probable_hostname(candidate):
                return candidate
    match = COLLECTION_RE.search(root.stem)
    if match:
        candidate = normalize_hostname(match.group(1))
        if is_probable_hostname(candidate):
            return candidate
    return None
