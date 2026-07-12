"""Package log parser for dpkg.log, yum.log, dnf.log, apt/history.log."""
from __future__ import annotations
import re
from datetime import datetime, timezone
from pathlib import Path

_MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

_DPKG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s+(\S.*)$"
)

_YUM_DNF_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S.*?)\s*:\s*(\S+)$"
)

_APT_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(.+)$"
)


def _parse_dpkg_timestamp(ts_str: str) -> str | None:
    try:
        dt = datetime.strptime(ts_str.strip(), "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except (ValueError, OverflowError):
        return None


def _parse_yum_timestamp(ts_str: str) -> str | None:
    ts_str = ts_str.strip()
    match = re.match(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", ts_str)
    if not match:
        return None
    month_str, day_str, hour_str, minute_str, second_str = match.groups()
    month = _MONTH_MAP.get(month_str.lower())
    if month is None:
        return None
    now = datetime.now(tz=timezone.utc)
    year = now.year
    try:
        dt = datetime(year, month, int(day_str), int(hour_str), int(minute_str), int(second_str), tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return None
    if dt > now:
        try:
            dt = datetime(year - 1, month, int(day_str), int(hour_str), int(minute_str), int(second_str), tzinfo=timezone.utc)
        except (ValueError, OverflowError):
            return None
    return dt.isoformat()


def _detect_package_manager(source_path: str) -> str:
    lower = str(source_path).lower()
    if "dpkg" in lower:
        return "dpkg"
    if "yum" in lower:
        return "yum"
    if "dnf" in lower:
        return "dnf"
    if "apt" in lower:
        return "apt"
    return "unknown"


def _detect_action(text: str) -> str:
    lower = text.lower()
    if "install" in lower and "upgrade" not in lower:
        return "install"
    if "upgrade" in lower:
        return "upgrade"
    if "remove" in lower or "purge" in lower:
        return "remove"
    if "downgrade" in lower:
        return "downgrade"
    if "configure" in lower:
        return "configure"
    if "status" in lower:
        return "status"
    return "unknown"


def _parse_dpkg_log(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        raw_excerpt = stripped[:2000]
        dpkg_match = _DPKG_RE.match(stripped)
        if dpkg_match:
            ts_str, action, package, message = dpkg_match.groups()
            timestamp = _parse_dpkg_timestamp(ts_str)
            results.append({
                "artifact_family": "linux_packages",
                "artifact_type": "dpkg_log",
                "source_file": source_path,
                "line_number": line_number,
                "timestamp": timestamp,
                "package_manager": "dpkg",
                "action": action.strip(),
                "package": package.strip(),
                "version": None,
                "message": message[:2000],
                "raw_excerpt": raw_excerpt,
            })
        else:
            results.append({
                "artifact_family": "linux_packages",
                "artifact_type": "dpkg_log",
                "source_file": source_path,
                "line_number": line_number,
                "timestamp": None,
                "package_manager": "dpkg",
                "action": "unknown",
                "package": None,
                "version": None,
                "message": stripped[:2000],
                "raw_excerpt": raw_excerpt,
            })
    return results


def _parse_yum_dnf_log(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    manager = _detect_package_manager(source_path)
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        raw_excerpt = stripped[:2000]
        match = _YUM_DNF_RE.match(stripped)
        if match:
            ts_str, action_and_pkg, info = match.groups()
            timestamp = _parse_yum_timestamp(ts_str)
            action = _detect_action(stripped)
            parts = action_and_pkg.split()
            package = parts[-1] if parts else action_and_pkg
            version = None
            version_match = re.search(r"\b\d+[.-][\d.]+", action_and_pkg)
            if version_match:
                version = version_match.group(0)
            results.append({
                "artifact_family": "linux_packages",
                "artifact_type": f"{manager}_log",
                "source_file": source_path,
                "line_number": line_number,
                "timestamp": timestamp,
                "package_manager": manager,
                "action": action,
                "package": package,
                "version": version,
                "message": stripped[:2000],
                "raw_excerpt": raw_excerpt,
            })
        else:
            results.append({
                "artifact_family": "linux_packages",
                "artifact_type": f"{manager}_log",
                "source_file": source_path,
                "line_number": line_number,
                "timestamp": None,
                "package_manager": manager,
                "action": "unknown",
                "package": None,
                "version": None,
                "message": stripped[:2000],
                "raw_excerpt": raw_excerpt,
            })
    return results


def _parse_apt_history(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        raw_excerpt = stripped[:2000]
        apt_match = _APT_RE.match(stripped)
        timestamp = None
        message = stripped
        if apt_match:
            ts_str, message = apt_match.groups()
            timestamp = _parse_dpkg_timestamp(ts_str)
        action = _detect_action(stripped)
        package_match = re.search(r"(\S+)\s*:\S+", stripped)
        package = package_match.group(1) if package_match else None
        version = None
        if package:
            ver_match = re.search(rf"{re.escape(package)}\s*:\s*(\S+)", stripped)
            if ver_match:
                version = ver_match.group(1)
        results.append({
            "artifact_family": "linux_packages",
            "artifact_type": "apt_history",
            "source_file": source_path,
            "line_number": line_number,
            "timestamp": timestamp,
            "package_manager": "apt",
            "action": action,
            "package": package,
            "version": version,
            "message": message[:2000],
            "raw_excerpt": raw_excerpt,
        })
    return results


def parse_packages(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    manager = _detect_package_manager(source_path)
    if manager == "dpkg":
        return _parse_dpkg_log(content, source_path=source_path, username=username)
    if manager in ("yum", "dnf"):
        return _parse_yum_dnf_log(content, source_path=source_path, username=username)
    if manager == "apt":
        return _parse_apt_history(content, source_path=source_path, username=username)
    dpkg_hint = content[:200].count(" ") if len(content) > 0 else 0
    if re.search(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}", content):
        return _parse_dpkg_log(content, source_path=source_path, username=username)
    return _parse_yum_dnf_log(content, source_path=source_path, username=username)
