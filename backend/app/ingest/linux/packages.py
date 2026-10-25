"""Package manager history and installed-package databases.

What was installed, upgraded or removed, when, and -- where the format records it -- by whom and with
which command. Every format below was checked against files written by the real tools.

Text logs (``parse_packages``):

* dpkg: ``/var/log/dpkg.log`` (one action per line) and ``/var/lib/dpkg/status`` (the installed set,
  one stanza per package, no times).
* apt: ``/var/log/apt/history.log`` (one transaction per block, with the command line and the
  ``Requested-By`` sudo user) and ``/var/log/apt/term.log`` (the dpkg output of each run).
* yum: ``/var/log/yum.log``. dnf 4: ``/var/log/dnf.rpm.log`` (package actions) and
  ``/var/log/dnf.log`` (only its ``Command:`` lines; the rest is repository chatter). dnf 5:
  ``/var/log/dnf5.log`` (launch command lines and RPM install/uninstall callbacks).
* pacman: ``/var/log/pacman.log``. zypper: ``/var/log/zypp/history``.
* apk: ``/lib/apk/db/installed`` (installed set), ``/etc/apk/world`` (packages asked for by name) and
  ``/etc/apk/repositories``.
* pacman's local database: ``/var/lib/pacman/local/<package>/desc`` (install date and reason).

Databases (``parse_package_database``): the yum, dnf 4 and dnf 5 transaction histories (SQLite, with
the UID that ran each transaction) and the RPM database (install time of every RPM) in its three
formats: ``rpmdb.sqlite`` (RHEL 9+, Fedora 33+), the Berkeley DB hash file ``/var/lib/rpm/Packages``
(RHEL/CentOS 7-8, Amazon Linux 2, older Fedora and SUSE) and the NDB file ``Packages.db`` (SUSE
15).

dpkg, apt, zypper and old pacman logs write the host's local time with no zone; those rows are marked
``assumed_utc`` and converted with the host's zone by app.ingest.linux.local_time. yum.log writes no
year either (``assumed_year_utc``). dnf, dnf5 and modern pacman logs carry a UTC offset, and the
databases store epoch seconds, so those times are exact.
"""
from __future__ import annotations

import re
import shlex
import shutil
import sqlite3
import struct
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable

ARTIFACT_FAMILY = "linux_packages"
MAX_TEXT = 2000

_MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

_DPKG_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s*(.*)$")
_YUM_RE = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([\w-]+):\s+(\S+)\s*$")
_ISO_LINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+(?:\[\d+\]\s+)?(\S+)\s+(.*)$")
_DNF_RPM_ACTION_RE = re.compile(r"^([A-Z][\w-]*):\s+(\S+)\s*$")
_DNF5_LAUNCH_RE = re.compile(r'^--- DNF5 launched with arguments: "(.*)" ---$')
_DNF5_CALLBACK_RE = re.compile(r'^RPM callback (install|uninstall) start "([^"]+)"')
_PACMAN_RE = re.compile(r"^\[(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?)\]\s+(?:\[([\w-]+)\]\s+)?(.*)$")
_PACMAN_ACTION_RE = re.compile(r"^(installed|removed|upgraded|downgraded|reinstalled)\s+(\S+)\s+\((.*)\)\s*$")
_PACMAN_COMMAND_RE = re.compile(r"^Running '(.*)'\s*$")
_APT_PACKAGE_RE = re.compile(r"([^\s,()]+)\s+\(([^)]*)\)")
_APT_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})$")
_REQUESTED_BY_RE = re.compile(r"^(.*?)\s*\((\d+)\)\s*$")
_TERM_ACTION_RE = re.compile(
    r"^(Unpacking|Setting up|Removing|Purging configuration files for)\s+(\S+)\s+\(([^)]*)\)"
    r"(?:\s+over\s+\(([^)]*)\))?"
)
_TERM_ACTIONS = {
    "Unpacking": "unpack",
    "Setting up": "configure",
    "Removing": "remove",
    "Purging configuration files for": "purge",
}

# dpkg.log action words; anything else is kept as written.
_DPKG_ACTIONS = {"install", "upgrade", "remove", "purge", "configure", "trigproc", "status", "startup", "conffile"}
_YUM_ACTIONS = {
    "installed": "install", "dep-installed": "install", "updated": "upgrade", "erased": "remove",
    "obsoleted": "obsoleted", "reinstalled": "reinstall", "downgraded": "downgrade",
}
_DNF_RPM_ACTIONS = {
    "installed": "install", "install": "install", "upgrade": "upgrade", "upgraded": "upgraded",
    "erase": "remove", "erased": "remove", "removed": "remove", "reinstall": "reinstall",
    "reinstalled": "reinstalled", "downgrade": "downgrade", "downgraded": "downgraded",
    "obsolete": "obsolete", "obsoleted": "obsoleted", "cleanup": "cleanup",
}
_PACMAN_ACTIONS = {"installed": "install", "removed": "remove", "upgraded": "upgrade", "downgraded": "downgrade", "reinstalled": "reinstall"}
_APT_SECTIONS = {
    "Install": "install", "Upgrade": "upgrade", "Downgrade": "downgrade", "Reinstall": "reinstall",
    "Remove": "remove", "Purge": "purge",
}
_ZYPPER_ACTIONS = {
    "install": "install", "remove": "remove", "command": "command", "radd": "repo_add", "rremove": "repo_remove",
    "ralias": "repo_rename", "rurl": "repo_url_change", "patch": "patch",
}
# libdnf (dnf 4) TransactionItemAction / TransactionItemReason / TransactionItemState enums.
_DNF4_ITEM_ACTIONS = {
    1: "install", 2: "downgrade", 3: "downgraded", 4: "obsolete", 5: "obsoleted", 6: "upgrade",
    7: "upgraded", 8: "remove", 9: "reinstall", 10: "reinstalled", 11: "reason_change",
}
_DNF4_REASONS = {1: "dependency", 2: "user", 3: "clean", 4: "weak_dependency", 5: "group"}
_DNF4_ITEM_STATES = {1: "done", 2: "error"}
_YUM_HISTORY_STATES = {
    "install": "install", "true-install": "install", "dep-install": "install", "update": "upgrade",
    "updated": "upgraded", "erase": "remove", "obsoleting": "obsolete", "obsoleted": "obsoleted",
    "reinstall": "reinstall", "downgrade": "downgrade", "downgraded": "downgraded",
}
# A UID the history could not attribute (no audit login UID): -1 or (uint32)-1.
_UNSET_UIDS = {-1, 4294967295}


def _row(artifact_type: str, manager: str, source_path: str, **fields: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_type": artifact_type,
        "source_file": source_path,
        "package_manager": manager,
        "timestamp": None,
        "timestamp_status": "missing",
        "action": "unknown",
        "package": None,
        "version": None,
    }
    row.update(fields)
    if row.get("timestamp") and row["timestamp_status"] == "missing":
        row["timestamp_status"] = "ok"
    row["message"] = str(row.get("message") or "")[:MAX_TEXT]
    row["raw_excerpt"] = str(row.get("raw_excerpt") or row["message"])[:MAX_TEXT]
    return row


def _local_time(date_text: str) -> str | None:
    """A zone-less local time, stamped provisionally as UTC (see app.ingest.linux.local_time)."""
    try:
        return datetime.strptime(" ".join(date_text.split()), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return None


def _iso_time(text: str) -> str | None:
    value = text.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    elif re.search(r"[+-]\d{4}$", value):
        value = f"{value[:-2]}:{value[-2:]}"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat()


def _epoch_time(value: Any) -> str | None:
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _yum_time(ts_str: str) -> str | None:
    """A provisional time for a year-less yum.log line: the latest past date with that month and day."""
    match = re.match(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", ts_str.strip())
    if not match:
        return None
    month = _MONTH_MAP.get(match.group(1).lower())
    if month is None:
        return None
    now = datetime.now(tz=timezone.utc)
    day, hour, minute, second = (int(part) for part in match.groups()[1:])
    for year in range(now.year, now.year - 8, -1):
        try:
            candidate = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
        except ValueError:
            continue  # 29 February outside a leap year
        if candidate <= now:
            return candidate.isoformat()
    return None


def split_nevra(text: str) -> tuple[str, str | None, str | None]:
    """(name, version-release with any epoch, arch) from an RPM ``name-[epoch:]version-release.arch``.

    yum.log writes the epoch before the name (``1:openssl-1.0.2k-21.el7.x86_64``), dnf after it
    (``openssl-1:3.0.7-25.el9.x86_64``); both come back as ``("openssl", "1:...", "x86_64")``.
    """
    value = text.strip()
    epoch = None
    leading = re.match(r"^(\d+):(.+)$", value)
    if leading:
        epoch, value = leading.groups()
    arch = None
    base, dot, tail = value.rpartition(".")
    if dot and tail and re.fullmatch(r"[A-Za-z0-9_]+", tail) and not tail.isdigit():
        value, arch = base, tail
    if ":" in value:
        # dnf's "name-epoch:version-release": the epoch follows the last dash before the colon.
        head, _colon, tail = value.partition(":")
        name, dash, epoch = head.rpartition("-")
        version, dash2, release = tail.rpartition("-")
        if not (dash and dash2 and name and version):
            return value, None, arch
    else:
        parts = value.rsplit("-", 2)
        if len(parts) < 3:
            return value, None, arch
        name, version, release = parts
    edition = f"{version}-{release}"
    if epoch and epoch != "0":
        edition = f"{epoch}:{edition}"
    return name, edition, arch


def _none_if_placeholder(value: str | None) -> str | None:
    return None if value in (None, "", "<none>") else value


def _dpkg_fields(action: str, words: list[str]) -> tuple[str | None, str | None, str | None, str | None]:
    """(package, version, previous version, status) from the words after a dpkg.log action.

    ``install|upgrade|trigproc PKG OLD NEW``, ``remove|purge|configure PKG VER [..]``,
    ``status STATE PKG VER``; ``startup`` and ``conffile`` lines name no package.
    """
    clean = [word for word in words if word]
    if action == "status" and len(clean) >= 3:
        return clean[1], _none_if_placeholder(clean[2]), None, clean[0]
    if action in {"install", "upgrade", "trigproc"} and len(clean) >= 3:
        return clean[0], _none_if_placeholder(clean[2]), _none_if_placeholder(clean[1]), None
    if action in {"remove", "purge", "configure", "unpack"} and clean:
        return clean[0], _none_if_placeholder(clean[1] if len(clean) > 1 else None), None, None
    return None, None, None, None


def _split_arch(package: str) -> tuple[str, str | None]:
    """``nano:arm64`` -> ("nano:arm64", "arm64"): the name keeps the qualifier dpkg writes."""
    _name, colon, arch = package.rpartition(":")
    return package, (arch if colon and arch else None)


# ------------------------------------------------------------------ dpkg / apt


def _parse_dpkg_log(content: str, *, source_path: str) -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        match = _DPKG_RE.match(stripped)
        if not match:
            results.append(_row("dpkg_log", "dpkg", source_path, line_number=line_number, message=stripped))
            continue
        ts_str, action, first, rest = match.groups()
        timestamp = _local_time(ts_str)
        package, version, previous_version, package_status = _dpkg_fields(action, [first, *rest.split()])
        results.append(_row(
            "dpkg_log", "dpkg", source_path,
            line_number=line_number,
            timestamp=timestamp,
            timestamp_status="assumed_utc" if timestamp else "missing",
            action=action if action in _DPKG_ACTIONS else action.lower(),
            package=package,
            package_arch=_split_arch(package)[1] if package else None,
            version=version,
            previous_version=previous_version,
            package_status=package_status,
            message=f"{action} {first} {rest}".strip(),
            raw_excerpt=stripped,
        ))
    return results


def _stanzas(content: str) -> list[tuple[int, dict[str, str]]]:
    """Blank-line separated ``Key: value`` stanzas (dpkg status) with continuation lines folded in."""
    stanzas: list[tuple[int, dict[str, str]]] = []
    current: dict[str, str] = {}
    start = 1
    key = None
    for line_number, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            if current:
                stanzas.append((start, current))
            current, key = {}, None
            continue
        if not current:
            start = line_number
        if line[:1] in {" ", "\t"}:
            continue  # continuation of a multi-line field (Description, Conffiles): not needed here
        key, sep, value = line.partition(":")
        if sep:
            current[key.strip()] = value.strip()
    if current:
        stanzas.append((start, current))
    return stanzas


def _parse_dpkg_status(content: str, *, source_path: str) -> list[dict]:
    results: list[dict] = []
    for line_number, fields in _stanzas(content):
        package = fields.get("Package")
        if not package:
            continue
        status = fields.get("Status", "")
        state = status.split()[-1] if status.split() else ""
        arch = fields.get("Architecture")
        results.append(_row(
            "dpkg_status", "dpkg", source_path,
            line_number=line_number,
            action="installed" if state == "installed" else state or "unknown",
            package=package if not arch or arch == "all" else f"{package}:{arch}",
            package_arch=arch,
            version=fields.get("Version"),
            package_status=status,
            message=f"{package} {fields.get('Version', '')} ({status})".strip(),
            raw_excerpt=f"Package: {package}\nStatus: {status}\nVersion: {fields.get('Version', '')}",
        ))
    return results


def _apt_packages(section: str, text: str) -> list[tuple[str, str | None, str | None, bool]]:
    """(package, version, previous version, automatic) for each entry of an apt history section."""
    entries = []
    for package, inner in _APT_PACKAGE_RE.findall(text):
        parts = [part.strip() for part in inner.split(",")]
        automatic = "automatic" in parts
        parts = [part for part in parts if part and part != "automatic"]
        if section in {"Upgrade", "Downgrade"} and len(parts) >= 2:
            entries.append((package, parts[1], parts[0], automatic))
        else:
            entries.append((package, parts[0] if parts else None, None, automatic))
    return entries


def _parse_apt_history(content: str, *, source_path: str) -> list[dict]:
    results: list[dict] = []
    block: dict[str, Any] = {}
    sections: list[tuple[int, str, str]] = []

    def flush() -> None:
        if not block and not sections:
            return
        start = block.get("start")
        timestamp = _local_time(start) if start else None
        common: dict[str, Any] = {
            "timestamp": timestamp,
            "timestamp_status": "assumed_utc" if timestamp else "missing",
            "command": block.get("Commandline"),
            "username": block.get("username"),
            "uid": block.get("uid"),
            "package_status": "error" if block.get("Error") else None,
        }
        emitted = False
        for line_number, section, text in sections:
            action = _APT_SECTIONS[section]
            for package, version, previous, automatic in _apt_packages(section, text):
                emitted = True
                results.append(_row(
                    "apt_history", "apt", source_path,
                    line_number=line_number,
                    action=action,
                    package=package,
                    package_arch=_split_arch(package)[1],
                    version=version,
                    previous_version=previous,
                    package_reason="automatic" if automatic else "requested",
                    message=f"{action} {package} {version or ''}".strip() + (f" ({block['Commandline']})" if block.get("Commandline") else ""),
                    raw_excerpt=f"{section}: {package} ({', '.join(filter(None, [previous, version]))})",
                    **common,
                ))
        if not emitted:
            # A transaction that changed nothing (an error, an aborted run) still records who ran what.
            results.append(_row(
                "apt_history", "apt", source_path,
                line_number=block.get("line"),
                action="error" if block.get("Error") else "command",
                message=block.get("Error") or block.get("Commandline") or "apt transaction",
                **common,
            ))
        block.clear()
        sections.clear()

    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        key, sep, value = stripped.partition(":")
        key, value = key.strip(), value.strip()
        if not sep:
            continue
        if key == "Start-Date":
            flush()
            block["start"] = value
            block["line"] = line_number
        elif key in _APT_SECTIONS:
            sections.append((line_number, key, value))
        elif key == "Requested-By":
            match = _REQUESTED_BY_RE.match(value)
            block["username"], block["uid"] = (match.group(1), int(match.group(2))) if match else (value, None)
        elif key in {"Commandline", "Error"}:
            block[key] = value
            block.setdefault("line", line_number)
        elif key == "End-Date":
            flush()
    flush()
    return results


def _parse_apt_term(content: str, *, source_path: str) -> list[dict]:
    results: list[dict] = []
    timestamp = None
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("(Reading database", "Preparing to unpack")):
            # Progress output, and the line naming the .deb file that the "Unpacking" line repeats.
            continue
        if stripped.startswith("Log started:"):
            timestamp = _local_time(stripped.partition(":")[2])
            continue
        if stripped.startswith("Log ended:"):
            continue
        match = _TERM_ACTION_RE.match(stripped)
        fields: dict[str, Any] = {"action": "output"}
        if match:
            verb, package, version, previous = match.groups()
            fields = {"action": _TERM_ACTIONS[verb], "package": package, "version": version, "previous_version": previous}
        results.append(_row(
            "apt_term", "apt", source_path,
            line_number=line_number,
            timestamp=timestamp,
            timestamp_status="assumed_utc" if timestamp else "missing",
            message=stripped,
            **fields,
        ))
    return results


# ------------------------------------------------------------------ yum / dnf


def _parse_yum_log(content: str, *, source_path: str) -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        match = _YUM_RE.match(stripped)
        if not match:
            results.append(_row("yum_log", "yum", source_path, line_number=line_number, message=stripped))
            continue
        ts_str, verb, nevra = match.groups()
        timestamp = _yum_time(ts_str)
        name, version, arch = split_nevra(nevra)
        results.append(_row(
            "yum_log", "yum", source_path,
            line_number=line_number,
            timestamp=timestamp,
            timestamp_status="assumed_year_utc" if timestamp else "missing",
            action=_YUM_ACTIONS.get(verb.lower(), verb.lower()),
            package=name,
            version=version,
            package_arch=arch,
            message=f"{verb}: {nevra}",
            raw_excerpt=stripped,
        ))
    return results


def _parse_dnf_rpm_log(content: str, *, source_path: str) -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        match = _ISO_LINE_RE.match(stripped)
        if not match:
            if stripped:
                results.append(_row("dnf_rpm_log", "dnf", source_path, line_number=line_number, action="log", message=stripped))
            continue
        ts_str, _level, message = match.groups()
        if message.startswith("--- logging initialized"):
            continue
        timestamp = _iso_time(ts_str)
        action_match = _DNF_RPM_ACTION_RE.match(message)
        fields: dict[str, Any] = {"action": "log"}
        if action_match:
            verb, nevra = action_match.groups()
            name, version, arch = split_nevra(nevra)
            fields = {"action": _DNF_RPM_ACTIONS.get(verb.lower(), verb.lower()), "package": name, "version": version, "package_arch": arch}
        results.append(_row(
            "dnf_rpm_log", "dnf", source_path,
            line_number=line_number, timestamp=timestamp, message=message, raw_excerpt=stripped, **fields,
        ))
    return results


def _parse_dnf_log(content: str, *, source_path: str) -> list[dict]:
    """dnf.log: the command line of every run; the repository and solver chatter is left out."""
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        match = _ISO_LINE_RE.match(line.strip())
        if not match:
            continue
        ts_str, _level, message = match.groups()
        if not message.startswith("Command:"):
            continue
        command = message.partition(":")[2].strip()
        results.append(_row(
            "dnf_log", "dnf", source_path,
            line_number=line_number, timestamp=_iso_time(ts_str), action="command", command=command,
            message=f"dnf command: {command}", raw_excerpt=line.strip(),
        ))
    return results


def _parse_dnf5_log(content: str, *, source_path: str) -> list[dict]:
    """dnf5.log: launch command lines and the RPM install/uninstall start callbacks."""
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        match = _ISO_LINE_RE.match(line.strip())
        if not match:
            continue
        ts_str, _level, message = match.groups()
        launch = _DNF5_LAUNCH_RE.match(message)
        callback = _DNF5_CALLBACK_RE.match(message)
        if launch:
            fields: dict[str, Any] = {"action": "command", "command": launch.group(1), "message": f"dnf5 command: {launch.group(1)}"}
        elif callback:
            verb, nevra = callback.groups()
            name, version, arch = split_nevra(nevra)
            action = "install" if verb == "install" else "remove"
            fields = {"action": action, "package": name, "version": version, "package_arch": arch, "message": f"{action} {nevra}"}
        else:
            continue
        results.append(_row("dnf5_log", "dnf5", source_path, line_number=line_number, timestamp=_iso_time(ts_str), raw_excerpt=line.strip(), **fields))
    return results


# ------------------------------------------------------------------ pacman / zypper / apk


def _parse_pacman_log(content: str, *, source_path: str) -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        match = _PACMAN_RE.match(stripped)
        if not match:
            if stripped:
                results.append(_row("pacman_log", "pacman", source_path, line_number=line_number, action="output", message=stripped))
            continue
        ts_str, tag, message = match.groups()
        exact = _iso_time(ts_str.replace(" ", "T"))
        if exact:
            timestamp, status = exact, "ok"
        else:
            # pacman before 5.2 wrote local time without seconds or zone: "[2019-01-21 10:00]".
            local = ts_str.replace("T", " ")
            timestamp = _local_time(local if local.count(":") == 2 else f"{local}:00")
            status = "assumed_utc" if timestamp else "missing"
        fields: dict[str, Any] = {"action": "output" if tag == "ALPM-SCRIPTLET" else "log"}
        action_match = _PACMAN_ACTION_RE.match(message)
        command_match = _PACMAN_COMMAND_RE.match(message)
        if action_match:
            verb, package, versions = action_match.groups()
            previous, arrow, version = versions.partition(" -> ")
            fields = {
                "action": _PACMAN_ACTIONS[verb],
                "package": package,
                "version": version if arrow else versions,
                "previous_version": previous if arrow else None,
            }
        elif command_match:
            fields = {"action": "command", "command": command_match.group(1)}
        results.append(_row(
            "pacman_log", "pacman", source_path,
            line_number=line_number, timestamp=timestamp, timestamp_status=status, component=tag,
            message=message, raw_excerpt=stripped, **fields,
        ))
    return results


def _parse_pacman_desc(content: str, *, source_path: str) -> list[dict]:
    """One installed package of pacman's local database: ``%KEY%`` headers, values on the lines after."""
    fields: dict[str, list[str]] = {}
    key = None
    for line in content.splitlines():
        stripped = line.strip()
        if re.fullmatch(r"%[A-Z0-9]+%", stripped):
            key = stripped.strip("%")
            fields[key] = []
        elif stripped and key:
            fields[key].append(stripped)
    first = lambda name: (fields.get(name) or [None])[0]  # noqa: E731
    name = first("NAME")
    if not name:
        return []
    timestamp = _epoch_time(first("INSTALLDATE"))
    return [_row(
        "pacman_local", "pacman", source_path,
        line_number=1,
        timestamp=timestamp,
        action="installed",
        package=name,
        version=first("VERSION"),
        package_arch=first("ARCH"),
        # %REASON% 1 means "installed as a dependency"; the field is absent for explicit installs.
        package_reason="dependency" if first("REASON") == "1" else "explicit",
        message=f"{name} {first('VERSION') or ''} installed".strip(),
        raw_excerpt=f"%NAME% {name} %VERSION% {first('VERSION') or ''} %INSTALLDATE% {first('INSTALLDATE') or ''}",
    )]


def _zypper_user(requested_by: str | None) -> str | None:
    value = (requested_by or "").strip()
    if not value or value == "(none)":
        return None
    return value.partition("@")[0] or None


def _unquote_command(text: str) -> str:
    try:
        return " ".join(shlex.split(text))
    except ValueError:
        return text


def _parse_zypper_history(content: str, *, source_path: str) -> list[dict]:
    """zypper's ``date|action|...`` lines; ``#`` lines (rpm script output) are left out."""
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = [part.strip() for part in stripped.split("|")]
        if len(parts) < 3:
            results.append(_row("zypper_history", "zypper", source_path, line_number=line_number, message=stripped))
            continue
        timestamp = _local_time(parts[0])
        verb = parts[1].lower()
        fields: dict[str, Any] = {"action": _ZYPPER_ACTIONS.get(verb, verb)}
        get = lambda index: parts[index] if len(parts) > index and parts[index] else None  # noqa: E731
        if verb in {"install", "remove"}:
            fields.update(package=get(2), version=get(3), package_arch=get(4), username=_zypper_user(get(5)))
            if verb == "install":
                fields["package_repository"] = get(6)
            message = f"{verb} {get(2)} {get(3) or ''}".strip()
        elif verb == "command":
            command = _unquote_command(get(3) or "")
            fields.update(username=_zypper_user(get(2)), command=command)
            message = f"zypper command: {command}"
        elif verb in {"radd", "rremove", "ralias", "rurl"}:
            fields.update(package_repository=get(2), repository_url=get(3))
            message = f"{fields['action']} {get(2)} {get(3) or ''}".strip()
        elif verb == "patch":
            fields.update(package=get(2), version=get(3), package_arch=get(4), package_repository=get(5), package_status=get(9))
            message = f"patch {get(2)} ({get(6) or ''} {get(7) or ''}, {get(9) or ''})"
        else:
            message = stripped
        results.append(_row(
            "zypper_history", "zypper", source_path,
            line_number=line_number, timestamp=timestamp, timestamp_status="assumed_utc" if timestamp else "missing",
            message=message, raw_excerpt=stripped, **fields,
        ))
    return results


def _parse_apk_installed(content: str, *, source_path: str) -> list[dict]:
    """apk's installed database: ``P:`` starts a package, ``V:``/``A:``/``o:``... describe it."""
    results: list[dict] = []
    current: dict[str, str] = {}
    start = 1

    def flush() -> None:
        name = current.get("P")
        if name:
            results.append(_row(
                "apk_installed", "apk", source_path,
                line_number=start, action="installed", package=name, version=current.get("V"),
                package_arch=current.get("A"),
                message=f"{name} {current.get('V', '')} installed".strip(),
                raw_excerpt=f"P:{name}\nV:{current.get('V', '')}\nA:{current.get('A', '')}",
            ))
        current.clear()

    for line_number, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            flush()
            continue
        key, sep, value = line.partition(":")
        if not sep or len(key) != 1:
            continue
        if key == "P":
            flush()
            start = line_number
        if key in {"P", "V", "A"}:
            current[key] = value.strip()
    flush()
    return results


def _parse_apk_world(content: str, *, source_path: str) -> list[dict]:
    results = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        for spec in line.split():
            name = re.split(r"[<>=~@]", spec, maxsplit=1)[0]
            results.append(_row(
                "apk_world", "apk", source_path,
                line_number=line_number, action="requested", package=name or spec,
                package_reason="explicit", message=f"{spec} requested", raw_excerpt=spec,
            ))
    return results


def _parse_apk_repositories(content: str, *, source_path: str) -> list[dict]:
    results = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        tag, _space, url = stripped.partition(" ") if stripped.startswith("@") else ("", "", stripped)
        results.append(_row(
            "apk_repositories", "apk", source_path,
            line_number=line_number, action="repository", package_repository=tag or None,
            repository_url=url.strip(), message=f"repository {stripped}", raw_excerpt=stripped,
        ))
    return results


# ------------------------------------------------------------------ routing

_PATH_PARSERS: tuple[tuple[re.Pattern[str], Callable[..., list[dict]]], ...] = (
    (re.compile(r"(^|/)var/lib/dpkg/status$"), _parse_dpkg_status),
    (re.compile(r"(^|/)apt/history\.log"), _parse_apt_history),
    (re.compile(r"(^|/)apt/term\.log"), _parse_apt_term),
    (re.compile(r"(^|/)dpkg\.log"), _parse_dpkg_log),
    (re.compile(r"(^|/)dnf\.rpm\.log"), _parse_dnf_rpm_log),
    (re.compile(r"(^|/)dnf5\.log"), _parse_dnf5_log),
    (re.compile(r"(^|/)dnf\.log"), _parse_dnf_log),
    (re.compile(r"(^|/)yum\.log"), _parse_yum_log),
    (re.compile(r"(^|/)pacman\.log"), _parse_pacman_log),
    (re.compile(r"(^|/)pacman/local/[^/]+/desc$"), _parse_pacman_desc),
    (re.compile(r"(^|/)zypp/history"), _parse_zypper_history),
    (re.compile(r"(^|/)apk/db/installed$"), _parse_apk_installed),
    (re.compile(r"(^|/)etc/apk/world$"), _parse_apk_world),
    (re.compile(r"(^|/)etc/apk/repositories$"), _parse_apk_repositories),
)


def parse_packages(content: str, *, source_path: str = "", username: str | None = None, truncated: bool = False) -> list[dict]:
    path = str(source_path or "").replace("\\", "/").lower()
    for pattern, parser in _PATH_PARSERS:
        if pattern.search(path):
            return parser(content, source_path=source_path)
    # An unnamed copy: dpkg.log lines start with a full date, yum.log lines with a month name.
    if re.search(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}", content):
        return _parse_dpkg_log(content, source_path=source_path)
    return _parse_yum_log(content, source_path=source_path)


# ------------------------------------------------------------------ SQLite databases

_DATABASE_RE = re.compile(
    r"(?:^|/)(?:"
    r"(?P<dnf>var/lib/dnf/history\.sqlite)"
    r"|(?P<dnf5>libdnf5/transaction_history\.sqlite)"
    r"|(?P<yum>var/lib/yum/history/history-[\d-]+\.sqlite)"
    r"|(?P<rpm>(?:var/lib/rpm|usr/lib/sysimage/rpm)/rpmdb\.sqlite)"
    r"|(?P<rpm_bdb>(?:var/lib/rpm|usr/lib/sysimage/rpm)/Packages)"
    r"|(?P<rpm_ndb>(?:var/lib/rpm|usr/lib/sysimage/rpm)/Packages\.db)"
    r")$",
    re.IGNORECASE,
)


def package_database_kind(source_path: str) -> str | None:
    match = _DATABASE_RE.search(str(source_path or "").replace("\\", "/"))
    if not match:
        return None
    return next(kind for kind, value in match.groupdict().items() if value)


def _open_copy(path: Path, workdir: Path) -> sqlite3.Connection:
    """Open a private copy (with its -wal/-journal) so the evidence file is never written to."""
    copy = workdir / path.name
    shutil.copyfile(path, copy)
    for suffix in ("-wal", "-journal"):
        companion = path.with_name(path.name + suffix)
        if companion.is_file():
            shutil.copyfile(companion, workdir / companion.name)
    connection = sqlite3.connect(str(copy))
    connection.row_factory = sqlite3.Row
    return connection


def _uid_names(passwd_content: str | None) -> dict[int, str]:
    names: dict[int, str] = {}
    for line in (passwd_content or "").splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and parts[2].isdigit():
            names.setdefault(int(parts[2]), parts[0])
    return names


def _uid_fields(value: Any, names: dict[int, str]) -> dict[str, Any]:
    try:
        uid = int(value)
    except (TypeError, ValueError):
        return {}
    if uid in _UNSET_UIDS:
        return {}
    return {"uid": uid, "username": names.get(uid)}


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info('{table}')")}


def _dnf4_history(connection: sqlite3.Connection, *, source_path: str, names: dict[int, str]) -> list[dict]:
    query = """
        SELECT t.id AS tid, t.dt_begin, t.user_id, t.cmdline, t.state AS trans_state,
               ti.action, ti.reason, ti.state, r.name, r.epoch, r.version, r.release, r.arch, repo.repoid
        FROM trans_item ti
        JOIN trans t ON t.id = ti.trans_id
        JOIN rpm r ON r.item_id = ti.item_id
        LEFT JOIN repo ON repo.id = ti.repo_id
        ORDER BY t.id, ti.id
    """
    results = []
    for row in connection.execute(query):
        version = f"{row['version']}-{row['release']}"
        if row["epoch"]:
            version = f"{row['epoch']}:{version}"
        action = _DNF4_ITEM_ACTIONS.get(row["action"], str(row["action"]))
        # dnf 4 records the arguments without the program name, which may have been dnf or yum.
        command = row["cmdline"]
        results.append(_row(
            "dnf_history", "dnf", source_path,
            transaction_id=row["tid"], timestamp=_epoch_time(row["dt_begin"]), action=action,
            package=row["name"], version=version, package_arch=row["arch"], package_repository=row["repoid"],
            package_reason=_DNF4_REASONS.get(row["reason"]), package_status=_DNF4_ITEM_STATES.get(row["state"]),
            command=command, message=f"{action} {row['name']} {version} (dnf transaction {row['tid']}: {command or ''})",
            **_uid_fields(row["user_id"], names),
        ))
    return results


def _dnf5_history(connection: sqlite3.Connection, *, source_path: str, names: dict[int, str]) -> list[dict]:
    query = """
        SELECT t.id AS tid, t.dt_begin, t.user_id, t.description, a.name AS action, rs.name AS reason,
               st.name AS state, ts.name AS trans_state, n.name, r.epoch, r.version, r.release, ar.name AS arch, repo.repoid
        FROM trans_item ti
        JOIN trans t ON t.id = ti.trans_id
        JOIN rpm r ON r.item_id = ti.item_id
        LEFT JOIN pkg_name n ON n.id = r.name_id
        LEFT JOIN arch ar ON ar.id = r.arch_id
        LEFT JOIN repo ON repo.id = ti.repo_id
        LEFT JOIN trans_item_action a ON a.id = ti.action_id
        LEFT JOIN trans_item_reason rs ON rs.id = ti.reason_id
        LEFT JOIN trans_item_state st ON st.id = ti.state_id
        LEFT JOIN trans_state ts ON ts.id = t.state_id
        ORDER BY t.id, ti.id
    """
    results = []
    for row in connection.execute(query):
        version = f"{row['version']}-{row['release']}"
        if row["epoch"]:
            version = f"{row['epoch']}:{version}"
        action = str(row["action"] or "unknown").lower().replace(" ", "_")
        results.append(_row(
            "dnf5_history", "dnf5", source_path,
            transaction_id=row["tid"], timestamp=_epoch_time(row["dt_begin"]), action=action,
            package=row["name"], version=version, package_arch=row["arch"], package_repository=row["repoid"],
            package_reason=str(row["reason"] or "").lower().replace(" ", "_") or None,
            # dnf5 leaves finished items "Started"; the transaction's own state is the outcome.
            package_status=("error" if str(row["state"] or "").lower() == "error" else str(row["trans_state"] or row["state"] or "").lower()) or None,
            command=row["description"],
            message=f"{action} {row['name']} {version} (dnf5 transaction {row['tid']}: {row['description'] or ''})",
            **_uid_fields(row["user_id"], names),
        ))
    return results


def _yum_history(connection: sqlite3.Connection, *, source_path: str, names: dict[int, str]) -> list[dict]:
    query = """
        SELECT b.tid, b.timestamp, b.loginuid, c.cmdline, e.return_code,
               p.name, p.epoch, p.version, p.release, p.arch, d.state, d.done
        FROM trans_data_pkgs d
        JOIN trans_beg b ON b.tid = d.tid
        JOIN pkgtups p ON p.pkgtupid = d.pkgtupid
        LEFT JOIN trans_cmdline c ON c.tid = b.tid
        LEFT JOIN trans_end e ON e.tid = b.tid
        ORDER BY b.tid, d.pkgtupid
    """
    results = []
    for row in connection.execute(query):
        version = f"{row['version']}-{row['release']}"
        if row["epoch"] and str(row["epoch"]) != "0":
            version = f"{row['epoch']}:{version}"
        state = str(row["state"] or "")
        action = _YUM_HISTORY_STATES.get(state.lower(), state.lower() or "unknown")
        command = row["cmdline"]
        status = "error" if row["return_code"] not in (None, 0) or str(row["done"]).upper() == "FALSE" else "done"
        results.append(_row(
            "yum_history", "yum", source_path,
            transaction_id=row["tid"], timestamp=_epoch_time(row["timestamp"]), action=action,
            package=row["name"], version=version, package_arch=row["arch"],
            package_reason="dependency" if state.lower() == "dep-install" else None, package_status=status,
            command=command, message=f"{action} {row['name']} {version} (yum transaction {row['tid']}: {command or ''})",
            **_uid_fields(row["loginuid"], names),
        ))
    return results


# RPM header tags read from rpmdb.sqlite blobs.
_RPMTAG_NAME, _RPMTAG_VERSION, _RPMTAG_RELEASE, _RPMTAG_EPOCH = 1000, 1001, 1002, 1003
_RPMTAG_SUMMARY, _RPMTAG_INSTALLTIME, _RPMTAG_VENDOR, _RPMTAG_ARCH = 1004, 1008, 1011, 1022
_RPM_WANTED = {_RPMTAG_NAME, _RPMTAG_VERSION, _RPMTAG_RELEASE, _RPMTAG_EPOCH, _RPMTAG_SUMMARY, _RPMTAG_INSTALLTIME, _RPMTAG_VENDOR, _RPMTAG_ARCH}


def parse_rpm_header(blob: bytes) -> dict[int, Any]:
    """The wanted tags of one RPM header as stored in rpmdb (index count, data size, entries, data)."""
    if len(blob) < 8:
        return {}
    index_count, data_size = struct.unpack(">II", blob[:8])
    data_start = 8 + index_count * 16
    if index_count > 100_000 or data_start + data_size > len(blob):
        return {}
    data = blob[data_start:data_start + data_size]
    values: dict[int, Any] = {}
    for index in range(index_count):
        tag, kind, offset, count = struct.unpack(">IIII", blob[8 + index * 16:24 + index * 16])
        if tag not in _RPM_WANTED or offset >= len(data):
            continue
        if kind == 4 and count:  # INT32
            values[tag] = struct.unpack(">I", data[offset:offset + 4])[0] if offset + 4 <= len(data) else None
        elif kind in {6, 8, 9}:  # STRING, STRING_ARRAY, I18NSTRING: first string
            end = data.find(b"\x00", offset)
            values[tag] = data[offset:end if end >= 0 else len(data)].decode("utf-8", errors="replace")
    return values


def _rpm_package_row(blob: bytes, *, artifact_type: str, source_path: str, line_number: int) -> dict | None:
    header = parse_rpm_header(blob)
    name = header.get(_RPMTAG_NAME)
    if not name:
        return None
    version = f"{header.get(_RPMTAG_VERSION, '')}-{header.get(_RPMTAG_RELEASE, '')}".strip("-")
    if header.get(_RPMTAG_EPOCH):
        version = f"{header[_RPMTAG_EPOCH]}:{version}"
    return _row(
        artifact_type, "rpm", source_path,
        line_number=line_number, timestamp=_epoch_time(header.get(_RPMTAG_INSTALLTIME)), action="installed",
        package=name, version=version or None, package_arch=header.get(_RPMTAG_ARCH),
        package_vendor=header.get(_RPMTAG_VENDOR),
        message=f"{name} {version} installed" + (f": {header[_RPMTAG_SUMMARY]}" if header.get(_RPMTAG_SUMMARY) else ""),
    )


def _rpmdb(connection: sqlite3.Connection, *, source_path: str, names: dict[int, str]) -> list[dict]:
    results = []
    for row in connection.execute("SELECT hnum, blob FROM Packages ORDER BY hnum"):
        package = _rpm_package_row(bytes(row["blob"]), artifact_type="rpmdb", source_path=source_path, line_number=row["hnum"])
        if package:
            results.append(package)
    return results


# Berkeley DB hash file (/var/lib/rpm/Packages): page 0 is the metadata page, whose magic also gives
# the byte order the host wrote it in. Every hash page holds key/value pairs; an RPM header is too big
# to sit on the page, so its value is an off-page reference to a chain of overflow pages.
_BDB_HASH_MAGIC = 0x061561
_BDB_PAGE_HEADER = 26
_BDB_HASH_PAGES = {2, 13}  # P_HASH_UNSORTED, P_HASH
_BDB_OVERFLOW_PAGE = 7
_BDB_OFFPAGE_ITEM = 3
_RPM_MAX_HEADER = 64 * 1024 * 1024


def _bdb_package_blobs(data: bytes) -> list[tuple[int, bytes]]:
    if len(data) < 512:
        return []
    for order in ("<", ">"):
        if struct.unpack_from(order + "I", data, 12)[0] == _BDB_HASH_MAGIC:
            break
    else:
        return []
    page_size = struct.unpack_from(order + "I", data, 20)[0]
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        return []
    page_count = len(data) // page_size
    blobs: list[tuple[int, bytes]] = []
    for page_number in range(1, page_count):
        page = page_number * page_size
        if data[page + 25] not in _BDB_HASH_PAGES:
            continue
        entries = struct.unpack_from(order + "H", data, page + 20)[0]
        # Items alternate key, value; the key of a Packages entry is the package's header number.
        for index in range(0, entries - 1, 2):
            key_offset, value_offset = struct.unpack_from(order + "HH", data, page + _BDB_PAGE_HEADER + index * 2)
            if value_offset + 12 > page_size or data[page + value_offset] != _BDB_OFFPAGE_ITEM:
                continue
            next_page, length = struct.unpack_from(order + "II", data, page + value_offset + 4)
            if length > _RPM_MAX_HEADER:
                continue
            blob = _bdb_overflow(data, order, page_size, page_count, next_page, length)
            if blob is None:
                continue
            key = data[page + key_offset + 1:page + key_offset + 5] if key_offset + 5 <= page_size else b""
            number = struct.unpack(order + "I", key)[0] if len(key) == 4 else len(blobs) + 1
            blobs.append((number, blob))
    return blobs


def _bdb_overflow(data: bytes, order: str, page_size: int, page_count: int, page_number: int, length: int) -> bytes | None:
    parts: list[bytes] = []
    remaining = length
    seen: set[int] = set()
    while remaining > 0:
        if not 0 < page_number < page_count or page_number in seen:
            return None
        seen.add(page_number)
        page = page_number * page_size
        if data[page + 25] != _BDB_OVERFLOW_PAGE:
            return None
        used = struct.unpack_from(order + "H", data, page + 22)[0]
        if used > page_size - _BDB_PAGE_HEADER:
            return None
        parts.append(data[page + _BDB_PAGE_HEADER:page + _BDB_PAGE_HEADER + min(used, remaining)])
        remaining -= used
        page_number = struct.unpack_from(order + "I", data, page + 16)[0]
    return b"".join(parts)


# NDB (SUSE's Packages.db, little-endian): a header page whose slots point at 16-byte blocks, each
# package a "BlbS" blob of one RPM header.
_NDB_MAGIC = b"RpmP"
_NDB_SLOT_MAGIC = b"Slot"
_NDB_BLOB_MAGIC = b"BlbS"
_NDB_BLOCK = 16
_NDB_SLOTS_PER_PAGE = 4096 // 16


def _ndb_package_blobs(data: bytes) -> list[tuple[int, bytes]]:
    if len(data) < 4096 or data[:4] != _NDB_MAGIC:
        return []
    slot_pages = struct.unpack_from("<I", data, 12)[0]
    slot_end = min(len(data), slot_pages * _NDB_SLOTS_PER_PAGE * 16)
    blobs: list[tuple[int, bytes]] = []
    # The header takes the first two slot positions.
    for slot in range(32, slot_end - 15, 16):
        magic, package_index, block_offset, block_count = struct.unpack_from("<4sIII", data, slot)
        if magic != _NDB_SLOT_MAGIC or not package_index:
            continue
        start = block_offset * _NDB_BLOCK
        if start + 16 > len(data) or data[start:start + 4] != _NDB_BLOB_MAGIC:
            continue
        blob_index, _checksum, blob_length = struct.unpack_from("<III", data, start + 4)
        if blob_index != package_index or blob_length > min(_RPM_MAX_HEADER, block_count * _NDB_BLOCK):
            continue
        blobs.append((package_index, data[start + 16:start + 16 + blob_length]))
    return blobs


def _rpm_file_database(path: Path, *, kind: str, source_path: str) -> list[dict]:
    data = path.read_bytes()
    blobs = _bdb_package_blobs(data) if kind == "rpm_bdb" else _ndb_package_blobs(data)
    results = []
    for number, blob in sorted(blobs, key=lambda item: item[0]):
        package = _rpm_package_row(blob, artifact_type="rpmdb", source_path=source_path, line_number=number)
        if package:
            results.append(package)
    return results


_DATABASE_READERS: dict[str, tuple[str, Callable[..., list[dict]]]] = {
    "dnf": ("trans_item", _dnf4_history),
    "dnf5": ("trans_item_action", _dnf5_history),
    "yum": ("trans_beg", _yum_history),
    "rpm": ("Packages", _rpmdb),
}


def parse_package_database(path: Path, *, source_path: str = "", passwd_content: str | None = None) -> list[dict]:
    kind = package_database_kind(source_path or path.name) or package_database_kind(str(path))
    if kind is None:
        return []
    if kind in {"rpm_bdb", "rpm_ndb"}:
        return _rpm_file_database(path, kind=kind, source_path=source_path or str(PurePosixPath(path.name)))
    required_table, reader = _DATABASE_READERS[kind]
    with tempfile.TemporaryDirectory(prefix="kairon-pkgdb-") as workdir:
        connection = _open_copy(path, Path(workdir))
        try:
            if not _columns(connection, required_table):
                # Same file name, different schema (a newer or older tool version): nothing to read.
                return []
            if kind == "dnf" and "cmdline" not in _columns(connection, "trans"):
                return []
            return reader(connection, source_path=source_path or str(PurePosixPath(path.name)), names=_uid_names(passwd_content))
        finally:
            connection.close()
