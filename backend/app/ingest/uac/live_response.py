"""Parsers for the command output UAC saves under ``live_response/``.

UAC runs the same commands on every Unix-like system it supports and stores each output in a file
named after the command (``ps_-eo_user_pid_ppid_..._lstart_args.txt``, ``netstat_-anp_tcp.txt``,
``last.txt``...). Only outputs whose format is stable and worth an event are parsed here; the rest
of ``live_response/`` stays in the evidence, listed but not indexed.

Everything here is a snapshot of the moment of the acquisition: a process list or a connection
table says what was running or open when UAC ran, nothing about before. Rows that have no time of
their own (a connection, a loaded launchd job) carry the time the collection started, marked
``collection_time``.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any

from app.ingest.uac.collection import collection_reference_time, uac_collection_for, uac_host_clock

ARTIFACT_FAMILY = "uac_live_response"
PARSER = "uac_live_response_raw"

# (artifact_type, pattern on the path below live_response/) -- the file name is the command line.
_OUTPUT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("process_list", re.compile(r"^process/ps_[^/]*lstart[^/]*\.txt$", re.IGNORECASE)),
    ("network_connections", re.compile(r"^network/netstat_-[a-z]*a[a-z]*n[a-z]*[^/]*\.txt$|^network/netstat_-[a-z]*n[a-z]*a[a-z]*[^/]*\.txt$", re.IGNORECASE)),
    ("open_network_files", re.compile(r"^(?:network|process)/lsof_-[A-Za-z]*i[A-Za-z]*\.txt$")),
    ("launchctl_list", re.compile(r"^system/launchctl_list\.txt$", re.IGNORECASE)),
    ("login_history", re.compile(r"^system/last(?:_-[^/]*)?\.txt$", re.IGNORECASE)),
    ("software_update_history", re.compile(r"^packages/softwareupdate_--history[^/]*\.txt$", re.IGNORECASE)),
    ("package_inventory", re.compile(r"^packages/(?:brew_list_--(?:formula|cask)|pkgutil_--packages)\.txt$", re.IGNORECASE)),
    ("kernel_identity", re.compile(r"^system/uname_-a\.txt$", re.IGNORECASE)),
    ("os_version", re.compile(r"^system/sw_vers\.txt$", re.IGNORECASE)),
)
_LIVE_RESPONSE_RE = re.compile(r"(?:^|/)live_response/(?P<rest>.+)$")
# Per-binary strings dumps and hash lists: bulk material, never listed as artifacts.
_IGNORED_RE = re.compile(r"(?:^|/)live_response/process/(?:strings/|hash_running_processes)", re.IGNORECASE)
# UAC's own outputs outside live_response/: kept in the evidence, not parsed.
_UNPARSED_OUTPUT_RE = re.compile(
    r"(?:^|/)(?:bodyfile/bodyfile\.txt|hash_executables/hash_executables\.(?:md5|sha1)"
    r"|system/(?:suid|sgid|socket_files|hidden_(?:files|directories)|(?:group|world)_writable[a-z_]*"
    r"|(?:user|group)_name_unknown_(?:files|directories))\.txt)$",
    re.IGNORECASE,
)

_DATE_RE = re.compile(
    r"(?P<dow>Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{1,2}:\d{2}(?::\d{2})?)(?:\s+(?P<year>\d{4}))?"
)
_MONTHS = {name: index for index, name in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}
_ARCHITECTURES = {"x86_64", "amd64", "arm64", "aarch64", "i386", "i686", "armv7l", "armv6l", "ppc64le", "s390x", "riscv64", "sparc64"}
_MAX_LINES = 200_000


_UAC_LOG_RE = re.compile(r"(?:^|/)uac\.log$")


def looks_like_uac_output(path: str | Path) -> tuple[str, str, str] | None:
    """(family, artifact_type, parser) for a UAC live-response output this module parses."""
    normalized = str(path).replace("\\", "/")
    if _UAC_LOG_RE.search(normalized) and "[root]/" not in normalized:
        # UAC's own log: the host name and time zone it recorded become Host Facts.
        return (ARTIFACT_FAMILY, "collection_log", PARSER)
    match = _LIVE_RESPONSE_RE.search(normalized)
    if not match or _IGNORED_RE.search(normalized):
        return None
    rest = match.group("rest")
    for artifact_type, pattern in _OUTPUT_PATTERNS:
        if pattern.search(rest):
            return (ARTIFACT_FAMILY, artifact_type, PARSER)
    return None


_BODYFILE_RE = re.compile(r"(?:^|/)bodyfile/bodyfile\.txt$")


def is_uac_bodyfile(path: str | Path) -> bool:
    """UAC's file system listing: searched on demand (app.services.uac_bodyfile), not indexed."""
    return bool(_BODYFILE_RE.search(str(path).replace("\\", "/")))


BODYFILE_CLASSIFICATION = {
    "artifact_type": "uac_bodyfile",
    "artifact_family": "uac_bodyfile",
    "profile": "filesystem",
    "parser": "not_implemented",
    "status": "detected_not_parsed",
    "reason": "UAC bodyfile (file listing with MAC times): searched on demand from File Listing, not indexed.",
}


def is_ignored_uac_output(path: str | Path) -> bool:
    return bool(_IGNORED_RE.search(str(path).replace("\\", "/")))


def is_unparsed_uac_output(path: str | Path) -> bool:
    """A UAC output kept in the evidence but not parsed (bodyfile, hash lists, find listings, other commands)."""
    normalized = str(path).replace("\\", "/")
    if _IGNORED_RE.search(normalized) or looks_like_uac_output(normalized):
        return False
    return bool(_UNPARSED_OUTPUT_RE.search(normalized) or _LIVE_RESPONSE_RE.search(normalized))


# -- time helpers ---------------------------------------------------------------------------------


def _zone_for(path: Path) -> tzinfo | None:
    return uac_host_clock(path).zone


def _local_to_utc(local: datetime, zone: tzinfo | None) -> tuple[str, str]:
    if zone is None:
        return local.replace(tzinfo=timezone.utc).isoformat(), "assumed_utc"
    return local.replace(tzinfo=zone).astimezone(timezone.utc).isoformat(), "host_timezone"


def _collection_time(path: Path) -> str | None:
    started = collection_reference_time(path)
    return started.astimezone(timezone.utc).isoformat() if started else None


def _date_from_match(match: re.Match[str], year: int) -> datetime | None:
    clock = match.group("time")
    fmt = "%H:%M:%S" if clock.count(":") == 2 else "%H:%M"
    try:
        moment = datetime.strptime(clock, fmt)
        return datetime(year, _MONTHS[match.group("mon")], int(match.group("day")), moment.hour, moment.minute, moment.second)
    except (KeyError, ValueError):
        return None


def _base_row(path: Path, source_path: str, artifact_type: str, line_number: int) -> dict[str, Any]:
    collection = uac_collection_for(path)
    return {
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_type": artifact_type,
        "source_file": source_path,
        "line_number": line_number,
        "collection_os": collection.operating_system if collection else None,
        "uac_command": _command_from_file_name(path.name),
    }


def _command_from_file_name(name: str) -> str:
    """The output file's name without ``.txt``: UAC names each output after its command line
    (``netstat_-anp_tcp``), with spaces turned into underscores -- which cannot be undone safely,
    since command names contain underscores too (``sw_vers``)."""
    return name[:-4] if name.lower().endswith(".txt") else name


def _read_lines(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        lines = []
        for index, line in enumerate(handle):
            if index >= _MAX_LINES:
                break
            lines.append(line.rstrip("\n"))
    return lines


# -- process list ---------------------------------------------------------------------------------


def _parse_process_list(path: Path, source_path: str) -> list[dict[str, Any]]:
    lines = _read_lines(path)
    if not lines:
        return []
    header = lines[0].split()
    upper = [column.upper() for column in header]
    if "PID" not in upper:
        return []
    zone = _zone_for(path)
    rows: list[dict[str, Any]] = []
    started_index = upper.index("STARTED") if "STARTED" in upper else (upper.index("LSTART") if "LSTART" in upper else None)
    for line_number, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        tokens = line.split()
        values: dict[str, str] = {}
        position = 0
        command_line = ""
        for column_index, column in enumerate(upper):
            if position >= len(tokens):
                break
            if column_index == started_index:
                # lstart prints five fields: "Thu Nov 19 17:49:22 2026".
                values[column] = " ".join(tokens[position:position + 5])
                position += 5
                continue
            if column in {"ARGS", "COMMAND", "CMD"} and column_index == len(upper) - 1:
                command_line = " ".join(tokens[position:])
                position = len(tokens)
                continue
            values[column] = tokens[position]
            position += 1
        pid = _to_int(values.get("PID"))
        if pid is None:
            continue
        row = _base_row(path, source_path, "process_list", line_number)
        executable = command_line.split(" ", 1)[0] if command_line else ""
        row.update({
            "pid": pid,
            "ppid": _to_int(values.get("PPID")),
            "username": values.get("USER") or values.get("UID") or "",
            "tty": values.get("TTY") or values.get("TT") or "",
            "process_state": values.get("STAT") or values.get("S") or "",
            "cpu_percent": values.get("%CPU") or "",
            "memory_percent": values.get("%MEM") or "",
            "command_line": command_line,
            "executable": executable,
            "process_name": executable.rsplit("/", 1)[-1] if executable else "",
        })
        start_text = values.get("STARTED") or values.get("LSTART") or ""
        start_match = _DATE_RE.search(start_text)
        start = _date_from_match(start_match, int(start_match.group("year"))) if start_match and start_match.group("year") else None
        if start is not None:
            row["timestamp"], row["timestamp_status"] = _local_to_utc(start, zone)
            row["process_start"] = row["timestamp"]
        row["message"] = f"Running process {pid} ({row['username'] or 'unknown user'}): {command_line[:300]}"
        rows.append(row)
    return rows


def _to_int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


# -- network ---------------------------------------------------------------------------------------

_LINUX_ADDRESS_RE = re.compile(r"^(?P<host>.*):(?P<port>\d+|\*)$")
_BSD_ADDRESS_RE = re.compile(r"^(?P<host>.*)\.(?P<port>\d+|\*)$")


def split_address(value: str) -> tuple[str, int | None]:
    """``0.0.0.0:22`` (Linux) or ``192.0.2.5.443`` / ``fe80::1%lo0.49152`` (BSD/macOS netstat)."""
    text = value.strip()
    if text in {"*", "*.*", "*:*"}:
        return "*", None
    if text.startswith("[") and "]:" in text:
        host, _, port = text[1:].partition("]:")
        return host, _to_int(port)
    linux = _LINUX_ADDRESS_RE.match(text)
    bsd = _BSD_ADDRESS_RE.match(text)
    if linux and not (bsd and text.count(":") > 1 and "." in text.rsplit(":", 1)[-1]):
        return linux.group("host") or "*", _to_int(linux.group("port"))
    if bsd:
        return bsd.group("host") or "*", _to_int(bsd.group("port"))
    return text, None


def _parse_netstat(path: Path, source_path: str) -> list[dict[str, Any]]:
    observed = _collection_time(path)
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(_read_lines(path), start=1):
        if line.startswith("Active UNIX domain sockets") or line.startswith("Active LOCAL"):
            break
        tokens = line.split()
        if len(tokens) < 5 or not tokens[0].lower().startswith(("tcp", "udp")):
            continue
        if not (tokens[1].isdigit() and tokens[2].isdigit()):
            continue
        protocol = tokens[0].lower()
        local_ip, local_port = split_address(tokens[3])
        remote_ip, remote_port = split_address(tokens[4])
        state = ""
        pid = None
        program = ""
        for token in tokens[5:]:
            owner = re.match(r"^(?P<pid>\d+)/(?P<program>.+)$", token)
            if owner:
                pid = int(owner.group("pid"))
                program = owner.group("program")
            elif not state and re.match(r"^[A-Z_0-9]+$", token):
                state = token
        row = _base_row(path, source_path, "network_connection", line_number)
        row.update({
            "network_protocol": protocol,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "connection_state": state,
            "pid": pid,
            "process_name": program,
            "timestamp": observed,
            "timestamp_status": "collection_time" if observed else "missing",
        })
        row["message"] = _connection_message(row)
        rows.append(row)
    return rows


def _connection_message(row: dict[str, Any]) -> str:
    local = f"{row.get('local_ip')}:{row.get('local_port') if row.get('local_port') is not None else '*'}"
    remote = f"{row.get('remote_ip')}:{row.get('remote_port') if row.get('remote_port') is not None else '*'}"
    owner = f" by {row['process_name']} ({row['pid']})" if row.get("process_name") else (f" by PID {row['pid']}" if row.get("pid") else "")
    state = f" {row['connection_state']}" if row.get("connection_state") else ""
    if row.get("connection_state") == "LISTEN" or remote in {"*:*", "*.*"}:
        return f"{row.get('network_protocol', '').upper()} listening on {local}{owner}"
    return f"{row.get('network_protocol', '').upper()} {local} -> {remote}{state}{owner}"


def _parse_lsof_network(path: Path, source_path: str) -> list[dict[str, Any]]:
    observed = _collection_time(path)
    lines = _read_lines(path)
    if not lines or not lines[0].startswith("COMMAND"):
        return []
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines[1:], start=2):
        tokens = line.split()
        if len(tokens) < 9 or tokens[4] not in {"IPv4", "IPv6"}:
            continue
        name = " ".join(tokens[8:])
        state = ""
        state_match = re.search(r"\((?P<state>[A-Z_]+)\)\s*$", name)
        if state_match:
            state = state_match.group("state")
            name = name[: state_match.start()].strip()
        local_text, _, remote_text = name.partition("->")
        local_ip, local_port = split_address(local_text)
        remote_ip, remote_port = split_address(remote_text) if remote_text else ("*", None)
        row = _base_row(path, source_path, "network_connection", line_number)
        row.update({
            "process_name": tokens[0].replace("\\x20", " "),
            "pid": _to_int(tokens[1]),
            # lsof -l prints the numeric uid.
            "uid": tokens[2] if tokens[2].isdigit() else None,
            "username": "" if tokens[2].isdigit() else tokens[2],
            "network_protocol": tokens[7].lower(),
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "connection_state": state,
            "timestamp": observed,
            "timestamp_status": "collection_time" if observed else "missing",
        })
        row["message"] = _connection_message(row)
        rows.append(row)
    return rows


# -- launchctl list -------------------------------------------------------------------------------


def _parse_launchctl_list(path: Path, source_path: str) -> list[dict[str, Any]]:
    observed = _collection_time(path)
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(_read_lines(path), start=1):
        parts = line.split("\t") if "\t" in line else line.split()
        if len(parts) < 3 or parts[0] == "PID":
            continue
        pid_text, status_text, label = parts[0].strip(), parts[1].strip(), "\t".join(parts[2:]).strip()
        if not label:
            continue
        pid = _to_int(pid_text)
        exit_status = _to_int(status_text)
        row = _base_row(path, source_path, "launchctl_job", line_number)
        row.update({
            "launchd_label": label,
            "pid": pid,
            "exit_status": exit_status,
            "running": pid is not None,
            "timestamp": observed,
            "timestamp_status": "collection_time" if observed else "missing",
        })
        if pid is not None:
            row["message"] = f"launchd job {label} running (PID {pid})"
        elif exit_status:
            row["message"] = f"launchd job {label} loaded, not running (last exit status {exit_status})"
        else:
            row["message"] = f"launchd job {label} loaded, not running"
        rows.append(row)
    return rows


# -- last -----------------------------------------------------------------------------------------

_DURATION_RE = re.compile(r"\((?:(?P<days>\d+)\+)?(?P<hours>\d{1,2}):(?P<minutes>\d{2})\)")
_LAST_SPECIAL_USERS = {"reboot", "shutdown"}


def _parse_last(path: Path, source_path: str) -> list[dict[str, Any]]:
    zone = _zone_for(path)
    reference = collection_reference_time(path)
    reference_local = (reference.astimezone(zone) if zone and reference else reference)
    year = reference_local.year if reference_local else None
    newer: datetime | None = reference_local.replace(tzinfo=None) if reference_local else None
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(_read_lines(path), start=1):
        if not line.strip() or line.startswith(("wtmp begins", "btmp begins", "utx.log begins")):
            continue
        match = _DATE_RE.search(line)
        if not match:
            continue
        prefix = line[: match.start()].split()
        if not prefix:
            continue
        username = prefix[0]
        terminal = prefix[1] if len(prefix) > 1 else ""
        remote_host = " ".join(prefix[2:]) if len(prefix) > 2 else ""
        if username in _LAST_SPECIAL_USERS:
            # "reboot    ~    Thu Nov 19 17:49" / "reboot system boot 6.5.0 ...": no terminal or host.
            terminal, remote_host = "", ""
        if match.group("year"):
            login_local = _date_from_match(match, int(match.group("year")))
        elif year is not None:
            login_local = _date_from_match(match, year)
            # last prints newest first: a date after the newer line belongs to the previous year.
            while login_local is not None and newer is not None and login_local > newer + timedelta(days=1) and year > 1990:
                year -= 1
                login_local = _date_from_match(match, year)
        else:
            login_local = None
        if login_local is None:
            continue
        newer = login_local
        suffix = line[match.end():].strip()
        row = _base_row(path, source_path, "login_session", line_number)
        row["timestamp"], row["timestamp_status"] = _local_to_utc(login_local, zone)
        if not match.group("year"):
            row["timestamp_status"] = "inferred_year_host_timezone" if zone else "inferred_year"
        duration = _DURATION_RE.search(suffix)
        logout = None
        if duration:
            delta = timedelta(days=int(duration.group("days") or 0), hours=int(duration.group("hours")), minutes=int(duration.group("minutes")))
            logout = _local_to_utc(login_local + delta, zone)[0]
        still = "still logged in" in suffix
        if username == "reboot":
            action, message = "system_boot", "System boot"
        elif username == "shutdown":
            action, message = "system_shutdown", "System shutdown"
        else:
            action = "login_session"
            origin = f" from {remote_host}" if remote_host else ""
            state = " (still logged in at acquisition)" if still else ""
            message = f"Login session: {username} on {terminal or 'unknown terminal'}{origin}{state}"
        row.update({
            "username": "" if username in _LAST_SPECIAL_USERS else username,
            "terminal": terminal,
            "remote_host": remote_host,
            "event_action": action,
            "session_end": logout,
            "session_state": "still_logged_in" if still else ("ended" if logout else (suffix.lstrip("- ").strip() or "")),
            "message": message,
        })
        rows.append(row)
    return rows


# -- packages -------------------------------------------------------------------------------------

_SOFTWARE_UPDATE_RE = re.compile(r"^(?P<name>.+?)\s{2,}(?P<version>\S+)\s{2,}(?P<date>\d{1,2}/\d{1,2}/\d{4},?\s+\d{1,2}:\d{2}(?::\d{2})?)\s*$")


def _parse_software_update_history(path: Path, source_path: str) -> list[dict[str, Any]]:
    zone = _zone_for(path)
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(_read_lines(path), start=1):
        match = _SOFTWARE_UPDATE_RE.match(line.replace("\u00a0", " ").strip())
        if not match:
            continue
        stamp = match.group("date").replace(",", "")
        parsed = None
        for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"):
            try:
                parsed = datetime.strptime(stamp, fmt)
                break
            except ValueError:
                continue
        row = _base_row(path, source_path, "software_update", line_number)
        row.update({
            "package": match.group("name").strip(),
            "package_version": match.group("version"),
            "package_manager": "softwareupdate",
            "event_action": "package_installed",
            "message": f"Software update installed: {match.group('name').strip()} {match.group('version')}",
        })
        if parsed is not None:
            row["timestamp"], row["timestamp_status"] = _local_to_utc(parsed, zone)
        rows.append(row)
    return rows


def _parse_package_inventory(path: Path, source_path: str) -> list[dict[str, Any]]:
    name = path.name.lower()
    manager = "pkgutil" if name.startswith("pkgutil") else ("homebrew-cask" if "cask" in name else "homebrew")
    observed = _collection_time(path)
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(_read_lines(path), start=1):
        package = line.strip()
        if not package or " " in package:
            continue
        row = _base_row(path, source_path, "package_inventory", line_number)
        row.update({
            "package": package,
            "package_manager": manager,
            "event_action": "package_present",
            "timestamp": observed,
            "timestamp_status": "collection_time" if observed else "missing",
            "message": f"Installed package ({manager}): {package}",
        })
        rows.append(row)
    return rows


# -- host identity --------------------------------------------------------------------------------


def _fact_row(path: Path, source_path: str, artifact_type: str, fact_type: str, raw: str, value: str, confidence: str, line_number: int) -> dict[str, Any]:
    row = _base_row(path, source_path, artifact_type, line_number)
    row.update({
        "fact_type": fact_type,
        "raw_value": raw,
        "normalized_value": value,
        "confidence": confidence,
        "parse_status": "valid",
        "reason": "",
        "message": f"{fact_type}: {value}",
    })
    return row


def _parse_uname(path: Path, source_path: str) -> list[dict[str, Any]]:
    lines = [line for line in _read_lines(path) if line.strip()]
    if not lines:
        return []
    raw = lines[0].strip()
    tokens = raw.split()
    if len(tokens) < 3:
        return []
    rows = [_fact_row(path, source_path, "kernel_identity", "host.kernel", raw, f"{tokens[0]} {tokens[2]}", "high", 1)]
    architecture = next((token for token in reversed(tokens) if token.lower() in _ARCHITECTURES), None)
    if architecture:
        rows.append(_fact_row(path, source_path, "kernel_identity", "host.architecture", raw, architecture, "high", 1))
    return rows


def _parse_sw_vers(path: Path, source_path: str) -> list[dict[str, Any]]:
    values: dict[str, str] = {}
    for line in _read_lines(path):
        key, separator, value = line.partition(":")
        if separator and value.strip():
            values[key.strip()] = value.strip()
    raw = "; ".join(f"{key}: {value}" for key, value in values.items())
    rows = []
    if values.get("ProductName"):
        rows.append(_fact_row(path, source_path, "os_version", "host.distribution", raw, values["ProductName"], "high", 1))
    if values.get("ProductVersion"):
        version = values["ProductVersion"] + (f" ({values['BuildVersion']})" if values.get("BuildVersion") else "")
        rows.append(_fact_row(path, source_path, "os_version", "host.distribution_version", raw, version, "high", 2))
    return rows


def _parse_uac_log(path: Path, source_path: str) -> list[dict[str, Any]]:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    from app.ingest.uac.collection import read_uac_log

    facts = read_uac_log(path)
    if not facts.get("version"):
        return []  # not written by UAC
    rows = []
    zone = facts.get("timezone")
    if zone:
        try:
            ZoneInfo(zone)
            rows.append(_fact_row(path, source_path, "collection_log", "host.timezone", zone, zone, "high", 1))
        except (ZoneInfoNotFoundError, ValueError):
            pass
    hostname = facts.get("hostname")
    if hostname:
        rows.append(_fact_row(path, source_path, "collection_log", "host.hostname", hostname, hostname.split(".", 1)[0], "high", 1))
        if "." in hostname:
            rows.append(_fact_row(path, source_path, "collection_log", "host.fqdn", hostname, hostname, "high", 1))
    for row in rows:
        row["collection_os"] = facts.get("operating_system")
    return rows


_PARSERS = {
    "collection_log": _parse_uac_log,
    "process_list": _parse_process_list,
    "network_connections": _parse_netstat,
    "open_network_files": _parse_lsof_network,
    "launchctl_list": _parse_launchctl_list,
    "login_history": _parse_last,
    "software_update_history": _parse_software_update_history,
    "package_inventory": _parse_package_inventory,
    "kernel_identity": _parse_uname,
    "os_version": _parse_sw_vers,
}


def parse_uac_output(path: Path, *, artifact_type: str | None, source_path: str) -> list[dict[str, Any]]:
    kind = str(artifact_type or "")
    if kind not in _PARSERS:
        detected = looks_like_uac_output(source_path) or looks_like_uac_output(path)
        kind = detected[1] if detected else ""
    parser = _PARSERS.get(kind)
    if parser is None:
        return []
    return parser(path, source_path)
