"""MemProcFS's forensic inventories of one memory image, as tables.

The forensic scan memprocfs.findevil runs also writes inventories Volatility has no tab for:
scheduled tasks (with command line, user and run times), services, the DNS cache, drivers,
devices, Prefetch, YARA matches and the Amcache database (applications, files, shortcuts, drivers,
devices). The child (memprocfs_findevil) saves them as CSV next to the run's other outputs; this
module reads them back from the active Find Evil run of the evidence. They are small (hundreds to
a few thousand rows), so they are filtered and paged in memory instead of being indexed.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.services.memory.memprocfs_runner import TIMELINE_DIRNAME


@dataclass(frozen=True)
class Table:
    key: str
    file: str
    label: str
    group: str
    description: str
    # (CSV column, label) in display order; the other columns stay in each row's details.
    columns: tuple[tuple[str, str], ...]


TABLES: tuple[Table, ...] = (
    Table("tasks", "tasks.csv", "Scheduled tasks", "Persistence", "Every scheduled task registered on the system, with its command, account and when it was created, last run and last completed.",
          (("TaskName", "Task"), ("CommandLine", "Command"), ("Parameters", "Arguments"), ("User", "Account"), ("TimeCreate", "Created"), ("TimeLastRun", "Last run"), ("TimeCompleted", "Completed"), ("TaskPath", "Path"))),
    Table("services", "services.csv", "Services", "Persistence", "Services in the Service Control Manager's memory: name, account, start type, state and the binary or command they run.",
          (("ServiceName", "Service"), ("DisplayName", "Display name"), ("State", "State"), ("StartType", "Start"), ("User", "Account"), ("PID", "PID"), ("ImagePath", "Image path"), ("DriverpathOrCmdline", "Command line"))),
    Table("netdns", "netdns.csv", "DNS cache", "Network", "Names the DNS client service had resolved and still kept in its cache. Entries whose name could not be read from memory are hidden.",
          (("Name", "Name"), ("Type", "Type"), ("Data", "Answer"), ("TTL", "TTL"))),
    Table("drivers", "drivers.csv", "Drivers", "System", "Driver objects in kernel memory with their image path and load range.",
          (("Name", "Name"), ("DriverName", "Driver object"), ("DriverPath", "Path"), ("ServiceKey", "Service key"), ("Size", "Size"), ("Start", "Start"))),
    Table("devices", "devices.csv", "Devices", "System", "Device objects and the driver that owns each, including filter devices attached on top of others.",
          (("Name", "Name"), ("DriverName", "Driver"), ("DriverPath", "Driver path"), ("Depth", "Depth"), ("ExtraInfo", "Info"))),
    Table("prefetch", "prefetch.csv", "Prefetch", "Execution", "Prefetch files still in memory: the program, how many times it ran and its last run times.",
          (("Process", "Program"), ("RunCount", "Runs"), ("RunTime1", "Last run"), ("RunTime2", "Previous run"), ("FileCount", "Files"), ("PrefetchFile", "Prefetch file"))),
    Table("amcache_files", "amcache_files.csv", "Amcache files", "Execution", "Executables Windows inventoried in Amcache: path, publisher, product, version and size.",
          (("LowerCaseLongPath", "Path"), ("Publisher", "Publisher"), ("ProductName", "Product"), ("Version", "Version"), ("Size", "Size"), ("LinkDate", "Link date"), ("KeyLastWrite", "Key written"))),
    Table("amcache_applications", "amcache_applications.csv", "Amcache applications", "Execution", "Installed applications Windows inventoried in Amcache.",
          (("Name", "Name"), ("Publisher", "Publisher"), ("Version", "Version"), ("Source", "Source"), ("RootDirPath", "Folder"), ("InstallDate", "Installed"), ("KeyLastWrite", "Key written"))),
    Table("amcache_shortcuts", "amcache_shortcuts.csv", "Amcache shortcuts", "Execution", "Start menu shortcuts in Amcache and the program each points to.",
          (("ShortcutPath", "Shortcut"), ("ShortcutTargetPath", "Target"), ("KeyLastWrite", "Key written"))),
    Table("amcache_driver_binaries", "amcache_driver_binaries.csv", "Amcache drivers", "System", "Driver binaries in Amcache: company, version, signature and whether they ship with Windows.",
          (("DriverName", "Driver"), ("DriverCompany", "Company"), ("Product", "Product"), ("DriverVersion", "Version"), ("DriverSigned", "Signed"), ("DriverInBox", "Inbox"), ("DriverLastWriteTime", "Written"))),
    Table("amcache_driver_packages", "amcache_driver_packages.csv", "Amcache driver packages", "System", "Driver packages installed from outside Windows (OEM .inf files).",
          (("Inf", "Inf"), ("Provider", "Provider"), ("Class", "Class"), ("Version", "Version"), ("Date", "Date"), ("SYSFILE", "Driver file"))),
    Table("amcache_device_containers", "amcache_device_containers.csv", "Amcache device containers", "System", "Physical devices Windows has seen (computer, network adapters, USB and Bluetooth devices).",
          (("FriendlyName", "Name"), ("PrimaryCategory", "Category"), ("Manufacturer", "Manufacturer"), ("ModelName", "Model"), ("IsConnected", "Connected"), ("KeyLastWrite", "Key written"))),
    Table("amcache_devices_pnp", "amcache_devices_pnp.csv", "Amcache PnP devices", "System", "Plug and Play devices with their driver.",
          (("Description", "Device"), ("Class", "Class"), ("Manufacturer", "Manufacturer"), ("DriverName", "Driver"), ("Service", "Service"), ("Enumerator", "Bus"), ("KeyLastWrite", "Key written"))),
    Table("yara", "yara.csv", "YARA matches", "Detection", "Matches of MemProcFS's built-in YARA rules in process and kernel memory.",
          (("Description", "Rule"), ("ProcessName", "Process"), ("PID", "PID"), ("MemoryTag", "Memory"), ("String0", "Match"), ("CommandLine", "Command line"))),
)
TABLES_BY_KEY = {table.key: table for table in TABLES}
PAGE_SIZE_MAX = 200

# A DNS name as it appears in the cache: letters, digits, hyphens, underscores and dots. Names the
# scan read from freed or reused memory come out as mojibake ("?ild᳭ⴌrd...") and are hidden.
_DNS_NAME = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})(?:\.[A-Za-z0-9_-]{1,63})*\.?$")
_PRINTABLE = re.compile(r"^[\x20-\x7e]*$")


def readable_dns_row(row: dict[str, str]) -> bool:
    name = (row.get("Name") or "").strip()
    data = (row.get("Data") or "").strip()
    return bool(name) and bool(_DNS_NAME.match(name)) and bool(_PRINTABLE.match(data))


@lru_cache(maxsize=32)
def _read_rows(path: str, mtime: float, size: int) -> tuple[tuple[str, ...], tuple[dict[str, str], ...]]:
    with open(path, encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = tuple({key: (value or "").strip() for key, value in record.items() if key} for record in reader)
        return tuple(reader.fieldnames or ()), rows


def table_rows(directory: Path, table: Table) -> tuple[list[dict[str, str]], int]:
    """(rows, hidden) of one saved inventory; hidden counts rows dropped as unreadable."""
    path = directory / table.file
    if not path.is_file():
        return [], 0
    stat = path.stat()
    _fields, rows = _read_rows(str(path), stat.st_mtime, stat.st_size)
    if table.key == "netdns":
        kept = [row for row in rows if readable_dns_row(row)]
        return kept, len(rows) - len(kept)
    return list(rows), 0


def _run_directory(output_dir: str | None) -> Path | None:
    from app.core.config import get_settings

    if not output_dir:
        return None
    path = Path(output_dir)
    settings = get_settings()
    candidates = [path] if path.is_absolute() else [settings.backend_data_dir / path]
    if not path.is_absolute() and str(path).startswith("memory-output/") and settings.memory_output_root:
        candidates.append(settings.memory_output_root / Path(str(path)[len("memory-output/"):]))
    for candidate in candidates:
        if (candidate / TIMELINE_DIRNAME).is_dir():
            return candidate / TIMELINE_DIRNAME
    return None


def active_find_evil_run(db: Session, case_id: str, evidence_id: str) -> tuple[dict[str, Any] | None, Path | None]:
    """The active Find Evil run of the evidence and the directory its MemProcFS CSVs are in."""
    from app.models.memory import MemoryScanRun
    from app.services.memory.active_result import resolve_active_memory_result

    resolved = resolve_active_memory_result(db, case_id=case_id, evidence_id=evidence_id, family="find_evil", page_size=1)
    run = resolved.get("active_run") if isinstance(resolved, dict) else None
    if not isinstance(run, dict) or not run.get("id"):
        return None, None
    model = db.get(MemoryScanRun, run["id"])
    return run, _run_directory(model.output_dir if model else None)


def _matches(row: dict[str, str], query: str) -> bool:
    return not query or any(query in value.lower() for value in row.values())


def memprocfs_table(db: Session, *, case_id: str, evidence_id: str, table: str, q: str | None = None, page: int = 1, page_size: int = 50) -> dict[str, Any]:
    spec = TABLES_BY_KEY.get(table) or TABLES[0]
    run, directory = active_find_evil_run(db, case_id, evidence_id)
    page = max(1, int(page))
    size = max(1, min(int(page_size), PAGE_SIZE_MAX))
    query = (q or "").strip().lower()
    counts: dict[str, int] = {}
    rows: list[dict[str, str]] = []
    hidden = 0
    if directory is not None:
        for candidate in TABLES:
            candidate_rows, candidate_hidden = table_rows(directory, candidate)
            counts[candidate.key] = len(candidate_rows)
            if candidate.key == spec.key:
                rows, hidden = candidate_rows, candidate_hidden
    filtered = [row for row in rows if _matches(row, query)]
    start = (page - 1) * size
    return {
        "table": spec.key,
        "tables": [{"key": item.key, "label": item.label, "group": item.group, "description": item.description, "count": counts.get(item.key, 0)} for item in TABLES],
        "columns": [{"key": column, "label": label} for column, label in spec.columns],
        "items": filtered[start : start + size],
        "total": len(filtered),
        "hidden": hidden,
        "page": page,
        "page_size": size,
        "run": run,
        # A Find Evil run from before these inventories were saved has none of them.
        "available": directory is not None and any(counts.values()),
    }
