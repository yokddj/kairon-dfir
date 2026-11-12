"""MemProcFS as the engine of Windows memory analysis; Volatility on request.

MemProcFS reads a Windows memory image without the kernel's symbols, and reads raw captures whose
page tables Volatility cannot find. Compared on six Windows images against Volatility's results
(with symbols): the same processes and command lines, the same DLLs, handles, kernel modules,
drivers, environment variables, SIDs and privileges (98-100 %, often more), and the network
connections (more on some images). So the Windows analyses run on MemProcFS; Volatility is an
extra the analyst asks for explicitly (``engine="volatility"``), for what MemProcFS does not give:
processes only a pool scan finds (psscan), injected-code regions (malfind), file objects
(filescan) and the PowerShell history read from them -- and for every Linux image.

One forensic scan per evidence gives everything (memprocfs_inventory, about a minute per 4 GB);
it is saved next to the evidence's memory outputs and every analysis reads it from there. Each
analysis's rows are given the columns of the Volatility plugin it stands in for, so they go
through the same normalizers into the same views.
"""

from __future__ import annotations

import csv
import fcntl
import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from app.services.memory.storage import memory_evidence_output_root

from app.core.storage import build_evidence_root

ENGINE_MEMPROCFS = "memprocfs"
ENGINE_VOLATILITY = "volatility"

# What each Windows profile runs on MemProcFS.
PROFILE_PLUGINS: dict[str, list[str]] = {
    "metadata_only": ["memprocfs.sysinfo"],
    "processes_basic": ["memprocfs.processes"],
    "processes_extended": ["memprocfs.envars", "memprocfs.getsids", "memprocfs.privileges"],
    "network_basic": ["memprocfs.network"],
    "modules_basic": ["memprocfs.dlllist"],
    "handles_basic": ["memprocfs.handles"],
    "kernel_basic": ["memprocfs.modules", "memprocfs.driverscan"],
    "shell_history_basic": ["memprocfs.console"],
    "find_evil": ["memprocfs.findevil"],
}
# Profiles with no MemProcFS equivalent: only with Volatility.
VOLATILITY_ONLY_PROFILES = {"suspicious_memory", "files_basic"}
# What the Volatility version of a profile adds over the MemProcFS one.
VOLATILITY_EXTRAS: dict[str, list[str]] = {
    "processes_extended": ["windows.psscan"],
    "shell_history_basic": ["windows.consoles", "windows.cmdscan", "kairon.psreadline"],
    "find_evil": ["kairon.findevil"],
}

# The analyses read from the saved inventory (the console and FindEvil open the image themselves).
INVENTORY_PLUGINS = {
    "memprocfs.sysinfo", "memprocfs.processes", "memprocfs.network", "memprocfs.dlllist", "memprocfs.handles",
    "memprocfs.modules", "memprocfs.driverscan", "memprocfs.envars", "memprocfs.getsids", "memprocfs.privileges",
}
# Which Volatility plugin's normalizer each one goes through.
STANDS_IN_FOR = {
    "memprocfs.sysinfo": "windows.info",
    "memprocfs.network": "windows.netscan",
    "memprocfs.dlllist": "windows.dlllist",
    "memprocfs.handles": "windows.handles",
    "memprocfs.modules": "windows.modules",
    "memprocfs.driverscan": "windows.driverscan",
    "memprocfs.envars": "windows.envars",
    "memprocfs.getsids": "windows.getsids",
    "memprocfs.privileges": "windows.privileges",
}

INVENTORY_DIRNAME = "memprocfs-inventory"
_COMPLETE_MARKER = "system.json"


def windows_profile_plugins(profile: str) -> list[str] | None:
    return list(PROFILE_PLUGINS[profile]) if profile in PROFILE_PLUGINS else None


def inventory_dir(case_id: str, evidence_id: str) -> Path:
    root = memory_evidence_output_root(case_id, evidence_id) or build_evidence_root(case_id, evidence_id)
    return root / "memory" / INVENTORY_DIRNAME


def inventory_ready(directory: Path) -> bool:
    return (directory / _COMPLETE_MARKER).is_file() and (directory / "process.csv").is_file()


@contextmanager
def _lock(directory: Path) -> Iterator[None]:
    directory.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    with open(directory.parent / f".{directory.name}.lock", "w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


SCAN_FILE = "scan.json"
FINDEVIL_FILE = "findevil.json"
FORENSIC_DIRNAME = "forensic"


def scan_complete(directory: Path) -> bool:
    """The evidence's whole MemProcFS scan is saved (not only an inventory saved by an older version)."""
    return inventory_ready(directory) and (directory / SCAN_FILE).is_file()


def scan_info(directory: Path) -> dict[str, Any] | None:
    try:
        return json.loads((directory / SCAN_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def ensure_scan(
    case_id: str,
    evidence_id: str,
    evidence_path: Path,
    work_dir: Path,
    *,
    timeout_seconds: int,
    cancellation_check: Callable[[], bool] | None = None,
    force: bool = False,
) -> Path:
    """The evidence's one MemProcFS scan -- inventory, FindEvil, timelines, tables, YARA details --
    made now if it is not saved yet or ``force`` asks for a new one (one scan at a time per
    evidence). Every Windows analysis reads it, so the image is scanned once."""
    from app.services.memory.memprocfs_runner import run_findevil
    from app.services.memory.volatility_runner import VolatilityRunnerError

    directory = inventory_dir(case_id, evidence_id)
    if scan_complete(directory) and not force:
        return directory
    with _lock(directory):
        if force or not scan_complete(directory):
            before = scan_info(directory) if force else None
            run_findevil(evidence_path, work_dir, timeout_seconds=timeout_seconds, max_output_bytes=1024 * 1024, cancellation_check=cancellation_check, scan_dir=directory)
            after = scan_info(directory)
            if not scan_complete(directory) or (force and after == before):
                raise VolatilityRunnerError("PLUGIN_FAILED", "MemProcFS's scan of this image did not complete.")
    return directory


def ensure_inventory(
    case_id: str,
    evidence_id: str,
    evidence_path: Path,
    work_dir: Path,
    *,
    timeout_seconds: int,
    cancellation_check: Callable[[], bool] | None = None,
    force: bool = False,
) -> Path:
    """The evidence's saved MemProcFS inventory: from its scan, made now if there is none. An
    inventory saved before the scan kept everything is still used."""
    directory = inventory_dir(case_id, evidence_id)
    if inventory_ready(directory) and not force:
        return directory
    return ensure_scan(case_id, evidence_id, evidence_path, work_dir, timeout_seconds=timeout_seconds, cancellation_check=cancellation_check, force=force)


def findevil_rows(directory: Path) -> list[dict[str, str]] | None:
    """FindEvil's rows from the saved scan; None when FindEvil does not cover the image."""
    path = directory / FINDEVIL_FILE
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def forensic_dir(directory: Path) -> Path:
    return directory / FORENSIC_DIRNAME


def _csv(directory: Path, name: str) -> list[dict[str, str]]:
    path = directory / f"{name}.csv"
    if not path.is_file():
        return []
    with path.open(encoding="utf-8", errors="replace", newline="") as handle:
        return list(csv.DictReader(handle))


def _json(directory: Path, name: str) -> Any:
    path = directory / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _int(value: Any, base: int = 10) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, base)
    except ValueError:
        return None


def _hex(value: Any) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def _iso(value: Any) -> str | None:
    text = str(value or "").strip().removesuffix(" UTC").strip()
    if len(text) == 19 and text[4] == "-" and text[10] == " ":
        return f"{text[:10]}T{text[11:]}+00:00"
    return text or None


def _process_names(directory: Path) -> dict[int, str]:
    return {pid: row.get("Name") or row.get("ShortName") or "" for row in _csv(directory, "process") if (pid := _int(row.get("PID"))) is not None}


_MACHINE_TYPES = {"X64": "34404", "X86": "332", "ARM64": "43620"}


def rows(plugin: str, directory: Path) -> list[dict[str, Any]]:
    """The analysis's rows, in the columns of the Volatility plugin it stands in for."""
    if plugin == "memprocfs.sysinfo":
        system = _json(directory, "system")
        build = system.get("version-build") or ""
        values = {
            "Computer Name": system.get("computername") or None,
            "NtMajorVersion": system.get("version-major") or None,
            "NtMinorVersion": system.get("version-minor") or None,
            "Major/Minor": f"15.{build}" if build else None,
            "Is64Bit": str(system.get("architecture") == "X64"),
            "MachineType": _MACHINE_TYPES.get(str(system.get("architecture") or "").upper()),
            "SystemTime": (_iso(system.get("time-current")) or "").replace("T", " ") or None,
            "BootTime": _iso(system.get("time-boot")),
            "TimeZone": system.get("timezone") or None,
            "Version": system.get("version") or None,
        }
        return [{"Variable": key, "Value": value} for key, value in values.items() if value]
    if plugin == "memprocfs.processes":
        return _csv(directory, "process")
    if plugin == "memprocfs.network":
        return _csv(directory, "net")  # converted by the network normalizer (memprocfs_net_rows)
    if plugin in ("memprocfs.dlllist", "memprocfs.modules"):
        kernel = plugin == "memprocfs.modules"
        out = []
        for row in _csv(directory, "modules"):
            pid = _int(row.get("PID"))
            if pid is None or (pid == 4) != kernel:
                continue
            item = {"Base": _hex(row.get("Start")), "Size": _hex(row.get("Size")), "Name": row.get("Name"), "Path": row.get("Path") or row.get("KernelPath") or None}
            if not kernel:
                item.update({"PID": pid, "Process": row.get("Process")})
            out.append(item)
        return out
    if plugin == "memprocfs.handles":
        names = _process_names(directory)
        return [
            {"PID": pid, "Process": names.get(pid), "Offset": _hex(row.get("Object")), "HandleValue": _hex(row.get("Handle")), "Type": row.get("Type"), "GrantedAccess": _hex(row.get("Access")), "Name": row.get("Description") or None}
            for row in _csv(directory, "handles")
            if (pid := _int(row.get("PID"))) is not None
        ]
    if plugin == "memprocfs.driverscan":
        return [
            {"Offset": _hex(row.get("ObjectAddress")), "Start": _hex(row.get("Start")), "Size": _hex(row.get("Size")), "Service Key": row.get("ServiceKey") or None, "Driver Name": row.get("Name") or None, "Name": row.get("DriverName") or None}
            for row in _csv(directory, "drivers")
        ]
    if plugin == "memprocfs.envars":
        names = _process_names(directory)
        return [
            {"PID": int(pid), "Process": names.get(int(pid)), "Block": None, "Variable": variable, "Value": value}
            for pid, variables in (_json(directory, "environment") or {}).items()
            for variable, value in variables.items()
        ]
    if plugin in ("memprocfs.getsids", "memprocfs.privileges"):
        names = _process_names(directory)
        out = []
        for pid, token in (_json(directory, "tokens") or {}).items():
            process = names.get(int(pid))
            if plugin == "memprocfs.getsids":
                out.extend({"PID": int(pid), "Process": process, "SID": item.get("sid"), "Name": item.get("name")} for item in token.get("sids") or [])
            else:
                for item in token.get("privileges") or []:
                    attributes = [label for flag, label in (("present", "Present"), ("enabled", "Enabled"), ("default", "Default")) if item.get(flag)]
                    out.append({"PID": int(pid), "Process": process, "Value": item.get("value"), "Privilege": item.get("name"), "Attributes": ",".join(attributes), "Description": None})
        return out
    raise ValueError(f"not a MemProcFS inventory analysis: {plugin}")
