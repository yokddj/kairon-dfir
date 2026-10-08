"""Kairon's own Find Evil checks, built from standard Volatility 3 plugins.

MemProcFS's FindEvil is a deep scan, but it is one native tool with its own limits: on some
images its forensic scan never finishes (seen on a Windows 11 24H2 crash dump stuck at 90 %),
and then it yields nothing. These checks need only plugins that work wherever Volatility can
read the image -- pslist, psscan, cmdline, malfind and ldrmodules -- so Find Evil always has
indicators to show, and MemProcFS's (when it finishes) are added next to them.

Every check is generic: it encodes how Windows normally looks (which process starts which, where
system binaries live, which processes run once), never anything specific to one case. Each
indicator is a lead with a review priority, not a verdict.

Output rows use the shape of MemProcFS's findevil.csv ({"PID", "Process", "Type", "Address",
"Description"}) plus an optional "Priority" that overrides the type's default, so one
normalizer (artifact_normalizers.normalize_memprocfs_findevil) handles both producers.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

KAIRON_FINDEVIL_PLUGIN = "kairon.findevil"

# Volatility plugins the checks read, in the order they run (cheapest first, so a timeout still
# leaves the process checks).
SOURCE_PLUGINS = ("windows.pslist", "windows.psscan", "windows.cmdline", "windows.malfind", "windows.ldrmodules")

# Image names are compared on Windows' 14-character EPROCESS.ImageFileName, which is all pslist
# and psscan report ("SearchIndexer." for SearchIndexer.exe).
_IMAGE_NAME_LENGTH = 14

# Expected parents of Windows system processes. Only checked when the parent is still in the
# process list and was created before the child: a parent PID that was reused by a later process
# says nothing about who started the child.
_EXPECTED_PARENTS: dict[str, tuple[str, ...]] = {
    "smss.exe": ("system", "smss.exe"),
    "wininit.exe": ("smss.exe",),
    "winlogon.exe": ("smss.exe",),
    "csrss.exe": ("smss.exe",),
    "services.exe": ("wininit.exe",),
    "lsass.exe": ("wininit.exe",),
    "lsaiso.exe": ("wininit.exe",),
    "svchost.exe": ("services.exe", "msmpeng.exe"),
    "spoolsv.exe": ("services.exe",),
    "searchindexer.exe": ("services.exe",),
    "taskhostw.exe": ("svchost.exe",),
    "runtimebroker.exe": ("svchost.exe",),
    "wmiprvse.exe": ("svchost.exe",),
    "userinit.exe": ("winlogon.exe",),
    "dwm.exe": ("winlogon.exe",),
}

# Processes Windows runs exactly once.
_SINGLETONS = ("lsass.exe", "services.exe", "wininit.exe", "lsaiso.exe")

# System binaries whose name malware imitates, and that live in System32 (or SysWOW64).
_SYSTEM_BINARIES = (
    "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "smss.exe", "winlogon.exe", "wininit.exe",
    "spoolsv.exe", "taskhostw.exe", "lsaiso.exe", "dllhost.exe", "conhost.exe", "rundll32.exe",
    "runtimebroker.exe", "searchindexer.exe", "wmiprvse.exe", "userinit.exe", "dwm.exe", "ctfmon.exe",
)
_LOOKALIKE_TARGETS = (*_SYSTEM_BINARIES, "explorer.exe")
# Real Windows binaries one edit away from another one.
_BENIGN_LOOKALIKES = frozenset({"taskhost.exe", "taskhostex.exe", "dllhst3g.exe"})

# Command interpreters and script hosts, and the processes that should not start them.
_SHELLS = (
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "msbuild.exe", "installutil.exe",
)
_UNUSUAL_SHELL_PARENTS = (
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe",
    "visio.exe", "acrord32.exe", "acrobat.exe", "foxitreader.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "iexplore.exe", "opera.exe", "brave.exe", "w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe",
    "sqlservr.exe", "tomcat.exe", "java.exe", "javaw.exe", "spoolsv.exe", "lsass.exe", "searchindexer.exe",
)

# Folders anyone can write to; programs run from there are worth a look. (pattern, priority)
_WRITABLE_LOCATIONS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"\\appdata\\local\\temp\\", re.I), "medium", "a temporary folder"),
    (re.compile(r"\\windows\\temp\\", re.I), "medium", "the Windows temporary folder"),
    (re.compile(r"\\users\\public\\", re.I), "medium", "the Public profile"),
    (re.compile(r"\\\$recycle\.bin\\", re.I), "high", "the Recycle Bin"),
    (re.compile(r"\\perflogs\\", re.I), "medium", "PerfLogs"),
    (re.compile(r"\\programdata\\[^\\]+\.(?:exe|scr|com)$", re.I), "medium", "the root of ProgramData"),
    (re.compile(r"\\appdata\\roaming\\[^\\]+\.(?:exe|scr|com)$", re.I), "medium", "the root of AppData\\Roaming"),
    (re.compile(r"\\downloads\\", re.I), "low", "a Downloads folder"),
    (re.compile(r"\\desktop\\", re.I), "low", "a Desktop folder"),
)

# Command-line patterns attackers rely on. (pattern, priority, what it is)
_COMMAND_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"(?:powershell|pwsh)(?:\.exe)?\b.*\s[-/](?:e|ec|en\w*)\s+[A-Za-z0-9+/=]{16,}", re.I), "high", "PowerShell with an encoded command"),
    (re.compile(r"(?:downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|invoke-restmethod|start-bitstransfer|\biwr\b|\birm\b)", re.I), "high", "PowerShell download"),
    (re.compile(r"(?:\biex\b|invoke-expression)", re.I), "high", "PowerShell Invoke-Expression"),
    (re.compile(r"frombase64string", re.I), "high", "Base64 decoding in a command line"),
    (re.compile(r"certutil(?:\.exe)?\b.*[-/](?:urlcache|decode|decodehex)\b", re.I), "high", "certutil download or decode"),
    (re.compile(r"mshta(?:\.exe)?\b.*(?:https?:|javascript:|vbscript:)", re.I), "high", "mshta running remote or inline script"),
    (re.compile(r"regsvr32(?:\.exe)?\b.*(?:/i:\s*https?:|scrobj\.dll)", re.I), "high", "regsvr32 script execution (Squiblydoo)"),
    (re.compile(r"rundll32(?:\.exe)?\b.*(?:javascript:|comsvcs(?:\.dll)?\W+#?\s*(?:24|minidump)|url\.dll,|shell32\.dll,\s*shellexec_rundll)", re.I), "high", "rundll32 proxy execution or memory dump"),
    (re.compile(r"bitsadmin(?:\.exe)?\b.*/(?:transfer|addfile)", re.I), "high", "bitsadmin download"),
    (re.compile(r"(?:vssadmin(?:\.exe)?\b.*delete\s+shadows|wmic(?:\.exe)?\b.*shadowcopy\s+delete|wbadmin(?:\.exe)?\b.*delete\s+(?:catalog|systemstatebackup)|bcdedit(?:\.exe)?\b.*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures))", re.I), "high", "backup or recovery deletion (ransomware)"),
    (re.compile(r"(?:sekurlsa::|lsadump::|kerberos::|privilege::debug|mimikatz)", re.I), "high", "credential dumping tool"),
    (re.compile(r"(?:procdump(?:64)?(?:\.exe)?\b.*lsass|lsass\.dmp)", re.I), "high", "LSASS memory dump"),
    (re.compile(r"wmic(?:\.exe)?\b.*(?:process\s+call\s+create|/node:)", re.I), "high", "WMI remote or process execution"),
    (re.compile(r"\bnet1?(?:\.exe)?\s+(?:user|localgroup)\b.*\s/add\b", re.I), "high", "account or group change"),
    (re.compile(r"(?:\s|^)[-/](?:w|win|window|windowstyle)\s+h(?:idden)?\b", re.I), "medium", "hidden window"),
    (re.compile(r"(?:\s|^)[-/](?:ep|exec|executionpolicy)\s+bypass\b", re.I), "medium", "execution policy bypass"),
    (re.compile(r"schtasks(?:\.exe)?\b.*/create\b", re.I), "medium", "scheduled task creation"),
    (re.compile(r"reg(?:\.exe)?\s+add\b.*\\currentversion\\(?:run|runonce)\b", re.I), "medium", "Run key persistence"),
    (re.compile(r"\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?create\b", re.I), "medium", "service creation"),
    (re.compile(r"(?:curl|wget)(?:\.exe)?\b.*https?://", re.I), "medium", "command-line download"),
    (re.compile(r"(?:psexe(?:c|svc)|paexec|\\\\[^\\\s]+\\(?:admin|c|ipc)\$)", re.I), "medium", "remote execution or admin share"),
    (re.compile(r"(?:^|[\\\s\"])(?:whoami|nltest|systeminfo|net(?:1)?\s+(?:view|group|localgroup|user)|ipconfig\s+/all|arp\s+-a|quser|qwinsta)(?:\.exe)?\b", re.I), "low", "discovery command"),
)

# Processes that allocate executable private memory as part of normal work (JIT compilers,
# browsers, the antivirus engine), so malfind's hits there are expected.
_JIT_HOSTS = (
    "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "msedgewebview2.exe", "iexplore.exe",
    "msmpeng.exe", "mssense.exe", "onedrive.exe", "teams.exe", "ms-teams.exe", "code.exe", "slack.exe",
    "discord.exe", "java.exe", "javaw.exe", "node.exe", "dotnet.exe", "searchapp.exe", "searchhost.exe",
    "widgets.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe", "smartscreen.exe",
)

_MODULE_EXTENSIONS = (".dll", ".exe", ".ocx", ".cpl", ".sys", ".drv", ".scr")
# Where Windows and installed programs keep their modules (ldrmodules reports paths without the
# drive letter).
_RESOURCE_MODULE = re.compile(r"resources?\.dll$", re.I)
_TRUSTED_MODULE_FOLDER = re.compile(r"^(?:[A-Za-z]:)?\\(?:windows|program files(?: \(x86\))?|programdata\\microsoft)\\", re.I)


# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------


def _short(name: str) -> str:
    return name.lower()[:_IMAGE_NAME_LENGTH]


def _is(name: str | None, *candidates: str) -> bool:
    """Whether a (possibly truncated) image name is one of ``candidates``."""
    if not name:
        return False
    short = _short(name)
    return any(short == _short(candidate) for candidate in candidates)


def _rows(payload: Any) -> list[dict[str, Any]]:
    flat: list[dict[str, Any]] = []

    def walk(nodes: Any) -> None:
        if not isinstance(nodes, list):
            return
        for node in nodes:
            if isinstance(node, dict):
                flat.append({key: value for key, value in node.items() if key != "__children"})
                walk(node.get("__children"))

    walk(payload)
    return flat


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _time(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _hex(value: Any) -> str:
    number = _int(value)
    return f"0x{number:x}" if number is not None else ""


def _one_typo_apart(a: str, b: str) -> bool:
    if a == b:
        return False
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        differences = [index for index, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(differences) == 1:
            return True
        # Two swapped neighbours ("scvhost.exe").
        first, *rest = differences
        return len(rest) == 1 and rest[0] == first + 1 and a[first] == b[first + 1] and a[first + 1] == b[first]
    if len(a) > len(b):
        a, b = b, a
    for index in range(len(b)):
        if b[:index] + b[index + 1:] == a:
            return True
    return False


def _image_path(command_line: str | None) -> str | None:
    """The executable path at the start of a command line, without quotes or NT prefixes."""
    if not command_line or not isinstance(command_line, str):
        return None
    text = command_line.strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        path = text[1:end] if end > 0 else text[1:]
    else:
        match = re.match(r"(.+?\.(?:exe|com|scr|bat|cmd))(?:\s|$)", text, re.I)
        path = match.group(1) if match else text.split(" ", 1)[0]
    for prefix in ("\\??\\", "\\\\?\\"):
        if path.startswith(prefix):
            path = path[len(prefix):]
    path = re.sub(r"^(?:%systemroot%|\\systemroot)", "C:\\\\Windows", path, flags=re.I)
    return path or None


def _in_system_folder(path: str) -> bool:
    return bool(re.search(r"\\windows\\(?:system32|syswow64|winsxs|servicing)\\", path, re.I))


def _indicator(pid: int | None, process: str | None, kind: str, description: str, *, address: str = "", priority: str | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {"PID": pid or 0, "Process": process or "", "Type": kind, "Address": address, "Description": description}
    if priority:
        row["Priority"] = priority
    return row


# ---------------------------------------------------------------------------------------------
# Checks (pure functions over plugin rows)
# ---------------------------------------------------------------------------------------------


def findevil_indicators(
    *,
    pslist: list[dict[str, Any]] | None = None,
    psscan: list[dict[str, Any]] | None = None,
    cmdline: list[dict[str, Any]] | None = None,
    malfind: list[dict[str, Any]] | None = None,
    ldrmodules: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Indicators from whichever plugin outputs are available (``None`` = plugin not run)."""
    indicators: list[dict[str, Any]] = []
    listed = {pid: row for row in (pslist or []) if (pid := _int(row.get("PID"))) is not None}
    commands = {pid: str(row.get("Args")) for row in (cmdline or []) if (pid := _int(row.get("PID"))) is not None and isinstance(row.get("Args"), str)}
    boot_time = next((_time(row.get("CreateTime")) for row in listed.values() if _int(row.get("PID")) == 4), None)

    def name_of(pid: int | None) -> str:
        row = listed.get(pid) if pid is not None else None
        return str(row.get("ImageFileName") or "") if row else ""

    def real_parent(row: dict[str, Any]) -> dict[str, Any] | None:
        """The parent process, if it is still listed and is really the one that started ``row``."""
        parent = listed.get(_int(row.get("PPID")))
        if not parent or parent is row:
            return None
        parent_created, child_created = _time(parent.get("CreateTime")), _time(row.get("CreateTime"))
        if parent_created and child_created and parent_created > child_created:
            return None  # PID reused after the real parent exited
        return parent

    # Hidden or terminated processes: found by scanning memory, missing from the kernel's list.
    for row in psscan or []:
        pid = _int(row.get("PID"))
        if pid is None or pid in listed or pid == 0:
            continue
        name = str(row.get("ImageFileName") or "")
        created = _time(row.get("CreateTime"))
        threads = _int(row.get("Threads")) or 0
        exited = row.get("ExitTime")
        if boot_time and created and created < boot_time:
            continue  # leftover from before this boot
        parent_pid = _int(row.get("PPID"))
        parent_name = name_of(parent_pid)
        context = f"created {row.get('CreateTime') or 'unknown'}, parent PID {parent_pid}{f' ({parent_name})' if parent_name else ''}"
        if not exited and threads > 0:
            indicators.append(_indicator(pid, name, "PROC_NOLINK", f"Not in the kernel's process list, yet it has {threads} thread(s) and no exit time: hidden (unlinked) process. {context}.", address=_hex(row.get("Offset(V)"))))
        elif exited:
            indicators.append(_indicator(pid, name, "PROC_TERMINATED", f"Exited at {exited}; {context}.", address=_hex(row.get("Offset(V)"))))

    alive = [row for row in listed.values() if not row.get("ExitTime")]

    # More than one instance of a process Windows runs once.
    for singleton in _SINGLETONS:
        instances = [row for row in alive if _is(str(row.get("ImageFileName") or ""), singleton)]
        if len(instances) > 1:
            pids = ", ".join(str(row.get("PID")) for row in instances)
            for row in instances:
                indicators.append(_indicator(_int(row.get("PID")), singleton, "PROC_DUPLICATE", f"{len(instances)} instances of {singleton} (PIDs {pids}); Windows runs only one."))

    for row in alive:
        pid = _int(row.get("PID"))
        name = str(row.get("ImageFileName") or "")
        lower = name.lower()
        parent = real_parent(row)
        parent_name = str(parent.get("ImageFileName") or "") if parent else ""
        command = commands.get(pid) if pid is not None else None
        path = _image_path(command)

        # Unexpected parent for a Windows system process.
        for system_name, parents in _EXPECTED_PARENTS.items():
            if _is(name, system_name):
                if parent and not _is(parent_name, *parents):
                    indicators.append(_indicator(pid, name, "PROC_PARENT", f"{system_name} started by {parent_name} (PID {row.get('PPID')}); expected {' or '.join(parents)}."))
                break

        # Name one character away from a system binary.
        if lower not in _BENIGN_LOOKALIKES and not any(_is(name, target) for target in _LOOKALIKE_TARGETS):
            for target in _LOOKALIKE_TARGETS:
                if _one_typo_apart(_short(name), _short(target)):
                    indicators.append(_indicator(pid, name, "PROC_NAME", f"Name looks like {target}."))
                    break

        # System binary outside System32.
        if path and re.match(r"^[A-Za-z]:\\", path) and any(_is(name, binary) for binary in _SYSTEM_BINARIES) and not _in_system_folder(path):
            indicators.append(_indicator(pid, name, "PROC_PATH", f"Runs from {path}, not from System32."))

        # Program running from a user-writable folder.
        if path:
            for pattern, priority, where in _WRITABLE_LOCATIONS:
                if pattern.search(path):
                    indicators.append(_indicator(pid, name, "PROC_LOCATION", f"Runs from {where}: {path}", priority=priority))
                    break

        # Command interpreter started by an Office application, browser or server.
        if parent and any(_is(name, shell) for shell in _SHELLS) and any(_is(parent_name, unusual) for unusual in _UNUSUAL_SHELL_PARENTS):
            indicators.append(_indicator(pid, name, "PROC_SPAWN", f"{name} started by {parent_name} (PID {row.get('PPID')})."))

    # Suspicious command lines (every process with a command line, exited or not).
    for pid, command in commands.items():
        hits = [(priority, label) for pattern, priority, label in _COMMAND_PATTERNS if pattern.search(command)]
        if not hits:
            continue
        order = {"high": 0, "medium": 1, "low": 2}
        hits.sort(key=lambda hit: order[hit[0]])
        labels = ", ".join(dict.fromkeys(label for _, label in hits))
        indicators.append(_indicator(pid, name_of(pid) or None, "CMDLINE", f"{labels}: {command[:900]}", priority=hits[0][0]))

    # Code injected into processes (malfind): a PE header in private executable memory is an
    # injected module; other hits are normal in JIT hosts.
    for row in malfind or []:
        pid = _int(row.get("PID"))
        name = str(row.get("Process") or name_of(pid))
        hexdump = str(row.get("Hexdump") or "").strip().lower()
        start = _hex(row.get("Start VPN"))
        protection = str(row.get("Protection") or "")
        if hexdump.startswith("4d 5a"):
            indicators.append(_indicator(pid, name, "PE_INJECT", f"PE header (MZ) in {protection or 'executable'} private memory at {start}.", address=start))
        else:
            jit = any(_is(name, host) for host in _JIT_HOSTS)
            indicators.append(_indicator(pid, name, "PRIVATE_RWX", f"{protection or 'Executable'} private memory at {start}{' (expected in this process: JIT or antivirus)' if jit else ''}.", address=start, priority="low" if jit else "medium"))

    # Modules mapped in a process but missing from its loader lists (unlinked DLLs).
    for row in ldrmodules or []:
        pid = _int(row.get("Pid") or row.get("PID"))
        if pid in (None, 4):
            continue
        mapped = str(row.get("MappedPath") or "")
        if row.get("InLoad") or row.get("InMem"):
            continue
        name = str(row.get("Process") or name_of(pid))
        base = _hex(row.get("Base"))
        if not mapped:
            indicators.append(_indicator(pid, name, "PE_NOLINK", f"Executable image at {base} with no file behind it and missing from the loader lists: possible manually mapped module.", address=base, priority="high"))
        elif mapped.lower().endswith(_MODULE_EXTENSIONS) and not _TRUSTED_MODULE_FOLDER.match(mapped) and not _RESOURCE_MODULE.search(mapped):
            # Windows maps many of its own DLLs as data (resources, LoadLibraryEx), outside the
            # loader lists; an unlinked module elsewhere is the unusual case.
            indicators.append(_indicator(pid, name, "PE_NOLINK", f"{mapped} mapped at {base} but missing from the process's loaded-module lists.", address=base))
    return indicators


# ---------------------------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------------------------


def run_kairon_findevil(
    evidence_path: Path,
    work_dir: Path,
    *,
    timeout_seconds: int,
    max_output_bytes: int,
    plugin_timeout: Callable[[str], int],
    cancellation_check: Callable[[], bool] | None = None,
):
    """Run the source plugins and return the indicators as a Volatility-shaped run result.

    A source plugin that fails or times out only removes its own checks; the others still run.
    """
    from app.services.memory.volatility_runner import VolatilityRunnerError, VolatilityRunResult, run_plugin

    started = time.monotonic()
    deadline = started + max(1, int(timeout_seconds))
    outputs: dict[str, list[dict[str, Any]] | None] = {}
    failures: list[str] = []
    for plugin in SOURCE_PLUGINS:
        remaining = int(deadline - time.monotonic())
        if remaining < 10:
            failures.append(f"{plugin}: no time left")
            outputs[plugin] = None
            continue
        try:
            result = run_plugin(
                plugin,
                evidence_path,
                work_dir / "kairon-findevil",
                timeout_seconds=min(remaining, plugin_timeout(plugin)),
                max_output_bytes=max_output_bytes,
                cancellation_check=cancellation_check,
            )
            outputs[plugin] = _rows(json.loads(result.stdout.decode("utf-8")))
        except VolatilityRunnerError as exc:
            if exc.code == "PLUGIN_CANCELLED":
                raise
            failures.append(f"{plugin}: {exc.code}")
            outputs[plugin] = None
        except (ValueError, UnicodeDecodeError):
            failures.append(f"{plugin}: output not readable")
            outputs[plugin] = None
    if all(value is None for value in outputs.values()):
        raise VolatilityRunnerError("PLUGIN_FAILED", "None of the Volatility plugins Kairon's Find Evil checks need could run on this image (" + "; ".join(failures)[:250] + ").")
    indicators = findevil_indicators(
        pslist=outputs.get("windows.pslist"),
        psscan=outputs.get("windows.psscan"),
        cmdline=outputs.get("windows.cmdline"),
        malfind=outputs.get("windows.malfind"),
        ldrmodules=outputs.get("windows.ldrmodules"),
    )
    stderr = ("Checks skipped: " + "; ".join(failures)).encode("utf-8") if failures else b""
    return VolatilityRunResult(
        argv_display=["kairon-findevil", *[plugin for plugin, rows in outputs.items() if rows is not None]],
        stdout=json.dumps(indicators).encode("utf-8"),
        stderr=stderr,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
