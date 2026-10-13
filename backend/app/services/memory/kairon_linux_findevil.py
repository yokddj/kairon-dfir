"""Kairon's Find Evil checks for Linux memory, built from standard Volatility 3 plugins.

The Linux counterpart of app.services.memory.kairon_findevil: it runs Volatility's process,
open-file, module and rootkit plugins and turns what they report into indicators to review.
Every check encodes how Linux normally looks (kernel threads are children of kthreadd, shells do
not read their commands from a socket, syscall handlers live in the kernel's code), never
anything specific to one case. Each indicator is a lead with a review priority, not a verdict.

Kernel hook checks compare handler addresses with the kernel's symbols. When most syscall
handlers have no symbol, the symbols' addresses do not belong to this exact kernel build (a
profile made from a near build moves only code addresses), so those checks would report noise:
they are skipped and the run says why.

Rows use the shape of kairon_findevil's ({"PID", "Process", "Type", "Address", "Description",
"Priority"}), so artifact_normalizers.normalize_memprocfs_findevil reads both.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

KAIRON_LINUX_FINDEVIL_PLUGIN = "kairon.linux_findevil"

# Volatility plugins the checks read, cheapest first so a timeout still leaves the process checks.
SOURCE_PLUGINS = (
    "linux.pslist",
    "linux.psaux",
    "linux.psscan",
    "linux.lsof",
    "linux.lsmod",
    "linux.malware.check_modules",
    "linux.malware.hidden_modules",
    "linux.malware.check_syscall",
    "linux.malware.check_idt",
    "linux.malware.tty_check",
    "linux.malware.check_afinfo",
    "linux.malware.malfind",
)

_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "ash", "busybox", "fish"})

# Services that answer the network and should not start shells: a shell under one of them is how
# a web shell or an exploited service shows up.
_NETWORK_SERVICES = frozenset({
    "apache", "apache2", "httpd", "nginx", "lighttpd", "php-fpm", "php-cgi", "php5-cgi", "php", "uwsgi",
    "gunicorn", "tomcat", "java", "node", "mysqld", "mariadbd", "postgres", "redis-server", "mongod",
    "named", "vsftpd", "proftpd", "pure-ftpd", "exim4", "exim", "sendmail", "master", "smtpd", "dovecot",
    "smbd", "cupsd", "squid", "memcached", "elasticsearch", "jenkins", "weblogic", "jboss",
})

# Programs whose job is to run something as another user; their children legitimately change uid.
_PRIVILEGE_CHANGERS = frozenset({
    "su", "sudo", "pkexec", "doas", "login", "sshd", "cron", "crond", "atd", "polkitd", "systemd",
    "init", "kthreadd", "newgrp", "sg", "passwd", "chsh", "chfn", "gdm", "lightdm", "sddm", "xdm",
    "runuser", "setpriv", "dbus-daemon", "udevd", "systemd-udevd", "agetty", "getty", "mingetty",
})

# Folders anyone can write to. (pattern, priority, label)
_WRITABLE_LOCATIONS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"^/dev/shm/"), "high", "shared memory (/dev/shm)"),
    (re.compile(r"^/(?:var/)?tmp/"), "medium", "a temporary folder"),
    (re.compile(r"^/run/user/\d+/"), "medium", "a user runtime folder"),
    (re.compile(r"/\.[^/]+/"), "medium", "a hidden folder"),
)

# Command-line patterns attackers rely on. (pattern, priority, what it is)
_COMMAND_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"/dev/(?:tcp|udp)/"), "high", "bash network redirection (/dev/tcp)"),
    (re.compile(r"\b(?:nc|ncat|netcat)(?:\.\w+)?\b.*\s-[a-z]*[ec]\b", re.I), "high", "netcat executing a program"),
    (re.compile(r"\bsocat\b.*\b(?:exec|system):", re.I), "high", "socat executing a program"),
    (re.compile(r"\b(?:ba|z|k)?sh\s+-i\b"), "high", "interactive shell"),
    (re.compile(r"\bpython[\d.]*\s+-c\b.*\bsocket\b", re.I), "high", "Python reverse shell"),
    (re.compile(r"\bperl\b.*\s-e\b.*\bsocket\b", re.I), "high", "Perl reverse shell"),
    (re.compile(r"\bphp\b.*\s-r\b.*\bfsockopen\b", re.I), "high", "PHP reverse shell"),
    (re.compile(r"\bruby\b.*\s-e\b.*\bTCPSocket\b"), "high", "Ruby reverse shell"),
    (re.compile(r"\bmkfifo\b.*\b(?:nc|ncat|netcat|openssl)\b", re.I), "high", "named pipe shell"),
    (re.compile(r"\b(?:curl|wget)\b[^|;]*\|\s*(?:sudo\s+)?(?:ba|da|z)?sh\b", re.I), "high", "download piped into a shell"),
    (re.compile(r"\bbase64\s+(?:-d|--decode)\b[^|;]*\|\s*(?:ba|da|z)?sh\b", re.I), "high", "decoded script piped into a shell"),
    (re.compile(r"(?:xmrig|minerd|cpuminer|stratum\+tcp://)", re.I), "high", "cryptocurrency miner"),
    (re.compile(r"(?:unset\s+HISTFILE|HISTFILE=/dev/null|history\s+-c\b|HISTSIZE=0)"), "high", "shell history disabled or cleared"),
    (re.compile(r"\b(?:insmod|modprobe)\s+\S*/(?:tmp|dev/shm|var/tmp|home)/", re.I), "high", "kernel module loaded from a user folder"),
    (re.compile(r"\bchmod\s+[+0-7]*[x7]\S*\s+/(?:tmp|dev/shm|var/tmp)/"), "medium", "file in a temporary folder made executable"),
    (re.compile(r"\b(?:curl|wget)\b.*\s(?:-O|-o|--output)\s*/(?:tmp|dev/shm|var/tmp)/", re.I), "medium", "download into a temporary folder"),
    (re.compile(r"\b(?:useradd|adduser)\b|\busermod\b.*\s-a?G\b"), "medium", "account or group change"),
    (re.compile(r"\bcrontab\s+(?:-\s*$|-r\b|\S+\s*$)"), "medium", "crontab change"),
    (re.compile(r"\biptables\s+(?:-F|--flush)\b"), "medium", "firewall rules flushed"),
    (re.compile(r"\brm\s+-[a-z]*r[a-z]*f?\S*\s+/var/log\b"), "high", "logs deleted"),
    (re.compile(r"\b(?:nc|ncat|netcat)\s+(?:-\S+\s+)*\d{1,3}(?:\.\d{1,3}){3}\s+\d+\b", re.I), "medium", "netcat connection"),
    (re.compile(r"(?:^|[\s/])(?:whoami|id|uname\s+-a|cat\s+/etc/(?:passwd|shadow)|sudo\s+-l|ifconfig|ip\s+a(?:ddr)?)(?:\s|$)"), "low", "discovery command"),
)

# Processes that create writable and executable memory as part of normal work (JIT compilers).
_JIT_HOSTS = frozenset({"java", "node", "chrome", "chromium", "firefox", "thunderbird", "code", "electron", "dotnet", "mono", "qemu-system-x86_64", "Xorg", "gnome-shell", "plasmashell"})


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


def _hex(value: Any) -> str:
    number = _int(value)
    return f"0x{number:x}" if number is not None else ""


def _get(row: dict[str, Any], *names: str) -> Any:
    lowered = {str(key).lower(): value for key, value in row.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _indicator(pid: int | None, process: str | None, kind: str, description: str, *, address: str = "", priority: str | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {"PID": pid or 0, "Process": process or "", "Type": kind, "Address": address, "Description": description}
    if priority:
        row["Priority"] = priority
    return row


def _executable(args: str | None) -> str | None:
    if not args or not isinstance(args, str):
        return None
    first = args.strip().split(" ", 1)[0]
    return first if first.startswith("/") else None


def _module_ranges(lsmod: list[dict[str, Any]] | None) -> list[tuple[int, int, str]]:
    ranges = []
    for row in lsmod or []:
        start, size = _int(_get(row, "Offset")), _int(_get(row, "Code Size"))
        name = str(_get(row, "Module Name", "Name") or "")
        if start and size:
            ranges.append((start, start + size, name))
    return ranges


def _module_at(address: int | None, ranges: list[tuple[int, int, str]]) -> str | None:
    if address is None:
        return None
    for start, end, name in ranges:
        if start <= address < end:
            return name
    return None


def _symbols_match_build(check_syscall: list[dict[str, Any]] | None) -> bool | None:
    """Whether kernel symbol addresses belong to this exact build (None: not known)."""
    if not check_syscall:
        return None
    resolved = sum(1 for row in check_syscall if str(_get(row, "Handler Symbol") or "UNKNOWN") != "UNKNOWN")
    return resolved * 2 >= len(check_syscall)


def linux_findevil_indicators(outputs: dict[str, list[dict[str, Any]] | None]) -> tuple[list[dict[str, Any]], list[str]]:
    """Indicators from whichever plugin outputs are available (``None`` = plugin not run).

    Returns (indicators, notes); notes explain checks that were skipped.
    """
    indicators: list[dict[str, Any]] = []
    notes: list[str] = []
    pslist = outputs.get("linux.pslist")
    psaux = outputs.get("linux.psaux")
    psscan = outputs.get("linux.psscan")
    lsof = outputs.get("linux.lsof")
    modules = _module_ranges(outputs.get("linux.lsmod"))

    listed: dict[int, dict[str, Any]] = {}
    for row in pslist or []:
        pid, tid = _int(_get(row, "PID")), _int(_get(row, "TID"))
        if pid is not None and (tid is None or tid == pid):
            listed[pid] = row
    args = {pid: str(_get(row, "ARGS") or "") for row in psaux or [] if (pid := _int(_get(row, "PID"))) is not None}
    parents = {pid: _int(_get(row, "PPID")) for pid, row in listed.items()}
    parents.update({pid: _int(_get(row, "PPID")) for row in psaux or [] if (pid := _int(_get(row, "PID"))) is not None and pid not in parents})

    def name_of(pid: int | None) -> str:
        if pid is None:
            return ""
        row = listed.get(pid)
        if row:
            return str(_get(row, "COMM") or "")
        return next((str(_get(r, "COMM") or "") for r in psaux or [] if _int(_get(r, "PID")) == pid), "")

    # Processes found by scanning memory but missing from the task list.
    if pslist is not None:
        seen: set[int] = set()
        for row in psscan or []:
            pid, tid = _int(_get(row, "PID")), _int(_get(row, "TID"))
            if pid is None or pid == 0 or pid in listed or pid in seen or (tid is not None and tid != pid):
                continue
            seen.add(pid)
            name = str(_get(row, "COMM") or "")
            state = str(_get(row, "EXIT_STATE") or "")
            parent = _int(_get(row, "PPID"))
            context = f"parent PID {parent}{f' ({name_of(parent)})' if name_of(parent) else ''}"
            offset = _hex(_get(row, "OFFSET (P)", "Offset(P)", "Offset"))
            if state in ("", "TASK_RUNNING", "0"):
                indicators.append(_indicator(pid, name, "PROC_NOLINK", f"Process structure found by scanning memory with no exit state, but not in the kernel's task list: hidden (unlinked) process, or a recently freed one. {context}.", address=offset))
            else:
                indicators.append(_indicator(pid, name, "PROC_TERMINATED", f"Exited ({state}); {context}.", address=offset))

    # Shells reading their commands from a socket: reverse or bind shells.
    if lsof is not None:
        socket_fds: dict[int, list[int]] = {}
        for row in lsof:
            pid, fd = _int(_get(row, "PID")), _int(_get(row, "FD"))
            if pid is None or fd not in (0, 1, 2):
                continue
            if str(_get(row, "Type") or "").upper() == "SOCK":
                socket_fds.setdefault(pid, []).append(fd)
        for pid, fds in sorted(socket_fds.items()):
            name = name_of(pid) or next((str(_get(r, "Process") or "") for r in lsof if _int(_get(r, "PID")) == pid), "")
            if name.lower() in _SHELLS:
                fds_text = ", ".join(str(fd) for fd in sorted(set(fds)))
                indicators.append(_indicator(pid, name, "SHELL_SOCKET", f"{name} has its standard input/output (FD {fds_text}) connected to a network socket: a reverse or bind shell."))

    for pid, row in listed.items():
        name = str(_get(row, "COMM") or "")
        parent_pid = parents.get(pid)
        parent_name = name_of(parent_pid)
        command = args.get(pid, "")
        # A user process whose command line imitates a kernel thread ("[kworker/0:1]").
        if command.startswith("[") and command.rstrip().endswith("]") and parent_pid not in (0, 2, None) and parent_name != "kthreadd":
            indicators.append(_indicator(pid, name, "PROC_KTHREAD_MASQ", f"Command line {command[:120]} looks like a kernel thread, but its parent is {parent_name or 'PID ' + str(parent_pid)}, not kthreadd."))
        if name.lower() in _SHELLS and parent_name.lower() in _NETWORK_SERVICES:
            indicators.append(_indicator(pid, name, "PROC_SPAWN", f"{name} started by the network service {parent_name} (PID {parent_pid}): typical of a web shell or an exploited service."))
        executable = _executable(command)
        if executable:
            for pattern, priority, where in _WRITABLE_LOCATIONS:
                if pattern.search(executable):
                    indicators.append(_indicator(pid, name, "PROC_LOCATION", f"Runs from {where}: {executable}", priority=priority))
                    break
        euid, parent_row = _int(_get(row, "EUID")), listed.get(parent_pid) if parent_pid is not None else None
        parent_uid = _int(_get(parent_row, "UID")) if parent_row else None
        if euid == 0 and parent_uid not in (None, 0) and name.lower() not in _PRIVILEGE_CHANGERS and parent_name.lower() not in _PRIVILEGE_CHANGERS:
            indicators.append(_indicator(pid, name, "PROC_ROOT", f"Runs as root, started by {parent_name or 'PID ' + str(parent_pid)}, which runs as uid {parent_uid}, and neither is a program meant to change user: possible privilege escalation."))

    for pid, command in args.items():
        hits = [(priority, label) for pattern, priority, label in _COMMAND_PATTERNS if pattern.search(command)]
        if not hits:
            continue
        order = {"high": 0, "medium": 1, "low": 2}
        hits.sort(key=lambda hit: order[hit[0]])
        labels = ", ".join(dict.fromkeys(label for _, label in hits))
        indicators.append(_indicator(pid, name_of(pid) or None, "CMDLINE", f"{labels}: {command[:900]}", priority=hits[0][0]))

    for plugin in ("linux.malware.hidden_modules", "linux.malware.check_modules"):
        for row in outputs.get(plugin) or []:
            name = str(_get(row, "Module Name", "Name") or "")
            address = _hex(_get(row, "Address", "Module Address", "Offset"))
            where = "found by scanning memory but missing from the kernel's module list" if plugin.endswith("hidden_modules") else "registered in sysfs but missing from the kernel's module list"
            indicators.append(_indicator(None, None, "MODULE_HIDDEN", f"Kernel module {name or '(no name)'} {where}: typical of a rootkit hiding itself.", address=address))

    check_syscall = outputs.get("linux.malware.check_syscall")
    matches_build = _symbols_match_build(check_syscall)
    if matches_build is False:
        notes.append("kernel hook checks skipped: most syscall handlers have no kernel symbol, so the symbols' addresses do not belong to this exact kernel build")
    elif matches_build:
        for row in check_syscall or []:
            if str(_get(row, "Handler Symbol") or "UNKNOWN") != "UNKNOWN":
                continue
            address = _int(_get(row, "Handler Address"))
            module = _module_at(address, modules)
            target = f"into kernel module {module}" if module else "outside the kernel's code"
            indicators.append(_indicator(None, None, "SYSCALL_HOOK", f"System call {_get(row, 'Index')} of the {_get(row, 'Table Name') or ''} table points {target} ({_hex(address)}).", address=_hex(address)))
        for kind, plugin in (("IDT_HOOK", "linux.malware.check_idt"), ("TTY_HOOK", "linux.malware.tty_check")):
            for row in outputs.get(plugin) or []:
                module = str(_get(row, "Module") or "")
                if module.lower() in ("kernel", "__kernel__"):
                    continue
                address = _hex(_get(row, "Address", "Handler Address", "Recv Address"))
                what = f"interrupt {_get(row, 'Index')}" if kind == "IDT_HOOK" else f"terminal {_get(row, 'Name') or ''} receive handler"
                symbol = _get(row, "Symbol")
                indicators.append(_indicator(None, None, kind, f"The {what} points into {module or 'unknown code'}{f' ({symbol})' if symbol and symbol != 'UNKNOWN' else ''} at {address}.", address=address))
        # check_afinfo only reports operations that point outside the kernel and its modules.
        for row in outputs.get("linux.malware.check_afinfo") or []:
            address = _hex(_get(row, "Handler Address"))
            indicators.append(_indicator(None, None, "AFINFO_HOOK", f"{_get(row, 'Symbol Name')}.{_get(row, 'Member')} points outside the kernel and its modules ({address}): hides network connections from /proc/net.", address=address))

    for row in outputs.get("linux.malware.malfind") or []:
        pid = _int(_get(row, "PID"))
        name = str(_get(row, "Process") or name_of(pid))
        start = _hex(_get(row, "Start"))
        hexdump = str(_get(row, "Hexdump") or "").strip().lower()
        protection = str(_get(row, "Protection") or "")
        if hexdump.startswith("7f 45 4c 46"):
            indicators.append(_indicator(pid, name, "ELF_INJECT", f"ELF header in {protection or 'executable'} anonymous memory at {start}: a program loaded without a file.", address=start))
        else:
            jit = name in _JIT_HOSTS
            indicators.append(_indicator(pid, name, "PRIVATE_RWX", f"{protection or 'Executable'} anonymous memory at {start}{' (expected in this process: JIT)' if jit else ''}.", address=start, priority="low" if jit else "medium"))
    return indicators, notes


def run_kairon_linux_findevil(
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
                work_dir / "kairon-linux-findevil",
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
        raise VolatilityRunnerError("PLUGIN_FAILED", "None of the Volatility plugins Kairon's Linux Find Evil checks need could run on this image (" + "; ".join(failures)[:250] + ").")
    indicators, notes = linux_findevil_indicators(outputs)
    skipped = failures + notes
    stderr = ("Checks skipped: " + "; ".join(skipped)).encode("utf-8") if skipped else b""
    return VolatilityRunResult(
        argv_display=["kairon-linux-findevil", *[plugin for plugin, rows in outputs.items() if rows is not None]],
        stdout=json.dumps(indicators).encode("utf-8"),
        stderr=stderr,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
