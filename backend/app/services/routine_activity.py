"""Routine system activity: process starts the operating system makes on its own.

Hiding them is an opt-in Search/Timeline filter, never a default. A process
start counts as routine only when all three facts are on the event and agree
with the platform's known-good baseline (the expected-image table DFIR
analysts use to spot masquerading -- "Hunt Evil"):

- the process name is a core system process,
- its image lives in the directory that process always runs from,
- its parent is the process that always starts it.

An event missing the path or the parent is never routine: it cannot be shown
to match. So a svchost.exe started from a user folder, or by cmd.exe, stays
visible -- that is exactly what an analyst looks for. Tools an attacker also
uses (wevtutil, schtasks, rundll32, powershell, cmd...) are never in the
table, whatever their parent; nor is conhost.exe, which any program can start
and which runs commands itself with --headless. Linux entries cover the systemd-managed daemons
that start at every boot. Memory process listings carry no parent name, so
nothing from a memory image is ever treated as routine.
"""

from __future__ import annotations

from typing import Any

_SYSTEM32 = ("*\\windows\\system32\\{name}",)
_SYSTEM32_AND_WOW64 = ("*\\windows\\system32\\{name}", "*\\windows\\syswow64\\{name}")
_DOTNET = ("*\\windows\\microsoft.net\\framework*\\{name}",)
_LINUX_SYSTEMD = ("/usr/lib/systemd/{name}", "/lib/systemd/{name}")

# name -> (image path patterns, expected parents)
ROUTINE_PROCESSES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    # Windows boot and session chain
    "smss.exe": (_SYSTEM32, ("system", "smss.exe")),
    "csrss.exe": (_SYSTEM32, ("smss.exe",)),
    "wininit.exe": (_SYSTEM32, ("smss.exe",)),
    "winlogon.exe": (_SYSTEM32, ("smss.exe",)),
    "services.exe": (_SYSTEM32, ("wininit.exe",)),
    "lsass.exe": (_SYSTEM32, ("wininit.exe",)),
    "lsaiso.exe": (_SYSTEM32, ("wininit.exe",)),
    "fontdrvhost.exe": (_SYSTEM32, ("wininit.exe", "winlogon.exe")),
    "dwm.exe": (_SYSTEM32, ("winlogon.exe",)),
    "logonui.exe": (_SYSTEM32, ("winlogon.exe",)),
    "userinit.exe": (_SYSTEM32, ("winlogon.exe",)),
    # Windows services and their hosts
    "svchost.exe": (_SYSTEM32_AND_WOW64, ("services.exe",)),
    "spoolsv.exe": (_SYSTEM32, ("services.exe",)),
    "sppsvc.exe": (_SYSTEM32, ("services.exe",)),
    "searchindexer.exe": (_SYSTEM32, ("services.exe",)),
    "trustedinstaller.exe": (("*\\windows\\servicing\\trustedinstaller.exe",), ("services.exe",)),
    "tiworker.exe": (("*\\windows\\winsxs\\*\\tiworker.exe",), ("svchost.exe",)),
    "taskhostw.exe": (_SYSTEM32, ("svchost.exe",)),
    "sihost.exe": (_SYSTEM32, ("svchost.exe",)),
    "runtimebroker.exe": (_SYSTEM32, ("svchost.exe",)),
    "dllhost.exe": (_SYSTEM32_AND_WOW64, ("svchost.exe", "services.exe")),
    "wmiprvse.exe": (("*\\windows\\system32\\wbem\\wmiprvse.exe", "*\\windows\\syswow64\\wbem\\wmiprvse.exe"), ("svchost.exe",)),
    "backgroundtaskhost.exe": (_SYSTEM32, ("svchost.exe",)),
    "smartscreen.exe": (_SYSTEM32, ("svchost.exe",)),
    "ctfmon.exe": (_SYSTEM32, ("svchost.exe",)),
    "audiodg.exe": (_SYSTEM32, ("svchost.exe",)),
    "mousocoreworker.exe": (_SYSTEM32, ("svchost.exe",)),
    "usocoreworker.exe": (_SYSTEM32, ("svchost.exe",)),
    "sppextcomobj.exe": (_SYSTEM32, ("svchost.exe",)),
    "searchprotocolhost.exe": (_SYSTEM32, ("searchindexer.exe",)),
    "searchfilterhost.exe": (_SYSTEM32, ("searchindexer.exe",)),
    # .NET native image generation after updates
    "ngentask.exe": (_DOTNET, ("svchost.exe", "taskhostw.exe")),
    "ngen.exe": (_DOTNET, ("ngentask.exe", "ngen.exe")),
    "mscorsvw.exe": (_DOTNET, ("ngen.exe", "ngentask.exe", "mscorsvw.exe")),
    # Linux daemons started by systemd
    "systemd-journald": (_LINUX_SYSTEMD, ("systemd",)),
    "systemd-logind": (_LINUX_SYSTEMD, ("systemd",)),
    "systemd-udevd": (_LINUX_SYSTEMD, ("systemd",)),
    "systemd-resolved": (_LINUX_SYSTEMD, ("systemd",)),
    "systemd-networkd": (_LINUX_SYSTEMD, ("systemd",)),
    "systemd-timesyncd": (_LINUX_SYSTEMD, ("systemd",)),
}

_PATH_FIELDS = ("process.executable", "process.path")
_PARENT_FIELDS = ("process.parent_name", "process.parent.name")


def _patterns(name: str, templates: tuple[str, ...]) -> list[str]:
    return [template.format(name=name) for template in templates]


def _wildcard_value(pattern: str) -> str:
    # Backslash escapes in an OpenSearch wildcard; a Windows path needs it doubled.
    return pattern.replace("\\", "\\\\")


def routine_process_clause() -> dict[str, Any]:
    """An OpenSearch clause matching routine process starts (for must_not)."""
    should = []
    for name, (paths, parents) in ROUTINE_PROCESSES.items():
        should.append({"bool": {"filter": [
            {"term": {"process.name": {"value": name, "case_insensitive": True}}},
            {"bool": {"should": [
                {"wildcard": {field: {"value": _wildcard_value(pattern), "case_insensitive": True}}}
                for pattern in _patterns(name, paths) for field in _PATH_FIELDS
            ], "minimum_should_match": 1}},
            {"bool": {"should": [
                {"term": {field: {"value": parent, "case_insensitive": True}}}
                for parent in parents for field in _PARENT_FIELDS
            ], "minimum_should_match": 1}},
        ]}})
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _matches(pattern: str, value: str) -> bool:
    from fnmatch import fnmatchcase

    return fnmatchcase(value.lower(), pattern.lower())


def is_routine_process(name: str | None, path: str | None, parent: str | None) -> bool:
    """The same rule in Python, for rows already loaded."""
    entry = ROUTINE_PROCESSES.get(str(name or "").strip().lower())
    if not entry or not path:
        return False
    paths, parents = entry
    if not any(_matches(pattern, str(path)) for pattern in _patterns(str(name).lower(), paths)):
        return False
    return str(parent or "").strip().lower() in parents
