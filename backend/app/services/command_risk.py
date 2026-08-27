"""Risk scoring for a single command line.

Lives in its own module because both the disk-derived command history and the
memory-derived one need it, and command_history already imports
investigation_memory -- scoring from there would close an import cycle.

Commands recovered from RAM used to be handed out with risk_score 0 and no
reasons at all, which meant every risk filter in the product treated them as
uninteresting by construction: on a case with memory dumps the analyst could
not reach them through "only suspicious", a risk floor, or any ranking. They
are scored by exactly the same rules as commands recovered from disk.
"""

from __future__ import annotations

from typing import Any


# Each entry is (tokens, points, reason). Points accumulate, so a command
# needs two independent signals to pass the "suspicious" threshold of 50.
# Every token must describe attacker tradecraft: literals borrowed from a
# particular investigation or demo fixture only ever match that one case and
# mislabel everyone else's.
COMMAND_RISK_CHECKS: list[tuple[tuple[str, ...], int, str]] = [
    (("-enc", "-encodedcommand", "frombase64string"), 35, "encoded command or base64 decoding"),
    (("-ep bypass", "executionpolicy bypass", "-executionpolicy bypass"), 30, "PowerShell execution policy bypass"),
    (("-w hidden", "windowstyle hidden", "-windowstyle hidden"), 20, "hidden window execution"),
    (("invoke-webrequest", "webclient", "downloadstring", "curl ", "certutil", "bitsadmin"), 25, "download cradle or file transfer utility"),
    (("rundll32", "regsvr32", "mshta", "wscript", "cscript"), 25, "suspicious LOLBin execution"),
    (("psexec", "psexesvc"), 30, "PsExec activity"),
    (("\\temp\\", "\\downloads\\", "\\appdata\\"), 15, "execution path in user-writable location"),
    (("whoami",), 10, "reconnaissance command"),
]

_SUSPICIOUS_PARENTS = ("winword", "excel", "chrome", "firefox", "msedge", "explorer")
_SUSPICIOUS_CHILDREN = ("powershell", "cmd.exe")


def score_command(command: str, process: dict[str, Any], parent: dict[str, Any]) -> tuple[int, list[str]]:
    lower = str(command or "").lower()
    reasons: list[str] = []
    score = 0
    for tokens, points, reason in COMMAND_RISK_CHECKS:
        if any(token in lower for token in tokens):
            score += points
            reasons.append(reason)
    parent_name = str(parent.get("name") or process.get("parent_name") or "").lower()
    proc_name = str(process.get("name") or "").lower()
    if any(item in parent_name for item in _SUSPICIOUS_PARENTS) and any(
        item in proc_name or item in lower for item in _SUSPICIOUS_CHILDREN
    ):
        score += 20
        reasons.append("suspicious parent-child relationship")
    return min(score, 100), sorted(set(reasons))
