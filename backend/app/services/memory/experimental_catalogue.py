"""Experimental analysis profile catalogue.

This module is the single source of truth for the experimental
mismatched-symbol profile catalogue.  The profiles are *explicitly
labelled* and never overlap with the validated catalogue: every
profile name is prefixed with ``experimental_`` to make the trust
domain obvious in storage and in the UI.

Design rules (v1):

* Profiles are intentionally small.  We never expose the full
  validated catalogue.
* The canary profile set is fixed (``experimental_canary``); the
  canary MUST run before any full experimental profile.
* The network and suspicious-memory profiles are gated on the
  canary outcome.  They are only enabled for ``canary_passed``.
* No profile mutates the exact symbol cache, the exact symbol
  requirement, or any validated ``MemoryScanRun``.
"""
from __future__ import annotations

from typing import Any


# Canary profile.  Runs a minimal bounded set of plugins whose
# output is structurally predictable.  The canary NEVER indexes
# results into the validated memory index; it only persists
# per-check results onto ``MemoryExperimentalRun.canary_checks``.
EXPERIMENTAL_CANARY_PROFILE = "experimental_canary"
EXPERIMENTAL_CANARY_PLUGINS: list[str] = [
    "windows.info",
]


# Full experimental profile catalogue (v1).  Each entry mirrors
# the validated catalogue shape but uses the experimental plugin
# list.  The catalogue is hard-coded and the analyst may only run
# profiles in this catalogue.
EXPERIMENTAL_PROFILES: list[dict[str, Any]] = [
    {
        "profile": "experimental_metadata",
        "family": "system_info",
        "title": "Experimental system metadata",
        "description": (
            "Reads the windows.info block (kernel base, OS family, "
            "architecture) using a mismatched symbol.  Result is "
            "labelled experimental and may be inconsistent."
        ),
        "cost_label": "Fast",
        "est_duration_seconds": 30,
        "requires_canary_pass": True,
        "plugins": ["windows.info"],
        "supported_os_families": ["windows"],
    },
    {
        "profile": "experimental_processes",
        "family": "processes",
        "title": "Experimental process listing",
        "description": (
            "Active processes (pslist/pstree/psscan) using a "
            "mismatched symbol.  Process names and offsets MAY be "
            "wrong.  Cross-checks the result against ``psscan``."
        ),
        "cost_label": "Medium",
        "est_duration_seconds": 180,
        "requires_canary_pass": True,
        "plugins": [
            "windows.info",
            "windows.pslist",
            "windows.pstree",
            "windows.psscan",
        ],
        "supported_os_families": ["windows"],
    },
    {
        "profile": "experimental_process_scan",
        "family": "processes",
        "title": "Experimental process scan",
        "description": (
            "Memory scan for terminated / unlinked processes using "
            "a mismatched symbol.  Use only for triage; the result "
            "MAY include false positives or miss entries."
        ),
        "cost_label": "Medium",
        "est_duration_seconds": 240,
        "requires_canary_pass": True,
        "plugins": [
            "windows.info",
            "windows.pslist",
            "windows.psscan",
        ],
        "supported_os_families": ["windows"],
    },
    {
        "profile": "experimental_command_lines",
        "family": "processes",
        "title": "Experimental command lines",
        "description": (
            "Process command lines using a mismatched symbol.  "
            "Off-by-one in the process argument offset MAY corrupt "
            "the first argument; review each entry."
        ),
        "cost_label": "Medium",
        "est_duration_seconds": 180,
        "requires_canary_pass": True,
        "plugins": [
            "windows.info",
            "windows.pslist",
            "windows.cmdline",
        ],
        "supported_os_families": ["windows"],
    },
    {
        "profile": "experimental_modules",
        "family": "modules",
        "title": "Experimental kernel modules",
        "description": (
            "Kernel modules and loaded drivers using a mismatched "
            "symbol.  Module names MAY be misaligned."
        ),
        "cost_label": "Medium",
        "est_duration_seconds": 180,
        "requires_canary_pass": True,
        "plugins": [
            "windows.info",
            "windows.modules",
            "windows.driverscan",
        ],
        "supported_os_families": ["windows"],
    },
    {
        "profile": "experimental_network",
        "family": "network",
        "title": "Experimental network connections",
        "description": (
            "Network endpoints using a mismatched symbol.  Only "
            "available when the canary passes AND the analyst "
            "explicitly requests it."
        ),
        "cost_label": "Medium",
        "est_duration_seconds": 120,
        "requires_canary_pass": True,
        "plugins": [
            "windows.info",
            "windows.netscan",
        ],
        "supported_os_families": ["windows"],
    },
    {
        "profile": "experimental_suspicious_memory",
        "family": "suspicious_regions",
        "title": "Experimental suspicious memory regions",
        "description": (
            "RX/RWX memory regions with no mapped file using a "
            "mismatched symbol.  Only available when the canary "
            "passes."
        ),
        "cost_label": "Slow",
        "est_duration_seconds": 1800,
        "requires_canary_pass": True,
        "plugins": [
            "windows.info",
            "windows.malfind",
        ],
        "supported_os_families": ["windows"],
    },
]


# Build a fast lookup table.
_EXPERIMENTAL_BY_PROFILE: dict[str, dict[str, Any]] = {
    item["profile"]: item for item in EXPERIMENTAL_PROFILES
}


def list_experimental_profiles() -> list[dict[str, Any]]:
    return list(EXPERIMENTAL_PROFILES)


def get_experimental_profile(name: str) -> dict[str, Any] | None:
    return _EXPERIMENTAL_BY_PROFILE.get(name)


def experimental_profile_names() -> set[str]:
    return set(_EXPERIMENTAL_BY_PROFILE.keys())


def allowed_profiles_for_canary_outcome(
    canary_status: str | None,
) -> list[str]:
    """Return the experimental profile names allowed for a given
    canary status.

    The policy mirrors the spec:

    * ``canary_passed``  -> all profiles
    * ``canary_degraded`` -> conservative subset (metadata / modules)
    * ``canary_failed`` / ``canary_inconclusive`` -> none
    * None / pending / running -> none (no full run may start)

    The function never raises.  An empty list is a valid answer.
    """
    if canary_status == "passed":
        return [item["profile"] for item in EXPERIMENTAL_PROFILES]
    if canary_status == "degraded":
        # Conservative subset for triage-only.
        return [
            "experimental_metadata",
            "experimental_modules",
        ]
    return []


__all__ = [
    "EXPERIMENTAL_CANARY_PLUGINS",
    "EXPERIMENTAL_CANARY_PROFILE",
    "EXPERIMENTAL_PROFILES",
    "allowed_profiles_for_canary_outcome",
    "experimental_profile_names",
    "get_experimental_profile",
    "list_experimental_profiles",
]
