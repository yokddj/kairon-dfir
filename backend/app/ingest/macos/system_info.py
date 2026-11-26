"""Host identity from macOS's own files: SystemVersion.plist (product name, version, build)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from app.ingest.macos.common import load_plist

ARTIFACT_FAMILY = "macos_system_info"


def _fact(source_path: str, fact_type: str, raw: str, value: str) -> dict[str, Any]:
    return {
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_type": "system_version",
        "source_file": source_path,
        "fact_type": fact_type,
        "raw_value": raw,
        "normalized_value": value,
        "confidence": "high",
        "parse_status": "valid",
        "reason": "",
        "event_action": "host_identity_detected",
        "message": f"{fact_type}: {value}",
    }


def parse_system_version(path: Path, *, source_path: str) -> list[dict[str, Any]]:
    plist = load_plist(path)
    if not isinstance(plist, dict):
        return []
    name = str(plist.get("ProductName") or "").strip()
    version = str(plist.get("ProductUserVisibleVersion") or plist.get("ProductVersion") or "").strip()
    build = str(plist.get("ProductBuildVersion") or "").strip()
    raw = "; ".join(f"{key}: {plist[key]}" for key in ("ProductName", "ProductVersion", "ProductBuildVersion") if plist.get(key))
    rows = []
    if name:
        rows.append(_fact(source_path, "host.distribution", raw, name))
    if version:
        rows.append(_fact(source_path, "host.distribution_version", raw, f"{version} ({build})" if build else version))
    return rows
