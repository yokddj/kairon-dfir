"""Linux OS release detection helpers."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LinuxReleaseDetection:
    distribution: str | None
    version: str | None
    confidence: str
    reasons: list[str]
    values: dict[str, str]


def parse_key_value_release(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip().upper()] = value.strip().strip('"').strip("'")
    return values


def detect_linux_release(markers: dict[str, str]) -> LinuxReleaseDetection:
    """Resolve Linux distribution with explicit source priority."""
    reasons: list[str] = []
    values: dict[str, str] = {}

    for path in ("/etc/os-release", "/usr/lib/os-release"):
        content = markers.get(path) or ""
        if not content.strip():
            continue
        values = parse_key_value_release(content)
        distro_id = (values.get("ID") or "").strip().lower()
        id_like = [item.strip().lower() for item in (values.get("ID_LIKE") or "").split()]
        name = values.get("NAME") or values.get("PRETTY_NAME") or values.get("ID")
        pretty = values.get("PRETTY_NAME") or name
        version = values.get("VERSION_ID") or values.get("VERSION") or pretty
        reasons.append(f"{path}:ID={distro_id or 'unknown'}")
        if id_like:
            reasons.append(f"{path}:ID_LIKE={' '.join(id_like)}")
        if distro_id == "ubuntu":
            return LinuxReleaseDetection(pretty or "Ubuntu", version, "high", reasons, values)
        if distro_id == "debian":
            return LinuxReleaseDetection(pretty or "Debian", version, "high", reasons, values)
        if name:
            return LinuxReleaseDetection(name, version, "high", reasons, values)

    lsb_values = parse_key_value_release(markers.get("/etc/lsb-release") or "")
    if lsb_values:
        distro_id = (lsb_values.get("DISTRIB_ID") or "").strip()
        description = lsb_values.get("DISTRIB_DESCRIPTION") or distro_id
        version = lsb_values.get("DISTRIB_RELEASE") or description
        reasons.append(f"/etc/lsb-release:DISTRIB_ID={distro_id or 'unknown'}")
        if distro_id.lower() == "ubuntu":
            return LinuxReleaseDetection(description or "Ubuntu", version, "high", reasons, lsb_values)
        return LinuxReleaseDetection(description or distro_id or None, version, "medium", reasons, lsb_values)

    for path, distro in (("/etc/redhat-release", None), ("/etc/centos-release", "CentOS"), ("/etc/fedora-release", "Fedora"), ("/etc/arch-release", "Arch Linux")):
        content = (markers.get(path) or "").strip()
        if content:
            reasons.append(path)
            return LinuxReleaseDetection(distro or content, content, "medium", reasons, {})

    issue = (markers.get("/etc/issue") or "").strip().splitlines()
    if issue and issue[0].strip():
        first = issue[0].replace("\\n", "").replace("\\l", "").strip()
        reasons.append("/etc/issue")
        if "ubuntu" in first.lower():
            return LinuxReleaseDetection("Ubuntu", first, "medium", reasons, {})
        return LinuxReleaseDetection(first, first, "low", reasons, {})

    debian_version = (markers.get("/etc/debian_version") or "").strip()
    if debian_version:
        reasons.append("/etc/debian_version")
        return LinuxReleaseDetection("Debian", debian_version.splitlines()[0], "low", reasons, {})

    return LinuxReleaseDetection(None, None, "medium", reasons, {})
