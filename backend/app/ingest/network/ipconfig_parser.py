from __future__ import annotations

from pathlib import Path
import re


def parse_ipconfig_txt(path: Path) -> list[dict]:
    rows: list[dict] = []
    current: dict | None = None
    last_key: str | None = None
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.rstrip()
        header_match = re.match(r"^[A-Za-z0-9].*adapter\s+(.+):$", line.strip(), flags=re.IGNORECASE)
        if header_match:
            if current:
                rows.append(current)
            current = {"ArtifactType": "ipconfig_output", "InterfaceName": header_match.group(1).strip()}
            last_key = None
            continue
        if not current or ":" not in line:
            continue
        key, value = [part.strip(" .") for part in line.split(":", 1)]
        key_lower = key.lower()
        clean_value = value.strip()
        if not clean_value and key_lower not in {"dns servers"}:
            last_key = key_lower
            continue
        if last_key == "dns servers" and raw_line.startswith(" " * 10):
            current["DNSServers"] = f"{current.get('DNSServers', '')}|{clean_value}".strip("|")
            continue
        if key_lower == "description":
            current["InterfaceDescription"] = clean_value
        elif key_lower == "physical address":
            current["MACAddress"] = clean_value
        elif key_lower == "dhcp enabled":
            current["DHCPEnabled"] = clean_value
        elif key_lower.startswith("ipv4 address"):
            current["IPv4Address"] = clean_value.split("(")[0].strip()
        elif key_lower.startswith("ipv6 address"):
            current["IPv6Address"] = clean_value
        elif key_lower == "subnet mask":
            current["SubnetMask"] = clean_value
        elif key_lower == "default gateway":
            current["DefaultGateway"] = clean_value
        elif key_lower == "dhcp server":
            current["DHCPServer"] = clean_value
        elif key_lower == "dns servers":
            current["DNSServers"] = clean_value
        elif key_lower == "connection-specific dns suffix":
            current["DomainSuffix"] = clean_value
        last_key = key_lower
    if current:
        rows.append(current)
    return rows


def parse_netsh_wlan_txt(path: Path) -> list[dict]:
    rows: list[dict] = []
    current: dict | None = None
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        profile_match = re.search(r"(?:All User Profile|Perfil de todos los usuarios)\s*:\s*(.+)$", stripped, flags=re.IGNORECASE)
        if profile_match:
            if current:
                rows.append(current)
            profile = profile_match.group(1).strip()
            current = {"ArtifactType": "netsh_wlan_output", "ProfileName": profile, "SSID": profile}
            continue
        if current and ":" in stripped:
            key, value = [part.strip() for part in stripped.split(":", 1)]
            key_lower = key.lower()
            if "authentication" in key_lower or "autenticación" in key_lower:
                current["Authentication"] = value
            elif "cipher" in key_lower or "cifrado" in key_lower:
                current["Encryption"] = value
            elif "ssid name" in key_lower:
                current["SSID"] = value.strip('"')
            elif "key content" in key_lower:
                current["KeyMaterial"] = "[REDACTED]"
                current["KeyMaterialPresent"] = True
    if current:
        rows.append(current)
    return rows


def parse_netstat_txt(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped.startswith(("TCP", "UDP")):
            continue
        parts = re.split(r"\s+", stripped)
        if len(parts) < 4:
            continue
        protocol = parts[0]
        local = parts[1]
        remote = parts[2]
        state = parts[3] if protocol == "TCP" and len(parts) >= 4 else None
        pid = parts[4] if protocol == "TCP" and len(parts) >= 5 else parts[3] if protocol == "UDP" and len(parts) >= 4 else None
        local_ip, _, local_port = local.rpartition(":")
        remote_ip, _, remote_port = remote.rpartition(":")
        rows.append(
            {
                "ArtifactType": "netstat_output",
                "Protocol": protocol,
                "LocalAddress": local_ip or local,
                "LocalPort": local_port or None,
                "RemoteAddress": remote_ip or remote,
                "RemotePort": remote_port or None,
                "State": state,
                "PID": pid,
            }
        )
    return rows


def parse_arp_txt(path: Path) -> list[dict]:
    rows: list[dict] = []
    current_interface = None
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        interface_match = re.search(r"Interface:\s+(\S+)", line, flags=re.IGNORECASE)
        if interface_match:
            current_interface = interface_match.group(1)
            continue
        stripped = line.strip()
        if not stripped or stripped.lower().startswith(("internet address", "dirección internet")):
            continue
        parts = re.split(r"\s+", stripped)
        if len(parts) >= 3 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
            rows.append(
                {
                    "ArtifactType": "arp_output",
                    "Interface": current_interface,
                    "IPAddress": parts[0],
                    "MACAddress": parts[1],
                    "Type": parts[2],
                }
            )
    return rows
