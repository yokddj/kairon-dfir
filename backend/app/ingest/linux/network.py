"""Network config parser: /etc/hosts, /etc/resolv.conf, /etc/network/interfaces, netplan."""
from __future__ import annotations
import re
from pathlib import Path

_COMMENT_RE = re.compile(r"^\s*#")
_EMPTY_RE = re.compile(r"^\s*$")
_HOSTS_RE = re.compile(r"^\s*(\S+)\s+(.+)$")
_RESOLV_RE = re.compile(r"^\s*(nameserver|domain|search|options)\s+(.+)$", re.IGNORECASE)
_INTERFACES_IFACE_RE = re.compile(r"^\s*iface\s+(\S+)\s+(\S+)\s+(\S+)", re.IGNORECASE)
_INTERFACES_AUTO_RE = re.compile(r"^\s*auto\s+(.+)$", re.IGNORECASE)
_INTERFACES_KV_RE = re.compile(r"^\s+(\S+)\s+(.+)$")


def _detect_config_type(source_path: str) -> str:
    lower = str(source_path).replace("\\", "/").lower()
    if "hosts" in lower and "known_hosts" not in lower:
        return "etc_hosts"
    if "resolv.conf" in lower:
        return "resolv_conf"
    if "netplan" in lower:
        return "netplan"
    if "interfaces" in lower:
        return "interfaces"
    return "network_config"


def _parse_hosts(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or _COMMENT_RE.match(stripped):
            continue
        raw_excerpt = stripped[:2000]
        match = _HOSTS_RE.match(stripped)
        if match:
            ip = match.group(1)
            rest = match.group(2).strip()
            if "#" in rest:
                rest = rest.split("#", 1)[0].strip()
            parts = rest.split()
            canonical = parts[0] if parts else ""
            aliases = parts[1:] if len(parts) > 1 else []
            results.append({
                "artifact_family": "linux_network",
                "artifact_type": "etc_hosts",
                "source_file": source_path,
                "line_number": line_number,
                "config_type": "etc_hosts",
                "interface": None,
                "address": ip,
                "gateway": None,
                "dns": None,
                "hostname": canonical,
                "aliases": aliases,
                "value": rest,
                "message": f"{ip} {rest}",
                "raw_excerpt": raw_excerpt,
            })
    return results


def _parse_resolv(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    results: list[dict] = []
    nameservers: list[str] = []
    search_domains: list[str] = []
    domain = None
    other_options: list[str] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or _COMMENT_RE.match(stripped):
            continue
        raw_excerpt = stripped[:2000]
        match = _RESOLV_RE.match(stripped)
        if match:
            directive = match.group(1).lower()
            value = match.group(2).strip()
            if directive == "nameserver":
                nameservers.append(value)
            elif directive == "search":
                search_domains.extend(v.strip() for v in value.split() if v.strip())
            elif directive == "domain":
                domain = value
            else:
                other_options.append(f"{directive} {value}")
    message_parts = []
    if domain:
        message_parts.append(f"domain={domain}")
    if nameservers:
        message_parts.append(f"nameservers={', '.join(nameservers)}")
    if search_domains:
        message_parts.append(f"search={', '.join(search_domains)}")
    raw_excerpt = content.strip()[:2000]
    results.append({
        "artifact_family": "linux_network",
        "artifact_type": "resolv_conf",
        "source_file": source_path,
        "line_number": 1,
        "config_type": "resolv_conf",
        "interface": None,
        "address": None,
        "gateway": None,
        "dns": nameservers,
        "hostname": domain,
        "search_domains": search_domains,
        "value": "; ".join(message_parts) if message_parts else content.strip()[:2000],
        "message": "; ".join(message_parts) if message_parts else content.strip()[:2000],
        "raw_excerpt": raw_excerpt,
    })
    return results


def _parse_interfaces(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    results: list[dict] = []
    current_iface: str | None = None
    current_type: str | None = None
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or _COMMENT_RE.match(stripped):
            continue
        raw_excerpt = stripped[:2000]
        iface_match = _INTERFACES_IFACE_RE.match(stripped)
        if iface_match:
            current_iface = iface_match.group(1)
            current_type = iface_match.group(3)
            results.append({
                "artifact_family": "linux_network",
                "artifact_type": "interfaces",
                "source_file": source_path,
                "line_number": line_number,
                "config_type": "interfaces",
                "interface": current_iface,
                "address": None,
                "gateway": None,
                "dns": None,
                "hostname": None,
                "iface_type": current_type,
                "value": stripped,
                "message": f"Interface: {current_iface} ({current_type})",
                "raw_excerpt": raw_excerpt,
            })
            continue
        auto_match = _INTERFACES_AUTO_RE.match(stripped)
        if auto_match:
            auto_ifaces = auto_match.group(1).strip()
            results.append({
                "artifact_family": "linux_network",
                "artifact_type": "interfaces",
                "source_file": source_path,
                "line_number": line_number,
                "config_type": "interfaces",
                "interface": auto_ifaces.split()[0] if auto_ifaces else None,
                "address": None,
                "gateway": None,
                "dns": None,
                "hostname": None,
                "iface_type": "auto",
                "value": stripped,
                "message": f"Auto: {auto_ifaces}",
                "raw_excerpt": raw_excerpt,
            })
            continue
        if stripped.startswith("iface"):
            continue
        if stripped.startswith("source") or stripped.startswith("source-directory"):
            continue
        kv_match = _INTERFACES_KV_RE.match(stripped)
        if not kv_match:
            results.append({
                "artifact_family": "linux_network",
                "artifact_type": "interfaces",
                "source_file": source_path,
                "line_number": line_number,
                "config_type": "interfaces",
                "interface": current_iface,
                "address": None,
                "gateway": None,
                "dns": None,
                "hostname": None,
                "value": stripped,
                "message": stripped[:2000],
                "raw_excerpt": raw_excerpt,
            })
    return results


def _parse_netplan(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    results: list[dict] = []
    current_interface: str | None = None
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        raw_excerpt = stripped[:2000]
        kv_match = re.match(r"^\s*(\S[^:]*?)\s*:\s*(.*)$", stripped)
        if not kv_match:
            continue
        key = kv_match.group(1).strip().rstrip(":")
        value = kv_match.group(2).strip()
        if re.match(r"^[a-zA-Z]", key) and not value and key not in ("ethernets", "wifis", "bonds", "bridges", "version", "network", "renderer"):
            current_interface = key
        if current_interface:
            message = f"{current_interface}: {key} = {value}" if value else f"{current_interface}: {key}"
        else:
            message = f"{key} = {value}" if value else key
        results.append({
            "artifact_family": "linux_network",
            "artifact_type": "netplan",
            "source_file": source_path,
            "line_number": line_number,
            "config_type": "netplan",
            "interface": current_interface,
            "address": value if "address" in key.lower() else None,
            "gateway": value if "gateway" in key.lower() else None,
            "dns": [value] if "nameserver" in key.lower() else None,
            "hostname": None,
            "key": key,
            "value": value,
            "message": message[:2000],
            "raw_excerpt": raw_excerpt,
        })
    if not results:
        return [{
            "artifact_family": "linux_network",
            "artifact_type": "netplan",
            "source_file": source_path,
            "line_number": 1,
            "config_type": "netplan",
            "interface": None,
            "address": None,
            "gateway": None,
            "dns": None,
            "hostname": None,
            "message": "Netplan configuration file (text parsing)",
            "raw_excerpt": content.strip()[:2000],
        }]
    return results


def parse_network(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    config_type = _detect_config_type(source_path)
    if config_type == "etc_hosts":
        return _parse_hosts(content, source_path=source_path, username=username)
    if config_type == "resolv_conf":
        return _parse_resolv(content, source_path=source_path, username=username)
    if config_type == "netplan":
        return _parse_netplan(content, source_path=source_path, username=username)
    if config_type == "interfaces":
        return _parse_interfaces(content, source_path=source_path, username=username)
    return [{
        "artifact_family": "linux_network",
        "artifact_type": "network_config",
        "source_file": source_path,
        "line_number": 1,
        "config_type": "network_config",
        "interface": None,
        "address": None,
        "gateway": None,
        "dns": None,
        "hostname": None,
        "message": content.strip()[:2000],
        "raw_excerpt": content.strip()[:2000],
    }]
