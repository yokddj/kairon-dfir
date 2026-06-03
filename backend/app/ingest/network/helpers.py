from __future__ import annotations

import csv
import ipaddress
import re
from pathlib import Path, PureWindowsPath
from urllib.parse import urlparse


NETWORK_NAME_HINTS = (
    "wlan",
    "wifi",
    "dnscache",
    "dnscache",
    "dns",
    "ipconfig",
    "netsh",
    "netadapter",
    "netipconfiguration",
    "networkinterfaces",
    "netroute",
    "route",
    "netstat",
    "arp",
    "hosts",
    "networklist",
    "tcpip",
)
NETWORK_HEADER_HINTS = {
    "ssid",
    "bssid",
    "authentication",
    "encryption",
    "recordtype",
    "ttl",
    "nameserver",
    "dhcpnameserver",
    "defaultgateway",
    "ipv4address",
    "ipv6address",
    "dhcpenabled",
    "remoteaddress",
    "localaddress",
    "state",
    "hostname",
    "interfacealias",
    "interfacedescription",
}
SUSPICIOUS_HOSTS_DOMAINS = (
    "microsoft.com",
    "windowsupdate.com",
    "security.microsoft.com",
    "defender",
    "google.com",
    "gmail.com",
    "drive.google.com",
    "dropbox.com",
    "onedrive.live.com",
)
SUSPICIOUS_PROCESS_NAMES = {"powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "mshta.exe"}
DNS_SCRIPTING_PROCESSES = {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"}
DNS_LOLBINS = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe"}
PUBLIC_DNS_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112"}
DIRECT_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
URL_RE = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
DYNAMIC_DNS_HINTS = ("duckdns.org", "no-ip", "ddns", "dyn", "hopto.org", "servehttp.com")
SUSPICIOUS_DNS_KEYWORDS = ("payload", "invoice", "update", "installer", "crack", "keygen", "pastebin", "raw", "ngrok", "duckdns", "no-ip", "ddns", "dyn")


def canonicalize_header(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def clean_value(value: object | None) -> str | None:
    if value in (None, ""):
        return None
    cleaned = str(value).strip().strip('"').strip("'")
    if cleaned.lower() in {"-", "--", "n/a", "na", "(null)", "null", "none", "unknown"}:
        return None
    return cleaned


def normalize_windows_path(value: str | None) -> str | None:
    cleaned = clean_value(value)
    if not cleaned:
        return None
    return cleaned.replace("/", "\\")


def basename_windows(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    try:
        return PureWindowsPath(normalized).name or normalized
    except Exception:  # noqa: BLE001
        return Path(normalized.replace("\\", "/")).name or normalized


def suffix_windows(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    try:
        suffix = PureWindowsPath(normalized).suffix.lower()
        return suffix or None
    except Exception:  # noqa: BLE001
        suffix = Path(normalized.replace("\\", "/")).suffix.lower()
        return suffix or None


def first_nonempty(row: dict, *names: str) -> str | None:
    lowered = {str(key).lower(): value for key, value in row.items()}
    canon = {canonicalize_header(key): value for key, value in row.items()}
    for name in names:
        for candidate in (name, name.lower(), canonicalize_header(name)):
            value = lowered.get(candidate) if candidate in lowered else canon.get(candidate)
            if value not in (None, ""):
                return str(value)
    return None


def parse_boolish(value: object | None) -> bool | None:
    cleaned = clean_value(value)
    if not cleaned:
        return None
    lowered = cleaned.lower()
    if lowered in {"true", "yes", "1", "enabled", "present"}:
        return True
    if lowered in {"false", "no", "0", "disabled", "absent"}:
        return False
    return None


def parse_csv_headers(path: Path) -> set[str]:
    try:
        with path.open("r", encoding="utf-8-sig", errors="ignore") as handle:
            headers = next(csv.reader(handle), [])
    except Exception:  # noqa: BLE001
        return set()
    return {canonicalize_header(header) for header in headers if header}


def looks_like_network_artifact(path: Path, headers: list[str] | None = None) -> bool:
    suffix = path.suffix.lower()
    lower_name = path.name.lower()
    if lower_name == "hosts":
        return True
    if suffix in {".xml", ".csv", ".json", ".txt"} and any(token in lower_name for token in NETWORK_NAME_HINTS):
        return True
    if suffix == ".xml" and "wlansvc" in str(path).lower():
        return True
    header_set = {canonicalize_header(header) for header in (headers or []) if header}
    return len(header_set & NETWORK_HEADER_HINTS) >= 2


def parse_domain(value: str | None) -> str | None:
    cleaned = clean_value(value)
    if not cleaned:
        return None
    if "://" in cleaned:
        host = urlparse(cleaned).hostname
        return host.rstrip(".").lower() if host else None
    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0]
    return cleaned.rstrip(".").lower()


def is_ip_literal(value: str | None) -> bool:
    cleaned = clean_value(value)
    if not cleaned:
        return False
    try:
        ipaddress.ip_address(cleaned)
        return True
    except Exception:  # noqa: BLE001
        return False


def normalize_dns_record_type(value: str | None) -> str:
    cleaned = str(clean_value(value) or "").upper()
    aliases = {"1": "A", "28": "AAAA", "5": "CNAME", "12": "PTR", "33": "SRV", "16": "TXT"}
    normalized = aliases.get(cleaned, cleaned)
    return normalized if normalized in {"A", "AAAA", "CNAME", "PTR", "SRV", "TXT"} else "UNKNOWN"


def normalize_dns_status(value: str | None) -> str:
    cleaned = str(clean_value(value) or "").lower()
    if not cleaned:
        return "unknown"
    if cleaned in {"success", "ok", "resolved"}:
        return "success"
    if cleaned in {"cache", "cached"}:
        return "cached"
    if "nxdomain" in cleaned or "name does not exist" in cleaned:
        return "nxdomain"
    if "timeout" in cleaned or "timed out" in cleaned:
        return "timeout"
    if "refused" in cleaned:
        return "refused"
    if "fail" in cleaned or "error" in cleaned:
        return "failed"
    return "unknown"


def looks_like_dga_domain(domain: str | None) -> bool:
    cleaned = parse_domain(domain)
    if not cleaned:
        return False
    label = cleaned.split(".", 1)[0]
    if len(cleaned) >= 35:
        return True
    if len(label) < 16:
        return False
    digits = sum(1 for char in label if char.isdigit())
    return digits >= 4 and len(set(label)) >= 10


def extract_urls(*values: object) -> list[str]:
    urls: list[str] = []
    for value in values:
        if value in (None, ""):
            continue
        for match in URL_RE.findall(str(value)):
            if match not in urls:
                urls.append(match)
    return urls


def classify_hosts_entry(ip: str | None, hostname: str | None) -> tuple[set[str], list[str], int]:
    tags = {"network", "dns", "hosts_file"}
    reasons: list[str] = []
    risk = 0
    host = str(hostname or "").lower()
    ip_norm = str(ip or "").strip()
    if host in {"localhost", "localhost.localdomain"} and ip_norm in {"127.0.0.1", "::1"}:
        return tags, reasons, risk
    if ip_norm in {"127.0.0.1", "0.0.0.0"} and any(token in host for token in SUSPICIOUS_HOSTS_DOMAINS):
        tags.update({"dns_override", "suspicious_hosts_entry"})
        reasons.append("Hosts file redirects security/vendor domain")
        risk = 85
    elif ip_norm not in {"127.0.0.1", "::1"} and host:
        tags.add("dns_override")
        reasons.append("Hosts file contains suspicious DNS override")
        risk = 42
    return tags, reasons, risk


def classify_dns_servers(servers: list[str], gateway: str | None = None) -> tuple[set[str], list[str], int]:
    tags = {"network", "dns_config"}
    reasons: list[str] = []
    risk = 0
    normalized = [str(server).strip() for server in servers if clean_value(server)]
    gateway_prefix = ".".join(str(gateway or "").split(".")[:3]) if gateway and "." in gateway else None
    suspicious = False
    for server in normalized:
        if server in PUBLIC_DNS_IPS:
            continue
        if gateway_prefix and server.startswith(f"{gateway_prefix}."):
            continue
        if DIRECT_IP_RE.match(server):
            suspicious = True
    if suspicious:
        tags.add("suspicious_dns_server")
        reasons.append("DNS server configuration may be unusual")
        risk = 35
    return tags, reasons, risk


def classify_wlan_profile(authentication: str | None, encryption: str | None, ssid: str | None) -> tuple[set[str], list[str], int]:
    tags = {"network", "wlan", "wifi", "wlan_profile"}
    reasons: list[str] = []
    risk = 0
    auth = str(authentication or "").strip().lower()
    enc = str(encryption or "").strip().lower()
    if auth == "open" or enc in {"none", "open"}:
        tags.add("open_wifi")
        reasons.append("WLAN open network profile")
        risk = max(risk, 35)
    if enc == "wep" or auth == "shared":
        tags.add("weak_encryption")
        reasons.append("WLAN weak encryption")
        risk = max(risk, 45)
    ssid_lower = str(ssid or "").lower()
    if any(token in ssid_lower for token in {"pineapple", "evil", "rogue", "free wifi", "free public wifi", "airport free", "guest", "public", "test"}):
        tags.add("suspicious_network_activity")
        reasons.append("WLAN suspicious SSID")
        risk = max(risk, 25)
        if any(token in ssid_lower for token in {"guest", "public", "free wifi", "airport free"}):
            reasons.append("WLAN connected to public/guest network")
            risk = max(risk, 30)
    return tags, reasons, risk


def classify_netstat_entry(process_name: str | None, destination_ip: str | None, destination_port: str | None) -> tuple[set[str], list[str], int]:
    tags = {"network", "netstat"}
    reasons: list[str] = []
    risk = 0
    if destination_ip and DIRECT_IP_RE.match(str(destination_ip)):
        tags.add("direct_ip_connection")
        risk = max(risk, 20)
        if str(process_name or "").lower() in SUSPICIOUS_PROCESS_NAMES:
            tags.add("suspicious_network_activity")
            reasons.append("Connection to direct public IP by suspicious process")
            risk = 72
    if destination_port and str(destination_port) not in {"80", "443", "53", "3389"} and risk:
        risk = max(risk, 76)
    return tags, reasons, risk


def classify_dns_query(domain: str | None, record_type: str | None, status: str | None, process_name: str | None) -> tuple[set[str], list[str], int]:
    tags = {"network", "dns"}
    reasons: list[str] = []
    risk = 0
    normalized_domain = parse_domain(domain)
    normalized_status = normalize_dns_status(status)
    normalized_record_type = normalize_dns_record_type(record_type)
    process_lower = str(process_name or "").strip().lower()

    if is_ip_literal(normalized_domain):
        reasons.append("DNS query name is IP literal")
        risk = max(risk, 35)
    if normalized_domain and normalized_domain.startswith("xn--"):
        reasons.append("DNS query has punycode domain")
        risk = max(risk, 45)
    if normalized_domain and len(normalized_domain) >= 35:
        reasons.append("DNS query has unusually long domain")
        risk = max(risk, 40)
    if looks_like_dga_domain(normalized_domain):
        reasons.append("DNS query has DGA-like domain")
        risk = max(risk, 60)
    if normalized_domain and any(keyword in normalized_domain for keyword in SUSPICIOUS_DNS_KEYWORDS):
        reasons.append("DNS query for suspicious domain")
        risk = max(risk, 50)
    if normalized_domain and any(hint in normalized_domain for hint in DYNAMIC_DNS_HINTS):
        reasons.append("DNS query to dynamic DNS provider")
        risk = max(risk, 55)
    if normalized_status == "nxdomain" and reasons:
        reasons.append("DNS NXDOMAIN for suspicious domain")
        risk = max(risk, 55)
    elif normalized_status in {"failed", "timeout", "refused"} and reasons:
        reasons.append("DNS query failed for suspicious domain")
        risk = max(risk, 45)
    if process_lower in DNS_SCRIPTING_PROCESSES:
        reasons.append("DNS query by scripting process")
        risk = max(risk, 55)
    elif process_lower in DNS_LOLBINS:
        reasons.append("DNS query by LOLBin")
        risk = max(risk, 55)
    if normalized_record_type == "UNKNOWN":
        tags.add("dns_unknown_record_type")
    return tags, reasons, risk
