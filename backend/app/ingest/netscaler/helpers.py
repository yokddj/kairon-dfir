"""Citrix NetScaler/ADC artifact detection helpers.

NetScaler (FreeBSD-based appliance) keeps its running and historical
configuration under /nsconfig on the appliance's own root filesystem --
there is no separate "config partition" the way the boot/firmware blobs
(ns-*.gz) might suggest; ns.conf itself (plus its dated/versioned backups)
is where the account, certificate, and feature configuration actually
lives, and is the highest-value artifact on a NetScaler disk image.
"""
from __future__ import annotations

import re
from pathlib import Path

# Each rotated backup is named either a small integer suffix (ns.conf.0..N),
# ".bak", or the NetScaler build that wrote it (ns.conf.NS14.1-73.37) -- all
# three naming schemes are seen in the wild across upgrade history.
_NS_CONF_RE = re.compile(r"(^|/)(ns|unified|deprecated_ns)\.conf(\.(bak|\d+|ns[\d.\-]+))?$", re.IGNORECASE)

# Compromise-indicator paths from CVE-2026-88771/88772 (Citrix NetScaler
# ADC/Gateway unauthenticated RCE + DTLS memory overflow, Unit42, published
# 2026-09-30: https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/).
# LogonPoint/custom/ is a legitimate branding-customization directory
# (logos, CSS) -- any dotfile or script dropped there is the attacker
# abusing that it's web-served and request-accessible, not a file type
# that belongs there under normal operation.
_WEBSHELL_DIR_RE = re.compile(r"(^|/)var/netscaler/logon/logonpoint/custom/", re.IGNORECASE)
_HTTPD_CONF_RE = re.compile(r"(^|/)etc/httpd\.conf$", re.IGNORECASE)
_NS_LOG_RE = re.compile(r"(^|/)var/log/ns\.log(\.\d+)?(\.gz)?$", re.IGNORECASE)
_HTTPACCESS_VPN_LOG_RE = re.compile(r"(^|/)var/log/httpaccess-vpn\.log(\.\d+)?(\.gz)?$", re.IGNORECASE)
# /vpn/scripts/linux/ legitimately ships stock NetScaler Gateway Plug-in
# installers (nsgclient*.deb, nsgsetup*.deb, ...) -- every .deb there is
# materialized so app.ingest.netscaler.compromise_indicators can hash it
# against the known-malicious nsg64.deb dropper, not because the directory
# itself is inherently suspicious.
_VPN_LINUX_SCRIPTS_DEB_RE = re.compile(r"(^|/)vpn/scripts/linux/[^/]+\.deb$", re.IGNORECASE)


def looks_like_netscaler_artifact(path: str | Path) -> tuple[str, str, str] | None:
    """Detect NetScaler artifact family, type, and parser from a path.

    Mirrors app.ingest.linux.helpers.looks_like_linux_artifact's contract:
    returns (artifact_family, artifact_type, parser) or None.
    """
    path_str = str(path).replace("\\", "/").lower()
    name = path_str.rsplit("/", 1)[-1]
    if _NS_CONF_RE.search(path_str):
        is_current = name == "ns.conf"
        return ("netscaler_config", "ns_conf" if is_current else "ns_conf_backup", "netscaler_config_raw")
    if _WEBSHELL_DIR_RE.search(path_str):
        return ("netscaler_compromise", "logonpoint_custom_file", "netscaler_webshell_scan_raw")
    if _HTTPD_CONF_RE.search(path_str):
        return ("netscaler_compromise", "httpd_conf", "netscaler_httpd_conf_raw")
    if _NS_LOG_RE.search(path_str):
        return ("netscaler_compromise", "ns_log", "netscaler_ns_log_raw")
    if _HTTPACCESS_VPN_LOG_RE.search(path_str):
        return ("netscaler_compromise", "httpaccess_vpn_log", "netscaler_httpaccess_vpn_log_raw")
    if _VPN_LINUX_SCRIPTS_DEB_RE.search(path_str):
        return ("netscaler_compromise", "vpn_linux_script_deb", "netscaler_deb_hash_raw")
    return None
