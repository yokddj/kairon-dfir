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
    return None
