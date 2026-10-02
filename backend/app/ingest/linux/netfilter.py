"""Extract packet fields from netfilter log lines (iptables / nftables / ufw / firewalld).

The kernel logs a dropped, rejected or audited packet as free text:

    [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=203.0.113.9 DST=192.0.2.10 ... PROTO=TCP SPT=51234 DPT=22 ... SYN

Those lines arrive in kern.log, syslog, messages, ufw.log and the journal, all of which are
already parsed as plain text. Pulling the packet fields out makes the source, destination,
port and verdict searchable, and puts the addresses on the same fields the rest of Kairon
uses for network activity.
"""
from __future__ import annotations

import re
from typing import Any

_KEY_VALUE_RE = re.compile(r"\b([A-Z]{2,8})=(\S*)")
_KERNEL_STAMP_RE = re.compile(r"^\s*\[\s*\d+\.\d+\]\s*")
_TCP_FLAGS = ("SYN", "ACK", "FIN", "RST", "PSH", "URG")

# Words a firewall puts in its LOG prefix, mapped to a verdict. The prefix is free text chosen
# by whoever wrote the rule, so an unrecognised one is reported as a plain "log".
_ACTIONS = (
    ("BLOCK", "block"),
    ("REJECT", "reject"),
    ("DROP", "drop"),
    ("DENY", "drop"),
    ("DENIED", "drop"),
    ("ALLOW", "allow"),
    ("ACCEPT", "allow"),
    ("AUDIT", "audit"),
    ("LIMIT", "limit"),
)


def parse_netfilter(message: str) -> dict[str, Any] | None:
    """Packet fields of a netfilter log line, or None when the line is not one."""
    if "SRC=" not in message or "DST=" not in message:
        return None
    fields: dict[str, str] = {}
    for key, value in _KEY_VALUE_RE.findall(message):
        fields.setdefault(key, value)  # LEN appears twice on UDP: keep the IP-level one
    if not fields.get("SRC") or not fields.get("DST") or not ("PROTO" in fields or "IN" in fields):
        return None

    marker = message.find("IN=")
    prefix = _KERNEL_STAMP_RE.sub("", message[: marker if marker > 0 else 0]).strip()
    upper = prefix.upper()
    action = next((verdict for word, verdict in _ACTIONS if word in upper), "log")
    protocol = fields.get("PROTO", "").lower()

    def port(name: str) -> int | None:
        value = fields.get(name, "")
        return int(value) if value.isdigit() and 0 <= int(value) <= 65535 else None

    tokens = set(re.findall(r"\b[A-Z]{3}\b", message))
    return {
        "firewall_action": action,
        "firewall_prefix": prefix[:120],
        "source_ip": fields["SRC"],
        "destination_ip": fields["DST"],
        "source_port": port("SPT"),
        "destination_port": port("DPT"),
        "network_protocol": protocol,
        "interface_in": fields.get("IN", ""),
        "interface_out": fields.get("OUT", ""),
        "tcp_flags": [flag for flag in _TCP_FLAGS if flag in tokens] if protocol == "tcp" else [],
    }


def enrich_with_netfilter(row: dict[str, Any], message: str) -> dict[str, Any]:
    """Merge packet fields into a parsed log row in place when the message is a netfilter line."""
    packet = parse_netfilter(message)
    if packet:
        row.update(packet)
    return row
