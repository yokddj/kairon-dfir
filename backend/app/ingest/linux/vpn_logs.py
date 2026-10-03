"""OpenVPN and strongSwan logs.

A VPN gateway's logs record who connected from where, who failed to, and which tunnel address they
were given: the trail of a password-guessing run against the gateway, a stolen certificate in use
from a new address, or a session that outlived its owner's access.

* OpenVPN: the server log (the classic ``Fri Mar  1 10:20:30 2024`` prefix and the ISO prefix), and
  the status file (``openvpn-status.log``, versions 1, 2 and 3), which lists the sessions open at the
  moment it was written.
* strongSwan: the ``charon`` log (syslog-style or ISO prefix): IKE negotiations, authentication
  results, established and closed tunnels.

Lines are matched with bounded regexes, never executed or fetched. ``suspicious_indicators`` are
generic leads for review, not verdicts.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

ARTIFACT_FAMILY = "linux_vpn"
MAX_MESSAGE_CHARS = 2000
_MIN_YEAR = 1990
_MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}

_PATTERNS = (
    ("openvpn_status", re.compile(r"(^|/)(?:var/log|etc|var/run|run)/(?:(?:[^/]*openvpn[^/]*/)(?:[^/]+/)*[^/]*status[^/]*|[^/]*openvpn[^/]*status[^/]*)\.(?:log|txt)(?:[.-]\w+)*$", re.I)),
    ("openvpn", re.compile(r"(^|/)var/log/openvpn/[^/]+\.log(?:[.-]\w+)*$", re.I)),
    ("openvpn", re.compile(r"(^|/)var/log/openvpn[^/]*\.log(?:[.-]\w+)*$", re.I)),
    ("strongswan", re.compile(r"(^|/)var/log/(?:strongswan/)?(?:charon|strongswan|ipsec)[^/]*\.log(?:[.-]\w+)*$", re.I)),
)

_IP = r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]+)"
_OVPN_CLASSIC = re.compile(r"^(?P<ts>\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(?P<rest>.*)$")
_OVPN_ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<rest>.*)$")
_OVPN_PEER = re.compile(rf"^(?:(?P<user>[^\s/\[\]]+)/)?(?:\[(?P<bracket>[^\]]+)\]\s*)?(?:\[AF_INET6?\])?(?P<ip>{_IP}):(?P<port>\d{{1,5}})\s+(?P<msg>.*)$")
_OVPN_CN = re.compile(r"\b(?:CN|cn)=([^,/\s]+)")
_OVPN_FROM = re.compile(rf"\[AF_INET6?\](?P<ip>{_IP}):(?P<port>\d{{1,5}})")
_OVPN_ASSIGN = re.compile(rf"MULTI: Learn: (?P<vip>{_IP}) -> ")
_SS_SYSLOG = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?:\S+\s+)?(?:charon(?:-\w+)?(?:\[\d+\])?:\s+)?(?P<thread>\d{2})\[(?P<group>[A-Z]{3})\]\s+(?P<msg>.*)$")
_SS_ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?:\S+\s+)?(?:charon(?:-\w+)?(?:\[\d+\])?:\s+)?(?P<thread>\d{2})\[(?P<group>[A-Z]{3})\]\s+(?P<msg>.*)$")

_OVPN_FAIL = re.compile(r"AUTH_FAILED|Auth Username/Password verification failed|TLS Auth Error|TLS Error: TLS handshake failed|TLS Error: TLS key negotiation failed|VERIFY ERROR|packet HMAC authentication failed|incoming packet authentication failed|Authenticate/Decrypt packet error|certificate verify failed|bad certificate|user.*not found", re.I)
_SS_FAIL = re.compile(r"authentication failed|AUTHENTICATION_FAILED|EAP method \S+ failed|no matching peer config|no proposal chosen|NO_PROPOSAL_CHOSEN|tried \d+ secrets|no shared key found|signature validation failed|received (?:AUTH_FAILED|NO_PROPOSAL)", re.I)


def vpn_kind(source_path: str) -> str | None:
    """``openvpn``, ``openvpn_status``, ``strongswan`` or None."""
    path = str(source_path or "").replace("\\", "/")
    for kind, pattern in _PATTERNS:
        if pattern.search(path):
            return kind
    return None


def _utc_iso(dt: datetime) -> str | None:
    if dt.year < _MIN_YEAR or dt > datetime.now(tz=timezone.utc) + timedelta(days=366):
        return None
    return dt.astimezone(timezone.utc).isoformat()


def _iso(value: str) -> tuple[str | None, str]:
    text = value.strip().replace(" ", "T", 1)
    exact = text.endswith("Z") or bool(re.search(r"[+-]\d{2}:?\d{2}$", text[10:]))
    text = text[:-1] + "+00:00" if text.endswith("Z") else text
    if re.search(r"[+-]\d{4}$", text[10:]):
        text = text[:-2] + ":" + text[-2:]
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None, "missing"
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    stamp = _utc_iso(parsed)
    return (stamp, "ok" if exact else "assumed_utc") if stamp else (None, "missing")


def _classic(value: str) -> tuple[str | None, str]:
    """``Fri Mar  1 10:20:30 2024``: the time of the machine, with no zone."""
    parts = value.split()
    if len(parts) != 5 or parts[1].lower() not in _MONTHS:
        return None, "missing"
    try:
        hour, minute, second = (int(x) for x in parts[3].split(":"))
        dt = datetime(int(parts[4]), _MONTHS[parts[1].lower()], int(parts[2]), hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None, "missing"
    stamp = _utc_iso(dt)
    return (stamp, "assumed_utc") if stamp else (None, "missing")


def _syslog_time(value: str) -> tuple[str | None, str]:
    """``Mar  1 10:20:30``: no year. The current year, or last year for a date that would be in the future."""
    parts = value.split()
    if len(parts) != 3 or parts[0].lower() not in _MONTHS:
        return None, "missing"
    now = datetime.now(tz=timezone.utc)
    try:
        hour, minute, second = (int(x) for x in parts[2].split(":"))
        for year in (now.year, now.year - 1):
            dt = datetime(year, _MONTHS[parts[0].lower()], int(parts[1]), hour, minute, second, tzinfo=timezone.utc)
            if dt <= now + timedelta(days=1):
                break
    except ValueError:
        return None, "missing"
    stamp = _utc_iso(dt)
    return (stamp, "assumed_year_utc") if stamp else (None, "missing")


def _row(kind: str, source_path: str, line_number: int, *, timestamp: str | None, status: str, message: str, raw: str, **fields: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_type": kind,
        "source_file": source_path,
        "line_number": line_number,
        "timestamp": timestamp,
        "timestamp_status": status if timestamp else "missing",
        "message": message[:MAX_MESSAGE_CHARS],
        "raw_excerpt": raw[:MAX_MESSAGE_CHARS],
        "vpn_software": "openvpn" if kind.startswith("openvpn") else "strongswan",
        "suspicious_indicators": [],
    }
    row.update({key: value for key, value in fields.items() if value not in (None, "")})
    return row


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    if ":" not in value:
        parts = value.split(".")
        return value if len(parts) == 4 and all(p.isdigit() and int(p) <= 255 for p in parts) else None
    return value if re.fullmatch(r"[0-9a-fA-F:.]{2,45}", value) else None


# ------------------------------------------------------------------- OpenVPN log

def _openvpn_event(msg: str) -> tuple[str | None, str | None, str]:
    """``(event_action, status, level)`` for the text after the peer."""
    if _OVPN_FAIL.search(msg):
        return "vpn_auth_failed", "failed", "warning"
    if "Peer Connection Initiated" in msg:
        return "vpn_connect", "success", "info"
    if re.search(r"SIGTERM\[soft,remote-exit\]|SIGUSR1\[soft,connection-reset|client-instance (?:exiting|restarting)|Connection reset, restarting", msg):
        return "vpn_disconnect", None, "info"
    if "VERIFY OK" in msg:
        return "vpn_cert_verified", "success", "info"
    if "MULTI: Learn:" in msg:
        return "vpn_address_assigned", "success", "info"
    if "Initial packet from" in msg:
        return "vpn_connection_received", None, "info"
    if re.search(r"\bERROR\b|Fatal|Exiting due to fatal error", msg):
        return "vpn_error", None, "error"
    return None, None, "info"


def _parse_openvpn(content: str, source_path: str) -> list[dict]:
    rows: list[dict] = []
    for number, raw in enumerate(content.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip():
            continue
        stamp, status, rest = None, "missing", line
        match = _OVPN_CLASSIC.match(line)
        if match:
            stamp, status = _classic(match["ts"])
            rest = match["rest"]
        else:
            match = _OVPN_ISO.match(line)
            if match:
                stamp, status = _iso(match["ts"])
                rest = match["rest"]
        fields: dict[str, Any] = {}
        peer = _OVPN_PEER.match(rest)
        message = rest
        if peer:
            fields["source_ip"] = _valid_ip(peer["ip"])
            fields["source_port"] = int(peer["port"]) if int(peer["port"]) <= 65535 else None
            user = peer["user"] or peer["bracket"]
            if user and user != "UNDEF":
                fields["username"] = user
            message = peer["msg"]
            named = re.match(r"\[([^\]\s]+)\]\s+", message)
            if named and "username" not in fields and named[1] != "UNDEF":
                fields["username"] = named[1]
        if "source_ip" not in fields:
            origin = _OVPN_FROM.search(rest)
            if origin:
                fields["source_ip"] = _valid_ip(origin["ip"])
        cn = _OVPN_CN.search(message)
        if cn and "username" not in fields and cn[1] != "UNDEF":
            fields["username"] = cn[1]
        assigned = _OVPN_ASSIGN.search(message)
        if assigned:
            fields["vpn_assigned_ip"] = _valid_ip(assigned["vip"])
        action, outcome, level = _openvpn_event(message)
        fields.update({"event_action": action, "vpn_status": outcome, "severity": level})
        rows.append(_row("openvpn_log", source_path, number, timestamp=stamp, status=status, message=rest, raw=line, **fields))
    return rows


# --------------------------------------------------------------- OpenVPN status

def _status_time(value: str) -> tuple[str | None, str]:
    value = value.strip()
    if value.isdigit() and len(value) >= 9:
        try:
            stamp = _utc_iso(datetime.fromtimestamp(int(value), tz=timezone.utc))
        except (OverflowError, OSError, ValueError):
            stamp = None
        return (stamp, "ok") if stamp else (None, "missing")
    return _classic(re.sub(r"\s+", " ", value))


def _split_address(value: str) -> tuple[str | None, int | None]:
    value = re.sub(r"^\[AF_INET6?\]", "", value.strip())
    host, _, port = value.rpartition(":")
    if host and port.isdigit() and int(port) <= 65535:
        return _valid_ip(host.strip("[]")), int(port)
    return _valid_ip(value.strip("[]")), None


def _int(value: str) -> int | None:
    return int(value) if value.strip().isdigit() else None


def _parse_openvpn_status(content: str, source_path: str) -> list[dict]:
    rows: list[dict] = []
    updated = None
    section = ""
    for number, raw in enumerate(content.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip():
            continue
        delimiter = "\t" if "\t" in line and line.startswith(("CLIENT_LIST", "ROUTING_TABLE", "TITLE", "TIME", "HEADER")) else ","
        cells = [c.strip() for c in line.split(delimiter)]
        head = cells[0]
        if head in {"TIME"} and len(cells) >= 3:
            updated = _status_time(cells[2])
            continue
        if head == "Updated" and len(cells) >= 2:
            updated = _status_time(",".join(cells[1:]))
            continue
        if head == "OpenVPN CLIENT LIST":
            section = "clients"
            continue
        if head == "ROUTING TABLE":
            section = "routes"
            continue
        if head in {"GLOBAL STATS", "END"} or head.startswith(("Max bcast", "TITLE", "HEADER")):
            section = "" if head in {"GLOBAL STATS", "END"} else section
            continue
        client = None
        if head == "CLIENT_LIST" and len(cells) >= 8:
            # v2/v3: CLIENT_LIST,name,real,virtual,virtual6,rx,tx,connected,connected_unix,user,...
            ip, port = _split_address(cells[2])
            since = _status_time(cells[8]) if len(cells) > 8 and cells[8].isdigit() else _status_time(cells[7])
            client = dict(common=cells[1], ip=ip, port=port, virtual=_valid_ip(cells[3]), rx=_int(cells[5]), tx=_int(cells[6]), since=since,
                          user=cells[9] if len(cells) > 9 and cells[9] not in {"", "UNDEF"} else None)
        elif section == "clients" and len(cells) >= 5 and head != "Common Name":
            ip, port = _split_address(cells[1])
            client = dict(common=cells[0], ip=ip, port=port, virtual=None, rx=_int(cells[2]), tx=_int(cells[3]), since=_status_time(cells[4]), user=None)
        if client is None:
            continue
        stamp, status = client["since"]
        who = client["user"] or client["common"]
        rows.append(_row("openvpn_status", source_path, number, timestamp=stamp, status=status,
                         message=f"VPN session open: {who} from {client['ip'] or 'unknown'}" + (f" as {client['virtual']}" if client["virtual"] else ""), raw=line,
                         event_action="vpn_session", vpn_status="success", severity="info", username=who, source_ip=client["ip"], source_port=client["port"],
                         vpn_assigned_ip=client["virtual"], vpn_bytes_received=client["rx"], vpn_bytes_sent=client["tx"],
                         vpn_status_updated=updated[0] if updated else None))
    return rows


# ------------------------------------------------------------------- strongSwan

_SS_PEER = re.compile(rf"(?:from|between|with|for peer|peer|to)\s+(?P<ip>{_IP})(?:\[(?P<port>\d+)\])?")
_SS_EST = re.compile(rf"IKE_SA (?P<conn>[\w.-]+)\[\d+\] established between (?P<local>{_IP})\[(?P<lid>[^\]]*)\]\.\.\.(?P<remote>{_IP})\[(?P<rid>[^\]]*)\]")
_SS_CLOSE = re.compile(rf"(?:deleting|closing) IKE_SA (?P<conn>[\w.-]+)\[\d+\] between (?P<local>{_IP})\[(?P<lid>[^\]]*)\]\.\.\.(?P<remote>{_IP})\[(?P<rid>[^\]]*)\]")
_SS_AUTH_OK = re.compile(r"authentication of '(?P<id>[^']*)'(?: \(myself\))? with (?P<method>[\w-]+(?: \w+)?)(?: successful| \(.*\) successful)")
_SS_EAP_FAIL = re.compile(r"EAP method \S+ failed for peer (?P<id>\S+)")
_SS_INIT = re.compile(rf"(?P<ip>{_IP}) is initiating (?:an? )?(?P<ver>IKE_SA|IKEv\d)")
_SS_CHILD = re.compile(r"CHILD_SA (?P<conn>[\w.-]+)\{\d+\} established with SPIs .* and TS (?P<ts>.+)$")
_SS_VIP = re.compile(rf"assigning virtual IP (?P<vip>{_IP}) to peer '(?P<id>[^']*)'")
_SS_RECEIVED = re.compile(rf"received packet: from (?P<ip>{_IP})\[(?P<port>\d+)\]")


def _strongswan_event(msg: str) -> tuple[str | None, str | None, str]:
    if _SS_FAIL.search(msg):
        return "vpn_auth_failed", "failed", "warning"
    if _SS_EST.search(msg):
        return "vpn_connect", "success", "info"
    if _SS_CLOSE.search(msg):
        return "vpn_disconnect", None, "info"
    if _SS_AUTH_OK.search(msg):
        return "vpn_auth_ok", "success", "info"
    if _SS_VIP.search(msg):
        return "vpn_address_assigned", "success", "info"
    if _SS_CHILD.search(msg):
        return "vpn_tunnel_established", "success", "info"
    if _SS_INIT.search(msg):
        return "vpn_connection_received", None, "info"
    if re.search(r"\b(?:error|failed|unable|could not)\b", msg, re.I):
        return "vpn_error", None, "error"
    return None, None, "info"


def _parse_strongswan(content: str, source_path: str) -> list[dict]:
    rows: list[dict] = []
    for number, raw in enumerate(content.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip():
            continue
        stamp, status, message, fields = None, "missing", line, {}
        match = _SS_ISO.match(line)
        if match:
            stamp, status = _iso(match["ts"])
        else:
            match = _SS_SYSLOG.match(line)
            if match:
                stamp, status = _syslog_time(match["ts"])
        if match:
            message = match["msg"]
            fields["vpn_component"] = match["group"]
        action, outcome, level = _strongswan_event(message)
        est, closed = _SS_EST.search(message), _SS_CLOSE.search(message)
        pair = est or closed
        if pair:
            fields.update(source_ip=_valid_ip(pair["remote"]), username=pair["rid"] if pair["rid"] and _valid_ip(pair["rid"]) is None else None,
                          vpn_connection=pair["conn"], vpn_local_ip=_valid_ip(pair["local"]))
        else:
            ok = _SS_AUTH_OK.search(message)
            eap = _SS_EAP_FAIL.search(message)
            vip = _SS_VIP.search(message)
            child = _SS_CHILD.search(message)
            if ok and not ok["id"].startswith(("%", "@")) and "(myself)" not in message:
                fields["username"] = ok["id"]
            if eap:
                fields["username"] = eap["id"]
            if vip:
                fields["username"], fields["vpn_assigned_ip"] = vip["id"], _valid_ip(vip["vip"])
            if child:
                fields["vpn_connection"], fields["vpn_traffic_selectors"] = child["conn"], child["ts"][:200]
            for pattern in (_SS_RECEIVED, _SS_INIT, _SS_PEER):
                peer = pattern.search(message)
                if peer and _valid_ip(peer["ip"]):
                    fields["source_ip"] = _valid_ip(peer["ip"])
                    if "port" in peer.groupdict() and peer["port"] and int(peer["port"]) <= 65535:
                        fields["source_port"] = int(peer["port"])
                    break
        fields.update({"event_action": action, "vpn_status": outcome, "severity": level})
        rows.append(_row("strongswan_log", source_path, number, timestamp=stamp, status=status, message=message, raw=line, **fields))
    return rows


def vpn_flags(rows: list[dict]) -> None:
    """Mark a source address that failed to authenticate repeatedly. A lead for review, not a verdict."""
    failures: dict[str, int] = {}
    for row in rows:
        if row.get("vpn_status") == "failed" and row.get("source_ip"):
            failures[row["source_ip"]] = failures.get(row["source_ip"], 0) + 1
    repeated = {ip for ip, count in failures.items() if count >= 5}
    for row in rows:
        if row.get("source_ip") in repeated and row.get("vpn_status") == "failed":
            row["suspicious_indicators"] = ["repeated_auth_failures"]


def parse_vpn_log(content: str, *, source_path: str = "", truncated: bool = False) -> list[dict]:
    kind = vpn_kind(source_path)
    if kind is None:
        return []
    rows = {"openvpn": _parse_openvpn, "openvpn_status": _parse_openvpn_status, "strongswan": _parse_strongswan}[kind](content, source_path)
    vpn_flags(rows)
    if truncated:
        rows.append(_row(rows[-1]["artifact_type"] if rows else (f"{kind}_log" if kind != "openvpn_status" else kind), source_path, len(content.splitlines()) + 1, timestamp=None, status="missing",
                         message="[kairon] log truncated: only the first part of this file was parsed (size limit or damaged archive)", raw=""))
    return rows
