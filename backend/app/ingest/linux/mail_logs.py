"""Postfix and Dovecot log lines (``mail.log`` / ``maillog``, or the journal).

A mail server's log is where mail abuse shows up: a password-guessing run against SMTP or IMAP,
an open relay being tried, a compromised account sending spam. The lines arrive as ordinary
syslog (``postfix/smtpd[123]: ...``, ``dovecot: imap-login: ...``), so the sender, recipient,
queue id, client address, authenticated user and delivery status sat inside the message text.
This extracts them, onto the same fields the Exim parser uses, and a vocabulary of ``mail_*``
actions so a login failure, a rejected relay attempt and a delivery can be told apart.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

MAX_MESSAGE_CHARS = 4000

_QUEUE_ID = r"(?P<qid>NOQUEUE|[0-9A-Za-z]{6,20})"
_QID_PREFIX_RE = re.compile(rf"^{_QUEUE_ID}: (?P<rest>.*)$", re.S)
_HOST_IP_RE = re.compile(r"(?P<host>[^\[\s,;]+)\[(?P<ip>[0-9a-fA-F:.]+)\](?::(?P<port>\d+))?")
_ADDR_RE = re.compile(r"<(?P<addr>[^<>\s]*)>")
_KV_RE = re.compile(r"(?:^|[\s,;])(?P<key>[a-z][a-z0-9_-]*)=(?P<value><[^>]*>|[^\s,;]*)")
_REJECT_RE = re.compile(r"reject: (?P<command>[A-Z]+) from (?P<client>\S+): (?P<code>\d{3}) (?:(?P<enhanced>\d\.\d+\.\d+) )?(?P<reason>.*?)(?:;|$)")
_SASL_FAIL_RE = re.compile(r"warning: (?P<client>\S+): SASL (?P<method>[A-Za-z0-9-]+) authentication failed(?:: (?P<reason>.*))?$")
_CONNECTION_RE = re.compile(r"^(?P<what>connect|disconnect|lost connection|timeout|too many errors|improper command pipelining|SSL_accept error|TLS library problem|warning: hostname .* does not resolve)\b.*?\bfrom (?P<client>\S+)")

# Dovecot, key=value after the event text: user=<alice>, method=PLAIN, rip=203.0.113.9, lip=192.0.2.10
_DOVECOT_KV_RE = re.compile(r"(?P<key>[a-z_]+)=(?P<value><[^>]*>|[^\s,]*)")
_DOVECOT_AUTH_FAIL_RE = re.compile(r"(?:Disconnected|Aborted login)(?: by server)? \(?(?:auth failed|no auth attempts|tried to use|aborted)", re.I)
_DOVECOT_BACKEND_RE = re.compile(r"^(?P<backend>pam|sql|ldap|passwd-file|passwd|shadow|static|checkpassword|lua|oauth2)\((?P<user>[^,)]*)(?:,(?P<ip>[^,)]*))?[^)]*\): (?P<what>.*)$")
_DOVECOT_SERVICES = ("imap-login", "pop3-login", "submission-login", "managesieve-login", "lmtp", "imap", "pop3", "auth", "auth-worker", "master", "doveadm", "indexer-worker", "stats")

# Keys that carry no analytical value but would make the generic scan noisy.
_IGNORED_KV = {"proto", "size", "nrcpt", "delay", "delays", "dsn", "orig_to", "uid", "to_size"}


def _ip(value: str | None) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip().strip("[]")))
    except ValueError:
        return ""


def _address(value: str | None) -> str:
    match = _ADDR_RE.search(value or "")
    return (match.group("addr") if match else str(value or "")).strip()[:320]


def _client(value: str | None) -> tuple[str, str]:
    match = _HOST_IP_RE.search(value or "")
    if not match:
        return "", ""
    host = match.group("host")
    return _ip(match.group("ip")), "" if host == "unknown" else host


def _kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for match in _KV_RE.finditer(text):
        out.setdefault(match.group("key"), match.group("value"))
    return out


def _postfix(process: str, message: str) -> dict[str, Any] | None:
    component = process.split("/", 1)[1] if "/" in process else ""
    text = message[:MAX_MESSAGE_CHARS]
    out: dict[str, Any] = {"mail_service": "postfix", "mail_component": component}

    sasl = _SASL_FAIL_RE.search(text)
    if sasl:
        ip, host = _client(sasl.group("client"))
        out.update(event_action="mail_auth_failed", mail_status="failed", source_ip=ip, remote_ip=ip, mail_client_host=host,
                   authentication=sasl.group("method"), mail_reason=(sasl.group("reason") or "")[:200])
        return out

    queue_match = _QID_PREFIX_RE.match(text)
    qid = queue_match.group("qid") if queue_match else ""
    rest = queue_match.group("rest") if queue_match else text
    if qid:
        out["queue_id"] = qid
    pairs = _kv(rest)

    if qid == "NOQUEUE" or rest.startswith("reject:"):
        reject = _REJECT_RE.search(rest)
        if reject:
            ip, host = _client(reject.group("client"))
            out.update(event_action="mail_reject", mail_status="reject", source_ip=ip, remote_ip=ip, mail_client_host=host,
                       smtp_status=int(reject.group("code")), mail_reason=reject.group("reason").strip()[:300], mail_command=reject.group("command"))
            if pairs.get("from"):
                out["sender"] = _address(pairs["from"])
            if pairs.get("to"):
                out["recipient"] = _address(pairs["to"])
            if pairs.get("helo"):
                out["helo"] = _address(pairs["helo"])
            return out

    if not qid:
        conn = _CONNECTION_RE.match(text)
        if conn:
            ip, host = _client(conn.group("client"))
            what = conn.group("what")
            action = "mail_disconnect" if what == "disconnect" else "mail_connect" if what == "connect" else "mail_connection_problem"
            out.update(event_action=action, source_ip=ip, remote_ip=ip, mail_client_host=host)
            if what not in {"connect", "disconnect"}:
                out["mail_reason"] = what
            return out
        return None

    # Lines that follow a queue id.
    if "client" in pairs:
        client_text = re.search(r"client=(\S+?)(?:,|$)", rest)
        ip, host = _client(client_text.group(1)) if client_text else ("", "")
        out.update(event_action="mail_received", source_ip=ip, remote_ip=ip, mail_client_host=host)
        if pairs.get("sasl_username"):
            out.update(username=pairs["sasl_username"], authentication=pairs.get("sasl_method", ""), event_action="mail_received_authenticated")
        return out
    if "message-id" in pairs:
        out.update(event_action="mail_cleanup", message_id=_address(pairs["message-id"]))
        return out
    if "status" in pairs and "to" in pairs:
        status = pairs["status"].lower()
        relay = re.search(r"relay=(\S+?)(?:,|$)", rest)
        relay_ip, relay_host = _client(relay.group(1)) if relay else ("", "")
        out.update(event_action="mail_delivery", mail_status=status, recipient=_address(pairs["to"]), destination_ip=relay_ip,
                   mail_relay=relay_host or relay_ip or (relay.group(1) if relay else ""))
        if pairs.get("orig_to"):
            out["mail_original_recipient"] = _address(pairs["orig_to"])
        # Only a code that opens the parenthesis is an SMTP reply ("(250 2.0.0 Ok)"); a number inside
        # free text, such as the octet of an address in "(connect to mx[192.0.2.9]...)", is not.
        smtp = re.search(r"status=\w+ \((\d{3})[ )]", rest)
        if smtp:
            out["smtp_status"] = int(smtp.group(1))
        return out
    if "from" in pairs:
        out.update(event_action="mail_queued", sender=_address(pairs["from"]))
        return out
    if rest.startswith("removed"):
        out["event_action"] = "mail_removed"
        return out
    return out if len(out) > 2 else None


def _dovecot(process: str, message: str) -> dict[str, Any] | None:
    text = message[:MAX_MESSAGE_CHARS]
    service = ""
    body = text
    head = re.match(r"^(?P<svc>[a-z0-9-]+)(?:\((?P<user>[^)]*)\))?(?:<[^>]*>)*: (?P<body>.*)$", text)
    if head and head.group("svc") in _DOVECOT_SERVICES:
        service, body = head.group("svc"), head.group("body")
    elif process in _DOVECOT_SERVICES:
        service = process
    else:
        return None
    pairs = {m.group("key"): m.group("value") for m in _DOVECOT_KV_RE.finditer(body)}
    out: dict[str, Any] = {"mail_service": "dovecot", "mail_component": service}
    user = _address(pairs.get("user")) if pairs.get("user") else ""
    if not user and head and head.group("user"):
        user = head.group("user")
    rip, lip = _ip(pairs.get("rip")), _ip(pairs.get("lip"))
    if user:
        out["username"] = user
    if rip:
        out.update(source_ip=rip, remote_ip=rip)
    if lip:
        out.update(destination_ip=lip, local_ip=lip)
    if pairs.get("method"):
        out["authentication"] = pairs["method"]

    backend = _DOVECOT_BACKEND_RE.match(body)
    if backend:
        ip = _ip(backend.group("ip"))
        failed = bool(re.search(r"fail|mismatch|unknown user|denied|invalid|not found|no such user", backend.group("what"), re.I))
        out.update(username=backend.group("user") or user or None, event_action="mail_auth_failed" if failed else "mail_auth_info",
                   mail_reason=backend.group("what")[:200], authentication=backend.group("backend"))
        if ip:
            out.update(source_ip=ip, remote_ip=ip)
        out["mail_status"] = "failed" if failed else ""
        return out
    if _DOVECOT_AUTH_FAIL_RE.search(body):
        out.update(event_action="mail_auth_failed", mail_status="failed", mail_reason=body.split(":", 1)[0][:200])
        return out
    if body.startswith("Login:"):
        out.update(event_action="mail_login", mail_status="success")
        return out
    if body.startswith(("Disconnected", "Logged out", "Connection closed")):
        # A login process disconnecting means no session was established; a session ending is a logout.
        out["event_action"] = "mail_disconnect" if service.endswith("login") else "mail_logout"
        return out
    return out if (out.get("username") or out.get("source_ip")) else None


def parse_mail_message(process: str | None, message: str) -> dict[str, Any] | None:
    """Mail fields of a Postfix or Dovecot line, or None when the line is neither."""
    name = str(process or "").strip().lower()
    if name == "postfix" or name.startswith("postfix/"):
        return _postfix(name, message)
    if name == "dovecot" or name in _DOVECOT_SERVICES or name.startswith("dovecot"):
        return _dovecot(name, message)
    return None


def enrich_with_mail(row: dict[str, Any], process: str | None, message: str) -> dict[str, Any]:
    """Merge mail fields into a parsed syslog / journal row, in place."""
    fields = parse_mail_message(process, message)
    if fields:
        row.update({key: value for key, value in fields.items() if value not in (None, "")})
    return row
