"""Linux authentication investigation: who got in, from where, what was tried, what they did.

Built from every carrier of Linux authentication data a case may hold, not from one log format:

- auth.log / secure (rsyslog), and the same messages in the systemd journal (hosts without
  rsyslog: Debian 12+, Fedora, Arch, minimal RHEL images, containers);
- auditd user-space records (USER_AUTH, USER_LOGIN, USER_START/END, USER_CMD, account changes);
- wtmp / btmp / lastlog login records;
- /etc/passwd entries, to tell root, system and human accounts apart.

One authentication attempt is often written by several of them at once (sshd's "Failed password",
pam_unix's "authentication failure", a btmp record, an auditd USER_AUTH), all under the PID of the
sshd/login process handling the connection. Attempts are therefore counted per connection as the
largest count any single carrier gives, never as the sum: carriers are incomplete in different ways
(rsyslog rate limits, rotated files), so the maximum is the closest to the truth.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.opensearch import get_events_index, get_opensearch_client
from app.ingest.linux.auth import classify_auth_message

MAX_DOCS = 250_000
_PAGE_SIZE = 5_000

# Processes whose journal entries are authentication or account-management messages.
_JOURNAL_AUTH_PROCESSES = [
    "sshd", "sshd-session", "sshd-auth", "sudo", "su", "runuser", "login", "systemd-logind",
    "gdm-password", "gdm-autologin", "lightdm", "sddm-helper", "xrdp-sesman", "cockpit-session",
    "useradd", "usermod", "userdel", "groupadd", "groupdel", "groupmod", "gpasswd", "passwd",
    "chpasswd", "chsh", "chfn", "chage", "newusers", "adduser", "deluser",
]
_AUDIT_AUTH_TYPES = [
    "USER_AUTH", "USER_LOGIN", "USER_START", "USER_END", "USER_CMD", "USER_CHAUTHTOK", "USER_MGMT",
    "GRP_MGMT", "ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP",
]
# PAM sessions of these services are scheduled jobs or privilege changes, not logins.
_NON_LOGIN_SESSION_SERVICES = {"cron", "crond", "atd", "sudo", "sudo-i", "su", "su-l", "runuser", "runuser-l", "systemd-user", "polkit-1"}
_PRIVILEGED_GROUPS = {"sudo", "wheel", "admin", "root", "docker", "lxd", "disk", "shadow"}
_NON_LOGIN_SHELLS = ("nologin", "false", "/bin/sync", "halt", "shutdown")
_ACCOUNT_PROCESSES = {"useradd", "usermod", "userdel", "groupadd", "groupdel", "groupmod", "gpasswd", "passwd", "chpasswd", "chsh", "chfn", "chage", "newusers", "adduser", "deluser"}

_CONNECTION_GAP = timedelta(minutes=10)
_CAMPAIGN_GAP = timedelta(minutes=30)
_LOGIN_MERGE_WINDOW = timedelta(seconds=10)
_SUCCESS_LOOKAHEAD = timedelta(hours=24)

_PAM_MORE_RE = re.compile(r"PAM\s+(\d+)\s+more\s+authentication\s+failures?", re.I)
_PAM_USER_RE = re.compile(r"\buser=([^\s;]+)")
_SESSION_RE = re.compile(r"pam_unix\((?P<service>[^:)]+)(?::[^)]*)?\):\s*session\s+(?P<state>opened|closed)\s+for\s+user\s+(?P<user>[^\s(]+)(?:\(uid=\d+\))?(?:\s+by\s+(?P<by>[^\s(]*)\(?)?", re.I)
_SU_RESULT_RE = re.compile(r"(?P<result>Successful|FAILED)\s+su\s+for\s+(?P<target>\S+)\s+by\s+(?P<by>\S+)", re.I)
_SU_SHORT_RE = re.compile(r"^(?P<sign>[+-])\s+(?P<tty>\S+)\s+(?P<by>[^:\s]+):(?P<target>\S+)")
_FAILED_LOGIN_RE = re.compile(r"FAILED LOGIN \(\d+\) on '?(?P<tty>[^'\s]+)'?(?: FROM '?(?P<host>[^'\s]+)'?)? FOR '?(?P<user>[^',\s]+)'?", re.I)
_SUDO_DENIED_RE = re.compile(r"(incorrect password attempts?|not in (?:the )?sudoers|not allowed to execute|command not allowed)", re.I)

_ACCOUNT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("user_created", re.compile(r"new user: name=(?P<account>[^,\s]+), UID=(?P<uid>\d+)(?:, GID=\d+)?(?:, home=(?P<home>[^,]*))?(?:, shell=(?P<shell>[^,\s]*))?", re.I)),
    ("group_created", re.compile(r"new group: name=(?P<group>[^,\s]+)(?:, GID=(?P<gid>\d+))?", re.I)),
    ("group_member_added", re.compile(r"add '(?P<account>[^']+)' to group '(?P<group>[^']+)'", re.I)),
    ("group_member_added", re.compile(r"user (?P<account>\S+) added by (?P<by>\S+) to group (?P<group>\S+)", re.I)),
    ("group_member_removed", re.compile(r"delete '(?P<account>[^']+)' from group '(?P<group>[^']+)'", re.I)),
    ("group_member_removed", re.compile(r"user (?P<account>\S+) removed by (?P<by>\S+) from group (?P<group>\S+)", re.I)),
    ("group_members_set", re.compile(r"members of group (?P<group>\S+) set by (?P<by>\S+) to (?P<members>.*)$", re.I)),
    ("user_deleted", re.compile(r"delete user '(?P<account>[^']+)'", re.I)),
    ("group_deleted", re.compile(r"(?:removed group|group deleted)[^']*'?(?P<group>[^',\s]+)'?", re.I)),
    ("password_changed", re.compile(r"password changed for (?P<account>\S+)", re.I)),
    ("password_changed", re.compile(r"change user '(?P<account>[^']+)' password", re.I)),
    ("shell_changed", re.compile(r"changed user '(?P<account>[^']+)' shell to '(?P<shell>[^']*)'", re.I)),
    ("account_info_changed", re.compile(r"changed user '(?P<account>[^']+)' information", re.I)),
    ("password_expiry_changed", re.compile(r"changed password expiry for (?P<account>\S+)", re.I)),
    ("user_locked", re.compile(r"lock user '(?P<account>[^']+)' password", re.I)),
    ("user_renamed", re.compile(r"change user name '(?P<old>[^']+)' to '(?P<account>[^']+)'", re.I)),
    ("uid_changed", re.compile(r"change user '(?P<account>[^']+)' UID from '(?P<old>\d+)' to '(?P<uid>\d+)'", re.I)),
]
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def _fetch_auth_docs(case_id: str) -> tuple[list[dict], bool]:
    """Every authentication-bearing document of the case (paged, not capped at one search)."""
    client = get_opensearch_client(timeout_seconds=120)
    query = {"bool": {"filter": [{"term": {"case_id": case_id}}], "should": [
        {"terms": {"artifact.type": ["linux_auth", "linux_lastlog"]}},
        {"bool": {"filter": [{"term": {"artifact.type": "linux_journal"}}, {"terms": {"linux.process": _JOURNAL_AUTH_PROCESSES}}]}},
        {"bool": {"filter": [{"term": {"artifact.type": "linux_audit"}}, {"terms": {"linux.audit_type": _AUDIT_AUTH_TYPES}}]}},
        {"bool": {"filter": [{"term": {"artifact.type": "linux_identity"}}, {"term": {"artifact.name": "passwd"}}]}},
    ], "minimum_should_match": 1}}
    docs: list[dict] = []
    search_after: list | None = None
    while len(docs) < MAX_DOCS:
        body: dict[str, Any] = {
            "size": _PAGE_SIZE,
            "query": query,
            "sort": [{"@timestamp": {"order": "asc", "missing": "_last"}}, {"event_id": "asc"}],
        }
        if search_after:
            body["search_after"] = search_after
        result = client.search(index=get_events_index(case_id), body=body, params={"ignore_unavailable": "true"})
        hits = result.get("hits", {}).get("hits", [])
        if not hits:
            return docs, False
        docs.extend({"_id": hit.get("_id"), **dict(hit.get("_source") or {})} for hit in hits)
        if len(hits) < _PAGE_SIZE:
            return docs, False
        search_after = hits[-1].get("sort")
    return docs[:MAX_DOCS], True


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def _clean(value: Any) -> str:
    text = str(value or "").strip().strip("`',.;")
    # login(1) writes "UNKNOWN" for a name that is not an account.
    return "" if text in {"?", "-", "(unknown)", "unknown", "UNKNOWN"} else text


def _carrier(doc: dict) -> str:
    artifact = doc.get("artifact") or {}
    linux = doc.get("linux") or {}
    family = str(artifact.get("type") or linux.get("artifact_family") or "")
    kind = str(linux.get("artifact_type") or artifact.get("name") or "")
    if family == "linux_journal":
        return "journal"
    if family == "linux_audit":
        return "audit"
    if family == "linux_lastlog" or kind == "lastlog":
        return "lastlog"
    if kind in {"wtmp", "btmp"}:
        return kind
    return "auth_log"


def _service_name(value: str) -> str:
    name = (value or "").strip()
    lower = name.lower()
    if lower.startswith("sshd"):
        return "sshd"
    return lower.rsplit("/", 1)[-1] if "/" in lower else lower


def _base_event(doc: dict, carrier: str) -> dict:
    linux = doc.get("linux") or {}
    host = doc.get("host") if isinstance(doc.get("host"), dict) else {}
    dt = _parse_time(doc.get("@timestamp") or doc.get("timestamp"))
    message = str(linux.get("message") or (doc.get("event") or {}).get("message") or doc.get("message") or "")
    pid = linux.get("pid")
    return {
        "id": doc.get("event_id") or doc.get("_id"),
        "evidence_id": doc.get("evidence_id"),
        "host_id": host.get("evidence_host_id"),
        "host": host.get("name") or "",
        "_dt": dt,
        "time": _iso(dt),
        "carrier": carrier,
        "source_file": doc.get("source_file") or linux.get("source_file") or "",
        "process": str(linux.get("process") or ""),
        "service": "",
        "pid": str(pid) if pid not in (None, "", 0, "0") else "",
        "kind": "other",
        "result": "unknown",
        "username": "",
        "target": "",
        "by": "",
        "source_ip": "",
        "source_port": None,
        "terminal": "",
        "method": "",
        "command": "",
        "cwd": "",
        "count": 1,
        "channel": "",
        "message": message,
    }


def _apply_auth_fields(event: dict, fields: dict, message: str) -> None:
    """Map auth-message fields (stored at ingest, or classified now) to the event vocabulary."""
    auth_type = str(fields.get("auth_event_type") or "")
    action = str(fields.get("event_action") or "")
    event["service"] = _service_name(str(fields.get("service") or event["process"]))
    event["username"] = _clean(fields.get("attempted_username") or fields.get("username"))
    event["source_ip"] = _clean(fields.get("source_ip"))
    event["source_port"] = fields.get("source_port") or None
    event["terminal"] = _clean(fields.get("terminal"))
    event["method"] = _clean(fields.get("auth_method"))
    lower = message.lower()
    session = _SESSION_RE.search(message)
    if session:
        # Checked first: the classifier files su/sudo session lines under su/sudo, and the
        # "by <login name>" they carry is what tells who really switched user.
        event.update(kind="session_open" if session.group("state").lower() == "opened" else "session_close", result="success",
                     service=_service_name(session.group("service")), username=_clean(session.group("user")), by=_clean(session.group("by")))
        return
    if auth_type == "login_success":
        event.update(kind="login", result="success", channel="auth")
        if action == "console_login" and not event["service"]:
            event["service"] = "login"
    elif auth_type in {"login_failure", "invalid_user"}:
        if action == "max_auth_attempts" or (auth_type == "invalid_user" and not lower.startswith("failed")):
            # A summary ("maximum authentication attempts exceeded") or the "Invalid user" notice
            # that precedes the real failures: context, not an attempt of its own.
            event.update(kind="failure_note", result="failure")
        else:
            event.update(kind="failure", result="failure", channel="explicit")
    elif auth_type == "authentication_failure":
        user = _PAM_USER_RE.search(message)
        event["username"] = _clean(user.group(1)) if user else ""
        if event["service"] in {"su", "su-l", "runuser"}:
            # A failed su password, not a login attempt.
            event.update(kind="su", result="failure", by=event["username"], username="")
            return
        if event["service"] in {"sudo", "sudo-i", "polkit-1", "passwd", "chpasswd"}:
            event.update(kind="failure_note", result="failure")
            return
        more = _PAM_MORE_RE.search(message)
        event.update(kind="failure", result="failure", channel="pam", count=int(more.group(1)) if more else 1)
    elif auth_type in {"session_open", "session_close"}:
        event.update(kind=auth_type, result="success")
    elif action in {"sudo_command", "sudo_failed"}:
        event.update(
            kind="sudo", result="success" if action == "sudo_command" else "failure", service="sudo",
            username=_clean(fields.get("username")), target=_clean(fields.get("run_as")),
            command=str(fields.get("command") or ""), cwd=str(fields.get("cwd") or ""),
        )
    elif action == "su_auth" or event["process"] == "su":
        _apply_su(event, message)
    elif "failed login" in lower:
        match = _FAILED_LOGIN_RE.search(message)
        event.update(kind="failure", result="failure", channel="login", service="login")
        if match:
            event.update(username=_clean(match.group("user")), terminal=match.group("tty"), source_ip=_clean(match.group("host")))
    elif auth_type == "logout":
        event.update(kind="logout", result="success")
    elif auth_type in {"system_boot", "system_shutdown"}:
        event.update(kind=auth_type)


def _apply_su(event: dict, message: str) -> None:
    event["service"] = "su"
    match = _SU_RESULT_RE.search(message)
    if match:
        ok = match.group("result").lower() == "successful"
        event.update(kind="su", result="success" if ok else "failure", target=_clean(match.group("target")), by=_clean(match.group("by")))
        return
    match = _SU_SHORT_RE.search(message.strip())
    if match:
        event.update(kind="su", result="success" if match.group("sign") == "+" else "failure",
                     target=_clean(match.group("target")), by=_clean(match.group("by")), terminal=match.group("tty"))
        return
    if "authentication failure" in message.lower():
        user = _PAM_USER_RE.search(message)
        event.update(kind="su", result="failure", by=_clean(user.group(1)) if user else "")


def _account_change(event: dict, message: str) -> bool:
    for action, pattern in _ACCOUNT_PATTERNS:
        match = pattern.search(message)
        if not match:
            continue
        groups = {key: _clean(value) for key, value in match.groupdict().items() if value is not None}
        event.update(kind="account_change", result="success", service=event["process"] or "account")
        event["change"] = {"action": action, **groups}
        event["username"] = groups.get("account", "")
        event["by"] = groups.get("by", "")
        return True
    return False


def _event_from_doc(doc: dict, uid_names: dict[str, str]) -> dict | None:
    carrier = _carrier(doc)
    linux = doc.get("linux") or {}
    event = _base_event(doc, carrier)
    message = event["message"]
    if carrier == "audit":
        _apply_audit(event, linux, uid_names)
        return event
    if carrier == "lastlog":
        event.update(kind="lastlog", result="success", service="lastlog", username=_clean(linux.get("username")),
                     source_ip=_clean(linux.get("source_ip") or linux.get("lastlog_host")), terminal=_clean(linux.get("terminal") or linux.get("lastlog_tty")))
        return event
    if carrier in {"wtmp", "btmp"}:
        auth_type = str(linux.get("auth_event_type") or linux.get("event_action") or "")
        event.update(username=_clean(linux.get("username")), source_ip=_clean(linux.get("source_ip")), terminal=_clean(linux.get("terminal")), service="login")
        if auth_type == "login_failure":
            event.update(kind="failure", result="failure", channel="btmp")
        elif auth_type == "login_success":
            event.update(kind="login", result="success", channel="wtmp")
            if event["terminal"].startswith(("pts", "ssh")) and event["source_ip"]:
                event["service"] = "sshd"
        elif auth_type == "logout":
            event.update(kind="logout", result="success")
        elif auth_type in {"system_boot", "system_shutdown"}:
            event["kind"] = auth_type
        return event
    if event["process"].lower() in _ACCOUNT_PROCESSES and _account_change(event, message):
        return event
    if carrier == "journal" or not linux.get("auth_event_type"):
        fields = classify_auth_message(message, event["process"] or None)
    else:
        fields = linux
    _apply_auth_fields(event, fields, message)
    return event


def _apply_audit(event: dict, linux: dict, uid_names: dict[str, str]) -> None:
    audit_type = str(linux.get("audit_type") or "")
    res = str(linux.get("audit_res") or "").lower()
    ok = res in {"success", "yes", "1"}
    exe = str(linux.get("exe") or "")
    acct = _clean(linux.get("audit_acct"))
    audit_id = _clean(linux.get("audit_id"))
    auid = _clean(linux.get("auid"))
    event.update(service=_service_name(exe) or "audit", source_ip=_clean(linux.get("audit_addr") or linux.get("audit_hostname")),
                 terminal=_clean(linux.get("audit_terminal")), channel="audit")
    name = acct or uid_names.get(audit_id, audit_id)
    if audit_type == "USER_AUTH":
        if not ok:
            event.update(kind="failure", result="failure", username=name)
        else:
            event.update(kind="auth_ok", result="success", username=name)
    elif audit_type == "USER_LOGIN":
        event.update(kind="login" if ok else "failure", result="success" if ok else "failure", username=name)
    elif audit_type in {"USER_START", "USER_END"}:
        event.update(kind="session_open" if audit_type == "USER_START" else "session_close", result="success", username=name,
                     by=uid_names.get(auid, auid) if auid and auid != "4294967295" else "")
    elif audit_type == "USER_CMD":
        event.update(kind="sudo", result="success" if ok else "failure", service="sudo",
                     username=uid_names.get(auid, auid) if auid and auid != "4294967295" else uid_names.get(_clean(linux.get("uid")), ""),
                     target="root", command=str(linux.get("command") or ""), cwd=str(linux.get("cwd") or ""))
    else:
        action = {
            "ADD_USER": "user_created", "DEL_USER": "user_deleted", "ADD_GROUP": "group_created", "DEL_GROUP": "group_deleted",
            "USER_CHAUTHTOK": "password_changed",
        }.get(audit_type, str(linux.get("audit_op") or audit_type).lower())
        event.update(kind="account_change", result="success" if ok or not res else "failure", username=name, service="audit")
        event["change"] = {"action": action, "account": name}


# ---------------------------------------------------------------------------
# Accounts known to the host
# ---------------------------------------------------------------------------

def _identity_accounts(docs: list[dict]) -> dict[str, dict]:
    accounts: dict[str, dict] = {}
    for doc in docs:
        linux = doc.get("linux") or {}
        if linux.get("superseded_backup"):
            continue
        name = _clean(linux.get("username"))
        if not name:
            continue
        uid = _clean(linux.get("uid"))
        accounts[name] = {"uid": int(uid) if uid.isdigit() else None, "shell": _clean(linux.get("shell"))}
    return accounts


def _account_kind(name: str, uid: int | None) -> str:
    if name == "root" or uid == 0:
        return "root"
    if uid is None:
        return "unknown"
    return "human" if 1000 <= uid < 60000 else "system"


def _login_shell(shell: str) -> bool | None:
    if not shell:
        return None
    return not any(marker in shell for marker in _NON_LOGIN_SHELLS)


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def _apply_filters(events: list[dict], filters: dict[str, Any]) -> list[dict]:
    username = filters.get("username")
    source_ip = filters.get("source_ip")
    result = filters.get("result")
    service = filters.get("service")
    time_from = filters.get("time_from")
    time_to = filters.get("time_to")

    def keep(event: dict) -> bool:
        if username and username not in {event["username"], event["target"], event["by"]}:
            return False
        if source_ip and event["source_ip"] != source_ip:
            return False
        if result and event["result"] != result:
            return False
        if service and service.lower() not in {event["service"], event["process"].lower()}:
            return False
        for key in ("evidence_id", "host_id"):
            if filters.get(key) and str(event.get(key) or "") != str(filters[key]):
                return False
        if time_from and event["_dt"] and event["_dt"] < time_from:
            return False
        if time_to and event["_dt"] and event["_dt"] > time_to:
            return False
        return True

    return [event for event in events if keep(event)]


def _infer_pam_users(events: list[dict]) -> None:
    """pam_unix failure lines often lack user=/rhost=; the explicit failure of the same PID has them."""
    by_pid: dict[tuple, dict] = {}
    for event in events:
        if event["kind"] == "failure" and event["channel"] in {"explicit", "btmp", "audit"} and event["pid"] and event["username"]:
            by_pid.setdefault((event["evidence_id"], event["pid"]), event)
    for event in events:
        if event["kind"] == "failure" and event["pid"] and (not event["username"] or not event["source_ip"]):
            reference = by_pid.get((event["evidence_id"], event["pid"]))
            if reference:
                event["username"] = event["username"] or reference["username"]
                event["source_ip"] = event["source_ip"] or reference["source_ip"]


def _cluster(items: list[dict], gap: timedelta) -> list[list[dict]]:
    ordered = sorted((item for item in items if item.get("_dt")), key=lambda item: item["_dt"])
    clusters: list[list[dict]] = []
    for item in ordered:
        if clusters and item["_dt"] - clusters[-1][-1]["_dt"] <= gap:
            clusters[-1].append(item)
        else:
            clusters.append([item])
    return clusters


def _most_common(values: list[str]) -> str:
    counted = Counter(value for value in values if value)
    return counted.most_common(1)[0][0] if counted else ""


def _attempts(events: list[dict]) -> list[dict]:
    """Failed attempts, one record per connection with every carrier collapsed into it."""
    failures = [event for event in events if event["kind"] == "failure"]
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for event in failures:
        if event["pid"]:
            key: tuple = (event["evidence_id"], "pid", event["pid"])
        else:
            second = event["_dt"].replace(microsecond=0) if event["_dt"] else None
            key = (event["evidence_id"], "nopid", event["username"], event["source_ip"], event["terminal"], second)
        groups[key].append(event)
    attempts: list[dict] = []
    for items in groups.values():
        for cluster in _cluster(items, _CONNECTION_GAP) or [items]:
            channels: Counter = Counter()
            for item in cluster:
                channels[item["channel"] or "other"] += int(item["count"] or 1)
            explicit = [item for item in cluster if item["channel"] == "explicit"] or cluster
            times = [item["_dt"] for item in cluster if item["_dt"]]
            attempts.append({
                "count": max(channels.values()),
                "channels": dict(channels),
                "username": _most_common([item["username"] for item in explicit]) or _most_common([item["username"] for item in cluster]),
                "source_ip": _most_common([item["source_ip"] for item in cluster]),
                "service": _most_common([item["service"] for item in explicit]) or _most_common([item["service"] for item in cluster]),
                "terminal": _most_common([item["terminal"] for item in cluster]),
                "_dt": min(times) if times else None,
                "_last": max(times) if times else None,
                "event_ids": [item["id"] for item in cluster[:3]],
                "evidence_id": cluster[0]["evidence_id"],
            })
    return attempts


def _logins(events: list[dict]) -> list[dict]:
    """Successful logins, each written once whatever the number of carriers that recorded it."""
    primary = [event for event in events if event["kind"] == "login" and event["channel"] == "auth"]
    secondary = [event for event in events if event["kind"] == "login" and event["channel"] in {"audit", "wtmp"}]
    opens = [event for event in events if event["kind"] == "session_open" and event["service"] not in _NON_LOGIN_SESSION_SERVICES]
    logins: list[dict] = []
    for event in sorted(primary, key=lambda item: item["_dt"] or datetime.min.replace(tzinfo=timezone.utc)):
        logins.append(_new_login(event))
    for event in sorted(secondary + opens, key=lambda item: item["_dt"] or datetime.min.replace(tzinfo=timezone.utc)):
        match = _matching_login(logins, event)
        if match:
            match["carriers"].add(event["carrier"])
            match["event_ids"].append(event["id"])
            if event["carrier"] == "wtmp":
                match["wtmp_terminal"] = event["terminal"]
                match["wtmp_pid"] = event["pid"]
            if event["kind"] == "session_open" and event["pid"]:
                match["session_pids"].add(event["pid"])
            match["terminal"] = match["terminal"] or event["terminal"]
            match["source_ip"] = match["source_ip"] or event["source_ip"]
            continue
        login = _new_login(event)
        if event["kind"] == "session_open":
            login["session_pids"].add(event["pid"])
        if event["carrier"] == "wtmp":
            login["wtmp_terminal"] = event["terminal"]
            login["wtmp_pid"] = event["pid"]
        logins.append(login)
    return logins


def _new_login(event: dict) -> dict:
    return {
        "id": f"login-{event['id']}",
        "username": event["username"],
        "source_ip": event["source_ip"],
        "source_port": event["source_port"],
        "service": event["service"] or "login",
        "method": event["method"],
        "terminal": event["terminal"],
        "pid": event["pid"],
        "session_pids": {event["pid"]} if event["pid"] else set(),
        "wtmp_terminal": "",
        "wtmp_pid": "",
        "_dt": event["_dt"],
        "carriers": {event["carrier"]},
        "event_ids": [event["id"]],
        "evidence_id": event["evidence_id"],
        "host": event["host"],
    }


def _matching_login(logins: list[dict], event: dict) -> dict | None:
    if not event["_dt"]:
        return None
    for login in reversed(logins):
        if not login["_dt"] or login["username"] != event["username"] or login["evidence_id"] != event["evidence_id"]:
            continue
        if abs(login["_dt"] - event["_dt"]) > _LOGIN_MERGE_WINDOW:
            continue
        if login["source_ip"] and event["source_ip"] and login["source_ip"] != event["source_ip"]:
            continue
        return login
    return None


def _session_kind(login: dict) -> str:
    service = login["service"]
    terminal = login["terminal"] or login["wtmp_terminal"]
    if service == "sshd" or terminal.startswith("ssh"):
        return "ssh"
    if any(name in service for name in ("gdm", "lightdm", "sddm", "xdm", "xrdp")) or terminal.startswith(":"):
        return "graphical"
    if service == "login" or terminal.startswith("tty"):
        return "console"
    return "other"


def _sessions(logins: list[dict], events: list[dict]) -> list[dict]:
    closes = [event for event in events if event["kind"] == "session_close" and event["_dt"]]
    logouts = [event for event in events if event["kind"] == "logout" and event["_dt"]]
    restarts = sorted((event for event in events if event["kind"] in {"system_boot", "system_shutdown"} and event["_dt"]), key=lambda event: event["_dt"])
    used: set = set()
    sessions: list[dict] = []
    for login in sorted(logins, key=lambda item: item["_dt"] or datetime.min.replace(tzinfo=timezone.utc)):
        start = login["_dt"]
        end_event = None
        # PIDs are reused after a restart: a close or logout written after the next boot belongs
        # to another process, however well its PID or terminal matches.
        next_restart = next((event["_dt"] for event in restarts if event["evidence_id"] == login["evidence_id"] and start and event["_dt"] > start), None)
        if start:
            candidates = [event for event in closes if event["id"] not in used and event["evidence_id"] == login["evidence_id"]
                          and event["pid"] in login["session_pids"] and event["_dt"] >= start and (not next_restart or event["_dt"] <= next_restart)
                          and (not event["username"] or event["username"] == login["username"])]
            if not candidates and login["wtmp_terminal"]:
                candidates = [event for event in logouts if event["id"] not in used and event["evidence_id"] == login["evidence_id"]
                              and event["terminal"] == login["wtmp_terminal"] and event["_dt"] >= start and (not next_restart or event["_dt"] <= next_restart)
                              and (not login["wtmp_pid"] or not event["pid"] or event["pid"] == login["wtmp_pid"])]
            end_event = min(candidates, key=lambda event: event["_dt"], default=None)
        status = "closed"
        if end_event:
            used.add(end_event["id"])
        elif start:
            # No logout written: a later shutdown or boot of the same host still bounds the session.
            end_event = next((event for event in restarts if event["evidence_id"] == login["evidence_id"] and event["_dt"] > start), None)
            status = "ended_by_restart" if end_event else "no_close_record"
        end = end_event["_dt"] if end_event else None
        sessions.append({
            "id": login["id"].replace("login-", "session-", 1),
            "kind": _session_kind(login),
            "username": login["username"],
            "source_ip": login["source_ip"],
            "source_port": login["source_port"],
            "service": login["service"],
            "method": login["method"],
            "terminal": login["terminal"] or login["wtmp_terminal"],
            "host": login["host"],
            "start": _iso(start),
            "end": _iso(end),
            "duration_seconds": int((end - start).total_seconds()) if end and start else None,
            "status": status,
            "carriers": sorted(login["carriers"]),
            "event_ids": login["event_ids"][:5],
        })
    return sorted(sessions, key=lambda item: item["start"] or "", reverse=True)


def _campaigns(attempts: list[dict], logins: list[dict]) -> list[dict]:
    by_source: dict[str, list[dict]] = defaultdict(list)
    for attempt in attempts:
        by_source[attempt["source_ip"] or "(local)"].append(attempt)
    campaigns: list[dict] = []
    for source, items in by_source.items():
        for cluster in _cluster(items, _CAMPAIGN_GAP):
            total = sum(item["count"] for item in cluster)
            accounts = Counter()
            for item in cluster:
                accounts[item["username"] or "(unknown)"] += item["count"]
            first, last = cluster[0]["_dt"], max(item["_last"] or item["_dt"] for item in cluster)
            if len(accounts) >= 5 and total / len(accounts) <= 3:
                pattern = "password_spray"
            elif total >= 10:
                pattern = "brute_force"
            elif total >= 5:
                pattern = "repeated_failures"
            else:
                pattern = "failed_logins"
            success = None
            if source != "(local)":
                following = [login for login in logins if login["source_ip"] == source and login["_dt"] and first <= login["_dt"] <= last + _SUCCESS_LOOKAHEAD]
                success = min(following, key=lambda login: login["_dt"], default=None)
            campaigns.append({
                "id": f"campaign-{source}-{int(first.timestamp())}",
                "source_ip": source,
                "pattern": pattern,
                "first_seen": _iso(first),
                "last_seen": _iso(last),
                "attempts": total,
                "accounts": [{"username": name, "attempts": count} for name, count in accounts.most_common(20)],
                "account_count": len(accounts),
                "services": sorted({item["service"] for item in cluster if item["service"]}),
                "followed_by_success": bool(success),
                "success_account": success["username"] if success else None,
                "success_time": _iso(success["_dt"]) if success else None,
                "seconds_to_success": int((success["_dt"] - last).total_seconds()) if success else None,
                "success_during_campaign": bool(success and success["_dt"] <= last),
                "event_ids": [event_id for item in cluster[:2] for event_id in item["event_ids"]][:4],
            })
    return sorted(campaigns, key=lambda item: (not item["followed_by_success"], -item["attempts"]))


def _distributed(attempts: list[dict]) -> list[dict]:
    by_account: dict[str, list[dict]] = defaultdict(list)
    for attempt in attempts:
        if attempt["username"] and attempt["source_ip"]:
            by_account[attempt["username"]].append(attempt)
    findings = []
    for account, items in by_account.items():
        for cluster in _cluster(items, timedelta(hours=1)):
            sources = {item["source_ip"] for item in cluster}
            total = sum(item["count"] for item in cluster)
            if len(sources) >= 5 and total >= 10:
                findings.append({"account": account, "sources": sorted(sources), "attempts": total,
                                 "first": cluster[0]["_dt"], "last": cluster[-1]["_dt"], "event_ids": cluster[0]["event_ids"][:3]})
    return findings


def _privilege(events: list[dict]) -> list[dict]:
    """sudo commands and denials, and su switches -- one su per process however many lines it wrote."""
    rows: list[dict] = []
    su_by_pid: dict[tuple, dict] = {}
    sudo_denied_by_pid: dict[tuple, dict] = {}
    for event in sorted((event for event in events if event["kind"] in {"sudo", "su"} or (event["kind"] == "session_open" and event["service"] in {"su", "su-l"})),
                        key=lambda item: item["_dt"] or datetime.min.replace(tzinfo=timezone.utc)):
        if event["kind"] == "sudo":
            denied = event["result"] == "failure"
            reason = _SUDO_DENIED_RE.search(event["message"])
            if denied and event["pid"]:
                # sudo writes a denial as its PAM line plus its own summary: one denial.
                previous = sudo_denied_by_pid.get((event["evidence_id"], event["pid"]))
                if previous:
                    previous["reason"] = previous["reason"] or (reason.group(1) if reason else "")
                    previous["command"] = previous["command"] or event["command"]
                    previous["user"] = previous["user"] or event["username"]
                    continue
            rows.append({
                "id": event["id"], "time": event["time"], "tool": "sudo", "user": event["username"], "target": event["target"] or "root",
                "command": event["command"], "cwd": event["cwd"], "terminal": event["terminal"],
                "result": "denied" if denied else "allowed", "reason": reason.group(1) if reason and denied else "",
                "carrier": event["carrier"],
            })
            if denied and event["pid"]:
                sudo_denied_by_pid[(event["evidence_id"], event["pid"])] = rows[-1]
            continue
        key = (event["evidence_id"], event["pid"]) if event["pid"] else (event["evidence_id"], event["id"])
        row = su_by_pid.get(key)
        if not row:
            row = {"id": event["id"], "time": event["time"], "tool": "su", "user": "", "target": "", "command": "", "cwd": "",
                   "terminal": "", "result": "allowed", "reason": "", "carrier": event["carrier"]}
            su_by_pid[key] = row
            rows.append(row)
        if event["kind"] == "session_open":
            # "session opened for user root by mail(uid=0)": the login name is the real actor,
            # where "Successful su for root by root" names the current uid.
            row["target"] = row["target"] or event["username"]
            if event["by"]:
                row["user"] = event["by"]
        else:
            row["target"] = event["target"] or row["target"]
            row["user"] = row["user"] or event["by"]
            row["terminal"] = row["terminal"] or event["terminal"]
            if event["result"] == "failure":
                row["result"] = "denied"
    return sorted(rows, key=lambda item: item["time"] or "", reverse=True)


def _account_changes(events: list[dict], accounts: dict[str, dict]) -> list[dict]:
    rows: list[dict] = []
    seen: set = set()
    for event in sorted((event for event in events if event["kind"] == "account_change"), key=lambda item: item["_dt"] or datetime.min.replace(tzinfo=timezone.utc)):
        change = dict(event.get("change") or {})
        action = change.pop("action", "change")
        second = event["time"][:19] if event["time"] else ""
        key = (event["evidence_id"], action, change.get("account"), change.get("group"), second)
        if key in seen:
            continue
        seen.add(key)
        account = change.get("account") or ""
        group = change.get("group") or ""
        privileged = (action in {"group_member_added", "group_members_set"} and group in _PRIVILEGED_GROUPS) or (action == "user_created" and change.get("uid") == "0")
        rows.append({
            "id": event["id"], "time": event["time"], "action": action, "account": account, "group": group,
            "by": change.get("by") or event["by"], "details": {key: value for key, value in change.items() if key not in {"account", "group", "by"}},
            "privileged": privileged, "tool": event["process"] or event["service"], "carrier": event["carrier"], "message": event["message"][:300],
            "account_kind": _account_kind(account, (accounts.get(account) or {}).get("uid")) if account else "",
        })
    return sorted(rows, key=lambda item: item["time"] or "", reverse=True)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _finding(severity: str, kind: str, title: str, detail: str, *, time: datetime | str | None = None, account: str = "", source_ip: str = "", event_ids: list | None = None) -> dict:
    stamp = _iso(time) if isinstance(time, datetime) else time
    return {"id": f"{kind}-{account}-{source_ip}-{stamp}", "severity": severity, "kind": kind, "title": title, "detail": detail,
            "time": stamp, "account": account, "source_ip": source_ip, "event_ids": [event_id for event_id in (event_ids or []) if event_id][:5]}


def _findings(campaigns, distributed, logins, privilege, changes, accounts, coverage) -> list[dict]:
    findings: list[dict] = []
    pattern_label = {"password_spray": "password spraying", "brute_force": "brute force", "repeated_failures": "repeated failures"}
    for campaign in campaigns:
        if campaign["pattern"] not in pattern_label:
            continue
        label = pattern_label[campaign["pattern"]]
        accounts_text = ", ".join(item["username"] for item in campaign["accounts"][:5])
        if campaign["followed_by_success"]:
            when = "during the attack" if campaign["success_during_campaign"] else f"{campaign['seconds_to_success']} s after the last failure"
            findings.append(_finding("critical", "success_after_attack", f"Successful login after {label} from {campaign['source_ip']}",
                                     f"{campaign['attempts']} failed attempts against {campaign['account_count']} account(s) ({accounts_text}), then {campaign['success_account']} logged in {when}.",
                                     time=campaign["success_time"], account=campaign["success_account"] or "", source_ip=campaign["source_ip"], event_ids=campaign["event_ids"]))
        elif campaign["pattern"] != "repeated_failures":
            findings.append(_finding("medium", campaign["pattern"], f"{label.capitalize()} from {campaign['source_ip']}",
                                     f"{campaign['attempts']} failed attempts against {campaign['account_count']} account(s) ({accounts_text}) between {campaign['first_seen']} and {campaign['last_seen']}; no successful login from this source followed.",
                                     time=campaign["first_seen"], source_ip=campaign["source_ip"], event_ids=campaign["event_ids"]))
    for item in distributed:
        findings.append(_finding("high", "distributed_attack", f"Distributed attack on account {item['account']}",
                                 f"{item['attempts']} failed attempts from {len(item['sources'])} sources within one hour.",
                                 time=item["first"], account=item["account"], event_ids=item["event_ids"]))
    flagged_system: set = set()
    for login in logins:
        info = accounts.get(login["username"]) or {}
        kind = _account_kind(login["username"], info.get("uid"))
        if kind == "system" and login["username"] not in flagged_system:
            flagged_system.add(login["username"])
            count = sum(1 for other in logins if other["username"] == login["username"])
            findings.append(_finding("high", "system_account_login", f"Interactive login by system account {login['username']}",
                                     f"UID {info.get('uid')}: system accounts do not normally log in. {count} login(s), first from {login['source_ip'] or login['terminal'] or 'local'}.",
                                     time=login["_dt"], account=login["username"], source_ip=login["source_ip"], event_ids=login["event_ids"]))
    root_remote = [login for login in logins if login["username"] == "root" and login["source_ip"] and login["service"] == "sshd"]
    if root_remote:
        sources = sorted({login["source_ip"] for login in root_remote})
        findings.append(_finding("medium", "root_remote_login", "Direct remote root login",
                                 f"{len(root_remote)} SSH login(s) as root from {', '.join(sources[:5])}.",
                                 time=root_remote[0]["_dt"], account="root", source_ip=sources[0], event_ids=root_remote[0]["event_ids"]))
    first_password: dict[str, datetime] = {}
    flagged_key: set = set()
    for login in sorted((login for login in logins if login["_dt"]), key=lambda item: item["_dt"]):
        if login["method"] == "password":
            first_password.setdefault(login["username"], login["_dt"])
        elif login["method"] == "publickey" and login["username"] in first_password and login["username"] not in flagged_key:
            flagged_key.add(login["username"])
            findings.append(_finding("medium", "key_after_password", f"Key-based access appears for {login['username']}",
                                     f"The account logged in with a password before; the first public-key login came from {login['source_ip'] or 'an unknown source'}. A newly planted authorized key is a common persistence step.",
                                     time=login["_dt"], account=login["username"], source_ip=login["source_ip"], event_ids=login["event_ids"]))
    for change in changes:
        if change["privileged"]:
            what = f"added to {change['group']}" if change["group"] else "created with UID 0"
            findings.append(_finding("critical" if change["action"] == "user_created" else "high", "privileged_account_change",
                                     f"{change['account'] or 'Account'} {what}", f"{change['message']}",
                                     time=change["time"], account=change["account"], event_ids=[change["id"]]))
        elif change["action"] == "shell_changed" and change["account_kind"] in {"system", "root"} and _login_shell(change["details"].get("shell", "")):
            findings.append(_finding("high", "system_account_shell", f"System account {change['account']} given a login shell",
                                     change["message"], time=change["time"], account=change["account"], event_ids=[change["id"]]))
        elif change["action"] == "user_created" and change["details"].get("uid", "").isdigit() and int(change["details"]["uid"]) < 1000 and _login_shell(change["details"].get("shell", "")):
            findings.append(_finding("medium", "system_uid_with_shell", f"Account {change['account']} created with a system UID and a login shell",
                                     change["message"], time=change["time"], account=change["account"], event_ids=[change["id"]]))
    denied = Counter(row["user"] for row in privilege if row["result"] == "denied" and row["tool"] == "sudo")
    for user, count in denied.items():
        row = next(row for row in privilege if row["user"] == user and row["result"] == "denied")
        findings.append(_finding("medium", "sudo_denied", f"sudo denied for {user or 'unknown user'}", f"{count} denied sudo request(s); the latest: {row['reason'] or 'denied'}.",
                                 time=row["time"], account=user, event_ids=[row["id"]]))
    findings.extend(coverage.get("findings") or [])
    return sorted(findings, key=lambda item: (_SEVERITY_ORDER.get(item["severity"], 9), item["time"] or ""))


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------

_CARRIER_LABELS = {"auth_log": "auth.log / secure", "journal": "systemd journal", "audit": "auditd", "wtmp": "wtmp", "btmp": "btmp", "lastlog": "lastlog"}


def _coverage(events: list[dict], logins: list[dict]) -> dict:
    by_carrier: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        by_carrier[event["carrier"]].append(event)
    sources = []
    for carrier, label in _CARRIER_LABELS.items():
        items = by_carrier.get(carrier) or []
        times = [event["_dt"] for event in items if event["_dt"]]
        sources.append({"carrier": carrier, "label": label, "events": len(items), "files": len({event["source_file"] for event in items}),
                        "first": _iso(min(times)) if times else None, "last": _iso(max(times)) if times else None})
    findings = []
    text_times = [event["_dt"] for carrier in ("auth_log", "journal") for event in by_carrier.get(carrier, []) if event["_dt"]]
    if text_times:
        text_first, text_last = min(text_times), max(text_times)
        record_logins = [login for login in logins if login["carriers"] <= {"wtmp", "audit"} and login["_dt"]]
        uncovered = [login for login in record_logins if text_first <= login["_dt"] <= text_last]
        if uncovered:
            findings.append(_finding("medium", "login_missing_from_logs", f"{len(uncovered)} login(s) recorded only in wtmp/auditd",
                                     "These logins fall inside the period the authentication logs cover, yet no log line records them: lines may have been removed or never written (rate limiting).",
                                     time=uncovered[0]["_dt"], account=uncovered[0]["username"], source_ip=uncovered[0]["source_ip"], event_ids=uncovered[0]["event_ids"]))
        later = [login for login in record_logins if login["_dt"] > text_last + timedelta(days=1)]
        if later:
            findings.append(_finding("medium", "logs_end_early", "Authentication logs end before the login records",
                                     f"auth.log/journal stop at {_iso(text_last)}, but {len(later)} later login(s) appear in wtmp/auditd, up to {_iso(max(login['_dt'] for login in later))}. The logs may have been rotated away or cleared.",
                                     time=text_last, event_ids=later[0]["event_ids"]))
    elif logins:
        findings.append(_finding("low", "no_text_auth_logs", "No auth.log, secure or journal authentication entries",
                                 "Only binary login records (wtmp/btmp/lastlog) or auditd were found: failed SSH details, sudo and account changes cannot be seen."))
    return {"sources": sources, "findings": findings}


# ---------------------------------------------------------------------------
# Rollups
# ---------------------------------------------------------------------------

def _source_rows(attempts, logins, campaigns) -> list[dict]:
    rows: dict[str, dict] = {}

    def row_for(source: str) -> dict:
        return rows.setdefault(source, {"source_ip": source, "first_seen": None, "last_seen": None, "failed_attempts": 0, "accounts_tried": Counter(),
                                        "logins": 0, "login_accounts": set(), "pattern": "none", "campaigns": 0, "first_login": None, "_times": []})

    for attempt in attempts:
        row = row_for(attempt["source_ip"] or "(local)")
        row["failed_attempts"] += attempt["count"]
        row["accounts_tried"][attempt["username"] or "(unknown)"] += attempt["count"]
        row["_times"].extend(time for time in (attempt["_dt"], attempt["_last"]) if time)
    for login in logins:
        row = row_for(login["source_ip"] or "(local)")
        row["logins"] += 1
        row["login_accounts"].add(login["username"])
        if login["_dt"]:
            row["_times"].append(login["_dt"])
            row["first_login"] = min(filter(None, [row["first_login"], login["_dt"]]))
    rank = {"none": 0, "failed_logins": 1, "repeated_failures": 2, "brute_force": 3, "password_spray": 3}
    for campaign in campaigns:
        row = row_for(campaign["source_ip"])
        row["campaigns"] += 1
        if rank[campaign["pattern"]] > rank[row["pattern"]]:
            row["pattern"] = campaign["pattern"]
    result = []
    for row in rows.values():
        times = row.pop("_times")
        tried = row.pop("accounts_tried")
        result.append({**row, "first_seen": _iso(min(times)) if times else None, "last_seen": _iso(max(times)) if times else None,
                       "accounts_tried": [{"username": name, "attempts": count} for name, count in tried.most_common(10)],
                       "accounts_tried_count": len(tried), "login_accounts": sorted(row["login_accounts"]), "first_login": _iso(row["first_login"])})
    return sorted(result, key=lambda item: (-(item["logins"] > 0 and item["failed_attempts"] > 0), -item["failed_attempts"], -item["logins"]))


def _account_rows(attempts, logins, privilege, changes, events, accounts) -> list[dict]:
    rows: dict[str, dict] = {}

    def row_for(name: str) -> dict:
        info = accounts.get(name) or {}
        return rows.setdefault(name, {"username": name, "uid": info.get("uid"), "shell": info.get("shell") or "",
                                      "kind": _account_kind(name, info.get("uid")), "known_account": name in accounts,
                                      "logins": 0, "failed_attempts": 0, "methods": set(), "sources": Counter(), "first_login": None, "last_login": None,
                                      "last_failure": None, "sudo_commands": 0, "sudo_denied": 0, "su_to": Counter(), "changes": 0, "lastlog": None})

    for attempt in attempts:
        if attempt["username"]:
            row = row_for(attempt["username"])
            row["failed_attempts"] += attempt["count"]
            row["last_failure"] = max(filter(None, [row["last_failure"], attempt["_last"] or attempt["_dt"]]), default=None)
    for login in logins:
        if not login["username"]:
            continue
        row = row_for(login["username"])
        row["logins"] += 1
        if login["method"]:
            row["methods"].add(login["method"])
        row["sources"][login["source_ip"] or "(local)"] += 1
        if login["_dt"]:
            row["first_login"] = min(filter(None, [row["first_login"], login["_dt"]]))
            row["last_login"] = max(filter(None, [row["last_login"], login["_dt"]]))
    for item in privilege:
        if not item["user"]:
            continue
        row = row_for(item["user"])
        if item["tool"] == "sudo":
            row["sudo_denied" if item["result"] == "denied" else "sudo_commands"] += 1
        else:
            row["su_to"][item["target"] or "?"] += 1
    for change in changes:
        if change["account"]:
            row_for(change["account"])["changes"] += 1
    for event in events:
        if event["kind"] == "lastlog" and event["username"]:
            row_for(event["username"])["lastlog"] = {"time": event["time"], "source_ip": event["source_ip"], "terminal": event["terminal"]}
    result = []
    for row in rows.values():
        result.append({**row, "methods": sorted(row["methods"]), "sources": [{"source_ip": ip, "logins": count} for ip, count in row["sources"].most_common(10)],
                       "first_login": _iso(row["first_login"]), "last_login": _iso(row["last_login"]), "last_failure": _iso(row["last_failure"]),
                       "su_to": [{"target": target, "count": count} for target, count in row["su_to"].most_common()]})
    return sorted(result, key=lambda item: (-item["logins"], -item["failed_attempts"], item["username"]))


def _failure_groups(attempts: list[dict]) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for attempt in attempts:
        key = (attempt["source_ip"] or "(local)", attempt["username"] or "(unknown)", attempt["service"] or "?")
        group = groups.setdefault(key, {"source_ip": key[0], "username": key[1], "service": key[2], "attempts": 0, "connections": 0, "_times": [], "event_ids": []})
        group["attempts"] += attempt["count"]
        group["connections"] += 1
        group["_times"].extend(time for time in (attempt["_dt"], attempt["_last"]) if time)
        if len(group["event_ids"]) < 3:
            group["event_ids"].extend(attempt["event_ids"][:1])
    result = []
    for group in groups.values():
        times = group.pop("_times")
        result.append({**group, "first_seen": _iso(min(times)) if times else None, "last_seen": _iso(max(times)) if times else None})
    return sorted(result, key=lambda item: -item["attempts"])


_EVENT_GROUPS = {
    "logins": {"login"},
    "failures": {"failure", "failure_note"},
    "sessions": {"session_open", "session_close", "logout"},
    "privilege": {"sudo", "su"},
    "accounts": {"account_change"},
}


def _public_event(event: dict) -> dict:
    return {key: value for key, value in event.items() if not key.startswith("_") and key not in {"count", "channel"}}


def build_linux_auth_investigation(case_id: str, filters: dict[str, Any] | None = None, *, event_group: str | None = None, offset: int = 0, limit: int = 100) -> dict:
    filters = filters or {}
    docs, truncated = _fetch_auth_docs(case_id)
    identity_docs: list[dict] = []
    auth_docs: list[dict] = []
    for doc in docs:
        (identity_docs if str((doc.get("artifact") or {}).get("type") or "") == "linux_identity" else auth_docs).append(doc)
    accounts = _identity_accounts(identity_docs)
    uid_names = {str(info["uid"]): name for name, info in accounts.items() if info.get("uid") is not None}
    all_events = [event for doc in auth_docs for event in [_event_from_doc(doc, uid_names)] if event]
    events = _apply_filters(all_events, filters)
    _infer_pam_users(events)

    attempts = _attempts(events)
    logins = _logins(events)
    sessions = _sessions(logins, events)
    campaigns = _campaigns(attempts, logins)
    privilege = _privilege(events)
    changes = _account_changes(events, accounts)
    coverage = _coverage(all_events, _logins(all_events) if filters else logins)
    findings = _findings(campaigns, _distributed(attempts), logins, privilege, changes, accounts, coverage)

    listed = [event for event in events if event["kind"] in _EVENT_GROUPS.get(event_group or "", set())] if event_group else [event for event in events if event["kind"] != "other"]
    listed.sort(key=lambda item: item["time"] or "", reverse=True)
    times = [event["_dt"] for event in events if event["_dt"]]
    severity_counts = Counter(finding["severity"] for finding in findings)
    return {
        "case_id": case_id,
        "truncated": truncated,
        "overview": {
            "successful_logins": len(logins),
            "failed_attempts": sum(attempt["count"] for attempt in attempts),
            "accounts_with_logins": len({login["username"] for login in logins if login["username"]}),
            "accounts_targeted": len({attempt["username"] for attempt in attempts if attempt["username"]}),
            "source_ips": len({ip for ip in [attempt["source_ip"] for attempt in attempts] + [login["source_ip"] for login in logins] if ip}),
            "attack_campaigns": sum(1 for campaign in campaigns if campaign["pattern"] in {"brute_force", "password_spray"}),
            "sessions": len(sessions),
            "privileged_actions": len(privilege),
            "account_changes": len(changes),
            "findings": dict(severity_counts),
            "first_event": _iso(min(times)) if times else None,
            "last_event": _iso(max(times)) if times else None,
        },
        "coverage": coverage["sources"],
        "findings": findings,
        "accounts": _account_rows(attempts, logins, privilege, changes, events, accounts),
        "sources": _source_rows(attempts, logins, campaigns),
        "campaigns": campaigns,
        "sessions": sessions,
        "failures": _failure_groups(attempts),
        "privilege": privilege,
        "account_changes": changes,
        "events": {"total": len(listed), "offset": offset, "limit": limit, "items": [_public_event(event) for event in listed[offset:offset + limit]]},
    }
