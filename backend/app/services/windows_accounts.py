"""One spelling per Windows account across sources.

Event logs, PSReadLine paths, task principals and memory tokens name the same
account differently: "MEGACORP\\alice", "alice", her SID; "SYSTEM",
"Local System", S-1-5-18. Grouping or filtering by user needs one spelling.
Nothing is guessed: a SID is named only from an event that carries both, and a
bare name gets a domain only when the case knows exactly one account by it.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Iterable

SID_RE = re.compile(r"^S-1(?:-\d+)+$", re.IGNORECASE)

_SERVICE_ACCOUNTS = {
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
    "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
}
_SERVICE_NAMES = {
    "system": "NT AUTHORITY\\SYSTEM",
    "local system": "NT AUTHORITY\\SYSTEM",
    "localsystem": "NT AUTHORITY\\SYSTEM",
    "local service": "NT AUTHORITY\\LOCAL SERVICE",
    "localservice": "NT AUTHORITY\\LOCAL SERVICE",
    "network service": "NT AUTHORITY\\NETWORK SERVICE",
    "networkservice": "NT AUTHORITY\\NETWORK SERVICE",
}

# Per-session virtual accounts: Desktop Window Manager and the font driver host.
_SESSION_ACCOUNT_RE = re.compile(r"^S-1-5-(90|96)-0-(\d+)$", re.IGNORECASE)
_SESSION_ACCOUNT_NAMES = {"90": "Window Manager\\DWM-{}", "96": "Font Driver Host\\UMFD-{}"}

# (SID field, domain field, user field) triples Windows events carry together.
_EVENT_ACCOUNT_FIELDS = (
    ("SubjectUserSid", "SubjectDomainName", "SubjectUserName"),
    ("TargetUserSid", "TargetDomainName", "TargetUserName"),
)


def service_account(value: str | None) -> str | None:
    """The NT AUTHORITY spelling of a built-in service account, if it is one."""
    text = str(value or "").strip()
    if not text:
        return None
    if text.upper() in _SERVICE_ACCOUNTS:
        return _SERVICE_ACCOUNTS[text.upper()]
    session = _SESSION_ACCOUNT_RE.match(text)
    if session:
        return _SESSION_ACCOUNT_NAMES[session.group(1)].format(session.group(2))
    bare = text.rsplit("\\", 1)[-1].strip().lower()
    domain = text.rsplit("\\", 1)[0].strip().lower() if "\\" in text else ""
    if domain in {"", "nt authority", "nt-autorität", "autorite nt"} and bare in _SERVICE_NAMES:
        return _SERVICE_NAMES[bare]
    return None


def _qualified(domain: Any, user: Any) -> str:
    domain_text = str(domain or "").strip()
    user_text = str(user or "").strip()
    if not user_text or user_text == "-":
        return ""
    return f"{domain_text}\\{user_text}" if domain_text and domain_text != "-" else user_text


def accounts_from_events(events: Iterable[dict[str, Any]]) -> dict[str, str]:
    """SID -> DOMAIN\\name, from events that record both."""
    names: dict[str, str] = {}
    for event in events:
        windows = event.get("windows") if isinstance(event.get("windows"), dict) else {}
        event_data = windows.get("event_data") if isinstance(windows.get("event_data"), dict) else {}
        for sid_field, domain_field, user_field in _EVENT_ACCOUNT_FIELDS:
            sid = str(event_data.get(sid_field) or "").strip().upper()
            name = _qualified(event_data.get(domain_field), event_data.get(user_field))
            if SID_RE.match(sid) and name and sid not in _SERVICE_ACCOUNTS:
                names.setdefault(sid, name)
        user = event.get("user") if isinstance(event.get("user"), dict) else {}
        sid = str(user.get("sid") or "").strip().upper()
        name = str(user.get("name") or "").strip()
        if "\\" not in name:
            name = _qualified(user.get("domain"), name)
        if SID_RE.match(sid) and name and not SID_RE.match(name) and sid not in _SERVICE_ACCOUNTS:
            names.setdefault(sid, name)
    return names


def canonical_accounts(values: Iterable[str], sid_names: dict[str, str]) -> dict[str, str]:
    """Map every spelling in ``values`` to the one shown for its account."""
    resolved: dict[str, str] = {}
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        if text == "-":  # Windows' placeholder for "no account"
            resolved[value] = ""
            continue
        resolved[value] = service_account(text) or sid_names.get(text.upper()) or text
    # A bare name takes the domain of the one qualified account the case has by
    # that name; with two (a local and a domain "admin") it stays as it is.
    domains_by_name: dict[str, set[str]] = defaultdict(set)
    for name in [*resolved.values(), *sid_names.values()]:
        if "\\" in name and not name.upper().startswith("NT AUTHORITY\\"):
            domain, bare = name.rsplit("\\", 1)
            domains_by_name[bare.lower()].add(f"{domain}\\{bare}")
    for value, name in resolved.items():
        if name and "\\" not in name and not SID_RE.match(name):
            candidates = {candidate.lower(): candidate for candidate in domains_by_name.get(name.lower(), set())}
            if len(candidates) == 1:
                resolved[value] = next(iter(candidates.values()))
    return resolved
