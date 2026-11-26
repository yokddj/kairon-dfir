"""Local accounts and groups from the directory service (``/private/var/db/dslocal/nodes/Default``).

On macOS ``/etc/passwd`` and ``/etc/group`` are only read in single-user mode; the accounts the
system actually uses are one property list per user and per group in dslocal. Every attribute is an
array. From a user record this keeps the name, uid, primary gid, home, shell, real name, generated
UID and hidden flag, plus what ``accountPolicyData`` (an embedded plist) says about the account's
creation, last password change and failed logins. Password hashes (``ShadowHashData``) and keys
are never read.

Each timed policy value becomes its own row (``account_created``, ``password_changed``,
``login_failed``) so it lands on the timeline; the account row itself carries the creation time when
there is one.
"""
from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Any

from app.ingest.macos.common import first_text, load_plist, original_path, unix_to_iso

ARTIFACT_FAMILY = "macos_accounts"
_HIDDEN_VALUES = {"1", "yes", "true"}


def _account_policy(value: Any) -> dict[str, Any]:
    raw = value[0] if isinstance(value, list) and value else value
    if not isinstance(raw, (bytes, bytearray)):
        return {}
    try:
        policy = plistlib.loads(bytes(raw))
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError):
        return {}
    return policy if isinstance(policy, dict) else {}


def _base(source_path: str, artifact_type: str) -> dict[str, Any]:
    return {
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_type": artifact_type,
        "source_file": source_path,
        "file_path": original_path(source_path),
    }


def parse_dslocal_user(path: Path, *, source_path: str) -> list[dict[str, Any]]:
    record = load_plist(path)
    if not isinstance(record, dict):
        return []
    username = first_text(record.get("name"))
    if not username:
        return []
    homes = [str(item) for item in record.get("home") or [] if isinstance(item, str)]
    policy = _account_policy(record.get("accountPolicyData"))
    created = unix_to_iso(policy.get("creationTime"))
    password_set = unix_to_iso(policy.get("passwordLastSetTime"))
    failed_at = unix_to_iso(policy.get("failedLoginTimestamp"))
    failed_count = policy.get("failedLoginCount")
    uid = first_text(record.get("uid"))
    # macOS gives people accounts UIDs from 501 up; below 500 are the system's own accounts, all
    # created with the OS. Their records stay searchable but their times stay off the timeline.
    system_account = uid.lstrip("-").isdigit() and int(uid) < 500
    account = {
        **_base(source_path, "local_user"),
        "username": username,
        "uid": uid,
        "gid": first_text(record.get("gid")),
        "home": homes[0] if homes else "",
        "shell": first_text(record.get("shell")),
        "gecos": first_text(record.get("realname")),
        "generated_uid": first_text(record.get("generateduid")),
        "hidden": first_text(record.get("IsHidden")).lower() in _HIDDEN_VALUES,
        "service_account": username.startswith("_"),
        "system_account": system_account,
        "account_created": created,
        "password_last_set": password_set,
        "failed_login_count": int(failed_count) if isinstance(failed_count, (int, float)) else None,
        "last_failed_login": failed_at,
        # The record itself is not an event; its creation is a row of its own below.
        "timestamp": None,
        "timestamp_status": "not_applicable",
        "event_action": "local_account",
    }
    kind = "service account" if account["service_account"] else "account"
    account["message"] = f"Local {kind} {username} (UID {uid or '?'})" + (f", home {account['home']}" if account["home"] else "")
    rows = [account]
    if created:
        rows.append({**_base(source_path, "account_event"), "username": username, "uid": uid, "system_account": system_account, "timestamp": created, "event_action": "account_created", "message": f"Local account {username} created"})
    if password_set:
        rows.append({**_base(source_path, "account_event"), "username": username, "uid": uid, "system_account": system_account, "timestamp": password_set, "event_action": "password_changed", "message": f"Password of {username} last set"})
    if failed_at:
        count = f" ({failed_count} consecutive failures)" if account["failed_login_count"] else ""
        rows.append({**_base(source_path, "account_event"), "username": username, "uid": uid, "system_account": system_account, "timestamp": failed_at, "event_action": "login_failed", "message": f"Last failed login for {username}{count}"})
    return rows


def parse_dslocal_group(path: Path, *, source_path: str) -> list[dict[str, Any]]:
    record = load_plist(path)
    if not isinstance(record, dict):
        return []
    group_name = first_text(record.get("name"))
    if not group_name:
        return []
    members = [str(item) for item in record.get("users") or [] if isinstance(item, str) and item.strip()]
    gid = first_text(record.get("gid"))
    return [{
        **_base(source_path, "local_group"),
        "group_name": group_name,
        "gid": gid,
        "members": members,
        "gecos": first_text(record.get("realname")),
        "event_action": "local_group",
        "message": f"Local group {group_name} (GID {gid or '?'}) members: {', '.join(members) if members else 'none'}",
    }]
