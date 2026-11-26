"""Host User Fact observations from macOS dslocal account and group records.

A dslocal user record is the account store itself (like /etc/passwd on Linux or the SAM on
Windows), so it resolves through the same identity fields under its own source kind
``dslocal_account``. Group records give group definitions and memberships, which is how an
account's membership in ``admin`` (the group allowed to administer the Mac) shows up.
"""
from __future__ import annotations

from app.ingest.host_user_extraction import register_host_user_fact_extractor

ARTIFACT_FAMILY = "macos_accounts"


def _account_rows(macos: dict) -> list[dict]:
    attributes = {
        key: macos[key]
        for key in ("generated_uid", "account_created", "password_last_set", "last_failed_login", "failed_login_count", "hidden", "service_account")
        if macos.get(key) not in (None, "", False)
    }
    return [{
        "source_kind": "dslocal_account",
        "username": macos.get("username") or None,
        "uid": macos.get("uid") or None,
        "id_kind": "uid" if macos.get("uid") else None,
        "primary_gid": macos.get("gid") or None,
        "gecos": macos.get("gecos") or None,
        "home": macos.get("home") or None,
        "shell": macos.get("shell") or None,
        "attributes": attributes,
    }]


def _group_rows(macos: dict) -> list[dict]:
    group_name = macos.get("group_name") or None
    gid = macos.get("gid") or None
    rows = [{"source_kind": "group_definition", "username": None, "group_name": group_name, "group_gid": gid}]
    for member in macos.get("members") or []:
        member = str(member).strip()
        if member:
            rows.append({"source_kind": "group_membership", "username": member, "group_name": group_name, "group_gid": gid})
    return rows


@register_host_user_fact_extractor
def extract_macos_host_user_facts(documents: list[dict]) -> list[dict]:
    derived: list[dict] = []
    for doc in documents:
        macos = doc.get("macos") or {}
        if macos.get("artifact_family") != ARTIFACT_FAMILY:
            continue
        kind = macos.get("artifact_type")
        if kind == "local_user":
            field_rows = _account_rows(macos)
        elif kind == "local_group":
            field_rows = _group_rows(macos)
        else:
            continue
        parser = str((doc.get("artifact") or {}).get("parser") or "")
        source_path = macos.get("source_file") or doc.get("source_file")
        for field_row in field_rows:
            derived.append({
                "source_file": source_path,
                "artifact": {"parser": parser},
                "event_id": doc.get("event_id"),
                "host_user_fact": {**field_row, "parser": parser, "source_file": source_path},
            })
    return derived
