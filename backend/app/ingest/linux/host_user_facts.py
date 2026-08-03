"""Host User Fact derived extractor for Linux identity data.

Linux passwd/group/shadow/lastlog/sudoers artifacts are normalized by
app.ingest.linux.identity / lastlog / sudoers into doc["linux"] documents
whose job is broader than Host User Facts (they also feed the raw artifact
search index) -- so, unlike the Windows SAM/ProfileList producers (which
emit one document per account record and can tag it inline), Linux
identity data needs a *derived* extractor: it inspects a whole artifact's
document batch and returns NEW, synthetic doc["host_user_fact"] documents,
without mutating the real documents.

This module is the direct relocation of the field-bundling logic that used
to live inline inside app.services.host_users.create_host_user_fact_observations
(pre-refactor) -- the field semantics are unchanged, only where the
family/artifact_type branching happens has moved, so that
create_host_user_fact_observations itself becomes platform-agnostic, the
same way app.services.host_facts.create_host_fact_observations already is.
"""
from __future__ import annotations

from datetime import datetime

from app.ingest.host_user_extraction import register_host_user_fact_extractor

ARTIFACT_FAMILY_IDENTITY = "linux_identity"
ARTIFACT_FAMILY_LASTLOG = "linux_lastlog"
ARTIFACT_FAMILY_SUDOERS = "linux_sudoers"


def _account_status_from_password_status(password_status: str | None) -> str | None:
    # "Disabled" is deliberately never returned -- there is no signal in
    # this evidence set independent of "locked" that would justify it, and
    # the shell alone must never be used to infer disabled.
    if password_status == "locked":
        return "locked"
    if password_status in ("set", "empty"):
        return "active"
    return None


def _passwd_rows(linux: dict) -> list[dict]:
    return [{
        "source_kind": "passwd",
        "username": linux.get("username") or None,
        "uid": linux.get("uid") or None,
        "id_kind": "uid" if linux.get("uid") else None,
        "primary_gid": linux.get("gid") or None,
        "gecos": linux.get("gecos") or None,
        "home": linux.get("home") or None,
        "shell": linux.get("shell") or None,
    }]


def _shadow_rows(linux: dict) -> list[dict]:
    password_status = linux.get("password_status") or None
    return [{
        "source_kind": "shadow",
        "username": linux.get("username") or None,
        "password_status": password_status,
        "account_status": _account_status_from_password_status(password_status),
    }]


def _group_rows(linux: dict) -> list[dict]:
    group_name = linux.get("group_name") or None
    gid = linux.get("gid") or None
    rows = [{"source_kind": "group_definition", "username": None, "group_name": group_name, "group_gid": gid}]
    for member in linux.get("members") or []:
        member = str(member).strip()
        if not member:
            continue
        rows.append({"source_kind": "group_membership", "username": member, "group_name": group_name, "group_gid": gid})
    return rows


def _sudoers_rows(linux: dict) -> list[dict]:
    # Defaults lines carry no principal and are not an account-level grant;
    # only real "who may run what" rules resolve into effective sudo access.
    if linux.get("is_defaults"):
        return []
    principal = str(linux.get("principal") or "").strip()
    if not principal:
        return []
    if principal.startswith("%"):
        return [{"source_kind": "sudoers_rule", "username": None, "group_name": principal[1:], "group_gid": None}]
    return [{"source_kind": "sudoers_rule", "username": principal, "group_name": None, "group_gid": None}]


def _lastlog_rows(linux: dict, doc: dict) -> list[dict]:
    timestamp = doc.get("@timestamp")
    observed: datetime | None = None
    if timestamp:
        try:
            observed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        except ValueError:
            observed = None
    uid = linux.get("uid")
    return [{
        "source_kind": "lastlog",
        "username": linux.get("username") or None,
        "uid": str(uid) if uid is not None else None,
        "id_kind": "uid" if uid is not None else None,
        "last_login_at": observed,
        "last_login_source_ip": linux.get("source_ip") or linux.get("lastlog_host") or None,
        "last_login_terminal": linux.get("terminal") or None,
    }]


@register_host_user_fact_extractor
def extract_linux_host_user_facts(documents: list[dict]) -> list[dict]:
    derived: list[dict] = []
    for doc in documents:
        linux = doc.get("linux") or {}
        family = str(linux.get("artifact_family") or "")
        artifact_type = str(linux.get("artifact_type") or "")
        if family == ARTIFACT_FAMILY_IDENTITY and artifact_type == "passwd":
            field_rows = _passwd_rows(linux)
        elif family == ARTIFACT_FAMILY_IDENTITY and artifact_type == "shadow":
            field_rows = _shadow_rows(linux)
        elif family == ARTIFACT_FAMILY_IDENTITY and artifact_type == "group":
            field_rows = _group_rows(linux)
        elif family == ARTIFACT_FAMILY_LASTLOG:
            field_rows = _lastlog_rows(linux, doc)
        elif family == ARTIFACT_FAMILY_SUDOERS:
            field_rows = _sudoers_rows(linux)
        else:
            continue
        parser = str((doc.get("artifact") or {}).get("parser") or "")
        source_path = linux.get("source_file") or doc.get("source_file")
        for field_row in field_rows:
            derived.append({
                "source_file": source_path,
                "artifact": {"parser": parser},
                "event_id": doc.get("event_id"),
                "host_user_fact": {**field_row, "parser": parser, "source_file": source_path},
            })
    return derived
