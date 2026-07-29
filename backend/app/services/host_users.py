"""Host User Inventory: correlates already-normalized passwd/shadow/lastlog/
group observations into one inventory entry per local account.

Architecture:

    Evidence -> Artifacts -> Normalized observations -> HostUserFact
        -> resolve_host_users() -> Host Information "Users" section

A HostUserFact row never duplicates evidence -- the raw file lives on disk
and the full normalized record is already searchable under the source
artifact's own family (``linux_identity`` for passwd/group/shadow,
``linux_lastlog`` for lastlog). This layer stores only the small set of
per-account fields each observation asserts, referencing case/evidence/
artifact/host the same way app.services.host_facts already does.

It is a sibling to Host Facts rather than a reuse of that table: Host Facts
represents one resolved *value* per (host, fact_type); a local account is a
bundle of several fields produced together by one artifact line (a passwd
line already carries uid/gid/home/shell/gecos together), and the entity key
is the username rather than a fact_type. Conflict resolution follows the
exact same philosophy as Host Facts though -- every supporting and
conflicting observation is always returned alongside a preferred value, so
disagreement is surfaced, never hidden.

Password hashes are never read, stored, or returned by this module --
password_status is a locked/set/empty classification already computed once
in app.ingest.linux.identity, from the shadow password field's leading
marker character only.
"""
from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from datetime import datetime

from sqlalchemy.orm import Session

from app.ingest.linux.shells import classify_shell
from app.models.host_user_fact import HostUserFact

_IDENTITY_FIELDS = ("uid", "primary_gid", "gecos", "home", "shell")


def build_host_user_fact_fingerprint(
    case_id: str,
    evidence_id: str,
    artifact_id: str | None,
    source_kind: str,
    username: str | None,
    group_name: str | None,
    line_number: int | None,
) -> str:
    # line_number is part of the fingerprint deliberately: two genuinely
    # distinct lines for the same username in one file (e.g. a duplicated
    # UID entry -- a known persistence technique) must stay two separate
    # observations, not silently collapse into one.
    blob = "|".join(str(part or "") for part in (case_id, evidence_id, artifact_id, source_kind, username, group_name, line_number))
    return hashlib.sha256(blob.encode("utf-8", errors="ignore")).hexdigest()


def _passwd_rows_from_doc(linux: dict) -> list[dict]:
    return [{
        "source_kind": "passwd",
        "username": linux.get("username") or None,
        "uid": linux.get("uid") or None,
        "primary_gid": linux.get("gid") or None,
        "gecos": linux.get("gecos") or None,
        "home": linux.get("home") or None,
        "shell": linux.get("shell") or None,
        "group_name": None,
        "group_gid": None,
    }]


def _shadow_rows_from_doc(linux: dict) -> list[dict]:
    return [{
        "source_kind": "shadow",
        "username": linux.get("username") or None,
        "password_status": linux.get("password_status") or None,
        "group_name": None,
        "group_gid": None,
    }]


def _group_rows_from_doc(linux: dict) -> list[dict]:
    group_name = linux.get("group_name") or None
    gid = linux.get("gid") or None
    rows = [{
        "source_kind": "group_definition",
        "username": None,
        "group_name": group_name,
        "group_gid": gid,
    }]
    for member in linux.get("members") or []:
        member = str(member).strip()
        if not member:
            continue
        rows.append({
            "source_kind": "group_membership",
            "username": member,
            "group_name": group_name,
            "group_gid": gid,
        })
    return rows


def _sudoers_rows_from_doc(linux: dict) -> list[dict]:
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


def _lastlog_rows_from_doc(linux: dict, doc: dict) -> list[dict]:
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
        "last_login_at": observed,
        "last_login_source_ip": linux.get("source_ip") or linux.get("lastlog_host") or None,
        "last_login_terminal": linux.get("terminal") or None,
        "group_name": None,
        "group_gid": None,
    }]


def create_host_user_fact_observations(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    artifact_id: str | None,
    host_id: str | None,
    observed_at: datetime | None,
    documents: list[dict],
) -> list[HostUserFact]:
    """Create one HostUserFact row per already-normalized identity/lastlog
    observation. Duplicate observations (matched by fingerprint) are
    skipped, so calling this twice for the same evidence/artifact is a
    no-op the second time -- same contract as create_host_fact_observations.
    """
    created: list[HostUserFact] = []
    for line_number, doc in enumerate(documents):
        linux = doc.get("linux") or {}
        family = str(linux.get("artifact_family") or "")
        artifact_type = str(linux.get("artifact_type") or "")
        if family == "linux_identity" and artifact_type == "passwd":
            field_rows = _passwd_rows_from_doc(linux)
        elif family == "linux_identity" and artifact_type == "shadow":
            field_rows = _shadow_rows_from_doc(linux)
        elif family == "linux_identity" and artifact_type == "group":
            field_rows = _group_rows_from_doc(linux)
        elif family == "linux_lastlog":
            field_rows = _lastlog_rows_from_doc(linux, doc)
        elif family == "linux_sudoers":
            field_rows = _sudoers_rows_from_doc(linux)
        else:
            continue
        parser = str((doc.get("artifact") or {}).get("parser") or "")
        source_path = linux.get("source_file") or doc.get("source_file")
        for field_row in field_rows:
            fingerprint = build_host_user_fact_fingerprint(
                case_id, evidence_id, artifact_id, field_row["source_kind"],
                field_row.get("username"), field_row.get("group_name"), line_number,
            )
            if db.query(HostUserFact.id).filter(HostUserFact.fingerprint == fingerprint).first() is not None:
                continue
            row = HostUserFact(
                case_id=case_id,
                evidence_id=evidence_id,
                artifact_id=artifact_id,
                host_id=host_id,
                username=field_row.get("username"),
                source_kind=field_row["source_kind"],
                parser=parser,
                source_path=source_path,
                uid=field_row.get("uid"),
                primary_gid=field_row.get("primary_gid"),
                gecos=field_row.get("gecos"),
                home=field_row.get("home"),
                shell=field_row.get("shell"),
                password_status=field_row.get("password_status"),
                last_login_at=field_row.get("last_login_at"),
                last_login_source_ip=field_row.get("last_login_source_ip"),
                last_login_terminal=field_row.get("last_login_terminal"),
                group_name=field_row.get("group_name"),
                group_gid=field_row.get("group_gid"),
                observed_at=observed_at,
                event_id=doc.get("event_id"),
                fingerprint=fingerprint,
                provenance={},
            )
            db.add(row)
            created.append(row)
    if created:
        db.commit()
    return created


def delete_host_user_facts_for_evidence(db: Session, evidence_id: str) -> int:
    """Remove every Host User Fact observation sourced from this evidence.

    Called from reprocess cleanup alongside delete_host_facts_for_evidence,
    so reprocessing an evidence rebuilds its Host User Inventory instead of
    accumulating stale rows next to fresh ones. Does not commit; the caller
    commits as part of its own cleanup transaction.
    """
    return db.query(HostUserFact).filter(HostUserFact.evidence_id == evidence_id).delete(synchronize_session=False)


def _serialize(row: HostUserFact) -> dict:
    return {
        "id": row.id,
        "source_kind": row.source_kind,
        "parser": row.parser,
        "source_path": row.source_path,
        "observed_at": row.observed_at.isoformat() if row.observed_at else None,
        "event_id": row.event_id,
        "evidence_id": row.evidence_id,
        "artifact_id": row.artifact_id,
        "host_id": row.host_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def _resolve_field(field: str, rows: list[HostUserFact]) -> dict:
    valid = [(row, getattr(row, field)) for row in rows if getattr(row, field)]
    if not valid:
        return {"field": field, "status": "missing", "preferred_value": None, "supporting": [], "conflicting": [], "observations": []}
    distinct = sorted({value for _, value in valid})
    if len(distinct) == 1:
        preferred = distinct[0]
        status = "confirmed" if len(valid) > 1 else "observed"
        supporting = [row for row, _ in valid]
        conflicting: list[HostUserFact] = []
    else:
        # No cross-source reliability ranking exists for identity fields the
        # way Host Facts ranks os-release over hostnamectl -- passwd is
        # definitionally the one source for these fields, so multiple
        # observations disagreeing is itself the noteworthy signal (e.g. a
        # UID changed, or was duplicated, between snapshots). The most
        # recently observed value is preferred, deterministically, while
        # every value is still surfaced.
        preferred_row, preferred = max(valid, key=lambda pair: pair[0].observed_at or pair[0].created_at)
        status = "conflicting"
        supporting = [row for row, value in valid if value == preferred]
        conflicting = [row for row, value in valid if value != preferred]
    return {
        "field": field,
        "status": status,
        "preferred_value": preferred,
        "supporting": [_serialize(row) for row in supporting],
        "conflicting": [_serialize(row) for row in conflicting],
        "observations": [_serialize(row) for row, _ in valid],
    }


def _resolve_password_status(shadow_rows: list[HostUserFact]) -> dict:
    if not shadow_rows:
        return {"field": "password_status", "status": "missing", "preferred_value": "unavailable", "supporting": [], "conflicting": [], "observations": []}
    return _resolve_field("password_status", shadow_rows)


def _account_status_from_password_status(password_status: str | None) -> str:
    # "Disabled" is deliberately never returned -- there is no signal in
    # this evidence set independent of "locked" that would justify it, and
    # the shell alone must never be used to infer disabled (per Design
    # Principles). See Known Limitations in the sprint report.
    if password_status == "locked":
        return "locked"
    if password_status in ("set", "empty"):
        return "active"
    return "unknown"


def _build_uid_username_map(passwd_rows: list[HostUserFact]) -> dict[str, str]:
    counts: dict[str, Counter] = defaultdict(Counter)
    for row in passwd_rows:
        if row.uid and row.username:
            counts[row.uid][row.username] += 1
    return {uid: counter.most_common(1)[0][0] for uid, counter in counts.items()}


def _build_gid_group_name_map(group_definition_rows: list[HostUserFact]) -> dict[str, str]:
    counts: dict[str, Counter] = defaultdict(Counter)
    for row in group_definition_rows:
        if row.group_gid and row.group_name:
            counts[row.group_gid][row.group_name] += 1
    return {gid: counter.most_common(1)[0][0] for gid, counter in counts.items()}


def _secondary_groups(membership_rows: list[HostUserFact]) -> list[dict]:
    by_group: dict[tuple[str, str | None], list[HostUserFact]] = defaultdict(list)
    for row in membership_rows:
        by_group[(row.group_name or "", row.group_gid)].append(row)
    groups = []
    for (group_name, gid), rows in sorted(by_group.items()):
        if not group_name:
            continue
        groups.append({"group_name": group_name, "gid": gid, "observations": [_serialize(row) for row in rows]})
    return groups


def _resolve_last_login(rows: list[HostUserFact]) -> dict | None:
    if not rows:
        return None
    latest = max(rows, key=lambda row: row.last_login_at or row.observed_at or row.created_at)
    return {
        "timestamp": latest.last_login_at.isoformat() if latest.last_login_at else None,
        "source_ip": latest.last_login_source_ip,
        "terminal": latest.last_login_terminal,
        "observations": [_serialize(row) for row in rows],
    }


def _effective_sudo(username: str, *, group_names: set[str], sudoers_rows: list[HostUserFact]) -> dict:
    direct = [row for row in sudoers_rows if row.username == username]
    via_group = [row for row in sudoers_rows if row.group_name and row.group_name in group_names]
    observations = direct + via_group
    via = "direct" if direct else "group" if via_group else None
    return {
        "has_sudo": bool(observations),
        "via": via,
        "granting_groups": sorted({row.group_name for row in via_group if row.group_name}),
        "observations": [_serialize(row) for row in observations],
    }


def _resolve_user_entry(username: str, *, is_synthetic: bool, passwd_rows, shadow_rows, membership_rows, lastlog_rows, sudoers_rows, gid_group_name_map) -> dict:
    identity = {field: _resolve_field(field, passwd_rows) for field in _IDENTITY_FIELDS}
    primary_gid_value = identity["primary_gid"]["preferred_value"]
    primary_group_name = gid_group_name_map.get(primary_gid_value) if primary_gid_value else None
    secondary_groups = _secondary_groups(membership_rows)
    group_names = {group["group_name"] for group in secondary_groups if group.get("group_name")}
    if primary_group_name:
        group_names.add(primary_group_name)
    return {
        "username": username,
        "is_synthetic_username": is_synthetic,
        "identity": identity,
        "primary_group_name": primary_group_name,
        "secondary_groups": secondary_groups,
        "password_status": _resolve_password_status(shadow_rows),
        "account_status": _account_status_from_password_status(_resolve_password_status(shadow_rows)["preferred_value"]),
        "last_login": _resolve_last_login(lastlog_rows),
        # Reusable classification (app.ingest.linux.shells) of the resolved
        # shell value -- "login" / "non_login" / "unknown" -- never a bare
        # "is it /bin/bash" check, so it generalizes to any distro's shell set.
        "shell_classification": classify_shell(identity["shell"]["preferred_value"]),
        # Effective sudo considers both a direct sudoers rule for this
        # username and any %group rule matching a group (primary or
        # secondary) this user actually belongs to -- not group membership
        # alone, since a group with no sudoers rule grants nothing.
        "effective_sudo": _effective_sudo(username, group_names=group_names, sudoers_rows=sudoers_rows),
    }


def resolve_host_users(
    db: Session,
    *,
    case_id: str,
    host_id: str | None = None,
    evidence_id: str | None = None,
) -> list[dict]:
    """Resolve stored observations into one inventory entry per username.

    Scope precedence matches resolve_host_facts: an explicit host_id takes
    every evidence assigned to that host into account; otherwise scope is
    the given evidence alone. Never merges usernames across hosts.
    """
    query = db.query(HostUserFact).filter(HostUserFact.case_id == case_id)
    if host_id:
        query = query.filter(HostUserFact.host_id == host_id)
    elif evidence_id:
        query = query.filter(HostUserFact.evidence_id == evidence_id)
    rows = query.order_by(HostUserFact.created_at).all()

    passwd_rows = [r for r in rows if r.source_kind == "passwd"]
    shadow_rows = [r for r in rows if r.source_kind == "shadow"]
    membership_rows = [r for r in rows if r.source_kind == "group_membership"]
    group_definition_rows = [r for r in rows if r.source_kind == "group_definition"]
    lastlog_rows = [r for r in rows if r.source_kind == "lastlog"]
    sudoers_rows = [r for r in rows if r.source_kind == "sudoers_rule"]

    uid_username_map = _build_uid_username_map(passwd_rows)
    gid_group_name_map = _build_gid_group_name_map(group_definition_rows)

    usernames: set[str] = set()
    for row in passwd_rows + shadow_rows + membership_rows + sudoers_rows:
        if row.username:
            usernames.add(row.username)

    lastlog_by_username: dict[str, list[HostUserFact]] = defaultdict(list)
    lastlog_orphans_by_uid: dict[str, list[HostUserFact]] = defaultdict(list)
    for row in lastlog_rows:
        resolved_username = row.username or (uid_username_map.get(row.uid) if row.uid else None)
        if resolved_username:
            usernames.add(resolved_username)
            lastlog_by_username[resolved_username].append(row)
        elif row.uid:
            # A lastlog record whose uid matches no known passwd entry --
            # never fabricate a username, but never drop the observation
            # either; it becomes its own synthetic-key entry.
            lastlog_orphans_by_uid[row.uid].append(row)

    entries = []
    for username in usernames:
        entries.append(_resolve_user_entry(
            username,
            is_synthetic=False,
            passwd_rows=[r for r in passwd_rows if r.username == username],
            shadow_rows=[r for r in shadow_rows if r.username == username],
            membership_rows=[r for r in membership_rows if r.username == username],
            lastlog_rows=lastlog_by_username.get(username, []),
            sudoers_rows=sudoers_rows,
            gid_group_name_map=gid_group_name_map,
        ))
    for uid, uid_rows in lastlog_orphans_by_uid.items():
        entries.append(_resolve_user_entry(
            f"uid:{uid}",
            is_synthetic=True,
            passwd_rows=[],
            shadow_rows=[],
            membership_rows=[],
            lastlog_rows=uid_rows,
            sudoers_rows=sudoers_rows,
            gid_group_name_map=gid_group_name_map,
        ))

    entries.sort(key=lambda entry: (entry["is_synthetic_username"], entry["username"].lower()))
    return entries
