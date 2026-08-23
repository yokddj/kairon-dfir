"""Host User Inventory: correlates already-normalized local-account
observations (Linux passwd/shadow/lastlog/group/sudoers; Windows SAM,
corroborated by ProfileList) into one inventory entry per local account.

Architecture:

    Evidence -> platform-specific producers -> Host User Fact observations
        (app.ingest.host_user_extraction.extract_host_user_documents)
        -> resolve_host_users() -> Host Information "Users" section

This module itself has no platform-specific logic at all -- it never
inspects which producer created an observation beyond its declared
source_kind, and it resolves every field (typed column or JSON attribute)
through the exact same supporting/conflicting/preferred_value mechanism,
mirroring app.services.host_facts. Platform knowledge lives entirely in
the producers (app.ingest.linux.host_user_facts,
app.ingest.raw_parsers.sam_identity_parser,
app.ingest.raw_parsers.profile_list_parser).

A HostUserFact row never duplicates evidence -- the raw file lives on disk
and the full normalized record is already searchable under the source
artifact's own family. This layer stores only the small set of per-account
fields each observation asserts, referencing case/evidence/artifact/host
the same way app.services.host_facts already does.

It is a sibling to Host Facts rather than a reuse of that table: a local
account is a bundle of several fields produced together by one artifact
record (a passwd line or a SAM account both carry several fields at once),
and the entity key is the username rather than a fact_type. Conflict
resolution follows the exact same philosophy as Host Facts though -- every
supporting and conflicting observation is always returned alongside a
preferred value, so disagreement is surfaced, never hidden.

Password hashes are never read, stored, or returned by this module.
"""
from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from datetime import datetime

from sqlalchemy.orm import Session

from app.ingest.linux.shells import classify_shell
from app.models.host_user_fact import HostUserFact

# uid/id_kind: numeric local identifier + which concept produced it
# ("uid" | "rid"). primary_gid/gecos/home/shell: see host_user_fact.py's
# column docstring for why Windows SAM/ProfileList reuse these columns
# rather than getting dedicated ones.
_IDENTITY_FIELDS = ("uid", "id_kind", "primary_gid", "gecos", "home", "shell")


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
    # distinct lines/records for the same username in one artifact (e.g. a
    # duplicated UID entry -- a known persistence technique) must stay two
    # separate observations, not silently collapse into one.
    blob = "|".join(str(part or "") for part in (case_id, evidence_id, artifact_id, source_kind, username, group_name, line_number))
    return hashlib.sha256(blob.encode("utf-8", errors="ignore")).hexdigest()


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
    """Create one HostUserFact row per already-tagged observation document.

    ``documents`` are the output of
    app.ingest.host_user_extraction.extract_host_user_documents() --
    every document carries a platform-agnostic ``host_user_fact`` dict,
    regardless of which platform/producer created it. This function has no
    platform-specific logic. Duplicate observations (matched by
    fingerprint) are skipped, so calling this twice for the same
    evidence/artifact is a no-op the second time.
    """
    created: list[HostUserFact] = []
    for line_number, doc in enumerate(documents):
        fact = doc.get("host_user_fact") or {}
        source_kind = str(fact.get("source_kind") or "")
        if not source_kind:
            continue
        username = fact.get("username")
        group_name = fact.get("group_name")
        fingerprint = build_host_user_fact_fingerprint(case_id, evidence_id, artifact_id, source_kind, username, group_name, line_number)
        if db.query(HostUserFact.id).filter(HostUserFact.fingerprint == fingerprint).first() is not None:
            continue
        row = HostUserFact(
            case_id=case_id,
            evidence_id=evidence_id,
            artifact_id=artifact_id,
            host_id=host_id,
            username=username,
            source_kind=source_kind,
            parser=str(fact.get("parser") or (doc.get("artifact") or {}).get("parser") or ""),
            source_path=fact.get("source_file") or doc.get("source_file"),
            uid=fact.get("uid"),
            id_kind=fact.get("id_kind"),
            primary_gid=fact.get("primary_gid"),
            gecos=fact.get("gecos"),
            home=fact.get("home"),
            shell=fact.get("shell"),
            password_status=fact.get("password_status"),
            account_status=fact.get("account_status"),
            last_login_at=fact.get("last_login_at"),
            last_login_source_ip=fact.get("last_login_source_ip"),
            last_login_terminal=fact.get("last_login_terminal"),
            group_name=group_name,
            group_gid=fact.get("group_gid"),
            attributes=fact.get("attributes") or {},
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


def _resolve_values(field_label: str, rows_with_values: list[tuple[HostUserFact, str]]) -> dict:
    valid = [(row, value) for row, value in rows_with_values if value]
    if not valid:
        return {"field": field_label, "status": "missing", "preferred_value": None, "supporting": [], "conflicting": [], "observations": []}
    distinct = sorted({value for _, value in valid})
    if len(distinct) == 1:
        preferred = distinct[0]
        status = "confirmed" if len(valid) > 1 else "observed"
        supporting = [row for row, _ in valid]
        conflicting: list[HostUserFact] = []
    else:
        # No cross-source reliability ranking exists for identity fields the
        # way Host Facts ranks os-release over hostnamectl -- SAM/passwd is
        # definitionally the one authoritative source for these fields, so
        # multiple observations disagreeing is itself the noteworthy signal
        # (e.g. a UID/RID changed, or was duplicated, between snapshots).
        # The most recently observed value is preferred, deterministically,
        # while every value is still surfaced.
        _, preferred = max(valid, key=lambda pair: pair[0].observed_at or pair[0].created_at)
        status = "conflicting"
        supporting = [row for row, value in valid if value == preferred]
        conflicting = [row for row, value in valid if value != preferred]
    return {
        "field": field_label,
        "status": status,
        "preferred_value": preferred,
        "supporting": [_serialize(row) for row in supporting],
        "conflicting": [_serialize(row) for row in conflicting],
        "observations": [_serialize(row) for row, _ in valid],
    }


def _resolve_field(field: str, rows: list[HostUserFact]) -> dict:
    return _resolve_values(field, [(row, getattr(row, field)) for row in rows])


def _resolve_attribute(key: str, rows: list[HostUserFact]) -> dict:
    return _resolve_values(key, [(row, (row.attributes or {}).get(key)) for row in rows])


def _observed_attribute_keys(rows: list[HostUserFact]) -> list[str]:
    # No platform branch here: whichever keys a producer actually put in
    # ``attributes`` are exactly the keys that get resolved and surfaced --
    # Linux rows never set attributes, so Linux entries simply get {}.
    keys: set[str] = set()
    for row in rows:
        keys.update((row.attributes or {}).keys())
    return sorted(keys)


def _resolve_password_status(shadow_rows: list[HostUserFact]) -> dict:
    if not shadow_rows:
        return {"field": "password_status", "status": "missing", "preferred_value": "unavailable", "supporting": [], "conflicting": [], "observations": []}
    return _resolve_field("password_status", shadow_rows)


def _build_uid_username_map(identity_rows: list[HostUserFact]) -> dict[str, str]:
    counts: dict[str, Counter] = defaultdict(Counter)
    for row in identity_rows:
        if row.uid and row.username:
            counts[row.uid][row.username] += 1
    return {uid: counter.most_common(1)[0][0] for uid, counter in counts.items()}


def _build_gid_group_name_map(group_definition_rows: list[HostUserFact]) -> dict[str, str]:
    counts: dict[str, Counter] = defaultdict(Counter)
    for row in group_definition_rows:
        if row.group_gid and row.group_name:
            counts[row.group_gid][row.group_name] += 1
    return {gid: counter.most_common(1)[0][0] for gid, counter in counts.items()}


def _build_sid_profile_map(profile_list_rows: list[HostUserFact]) -> dict[str, list[HostUserFact]]:
    mapping: dict[str, list[HostUserFact]] = defaultdict(list)
    for row in profile_list_rows:
        sid = (row.attributes or {}).get("sid")
        if sid:
            mapping[sid].append(row)
    return mapping


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


def _resolve_user_entry(
    username: str, *, is_synthetic: bool,
    identity_rows: list[HostUserFact], home_rows: list[HostUserFact], status_rows: list[HostUserFact],
    shadow_rows: list[HostUserFact], membership_rows: list[HostUserFact], lastlog_rows: list[HostUserFact],
    sudoers_rows: list[HostUserFact], gid_group_name_map: dict[str, str],
) -> dict:
    identity = {}
    for field in _IDENTITY_FIELDS:
        identity[field] = _resolve_field(field, home_rows if field == "home" else identity_rows)
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
        # Any producer-specific extra (Windows RID/SID/account flags/logon
        # counters, ...) that isn't one of the typed identity columns --
        # resolved through the exact same mechanism as everything else, so
        # a new producer never needs a resolver change to surface its data.
        "attributes": {key: _resolve_attribute(key, identity_rows) for key in _observed_attribute_keys(identity_rows)},
        "primary_group_name": primary_group_name,
        "secondary_groups": secondary_groups,
        "password_status": _resolve_password_status(shadow_rows),
        # A resolution object, not a bare string, so account_status carries
        # the same source/provenance/confidence transparency as every other
        # field -- computed once per producer from its own reliable signal
        # (Linux: shadow password_status; Windows: SAM control-flag bits),
        # never inferred here.
        "account_status": _resolve_field("account_status", status_rows),
        "last_login": _resolve_last_login(lastlog_rows),
        # Reusable classification (app.ingest.linux.shells) of the resolved
        # shell value -- "login" / "non_login" / "unknown" -- never a bare
        # "is it /bin/bash" check. Always "unknown" for Windows accounts,
        # which have no shell concept -- honest absence, not an error.
        "shell_classification": classify_shell(identity["shell"]["preferred_value"]),
        # Effective sudo considers both a direct sudoers rule for this
        # username and any %group rule matching a group (primary or
        # secondary) this user actually belongs to -- not group membership
        # alone, since a group with no sudoers rule grants nothing. Always
        # empty for Windows accounts this sprint -- local group membership
        # (Administrators/...) is a documented, not-yet-implemented gap,
        # never inferred from account flags.
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

    # "passwd" (Linux) and "sam_account" (Windows) are both direct,
    # authoritative account-store records that resolve through the exact
    # same identity fields -- this is the only place they're merged, and
    # only because both genuinely answer "what does this account's own
    # store say about it", the same way EVTX/Registry/Memory Host Facts
    # observations merge under one fact_type.
    identity_rows = [r for r in rows if r.source_kind in ("passwd", "sam_account")]
    shadow_rows = [r for r in rows if r.source_kind == "shadow"]
    status_rows = [r for r in rows if r.account_status]
    membership_rows = [r for r in rows if r.source_kind == "group_membership"]
    group_definition_rows = [r for r in rows if r.source_kind == "group_definition"]
    lastlog_rows = [r for r in rows if r.source_kind == "lastlog"]
    sudoers_rows = [r for r in rows if r.source_kind == "sudoers_rule"]
    # profile_list rows are NEVER added to identity_rows/usernames below --
    # they may only attach to an account that a direct source (SAM) already
    # created, via SID cross-reference, and only ever contribute to "home".
    profile_list_rows = [r for r in rows if r.source_kind == "profile_list"]

    uid_username_map = _build_uid_username_map(identity_rows)
    gid_group_name_map = _build_gid_group_name_map(group_definition_rows)
    sid_to_profile_rows = _build_sid_profile_map(profile_list_rows)

    usernames: set[str] = set()
    for row in identity_rows + shadow_rows + membership_rows + sudoers_rows:
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
            # A lastlog record whose uid matches no known identity entry --
            # never fabricate a username, but never drop the observation
            # either; it becomes its own synthetic-key entry.
            lastlog_orphans_by_uid[row.uid].append(row)

    entries = []
    for username in usernames:
        user_identity_rows = [r for r in identity_rows if r.username == username]
        matched_profile_rows: list[HostUserFact] = []
        for row in user_identity_rows:
            sid = (row.attributes or {}).get("sid")
            if sid:
                matched_profile_rows.extend(sid_to_profile_rows.get(sid, []))
        entries.append(_resolve_user_entry(
            username,
            is_synthetic=False,
            identity_rows=user_identity_rows,
            home_rows=user_identity_rows + matched_profile_rows,
            status_rows=[r for r in status_rows if r.username == username],
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
            identity_rows=[],
            home_rows=[],
            status_rows=[],
            shadow_rows=[],
            membership_rows=[],
            lastlog_rows=uid_rows,
            sudoers_rows=sudoers_rows,
            gid_group_name_map=gid_group_name_map,
        ))

    entries.sort(key=lambda entry: (entry["is_synthetic_username"], entry["username"].lower()))
    return entries
