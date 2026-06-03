from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from datetime import UTC, datetime
import logging
import threading
from typing import Any

from sqlalchemy import case as sql_case
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.core.database import utc_now
from app.models.case_host import CaseHost
from app.models.case_host_alias import CaseHostAlias
from app.models.case_host_identity_audit import CaseHostIdentityAudit
from app.models.evidence import Evidence
from app.models.finding import Finding

logger = logging.getLogger(__name__)

_HOST_IDENTITY_STATS_KEY = "host_identity_runtime_stats"


def _debug_db_trace(function: str, *, db: Session, case_id: str | None = None, canonical_name: str | None = None) -> None:
    if not logger.isEnabledFor(logging.DEBUG):
        return
    connection_id = None
    try:
        connection = db.connection()
        connection_id = id(connection.connection)
    except Exception:  # noqa: BLE001
        connection_id = None
    logger.debug(
        "db_trace function=%s thread=%s thread_id=%s session_id=%s connection_id=%s case_id=%s canonical_name=%s",
        function,
        threading.current_thread().name,
        threading.get_ident(),
        id(db),
        connection_id,
        case_id,
        canonical_name,
    )


INVALID_HOST_VALUES = {"", "-", "unknown", "template", "n/a", "na", "none", "null", "localhost"}


def normalize_host_alias(name: str | None) -> str | None:
    text = str(name or "").strip().strip('"').strip("'").rstrip(".").lower()
    return text or None


def is_invalid_host_value(name: str | None) -> bool:
    normalized = normalize_host_alias(name)
    return not normalized or normalized in INVALID_HOST_VALUES


def _short_host_alias(name: str | None) -> str | None:
    normalized = normalize_host_alias(name)
    if not normalized or "." not in normalized:
        return None
    short = normalized.split(".", 1)[0].strip()
    return short or None


def _host_aliases(*values: str | None) -> list[str]:
    aliases: list[str] = []
    for value in values:
        normalized = normalize_host_alias(value)
        if not normalized or normalized in INVALID_HOST_VALUES:
            continue
        for candidate in (normalized, _short_host_alias(normalized)):
            if candidate and candidate not in aliases:
                aliases.append(candidate)
    return aliases


def _same_host_family(left: str | None, right: str | None) -> bool:
    left_aliases = set(_host_aliases(left))
    right_aliases = set(_host_aliases(right))
    return bool(left_aliases and right_aliases and left_aliases.intersection(right_aliases))


def canonicalize_host(
    *,
    provided_host: str | None = None,
    detected_host: str | None = None,
    artifact_host: str | None = None,
) -> dict[str, Any]:
    provided = str(provided_host or "").strip() or None
    detected = str(detected_host or "").strip() or None
    artifact = str(artifact_host or "").strip() or None
    valid_provided = provided if not is_invalid_host_value(provided) else None
    valid_detected = detected if not is_invalid_host_value(detected) else None
    valid_artifact = artifact if not is_invalid_host_value(artifact) else None
    canonical = valid_provided or valid_artifact or valid_detected
    source = "provided_host" if valid_provided else "artifact" if valid_artifact else "detected_host" if valid_detected else "unknown"
    confidence = "evidence_scope" if valid_provided else "artifact" if valid_artifact else "evidence_scope" if valid_detected else "unknown"
    conflict = bool(valid_provided and valid_artifact and not _same_host_family(valid_provided, valid_artifact))
    return {
        "canonical": canonical,
        "original": artifact if artifact is not None else None,
        "aliases": _host_aliases(valid_provided, valid_detected, valid_artifact),
        "source": source,
        "confidence": confidence,
        "conflict": conflict,
    }


def _evidence_hosts(db: Session, evidence_id: str | None) -> tuple[str | None, str | None]:
    if not evidence_id:
        return None, None
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        return None, None
    metadata = dict(evidence.metadata_json or {})
    provided = str(metadata.get("provided_host") or "").strip() or None
    detected = str(getattr(evidence, "detected_host", None) or "").strip() or None
    return provided, detected


def _apply_host_canonicalization(event: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    host = event.setdefault("host", {})
    if not isinstance(host, dict):
        host = {}
        event["host"] = host
    observed_host = event.setdefault("observed_host", {})
    if not isinstance(observed_host, dict):
        observed_host = {}
        event["observed_host"] = observed_host
    original = result.get("original")
    if original is not None:
        host.setdefault("original", original)
        if is_invalid_host_value(str(original)):
            host.setdefault("original_value", original)
        observed_host.setdefault("name", original)
        observed_host.setdefault("hostname", original)
    canonical = result.get("canonical")
    if not canonical:
        for key in ("name", "hostname", "canonical"):
            if is_invalid_host_value(host.get(key)):
                host.pop(key, None)
        host.setdefault("source", "unknown")
        host.setdefault("confidence", "unknown")
        return event
    host["name"] = canonical
    host["hostname"] = canonical
    host["canonical"] = canonical
    host["aliases"] = list(result.get("aliases") or [])
    host["source"] = result.get("source") or "unknown"
    host["confidence"] = result.get("confidence") or "unknown"
    host["conflict"] = bool(result.get("conflict"))
    return event


def _parse_seen(value: str | None) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except Exception:  # noqa: BLE001
        return None


def _seen_iso(values: list[str | None], *, pick: str) -> str | None:
    parsed = [item for item in (_parse_seen(value) for value in values) if item]
    if not parsed:
        return None
    selected = min(parsed) if pick == "min" else max(parsed)
    return selected.isoformat().replace("+00:00", "Z")


def _audit_entry(
    db: Session,
    *,
    case_id: str,
    case_host_id: str | None,
    action: str,
    old_value: dict[str, Any],
    new_value: dict[str, Any],
    reason: str | None = None,
    analyst: str | None = None,
) -> None:
    db.add(
        CaseHostIdentityAudit(
            case_id=case_id,
            case_host_id=case_host_id,
            action=action,
            old_value=old_value,
            new_value=new_value,
            reason=reason,
            analyst=analyst,
        )
    )


def _load_case_hosts(db: Session, case_id: str) -> list[CaseHost]:
    query = db.query(CaseHost)
    if hasattr(query, "options"):
        query = query.options(joinedload(CaseHost.aliases))
    rows = query.filter(CaseHost.case_id == case_id).order_by(CaseHost.display_name.asc(), CaseHost.created_at.asc()).all()
    return [row for row in rows if isinstance(row, CaseHost)]


def _load_alias_by_normalized(db: Session, case_id: str) -> dict[str, CaseHostAlias]:
    query = db.query(CaseHostAlias)
    if hasattr(query, "options"):
        query = query.options(joinedload(CaseHostAlias.case_host).joinedload(CaseHost.aliases))
    rows = query.filter(CaseHostAlias.case_id == case_id).all()
    rows = [row for row in rows if isinstance(row, CaseHostAlias)]
    return {row.normalized_alias: row for row in rows}


def _can_materialize_host_identity(db: Session) -> bool:
    return all(hasattr(db, attribute) for attribute in ("add", "commit", "flush"))


def _host_identity_stats(db: Session) -> dict[str, Any]:
    info = getattr(db, "info", None)
    if not isinstance(info, dict):
        return {
            "upserts": 0,
            "conflicts_recovered": 0,
            "host_identity_conflict_retries": 0,
            "aliases_updated": 0,
            "warnings": [],
        }
    bucket = info.setdefault(
        _HOST_IDENTITY_STATS_KEY,
        {
            "upserts": 0,
            "conflicts_recovered": 0,
            "host_identity_conflict_retries": 0,
            "aliases_updated": 0,
            "warnings": [],
        },
    )
    return bucket if isinstance(bucket, dict) else {}


def get_host_identity_runtime_stats(db: Session) -> dict[str, Any]:
    stats = dict(_host_identity_stats(db))
    stats["warnings"] = list(stats.get("warnings") or [])
    return stats


def _add_host_identity_warning(db: Session, warning: str) -> None:
    stats = _host_identity_stats(db)
    warnings = stats.setdefault("warnings", [])
    if warning not in warnings:
        warnings.append(warning)


def _record_host_identity_conflict_recovered(
    db: Session,
    *,
    case_id: str,
    canonical_name: str,
    entity: str,
) -> None:
    stats = _host_identity_stats(db)
    stats["conflicts_recovered"] = int(stats.get("conflicts_recovered") or 0) + 1
    stats["host_identity_conflict_retries"] = int(stats.get("host_identity_conflict_retries") or 0) + 1
    _add_host_identity_warning(db, "host_identity_upsert_conflict_recovered")
    logger.warning(
        "host_identity_upsert_conflict_recovered case_id=%s canonical_name=%s entity=%s",
        case_id,
        canonical_name,
        entity,
    )


def _combine_seen(existing: str | None, incoming: str | None, *, pick: str) -> str | None:
    return _seen_iso([existing, incoming], pick=pick)


def _merge_host_values(host: CaseHost, values: dict[str, Any]) -> None:
    host.first_seen = _combine_seen(host.first_seen, values.get("first_seen"), pick="min")
    host.last_seen = _combine_seen(host.last_seen, values.get("last_seen"), pick="max")
    host.event_count = max(int(host.event_count or 0), int(values.get("event_count") or 0))
    host.evidence_count = max(int(host.evidence_count or 0), int(values.get("evidence_count") or 0))


def _merge_alias_values(alias: CaseHostAlias, values: dict[str, Any]) -> None:
    alias.alias = str(values.get("alias") or alias.alias or "").strip() or alias.alias
    alias.first_seen = _combine_seen(alias.first_seen, values.get("first_seen"), pick="min")
    alias.last_seen = _combine_seen(alias.last_seen, values.get("last_seen"), pick="max")
    alias.event_count = max(int(alias.event_count or 0), int(values.get("event_count") or 0))


def _load_case_host_by_id(db: Session, host_id: str) -> CaseHost:
    return (
        db.query(CaseHost)
        .options(joinedload(CaseHost.aliases))
        .filter(CaseHost.id == host_id)
        .one()
    )


def _case_host_upsert_values(case_id: str, normalized: str, counts: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "canonical_name": normalized,
        "display_name": normalized,
        "confidence": "high",
        "source": "observed",
        "first_seen": counts.get("first_seen"),
        "last_seen": counts.get("last_seen"),
        "event_count": int(counts.get("event_count") or 0),
        "evidence_count": len(set(counts.get("evidence_ids") or [])),
    }


def _case_host_alias_upsert_values(case_id: str, host_id: str, normalized: str, counts: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_host_id": host_id,
        "case_id": case_id,
        "alias": normalized,
        "normalized_alias": normalized,
        "source": "observed",
        "confidence": "high",
        "first_seen": counts.get("first_seen"),
        "last_seen": counts.get("last_seen"),
        "event_count": int(counts.get("event_count") or 0),
        "is_primary": True,
    }


def _postgresql_case_host_upsert(db: Session, values: dict[str, Any]) -> str:
    stmt = pg_insert(CaseHost).values(**values)
    excluded = stmt.excluded
    stmt = stmt.on_conflict_do_update(
        constraint="uq_case_hosts_case_canonical_name",
        set_={
            "first_seen": sql_case(
                (CaseHost.first_seen.is_(None), excluded.first_seen),
                (excluded.first_seen.is_(None), CaseHost.first_seen),
                else_=func.least(CaseHost.first_seen, excluded.first_seen),
            ),
            "last_seen": sql_case(
                (CaseHost.last_seen.is_(None), excluded.last_seen),
                (excluded.last_seen.is_(None), CaseHost.last_seen),
                else_=func.greatest(CaseHost.last_seen, excluded.last_seen),
            ),
            "event_count": func.greatest(CaseHost.event_count, excluded.event_count),
            "evidence_count": func.greatest(CaseHost.evidence_count, excluded.evidence_count),
            "updated_at": utc_now(),
        },
    ).returning(CaseHost.id)
    return str(db.execute(stmt).scalar_one())


def _postgresql_case_host_alias_upsert(db: Session, values: dict[str, Any]) -> str:
    stmt = pg_insert(CaseHostAlias).values(**values)
    excluded = stmt.excluded
    stmt = stmt.on_conflict_do_update(
        constraint="uq_case_host_aliases_case_normalized_alias",
        set_={
            "alias": excluded.alias,
            "first_seen": sql_case(
                (CaseHostAlias.first_seen.is_(None), excluded.first_seen),
                (excluded.first_seen.is_(None), CaseHostAlias.first_seen),
                else_=func.least(CaseHostAlias.first_seen, excluded.first_seen),
            ),
            "last_seen": sql_case(
                (CaseHostAlias.last_seen.is_(None), excluded.last_seen),
                (excluded.last_seen.is_(None), CaseHostAlias.last_seen),
                else_=func.greatest(CaseHostAlias.last_seen, excluded.last_seen),
            ),
            "event_count": func.greatest(CaseHostAlias.event_count, excluded.event_count),
            "updated_at": utc_now(),
        },
    ).returning(CaseHostAlias.id)
    return str(db.execute(stmt).scalar_one())


def _fallback_case_host_upsert(db: Session, values: dict[str, Any]) -> str:
    host = (
        db.query(CaseHost)
        .filter(CaseHost.case_id == values["case_id"], CaseHost.canonical_name == values["canonical_name"])
        .first()
    )
    if host:
        _merge_host_values(host, values)
        db.flush()
        return str(host.id)
    savepoint = db.begin_nested()
    host = CaseHost(**values)
    try:
        db.add(host)
        db.flush()
        savepoint.commit()
        return str(host.id)
    except IntegrityError:
        savepoint.rollback()
        if host in db:
            db.expunge(host)
        _record_host_identity_conflict_recovered(
            db,
            case_id=str(values["case_id"]),
            canonical_name=str(values["canonical_name"]),
            entity="case_host",
        )
        host = (
            db.query(CaseHost)
            .filter(CaseHost.case_id == values["case_id"], CaseHost.canonical_name == values["canonical_name"])
            .one()
        )
        _merge_host_values(host, values)
        db.flush()
        return str(host.id)


def _fallback_case_host_alias_upsert(db: Session, values: dict[str, Any]) -> str:
    alias = (
        db.query(CaseHostAlias)
        .filter(CaseHostAlias.case_id == values["case_id"], CaseHostAlias.normalized_alias == values["normalized_alias"])
        .first()
    )
    if alias:
        _merge_alias_values(alias, values)
        db.flush()
        return str(alias.id)
    savepoint = db.begin_nested()
    alias = CaseHostAlias(**values)
    try:
        db.add(alias)
        db.flush()
        savepoint.commit()
        return str(alias.id)
    except IntegrityError:
        savepoint.rollback()
        if alias in db:
            db.expunge(alias)
        _record_host_identity_conflict_recovered(
            db,
            case_id=str(values["case_id"]),
            canonical_name=str(values["normalized_alias"]),
            entity="case_host_alias",
        )
        alias = (
            db.query(CaseHostAlias)
            .filter(CaseHostAlias.case_id == values["case_id"], CaseHostAlias.normalized_alias == values["normalized_alias"])
            .one()
        )
        _merge_alias_values(alias, values)
        db.flush()
        return str(alias.id)


def _upsert_observed_case_host(db: Session, *, case_id: str, normalized: str, counts: dict[str, Any]) -> CaseHost:
    _debug_db_trace("_upsert_observed_case_host", db=db, case_id=case_id, canonical_name=normalized)
    existing_alias = (
        db.query(CaseHostAlias)
        .options(joinedload(CaseHostAlias.case_host).joinedload(CaseHost.aliases))
        .filter(CaseHostAlias.case_id == case_id, CaseHostAlias.normalized_alias == normalized)
        .first()
    )
    if existing_alias:
        _merge_alias_values(existing_alias, _case_host_alias_upsert_values(case_id, existing_alias.case_host_id, normalized, counts))
        _merge_host_values(existing_alias.case_host, _case_host_upsert_values(case_id, normalized, counts))
        _host_identity_stats(db)["aliases_updated"] = int(_host_identity_stats(db).get("aliases_updated") or 0) + 1
        return existing_alias.case_host

    host_values = _case_host_upsert_values(case_id, normalized, counts)
    if getattr(getattr(db, "bind", None), "dialect", None) and db.bind.dialect.name == "postgresql":
        host_id = _postgresql_case_host_upsert(db, host_values)
    else:
        host_id = _fallback_case_host_upsert(db, host_values)
    _host_identity_stats(db)["upserts"] = int(_host_identity_stats(db).get("upserts") or 0) + 1

    alias_values = _case_host_alias_upsert_values(case_id, host_id, normalized, counts)
    if getattr(getattr(db, "bind", None), "dialect", None) and db.bind.dialect.name == "postgresql":
        alias_id = _postgresql_case_host_alias_upsert(db, alias_values)
    else:
        alias_id = _fallback_case_host_alias_upsert(db, alias_values)
    _host_identity_stats(db)["aliases_updated"] = int(_host_identity_stats(db).get("aliases_updated") or 0) + 1

    alias_row = (
        db.query(CaseHostAlias)
        .options(joinedload(CaseHostAlias.case_host).joinedload(CaseHost.aliases))
        .filter(CaseHostAlias.id == alias_id)
        .one()
    )
    if alias_row.case_host_id != host_id:
        orphan = (
            db.query(CaseHost)
            .options(joinedload(CaseHost.aliases))
            .filter(CaseHost.id == host_id)
            .first()
        )
        if orphan and not orphan.aliases:
            db.delete(orphan)
            db.flush()
        return alias_row.case_host
    return _load_case_host_by_id(db, host_id)


def _serialize_case_host(host: CaseHost, *, counts: dict[str, Any] | None = None) -> dict[str, Any]:
    alias_rows = sorted(host.aliases, key=lambda item: (not item.is_primary, item.alias.lower()))
    aliases = [item.alias for item in alias_rows if not item.is_primary]
    counts = counts or {}
    return {
        "id": host.id,
        "canonical_name": host.canonical_name,
        "display_name": host.display_name,
        "confidence": host.confidence,
        "source": host.source,
        "first_seen": counts.get("first_seen", host.first_seen),
        "last_seen": counts.get("last_seen", host.last_seen),
        "event_count": int(counts.get("event_count", host.event_count) or 0),
        "evidence_count": int(counts.get("evidence_count", host.evidence_count) or 0),
        "findings_count": int(counts.get("findings_count") or 0),
        "high_risk_count": int(counts.get("high_risk_count") or 0),
        "aliases": aliases,
        "alias_rows": [
            {
                "id": item.id,
                "alias": item.alias,
                "normalized_alias": item.normalized_alias,
                "is_primary": item.is_primary,
                "event_count": int(item.event_count or 0),
                "first_seen": item.first_seen,
                "last_seen": item.last_seen,
            }
            for item in alias_rows
        ],
        "all_names": [item.alias for item in alias_rows],
        "alias_count": len(aliases),
    }


def _host_attribution_snapshot(
    db: Session,
    case_id: str,
    *,
    evidences: list[Evidence] | None = None,
    findings: list[Finding] | None = None,
) -> dict[str, Any]:
    from app.services.host_attribution import build_host_attribution

    evidence_rows = evidences if evidences is not None else db.query(Evidence).filter(Evidence.case_id == case_id).all()
    finding_rows = findings if findings is not None else db.query(Finding).filter(Finding.case_id == case_id).all()
    return build_host_attribution(case_id, evidences=evidence_rows, findings=finding_rows, top_host_counts=None)


def _observed_host_counts(db: Session, case_id: str) -> dict[str, dict[str, Any]]:
    host_attribution = _host_attribution_snapshot(db, case_id)
    counts: dict[str, dict[str, Any]] = {}
    for row in host_attribution.get("hosts") or []:
        host = normalize_host_alias(row.get("host"))
        if not host or host == "unknown":
            continue
        counts[host] = {
            "host": host,
            "event_count": int(row.get("events_count") or 0),
            "findings_count": int(row.get("findings_count") or 0),
            "high_risk_count": int(row.get("high_risk_count") or 0),
            "evidence_ids": list(row.get("evidence_ids") or []),
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
        }
    return counts


def _ensure_default_case_hosts(db: Session, case_id: str) -> None:
    if not _can_materialize_host_identity(db):
        return
    observed = _observed_host_counts(db, case_id)
    changed = False
    for normalized, counts in observed.items():
        _upsert_observed_case_host(db, case_id=case_id, normalized=normalized, counts=counts)
        changed = True
    if changed:
        db.commit()


def _sync_case_host_rollups(db: Session, case_id: str) -> None:
    if not _can_materialize_host_identity(db):
        return
    observed = _observed_host_counts(db, case_id)
    hosts = _load_case_hosts(db, case_id)
    changed = False
    for host in hosts:
        alias_counts = [observed.get(alias.normalized_alias) for alias in host.aliases if alias.normalized_alias in observed]
        host.event_count = sum(int(item.get("event_count") or 0) for item in alias_counts if item)
        host.evidence_count = len({evidence_id for item in alias_counts if item for evidence_id in (item.get("evidence_ids") or [])})
        host.first_seen = _seen_iso([item.get("first_seen") for item in alias_counts if item], pick="min")
        host.last_seen = _seen_iso([item.get("last_seen") for item in alias_counts if item], pick="max")
        for alias in host.aliases:
            details = observed.get(alias.normalized_alias)
            alias.event_count = int(details.get("event_count") or 0) if details else 0
            alias.first_seen = details.get("first_seen") if details else None
            alias.last_seen = details.get("last_seen") if details else None
        changed = True
    if changed:
        db.commit()


def get_case_hosts(db: Session, case_id: str) -> list[dict[str, Any]]:
    _ensure_default_case_hosts(db, case_id)
    _sync_case_host_rollups(db, case_id)
    observed = _observed_host_counts(db, case_id)
    output: list[dict[str, Any]] = []
    for host in _load_case_hosts(db, case_id):
        alias_counts = [observed.get(alias.normalized_alias) for alias in host.aliases if alias.normalized_alias in observed]
        counts = {
            "event_count": sum(int(item.get("event_count") or 0) for item in alias_counts if item),
            "findings_count": sum(int(item.get("findings_count") or 0) for item in alias_counts if item),
            "high_risk_count": sum(int(item.get("high_risk_count") or 0) for item in alias_counts if item),
            "evidence_count": len({evidence_id for item in alias_counts if item for evidence_id in (item.get("evidence_ids") or [])}),
            "first_seen": _seen_iso([item.get("first_seen") for item in alias_counts if item], pick="min"),
            "last_seen": _seen_iso([item.get("last_seen") for item in alias_counts if item], pick="max"),
        }
        output.append(_serialize_case_host(host, counts=counts))
    return sorted(output, key=lambda item: (-item["event_count"], item["display_name"]))


def build_case_host_candidates(db: Session, case_id: str) -> list[dict[str, Any]]:
    hosts = get_case_hosts(db, case_id)
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, left in enumerate(hosts):
        left_names = [left["canonical_name"], *left.get("aliases", [])]
        left_short = {item for item in (_short_host_alias(name) for name in left_names) if item}
        left_all = {normalize_host_alias(name) for name in left_names if normalize_host_alias(name)}
        for right in hosts[index + 1 :]:
            right_names = [right["canonical_name"], *right.get("aliases", [])]
            right_short = {item for item in (_short_host_alias(name) for name in right_names) if item}
            right_all = {normalize_host_alias(name) for name in right_names if normalize_host_alias(name)}
            if left_all & right_all:
                continue
            shared_short = sorted(left_short & right_short)
            if not shared_short:
                continue
            key = tuple(sorted((left["id"], right["id"])))
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                {
                    "candidate_type": "short_hostname_match",
                    "shared_short_names": shared_short,
                    "hosts": [
                        {"id": left["id"], "display_name": left["display_name"], "aliases": left.get("aliases", [])},
                        {"id": right["id"], "display_name": right["display_name"], "aliases": right.get("aliases", [])},
                    ],
                    "confidence": "medium",
                }
            )
    return candidates


def get_host_identity_audit(db: Session, case_id: str) -> list[dict[str, Any]]:
    rows = (
        db.query(CaseHostIdentityAudit)
        .filter(CaseHostIdentityAudit.case_id == case_id)
        .order_by(CaseHostIdentityAudit.created_at.desc())
        .all()
    )
    return [
        {
            "id": row.id,
            "case_id": row.case_id,
            "case_host_id": row.case_host_id,
            "action": row.action,
            "old_value": deepcopy(row.old_value or {}),
            "new_value": deepcopy(row.new_value or {}),
            "reason": row.reason,
            "analyst": row.analyst,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


def resolve_canonical_host(db: Session, case_id: str, observed_host_name: str | None) -> dict[str, Any] | None:
    normalized = normalize_host_alias(observed_host_name)
    if not normalized:
        return None
    _ensure_default_case_hosts(db, case_id)
    alias_row = _load_alias_by_normalized(db, case_id).get(normalized)
    if not alias_row:
        return None
    host = alias_row.case_host
    aliases = sorted(item.alias for item in host.aliases)
    return {
        "case_host_id": host.id,
        "canonical_name": host.canonical_name,
        "display_name": host.display_name,
        "confidence": host.confidence,
        "source": host.source,
        "aliases": aliases,
        "normalized_aliases": sorted(item.normalized_alias for item in host.aliases),
        "observed_name": alias_row.alias,
    }


def expand_host_filter(db: Session, case_id: str, canonical_or_alias: str | None) -> list[str]:
    normalized = normalize_host_alias(canonical_or_alias)
    if not normalized:
        return []
    resolved = resolve_canonical_host(db, case_id, normalized)
    if not resolved:
        return [normalized]
    expanded = set(resolved.get("normalized_aliases") or [])
    expanded.add(str(resolved.get("canonical_name") or "").strip().lower())
    return sorted(item for item in expanded if item)


def event_matches_host_filter(db: Session, case_id: str, event: dict[str, Any], host_filter: str | None) -> bool:
    expanded = set(expand_host_filter(db, case_id, host_filter))
    if not expanded:
        return True
    host = event.get("host") or {}
    observed_host = event.get("observed_host") or {}
    candidates = {
        normalize_host_alias((host if isinstance(host, dict) else {}).get("name")),
        normalize_host_alias((observed_host if isinstance(observed_host, dict) else {}).get("name")),
    }
    return any(candidate in expanded for candidate in candidates if candidate)


def apply_case_host_identity(db: Session, case_id: str, event: dict[str, Any]) -> dict[str, Any]:
    host = event.setdefault("host", {})
    if not isinstance(host, dict):
        host = {}
        event["host"] = host
    observed_host = event.setdefault("observed_host", {})
    if not isinstance(observed_host, dict):
        observed_host = {}
        event["observed_host"] = observed_host
    observed_name = str(observed_host.get("name") or host.get("name") or host.get("hostname") or "").strip()
    provided_host, detected_host = _evidence_hosts(db, str(event.get("evidence_id") or "").strip() or None)
    canonicalized = canonicalize_host(provided_host=provided_host, detected_host=detected_host, artifact_host=observed_name)
    if canonicalized.get("canonical") or is_invalid_host_value(observed_name):
        return _apply_host_canonicalization(event, canonicalized)
    if not observed_name:
        return event
    observed_host.setdefault("name", observed_name)
    observed_host.setdefault("hostname", observed_name)
    resolved = resolve_canonical_host(db, case_id, observed_name)
    if not resolved:
        return event
    host["name"] = resolved["canonical_name"]
    host["hostname"] = resolved["canonical_name"]
    host["canonical"] = resolved["canonical_name"]
    host["aliases"] = list(resolved.get("aliases") or [])
    host["identity_id"] = resolved["case_host_id"]
    host["identity_confidence"] = resolved["confidence"]
    return event


def hydrate_case_host_display(db: Session, case_id: str, event: dict[str, Any]) -> dict[str, Any]:
    item = deepcopy(event)
    host = item.setdefault("host", {})
    if not isinstance(host, dict):
        host = {}
        item["host"] = host
    observed_host = item.setdefault("observed_host", {})
    if not isinstance(observed_host, dict):
        observed_host = {}
        item["observed_host"] = observed_host
    observed_name = str(observed_host.get("name") or host.get("name") or "").strip()
    if observed_name:
        observed_host.setdefault("name", observed_name)
        observed_host.setdefault("hostname", observed_name)
    resolved = resolve_canonical_host(db, case_id, observed_name or host.get("name"))
    if not resolved:
        return item
    host["name"] = resolved["canonical_name"]
    host["hostname"] = resolved["canonical_name"]
    host["canonical"] = resolved["canonical_name"]
    host["aliases"] = list(resolved.get("aliases") or [])
    host["identity_id"] = resolved["case_host_id"]
    host["identity_confidence"] = resolved["confidence"]
    return item


def _ensure_primary_alias(host: CaseHost) -> None:
    primary = next((alias for alias in host.aliases if alias.is_primary), None)
    if primary:
        host.canonical_name = primary.normalized_alias
        host.display_name = primary.alias
        return
    if host.aliases:
        host.aliases[0].is_primary = True
        host.canonical_name = host.aliases[0].normalized_alias
        host.display_name = host.aliases[0].alias


def _delete_empty_host(db: Session, host: CaseHost) -> None:
    if host.aliases:
        return
    db.delete(host)


def merge_hosts(
    db: Session,
    case_id: str,
    canonical_host_id: str,
    aliases: list[str],
    reason: str | None = None,
    analyst: str | None = None,
) -> dict[str, Any]:
    _ensure_default_case_hosts(db, case_id)
    host = (
        db.query(CaseHost)
        .options(joinedload(CaseHost.aliases))
        .filter(CaseHost.id == canonical_host_id, CaseHost.case_id == case_id)
        .first()
    )
    if not host:
        raise ValueError("Canonical host not found")
    alias_rows = _load_alias_by_normalized(db, case_id)
    moved: list[dict[str, Any]] = []
    for alias_name in aliases:
        normalized = normalize_host_alias(alias_name)
        if not normalized:
            continue
        alias_row = alias_rows.get(normalized)
        if not alias_row or alias_row.case_host_id == host.id:
            continue
        previous_host = alias_row.case_host
        moved.append(
            {
                "alias": alias_row.alias,
                "from_host_id": previous_host.id if previous_host else None,
                "from_canonical": previous_host.canonical_name if previous_host else None,
                "to_host_id": host.id,
                "to_canonical": host.canonical_name,
            }
        )
        alias_row.case_host = host
        alias_row.source = "manual"
        alias_row.confidence = "manual"
        alias_row.is_primary = False
        if previous_host:
            previous_host.source = "manual"
            previous_host.confidence = "manual"
            _ensure_primary_alias(previous_host)
            if not previous_host.aliases:
                _delete_empty_host(db, previous_host)
    host.source = "manual"
    host.confidence = "manual"
    _ensure_primary_alias(host)
    _audit_entry(
        db,
        case_id=case_id,
        case_host_id=host.id,
        action="merge_hosts",
        old_value={"canonical_host_id": canonical_host_id, "aliases": aliases},
        new_value={"canonical_name": host.canonical_name, "moved_aliases": moved},
        reason=reason,
        analyst=analyst,
    )
    db.commit()
    _sync_case_host_rollups(db, case_id)
    return _serialize_case_host(db.get(CaseHost, host.id))


def split_alias(
    db: Session,
    case_id: str,
    alias_id: str,
    reason: str | None = None,
    analyst: str | None = None,
) -> dict[str, Any]:
    alias = (
        db.query(CaseHostAlias)
        .options(joinedload(CaseHostAlias.case_host).joinedload(CaseHost.aliases))
        .filter(CaseHostAlias.id == alias_id, CaseHostAlias.case_id == case_id)
        .first()
    )
    if not alias:
        raise ValueError("Alias not found")
    if alias.is_primary:
        raise ValueError("Primary alias cannot be split from its own host")
    previous = alias.case_host
    new_host = CaseHost(
        case_id=case_id,
        canonical_name=alias.normalized_alias,
        display_name=alias.alias,
        confidence="manual",
        source="manual",
    )
    db.add(new_host)
    db.flush()
    alias.case_host = new_host
    alias.is_primary = True
    alias.source = "manual"
    alias.confidence = "manual"
    _ensure_primary_alias(previous)
    _audit_entry(
        db,
        case_id=case_id,
        case_host_id=new_host.id,
        action="split_alias",
        old_value={"previous_host_id": previous.id, "alias": alias.alias},
        new_value={"new_host_id": new_host.id, "canonical_name": new_host.canonical_name},
        reason=reason,
        analyst=analyst,
    )
    db.commit()
    _sync_case_host_rollups(db, case_id)
    return _serialize_case_host(db.get(CaseHost, new_host.id))


def rename_canonical_host(
    db: Session,
    case_id: str,
    host_id: str,
    new_name: str,
    reason: str | None = None,
    analyst: str | None = None,
) -> dict[str, Any]:
    normalized = normalize_host_alias(new_name)
    if not normalized:
        raise ValueError("New canonical host name is empty")
    host = (
        db.query(CaseHost)
        .options(joinedload(CaseHost.aliases))
        .filter(CaseHost.id == host_id, CaseHost.case_id == case_id)
        .first()
    )
    if not host:
        raise ValueError("Host not found")
    conflict = (
        db.query(CaseHostAlias)
        .filter(
            CaseHostAlias.case_id == case_id,
            CaseHostAlias.normalized_alias == normalized,
            CaseHostAlias.case_host_id != host.id,
        )
        .first()
    )
    if conflict:
        raise ValueError("New canonical host name already belongs to another host")
    previous = {"canonical_name": host.canonical_name, "display_name": host.display_name}
    primary = next((alias for alias in host.aliases if alias.is_primary), None)
    if primary:
        old_primary_alias = primary.alias
        old_primary_normalized = primary.normalized_alias
        primary.alias = new_name.strip()
        primary.normalized_alias = normalized
        primary.source = "manual"
        primary.confidence = "manual"
        if old_primary_normalized != normalized and not any(item.normalized_alias == old_primary_normalized and not item.is_primary for item in host.aliases):
            db.add(
                CaseHostAlias(
                    case_host_id=host.id,
                    case_id=case_id,
                    alias=old_primary_alias,
                    normalized_alias=old_primary_normalized,
                    source="manual",
                    confidence="manual",
                    is_primary=False,
                )
            )
    else:
        db.add(
            CaseHostAlias(
                case_host_id=host.id,
                case_id=case_id,
                alias=new_name.strip(),
                normalized_alias=normalized,
                source="manual",
                confidence="manual",
                is_primary=True,
            )
        )
    host.canonical_name = normalized
    host.display_name = new_name.strip()
    host.source = "manual"
    host.confidence = "manual"
    _audit_entry(
        db,
        case_id=case_id,
        case_host_id=host.id,
        action="rename_canonical_host",
        old_value=previous,
        new_value={"canonical_name": host.canonical_name, "display_name": host.display_name},
        reason=reason,
        analyst=analyst,
    )
    db.commit()
    _sync_case_host_rollups(db, case_id)
    return _serialize_case_host(db.get(CaseHost, host.id))
