"""Host Facts: a generic layer that aggregates normalized observations into
small, connected records of what Kairon has learned about a host.

Architecture:

    Evidence -> Artifacts -> Normalized documents -> host_fact extraction
        (app.ingest.host_facts_extraction, platform-agnostic)
        -> Host Facts (this module) -> Host Info UI -> Timeline
        -> Correlation -> AI

A HostFact row never duplicates evidence. The raw file/record lives on disk
or in the search index under the evidence's own storage. This layer stores
only the small, structured fact each observation asserts, plus enough
foreign keys (case, evidence, artifact, host) to stay connected to that
chain, and (when the source document was itself indexed, as Linux's
dedicated os_info/timezone observations are) an ``event_id`` to pivot
straight back to it.

Conflict resolution is deliberately not silent: ``resolve_host_facts``
always returns every supporting and conflicting observation alongside the
preferred value, so an analyst sees a disagreement rather than a single
number that hides it.

Platform coverage: every function in this module is generic over fact_type
and reads only the platform-agnostic ``document["host_fact"]`` shape (see
app.ingest.host_facts_extraction) -- it has no platform-specific logic of
its own. Linux was the first producer (host.timezone, then host.hostname,
host.fqdn, host.distribution, host.distribution_version, host.kernel,
host.architecture -- see app.ingest.linux.os_info / .timezone). Windows
followed (host.hostname, host.fqdn from the EVTX Computer field -- see
app.ingest.windows.host_facts) without any change to this module at all.
Adding a new platform's producer never requires touching this file.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime

from sqlalchemy.orm import Session

from app.ingest.linux.os_info import (
    FACT_ARCHITECTURE,
    FACT_DISTRIBUTION,
    FACT_DISTRIBUTION_VERSION,
    FACT_FQDN,
    FACT_HOSTNAME,
    FACT_KERNEL,
)
from app.ingest.linux.timezone import FACT_TYPE_TIMEZONE
from app.models.host_fact import HostFact

# Deterministic tie-break order used only when independent sources for the
# same host and fact_type disagree and a single "preferred value" must still
# be surfaced (the resolution response always also carries every
# conflicting observation, so this ranking never hides the disagreement --
# see resolve_host_facts). Keyed by (fact_type, source_kind) because the
# same source_kind can rank differently depending on what it is being
# asked about -- hostnamectl is a strong source for the host's live
# hostname, but only a secondary one for distribution (no machine-readable
# ID field) and for kernel/architecture (it just echoes uname/proc). A
# (fact_type, source_kind) pair with no entry defaults to 0.
_SOURCE_PRIORITY: dict[tuple[str, str], int] = {
    # host.timezone -- the two sources that reflect the system's current,
    # live configuration on the two major distro families rank above
    # copies/derivations of it.
    (FACT_TYPE_TIMEZONE, "etc_timezone"): 100,
    (FACT_TYPE_TIMEZONE, "timedatectl"): 90,
    (FACT_TYPE_TIMEZONE, "etc_localtime_symlink"): 80,
    (FACT_TYPE_TIMEZONE, "sysconfig_clock"): 70,
    (FACT_TYPE_TIMEZONE, "conf_d_clock"): 65,
    (FACT_TYPE_TIMEZONE, "etc_localtime_tzif"): 60,
    (FACT_TYPE_TIMEZONE, "hostnamectl"): 50,
    # host.hostname / host.fqdn -- the persisted config file and the live
    # systemd-managed value should normally agree; when they don't,
    # /etc/hostname is what the machine will present on its next boot.
    (FACT_HOSTNAME, "hostname"): 100,
    (FACT_HOSTNAME, "hostnamectl"): 90,
    (FACT_FQDN, "hostname"): 100,
    (FACT_FQDN, "hostnamectl"): 90,
    # Windows has no equivalent of a persisted /etc/hostname file today
    # (see app.ingest.windows.host_facts) -- the EVTX Computer field is
    # currently its only source, so it has no sibling to rank against.
    (FACT_HOSTNAME, "evtx_computer_field"): 80,
    (FACT_FQDN, "evtx_computer_field"): 80,
    # host.distribution / host.distribution_version -- os-release is the
    # current standard, machine-readable spec; lsb-release is its legacy
    # predecessor (still shipped alongside it on Debian/Ubuntu, usually
    # redundant); hostnamectl only carries a human-readable pretty name,
    # no machine-readable ID; debian_version is the weakest signal (its
    # presence alone implies "debian", but it carries no distribution name
    # of its own -- see the reason on that row).
    (FACT_DISTRIBUTION, "os_release"): 100,
    (FACT_DISTRIBUTION, "lsb_release"): 80,
    (FACT_DISTRIBUTION, "hostnamectl"): 60,
    (FACT_DISTRIBUTION, "debian_version"): 40,
    (FACT_DISTRIBUTION_VERSION, "os_release"): 100,
    (FACT_DISTRIBUTION_VERSION, "lsb_release"): 80,
    (FACT_DISTRIBUTION_VERSION, "debian_version"): 70,
    (FACT_DISTRIBUTION_VERSION, "hostnamectl"): 60,
    # host.kernel / host.architecture -- uname is the direct command output
    # this information exists to describe; /proc/version is equally
    # authoritative but a little harder to parse cleanly; hostnamectl
    # again only echoes what uname already reports.
    (FACT_KERNEL, "uname"): 100,
    (FACT_KERNEL, "kernel_version"): 90,
    (FACT_KERNEL, "hostnamectl"): 70,
    (FACT_ARCHITECTURE, "uname"): 100,
    (FACT_ARCHITECTURE, "kernel_version"): 90,
    (FACT_ARCHITECTURE, "hostnamectl"): 70,
    # Windows -- the SYSTEM hive's own persisted configuration (a genuine
    # on-disk record, the same tier of reliability as Linux's /etc/hostname)
    # outranks the EVTX Computer field (a per-record echo, present on every
    # log entry but not the canonical source of truth for the value), which
    # in turn outranks a memory snapshot (windows.info -- reflects the
    # single instant the image was acquired, and Volatility's own value
    # extraction is a best-effort read of kernel structures rather than a
    # persisted configuration file). See app.ingest.windows.host_facts,
    # app.ingest.raw_parsers.system_hive_identity_parser,
    # app.ingest.windows.memory_host_facts.
    (FACT_HOSTNAME, "system_hive_computername"): 90,
    (FACT_TYPE_TIMEZONE, "system_hive_timezone_key_name"): 80,
    (FACT_DISTRIBUTION, "system_hive_buildlab"): 90,
    (FACT_DISTRIBUTION, "memory_windows_info"): 70,
    (FACT_DISTRIBUTION_VERSION, "system_hive_buildlab"): 90,
    (FACT_DISTRIBUTION_VERSION, "memory_windows_info"): 70,
    (FACT_ARCHITECTURE, "system_hive_buildlab"): 90,
    (FACT_ARCHITECTURE, "memory_windows_info"): 70,
}


# Fact types whose *comparison* is case-insensitive: DNS/NetBIOS names
# carry no intentional distinction between two observations that differ
# only in casing ("WS01.megacorp.local" and "ws01.megacorp.local" name the
# same machine), so treating them as a real conflict would be noise, not
# signal. No other fact_type gets this treatment -- a distribution or
# version string that differs by casing is either already normalized by
# its own producer (see app.ingest.linux.os_info's own .lower() calls on
# distribution/architecture) or is a genuine difference this resolver must
# keep visible, never paper over.
_CASE_INSENSITIVE_FACT_TYPES = {FACT_HOSTNAME, FACT_FQDN}


def normalize_host_fact_value(fact_type: str, value: str) -> str:
    """Comparison key for grouping observations of one fact_type.

    Used only to decide whether two observations agree -- it never
    replaces or mutates what is stored or shown. HostFact.normalized_value
    (and raw_value, provenance) always keep the exact casing/whitespace
    each source observed; this function is called at comparison time only,
    on values already read from the database or freshly extracted.
    """
    stripped = value.strip()
    if fact_type in _CASE_INSENSITIVE_FACT_TYPES:
        return stripped.lower()
    return stripped


def build_host_fact_fingerprint(
    case_id: str,
    evidence_id: str,
    artifact_id: str | None,
    fact_type: str,
    source_kind: str,
    raw_value: str | None,
) -> str:
    blob = "|".join(str(part or "") for part in (case_id, evidence_id, artifact_id, fact_type, source_kind, raw_value))
    return hashlib.sha256(blob.encode("utf-8", errors="ignore")).hexdigest()


def _group_query(db: Session, *, case_id: str, host_id: str | None, evidence_id: str, fact_type: str):
    query = db.query(HostFact).filter(HostFact.case_id == case_id, HostFact.fact_type == fact_type)
    if host_id:
        # Host identity is known: every evidence item assigned to this host
        # is in scope, so a disk image and a memory image of the same
        # machine correctly cross-check each other's timezone.
        return query.filter(HostFact.host_id == host_id)
    # Host identity is not resolved yet -- never guess that two evidence
    # items are the same host; scope strictly to this evidence.
    return query.filter(HostFact.host_id.is_(None), HostFact.evidence_id == evidence_id)


def _recompute_group_status(fact_type: str, rows: list[HostFact]) -> None:
    valid_rows = [row for row in rows if row.normalized_value]
    distinct_keys = {normalize_host_fact_value(fact_type, row.normalized_value) for row in valid_rows}
    for row in rows:
        if not row.normalized_value:
            row.status = "invalid"
        elif len(distinct_keys) == 1:
            row.status = "confirmed" if len(valid_rows) > 1 else "observed"
        else:
            row.status = "conflicting"


def create_host_fact_observations(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    artifact_id: str | None,
    host_id: str | None,
    observed_at: datetime | None,
    documents: list[dict],
) -> list[HostFact]:
    """Create one HostFact row per already-normalized observation document.

    ``documents`` are the output of app.ingest.host_facts_extraction
    .extract_host_fact_documents() for one artifact -- every document
    carries a platform-agnostic ``host_fact`` dict (fact_type,
    artifact_family, artifact_type, source_file, raw_value,
    normalized_value, confidence, parse_status, reason), regardless of
    which platform's normalizer/extractor produced it (see
    app.ingest.linux.os_info / app.ingest.linux.timezone for the Linux
    producers, app.ingest.windows.host_facts for the Windows one) -- this
    function itself has no platform-specific logic at all. Duplicate
    observations (matched by fingerprint) are skipped, so calling this
    twice for the same evidence/artifact is a no-op the second time.
    """
    created: list[HostFact] = []
    touched_groups: set[str] = set()
    for doc in documents:
        fact = doc.get("host_fact") or {}
        fact_type = str(fact.get("fact_type") or "").strip()
        if not fact_type:
            continue
        source_kind = str(fact.get("artifact_type") or "")
        raw_value = str(fact.get("raw_value") or "")
        normalized_value = str(fact.get("normalized_value") or "").strip() or None
        confidence = str(fact.get("confidence") or "medium")
        parse_status = str(fact.get("parse_status") or "")
        fingerprint = build_host_fact_fingerprint(case_id, evidence_id, artifact_id, fact_type, source_kind, raw_value)
        if db.query(HostFact.id).filter(HostFact.fingerprint == fingerprint).first() is not None:
            continue
        row = HostFact(
            case_id=case_id,
            evidence_id=evidence_id,
            artifact_id=artifact_id,
            host_id=host_id,
            fact_type=fact_type,
            source_kind=source_kind,
            parser=str((doc.get("artifact") or {}).get("parser") or ""),
            source_path=fact.get("source_file") or doc.get("source_file"),
            raw_value=raw_value or None,
            normalized_value=normalized_value,
            confidence=confidence,
            status="invalid" if parse_status != "valid" else "observed",
            observed_at=observed_at,
            event_id=doc.get("event_id"),
            fingerprint=fingerprint,
            provenance={
                "reason": fact.get("reason") or "",
                "tzif_meta": fact.get("tzif_meta") or {},
                "parse_status": parse_status,
                # Purely additive, optional passthrough for producers whose
                # provenance doesn't fit case_id/evidence_id/artifact_id/
                # event_id alone -- e.g. app.ingest.windows.memory_host_facts
                # has no artifacts-table row to point artifact_id at, so it
                # carries memory_run_id/memory_plugin_run_id/plugin here.
                **(fact.get("extra_provenance") or {}),
            },
        )
        db.add(row)
        created.append(row)
        touched_groups.add(fact_type)
    if not created:
        return created
    db.flush()
    for fact_type in touched_groups:
        group_rows = _group_query(db, case_id=case_id, host_id=host_id, evidence_id=evidence_id, fact_type=fact_type).all()
        _recompute_group_status(fact_type, group_rows)
    db.commit()
    return created


def delete_host_facts_for_evidence(db: Session, evidence_id: str) -> int:
    """Remove every Host Fact observation sourced from this evidence.

    Called from reprocess cleanup alongside the existing events/artifacts
    cleanup, so reprocessing an evidence rebuilds its Host Facts instead of
    accumulating stale rows next to fresh ones. Does not commit; the caller
    commits as part of its own cleanup transaction.
    """
    return db.query(HostFact).filter(HostFact.evidence_id == evidence_id).delete(synchronize_session=False)


def _serialize(row: HostFact) -> dict:
    return {
        "id": row.id,
        "source_kind": row.source_kind,
        "parser": row.parser,
        "source_path": row.source_path,
        "raw_value": row.raw_value,
        "normalized_value": row.normalized_value,
        "confidence": row.confidence,
        "status": row.status,
        "observed_at": row.observed_at.isoformat() if row.observed_at else None,
        "event_id": row.event_id,
        "evidence_id": row.evidence_id,
        "artifact_id": row.artifact_id,
        "host_id": row.host_id,
        "provenance": row.provenance,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def _resolve_group(fact_type: str, rows: list[HostFact]) -> dict:
    if not rows:
        return {"fact_type": fact_type, "status": "missing", "preferred_value": None, "supporting": [], "conflicting": [], "invalid": [], "observations": []}
    valid_rows = [row for row in rows if row.normalized_value]
    invalid_rows = [row for row in rows if not row.normalized_value]
    if not valid_rows:
        return {
            "fact_type": fact_type,
            "status": "invalid",
            "preferred_value": None,
            "supporting": [],
            "conflicting": [],
            "invalid": [_serialize(row) for row in invalid_rows],
            "observations": [_serialize(row) for row in rows],
        }
    # Grouping key: case-insensitive for host.hostname/host.fqdn, exact
    # match for everything else (see normalize_host_fact_value). Two
    # observations that share a key never surface as a conflict, however
    # many distinct raw strings back that key -- but the exact original
    # casing each source reported still stays intact in raw_value,
    # normalized_value and provenance, and a genuinely different key (a
    # different hostname, not just a different casing of the same one) is
    # never folded into that group.
    distinct_keys = {normalize_host_fact_value(fact_type, row.normalized_value) for row in valid_rows}
    # Same tie-break already used for genuine conflicts (highest-priority
    # source; ties broken by the stable created_at ordering rows already
    # arrive in) now also picks the displayed representation when several
    # observations agree but differ only in casing -- deterministic and
    # stable across reprocesses without a new heuristic.
    preferred_row = max(valid_rows, key=lambda row: _SOURCE_PRIORITY.get((fact_type, row.source_kind), 0))
    preferred = preferred_row.normalized_value
    preferred_key = normalize_host_fact_value(fact_type, preferred)
    status = ("confirmed" if len(valid_rows) > 1 else "observed") if len(distinct_keys) == 1 else "conflicting"
    return {
        "fact_type": fact_type,
        "status": status,
        "preferred_value": preferred,
        "supporting": [_serialize(row) for row in valid_rows if normalize_host_fact_value(fact_type, row.normalized_value) == preferred_key],
        "conflicting": [_serialize(row) for row in valid_rows if normalize_host_fact_value(fact_type, row.normalized_value) != preferred_key],
        "invalid": [_serialize(row) for row in invalid_rows],
        "observations": [_serialize(row) for row in rows],
    }


def resolve_host_facts(
    db: Session,
    *,
    case_id: str,
    host_id: str | None = None,
    evidence_id: str | None = None,
    fact_type: str | None = None,
) -> list[dict]:
    """Resolve stored observations into a per-fact_type summary.

    Scope precedence: an explicit host_id takes every evidence assigned to
    that host into account; otherwise an explicit evidence_id scopes to
    that evidence alone; at least one of the two must be provided by the
    caller (enforced by the API layer, not here, so this function stays a
    plain query helper).

    When ``fact_type`` is given and no observation exists for it, a single
    ``status: "missing"`` entry is returned -- Host Facts represent
    observations, so this never invents a value, only reports its absence.
    """
    query = db.query(HostFact).filter(HostFact.case_id == case_id)
    if host_id:
        query = query.filter(HostFact.host_id == host_id)
    elif evidence_id:
        query = query.filter(HostFact.evidence_id == evidence_id)
    if fact_type:
        query = query.filter(HostFact.fact_type == fact_type)
    rows = query.order_by(HostFact.fact_type, HostFact.created_at).all()
    grouped: dict[str, list[HostFact]] = defaultdict(list)
    for row in rows:
        grouped[row.fact_type].append(row)
    fact_types = [fact_type] if fact_type else sorted(grouped.keys())
    return [_resolve_group(ft, grouped.get(ft, [])) for ft in fact_types]
