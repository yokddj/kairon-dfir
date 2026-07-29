"""Host Facts: a generic layer that aggregates normalized observations into
small, connected records of what Kairon has learned about a host.

Architecture (see the Linux Host Facts Foundation sprint):

    Evidence -> Artifacts -> Normalized observations -> Host Facts
        -> (future) Host Info UI -> Timeline -> Correlation -> AI

A HostFact row never duplicates evidence. The raw file lives on disk under
the evidence's own storage, and the full normalized record is already
searchable as an indexed event under the source artifact's own family (for
timezone: ``linux_timezone``). This layer stores only the small, structured
fact each observation asserts, plus enough foreign keys (case, evidence,
artifact, host) to stay connected to that chain, and an ``event_id`` to
pivot straight back to the underlying searchable record.

Conflict resolution is deliberately not silent: ``resolve_host_facts``
always returns every supporting and conflicting observation alongside the
preferred value, so an analyst sees a disagreement rather than a single
number that hides it.

Timezone (``host.timezone``) was the first fact_type this module supported;
host.hostname, host.fqdn, host.distribution, host.distribution_version,
host.kernel and host.architecture followed in the Host Facts: Identity &
Operating System sprint without any change to this module at all -- every
function here was already generic over fact_type, which is exactly what
that sprint set out to validate.
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
}


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


def _recompute_group_status(rows: list[HostFact]) -> None:
    valid_rows = [row for row in rows if row.normalized_value]
    distinct_values = {row.normalized_value for row in valid_rows}
    for row in rows:
        if not row.normalized_value:
            row.status = "invalid"
        elif len(distinct_values) == 1:
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

    ``documents`` are the same normalized documents already headed to the
    search index for this artifact (see app.ingest.linux.timezone and
    app.ingest.artifact_normalizers.normalize_linux_row) -- this function
    reads the small set of ``linux.timezone_*``/``linux.fact_type`` fields
    they already carry rather than re-parsing anything. Duplicate
    observations (matched by fingerprint) are skipped, so calling this
    twice for the same evidence/artifact is a no-op the second time.
    """
    created: list[HostFact] = []
    touched_groups: set[str] = set()
    for doc in documents:
        linux = doc.get("linux") or {}
        fact_type = str(linux.get("fact_type") or "").strip()
        if not fact_type:
            continue
        source_kind = str(linux.get("artifact_type") or "")
        raw_value = str(linux.get("timezone_raw_value") or "")
        normalized_value = str(linux.get("timezone_name") or "").strip() or None
        confidence = str(linux.get("timezone_confidence") or "medium")
        parse_status = str(linux.get("timezone_parse_status") or "")
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
            source_path=linux.get("source_file") or doc.get("source_file"),
            raw_value=raw_value or None,
            normalized_value=normalized_value,
            confidence=confidence,
            status="invalid" if parse_status != "valid" else "observed",
            observed_at=observed_at,
            event_id=doc.get("event_id"),
            fingerprint=fingerprint,
            provenance={
                "reason": linux.get("timezone_parse_reason") or "",
                "tzif_meta": linux.get("timezone_tzif_meta") or {},
                "parse_status": parse_status,
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
        _recompute_group_status(group_rows)
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
    distinct_values = sorted({row.normalized_value for row in valid_rows})
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
    if len(distinct_values) == 1:
        preferred = distinct_values[0]
        status = "confirmed" if len(valid_rows) > 1 else "observed"
    else:
        preferred = max(valid_rows, key=lambda row: _SOURCE_PRIORITY.get((fact_type, row.source_kind), 0)).normalized_value
        status = "conflicting"
    return {
        "fact_type": fact_type,
        "status": status,
        "preferred_value": preferred,
        "supporting": [_serialize(row) for row in valid_rows if row.normalized_value == preferred],
        "conflicting": [_serialize(row) for row in valid_rows if row.normalized_value != preferred],
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
