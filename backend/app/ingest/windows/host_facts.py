"""Host-identity Host Facts derived from Windows artifacts.

Windows has no single dedicated "who am I" file the way Linux does
(/etc/hostname, hostnamectl -- see app.ingest.linux.os_info). What every
Windows Event Log record DOES carry, per the MS-EVEN6 System/Computer
element, is the FQDN of the machine that generated it -- independent of
which parser, collection tool, or artifact family produced the record
(EVTX raw, Sysmon, PowerShell operational, Security, Defender, ...). That
field already reaches every normalized Windows event as
document["windows"]["computer_field"] (see normalize_evtx_row in
app.ingest.artifact_normalizers) -- deliberately NOT the sibling
"computer" field, which falls back to evidence-level detected/provided
host metadata and is therefore unsuitable as a Host Facts source (a Host
Fact must be a genuine per-artifact observation, never a copy of the
case's already-assigned host label).

This module derives at most one hostname + one fqdn observation per
artifact batch from that field -- never per individual event, which would
turn one fact into tens of thousands of redundant rows. It returns NEW
synthetic documents (artifact_family "windows_host_identity") rather than
mutating the real event documents, which stay exactly as parsed and headed
to the search index unchanged.

Deliberately out of scope here (per the sprint's own constraints): Windows
distribution/version (needs a SOFTWARE hive artifact, not collected for
every case), kernel/architecture (no reliable generic Windows artifact
observed today), timezone and computer name from the SYSTEM registry hive
(technically reachable via the same python-registry dependency
app.ingest.raw_parsers.shimcache_parser already uses to open that hive,
but ControlSet-aware key resolution is real new parsing work, not just
wiring -- building it without dedicated hive-format testing would risk
exactly the "weak inference" this feature explicitly must not produce).
Any of those becomes a second registered extractor in this same module
once a reliable source exists; nothing about this file's shape changes.
"""
from __future__ import annotations

import re

from app.ingest.host_facts_extraction import register_host_fact_extractor
from app.ingest.identity_extraction import is_valid_hostname
from app.ingest.linux.os_info import FACT_FQDN, FACT_HOSTNAME

ARTIFACT_FAMILY = "windows_host_identity"
SOURCE_KIND_EVTX_COMPUTER = "evtx_computer_field"

# is_valid_hostname() is a shared, general-purpose syntax check (used well
# beyond Host Facts) and does not reject "localhost" -- syntactically valid
# as a hostname, but never a genuine machine identity, and Windows Event
# Log never legitimately writes it into System/Computer. Rejected locally
# rather than widening the shared check, whose other callers this was not
# evaluated against.
_NEVER_A_REAL_IDENTITY = {"localhost", "127.0.0.1", "::1"}

# RFC 1123-shaped, at least two dot-separated labels -- mirrors
# app.ingest.linux.os_info's own FQDN check exactly, so "WS01" is never
# promoted to an FQDN and no domain is ever invented that was not already
# present in the observed value.
_LABEL = r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
_FQDN_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})+$")


def _looks_like_fqdn(value: str) -> bool:
    return bool(_FQDN_RE.match(value.strip()))


def _row(*, fact_type: str, raw_value: str, normalized_value: str, source_file: str) -> dict:
    return {
        "event": {
            "category": "host",
            "type": "windows_host_identity",
            "action": "windows_host_identity_observed",
            "message": f"Windows {fact_type} observation ({SOURCE_KIND_EVTX_COMPUTER}): {normalized_value}",
            "severity": "info",
        },
        "artifact": {
            "type": ARTIFACT_FAMILY,
            "name": "Windows Event Log Computer field",
            "parser": SOURCE_KIND_EVTX_COMPUTER,
            "source_path": source_file,
        },
        "source_file": source_file,
        "host_fact": {
            "fact_type": fact_type,
            "artifact_family": ARTIFACT_FAMILY,
            "artifact_type": SOURCE_KIND_EVTX_COMPUTER,
            "source_file": source_file,
            "raw_value": raw_value,
            "normalized_value": normalized_value,
            # An EVTX record's own System/Computer element is written by
            # the Windows Event Log subsystem itself, not a heuristic --
            # the same tier of reliability as Linux's /etc/hostname.
            "confidence": "high",
            "parse_status": "valid",
            "reason": "",
        },
    }


@register_host_fact_extractor
def extract_windows_host_identity(documents: list[dict]) -> list[dict]:
    for doc in documents:
        raw = ((doc.get("windows") or {}).get("computer_field") or "").strip()
        if not raw or raw.lower() in _NEVER_A_REAL_IDENTITY or not is_valid_hostname(raw):
            continue
        source_file = (doc.get("artifact") or {}).get("source_path") or doc.get("source_file") or ""
        short_hostname = raw.split(".", 1)[0].strip()
        rows: list[dict] = []
        if short_hostname:
            rows.append(_row(fact_type=FACT_HOSTNAME, raw_value=raw, normalized_value=short_hostname, source_file=source_file))
        if _looks_like_fqdn(raw):
            rows.append(_row(fact_type=FACT_FQDN, raw_value=raw, normalized_value=raw, source_file=source_file))
        # is_valid_hostname() (which internally normalizes/lowercases) is
        # only the validity gate above -- it rejects placeholder/junk
        # values ("unknown", "localhost", driver names, ...). The recorded
        # fact keeps the original observed casing, matching how
        # app.ingest.linux.os_info._hostname_rows never lowercases either.
        return rows  # one representative observation per artifact batch is enough
    return []
