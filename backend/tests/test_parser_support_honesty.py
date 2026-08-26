from __future__ import annotations

from app.ingest.detector import EVIDENCE_TYPES_WITHOUT_INGEST_SUPPORT
from app.models.evidence import EvidenceType


def test_pcap_is_declared_as_having_no_ingest_support() -> None:
    """detect_evidence_type() classifies .pcap/.pcapng, but nothing parses them.

    Finishing that ingest as a clean "completed" with zero events tells an
    analyst the capture held nothing relevant, when in truth it was never read.
    """
    assert "pcap" in EVIDENCE_TYPES_WITHOUT_INGEST_SUPPORT


def test_working_evidence_types_are_not_marked_unsupported() -> None:
    """Guard against the inverse failure: flagging types that do ingest fine
    would fail perfectly good evidence. These all have real ingest paths in
    tasks.py/_select_artifacts and are exercised by real cases."""
    for evidence_type in (
        EvidenceType.velociraptor_zip,
        EvidenceType.memory_dump,
        EvidenceType.evtx,
        EvidenceType.kape_archive,
        EvidenceType.parsed_folder,
        EvidenceType.linux_triage,
        EvidenceType.macos_triage,
        EvidenceType.disk_image,
    ):
        assert evidence_type.value not in EVIDENCE_TYPES_WITHOUT_INGEST_SUPPORT, evidence_type


def test_unsupported_set_only_contains_known_evidence_types() -> None:
    known = {item.value for item in EvidenceType}
    assert EVIDENCE_TYPES_WITHOUT_INGEST_SUPPORT <= known
