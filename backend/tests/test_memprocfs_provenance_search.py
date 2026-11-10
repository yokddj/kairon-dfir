"""MemProcFS event provenance (memprocfs.source / memprocfs.timeline) is mapped and searchable."""

from __future__ import annotations

from pathlib import Path

from app.core import opensearch
from app.search.query_syntax import analyze_query_syntax


def test_memprocfs_provenance_is_mapped_on_new_and_existing_indices() -> None:
    assert Path(opensearch.__file__).read_text().count('"memprocfs": {') == 2


def test_memprocfs_provenance_is_accepted_in_queries() -> None:
    query = analyze_query_syntax("memprocfs.source:evtx_repaired AND memprocfs.timeline:eventlog", lambda text: {"simple_query_string": {"query": text}})["query"]
    assert "memprocfs.source" in str(query) and "evtx_repaired" in str(query) and "memprocfs.timeline" in str(query)


def test_memory_copies_can_be_listed() -> None:
    query = analyze_query_syntax("memprocfs.on_disk:true", lambda text: {"simple_query_string": {"query": text}})["query"]
    assert "memprocfs.on_disk" in str(query)
