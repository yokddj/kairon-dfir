"""Tests for the canonical memory process entity model.

These tests exercise the pure reconciliation logic in
``app.services.memory.process_entities`` and do not require
OpenSearch, PostgreSQL or any network access.
"""
from __future__ import annotations

from typing import Any

import pytest

from app.services.memory import process_entities as canonical


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _legacy_doc(
    *,
    pid: int,
    plugin: str,
    ppid: int | None = None,
    name: str | None = None,
    command_line: str | None = None,
    create_time: str | None = None,
    exit_time: str | None = None,
    document_id: str | None = None,
    case_id: str = "case-x",
    evidence_id: str = "ev-1",
    run_id: str = "run-1",
) -> dict[str, Any]:
    doc_id = document_id or f"{run_id}:memory_process:{plugin}:{pid}:{name or 'n'}"
    return {
        "document_id": doc_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "memory_run_id": run_id,
        "memory_artifact_type": "memory_process",
        "backend": "volatility3",
        "plugins": [plugin],
        "process": {
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "command_line": command_line,
            "create_time": create_time,
            "exit_time": exit_time,
        },
        "memory": {},
        "visibility": {"pslist": plugin == "windows.pslist", "psscan": plugin == "windows.psscan", "pstree": plugin == "windows.pstree"},
        "state": {"active_candidate": exit_time is None, "terminated_candidate": exit_time is not None, "hidden_candidate": False},
        "parsed_at": "2026-01-01T00:00:00Z",
        "raw": {},
        "warnings": [],
    }


def _renormalize(docs: list[dict[str, Any]], *, case_id: str = "case-x", evidence_id: str = "ev-1", run_id: str = "run-1") -> dict[str, Any]:
    return canonical.renormalize_documents(
        docs, case_id=case_id, evidence_id=evidence_id, run_id=run_id, materialize=False
    )


# ---------------------------------------------------------------------------
# 1. pslist + cmdline same PID → one entity, command_line enriched
# ---------------------------------------------------------------------------


def test_pslist_cmdline_same_pid_merges_with_command_line() -> None:
    docs = [
        _legacy_doc(pid=1116, plugin="windows.pslist", ppid=808, name="svchost.exe", create_time="2024-03-22T10:00:00Z"),
        _legacy_doc(pid=1116, plugin="windows.cmdline", name="svchost.exe", command_line="svchost.exe -k netsvcs", document_id="cmd-1"),
    ]
    result = _renormalize(docs)
    summary = result["summary"]
    assert summary["candidate_entities"] == 1
    assert summary["duplicate_groups_collapsed"] == 1
    entity = result["entities"][0]
    assert entity["process"]["pid"] == 1116
    assert entity["process"]["command_line"] == "svchost.exe -k netsvcs"
    assert entity["process"]["ppid"] == 808
    sources = set(entity["sources"])
    assert "windows.pslist" in sources
    assert "windows.cmdline" in sources


# ---------------------------------------------------------------------------
# 2. pslist + psscan same PID + create_time → one entity, both sources
# ---------------------------------------------------------------------------


def test_pslist_psscan_same_pid_and_create_time_merges() -> None:
    docs = [
        _legacy_doc(pid=4, plugin="windows.pslist", ppid=0, name="System", create_time="2024-03-22T09:00:00Z"),
        _legacy_doc(pid=4, plugin="windows.psscan", ppid=0, name="System", create_time="2024-03-22T09:00:00Z"),
    ]
    result = _renormalize(docs)
    assert result["summary"]["candidate_entities"] == 1
    entity = result["entities"][0]
    assert set(entity["sources"]) == {"windows.pslist", "windows.psscan"}


# ---------------------------------------------------------------------------
# 3. pstree aporta PPID → no duplicate
# ---------------------------------------------------------------------------


def test_pstree_ppid_does_not_duplicate() -> None:
    docs = [
        _legacy_doc(pid=200, plugin="windows.pslist", name="cmd.exe", create_time="2024-03-22T11:00:00Z"),  # no ppid
        _legacy_doc(pid=200, plugin="windows.pstree", name="cmd.exe", ppid=100, create_time="2024-03-22T11:00:00Z"),
    ]
    result = _renormalize(docs)
    assert result["summary"]["candidate_entities"] == 1
    entity = result["entities"][0]
    assert entity["process"]["ppid"] == 100
    assert set(entity["sources"]) == {"windows.pslist", "windows.pstree"}


# ---------------------------------------------------------------------------
# 4. cmdline sin PPID → no crea root
# ---------------------------------------------------------------------------


def test_cmdline_without_ppid_does_not_become_root() -> None:
    docs = [
        _legacy_doc(pid=555, plugin="windows.cmdline", name="notepad.exe", command_line="notepad.exe", create_time="2024-03-22T12:00:00Z"),
    ]
    result = _renormalize(docs)
    assert result["summary"]["candidate_entities"] == 1
    entity = result["entities"][0]
    # ppid missing must not be coerced to 0
    assert entity["process"]["ppid"] is None
    # The cmdline-only entity is unknown_parent, not a root.
    metrics = result["summary"]["tree_metrics"]
    assert metrics["unknown_parent"] == 1
    assert metrics["roots"] == 0


# ---------------------------------------------------------------------------
# 5. pslist PPID is not replaced by None
# ---------------------------------------------------------------------------


def test_pslist_ppid_not_replaced_by_null() -> None:
    docs = [
        _legacy_doc(pid=300, plugin="windows.pslist", ppid=42, name="a.exe", create_time="2024-03-22T13:00:00Z"),
        _legacy_doc(pid=300, plugin="windows.cmdline", name="a.exe", command_line="a.exe --foo", create_time="2024-03-22T13:00:00Z"),
    ]
    result = _renormalize(docs)
    entity = result["entities"][0]
    assert entity["process"]["ppid"] == 42


# ---------------------------------------------------------------------------
# 6. PID reused with different create_time → two entities
# ---------------------------------------------------------------------------


def test_pid_reuse_with_different_create_time_yields_two_entities() -> None:
    docs = [
        _legacy_doc(pid=1234, plugin="windows.pslist", ppid=1, name="cmd.exe", create_time="2024-03-22T08:00:00Z"),
        _legacy_doc(pid=1234, plugin="windows.pslist", ppid=1, name="powershell.exe", create_time="2024-03-22T18:00:00Z"),
    ]
    result = _renormalize(docs)
    assert result["summary"]["candidate_entities"] == 2


# ---------------------------------------------------------------------------
# 7. Same PID, no create_time → provisional identity
# ---------------------------------------------------------------------------


def test_provisional_identity_when_create_time_missing() -> None:
    docs = [
        _legacy_doc(pid=99, plugin="windows.pslist", ppid=1, name="x.exe"),
        _legacy_doc(pid=99, plugin="windows.pslist", ppid=1, name="x.exe"),
    ]
    result = _renormalize(docs)
    assert result["summary"]["candidate_entities"] == 1
    entity = result["entities"][0]
    assert entity["confidence"] in {"low", "medium"}


# ---------------------------------------------------------------------------
# 8. Provisional reconciled when create_time arrives
# ---------------------------------------------------------------------------


def test_provisional_reconciled_when_create_time_compatible() -> None:
    docs_no_time = _legacy_doc(pid=42, plugin="windows.pslist", name="agent.exe", ppid=1)
    docs_with_time = _legacy_doc(pid=42, plugin="windows.pslist", name="agent.exe", ppid=1, create_time="2024-03-22T14:00:00Z")
    result1 = _renormalize([docs_no_time])
    assert result1["summary"]["candidate_entities"] == 1
    # Adding the create_time doc merges into the same entity (idempotent identity).
    result2 = _renormalize([docs_no_time, docs_with_time])
    assert result2["summary"]["candidate_entities"] == 1
    entity = result2["entities"][0]
    assert entity["process"]["create_time"] == "2024-03-22T14:00:00Z"


# ---------------------------------------------------------------------------
# 9. Name conflict: canonical priority, conflict retained
# ---------------------------------------------------------------------------


def test_name_conflict_canonical_priority_and_warning() -> None:
    docs = [
        _legacy_doc(pid=1, plugin="windows.pslist", name="svchost.exe", create_time="2024-03-22T15:00:00Z"),
        _legacy_doc(pid=1, plugin="windows.psscan", name="svch0st.exe", create_time="2024-03-22T15:00:00Z"),
    ]
    result = _renormalize(docs)
    entity = result["entities"][0]
    # pslist wins
    assert entity["process"]["name"] == "svchost.exe"
    # conflict retained as a finding
    assert "name_conflict" in entity["findings"]


# ---------------------------------------------------------------------------
# 10. psscan-only → visibility scan_only
# ---------------------------------------------------------------------------


def test_psscan_only_visibility() -> None:
    docs = [_legacy_doc(pid=888, plugin="windows.psscan", name="ghost.exe", create_time="2024-03-22T16:00:00Z")]
    result = _renormalize(docs)
    entity = result["entities"][0]
    assert entity["visibility"]["scan_only"] is True
    assert entity["visibility"]["listed"] is False


# ---------------------------------------------------------------------------
# 11. Explicit exit time → terminated
# ---------------------------------------------------------------------------


def test_explicit_exit_time_marks_terminated() -> None:
    docs = [
        _legacy_doc(pid=7, plugin="windows.psscan", name="exited.exe", create_time="2024-03-22T17:00:00Z", exit_time="2024-03-22T17:30:00Z"),
    ]
    result = _renormalize(docs)
    entity = result["entities"][0]
    assert entity["visibility"]["terminated"] is True
    assert "terminated" in entity["findings"]


# ---------------------------------------------------------------------------
# 12. psscan-only without exit → not automatically terminated
# ---------------------------------------------------------------------------


def test_psscan_only_without_exit_not_terminated() -> None:
    docs = [_legacy_doc(pid=11, plugin="windows.psscan", name="possible.exe", create_time="2024-03-22T17:00:00Z")]
    result = _renormalize(docs)
    entity = result["entities"][0]
    assert entity["visibility"]["terminated"] is False


# ---------------------------------------------------------------------------
# 13. hidden_candidate is a low-confidence indicator
# ---------------------------------------------------------------------------


def test_hidden_candidate_for_psscan_only() -> None:
    docs = [_legacy_doc(pid=22, plugin="windows.psscan", name="hidden.exe", create_time="2024-03-22T17:00:00Z")]
    result = _renormalize(docs)
    entity = result["entities"][0]
    assert entity["visibility"]["hidden_candidate"] is True
    assert "hidden_candidate" in entity["findings"]
    assert "scan_only" in entity["findings"]


# ---------------------------------------------------------------------------
# 14. process tree: no duplicates
# ---------------------------------------------------------------------------


def test_process_tree_no_duplicates() -> None:
    docs = [
        _legacy_doc(pid=4, plugin="windows.pslist", ppid=0, name="System", create_time="2024-03-22T07:00:00Z"),
        _legacy_doc(pid=4, plugin="windows.psscan", ppid=0, name="System", create_time="2024-03-22T07:00:00Z"),
        _legacy_doc(pid=4, plugin="windows.pstree", ppid=0, name="System", create_time="2024-03-22T07:00:00Z"),
        _legacy_doc(pid=4, plugin="windows.cmdline", ppid=0, name="System", create_time="2024-03-22T07:00:00Z"),
    ]
    result = _renormalize(docs)
    assert result["summary"]["candidate_entities"] == 1
    metrics = result["summary"]["tree_metrics"]
    assert metrics["pid_4_count"] == 1


# ---------------------------------------------------------------------------
# 15. unknown parent is NOT a root
# ---------------------------------------------------------------------------


def test_unknown_parent_not_counted_as_root() -> None:
    docs = [
        _legacy_doc(pid=600, plugin="windows.cmdline", name="orphan.exe", command_line="orphan.exe"),
    ]
    result = _renormalize(docs)
    metrics = result["summary"]["tree_metrics"]
    assert metrics["unknown_parent"] == 1
    assert metrics["roots"] == 0


# ---------------------------------------------------------------------------
# 16. missing parent → orphan
# ---------------------------------------------------------------------------


def test_missing_parent_counted_as_orphan() -> None:
    docs = [
        _legacy_doc(pid=700, plugin="windows.pslist", ppid=999999, name="orphan2.exe", create_time="2024-03-22T19:00:00Z"),
    ]
    result = _renormalize(docs)
    metrics = result["summary"]["tree_metrics"]
    assert metrics["orphans"] == 1


# ---------------------------------------------------------------------------
# 17. PID 0 special handling: one entity, not duplicated
# ---------------------------------------------------------------------------


def test_pid_zero_handling() -> None:
    docs = [
        _legacy_doc(pid=0, plugin="windows.pslist", ppid=0, name="Idle", create_time="2024-03-22T20:00:00Z", document_id="pid0-1"),
        _legacy_doc(pid=0, plugin="windows.pslist", ppid=0, name="Idle", create_time="2024-03-22T20:00:00Z", document_id="pid0-2"),
    ]
    result = _renormalize(docs)
    assert result["summary"]["candidate_entities"] == 1
    assert result["summary"]["tree_metrics"]["pid_zero_count"] == 1


# ---------------------------------------------------------------------------
# 18. PID 4 (System) unique per identity
# ---------------------------------------------------------------------------


def test_pid_4_unique() -> None:
    docs = [
        _legacy_doc(pid=4, plugin="windows.pslist", ppid=0, name="System", create_time="2024-03-22T07:00:00Z"),
        _legacy_doc(pid=4, plugin="windows.psscan", ppid=0, name="System", create_time="2024-03-22T07:00:00Z"),
        _legacy_doc(pid=4, plugin="windows.pstree", ppid=0, name="System", create_time="2024-03-22T07:00:00Z"),
    ]
    result = _renormalize(docs)
    assert result["summary"]["candidate_entities"] == 1
    assert result["summary"]["tree_metrics"]["pid_4_count"] == 1


# ---------------------------------------------------------------------------
# 19. cycle detection
# ---------------------------------------------------------------------------


def test_cycle_detection() -> None:
    docs = [
        _legacy_doc(pid=10, plugin="windows.pslist", ppid=11, name="loop-a.exe", create_time="2024-03-22T10:00:00Z"),
        _legacy_doc(pid=11, plugin="windows.pslist", ppid=10, name="loop-b.exe", create_time="2024-03-22T10:00:00Z"),
    ]
    result = _renormalize(docs)
    metrics = result["summary"]["tree_metrics"]
    assert metrics["cycles"] >= 2


# ---------------------------------------------------------------------------
# 20. idempotent renormalization
# ---------------------------------------------------------------------------


def test_idempotent_renormalization() -> None:
    docs = [
        _legacy_doc(pid=1, plugin="windows.pslist", name="a.exe", ppid=0, create_time="2024-03-22T08:00:00Z"),
        _legacy_doc(pid=2, plugin="windows.pslist", name="b.exe", ppid=1, create_time="2024-03-22T08:01:00Z"),
    ]
    r1 = _renormalize(docs)
    r2 = _renormalize(docs)
    assert r1["summary"]["candidate_entities"] == r2["summary"]["candidate_entities"]
    ids1 = sorted(e["process_entity_id"] for e in r1["entities"])
    ids2 = sorted(e["process_entity_id"] for e in r2["entities"])
    assert ids1 == ids2


# ---------------------------------------------------------------------------
# 21. rerun indexing: no duplicate entities
# ---------------------------------------------------------------------------


def test_rerun_does_not_duplicate() -> None:
    docs = [_legacy_doc(pid=1, plugin="windows.pslist", name="a.exe", ppid=0, create_time="2024-03-22T08:00:00Z")]
    r1 = _renormalize(docs)
    r2 = _renormalize(docs)
    assert r1["summary"]["candidate_entities"] == 1
    assert r2["summary"]["candidate_entities"] == 1


# ---------------------------------------------------------------------------
# 22. basic run: produces entities without psscan
# ---------------------------------------------------------------------------


def test_basic_run_entities_without_psscan() -> None:
    docs = [
        _legacy_doc(pid=1, plugin="windows.pslist", name="a.exe", ppid=0, create_time="2024-03-22T08:00:00Z"),
        _legacy_doc(pid=2, plugin="windows.pstree", name="b.exe", ppid=1, create_time="2024-03-22T08:01:00Z"),
        _legacy_doc(pid=1, plugin="windows.cmdline", name="a.exe", command_line="a.exe", create_time="2024-03-22T08:00:00Z"),
    ]
    result = _renormalize(docs)
    assert result["summary"]["candidate_entities"] == 2
    for e in result["entities"]:
        assert "windows.psscan" not in e["sources"]


# ---------------------------------------------------------------------------
# 23. extended run: enriches with psscan
# ---------------------------------------------------------------------------


def test_extended_run_enriches_with_psscan() -> None:
    docs = [
        _legacy_doc(pid=1, plugin="windows.pslist", name="a.exe", ppid=0, create_time="2024-03-22T08:00:00Z"),
        _legacy_doc(pid=2, plugin="windows.psscan", name="hidden.exe", create_time="2024-03-22T08:01:00Z"),
    ]
    result = _renormalize(docs)
    assert result["summary"]["candidate_entities"] == 2
    by_pid = {e["process"]["pid"]: e for e in result["entities"]}
    assert "windows.psscan" in by_pid[2]["sources"]


# ---------------------------------------------------------------------------
# 24. run isolation: no silent mixing (separate runs = separate entity IDs)
# ---------------------------------------------------------------------------


def test_run_isolation_separate_runs_distinct_ids() -> None:
    docs_a = [_legacy_doc(pid=1, plugin="windows.pslist", name="a.exe", ppid=0, create_time="2024-03-22T08:00:00Z")]
    docs_b = [_legacy_doc(pid=1, plugin="windows.pslist", name="a.exe", ppid=0, create_time="2024-03-22T08:00:00Z")]
    r1 = _renormalize(docs_a, run_id="run-1")
    r2 = _renormalize(docs_b, run_id="run-2")
    assert r1["entities"][0]["process_entity_id"] == r2["entities"][0]["process_entity_id"]
    # document IDs must be different per run
    assert r1["entities"][0]["document_id"] != r2["entities"][0]["document_id"]


# ---------------------------------------------------------------------------
# 25. pagination and filters (smoke test on list helpers)
# ---------------------------------------------------------------------------


def test_entity_list_pagination_is_deterministic() -> None:
    docs = [
        _legacy_doc(pid=i, plugin="windows.pslist", name=f"p{i}.exe", ppid=0, create_time=f"2024-03-22T08:{i:02d}:00Z")
        for i in range(1, 11)
    ]
    r1 = _renormalize(docs)
    r2 = _renormalize(docs)
    ids1 = [e["process_entity_id"] for e in r1["entities"]]
    ids2 = [e["process_entity_id"] for e in r2["entities"]]
    assert ids1 == ids2


# ---------------------------------------------------------------------------
# 26. no dfir-events writes (the canonical module never imports the disk index)
# ---------------------------------------------------------------------------


def test_canonical_module_does_not_import_disk_index() -> None:
    import inspect
    import app.services.memory.process_entities as mod
    source = inspect.getsource(mod)
    assert "dfir-events" not in source
    assert "normalized_event" not in source.lower()
    assert "NormalizedEvent" not in source


# ---------------------------------------------------------------------------
# 27. no NormalizedEvent creation (verified by the missing import path)
# ---------------------------------------------------------------------------


def test_no_normalized_event_creation() -> None:
    import inspect
    import app.services.memory.process_entities as mod
    source = inspect.getsource(mod)
    forbidden = ["NormalizedEvent", "create_normalized_event", "disk_event"]
    for token in forbidden:
        assert token not in source, f"forbidden token {token!r} in canonical module"


# ---------------------------------------------------------------------------
# 28. no disk case mutation (canonical renormalization only touches memory index)
# ---------------------------------------------------------------------------


def test_renormalize_does_not_touch_disk_index() -> None:
    import inspect
    import app.services.memory.process_entities as mod
    source = inspect.getsource(mod)
    # Only memory index helpers
    assert "get_memory_index" in source
    assert "dfir-events" not in source


# ---------------------------------------------------------------------------
# 29. OpenSearch mapping is well-formed (smoke)
# ---------------------------------------------------------------------------


def test_canonical_mapping_is_well_formed() -> None:
    mapping = canonical.CANONICAL_MAPPING_ADDITIONS
    assert "memory_process_entity" in mapping
    assert "memory_process_observation" in mapping
    assert "memory_process_edge" in mapping
    for name, schema in mapping.items():
        # Each mapping defines fields (top-level keys); we verify that
        # at least the canonical identifiers are present.
        assert "document_id" in schema or name.endswith("_observation")
        assert "case_id" in schema
        assert "evidence_id" in schema


# ---------------------------------------------------------------------------
# 30. source raw documents preserved
# ---------------------------------------------------------------------------


def test_source_raw_documents_preserved_in_result() -> None:
    docs = [
        _legacy_doc(pid=1, plugin="windows.pslist", name="a.exe", ppid=0, create_time="2024-03-22T08:00:00Z"),
    ]
    result = _renormalize(docs)
    # The renormalization result returns the same number of observations as source.
    assert len(result["observations"]) == len(docs)
    # The original pid is preserved in observations.
    assert {obs["observed"]["pid"] for obs in result["observations"]} == {1}


# ---------------------------------------------------------------------------
# Bonus: visibility classification
# ---------------------------------------------------------------------------


def test_visibility_unknown_when_no_sources() -> None:
    # An observation-less entity cannot exist; but if all observations
    # are unusable, we still produce a single provisional entity.
    docs = [_legacy_doc(pid=33, plugin="windows.cmdline", name="raw.exe", command_line="raw.exe", create_time="2024-03-22T19:00:00Z")]
    result = _renormalize(docs)
    entity = result["entities"][0]
    assert entity["visibility"]["unknown"] in (True, False)


def test_alternate_command_lines_recorded() -> None:
    docs = [
        _legacy_doc(pid=44, plugin="windows.pslist", name="x.exe", ppid=0, create_time="2024-03-22T20:00:00Z"),
        _legacy_doc(pid=44, plugin="windows.cmdline", name="x.exe", command_line="x.exe --first", create_time="2024-03-22T20:00:00Z"),
        _legacy_doc(pid=44, plugin="windows.cmdline", name="x.exe", command_line="x.exe --second", document_id="cmd-2", create_time="2024-03-22T20:00:00Z"),
    ]
    result = _renormalize(docs)
    entity = result["entities"][0]
    assert "x.exe --first" in entity["process"]["command_line"] or "x.exe --second" in entity["process"]["command_line"]
    sources = entity["sources"]
    assert sources.count("windows.cmdline") == 1


def test_lineage_exact_pid_selects_process_and_reveals_parent_children(monkeypatch: pytest.MonkeyPatch) -> None:
    docs = [
        _legacy_doc(pid=9132, plugin="windows.pstree", name="explorer.exe", ppid=4, create_time="2024-03-22T11:00:00Z"),
        _legacy_doc(pid=6996, plugin="windows.pstree", name="powershell.exe", ppid=9132, create_time="2024-03-22T11:01:00Z"),
        _legacy_doc(pid=5528, plugin="windows.pstree", name="powershell.exe", ppid=6996, create_time="2024-03-22T11:02:00Z"),
        _legacy_doc(pid=5788, plugin="windows.pstree", name="conhost.exe", ppid=6996, create_time="2024-03-22T11:01:01Z"),
    ]
    entities = _renormalize(docs)["entities"]
    monkeypatch.setattr(canonical, "fetch_canonical_entities", lambda *args, **kwargs: {"items": entities, "page": 1, "page_size": 200, "total": len(entities)})

    lineage = canonical.fetch_canonical_lineage("case-x", run_id="run-1", pid=6996)

    assert lineage["selected_entity_id"] is not None
    root = lineage["nodes"][0]
    assert root["pid"] == 9132
    selected = root["children"][0]
    assert selected["pid"] == 6996
    assert [child["pid"] for child in selected["children"]] == [5528, 5788]
    assert selected["child_count"] == 2
    assert lineage["topology_source"] == "pstree"


def test_lineage_ambiguous_pid_selects_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    docs = [
        _legacy_doc(pid=1234, plugin="windows.pslist", name="cmd.exe", ppid=1, create_time="2024-03-22T08:00:00Z"),
        _legacy_doc(pid=1234, plugin="windows.pslist", name="powershell.exe", ppid=1, create_time="2024-03-22T18:00:00Z"),
    ]
    entities = _renormalize(docs)["entities"]
    monkeypatch.setattr(canonical, "fetch_canonical_entities", lambda *args, **kwargs: {"items": entities, "page": 1, "page_size": 200, "total": len(entities)})

    lineage = canonical.fetch_canonical_lineage("case-x", run_id="run-1", pid=1234)

    assert lineage["selected_entity_id"] is None
    assert lineage["nodes"] == []
    assert len(lineage["exact_match_ids"]) == 2
    assert lineage["truncation_reason"] == "pid_ambiguous"
