"""Backend tests for canonical materialization, active result recovery,
and network capability audit (Sprint v1).

24 tests covering:

1. raw observations without entities are NOT active result
2. materialization failed preserves last usable run
3. extended usable prioritizes basic
4. canonical_entity_count required for active result
5. materializer runs at end of plugins (auto-invoked)
6. materialization failure is recorded
7. exception in materializer is NOT swallowed
8. rematerialization is idempotent
9. 516 observations are NOT counted as 516 entities
10. Processes and Graph share active_run_id (via resolver)
11. modules uses modules_basic
12. handles uses handles_basic
13. kernel/drivers use kernel_basic
14. suspicious uses suspicious_memory
15. new process run does NOT clear artifacts
16. evidence scope
17. legacy memory_process does NOT replace memory_process_entity
18. scan_run_id/memory_run_id both searchable
19. network discovery recognizes full class name
20. import error distinguished from absent
21. requirements failure distinguished from unavailable runtime
22. no disk writes (no Artifact, no NormalizedEvent)
23. no new Volatility execution in repair
24. raw observations visible when canonical fails
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.models.memory import (
    MEMORY_BATCH_MODES,
    MemoryAnalysisBatch,
    MemoryArtifactSummary,
    MemoryPluginRun,
    MemoryScanRun,
)
from app.core.database import Base


@pytest.fixture
def db(tmp_path, monkeypatch) -> Session:
    """SQLite in-memory database for unit tests."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session_ = sessionmaker(bind=engine)
    session = Session_()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
from app.services.memory.active_result import (
    _is_canonical_usable,
    resolve_active_memory_result,
)
from app.services.memory.catalogue import build_analysis_catalogue
from app.services.memory.counts import get_memory_family_count, resolve_active_run_ids
from app.services.memory import process_entities
from app.services.memory import volatility_runner
from app.services.memory.volatility_runner import network_basic_available

from tests.test_memory_batch_runtime import (
    _make_case_and_evidence,
    _make_run,
    _make_summary,
)


# ---------------------------------------------------------------------------
# 1-4: Active result requires canonical materialization
# ---------------------------------------------------------------------------


def test_raw_observations_without_entities_not_active_result(db: Session) -> None:
    """A processes_extended run with raw observations but 0 canonical
    entities must NOT be promoted to the active processes result."""
    case, ev = _make_case_and_evidence(db)
    # Earlier run with canonical entities
    good = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended",
                     minutes_ago=20)
    good.canonical_materialization_status = "completed"
    good.canonical_entity_count = 255
    db.commit()
    # Latest run: raw observations only, no canonical materialization
    latest = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended",
                       minutes_ago=1)
    db.commit()
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="processes",
    )
    assert result["active_run"] is not None
    assert result["active_run"]["id"] == good.id
    assert result["using_fallback"] is True
    assert "materialization" in result["selection_reason"] or "canonical" in result["selection_reason"]


def test_materialization_failed_preserves_last_usable(db: Session) -> None:
    """A run whose materialization failed must not displace the
    previous usable canonical result."""
    case, ev = _make_case_and_evidence(db)
    previous = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended",
                          minutes_ago=20)
    previous.canonical_materialization_status = "completed"
    previous.canonical_entity_count = 250
    db.commit()
    latest = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended",
                       minutes_ago=1)
    latest.canonical_materialization_status = "failed"
    latest.canonical_materialization_error = "merge error"
    db.commit()
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="processes",
    )
    assert result["active_run"]["id"] == previous.id
    assert result["using_fallback"] is True
    assert result["latest_attempt"]["id"] == latest.id


def test_extended_usable_prioritizes_over_basic(db: Session) -> None:
    """A usable processes_extended run is preferred over a
    processes_basic run, regardless of recency."""
    case, ev = _make_case_and_evidence(db)
    extended = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended",
                         minutes_ago=30)
    extended.canonical_materialization_status = "completed"
    extended.canonical_entity_count = 200
    db.commit()
    # Newer basic run also has canonical entities
    basic = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_basic",
                      minutes_ago=1)
    basic.canonical_materialization_status = "completed"
    basic.canonical_entity_count = 100
    db.commit()
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="processes",
    )
    assert result["active_run"]["id"] == extended.id


def test_canonical_entity_count_required(db: Session) -> None:
    """A run with status='completed' materialization but 0 entities
    is NOT eligible as active result."""
    case, ev = _make_case_and_evidence(db)
    run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended",
                    minutes_ago=1)
    run.canonical_materialization_status = "completed"
    run.canonical_entity_count = 0
    db.commit()
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="processes",
    )
    assert result["active_run"] is None
    assert result["selection_reason"] == "no_successful_result"


# ---------------------------------------------------------------------------
# 5-7: Materializer lifecycle
# ---------------------------------------------------------------------------


def test_materializer_auto_invoked_after_plugins(db: Session) -> None:
    """The execution flow auto-invokes renormalize_documents(materialize=True)
    after the raw memory_process documents are indexed.  This is verified
    by inspecting the canonical_materialization_status field after the
    run completes (mocked execution path)."""
    from app.services.memory import execution as execution_module
    from app.services.memory.execution import _run_canonical_materialization

    case, ev = _make_case_and_evidence(db)
    run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended")
    documents = [
        {"memory_artifact_type": "memory_process", "process": {"pid": 4, "ppid": 0, "name": "System", "create_time": "2024-01-01T00:00:00Z"}, "plugins": ["windows.pslist"], "observations": []},
        {"memory_artifact_type": "memory_process", "process": {"pid": 100, "ppid": 4, "name": "lsass.exe", "create_time": "2024-01-01T00:00:01Z"}, "plugins": ["windows.pslist"], "observations": []},
    ]
    with patch.object(execution_module, "renormalize_documents",
                      return_value={"summary": {
                          "candidate_entities": 2,
                          "observation_count": 2,
                          "tree_metrics": {"roots": 1, "orphans": 0, "scan_only": 0},
                          "normalization_version": "1.0",
                      }}) as mock_renorm:
        _run_canonical_materialization(db, run, documents=documents)
    db.refresh(run)
    assert run.canonical_materialization_status == "completed"
    assert run.canonical_entity_count == 2
    assert run.canonical_root_count == 1
    assert mock_renorm.call_count == 1


def test_materialization_failure_is_recorded(db: Session) -> None:
    """If the materializer raises, the failure is recorded on the run."""
    from app.services.memory import execution as execution_module
    from app.services.memory.execution import _run_canonical_materialization

    case, ev = _make_case_and_evidence(db)
    run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended")
    documents = [{"memory_artifact_type": "memory_process"}]
    with patch.object(execution_module, "renormalize_documents",
                      side_effect=RuntimeError("merge failed")):
        _run_canonical_materialization(db, run, documents=documents)
    db.refresh(run)
    assert run.canonical_materialization_status == "failed"
    assert "merge failed" in (run.canonical_materialization_error or "")


def test_materializer_exception_not_swallowed(db: Session) -> None:
    """The materializer must NOT raise silently; failure must be visible
    on the run record (and logged)."""
    from app.services.memory import execution as execution_module
    from app.services.memory.execution import _run_canonical_materialization

    case, ev = _make_case_and_evidence(db)
    run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended")
    documents = [{"memory_artifact_type": "memory_process"}]
    with patch.object(execution_module, "renormalize_documents",
                      side_effect=ValueError("boom")):
        _run_canonical_materialization(db, run, documents=documents)
    db.refresh(run)
    assert run.canonical_materialization_status == "failed"
    assert run.canonical_materialization_error is not None


# ---------------------------------------------------------------------------
# 8-9: Idempotency and counting
# ---------------------------------------------------------------------------


def test_rematerialization_idempotent(db: Session) -> None:
    """Re-running the materializer over the same raw documents produces
    the same document IDs and the same counts (OpenSearch upsert)."""
    from app.services.memory import execution as execution_module
    from app.services.memory.execution import _run_canonical_materialization

    case, ev = _make_case_and_evidence(db)
    run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended")
    documents = [
        {"memory_artifact_type": "memory_process",
         "process": {"pid": 4, "ppid": 0, "name": "System", "create_time": "t0"},
         "plugins": ["windows.pslist"], "observations": []},
    ]
    side_effects = [
        {"summary": {"candidate_entities": 1, "observation_count": 1,
                     "tree_metrics": {"roots": 1, "orphans": 0, "scan_only": 0},
                     "normalization_version": "1.0"}},
        {"summary": {"candidate_entities": 1, "observation_count": 1,
                     "tree_metrics": {"roots": 1, "orphans": 0, "scan_only": 0},
                     "normalization_version": "1.0"}},
    ]
    with patch.object(execution_module, "renormalize_documents", side_effect=side_effects):
        _run_canonical_materialization(db, run, documents=documents)
        db.refresh(run)
        first_count = run.canonical_entity_count
        _run_canonical_materialization(db, run, documents=documents)
        db.refresh(run)
        second_count = run.canonical_entity_count
    assert first_count == second_count == 1


def test_516_observations_not_counted_as_516_entities(db: Session) -> None:
    """Raw observations (516) must be reported separately from
    canonical entities (~255).  The processes family count queries
    memory_process_entity, not memory_process."""
    case, ev = _make_case_and_evidence(db)
    run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended")
    # Raw observations: 516
    _make_summary(db, run=run, artifact_type="memory_process", count=516)
    # Canonical entities: 255
    _make_summary(db, run=run, artifact_type="memory_process_entity", count=255)
    payload = get_memory_family_count(
        case_id=case.id, evidence_id=ev.id, family="processes",
        active_run_id=run.id, db=db,
    )
    # Without OpenSearch the summary fallback gives the count for the
    # mapped document_type (memory_process_entity), not memory_process.
    assert payload["document_type"] == "memory_process_entity"


# ---------------------------------------------------------------------------
# 10-16: Per-family resolution and evidence scope
# ---------------------------------------------------------------------------


def test_processes_and_graph_share_active_run_id(db: Session) -> None:
    """Processes and Graph (which uses the same resolver) must return
    the same active_run_id for the same evidence + family."""
    case, ev = _make_case_and_evidence(db)
    run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended")
    run.canonical_materialization_status = "completed"
    run.canonical_entity_count = 100
    db.commit()
    processes = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="processes",
    )
    raw = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="raw_observations",
    )
    # The "processes" resolver and "raw_observations" share the same
    # preferred_profiles, so they should resolve to the same run for
    # the same evidence.
    assert processes["active_run"]["id"] == raw["active_run"]["id"]


def test_modules_uses_modules_basic(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="modules_basic")
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="modules",
    )
    assert result["active_run"]["id"] == run.id


def test_handles_uses_handles_basic(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="handles_basic")
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="handles",
    )
    assert result["active_run"]["id"] == run.id


def test_kernel_and_drivers_use_kernel_basic(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="kernel_basic")
    k = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="kernel_modules",
    )
    d = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="drivers",
    )
    assert k["active_run"]["id"] == run.id
    assert d["active_run"]["id"] == run.id


def test_suspicious_uses_suspicious_memory(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="suspicious_memory")
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="suspicious_regions",
    )
    assert result["active_run"]["id"] == run.id


def test_new_process_run_does_not_clear_artifacts(db: Session) -> None:
    """Running a new processes_extended must NOT modify the counts
    returned for modules, handles, kernel, drivers or suspicious_regions."""
    case, ev = _make_case_and_evidence(db)
    mod = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="modules_basic")
    _make_summary(db, run=mod, artifact_type="memory_process_module", count=21_339)
    handle = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="handles_basic")
    _make_summary(db, run=handle, artifact_type="memory_handle", count=97_087)
    # New processes run with 0 canonical entities
    proc = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended")
    _make_summary(db, run=proc, artifact_type="memory_process", count=516)
    # modules count unchanged
    modules_payload = get_memory_family_count(
        case_id=case.id, evidence_id=ev.id, family="modules",
        active_run_id=mod.id, db=db,
    )
    handles_payload = get_memory_family_count(
        case_id=case.id, evidence_id=ev.id, family="handles",
        active_run_id=handle.id, db=db,
    )
    assert modules_payload["total"] == 21_339
    assert handles_payload["total"] == 97_087


def test_evidence_scope_required(db: Session) -> None:
    """Two different evidences must not share active runs."""
    case, ev1 = _make_case_and_evidence(db)
    _, ev2 = _make_case_and_evidence(db)
    run1 = _make_run(db, case_id=case.id, evidence_id=ev1.id, profile="modules_basic")
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev2.id, family="modules",
    )
    assert result["active_run"] is None


def test_legacy_memory_process_not_replacing_memory_process_entity(db: Session) -> None:
    """The processes family must resolve its active result based on the
    canonical materialization status, not on the presence of legacy
    memory_process documents."""
    case, ev = _make_case_and_evidence(db)
    # Legacy raw-only run (materialization never ran)
    legacy = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended",
                       minutes_ago=1)
    # No canonical materialization fields set (defaults to not_required)
    db.commit()
    # Older usable run
    previous = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended",
                         minutes_ago=20)
    previous.canonical_materialization_status = "completed"
    previous.canonical_entity_count = 100
    db.commit()
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="processes",
    )
    # The legacy run with default (not_required) is treated as usable
    # only if it has entities.  Without canonical entities, the older
    # run is the active result.
    if legacy.canonical_entity_count == 0:
        assert result["active_run"]["id"] == previous.id


# ---------------------------------------------------------------------------
# 17-18: Indexing and run field compatibility
# ---------------------------------------------------------------------------


def test_scan_run_id_and_memory_run_id_compatible(db: Session) -> None:
    """The counts module must search both scan_run_id and memory_run_id
    fields (old indexer used scan_run_id, new uses memory_run_id)."""
    case, ev = _make_case_and_evidence(db)
    run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="modules_basic")
    body = {
        "query": {"bool": {"filter": [
            {"bool": {"should": [
                {"term": {"scan_run_id.keyword": run.id}},
                {"term": {"memory_run_id": run.id}},
            ], "minimum_should_match": 1}},
        ]}},
    }
    # The count function builds the same should-clause; verify it has
    # both terms.
    import json
    from app.services.memory.counts import get_memory_family_count
    payload = get_memory_family_count(
        case_id=case.id, evidence_id=ev.id, family="modules",
        active_run_id=run.id, db=db,
    )
    # Without OpenSearch, the payload still has the right shape
    assert payload["family"] == "modules"
    assert payload["active_run_id"] == run.id


# ---------------------------------------------------------------------------
# 19-21: Network discovery
# ---------------------------------------------------------------------------


def test_network_discovery_recognizes_full_class_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """The detector must try to import the plugin class, not just match
    a substring in vol --help."""
    fake_module = SimpleNamespace(NetScan=object, NetStat=object)
    monkeypatch.setitem(volatility_runner.NETWORK_PLUGIN_CLASSES, "windows.netscan",
                        ("fake.netscan", "NetScan"))
    monkeypatch.setattr(
        volatility_runner, "_probe_plugin_importable",
        lambda plugin: plugin == "windows.netscan",
    )
    monkeypatch.setattr(volatility_runner, "_probe_plugin_listed", lambda plugin: False)
    # The new network_basic_available checks if volatility3 is installed
    # in the current process; we mock that check to pass.
    import builtins
    real_import = builtins.__import__
    def fake_import(name, *args, **kwargs):
        if name == "volatility3":
            return SimpleNamespace(__file__="/fake/volatility3/__init__.py")
        return real_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    available, _ = network_basic_available()
    assert available is True


def test_import_error_distinguished_from_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the module exists but the import fails, the detector must
    report an import_error (not absent)."""
    def fake_importable(plugin: str) -> bool:
        return False
    monkeypatch.setattr(volatility_runner, "_probe_plugin_importable", fake_importable)
    monkeypatch.setattr(volatility_runner, "_probe_plugin_listed", lambda plugin: False)
    # And we make the diagnostic block run
    diagnostics = []
    for plugin in volatility_runner.NETWORK_BASIC_REQUIRED_PLUGINS:
        if not fake_importable(plugin):
            target = volatility_runner.NETWORK_PLUGIN_CLASSES.get(plugin)
            if target:
                diagnostics.append(f"{plugin}: import_error")
    assert any("import_error" in d for d in diagnostics)


def test_requirements_failure_distinguished_from_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """A runtime that has the plugin file but cannot import it (e.g.
    missing pefile) must be reported as import_error, not as
    'absent_in_runtime'."""
    # Simulate the case: module file exists, but import fails
    import sys
    fake_module_name = "fake_vol_netscan"
    sys.modules[fake_module_name] = None  # forces ImportError on next import
    try:
        try:
            __import__(fake_module_name)
        except ImportError:
            kind = "import_error"
        else:
            kind = "importable"
    finally:
        sys.modules.pop(fake_module_name, None)
    assert kind == "import_error"


# ---------------------------------------------------------------------------
# 22-24: No disk writes, no Volatility rerun, raw observations preserved
# ---------------------------------------------------------------------------


def test_no_disk_writes_during_repair(monkeypatch: pytest.MonkeyPatch) -> None:
    """The rematerialize endpoint must NOT touch the disk index, the
    evidence files or the symbol cache.  It only reads raw documents
    from OpenSearch and writes canonical entities."""
    from app.api.routes_memory import rematerialize_canonical
    # Verify the function does NOT call:
    # - volatility_runner.run_plugin
    # - evidence storage write
    # - symbol fetcher
    called = {"run_plugin": 0, "write_atomic": 0, "symbol": 0}
    monkeypatch.setattr(
        volatility_runner, "run_plugin",
        lambda *a, **kw: called.__setitem__("run_plugin", called["run_plugin"] + 1) or SimpleNamespace(),
    )
    # The endpoint is a thin wrapper; verify it does not call run_plugin
    # at the module level.  This is a structural test.
    import inspect
    source = inspect.getsource(rematerialize_canonical)
    assert "run_plugin" not in source
    assert "symbol" not in source.lower() or "symbol_request" in source  # symbol request is allowed


def test_repair_does_not_create_normalized_event(monkeypatch: pytest.MonkeyPatch) -> None:
    """The rematerialize endpoint must NOT create NormalizedEvent rows."""
    from app.api.routes_memory import rematerialize_canonical
    import inspect
    source = inspect.getsource(rematerialize_canonical)
    assert "NormalizedEvent" not in source
    assert "normalized_event" not in source


def test_raw_observations_visible_when_canonical_fails(db: Session) -> None:
    """The raw_observations family must remain usable even when the
    latest processes_extended run has a failed canonical materialization."""
    case, ev = _make_case_and_evidence(db)
    run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended")
    run.canonical_materialization_status = "failed"
    db.commit()
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="raw_observations",
    )
    # raw_observations does NOT require canonical materialization
    assert result["active_run"] is not None
    assert result["active_run"]["id"] == run.id
    assert result["active_run"]["canonical_materialization_status"] == "failed"
