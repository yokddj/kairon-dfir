"""Linux Shell History Phase 1: normalizer + family backend end-to-end.

Covers everything the pure normalizer unit tests in
``test_memory_artifact_normalizers.py`` don't: execution dispatch (the
A/B distinction between "0 legitimate rows" and "malformed payload"),
family resolution/active-result, counts, search, timeline, and the
regression guarantees that this phase must not touch: the catalogue,
``PROFILE_CAPABILITY``, ``allowed_memory_profiles``, or any existing
profile's plugin list.

``linux.bash`` is intentionally not wired into any profile yet (Phase 2
scope), so every test here drives the plugin directly -- either through
the pure normalizer dispatch or by constructing a ``MemoryScanRun`` /
``MemoryPluginRun`` by hand -- never through profile resolution.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.memory import MemoryPluginRun, MemoryScanRun
from app.services.memory import active_result as active_result_module
from app.services.memory import counts as counts_module
from app.services.memory import execution as execution_module
from app.services.memory import search as search_module
from app.services.memory import timeline as timeline_module
from app.services.memory.active_result import FAMILY_RESOLUTION, resolve_active_memory_result
from app.services.memory.counts import FAMILY_ORDER, FAMILY_TO_DOCUMENT_TYPE
from app.services.memory.execution import ARTIFACT_PLUGIN_NORMALIZER, PROFILE_CAPABILITY, PROFILE_PLUGINS, _normalize_artifact_payload
from app.services.memory.timeline import MEMORY_TIMESTAMP_MATRIX


CASE = "case-shell-history"
EVIDENCE = "ev-shell-history"
RUN = "run-shell-history"


def _bash_rows() -> list[dict[str, Any]]:
    return [
        {"PID": 1234, "Process": "bash", "CommandTime": "2024-03-22T10:53:00", "Command": "sudo apt update"},
        {"PID": 1234, "Process": "bash", "CommandTime": "2024-03-22T10:54:00", "Command": "cat /etc/passwd"},
    ]


# ---------------------------------------------------------------------------
# Execution dispatch (point 4): A/B distinction between a legitimate
# zero-row result and a malformed payload that drops rows.
# ---------------------------------------------------------------------------


def test_linux_bash_no_longer_falls_into_unsupported_artifact_plugin() -> None:
    result = _normalize_artifact_payload(
        "linux.bash",
        _bash_rows(),
        case_id=CASE,
        evidence_id=EVIDENCE,
        scan_run_id=RUN,
        plugin_run_id=f"{RUN}:linux.bash",
    )
    assert not any("unsupported_artifact_plugin" in w for w in result["warnings"])
    assert result["items"][0]["document_type"] == "memory_shell_history"


def test_linux_bash_n_rows_yields_n_items() -> None:
    result = _normalize_artifact_payload(
        "linux.bash",
        _bash_rows(),
        case_id=CASE,
        evidence_id=EVIDENCE,
        scan_run_id=RUN,
        plugin_run_id=f"{RUN}:linux.bash",
    )
    assert len(result["items"]) == 2
    assert result["accepted_count"] == 2


def test_linux_bash_zero_rows_is_completed_empty_not_an_error() -> None:
    """Case A: Volatility genuinely found nothing (no bash/sh/dash
    process, or history not resident).  This must produce a clean,
    warning-free empty result -- never treated as a failure.
    """
    result = _normalize_artifact_payload(
        "linux.bash",
        [],
        case_id=CASE,
        evidence_id=EVIDENCE,
        scan_run_id=RUN,
        plugin_run_id=f"{RUN}:linux.bash",
    )
    assert result["raw_count"] == 0
    assert result["accepted_count"] == 0
    assert result["items"] == []
    assert result["warnings"] == []


def test_linux_bash_malformed_payload_is_distinct_from_legitimate_zero() -> None:
    """Case B: Volatility returned rows, but they carry no usable
    command text (e.g. a garbled heap read).  This must be visibly
    different from case A: raw_count > 0, dropped_count > 0, and a
    warning explaining why -- never silently collapsed into the same
    "0 rows" shape as a clean empty scan.
    """
    malformed = [
        {"PID": 1234, "Process": "bash", "CommandTime": None, "Command": ""},
        {"PID": None, "Process": None, "CommandTime": None, "Command": "   "},
    ]
    result = _normalize_artifact_payload(
        "linux.bash",
        malformed,
        case_id=CASE,
        evidence_id=EVIDENCE,
        scan_run_id=RUN,
        plugin_run_id=f"{RUN}:linux.bash",
    )
    assert result["raw_count"] == 2
    assert result["accepted_count"] == 0
    assert result["dropped_count"] == 2
    assert result["items"] == []
    assert "bash_row_missing_command" in result["warnings"]
    # The two "zero results" shapes must remain distinguishable by their
    # raw_count / dropped_count, even though both produce items=[].
    clean = _normalize_artifact_payload("linux.bash", [], case_id=CASE, evidence_id=EVIDENCE, scan_run_id=RUN, plugin_run_id=f"{RUN}:linux.bash")
    assert (result["raw_count"], result["dropped_count"]) != (clean["raw_count"], clean["dropped_count"])


# ---------------------------------------------------------------------------
# Full run_memory_metadata_scan integration: linux.bash driven directly
# (metadata_json plugin override), bypassing profile resolution --
# no profile selects it yet.
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_session(tmp_path: Path) -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _seed_case_and_evidence(db: Session, tmp_path: Path) -> tuple[Case, Evidence, Path]:
    case = Case(id=str(uuid4()), name="Linux Shell History", description="", status="open", mode="investigation")
    evidence_path = tmp_path / "memory.mem"
    evidence_path.write_bytes(b"synthetic")
    evidence = Evidence(
        id=str(uuid4()),
        case_id=case.id,
        original_filename="memory.mem",
        stored_path=str(evidence_path),
        storage_mode=EvidenceStorageMode.uploaded,
        evidence_type=EvidenceType.memory_dump,
        size_bytes=evidence_path.stat().st_size,
        ingest_status=IngestStatus.completed,
        sha256="0" * 64,
        metadata_json={},
        detection_status="confirmed_memory",
        detection_confidence="high",
        detected_format="linux_memory",
    )
    db.add_all([case, evidence])
    db.commit()
    return case, evidence, evidence_path


class _SessionCtx:
    def __init__(self, db: Session) -> None:
        self._db = db

    def __enter__(self) -> Session:
        return self._db

    def __exit__(self, *_args: Any) -> bool:
        return False


def _run_linux_bash_scan(db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, payload: list[dict[str, Any]]) -> tuple[MemoryScanRun, MemoryPluginRun, dict[str, Any]]:
    case, evidence, evidence_path = _seed_case_and_evidence(db, tmp_path)
    run = MemoryScanRun(
        case_id=case.id,
        evidence_id=evidence.id,
        backend="volatility3",
        # "shell_history_basic" is a forward-reference profile name only
        # used to construct this run directly for the test -- it is not
        # registered anywhere in PROFILE_CAPABILITY / PROFILE_CATALOGUE /
        # allowed_memory_profiles, so it cannot be reached via the UI or
        # the normal profile-selection API.
        profile="shell_history_basic",
        status="queued",
        requested_plugin_count=1,
        plugin_count=1,
        metadata_json={"plugins": ["linux.bash"]},
    )
    db.add(run)
    db.commit()
    plugin_run = MemoryPluginRun(memory_scan_run_id=run.id, case_id=case.id, evidence_id=evidence.id, plugin="linux.bash", status="pending")
    db.add(plugin_run)
    db.commit()

    indexed: dict[str, Any] = {}
    monkeypatch.setattr(execution_module, "SessionLocal", lambda: _SessionCtx(db))
    monkeypatch.setattr(execution_module, "validate_memory_execution_request", lambda _db, _id: SimpleNamespace(evidence=evidence, path=evidence_path, size_bytes=evidence_path.stat().st_size))
    monkeypatch.setattr(execution_module, "validate_current_process_output_access", lambda: None)
    monkeypatch.setattr(execution_module.backend_readiness, "check_volatility3_backend", lambda: {"ready": True, "version": "Volatility 3 Framework 2.28.0"})
    monkeypatch.setattr(execution_module, "memory_run_dir", lambda *_args: tmp_path / "run")
    monkeypatch.setattr(execution_module, "relative_to_data_dir", lambda _path: "memory-output/run")
    monkeypatch.setattr(execution_module, "write_atomic_json", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(execution_module, "run_plugin", lambda *_args, **_kwargs: SimpleNamespace(argv_display=["vol", "-f", "[evidence]", "linux.bash"], stdout=__import__("json").dumps(payload).encode("utf-8"), stderr=b"", duration_ms=5))
    monkeypatch.setattr(execution_module, "write_atomic_bytes", lambda *_args, **_kwargs: {"path": "memory-output/linux.bash.json", "sha256": "0" * 64, "size": 10, "stderr_preview": None, "vmware_metadata_warning_detected": False})

    def fake_index(case_id: str, documents: list[dict[str, Any]]) -> dict[str, Any]:
        indexed[case_id] = documents
        return {"indexed": len(documents), "errors": 0}

    monkeypatch.setattr(execution_module, "index_artifact_documents", fake_index)
    monkeypatch.setattr(execution_module, "link_process_entities", lambda *args, **kwargs: 0)
    monkeypatch.setattr(execution_module, "count_artifact_documents", lambda *args, **kwargs: len(indexed.get(case.id, [])))

    execution_module.run_memory_metadata_scan(run.id)
    db.refresh(run)
    db.refresh(plugin_run)
    return run, plugin_run, indexed


def test_run_scan_with_rows_indexes_shell_history_documents(db_session: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run, plugin_run, indexed = _run_linux_bash_scan(db_session, tmp_path, monkeypatch, payload=_bash_rows())

    assert plugin_run.status == "completed"
    assert plugin_run.row_count == 2
    assert plugin_run.metadata_json["normalized_type"] == "memory_shell_history"
    assert plugin_run.metadata_json["accepted_count"] == 2
    assert not any("unsupported_artifact_plugin" in w for w in plugin_run.metadata_json.get("warnings", []))
    assert run.status == "completed"
    documents = indexed[run.case_id]
    assert len(documents) == 2
    assert {doc["document_type"] for doc in documents} == {"memory_shell_history"}


def test_run_scan_with_zero_rows_completes_cleanly(db_session: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run, plugin_run, indexed = _run_linux_bash_scan(db_session, tmp_path, monkeypatch, payload=[])

    assert plugin_run.status == "completed"
    assert plugin_run.row_count == 0
    assert plugin_run.metadata_json["accepted_count"] == 0
    assert not any("unsupported_artifact_plugin" in w for w in plugin_run.metadata_json.get("warnings", []))
    assert run.status == "completed"
    assert run.case_id not in indexed or indexed[run.case_id] == []


# ---------------------------------------------------------------------------
# Family resolution / active-result (points 5, 7)
# ---------------------------------------------------------------------------


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _make_case(db: Session) -> Case:
    case = Case(id=str(uuid4()), name="Shell History Family", description="", status="open", mode="investigation")
    db.add(case)
    db.commit()
    return case


def _make_evidence(db: Session, case_id: str) -> Evidence:
    evidence = Evidence(
        id=str(uuid4()),
        case_id=case_id,
        original_filename="a.mem",
        stored_path="/tmp/a.mem",
        evidence_type=EvidenceType.memory_dump,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256=str(uuid4()),
        size_bytes=1024,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        path_validation={},
        ingest_source={},
        error_log={},
    )
    db.add(evidence)
    db.commit()
    return evidence


def test_shell_history_is_a_registered_family() -> None:
    assert "shell_history" in FAMILY_RESOLUTION
    rules = FAMILY_RESOLUTION["shell_history"]
    assert rules["evidence_id_required"] is True
    assert "memory_shell_history" in rules["fallback_doc_types"]


def test_shell_history_resolves_as_a_generic_active_result(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    run = MemoryScanRun(
        case_id=case.id,
        evidence_id=ev.id,
        profile="shell_history_basic",
        status="completed",
        requested_plugin_count=1,
        plugin_count=1,
        plugins_completed=1,
    )
    db.add(run)
    db.commit()

    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="shell_history")
    assert result["active_run"] is not None
    assert result["active_run"]["id"] == run.id
    assert result["analysis_state"] in {"analyzed_empty", "analyzed_with_results"}


def test_shell_history_zero_results_run_is_still_active_not_failed(db: Session) -> None:
    """A completed run with zero legitimate shell-history rows must
    resolve as active with analysis_state analyzed_empty, exactly like
    every other non-canonical-required family -- 0 results is not a
    failure.
    """
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    run = MemoryScanRun(case_id=case.id, evidence_id=ev.id, profile="shell_history_basic", status="completed", requested_plugin_count=1, plugin_count=1, plugins_completed=1)
    db.add(run)
    db.commit()

    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="shell_history")
    assert result["active_run"] is not None
    assert result["using_fallback"] is False


def test_shell_history_no_run_is_not_analyzed(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="shell_history")
    assert result["analysis_state"] == "not_analyzed"
    assert result["active_run"] is None


def test_shell_history_failed_latest_attempt_keeps_last_success(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    ok = MemoryScanRun(case_id=case.id, evidence_id=ev.id, profile="shell_history_basic", status="completed", requested_plugin_count=1, plugin_count=1, plugins_completed=1, created_at=datetime(2026, 6, 15, tzinfo=timezone.utc))
    db.add(ok)
    db.commit()
    failed = MemoryScanRun(case_id=case.id, evidence_id=ev.id, profile="shell_history_basic", status="failed", requested_plugin_count=1, plugin_count=1, plugins_failed=1, created_at=datetime(2026, 6, 16, tzinfo=timezone.utc))
    db.add(failed)
    db.commit()

    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="shell_history")
    assert result["active_run"]["id"] == ok.id
    assert result["using_fallback"] is True
    assert result["selection_reason"] == "latest_attempt_failed_kept_last_success"


# ---------------------------------------------------------------------------
# Counts (point 8): family -> document_type mapping, not exposed in the
# catalogue/Overview ordering yet.
# ---------------------------------------------------------------------------


def test_shell_history_counts_mapping_present_and_in_family_order() -> None:
    # Phase 1 kept shell_history out of FAMILY_ORDER deliberately (backend
    # only, not yet exposed). Phase 2 (profile + catalogue + frontend view)
    # activates it -- see counts.FAMILY_ORDER's own comment for the chosen
    # position (right after "processes").
    assert FAMILY_TO_DOCUMENT_TYPE["shell_history"] == "memory_shell_history"
    assert "shell_history" in FAMILY_ORDER


# ---------------------------------------------------------------------------
# Search (point 9)
# ---------------------------------------------------------------------------


class _FakeSearchClient:
    def __init__(self) -> None:
        self.last_body: dict[str, Any] | None = None

    def search(self, index: str, body: dict[str, Any], params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.last_body = body
        return {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": {}}


def test_shell_history_is_searchable_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    assert "shell_history" in search_module.SUPPORTED_FAMILIES
    assert search_module.FAMILY_SPECS["shell_history"].document_type == "memory_shell_history"
    assert search_module.FAMILY_SPECS["shell_history"].active_family == "shell_history"


def test_shell_history_command_text_search_targets_command_field(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeSearchClient()
    monkeypatch.setattr(search_module, "get_opensearch_client", lambda: client)
    monkeypatch.setattr(search_module, "get_memory_index", lambda case_id: f"dfir-memory-{case_id}")
    monkeypatch.setattr(search_module, "resolve_active_memory_result", lambda db, **kwargs: {"active_run": {"id": "run-1", "profile": "shell_history_basic", "status": "completed"}})
    db = SimpleNamespace(get=lambda model, ident: SimpleNamespace(id=ident, filename="mem.raw"))

    search_module.search_memory_artifacts(db, case_id="case-1", evidence_id="ev-1", query="sudo apt update", artifact_types=["shell_history"])
    assert client.last_body is not None
    assert "command" in str(client.last_body["query"]["bool"]["must"])


# ---------------------------------------------------------------------------
# Timeline (point 10): MEMORY_TIMESTAMP_MATRIX is load-bearing --
# _fetch_memory_docs iterates it to decide which doc types to fetch at
# all, so a missing entry here means shell history is invisible to the
# timeline no matter what _memory_events does.
# ---------------------------------------------------------------------------


def test_shell_history_registered_in_timestamp_matrix() -> None:
    assert "memory_shell_history" in MEMORY_TIMESTAMP_MATRIX
    entry = MEMORY_TIMESTAMP_MATRIX["memory_shell_history"]
    assert entry["nullable"] is True
    assert entry["occurrence"] is True


class _FakeTimelineClient:
    def __init__(self, memory_docs: list[dict[str, Any]]) -> None:
        self.memory_docs = memory_docs

    def search(self, index: str, body: dict[str, Any], params: dict[str, Any] | None = None) -> dict[str, Any]:
        if index == "events":
            return {"hits": {"total": {"value": 0}, "hits": []}}
        text = str(body)
        docs = [doc for doc in self.memory_docs if doc.get("document_type") in text]
        return {"hits": {"total": {"value": len(docs)}, "hits": [{"_id": doc.get("document_id"), "_source": doc} for doc in docs]}}


class _FakeTimelineDb:
    def get(self, model: Any, ident: Any) -> Any:
        if ident == "ev-1":
            return SimpleNamespace(id="ev-1", case_id="case-1", filename="mem.raw")
        return SimpleNamespace(id=ident, case_id="case-1", evidence_id="ev-1", profile="shell_history_basic", status="completed")


def _shell_history_doc(command_time: str | None) -> dict[str, Any]:
    return {
        "document_id": "sh-1",
        "document_type": "memory_shell_history",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "scan_run_id": "run-1",
        "plugin_run_id": "plug-1",
        "pid": 1234,
        "process_name": "bash",
        "command": "sudo apt update",
        "command_time": command_time,
        "source_plugin": "linux.bash",
    }


def _patch_timeline_client(monkeypatch: pytest.MonkeyPatch, client: _FakeTimelineClient) -> None:
    monkeypatch.setattr(timeline_module, "get_opensearch_client", lambda: client)
    monkeypatch.setattr(timeline_module, "get_memory_index", lambda case_id: f"memory-{case_id}")
    monkeypatch.setattr(timeline_module, "get_events_index", lambda: "events")
    monkeypatch.setattr(timeline_module, "resolve_active_memory_result", lambda *a, **k: {"active_run": {"id": "run-1"}})


def test_shell_history_command_with_timestamp_enters_timeline(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeTimelineClient([_shell_history_doc("2024-03-22T10:53:00")])
    _patch_timeline_client(monkeypatch, client)
    result = timeline_module.get_memory_timeline(_FakeTimelineDb(), case_id="case-1", evidence_id="ev-1")
    assert result["items"]
    assert result["items"][0]["event_kind"] == "shell_command"
    assert result["items"][0]["is_undated"] is False
    assert result["items"][0]["command_line_summary"] is None or "sudo" not in (result["items"][0]["command_line_summary"] or "")
    assert result["items"][0]["summary"] and "sudo apt update" in result["items"][0]["summary"]


def test_shell_history_command_without_timestamp_is_undated_not_fabricated(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeTimelineClient([_shell_history_doc(None)])
    _patch_timeline_client(monkeypatch, client)
    result = timeline_module.get_memory_timeline(_FakeTimelineDb(), case_id="case-1", evidence_id="ev-1", include_undated=True)
    assert result["undated_count"] == 1
    undated_item = result["items"][0]
    assert undated_item["is_undated"] is True
    assert undated_item["occurred_at"] is None
    assert undated_item["event_kind"] == "undated_shell_command"


# ---------------------------------------------------------------------------
# Regression (point 14): the catalogue, PROFILE_CAPABILITY,
# allowed_memory_profiles, and every existing profile's plugin list
# remain untouched -- linux.bash is still not reachable via any profile.
# ---------------------------------------------------------------------------


def test_processes_basic_and_network_basic_plugin_lists_are_unchanged() -> None:
    assert PROFILE_PLUGINS["processes_basic"] == ["windows.info", "windows.pslist", "windows.pstree", "windows.cmdline"]
    assert PROFILE_PLUGINS["network_basic"] == ["windows.netscan", "windows.netstat"]


def test_no_profile_references_linux_bash() -> None:
    for profile, plugins in PROFILE_PLUGINS.items():
        assert "linux.bash" not in plugins, f"{profile} unexpectedly selects linux.bash"


def test_profile_capability_now_includes_shell_history_basic() -> None:
    """Phase 1 kept SHELL_HISTORY out of PROFILE_CAPABILITY deliberately
    (no real profile existed yet). Phase 2 adds shell_history_basic ->
    MemoryCapability.SHELL_HISTORY -- see test_memory_shell_history_phase2.py
    for the full profile/catalogue/platform-availability coverage.
    """
    from app.services.memory.capability_registry import MemoryCapability

    assert set(PROFILE_CAPABILITY.values()) == {
        MemoryCapability.IDENTIFICATION,
        MemoryCapability.PROCESSES,
        MemoryCapability.PROCESSES_EXTENDED,
        MemoryCapability.NETWORK,
        MemoryCapability.MODULES,
        MemoryCapability.HANDLES,
        MemoryCapability.KERNEL_MODULES,
        MemoryCapability.SUSPICIOUS_REGIONS,
        MemoryCapability.SHELL_HISTORY,
    }
    assert PROFILE_CAPABILITY["shell_history_basic"] == MemoryCapability.SHELL_HISTORY


def test_resolve_profile_plugins_plan_none_never_selects_real_plugins_for_any_profile() -> None:
    """plan=None is documented as a backward-compatible fallback never
    relied on for real routing (see resolve_profile_plugins's docstring):
    it returns the flat PROFILE_PLUGINS entry when one exists, or an
    empty list otherwise -- never linux.bash, regardless of profile,
    since platform routing requires a real MemoryAnalysisPlan.
    """
    from app.services.memory.execution import resolve_profile_plugins

    for profile in PROFILE_CAPABILITY:
        try:
            plugins = resolve_profile_plugins(profile, plan=None)
        except Exception:
            continue
        assert "linux.bash" not in plugins


def test_shell_history_now_appears_in_the_case_landing_page(db: Session) -> None:
    """Phase 1 deliberately excluded shell_history from the landing page
    (FAMILY_ORDER-gated, backend only). Phase 2 activates it in
    FAMILY_ORDER (counts.py) specifically so it appears here, alongside
    every other catalogued family -- see
    test_memory_shell_history_phase2.py for the full assertion.
    """
    from app.services.memory.overview import get_evidence_landing

    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    landing = get_evidence_landing(db, case.id)
    matching = [item for item in landing if item["evidence_id"] == ev.id]
    assert matching, "expected the seeded evidence to appear in the landing page"
    families_shown = {family["family"] for family in matching[0]["families"]}
    assert "shell_history" in families_shown
    assert families_shown == set(FAMILY_ORDER)
