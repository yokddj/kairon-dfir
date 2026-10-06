"""MemProcFS FindEvil: child output parsing, runner containment and error mapping, normalization."""

from __future__ import annotations

import json
import pytest

from app.services.memory import memprocfs_runner
from app.services.memory.artifact_normalizers import FINDEVIL_TYPES, normalize_memprocfs_findevil
from app.services.memory.memprocfs_findevil import findevil_rows
from app.services.memory.volatility_runner import VolatilityRunnerError

# Shaped like MemProcFS 5.19's forensic/csv/findevil.csv on a Windows 11 image.
CSV = (
    "PID,ProcessName,Type,Address,Description\n"
    '0,"",AV_DETECT,0x0,"AV:[Windows Defender] EVENT:[2024-03-22T12:46:35.870Z DETECTIONEVENT MPSOURCE_REALTIME VirTool:Win32/Example.A file:C:\\Users\\Public\\tool.exe]"\n'
    '52,"WmiPrvSE.exe",PROC_NOLINK,0xffff988a4d6d60c0,""\n'
    '3944,"psexec.exe",PROC_DEBUG,0x0,""\n'
    '4292,"dllhost.exe",THREAD,0x7ffb21905080,"TID:15452 SYSTEM_IMPERSONATION"\n'
    '2152,"msedge.exe",PRIVATE_RWX,0x7ffae1950000,"0000661c9000 00002000661c9860 T --- p-rwx-"\n'
    '9816,"OUTLOOK.EXE",HIGH_ENTROPY,0x1e990000,"Entropy:[7.71]       p-rw--"\n'
)


def test_child_parses_the_findevil_csv() -> None:
    rows = findevil_rows(CSV)
    assert [row["Type"] for row in rows] == ["AV_DETECT", "PROC_NOLINK", "PROC_DEBUG", "THREAD", "PRIVATE_RWX", "HIGH_ENTROPY"]
    assert rows[1] == {"PID": "52", "Process": "WmiPrvSE.exe", "Type": "PROC_NOLINK", "Address": "0xffff988a4d6d60c0", "Description": ""}
    assert rows[0]["Description"].startswith("AV:[Windows Defender]")


def _normalize(rows: list[dict]) -> dict:
    return normalize_memprocfs_findevil(rows, case_id="case-1", evidence_id="ev-1", scan_run_id="run-1", plugin_run_id="run-1:memprocfs.findevil")


def test_indicators_are_neutral_observations_with_a_review_priority() -> None:
    result = _normalize(findevil_rows(CSV))
    assert result["accepted_count"] == 6 and result["dropped_count"] == 0
    by_type = {item["indicator_type"]: item for item in result["items"]}
    assert (by_type["AV_DETECT"]["review_priority"], by_type["AV_DETECT"]["indicator_category"], by_type["AV_DETECT"]["pid"]) == ("high", "antivirus", None)
    assert by_type["PROC_NOLINK"]["review_priority"] == "high"
    assert (by_type["PROC_DEBUG"]["review_priority"], by_type["THREAD"]["review_priority"]) == ("medium", "medium")
    assert by_type["PRIVATE_RWX"]["review_priority"] == "low"
    assert "JIT" in by_type["PRIVATE_RWX"]["explanation"]
    item = by_type["PROC_NOLINK"]
    assert (item["document_type"], item["pid"], item["process_name"], item["address"], item["platform"]) == ("memory_findevil", 52, "WmiPrvSE.exe", "0xffff988a4d6d60c0", "windows")
    assert item["description"] is None
    assert [item["review_rank"] for item in result["items"]] == [0, 0, 1, 1, 2, 1]
    assert [item["sequence"] for item in result["items"]] == list(range(6))


def test_unknown_and_yara_types_are_kept() -> None:
    result = _normalize([{"PID": "7", "Process": "a.exe", "Type": "YR_EXAMPLE_RULE", "Address": "0x1", "Description": "rule"}, {"PID": "8", "Process": "b.exe", "Type": "SOMETHING_NEW", "Address": "0x2", "Description": ""}])
    assert [(item["indicator_category"], item["review_priority"]) for item in result["items"]] == [("yara", "high"), ("other", "medium")]


def test_rows_without_a_type_are_dropped() -> None:
    result = _normalize([{"PID": "1", "Process": "x.exe", "Type": "", "Address": "0x0", "Description": ""}])
    assert (result["accepted_count"], result["dropped_count"], result["warnings"]) == (0, 1, ["findevil_row_missing_type"])


def test_every_known_type_has_a_priority_and_an_explanation() -> None:
    for indicator_type, (priority, category, explanation) in FINDEVIL_TYPES.items():
        assert priority in {"high", "medium", "low"}, indicator_type
        assert category and explanation.endswith("."), indicator_type


# --- runner -----------------------------------------------------------------------------------


@pytest.fixture
def library(tmp_path, monkeypatch):
    lib = tmp_path / "vmm.so"
    lib.write_bytes(b"")
    monkeypatch.setattr(memprocfs_runner, "memprocfs_library", lambda: lib)
    return lib


def test_missing_library_is_reported_not_crashed(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(memprocfs_runner, "memprocfs_library", lambda: tmp_path / "absent.so")
    assert memprocfs_runner.memprocfs_available() is False
    with pytest.raises(VolatilityRunnerError) as exc:
        memprocfs_runner.run_findevil(tmp_path / "image.dmp", tmp_path, timeout_seconds=60, max_output_bytes=1024)
    assert exc.value.code == "MEMPROCFS_UNAVAILABLE"


def test_runner_starts_the_child_contained_and_returns_its_rows(tmp_path, library, monkeypatch) -> None:
    calls = {}

    def fake_run(argv, **kwargs):
        calls["argv"], calls["kwargs"] = argv, kwargs
        return json.dumps(findevil_rows(CSV)).encode(), b"", 0, 1234

    monkeypatch.setattr(memprocfs_runner, "run_isolated_process", fake_run)
    result = memprocfs_runner.run_findevil(tmp_path / "image.dmp", tmp_path, timeout_seconds=600, max_output_bytes=4096, cancellation_check=lambda: False)
    assert calls["argv"][1:3] == ["-m", "app.services.memory.memprocfs_findevil"]
    assert calls["argv"][calls["argv"].index("--evidence") + 1] == str(tmp_path / "image.dmp")
    assert calls["argv"][calls["argv"].index("--scan-timeout") + 1] == "570"
    assert calls["kwargs"]["timeout"] == 600 and calls["kwargs"]["max_bytes"] == 4096
    assert calls["kwargs"]["env"]["LD_LIBRARY_PATH"] == str(library.parent)
    assert "[evidence]" in result.argv_display and str(tmp_path) not in " ".join(result.argv_display)
    assert len(json.loads(result.stdout)) == 6


@pytest.mark.parametrize(
    "returncode, code",
    [(3, "MEMPROCFS_UNAVAILABLE"), (4, "UNSUPPORTED_MEMORY_IMAGE"), (5, "PLUGIN_REQUIREMENTS_UNSATISFIED"), (6, "PLUGIN_UNSUPPORTED_WINDOWS_BUILD"), (1, "PLUGIN_FAILED"), (-11, "PLUGIN_FAILED")],
)
def test_child_exit_codes_map_to_pipeline_errors(tmp_path, library, monkeypatch, returncode, code) -> None:
    monkeypatch.setattr(memprocfs_runner, "run_isolated_process", lambda argv, **kwargs: (b"", b"MemProcFS said why\n", returncode, 10))
    with pytest.raises(VolatilityRunnerError) as exc:
        memprocfs_runner.run_findevil(tmp_path / "image.dmp", tmp_path, timeout_seconds=60, max_output_bytes=1024)
    assert exc.value.code == code


def test_execution_sends_findevil_to_memprocfs_not_volatility(tmp_path, monkeypatch) -> None:
    from types import SimpleNamespace

    from app.services.memory import execution

    used = {}

    def fake_findevil(evidence_path, work_dir, **kwargs):
        used["memprocfs"] = True
        return memprocfs_runner.VolatilityRunResult(argv_display=["memprocfs"], stdout=json.dumps(findevil_rows(CSV)).encode(), stderr=b"", duration_ms=5)

    def fake_volatility(*args, **kwargs):
        raise AssertionError("FindEvil must not go to Volatility")

    monkeypatch.setattr(execution, "run_findevil", fake_findevil)
    monkeypatch.setattr(execution, "run_plugin", fake_volatility)

    class _Db:
        def commit(self):
            pass

        def refresh(self, obj):
            pass

    run = SimpleNamespace(cancellation_requested=False)
    plugin_run = SimpleNamespace(status=None, started_at=None, metadata_json={})
    payload, raw_info, duration_ms, argv = execution._execute_plugin(_Db(), run, plugin_run, "memprocfs.findevil", tmp_path / "image.dmp", tmp_path)
    assert used == {"memprocfs": True}
    assert len(payload) == 6 and duration_ms == 5 and argv == ["memprocfs"]
    # The raw output is kept like any plugin's, under the run's output directory.
    assert raw_info["size"] == len(json.dumps(findevil_rows(CSV)).encode())


def test_listing_sorts_and_filters_on_fields_every_case_index_has(monkeypatch) -> None:
    # Case indexes created before FindEvil existed got these fields from dynamic mapping
    # (text + .keyword): sorting or term-filtering the text field itself fails there.
    from app.services.memory import active_result, artifact_indexing

    captured = {}

    class _Client:
        def search(self, index, body, params):  # noqa: ANN001
            captured.update(body)
            return {"hits": {"total": {"value": 0}, "hits": []}}

    monkeypatch.setattr(artifact_indexing, "get_opensearch_client", lambda: _Client())
    artifact_indexing.search_artifact_documents(
        "case-1",
        document_type="memory_findevil",
        evidence_id="ev-1",
        filters={"indicator_type": "PROC_NOLINK", "review_priority": "high"},
        sort=active_result.FAMILY_SORT["find_evil"],
    )
    fields = [next(iter(clause)) for clause in captured["sort"]]
    assert fields[:2] == ["review_rank", "indicator_type.keyword"]
    terms = [clause["term"] for clause in captured["query"]["bool"]["filter"] if "term" in clause]
    assert {"indicator_type.keyword": "PROC_NOLINK"} in terms
    assert {"review_priority.keyword": "high"} in terms
    mapping = artifact_indexing.ARTIFACT_MAPPING["mappings"]["properties"]
    assert mapping["indicator_type"]["fields"]["keyword"]["type"] == "keyword"
