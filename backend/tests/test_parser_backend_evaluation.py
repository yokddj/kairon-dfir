from app.services.parser_backend_evaluation import (
    CORE_ARTIFACT_TYPES,
    build_core_parser_backend_evaluation,
    build_core_ez_tools_backend_plan,
    build_parser_backend_inventory,
    build_windows_ez_tools_worker_feasibility,
    detect_ez_tools,
)


def test_parser_backend_inventory_includes_core_artifact_types(monkeypatch) -> None:
    fake_tools = {
        "LECmd": {"available": True, "version": "2026.5.0"},
        "JLECmd": {"available": True, "version": "2026.5.0"},
        "PECmd": {"available": True, "version": "2026.5.0"},
        "AmcacheParser": {"available": True, "version": "2026.5.0"},
        "AppCompatCacheParser": {"available": True, "version": "2026.5.0"},
        "RECmd": {"available": True, "version": "2026.5.0"},
        "MFTECmd": {"available": True, "version": "2026.5.0"},
        "SrumECmd": {
            "available": True,
            "version": "2026.5.0",
            "runs_on_linux": False,
            "requires_windows": True,
            "recommended_worker": "windows",
            "parser_execution_backend": "windows_worker",
        },
        "PECmd": {
            "available": True,
            "version": "2026.5.0",
            "runs_on_linux": True,
            "requires_windows": False,
            "raw_command_requires_windows": True,
            "recommended_worker": "windows",
            "parser_execution_backend": "windows_worker",
        },
    }

    inventory = build_parser_backend_inventory(fake_tools)

    artifact_types = {item["artifact_type"] for item in inventory["items"]}
    assert set(CORE_ARTIFACT_TYPES) <= artifact_types
    assert all("candidate_external_tool" in item for item in inventory["items"])
    assert any(item["artifact_type"] == "jumplist" and item["recommendation"] == "defer" for item in inventory["items"])
    srum = next(item for item in inventory["items"] if item["artifact_type"] == "srum")
    assert srum["external_tool_installed"] is True
    assert srum["external_tool_available"] is False
    assert srum["parser_execution_backend"] == "windows_worker"
    prefetch = next(item for item in inventory["items"] if item["artifact_type"] == "prefetch")
    assert prefetch["external_raw_command_requires_windows"] is True
    assert prefetch["external_tool_available"] is False


def test_ez_tools_registry_reports_unavailable_when_missing(monkeypatch) -> None:
    monkeypatch.setattr("app.services.parser_backend_evaluation._tool_dll_path", lambda tool: None)

    tools = detect_ez_tools()

    assert tools["LECmd"]["available"] is False
    assert tools["PECmd"]["error"] == "tool_dll_not_found"
    assert tools["SrumECmd"]["parser_execution_backend"] == "unavailable"


def test_windows_worker_feasibility_records_windows_only_srum() -> None:
    feasibility = build_windows_ez_tools_worker_feasibility(
        {
            "SrumECmd": {
                "available": True,
                "version": "2026.5.0",
                "runs_on_linux": False,
                "requires_windows": True,
                "sample_command_ok": False,
                "recommended_worker": "windows",
                "parser_execution_backend": "windows_worker",
                "output_format": "csv",
            },
            "MFTECmd": {
                "available": True,
                "version": "2026.5.0",
                "runs_on_linux": True,
                "requires_windows": False,
                "sample_command_ok": True,
                "recommended_worker": "linux",
                "parser_execution_backend": "linux_local",
                "output_format": "csv",
            },
            "PECmd": {
                "available": True,
                "version": "2026.5.0",
                "runs_on_linux": True,
                "requires_windows": False,
                "raw_command_requires_windows": True,
                "sample_command_ok": False,
                "recommended_worker": "windows",
                "parser_execution_backend": "windows_worker",
                "output_format": "csv",
            },
            "SBECmd": {"available": False, "error": "tool_dll_not_found"},
        }
    )

    rows = {row["tool"]: row for row in feasibility["compatibility_matrix"]}
    assert rows["SrumECmd"]["requires_windows"] is True
    assert rows["SrumECmd"]["recommended_worker"] == "windows"
    assert rows["SrumECmd"]["parser_execution_backend"] == "windows_worker"
    assert rows["PECmd"]["raw_command_requires_windows"] is True
    assert rows["PECmd"]["parser_execution_backend"] == "windows_worker"
    assert rows["MFTECmd"]["recommended_worker"] == "linux"
    assert rows["SBECmd"]["available"] is False
    assert feasibility["windows_worker_design"]["job_model"]
    assert feasibility["srum_decision"]["recommended_backend"] == "windows_worker"
    assert feasibility["shellbags_decision"]["recommended_backend"] == "defer"


def test_core_ez_tools_backend_plan_keeps_prefetch_internal_and_core_tools_advanced() -> None:
    plan = build_core_ez_tools_backend_plan(
        {
            "PECmd": {"available": True, "version": "2026.5.0", "runs_on_linux": True, "raw_command_requires_windows": True, "parser_execution_backend": "windows_worker"},
            "LECmd": {"available": True, "version": "2026.5.0", "runs_on_linux": True, "parser_execution_backend": "linux_local"},
            "JLECmd": {"available": True, "version": "2026.5.0", "runs_on_linux": True, "parser_execution_backend": "linux_local"},
            "AmcacheParser": {"available": True, "version": "2026.5.0", "runs_on_linux": True, "parser_execution_backend": "linux_local"},
            "AppCompatCacheParser": {"available": True, "version": "2026.5.0", "runs_on_linux": True, "parser_execution_backend": "linux_local"},
        }
    )

    artifacts = plan["artifacts"]
    assert artifacts["prefetch"]["decision"] == "keep_internal"
    assert artifacts["prefetch"]["raw_command_requires_windows"] is True
    assert artifacts["lnk"]["decision"] == "advanced_only"
    assert artifacts["jumplist"]["decision"] == "advanced_only"
    assert artifacts["amcache"]["decision"] == "advanced_only"
    assert artifacts["shimcache"]["decision"] == "advanced_only"
    assert artifacts["lnk"]["command_contract"]["output_format"] == "csv"


def test_core_parser_backend_evaluation_has_benchmark_and_decisions(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.parser_backend_evaluation.detect_ez_tools",
        lambda: {
            "EvtxECmd": {"available": True, "version": "2026.5.0"},
            "LECmd": {"available": True, "version": "2026.5.0"},
            "JLECmd": {"available": True, "version": "2026.5.0"},
            "PECmd": {"available": True, "version": "2026.5.0"},
            "AmcacheParser": {"available": True, "version": "2026.5.0"},
            "AppCompatCacheParser": {"available": True, "version": "2026.5.0"},
            "RECmd": {"available": True, "version": "2026.5.0"},
            "MFTECmd": {"available": True, "version": "2026.5.0"},
            "SrumECmd": {"available": True, "version": "2026.5.0", "runs_on_linux": False, "requires_windows": True, "parser_execution_backend": "windows_worker"},
        },
    )

    evaluation = build_core_parser_backend_evaluation()

    assert "parser_backend_inventory" in evaluation
    assert "windows_ez_tools_worker_feasibility" in evaluation
    assert "core_ez_tools_backend_plan" in evaluation
    lnk_benchmark = evaluation["parser_backend_benchmark"]["lnk"]["eztool_csv"]
    assert lnk_benchmark["status"] in {"completed", "completed_with_errors", "insufficient_sample"}
    if "searchable_contract" in lnk_benchmark:
        assert lnk_benchmark["searchable_contract"] in {"pass", "partial"}
    assert evaluation["parser_backend_decisions"]["prefetch"]["fallback_backend"] == "internal"
