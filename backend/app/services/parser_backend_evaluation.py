from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.ingest.eztools.amcache import AmcacheParser
from app.ingest.eztools.jlecmd import JLECmdParser
from app.ingest.eztools.lecmd import LECmdParser
from app.ingest.eztools.mftecmd import MFTECmdParser
from app.ingest.eztools.pecmd import PECmdParser
from app.ingest.eztools.recmd import RECmdParser
from app.ingest.eztools.shimcache import ShimCacheParser
from app.ingest.eztools.srumecmd import SrumECmdParser
from app.ingest.raw_parsers.amcache_parser import AmcacheRawParser
from app.ingest.raw_parsers.lnk_parser import LnkRawParser
from app.ingest.raw_parsers.prefetch_parser import PrefetchRawParser
from app.ingest.raw_parsers.shimcache_parser import ShimcacheRawParser
from app.services.parser_registry import get_parser_registry_entry


CORE_ARTIFACT_TYPES = ["lnk", "jumplist", "prefetch", "amcache", "shimcache", "registry_selected", "mft", "srum"]
WINDOWS_WORKER_COMPATIBILITY_TOOLS = [
    "SrumECmd",
    "SBECmd",
    "ShellBagsExplorer",
    "PECmd",
    "LECmd",
    "JLECmd",
    "AmcacheParser",
    "AppCompatCacheParser",
    "RECmd",
    "MFTECmd",
    "EvtxECmd",
    "UsnJrnl2Csv",
]
WINDOWS_ONLY_TOOLS = {"SrumECmd"}
RAW_COMMAND_WINDOWS_ONLY_TOOLS = {"PECmd"}
TOOL_OUTPUT_FORMATS = {
    "EvtxECmd": "csv",
    "LECmd": "csv",
    "JLECmd": "csv",
    "PECmd": "csv",
    "AmcacheParser": "csv",
    "AppCompatCacheParser": "csv",
    "RECmd": "csv",
    "MFTECmd": "csv",
    "SrumECmd": "csv",
    "SBECmd": "csv",
    "ShellBagsExplorer": "csv",
    "UsnJrnl2Csv": "csv",
}
CORE_EZ_BACKEND_DECISIONS = {
    "prefetch": {
        "decision": "keep_internal",
        "reason": "PECmd is installed, but raw .pf parsing on this Linux runtime exits with Windows decompression library requirements. Keep native prefetch_raw as default.",
        "activation_safe": False,
    },
    "lnk": {
        "decision": "advanced_only",
        "reason": "LECmd runs on Linux and emits richer target/argument metadata, but HOSTA scoped benchmark produced fewer rows than the current indexed internal set. Keep default internal until scoped per-candidate rebuild is wired.",
        "activation_safe": False,
    },
    "jumplist": {
        "decision": "advanced_only",
        "reason": "JLECmd runs on Linux and emits AppId/MRU/target metadata, but HOSTA scoped benchmark produced fewer rows than the current indexed internal set. Keep default internal until rebuild coverage is complete.",
        "activation_safe": False,
    },
    "amcache": {
        "decision": "advanced_only",
        "reason": "AmcacheParser runs on Linux and improves path/hash/publisher fields for executable inventory, but raw execution/replacement should stay scoped because count differs from existing native output.",
        "activation_safe": False,
    },
    "shimcache": {
        "decision": "advanced_only",
        "reason": "AppCompatCacheParser runs on Linux and produced more AppCompatCache rows on HOSTA, but execution semantics are low-confidence and should remain an explicit scoped rebuild before default activation.",
        "activation_safe": False,
    },
}
CORE_EZ_COMMAND_CONTRACTS = {
    "prefetch": {
        "tool": "PECmd",
        "command": "dotnet /opt/eztools/PECmd/PECmd.dll -d <PrefetchDir> --csv <output_dir>",
        "input_type": "directory of .pf files",
        "output_format": "csv",
    },
    "lnk": {
        "tool": "LECmd",
        "command": "dotnet /opt/eztools/LECmd/LECmd.dll -d <RecentOrShortcutDir> --csv <output_dir>",
        "input_type": "directory or single .lnk file",
        "output_format": "csv",
    },
    "jumplist": {
        "tool": "JLECmd",
        "command": "dotnet /opt/eztools/JLECmd/JLECmd.dll -d <RecentDir> --csv <output_dir>",
        "input_type": "automatic/custom destination files",
        "output_format": "csv",
    },
    "amcache": {
        "tool": "AmcacheParser",
        "command": "dotnet /opt/eztools/AmcacheParser/AmcacheParser.dll -f <Amcache.hve> --csv <output_dir>",
        "input_type": "Amcache.hve",
        "output_format": "csv",
    },
    "shimcache": {
        "tool": "AppCompatCacheParser",
        "command": "dotnet /opt/eztools/AppCompatCacheParser/AppCompatCacheParser.dll -f <SYSTEM> --csv <output_dir>",
        "input_type": "SYSTEM hive",
        "output_format": "csv",
    },
}


@dataclass(frozen=True)
class ToolDefinition:
    artifact_type: str
    tool: str
    internal_parser: str
    fixture: str | None
    csv_parser: type | None
    raw_parser: type | None = None
    raw_globs: tuple[str, ...] = ()
    recommendation_when_available: str = "defer"
    recommendation_reason: str = "Needs raw-tool benchmark before default backend change."
    volume_risk: str = "low"


TOOL_DEFINITIONS: dict[str, ToolDefinition] = {
    "lnk": ToolDefinition(
        artifact_type="lnk",
        tool="LECmd",
        internal_parser="lnk_raw",
        fixture="lecmd_sample.csv",
        csv_parser=LECmdParser,
        raw_parser=LnkRawParser,
        raw_globs=("*.lnk",),
        recommendation_when_available="defer",
        recommendation_reason="LECmd likely has richer parsing, but default change requires raw LNK benchmark and command validation.",
    ),
    "jumplist": ToolDefinition(
        artifact_type="jumplist",
        tool="JLECmd",
        internal_parser="jumplist_raw_automatic",
        fixture="jlecmd_sample.csv",
        csv_parser=JLECmdParser,
        raw_parser=None,
        raw_globs=("*.automaticDestinations-ms", "*.customDestinations-ms"),
        recommendation_when_available="defer",
        recommendation_reason="JLECmd CSV normalizer already exists and raw JumpList parsing is beta/partial, but raw-tool benchmark and backend wiring are needed before changing the default.",
    ),
    "prefetch": ToolDefinition(
        artifact_type="prefetch",
        tool="PECmd",
        internal_parser="prefetch_raw",
        fixture="pecmd_sample.csv",
        csv_parser=PECmdParser,
        raw_parser=PrefetchRawParser,
        raw_globs=("*.pf",),
        recommendation_when_available="defer",
        recommendation_reason="PECmd output is supported, but native prefetch is stable; raw-tool benchmark is needed before changing default.",
    ),
    "amcache": ToolDefinition(
        artifact_type="amcache",
        tool="AmcacheParser",
        internal_parser="amcache_raw",
        fixture="amcache_sample.csv",
        csv_parser=AmcacheParser,
        raw_parser=AmcacheRawParser,
        raw_globs=("Amcache.hve",),
        recommendation_when_available="defer",
        recommendation_reason="AmcacheParser CSV support exists, but raw hive external execution needs validation before default change.",
    ),
    "shimcache": ToolDefinition(
        artifact_type="shimcache",
        tool="AppCompatCacheParser",
        internal_parser="shimcache_raw",
        fixture="appcompat_sample.csv",
        csv_parser=ShimCacheParser,
        raw_parser=ShimcacheRawParser,
        raw_globs=("SYSTEM",),
        recommendation_when_available="defer",
        recommendation_reason="AppCompatCacheParser likely improves fidelity, but SYSTEM hive scope needs bounded validation.",
    ),
    "registry_selected": ToolDefinition(
        artifact_type="registry_selected",
        tool="RECmd",
        internal_parser="registry_selected_internal",
        fixture="recmd_sample.csv",
        csv_parser=RECmdParser,
        raw_parser=None,
        raw_globs=("NTUSER.DAT", "UsrClass.dat", "SYSTEM", "SOFTWARE"),
        recommendation_when_available="defer",
        recommendation_reason="RECmd CSV is already supported; raw hives need explicit batch-file scoping before default enablement.",
        volume_risk="medium",
    ),
    "mft": ToolDefinition(
        artifact_type="mft",
        tool="MFTECmd",
        internal_parser="mft_internal",
        fixture="mftecmd_mft_sample.csv",
        csv_parser=MFTECmdParser,
        raw_parser=None,
        raw_globs=("$MFT",),
        recommendation_when_available="defer",
        recommendation_reason="MFTECmd CSV is supported, but raw $MFT can generate high volume and should not be default without scope controls.",
        volume_risk="high",
    ),
    "srum": ToolDefinition(
        artifact_type="srum",
        tool="SrumECmd",
        internal_parser="srum_raw",
        fixture="srum_network_usage_sample.csv",
        csv_parser=SrumECmdParser,
        raw_parser=None,
        raw_globs=("SRUDB.dat",),
        recommendation_when_available="defer",
        recommendation_reason="SrumECmd CSV is supported; raw SRUDB.dat indexing should remain scoped/on-demand because it needs external tooling and table-level validation.",
        volume_risk="medium",
    ),
}


def _repo_fixture_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "tests" / "fixtures"


def _eztools_root() -> Path:
    return Path(os.environ.get("EZTOOLS_ROOT") or "/opt/eztools")


def _tool_dll_path(tool: str) -> Path | None:
    if tool == "EvtxECmd":
        env_path = os.environ.get("EVTXECMD_DOTNET_DLL")
        if env_path and Path(env_path).exists():
            return Path(env_path)
        candidates = list(Path("/opt/evtxecmd").glob("**/EvtxECmd.dll"))
        return candidates[0] if candidates else None
    direct = _eztools_root() / tool / f"{tool}.dll"
    if direct.exists():
        return direct
    candidates = list((_eztools_root() / tool).glob(f"**/{tool}.dll")) if (_eztools_root() / tool).exists() else []
    return candidates[0] if candidates else None


def _extract_version(output: str) -> str:
    for line in output.splitlines():
        match = re.search(r"(\d{4}\.\d{1,2}\.\d{1,2}(?:\.\d+)?)", line)
        if match:
            return match.group(1)
    return ""


def _probe_tool(tool: str) -> dict[str, Any]:
    dll = _tool_dll_path(tool)
    if not dll:
        return {
            "available": False,
            "version": "",
            "path": "",
            "supports_csv": tool != "EvtxECmd",
            "supports_json": tool in {"EvtxECmd"},
            "help_works": False,
            "error": "tool_dll_not_found",
            "runs_on_linux": False,
            "requires_windows": False,
            "sample_command_ok": False,
            "recommended_worker": "unavailable",
            "parser_execution_backend": "unavailable",
            "output_format": TOOL_OUTPUT_FORMATS.get(tool, "csv"),
        }
    command = ["/opt/dotnet/dotnet", str(dll), "--version"]
    output = ""
    help_works = False
    error = None
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=12, check=False)
        output = f"{completed.stdout}\n{completed.stderr}".strip()
        help_works = completed.returncode in {0, 1}
    except Exception as exc:  # noqa: BLE001
        error = str(exc)
    if not output:
        try:
            completed = subprocess.run(["/opt/dotnet/dotnet", str(dll), "-h"], capture_output=True, text=True, timeout=12, check=False)
            output = f"{completed.stdout}\n{completed.stderr}".strip()
            help_works = completed.returncode in {0, 1}
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
    requires_windows = tool in WINDOWS_ONLY_TOOLS or "Non-Windows platforms not supported" in output or "Windows libraries" in output
    runs_on_linux = bool(help_works and not requires_windows)
    raw_command_requires_windows = tool in RAW_COMMAND_WINDOWS_ONLY_TOOLS
    recommended_worker = "windows" if requires_windows or raw_command_requires_windows else "linux" if runs_on_linux else "unavailable"
    parser_execution_backend = "windows_worker" if requires_windows or raw_command_requires_windows else "linux_local" if runs_on_linux else "unavailable"
    if requires_windows and not error:
        error = "requires_windows_runtime"
    return {
        "available": True,
        "version": _extract_version(output),
        "path": f"/opt/dotnet/dotnet {dll}",
        "supports_csv": True,
        "supports_json": tool == "EvtxECmd",
        "help_works": help_works,
        "error": error,
        "runs_on_linux": runs_on_linux,
        "requires_windows": requires_windows,
        "raw_command_requires_windows": raw_command_requires_windows,
        "sample_command_ok": runs_on_linux,
        "recommended_worker": recommended_worker,
        "parser_execution_backend": parser_execution_backend,
        "output_format": TOOL_OUTPUT_FORMATS.get(tool, "csv"),
    }


def detect_ez_tools() -> dict[str, dict[str, Any]]:
    tools = list(dict.fromkeys(["EvtxECmd"] + [definition.tool for definition in TOOL_DEFINITIONS.values()] + WINDOWS_WORKER_COMPATIBILITY_TOOLS))
    return {tool: _probe_tool(tool) for tool in tools}


def _compatibility_row(tool: str, status: dict[str, Any]) -> dict[str, Any]:
    available = bool(status.get("available"))
    requires_windows = bool(status.get("requires_windows"))
    raw_command_requires_windows = bool(status.get("raw_command_requires_windows"))
    runs_on_linux = bool(status.get("runs_on_linux"))
    failure_reason = ""
    if not available:
        failure_reason = str(status.get("error") or "tool_not_available")
    elif requires_windows:
        failure_reason = "Requires Windows runtime libraries; keep Linux backend clean and execute via Windows parser worker."
    elif raw_command_requires_windows:
        failure_reason = "Version/help works on Linux, but raw artifact execution requires Windows runtime libraries."
    elif not runs_on_linux:
        failure_reason = str(status.get("error") or "Linux command probe did not succeed")
    return {
        "tool": tool,
        "available": available,
        "runs_on_linux": runs_on_linux,
        "requires_windows": requires_windows,
        "raw_command_requires_windows": raw_command_requires_windows,
        "sample_command_ok": bool(status.get("sample_command_ok")),
        "failure_reason": failure_reason,
        "output_format": status.get("output_format") or TOOL_OUTPUT_FORMATS.get(tool, "csv"),
        "recommended_worker": status.get("recommended_worker") or ("windows" if requires_windows or raw_command_requires_windows else "linux" if runs_on_linux else "unavailable"),
        "parser_execution_backend": status.get("parser_execution_backend") or ("windows_worker" if requires_windows or raw_command_requires_windows else "linux_local" if runs_on_linux else "unavailable"),
        "version": status.get("version") or "",
        "path": status.get("path") or "",
    }


def build_windows_ez_tools_worker_feasibility(tool_status: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    tool_status = tool_status or detect_ez_tools()
    matrix = [_compatibility_row(tool, tool_status.get(tool, {"available": False, "error": "tool_dll_not_found"})) for tool in WINDOWS_WORKER_COMPATIBILITY_TOOLS]
    return {
        "version": 1,
        "compatibility_matrix": matrix,
        "windows_worker_design": {
            "job_model": {
                "parser_execution_backend_values": ["linux_local", "windows_worker", "unavailable"],
                "request": ["case_id", "evidence_id", "artifact_path", "parser_name", "parser_args", "timeout_seconds", "max_output_bytes"],
                "response": ["csv_or_json_outputs", "metadata", "logs", "exit_code", "elapsed_seconds"],
                "linux_pipeline_role": "Normalize returned CSV/JSON and index it; Windows worker only executes Windows-only tooling.",
            },
            "security_model": {
                "low_privilege": True,
                "per_job_workspace": True,
                "timeouts": True,
                "max_output_size": True,
                "path_sanitization": True,
                "audit_log": True,
            },
            "deployment_model": {
                "optional_remote_worker": True,
                "registered_with_token": True,
                "disabled_by_default": True,
                "linux_local_tools_remain_unchanged": True,
            },
        },
        "srum_decision": {
            "recommended_backend": "windows_worker",
            "reason": "SrumECmd is installed, but raw SRUDB.dat parsing requires Windows ESE libraries and fails on Linux. Keep SRUM as tooling_missing until a Windows parser worker is configured.",
        },
        "shellbags_decision": {
            "recommended_backend": "defer",
            "reason": "SBECmd/ShellBagsExplorer are not installed in the Linux image. Keep RECmd-derived user activity where available, then validate SBECmd on Linux or route it through the same Windows worker if it requires Windows.",
        },
    }


def build_core_ez_tools_backend_plan(tool_status: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    tool_status = tool_status or detect_ez_tools()
    artifacts = {}
    for artifact_type, contract in CORE_EZ_COMMAND_CONTRACTS.items():
        definition = TOOL_DEFINITIONS[artifact_type]
        status = tool_status.get(definition.tool, {})
        decision = dict(CORE_EZ_BACKEND_DECISIONS[artifact_type])
        artifacts[artifact_type] = {
            "tool": definition.tool,
            "available": bool(status.get("available")),
            "runs_on_linux": bool(status.get("runs_on_linux")),
            "requires_windows": bool(status.get("requires_windows")),
            "raw_command_requires_windows": bool(status.get("raw_command_requires_windows")),
            "parser_execution_backend": status.get("parser_execution_backend") or "unavailable",
            "version": status.get("version") or "",
            "command_contract": contract,
            "decision": decision["decision"],
            "activation_safe": bool(decision["activation_safe"]),
            "reason": decision["reason"],
            "fallback_backend": "internal",
            "default_changed": False,
        }
    return {"version": 1, "artifacts": artifacts}


def _sample_fields(path: Path, parser_cls: type | None) -> list[str]:
    if not parser_cls or not path.exists():
        return []
    try:
        rows = list(parser_cls().parse(path, case_id="case-sample", evidence_id="evidence-sample", artifact_id="artifact-sample", artifact_meta={"artifact_type": "sample", "parser": "sample", "source_path": str(path)}))
    except TypeError:
        rows = list(parser_cls().parse(path))
    except Exception:  # noqa: BLE001
        return []
    fields: set[str] = set()
    for row in rows[:25]:
        if isinstance(row, dict):
            fields.update(str(key) for key in row.keys())
    return sorted(fields)


def build_parser_backend_inventory(tool_status: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    tool_status = tool_status or detect_ez_tools()
    items = []
    for artifact_type in CORE_ARTIFACT_TYPES:
        definition = TOOL_DEFINITIONS[artifact_type]
        fixture = _repo_fixture_dir() / str(definition.fixture or "")
        registry_entry = get_parser_registry_entry(artifact_type=artifact_type if artifact_type != "registry_selected" else "registry")
        available = bool(tool_status.get(definition.tool, {}).get("available"))
        linux_available = available and not bool(tool_status.get(definition.tool, {}).get("requires_windows")) and not bool(tool_status.get(definition.tool, {}).get("raw_command_requires_windows")) and bool(tool_status.get(definition.tool, {}).get("runs_on_linux", available))
        csv_fields = _sample_fields(fixture, definition.csv_parser)[:80]
        recommendation = definition.recommendation_when_available if linux_available else "windows_worker" if bool(tool_status.get(definition.tool, {}).get("requires_windows")) else "evaluate"
        items.append(
            {
                "artifact_type": artifact_type,
                "current_internal_parser": definition.internal_parser,
                "current_status": registry_entry.get("maturity", "unknown"),
                "searchable_contract_status": "pass" if registry_entry.get("searchable") else "partial",
                "current_fields": list(registry_entry.get("searchable_fields") or []),
                "current_runtime_sample": None,
                "candidate_external_tool": definition.tool,
                "external_tool_available": linux_available,
                "external_tool_installed": available,
                "external_tool_runs_on_linux": bool(tool_status.get(definition.tool, {}).get("runs_on_linux", linux_available)),
                "external_tool_requires_windows": bool(tool_status.get(definition.tool, {}).get("requires_windows")),
                "external_raw_command_requires_windows": bool(tool_status.get(definition.tool, {}).get("raw_command_requires_windows")),
                "parser_execution_backend": tool_status.get(definition.tool, {}).get("parser_execution_backend") or ("linux_local" if linux_available else "unavailable"),
                "recommended_worker": tool_status.get(definition.tool, {}).get("recommended_worker") or ("linux" if linux_available else "unavailable"),
                "external_tool_version": tool_status.get(definition.tool, {}).get("version") or "",
                "existing_csv_or_json_normalizer": bool(definition.csv_parser),
                "external_sample_fields": csv_fields,
                "volume_risk": definition.volume_risk,
                "recommendation": recommendation,
                "recommendation_reason": (
                    "External tool is installed but requires a Windows parser worker on this runtime."
                    if bool(tool_status.get(definition.tool, {}).get("requires_windows"))
                    else definition.recommendation_reason
                    if linux_available
                    else "External tool is not available in this image."
                ),
            }
        )
    return {"version": 1, "items": items}


def _benchmark_csv_parser(definition: ToolDefinition) -> dict[str, Any]:
    fixture = _repo_fixture_dir() / str(definition.fixture or "")
    if not fixture.exists() or not definition.csv_parser:
        return {"status": "insufficient_sample", "files_processed": 0, "records_parsed": 0, "total_seconds": 0, "errors": ["fixture_missing_or_parser_missing"]}
    start = time.perf_counter()
    errors: list[str] = []
    records = 0
    fields: set[str] = set()
    try:
        rows = list(definition.csv_parser().parse(fixture, case_id="case-bench", evidence_id="evidence-bench", artifact_id="artifact-bench", artifact_meta={"artifact_type": definition.artifact_type, "parser": definition.tool.lower(), "source_path": str(fixture)}))
        records = len(rows)
        for row in rows[:50]:
            if isinstance(row, dict):
                fields.update(str(key) for key in row.keys())
    except Exception as exc:  # noqa: BLE001
        errors.append(str(exc))
    elapsed = max(time.perf_counter() - start, 0.0001)
    return {
        "status": "completed" if not errors else "completed_with_errors",
        "files_processed": 1,
        "records_parsed": records,
        "total_seconds": round(elapsed, 4),
        "records_per_second": round(records / elapsed, 2),
        "output_size": fixture.stat().st_size,
        "parser_errors": errors,
        "fields_extracted": sorted(fields)[:120],
        "searchable_contract": "pass" if records else "partial",
        "search_validation": "pass" if records else "partial",
        "timeline_relevance": "pass" if records and definition.artifact_type not in {"registry_selected"} else "partial",
    }


def _benchmark_internal_fixture(definition: ToolDefinition) -> dict[str, Any]:
    if not definition.raw_parser:
        return {"status": "not_applicable", "files_processed": 0, "records_parsed": 0, "total_seconds": 0, "parser_errors": []}
    fixture = _repo_fixture_dir() / str(definition.fixture or "")
    return {
        "status": "not_comparable_fixture",
        "files_processed": 0,
        "records_parsed": 0,
        "total_seconds": 0,
        "parser_errors": [],
        "reason": f"No raw {definition.artifact_type} fixture paired with {fixture.name}; runtime validation should use real evidence samples.",
    }


def build_parser_backend_benchmark() -> dict[str, Any]:
    tool_status = detect_ez_tools()
    benchmark: dict[str, Any] = {}
    for artifact_type in CORE_ARTIFACT_TYPES:
        definition = TOOL_DEFINITIONS[artifact_type]
        benchmark[artifact_type] = {
            "internal": _benchmark_internal_fixture(definition),
            "eztool_csv": _benchmark_csv_parser(definition),
            "eztool_json": {"status": "not_evaluated", "reason": "CSV is the existing normalizer path for these tools."},
            "tool_available": bool(tool_status.get(definition.tool, {}).get("available")),
            "tool_version": tool_status.get(definition.tool, {}).get("version") or "",
        }
    return benchmark


def build_parser_backend_decisions(tool_status: dict[str, dict[str, Any]] | None = None, benchmark: dict[str, Any] | None = None) -> dict[str, Any]:
    tool_status = tool_status or detect_ez_tools()
    benchmark = benchmark or build_parser_backend_benchmark()
    decisions = {}
    for artifact_type in CORE_ARTIFACT_TYPES:
        definition = TOOL_DEFINITIONS[artifact_type]
        available = bool(tool_status.get(definition.tool, {}).get("available"))
        csv_status = str(((benchmark.get(artifact_type) or {}).get("eztool_csv") or {}).get("status") or "")
        decision = definition.recommendation_when_available if available and csv_status.startswith("completed") else "defer"
        if artifact_type in {"lnk", "prefetch"} and available:
            decision = "keep_internal"
        decisions[artifact_type] = {
            "decision": decision,
            "preferred_backend": f"{definition.tool}_csv" if decision == "prefer_external" else "internal",
            "fallback_backend": "internal",
            "reason": definition.recommendation_reason,
            "tool_available": available,
            "csv_normalizer_pass": csv_status.startswith("completed"),
            "default_changed": False,
        }
    return decisions


def build_core_parser_backend_evaluation() -> dict[str, Any]:
    tools = detect_ez_tools()
    benchmark = build_parser_backend_benchmark()
    return {
        "parser_backend_inventory": build_parser_backend_inventory(tools),
        "parser_backend_benchmark": benchmark,
        "parser_backend_decisions": build_parser_backend_decisions(tools, benchmark),
        "windows_ez_tools_worker_feasibility": build_windows_ez_tools_worker_feasibility(tools),
        "core_ez_tools_backend_plan": build_core_ez_tools_backend_plan(tools),
    }
