"""Operator CLI to reindex completed memory process runs from raw output.

Usage:

    # Dry-run (read only, no OpenSearch mutations):
    docker compose exec backend python -m app.cli.memory_reindex \\
        --run-id e15315f5-12cd-4501-881e-2949a4844875 \\
        --dry-run

    # Apply (normalize and reindex):
    docker compose exec backend python -m app.cli.memory_reindex \\
        --run-id e15315f5-12cd-4501-881e-2949a4844875 \\
        --apply

    # Full help:
    docker compose exec backend python -m app.cli.memory_reindex --help
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any

from app.core.database import SessionLocal
from app.services.memory.execution import reindex_completed_process_run_from_raw
from app.services.memory.indexing import index_memory_documents, sanitize_memory_process_document
from app.services.memory.normalizers import (
    merge_memory_process_results,
    normalize_windows_pslist,
    normalize_windows_pstree,
    normalize_windows_cmdline,
)


logger = logging.getLogger(__name__)

PLUGIN_NORMALIZERS: dict[str, Any] = {
    "windows.pslist": normalize_windows_pslist,
    "windows.pstree": normalize_windows_pstree,
    "windows.cmdline": normalize_windows_cmdline,
}


def _read_raw_output(output_relative_path: str) -> list[dict[str, Any]] | None:
    from pathlib import Path

    from app.core.config import get_settings

    path = Path(output_relative_path)
    if not path.is_absolute():
        settings = get_settings()
        candidates = [settings.backend_data_dir / path]
        if str(path).startswith("memory-output/") and settings.memory_output_root:
            candidates.append(settings.memory_output_root / Path(str(path)[len("memory-output/"):]))
        for candidate in candidates:
            if candidate.is_file():
                path = candidate
                break
    if not path.is_file():
        return None
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _dry_run_analysis(db: Any, run_id: str) -> dict[str, Any]:
    """Analyze what would happen during reindex without mutating anything."""
    from app.models.memory import MemoryPluginRun, MemoryScanRun

    run = db.get(MemoryScanRun, run_id)
    if run is None:
        return {"status": "error", "reason": "run_not_found"}
    if run.status not in {"completed", "completed_with_errors"}:
        return {"status": "error", "reason": "run_not_terminal", "current_status": run.status}

    plugin_runs = (
        db.query(MemoryPluginRun)
        .filter(
            MemoryPluginRun.memory_scan_run_id == run.id,
            MemoryPluginRun.plugin.in_({"windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline"}),
            MemoryPluginRun.status == "completed",
        )
        .all()
    )

    raw_info: list[dict[str, Any]] = []
    all_rows: list[dict[str, Any]] = []
    invalid_pids: list[dict[str, Any]] = []
    for pr in plugin_runs:
        raw = _read_raw_output(pr.output_relative_path) if pr.output_relative_path else None
        raw_info.append({
            "plugin": pr.plugin,
            "output_relative_path": pr.output_relative_path,
            "raw_exists": raw is not None,
            "row_count": len(raw) if isinstance(raw, list) else 0,
        })
        if isinstance(raw, list):
            for row in raw:
                pid_val = row.get("PID") or row.get("Pid") or row.get("pid")
                ppid_val = row.get("PPID") or row.get("PPid") or row.get("ParentPID")
                from app.services.memory.pids import normalize_pid
                norm_pid = normalize_pid(pid_val)
                norm_ppid = normalize_pid(ppid_val)
                if norm_pid is None and pid_val is not None:
                    invalid_pids.append({"plugin": pr.plugin, "pid_raw": str(pid_val)[:200], "ppid_raw": str(ppid_val)[:200] if ppid_val is not None else None, "image": (row.get("ImageFileName") or row.get("Name") or "")[:200], "reason": "pid_out_of_range_or_invalid"})
                if norm_ppid is None and ppid_val is not None:
                    if not any(p["pid_raw"] == str(pid_val)[:200] for p in invalid_pids):
                        invalid_pids.append({"plugin": pr.plugin, "pid_raw": str(pid_val)[:200], "ppid_raw": str(ppid_val)[:200] if ppid_val is not None else None, "image": (row.get("ImageFileName") or row.get("Name") or "")[:200], "reason": "ppid_out_of_range_or_invalid"})
                all_rows.append({"plugin": pr.plugin, "pid": pid_val, "ppid": ppid_val, "normalized_pid": norm_pid, "normalized_ppid": norm_ppid, "image": row.get("ImageFileName") or row.get("Name") or ""})

    excluded_rows = [r for r in all_rows if r["normalized_pid"] is None]
    included_rows = [r for r in all_rows if r["normalized_pid"] is not None]

    return {
        "status": "ok",
        "run_id": run_id,
        "run_profile": run.profile,
        "run_status": run.status,
        "plugin_runs": raw_info,
        "total_raw_rows": len(all_rows),
        "rows_with_valid_pid": len(included_rows),
        "rows_with_invalid_pid": len(excluded_rows),
        "invalid_pids": invalid_pids,
        "volatility_rerun": False,
    }


def _simulate_reindex_documents(db: Any, run_id: str) -> dict[str, Any]:
    """Simulate the full reindex pipeline in memory to show what documents
    would be produced and their normalized shapes."""
    from app.models.memory import MemoryPluginRun, MemoryScanRun

    run = db.get(MemoryScanRun, run_id)
    if run is None:
        return {"status": "error", "reason": "run_not_found"}

    plugin_runs = (
        db.query(MemoryPluginRun)
        .filter(
            MemoryPluginRun.memory_scan_run_id == run.id,
            MemoryPluginRun.plugin.in_({"windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline"}),
            MemoryPluginRun.status == "completed",
        )
        .all()
    )

    process_results: list[dict[str, Any]] = []
    missing: list[str] = []
    for pr in plugin_runs:
        normalizer = PLUGIN_NORMALIZERS.get(pr.plugin)
        if normalizer is None:
            missing.append(pr.plugin)
            continue
        raw = _read_raw_output(pr.output_relative_path) if pr.output_relative_path else None
        if raw is None:
            missing.append(pr.plugin)
            continue
        process_results.append(normalizer(raw))

    if not process_results:
        return {"status": "error", "reason": "no_process_results", "missing_plugins": missing}

    merged = merge_memory_process_results(
        process_results, case_id=run.case_id, evidence_id=run.evidence_id, memory_run_id=run.id
    )

    # Sanitize documents in memory to show final shapes
    sanitized_docs = [sanitize_memory_process_document(doc) for doc in merged["processes"]]
    sanitized_edges = [sanitize_memory_process_document(doc) for doc in merged["edges"]]

    # Validate PID fields
    pid_errors = []
    for doc in sanitized_docs:
        proc = doc.get("process", {})
        for field in ("pid", "ppid"):
            val = proc.get(field)
            if val is not None and not isinstance(val, int):
                pid_errors.append({"document_id": doc.get("document_id"), "field": f"process.{field}", "value": val, "type": type(val).__name__})

    return {
        "status": "ok",
        "run_id": run_id,
        "volatility_rerun": False,
        "processes": len(merged["processes"]),
        "edges": len(merged["edges"]),
        "document_count": len(sanitized_docs) + len(sanitized_edges),
        "document_ids": [doc.get("document_id") for doc in sanitized_docs[:20]],
        "pid_validation_errors": pid_errors,
        "warnings": merged["warnings"],
        "missing_plugins": missing,
        "sample_document": sanitized_docs[0] if sanitized_docs else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Reindex completed memory process runs from raw output")
    parser.add_argument("--run-id", required=True, help="MemoryScanRun UUID")
    parser.add_argument("--dry-run", action="store_true", help="Analyze without mutating OpenSearch or DB")
    parser.add_argument("--apply", action="store_true", help="Normalize and reindex into OpenSearch")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")

    db = SessionLocal()
    try:
        if args.dry_run:
            analysis = _dry_run_analysis(db, args.run_id)
            print(json.dumps(analysis, indent=2, default=str))

            if analysis.get("total_raw_rows", 0) > 0:
                sim = _simulate_reindex_documents(db, args.run_id)
                print("\n--- Document simulation ---")
                print(json.dumps(sim, indent=2, default=str))
            return

        if args.apply:
            result = reindex_completed_process_run_from_raw(db, args.run_id)
            print(json.dumps(result, indent=2, default=str))
            return

        parser.print_help()
    finally:
        db.close()


if __name__ == "__main__":
    main()
