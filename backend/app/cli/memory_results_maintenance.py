"""Memory results maintenance CLI.

Provides safe renormalization of historical completed memory runs
without re-running Volatility.

Usage:

    python -m app.cli.memory_results_maintenance renormalize --run-id <id> --dry-run
    python -m app.cli.memory_results_maintenance renormalize --run-id <id> --apply
    python -m app.cli.memory_results_maintenance renormalize --case-id <id> --dry-run --json
    python -m app.cli.memory_results_maintenance coverage --run-id <id> --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.memory import MemoryArtifactSummary, MemoryPluginRun, MemoryScanRun
from app.services.memory.artifact_normalizers import (
    NORMALIZATION_VERSION,
    normalize_windows_envars,
    normalize_windows_getsids,
    normalize_windows_malfind,
    normalize_windows_netscan,
    normalize_windows_privileges,
    normalize_windows_vadinfo,
)
from app.services.memory.artifact_indexing import count_artifact_documents, index_artifact_documents, link_process_entities
from app.services.memory.execution import ARTIFACT_PLUGIN_NORMALIZER
from app.services.memory.timeline import get_memory_correlations, materialize_timeline


def _load_raw_plugin_output(run: MemoryScanRun, plugin_name: str, output_relative_path: str | None = None) -> Any:
    from app.services.memory.storage import memory_run_dir

    candidates: list[Path] = []
    settings = get_settings()
    if output_relative_path:
        stored = Path(output_relative_path)
        if stored.is_absolute():
            candidates.append(stored)
        else:
            candidates.append(settings.backend_data_dir / stored)
            if str(stored).startswith("memory-output/") and settings.memory_output_root:
                candidates.append(settings.memory_output_root / Path(str(stored)[len("memory-output/"):]))
    output_path = next((path for path in candidates if path.exists()), None)
    if output_path is None:
        fallback = memory_run_dir(run.case_id, run.evidence_id, run.id) / f"{plugin_name}.json"
        if fallback.exists():
            output_path = fallback
    if output_path is None:
        return None
    with open(output_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def renormalize_command(db, args: argparse.Namespace) -> int:
    dry_run = not args.apply
    run_id = args.run_id
    case_id = args.case_id
    evidence_id = args.evidence_id
    profile = args.profile

    query = db.query(MemoryScanRun).filter(
        MemoryScanRun.status.in_(["completed", "succeeded"]),
    )
    if run_id:
        query = query.filter(MemoryScanRun.id == run_id)
    if case_id:
        query = query.filter(MemoryScanRun.case_id == case_id)
    if evidence_id:
        query = query.filter(MemoryScanRun.evidence_id == evidence_id)
    if profile:
        query = query.filter(MemoryScanRun.profile == profile)

    runs = query.order_by(MemoryScanRun.completed_at.desc()).limit(args.batch_size or 10).all()

    report: dict[str, Any] = {
        "dry_run": dry_run,
        "runs_considered": len(runs),
        "runs_renormalized": 0,
        "artifacts_renormalized": 0,
        "artifacts_skipped": 0,
        "rows_accepted": 0,
        "rows_dropped": 0,
        "errors": [],
    }

    for run in runs:
        run_report = _renormalize_run(db, run, dry_run)
        if run_report.get("error"):
            report["errors"].append(run_report["error"])
            continue
        report["runs_renormalized"] += 1
        report["artifacts_renormalized"] += run_report.get("artifacts_renormalized", 0)
        report["artifacts_skipped"] += run_report.get("artifacts_skipped", 0)
        report["rows_accepted"] += run_report.get("rows_accepted", 0)
        report["rows_dropped"] += run_report.get("rows_dropped", 0)

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"Runs considered: {report['runs_considered']}")
        print(f"Runs renormalized: {report['runs_renormalized']}")
        print(f"Artifacts renormalized: {report['artifacts_renormalized']}")
        print(f"Artifacts skipped: {report['artifacts_skipped']}")
        print(f"Rows accepted: {report['rows_accepted']}")
        print(f"Rows dropped: {report['rows_dropped']}")
        if dry_run:
            print("(dry-run: no changes applied)")
        if report["errors"]:
            print(f"Errors: {len(report['errors'])}")
            for err in report["errors"][:5]:
                print(f"  - {str(err)[:200]}")

    return 0


_RENORMALIZABLE_PLUGINS = {
    "windows.envars": normalize_windows_envars,
    "windows.getsids": normalize_windows_getsids,
    "windows.privileges": normalize_windows_privileges,
    "windows.netscan": normalize_windows_netscan,
    "windows.netstat": normalize_windows_netscan,
    "windows.malfind": normalize_windows_malfind,
    "windows.vadinfo": normalize_windows_vadinfo,
}


def _renormalize_run(db, run: MemoryScanRun, dry_run: bool) -> dict[str, Any]:
    report: dict[str, Any] = {
        "run_id": run.id,
        "profile": run.profile,
        "artifacts_renormalized": 0,
        "artifacts_skipped": 0,
        "rows_accepted": 0,
        "rows_dropped": 0,
        "error": None,
    }
    try:
        summary_counts: dict[str, int] = {}
        summary_plugins: dict[str, list[str]] = {}
        summary_warnings: dict[str, list[str]] = {}
        plugin_runs = db.query(MemoryPluginRun).filter(
            MemoryPluginRun.memory_scan_run_id == run.id,
            MemoryPluginRun.status == "completed",
        ).all()
        for plugin_run in plugin_runs:
            if plugin_run.plugin not in _RENORMALIZABLE_PLUGINS:
                report["artifacts_skipped"] += 1
                continue
            raw = _load_raw_plugin_output(run, plugin_run.plugin, plugin_run.output_relative_path)
            if raw is None:
                report["artifacts_skipped"] += 1
                continue
            normalizer = _RENORMALIZABLE_PLUGINS[plugin_run.plugin]
            source_plugin = plugin_run.plugin
            result = normalizer(
                raw,
                case_id=run.case_id,
                evidence_id=run.evidence_id,
                scan_run_id=run.id,
                plugin_run_id=plugin_run.id,
                source_plugin=source_plugin,
            )
            report["rows_accepted"] += result.get("accepted_count", 0)
            report["rows_dropped"] += result.get("dropped_count", 0)
            report["artifacts_renormalized"] += 1
            doc_type = ARTIFACT_PLUGIN_NORMALIZER.get(source_plugin)
            if doc_type:
                summary_counts[doc_type] = summary_counts.get(doc_type, 0) + int(result.get("accepted_count", 0))
                summary_plugins.setdefault(doc_type, []).append(source_plugin)
                summary_warnings.setdefault(doc_type, []).extend(result.get("warnings", [])[:20])
            if not dry_run and result.get("items"):
                try:
                    indexing = index_artifact_documents(run.case_id, result["items"])
                except Exception as exc:
                    report["error"] = f"Indexing failed for {plugin_run.plugin}: {exc}"
                    return report
                if int(indexing.get("errors", 0) or 0) > 0:
                    report["error"] = f"Indexing failed for {plugin_run.plugin}: {indexing.get('errors')} document errors"
                    return report
                plugin_run.metadata_json = {
                    **(plugin_run.metadata_json or {}),
                    "renormalized_at_normalization_version": result.get("normalization_version", NORMALIZATION_VERSION),
                    "renormalized_accepted_count": result.get("accepted_count", 0),
                    "renormalized_dropped_count": result.get("dropped_count", 0),
                }
                db.add(plugin_run)
                db.commit()
        if not dry_run:
            for doc_type, count in summary_counts.items():
                try:
                    count = count_artifact_documents(run.case_id, document_type=doc_type, run_id=run.id)
                except Exception:  # noqa: BLE001
                    pass
                _upsert_summary(
                    db,
                    run,
                    doc_type,
                    count,
                    {
                        "profile": run.profile,
                        "plugins": summary_plugins.get(doc_type, []),
                        "warnings": summary_warnings.get(doc_type, [])[:20],
                        "normalization_version": NORMALIZATION_VERSION,
                        "renormalized": True,
                    },
                )
                try:
                    link_process_entities(run.case_id, scan_run_id=run.id, document_type=doc_type)
                except Exception as exc:  # noqa: BLE001
                    report["error"] = f"Process linking failed for {doc_type}: {exc}"
                    return report
            db.commit()
    except Exception as exc:
        db.rollback()
        report["error"] = str(exc)
    return report


def _upsert_summary(db, run: MemoryScanRun, artifact_type: str, count: int, metadata: dict[str, Any]) -> None:
    summaries = (
        db.query(MemoryArtifactSummary)
        .filter(MemoryArtifactSummary.memory_run_id == run.id, MemoryArtifactSummary.memory_artifact_type == artifact_type)
        .all()
    )
    if not summaries:
        summary = MemoryArtifactSummary(case_id=run.case_id, evidence_id=run.evidence_id, memory_run_id=run.id, memory_artifact_type=artifact_type, count=count, metadata_json=metadata)
        db.add(summary)
    else:
        for summary in summaries:
            summary.count = count
            summary.metadata_json = metadata


def coverage_command(db, args: argparse.Namespace) -> int:
    run_id = args.run_id
    if not run_id:
        print("--run-id is required for coverage report", file=sys.stderr)
        return 1

    run = db.query(MemoryScanRun).filter(MemoryScanRun.id == run_id).first()
    if not run:
        print(f"Run not found: {run_id}", file=sys.stderr)
        return 1

    plugin_runs = db.query(MemoryPluginRun).filter(
        MemoryPluginRun.memory_scan_run_id == run_id,
    ).all()

    coverage: dict[str, Any] = {
        "run_id": run.id,
        "profile": run.profile,
        "status": run.status,
        "evidence_id": run.evidence_id,
        "plugins_expected": [],
        "plugins_completed": [],
        "plugins_with_rows": [],
        "plugins_with_zero_rows": [],
        "plugins_failed": [],
        "normalized_artifact_counts": {},
        "raw_only_plugins": [],
    }

    for pr in plugin_runs:
        coverage["plugins_expected"].append(pr.plugin)
        if pr.status == "completed":
            coverage["plugins_completed"].append(pr.plugin)
            if pr.row_count and pr.row_count > 0:
                coverage["plugins_with_rows"].append(pr.plugin)
            else:
                coverage["plugins_with_zero_rows"].append(pr.plugin)
            meta = pr.metadata_json or {}
            ntype = meta.get("normalized_type")
            if ntype:
                count = meta.get("accepted_count", 0)
                coverage["normalized_artifact_counts"][pr.plugin] = {
                    "type": ntype,
                    "accepted": count,
                    "dropped": meta.get("dropped_count", 0),
                    "raw_retained": meta.get("raw_output_retained", False),
                }
            else:
                coverage["raw_only_plugins"].append(pr.plugin)
        else:
            coverage["plugins_failed"].append(pr.plugin)

    if args.json:
        print(json.dumps(coverage, indent=2, default=str))
    else:
        print(f"Run: {run.id} (profile={run.profile}, status={run.status})")
        print(f"Plugins expected: {len(coverage['plugins_expected'])}")
        print(f"Plugins completed: {len(coverage['plugins_completed'])}")
        print(f"Plugins with rows: {len(coverage['plugins_with_rows'])}")
        print(f"Plugins with zero rows: {len(coverage['plugins_with_zero_rows'])}")
        print(f"Plugins failed: {len(coverage['plugins_failed'])}")
        print(f"Normalized artifact counts: {json.dumps(coverage['normalized_artifact_counts'], indent=2, default=str)}")

    return 0


def timeline_build_command(db, args: argparse.Namespace) -> int:
    report = materialize_timeline(
        db,
        case_id=args.case_id,
        evidence_id=args.evidence_id,
        memory_run_id=args.memory_run_id,
        apply=bool(args.apply),
        batch_size=args.batch_size,
        confidence_min=args.confidence_min,
    )
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"Dry run: {report['dry_run']}")
        print(f"Timeline events: {report['timeline_events']}")
        print(f"Correlations: {report['correlations']}")
        print(f"Would create/update: {report['would_create_or_update']}")
        print(f"Created/updated: {report['created_or_updated']}")
        print(f"Rejected candidates: {report['rejected']}")
    return 0


def correlate_command(db, args: argparse.Namespace) -> int:
    payload = get_memory_correlations(
        db,
        case_id=args.case_id,
        evidence_id=args.evidence_id,
        process_entity_id=args.process_entity_id,
        correlation_type=args.correlation_type,
        confidence=args.confidence_min,
        artifact_type=args.artifact_family,
        page=1,
        page_size=args.batch_size,
    )
    report = {
        "dry_run": not args.apply,
        "case_id": args.case_id,
        "evidence_id": args.evidence_id,
        "correlations": payload.get("total", 0),
        "returned": len(payload.get("items", [])),
        "created_or_updated": 0,
        "would_create_or_update": payload.get("total", 0),
        "rejected": payload.get("coverage", {}).get("rejected_correlation_candidates", 0),
        "rule_versions": payload.get("coverage", {}).get("correlation_rule_versions", []),
    }
    if args.apply:
        materialized = materialize_timeline(db, case_id=args.case_id, evidence_id=args.evidence_id, memory_run_id=args.memory_run_id, apply=True, batch_size=args.batch_size, confidence_min=args.confidence_min)
        report["created_or_updated"] = materialized.get("created_or_updated", 0)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"Dry run: {report['dry_run']}")
        print(f"Correlations: {report['correlations']}")
        print(f"Would create/update: {report['would_create_or_update']}")
        print(f"Created/updated: {report['created_or_updated']}")
        print(f"Rejected candidates: {report['rejected']}")
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Memory results maintenance")
    sub = parser.add_subparsers(dest="command", required=True)

    ren = sub.add_parser("renormalize", help="Renormalize existing completed memory runs")
    ren.add_argument("--run-id")
    ren.add_argument("--case-id")
    ren.add_argument("--evidence-id")
    ren.add_argument("--profile")
    ren.add_argument("--dry-run", action="store_true", default=True)
    ren.add_argument("--apply", action="store_true")
    ren.add_argument("--json", action="store_true")
    ren.add_argument("--batch-size", type=int, default=10)

    cov = sub.add_parser("coverage", help="Report coverage for a memory run")
    cov.add_argument("--run-id", required=True)
    cov.add_argument("--json", action="store_true")

    tl = sub.add_parser("timeline-build", help="Build scoped derived memory timeline/correlation documents")
    tl.add_argument("--case-id", required=True)
    tl.add_argument("--evidence-id", required=True)
    tl.add_argument("--memory-run-id")
    tl.add_argument("--artifact-family")
    tl.add_argument("--confidence-min")
    tl.add_argument("--dry-run", action="store_true", default=True)
    tl.add_argument("--apply", action="store_true")
    tl.add_argument("--json", action="store_true")
    tl.add_argument("--batch-size", type=int, default=500)

    corr = sub.add_parser("correlate", help="Report or materialize scoped deterministic correlations")
    corr.add_argument("--case-id", required=True)
    corr.add_argument("--evidence-id", required=True)
    corr.add_argument("--memory-run-id")
    corr.add_argument("--process-entity-id")
    corr.add_argument("--correlation-type")
    corr.add_argument("--artifact-family")
    corr.add_argument("--confidence-min")
    corr.add_argument("--dry-run", action="store_true", default=True)
    corr.add_argument("--apply", action="store_true")
    corr.add_argument("--json", action="store_true")
    corr.add_argument("--batch-size", type=int, default=500)

    args = parser.parse_args(argv)
    db = SessionLocal()
    try:
        if args.command == "renormalize":
            sys.exit(renormalize_command(db, args))
        elif args.command == "coverage":
            sys.exit(coverage_command(db, args))
        elif args.command == "timeline-build":
            sys.exit(timeline_build_command(db, args))
        elif args.command == "correlate":
            sys.exit(correlate_command(db, args))
    finally:
        db.close()


if __name__ == "__main__":
    main()
