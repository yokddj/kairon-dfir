from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from app.core.database import SessionLocal
from app.services.memory.upload_sessions import cleanup_memory_upload_staging, reconcile_memory_upload_storage


REQUIRED_OUTPUT_FIELDS = (
    "sessions_inspected",
    "active_sessions_skipped",
    "expired_sessions",
    "orphan_directories",
    "missing_staging",
    "completed_with_staging",
    "bytes_reclaimable",
    "bytes_removed",
    "reconciliation_findings",
    "errors",
)


def _normalise_report(report: dict[str, Any]) -> dict[str, Any]:
    payload = dict(report)
    payload.setdefault("sessions_inspected", payload.get("uploads_inspected", 0))
    payload.setdefault("active_sessions_skipped", payload.get("skipped_active_sessions", 0))
    payload.setdefault("expired_sessions", 0)
    payload.setdefault("orphan_directories", 0)
    payload.setdefault("missing_staging", 0)
    payload.setdefault("completed_with_staging", 0)
    payload.setdefault("bytes_reclaimable", 0)
    payload.setdefault("bytes_removed", 0)
    payload.setdefault("reconciliation_findings", payload.get("findings", []))
    payload.setdefault("errors", [])
    return {field: payload[field] for field in REQUIRED_OUTPUT_FIELDS} | {
        key: value for key, value in payload.items() if key not in REQUIRED_OUTPUT_FIELDS
    }


def _print_report(report: dict[str, Any], *, as_json: bool) -> None:
    payload = _normalise_report(report)
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return
    for field in REQUIRED_OUTPUT_FIELDS:
        print(f"{field}: {payload[field]}")


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Report actions without deleting files (default)")
    mode.add_argument("--apply", action="store_true", help="Apply safe cleanup actions")
    parser.add_argument("--case-id", help="Limit to one case UUID")
    parser.add_argument("--upload-id", help="Limit to one memory upload UUID")
    parser.add_argument("--older-than-hours", type=int, help="Only include sessions/staging older than this many hours")
    parser.add_argument("--batch-size", type=int, default=500, help="Maximum DB sessions/staging candidates to inspect/apply")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")


def cmd_cleanup(args: argparse.Namespace) -> int:
    dry_run = not bool(args.apply)
    db = None
    try:
        db = SessionLocal()
        report = cleanup_memory_upload_staging(
            db,
            dry_run=dry_run,
            case_id=args.case_id,
            upload_id=args.upload_id,
            older_than_hours=args.older_than_hours,
            limit=args.batch_size,
        )
        _print_report(report, as_json=args.json)
        return 1 if report.get("errors") else 0
    except Exception as exc:  # noqa: BLE001
        _print_report({"errors": [str(exc)]}, as_json=args.json)
        return 2
    finally:
        if db is not None:
            db.close()


def cmd_reconcile(args: argparse.Namespace) -> int:
    db = None
    try:
        db = SessionLocal()
        report = reconcile_memory_upload_storage(
            db,
            case_id=args.case_id,
            upload_id=args.upload_id,
            older_than_hours=args.older_than_hours,
            limit=args.batch_size,
        )
        _print_report(report, as_json=args.json)
        return 1 if report.get("errors") else 0
    except Exception as exc:  # noqa: BLE001
        _print_report({"errors": [str(exc)]}, as_json=args.json)
        return 2
    finally:
        if db is not None:
            db.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="memory-upload-maintenance", description="Inspect and safely clean memory upload staging")
    sub = parser.add_subparsers(dest="command", required=True)
    cleanup = sub.add_parser("cleanup", help="Dry-run/apply safe staging cleanup")
    _add_common_options(cleanup)
    cleanup.set_defaults(func=cmd_cleanup)
    reconcile = sub.add_parser("reconcile", help="Classify DB/filesystem upload drift without repair")
    _add_common_options(reconcile)
    reconcile.set_defaults(func=cmd_reconcile)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
