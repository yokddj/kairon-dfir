"""Local-operator CLI for memory symbol acquisition.

This CLI is intended to be executed on the deployment host by an
authorized server operator:

    docker compose exec backend python -m app.cli.memory_symbols list-pending
    docker compose exec backend python -m app.cli.memory_symbols show --request-id <id>
    docker compose exec backend python -m app.cli.memory_symbols approve --request-id <id>
    docker compose exec backend python -m app.cli.memory_symbols revoke --request-id <id>
    docker compose exec backend python -m app.cli.memory_symbols status --request-id <id>

The CLI is a thin wrapper over the service layer.  It does NOT accept
custom URLs, hosts, PDB/GUID/age, or cache paths: the exact symbol
identity always comes from the stored trusted requirement.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

from app.core.database import SessionLocal
from app.services.memory.symbol_approval import (
    ApprovalError,
    approve_request,
    list_pending_requests,
    revoke_approval,
    show_request,
    summarize_pending_for_operator,
)


def _print_json(data) -> None:
    print(json.dumps(data, indent=2, default=str, sort_keys=True))


def _format_timestamp(value) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")
    return str(value)


def cmd_list_pending(_args: argparse.Namespace) -> int:
    with SessionLocal() as db:
        items = list_pending_requests(db)
    if not items:
        print("No symbol acquisition requests are awaiting operator action.")
        return 0
    print(f"{'request_id':<38} {'status':<32} {'case_id':<38} {'symbol'}")
    print("-" * 130)
    for item in items:
        symbol = f"{item['pdb_name']}/{item['pdb_guid']}-{item['pdb_age']} ({item['architecture']})"
        print(f"{item['request_id']:<38} {item['status']:<32} {item['case_id']:<38} {symbol}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    with SessionLocal() as db:
        data = show_request(db, args.request_id)
    request = data["request"]
    requirement = data["requirement"]
    approval = data["approval"]
    print("== Symbol acquisition request ==")
    print(f"  request_id        : {request['id']}")
    print(f"  status            : {request['status']}")
    print(f"  case_id           : {request['case_id']}")
    print(f"  evidence_id       : {request['evidence_id']}")
    print(f"  source_category   : {request['source_category']}")
    print(f"  fingerprint       : {request['requirement_fingerprint']}")
    print(f"  created_at        : {_format_timestamp(request['created_at'])}")
    print(f"  updated_at        : {_format_timestamp(request['updated_at'])}")
    print(f"  approved_at       : {_format_timestamp(request['approved_at'])}")
    print(f"  approval_expires  : {_format_timestamp(request['approval_expires_at'])}")
    print(f"  approval_consumed : {_format_timestamp(request['approval_consumed_at'])}")
    print(f"  queued_at         : {_format_timestamp(request['queued_at'])}")
    print(f"  completed_at      : {_format_timestamp(request['completed_at'])}")
    print(f"  error_code        : {request['error_code']}")
    print(f"  sanitized_message : {request['sanitized_message']}")
    if requirement is not None:
        print("== Required symbol (trusted) ==")
        print(f"  pdb_name    : {requirement['pdb_name']}")
        print(f"  pdb_guid    : {requirement['pdb_guid']}")
        print(f"  pdb_age     : {requirement['pdb_age']}")
        print(f"  architecture: {requirement['architecture']}")
    if approval is not None:
        print("== Active/recorded approval ==")
        print(f"  approval_id   : {approval['id']}")
        print(f"  status        : {approval['status']}")
        print(f"  actor_category: {approval['actor_category']}")
        print(f"  actor_label   : {approval['actor_label']}")
        print(f"  expires_at    : {_format_timestamp(approval['expires_at'])}")
        print(f"  consumed_at   : {_format_timestamp(approval['consumed_at'])}")
        print(f"  revoked_at    : {_format_timestamp(approval['revoked_at'])}")
    return 0


def cmd_summarize(args: argparse.Namespace) -> int:
    """Print the sanitized summary shown before approval.

    Intended for confirmation prompts.  Never includes evidence bytes,
    paths, or user-supplied data.
    """
    with SessionLocal() as db:
        summary = summarize_pending_for_operator(db, args.request_id)
    _print_json(summary)
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    with SessionLocal() as db:
        if args.summary or not args.yes:
            summary = summarize_pending_for_operator(db, args.request_id)
            print("== Pending symbol acquisition (sanitized) ==")
            _print_json(summary)
            if not args.yes:
                print("")
                print("This approval is local-operator authorization for the server only.")
                print("It is not a replacement for application RBAC.")
                print("")
                resp = input("Type 'approve' to confirm, or Ctrl+C to abort: ").strip()
                if resp != "approve":
                    print("Aborted.")
                    return 1
        try:
            approval = approve_request(
                db,
                request_id=args.request_id,
                actor_label=args.actor,
                confirm=True,
                yes=args.yes,
            )
            # Capture scalar values while the session is still open to
            # avoid DetachedInstanceError when printing after commit.
            approval_snapshot = {
                "id": str(approval.id),
                "status": str(approval.status),
                "expires_at": approval.expires_at,
            }
        except ApprovalError as exc:
            print(f"ERROR: {exc.code}: {exc.message}", file=sys.stderr)
            return 2
    print(f"approval_id = {approval_snapshot['id']}")
    print(f"status      = {approval_snapshot['status']}")
    print(f"expires_at  = {_format_timestamp(approval_snapshot['expires_at'])}")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    with SessionLocal() as db:
        try:
            approval = revoke_approval(db, request_id=args.request_id)
        except ApprovalError as exc:
            print(f"ERROR: {exc.code}: {exc.message}", file=sys.stderr)
            return 2
    print(f"approval_id = {approval.id}")
    print(f"status      = {approval.status}")
    print(f"revoked_at  = {_format_timestamp(approval.revoked_at)}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    return cmd_show(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.cli.memory_symbols",
        description="Kairon local-operator CLI for Windows symbol acquisition.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list-pending", help="List requests awaiting operator action.")
    p_list.set_defaults(func=cmd_list_pending)

    p_show = sub.add_parser("show", help="Show full state of a request.")
    p_show.add_argument("--request-id", required=True)
    p_show.set_defaults(func=cmd_show)

    p_summary = sub.add_parser("summarize", help="Show the sanitized summary of a request.")
    p_summary.add_argument("--request-id", required=True)
    p_summary.set_defaults(func=cmd_summarize)

    p_approve = sub.add_parser("approve", help="Approve a pending request (requires explicit confirmation).")
    p_approve.add_argument("--request-id", required=True)
    p_approve.add_argument("--actor", default="server-operator", help="Operator label recorded in the audit metadata.")
    p_approve.add_argument("--yes", action="store_true", help="Skip the interactive confirmation prompt.")
    p_approve.add_argument("--summary", action="store_true", help="Print the sanitized summary before approval.")
    p_approve.set_defaults(func=cmd_approve)

    p_revoke = sub.add_parser("revoke", help="Revoke a pending or approved-but-not-queued approval.")
    p_revoke.add_argument("--request-id", required=True)
    p_revoke.set_defaults(func=cmd_revoke)

    p_status = sub.add_parser("status", help="Alias for show.")
    p_status.add_argument("--request-id", required=True)
    p_status.set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
