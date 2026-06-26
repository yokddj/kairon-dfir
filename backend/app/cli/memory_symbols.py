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

Operator-only exact symbol import (no HTTP route):

    docker compose exec backend python -m app.cli.memory_symbols inspect-pdb \\
        --file /path/to/ntkrnlmp.pdb
    docker compose exec backend python -m app.cli.memory_symbols inspect-isf \\
        --file /path/to/isf.json
    docker compose exec backend python -m app.cli.memory_symbols import-pdb \\
        --requirement-id <UUID> \\
        --file /path/to/ntkrnlmp.pdb \\
        --operator "ops@example.com"
    docker compose exec backend python -m app.cli.memory_symbols import-isf \\
        --requirement-id <UUID> \\
        --file /path/to/isf.json \\
        --operator "ops@example.com"
    docker compose exec backend python -m app.cli.memory_symbols status \\
        --requirement-id <UUID>

The import commands REUSE the canonical recovery, validation,
cache, provenance, fan-out, and preparation services.  No second
symbol import implementation is created.  The import commands are
INDEPENDENT of the ``MEMORY_SYMBOL_ADMIN_RECOVERY_ENABLED`` and
``MEMORY_SYMBOL_MANUAL_IMPORT_ENABLED`` feature flags; they are
a trusted-maintenance entry point that is only invokable from
inside the backend container.  No HTTP route mounts these
subcommands.
"""
from __future__ import annotations

import argparse
import json
import secrets
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
from app.services.memory.experimental_lifecycle import (
    ExperimentalLifecycleError,
    record_cli_candidate,
    trust_state,
)
from app.services.memory.experimental_import import (
    ExperimentalImportError,
    cli_import_experimental_isf_for_requirement,
    cli_import_experimental_pdb_for_requirement,
    inspect_experimental_pdb_for_requirement,
)
from app.services.memory.experimental_trust import is_experimental_enabled


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


def cmd_backfill(args: argparse.Namespace) -> int:
    """Reconstruct missing symbol requirements from history.

    The function is read-only with respect to Volatility: it only
    walks the database, the OpenSearch index for ``memory_system_info``
    documents, and the existing ``MemoryCachedSymbol`` rows.  It
    persists a new ``MemorySymbolRequirement`` row for each
    evidence where the requirement can be reconstructed and no row
    already exists.  When the exact identifier is in the cache, the
    row is recorded as ``status=cached``; otherwise as
    ``status=unavailable_offline`` so the UI can offer the
    acquisition flow.
    """
    from app.services.memory.symbol_backfill import backfill_memory_symbol_readiness

    with SessionLocal() as db:
        stats = backfill_memory_symbol_readiness(
            db,
            case_id=args.case_id,
            evidence_id=args.evidence_id,
        )
    _print_json(stats.to_dict())
    return 0


# ---------------------------------------------------------------------------
# Operator-only exact symbol import (no HTTP route)
# ---------------------------------------------------------------------------


def _cli_print_result(result: dict, *, as_json: bool) -> int:
    """Print a CLI import result.

    Returns 0 on terminal ``ready`` / ``dry_run`` / ``not_implemented``,
    2 on any other terminal state (so shell scripts can branch on
    the exit code).
    """
    if as_json:
        _print_json(result)
    else:
        # Human-readable line-oriented output.  The status is the
        # first line; the rest are the canonical fields.  No
        # internal filesystem paths or secrets are emitted.
        status = result.get("status")
        print(f"status           : {status}")
        rid = result.get("requirement_id") or result.get("requirement", {}).get("id")
        if rid:
            print(f"requirement_id   : {rid}")
        ec = result.get("error_code")
        if ec:
            print(f"error_code       : {ec}")
        sm = result.get("sanitized_message")
        if sm:
            print(f"sanitized_message: {sm}")
        sha = result.get("sha256")
        if sha:
            print(f"sha256           : {sha}")
        sz = result.get("size_bytes")
        if sz is not None:
            print(f"size_bytes       : {sz}")
        cid = result.get("cached_symbol_id")
        if cid:
            print(f"cached_symbol_id : {cid}")
        ijob = result.get("import_job_id")
        if ijob:
            print(f"import_job_id    : {ijob}")
        obs = result.get("identity_observed") or {}
        if obs:
            obs_guid = obs.get("pdb_guid") or obs.get("expected_pdb_guid")
            obs_age = obs.get("pdb_age")
            if obs_guid is not None:
                print(f"observed_guid    : {obs_guid}")
            if obs_age is not None:
                print(f"observed_age     : {obs_age}")
    if result.get("status") in {"ready", "dry_run", "not_implemented"}:
        return 0
    return 2


def cmd_inspect_pdb(args: argparse.Namespace) -> int:
    """Inspect a PDB file: SHA-256, identity, size, architecture.

    No database writes, no cache promotion, no conversion.
    Returns non-zero on invalid PDB.
    """
    from pathlib import Path
    from app.cli.memory_symbols_runtime import (
        InputFileError,
        validate_input_file,
    )
    from app.services.memory.symbol_fetcher import read_pdb_identity

    raw_path = Path(args.file)
    try:
        info = validate_input_file(
            raw_path,
            allowed_extensions={".pdb"},
            safe_override=args.safe_override,
        )
    except InputFileError as exc:
        if args.json:
            _print_json({"status": "invalid", "error": str(exc)})
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    observed: dict = {}
    read_error: str | None = None
    try:
        guid, age = read_pdb_identity(Path(info["resolved_path"]))
    except Exception as exc:  # SymbolFetchError or OSError
        read_error = type(exc).__name__
        if hasattr(exc, "code"):
            read_error = f"{exc.code}"
        observed = {"pdb_name": Path(info["resolved_path"]).name, "read_error": read_error}
    else:
        observed = {
            "pdb_guid": guid.upper(),
            "pdb_age": int(age),
            "pdb_name": Path(info["resolved_path"]).name,
        }
    payload = {
        "status": "ok" if read_error is None else "invalid",
        "file": info["original_filename"],
        "size_bytes": info["size_bytes"],
        "sha256": info["sha256"],
        "mode": info["mode"],
        "pdb_identity": observed,
    }
    if args.json:
        _print_json(payload)
    else:
        if read_error is not None:
            print(f"status     : invalid ({read_error})")
        else:
            print("status     : ok")
        print(f"file       : {info['original_filename']}")
        print(f"size_bytes : {info['size_bytes']}")
        print(f"sha256     : {info['sha256']}")
        print(f"mode       : {info['mode']}")
        print(f"pdb_name   : {observed.get('pdb_name', '?')}")
        print(f"pdb_guid   : {observed.get('pdb_guid', '?')}")
        print(f"pdb_age    : {observed.get('pdb_age', '?')}")
    return 0 if read_error is None else 2


def cmd_inspect_isf(args: argparse.Namespace) -> int:
    """Inspect an ISF file: safe-parse, identity, schema, sufficiency.

    No database writes.  Returns non-zero on invalid or
    identity-less ISF.
    """
    from pathlib import Path
    from app.cli.memory_symbols_runtime import (
        InputFileError,
        validate_input_file,
    )
    from app.core.config import get_settings
    from app.services.memory.symbol_recovery import (
        SYMBOL_ISF_RESOURCE_LIMIT_EXCEEDED,
        IsfResourceLimitError,
        _safe_json_load,
    )

    raw_path = Path(args.file)
    try:
        info = validate_input_file(
            raw_path,
            allowed_extensions={".isf", ".json", ".xz"},
            safe_override=args.safe_override,
        )
    except InputFileError as exc:
        if args.json:
            _print_json({"status": "invalid", "error": str(exc)})
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    settings = get_settings()
    try:
        if str(info["resolved_path"]).lower().endswith(".xz"):
            import lzma
            with lzma.open(info["resolved_path"], "rb") as handle:
                payload = _safe_json_load(handle, settings)
        else:
            with open(info["resolved_path"], "rb") as handle:
                payload = _safe_json_load(handle, settings)
    except IsfResourceLimitError as exc:
        if args.json:
            _print_json({
                "status": "invalid",
                "error_code": SYMBOL_ISF_RESOURCE_LIMIT_EXCEEDED,
                "limit": exc.kind,
            })
        else:
            print(f"ERROR: {SYMBOL_ISF_RESOURCE_LIMIT_EXCEEDED}: {exc.kind}", file=sys.stderr)
        return 2
    except Exception as exc:
        if args.json:
            _print_json({"status": "invalid", "error": f"{type(exc).__name__}: {exc}"})
        else:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    # Validate schema
    is_dict = isinstance(payload, dict)
    metadata = payload.get("metadata") if is_dict else None
    windows = metadata.get("windows") if isinstance(metadata, dict) else None
    pdb_block = windows.get("pdb") if isinstance(windows, dict) else None
    isf_guid = (
        str(pdb_block.get("GUID") or "").replace("-", "").replace("{", "").replace("}", "").upper()
        if isinstance(pdb_block, dict) else ""
    )
    try:
        isf_age = int(pdb_block.get("age")) if isinstance(pdb_block, dict) else -1
    except (TypeError, ValueError):
        isf_age = -1
    identity_sufficient = bool(
        is_dict
        and isinstance(metadata, dict)
        and isinstance(windows, dict)
        and isinstance(pdb_block, dict)
        and isf_guid
        and len(isf_guid) == 32
        and isf_age >= 0
    )
    payload_out = {
        "status": "ok" if is_dict else "invalid",
        "file": info["original_filename"],
        "size_bytes": info["size_bytes"],
        "sha256": info["sha256"],
        "schema": {
            "is_object": is_dict,
            "has_metadata": isinstance(metadata, dict),
            "has_windows": isinstance(windows, dict),
            "has_pdb_block": isinstance(pdb_block, dict),
            "has_symbols": is_dict and isinstance(payload.get("symbols"), dict),
            "has_user_types": is_dict and isinstance(payload.get("user_types"), dict),
        },
        "isf_identity": {
            "pdb_guid": isf_guid or None,
            "pdb_age": isf_age if isf_age >= 0 else None,
        },
        "identity_sufficient": identity_sufficient,
    }
    if args.json:
        _print_json(payload_out)
    else:
        print(f"status            : {'ok' if is_dict else 'invalid'}")
        print(f"file              : {info['original_filename']}")
        print(f"size_bytes        : {info['size_bytes']}")
        print(f"sha256            : {info['sha256']}")
        print(f"schema.is_object  : {payload_out['schema']['is_object']}")
        print(f"schema.metadata   : {payload_out['schema']['has_metadata']}")
        print(f"schema.windows    : {payload_out['schema']['has_windows']}")
        print(f"schema.pdb        : {payload_out['schema']['has_pdb_block']}")
        print(f"schema.symbols    : {payload_out['schema']['has_symbols']}")
        print(f"schema.user_types : {payload_out['schema']['has_user_types']}")
        print(f"isf_pdb_guid      : {payload_out['isf_identity']['pdb_guid'] or '?'}")
        print(f"isf_pdb_age       : {payload_out['isf_identity']['pdb_age']}")
        print(f"identity_sufficient: {identity_sufficient}")
    return 0 if identity_sufficient else 2


def _cli_print_confirmation(result: dict) -> None:
    """Print the canonical confirmation block (no internal paths)."""
    print("== Operator exact symbol import (sanitized) ==")
    exp = result.get("identity_expected") or {}
    obs = result.get("identity_observed") or {}
    if exp:
        print(f"  expected pdb_name : {exp.get('pdb_name')}")
        print(f"  expected pdb_guid : {exp.get('pdb_guid')}")
        print(f"  expected pdb_age  : {exp.get('pdb_age')}")
        print(f"  expected arch     : {exp.get('architecture')}")
    if obs:
        print(f"  observed pdb_guid : {obs.get('pdb_guid') or obs.get('expected_pdb_guid') or '?'}")
        print(f"  observed pdb_age  : {obs.get('pdb_age')}")
    print(f"  file sha256       : {result.get('sha256')}")
    print(f"  file size_bytes   : {result.get('size_bytes')}")


def _cli_affected_exact_match_count(db, requirement) -> int:
    """Count exact-match requirements that will be linked by the
    import.  Used for the confirmation block.
    """
    from app.models.memory import MemorySymbolRequirement

    return (
        db.query(MemorySymbolRequirement)
        .filter(
            MemorySymbolRequirement.symbol_key == requirement.symbol_key,
            MemorySymbolRequirement.architecture == requirement.architecture,
        )
        .count()
    )


def cmd_import_pdb(args: argparse.Namespace) -> int:
    """Operator-only PDB import.  Requires --operator."""
    from pathlib import Path
    from app.cli.memory_symbols_runtime import prompt_for_confirmation
    from app.models.memory import MemorySymbolRequirement
    from app.services.memory.symbol_recovery import (
        ATTEMPT_PENDING,
        cli_import_pdb_for_requirement,
    )
    from app.services.memory.symbol_recovery import expected_identity_dict

    import_job_id = args.import_job_id or secrets.token_hex(8)
    with SessionLocal() as db:
        requirement = db.get(MemorySymbolRequirement, str(args.requirement_id))
        if requirement is None:
            print(f"ERROR: requirement {args.requirement_id} not found", file=sys.stderr)
            return 2
        identity_expected = expected_identity_dict(requirement)
        affected = _cli_affected_exact_match_count(db, requirement)
        if args.dry_run:
            result = cli_import_pdb_for_requirement(
                db,
                requirement_id=args.requirement_id,
                file_path=Path(args.file),
                operator=args.operator,
                import_job_id=import_job_id,
                safe_override=args.safe_override,
                dry_run=True,
            )
            return _cli_print_result(result, as_json=args.json)
        # Print the confirmation block.  When ``--yes`` is set, skip
        # the interactive prompt.  In both cases the sanitized
        # summary is printed.
        preflight = cli_import_pdb_for_requirement(
            db,
            requirement_id=args.requirement_id,
            file_path=Path(args.file),
            operator=args.operator,
            import_job_id=import_job_id,
            safe_override=args.safe_override,
            dry_run=True,
        )
        # ``dry_run`` does not raise; failures are reported in the
        # result dict.  Surface the failure early so the operator
        # can correct the input before any row is written.
        if preflight.get("status") != "dry_run":
            return _cli_print_result(preflight, as_json=args.json)
        preflight["affected_exact_match_count"] = affected
        preflight["identity_expected"] = identity_expected
        if not args.json:
            _cli_print_confirmation(preflight)
            print("")
            print(f"This import will be linked to {affected} exact-match requirement(s).")
            print("It is a maintenance operation.  No analyst path is available.")
            print("")
        if not prompt_for_confirmation(
            "Type 'yes' to confirm, or Ctrl+C to abort: ",
            assume_yes=args.yes,
        ):
            print("Aborted.")
            return 1
        # Active attempt may exist; if so, the canonical service
        # returns ``identity_mismatch`` or ``validation_failed``
        # early.  We honour that.
        result = cli_import_pdb_for_requirement(
            db,
            requirement_id=args.requirement_id,
            file_path=Path(args.file),
            operator=args.operator,
            import_job_id=import_job_id,
            safe_override=args.safe_override,
            dry_run=False,
        )
    return _cli_print_result(result, as_json=args.json)


def cmd_import_isf(args: argparse.Namespace) -> int:
    """Operator-only ISF import.  Requires --operator."""
    from pathlib import Path
    from app.cli.memory_symbols_runtime import prompt_for_confirmation
    from app.models.memory import MemorySymbolRequirement
    from app.services.memory.symbol_recovery import (
        cli_import_isf_for_requirement,
        expected_identity_dict,
    )

    import_job_id = args.import_job_id or secrets.token_hex(8)
    with SessionLocal() as db:
        requirement = db.get(MemorySymbolRequirement, str(args.requirement_id))
        if requirement is None:
            print(f"ERROR: requirement {args.requirement_id} not found", file=sys.stderr)
            return 2
        identity_expected = expected_identity_dict(requirement)
        affected = _cli_affected_exact_match_count(db, requirement)
        if args.dry_run:
            result = cli_import_isf_for_requirement(
                db,
                requirement_id=args.requirement_id,
                file_path=Path(args.file),
                operator=args.operator,
                import_job_id=import_job_id,
                safe_override=args.safe_override,
                dry_run=True,
            )
            return _cli_print_result(result, as_json=args.json)
        preflight = cli_import_isf_for_requirement(
            db,
            requirement_id=args.requirement_id,
            file_path=Path(args.file),
            operator=args.operator,
            import_job_id=import_job_id,
            safe_override=args.safe_override,
            dry_run=True,
        )
        if preflight.get("status") != "dry_run":
            return _cli_print_result(preflight, as_json=args.json)
        preflight["affected_exact_match_count"] = affected
        preflight["identity_expected"] = identity_expected
        if not args.json:
            _cli_print_confirmation(preflight)
            print("")
            print(f"This import will be linked to {affected} exact-match requirement(s).")
            print("It is a maintenance operation.  No analyst path is available.")
            print("")
        if not prompt_for_confirmation(
            "Type 'yes' to confirm, or Ctrl+C to abort: ",
            assume_yes=args.yes,
        ):
            print("Aborted.")
            return 1
        result = cli_import_isf_for_requirement(
            db,
            requirement_id=args.requirement_id,
            file_path=Path(args.file),
            operator=args.operator,
            import_job_id=import_job_id,
            safe_override=args.safe_override,
            dry_run=False,
        )
    return _cli_print_result(result, as_json=args.json)


def cmd_status(args: argparse.Namespace) -> int:
    """Alias for ``show`` (with the existing request-id argument)."""
    return cmd_show(args)


def cmd_status_requirement(args: argparse.Namespace) -> int:
    """Operator-facing summary of a requirement by requirement_id.

    Shows the canonical identity, the cache link, the preparation
    state, the last recovery / import attempt, and whether analysis
    is currently allowed.  Never prints internal filesystem paths,
    credentials, or secrets.
    """
    from app.models.memory import (
        MemoryCachedSymbol,
        MemorySymbolAcquisition,
        MemorySymbolPreparation,
        MemorySymbolRecoveryAttempt,
        MemorySymbolRequirement,
    )
    from app.services.memory.symbol_recovery import (
        RECOVERY_TERMINAL_STATES,
    )

    rid = str(args.requirement_id)
    with SessionLocal() as db:
        requirement = db.get(MemorySymbolRequirement, rid)
        if requirement is None:
            if args.json:
                _print_json({"status": "not_found", "requirement_id": rid})
            else:
                print(f"ERROR: requirement {rid} not found", file=sys.stderr)
            return 2
        # Canonical identity
        identity_expected = {
            "pdb_name": requirement.pdb_name,
            "pdb_guid": (requirement.pdb_guid or "").upper(),
            "pdb_age": int(requirement.pdb_age),
            "architecture": requirement.architecture,
        }
        # Cache link
        cached = None
        if requirement.cached_symbol_id:
            cached = db.get(MemoryCachedSymbol, requirement.cached_symbol_id)
        cache_summary = None
        if cached is not None:
            cache_summary = {
                "id": str(cached.id),
                "symbol_key": cached.symbol_key,
                "pdb_sha256": cached.pdb_sha256,
                "isf_sha256": cached.isf_sha256,
                "pdb_size_bytes": int(cached.pdb_size_bytes),
                "isf_size_bytes": int(cached.isf_size_bytes),
                "validation_status": cached.validation_status,
                "provenance_source_type": cached.provenance_source_type,
                "provenance_source_name": cached.provenance_source_name,
                "provenance_actor": cached.provenance_actor,
                "provenance_acquired_at": _format_timestamp(cached.provenance_acquired_at),
                # Relative paths only; never the absolute on-disk path.
                "pdb_relative_path": cached.pdb_relative_path,
                "isf_relative_path": cached.isf_relative_path,
            }
        # Preparation
        prep = (
            db.query(MemorySymbolPreparation)
            .filter(
                MemorySymbolPreparation.evidence_id == requirement.evidence_id,
                MemorySymbolPreparation.active.is_(True),
            )
            .order_by(MemorySymbolPreparation.created_at.desc())
            .first()
        )
        prep_summary = None
        if prep is not None:
            prep_summary = {
                "id": str(prep.id),
                "state": prep.state,
                "state_reason": prep.state_reason,
                "error_code": prep.error_code,
                "attempts": int(prep.attempts or 0),
                "started_at": _format_timestamp(prep.started_at),
                "completed_at": _format_timestamp(prep.completed_at),
                "active": bool(prep.active),
            }
        # Latest acquisition (for the UI's "Observed age: N" field)
        latest_acq = (
            db.query(MemorySymbolAcquisition)
            .filter(MemorySymbolAcquisition.requirement_id == requirement.id)
            .order_by(MemorySymbolAcquisition.created_at.desc())
            .first()
        )
        acq_summary = None
        if latest_acq is not None:
            acq_summary = {
                "id": str(latest_acq.id),
                "status": latest_acq.status,
                "error_code": latest_acq.error_code,
                "sanitized_message": latest_acq.sanitized_message,
                "observed_pdb_guid": latest_acq.observed_pdb_guid,
                "observed_pdb_age": (
                    int(latest_acq.observed_pdb_age)
                    if latest_acq.observed_pdb_age is not None else None
                ),
                "observed_architecture": latest_acq.observed_architecture,
                "completed_at": _format_timestamp(latest_acq.completed_at),
            }
        # Last attempt (recovery + CLI)
        last_attempt = (
            db.query(MemorySymbolRecoveryAttempt)
            .filter(MemorySymbolRecoveryAttempt.requirement_id == requirement.id)
            .order_by(MemorySymbolRecoveryAttempt.created_at.desc())
            .first()
        )
        last_attempt_summary = None
        if last_attempt is not None:
            md = dict(last_attempt.metadata_json or {})
            last_attempt_summary = {
                "id": str(last_attempt.id),
                "source_type": last_attempt.source_type,
                "source_label": last_attempt.source_label,
                "status": last_attempt.status,
                "error_code": last_attempt.error_code,
                "sanitized_message": last_attempt.sanitized_message,
                "terminal_at": _format_timestamp(last_attempt.terminal_at),
                "operator": md.get("operator"),
                "import_job_id": md.get("import_job_id"),
                "sha256": md.get("sha256"),
            }
        # Whether analysis is currently allowed.  The canonical
        # signal is the preparation state: ``ready`` is the only
        # state where the analyst UI exposes the analysis action.
        analysis_allowed = prep is not None and prep.state == "ready" and cached is not None
        payload = {
            "requirement_id": rid,
            "case_id": requirement.case_id,
            "evidence_id": requirement.evidence_id,
            "identity_expected": identity_expected,
            "cache": cache_summary,
            "preparation": prep_summary,
            "latest_acquisition": acq_summary,
            "last_attempt": last_attempt_summary,
            "analysis_allowed": bool(analysis_allowed),
            "terminal_states": sorted(RECOVERY_TERMINAL_STATES),
        }
    if args.json:
        _print_json(payload)
        return 0
    print("== Requirement (sanitized) ==")
    print(f"  requirement_id    : {payload['requirement_id']}")
    print(f"  case_id           : {payload['case_id']}")
    print(f"  evidence_id       : {payload['evidence_id']}")
    exp = payload["identity_expected"]
    print(f"  expected pdb_name : {exp['pdb_name']}")
    print(f"  expected pdb_guid : {exp['pdb_guid']}")
    print(f"  expected pdb_age  : {exp['pdb_age']}")
    print(f"  expected arch     : {exp['architecture']}")
    print("== Cache ==")
    if cache_summary is None:
        print("  cache             : <not linked>")
    else:
        print(f"  cache.id          : {cache_summary['id']}")
        print(f"  cache.symbol_key  : {cache_summary['symbol_key']}")
        print(f"  cache.pdb_sha256  : {cache_summary['pdb_sha256']}")
        print(f"  cache.isf_sha256  : {cache_summary['isf_sha256']}")
        print(f"  cache.provenance  : {cache_summary['provenance_source_type']} / {cache_summary['provenance_source_name']} / {cache_summary['provenance_actor']}")
    print("== Preparation ==")
    if prep_summary is None:
        print("  preparation       : <none>")
    else:
        print(f"  state             : {prep_summary['state']}")
        print(f"  state_reason      : {prep_summary['state_reason']}")
        print(f"  error_code        : {prep_summary['error_code']}")
    print("== Latest acquisition (canonical observed identity) ==")
    if acq_summary is None:
        print("  acquisition       : <none>")
    else:
        print(f"  status            : {acq_summary['status']}")
        print(f"  error_code        : {acq_summary['error_code']}")
        print(f"  observed_guid     : {acq_summary['observed_pdb_guid']}")
        print(f"  observed_age      : {acq_summary['observed_pdb_age']}")
    print("== Last attempt ==")
    if last_attempt_summary is None:
        print("  attempt           : <none>")
    else:
        print(f"  source_type       : {last_attempt_summary['source_type']}")
        print(f"  status            : {last_attempt_summary['status']}")
        print(f"  error_code        : {last_attempt_summary['error_code']}")
        print(f"  operator          : {last_attempt_summary['operator']}")
        print(f"  import_job_id     : {last_attempt_summary['import_job_id']}")
    print(f"analysis_allowed    : {payload['analysis_allowed']}")
    return 0


def cmd_register_experimental_candidate(args: argparse.Namespace) -> int:
    """Register an exact cache row as an experimental mismatched candidate.

    The function refuses to run when the experimental feature
    flag is off.  It only writes a ``MemoryExperimentalSymbolCandidate``
    row; the exact symbol cache and the requirement are NEVER
    mutated.  The function is read-only on disk and never
    downloads symbols.
    """
    if not is_experimental_enabled():
        print(
            "experimental mismatched-symbol analysis is disabled "
            "(memory_symbol_experimental_mismatch_enabled=False)",
            file=sys.stderr,
        )
        return 2
    try:
        with SessionLocal() as db:
            candidate = record_cli_candidate(
                db,
                case_id=args.case_id,
                evidence_id=args.evidence_id,
                cached_symbol_id=args.cached_symbol_id,
                source_host_path=args.source_host_path,
                actor=args.actor,
            )
        if args.json:
            _print_json(
                {
                    "id": candidate.id,
                    "case_id": candidate.case_id,
                    "evidence_id": candidate.evidence_id,
                    "requirement_id": candidate.requirement_id,
                    "cached_symbol_id": candidate.cached_symbol_id,
                    "required_pdb_name": candidate.required_pdb_name,
                    "required_pdb_guid": candidate.required_pdb_guid,
                    "required_pdb_age": int(candidate.required_pdb_age),
                    "required_architecture": candidate.required_architecture,
                    "observed_pdb_name": candidate.observed_pdb_name,
                    "observed_pdb_guid": candidate.observed_pdb_guid,
                    "observed_pdb_age": int(candidate.observed_pdb_age),
                    "observed_architecture": candidate.observed_architecture,
                    "symbol_match_type": candidate.symbol_match_type,
                    "symbol_warning": candidate.symbol_warning,
                    "created_at": candidate.created_at.isoformat() if candidate.created_at else None,
                }
            )
        else:
            print("Experimental candidate registered.")
            print(f"  candidate_id        : {candidate.id}")
            print(f"  required identity   : {candidate.required_pdb_name} / {candidate.required_pdb_guid} / age={int(candidate.required_pdb_age)} / {candidate.required_architecture}")
            print(f"  observed identity   : {candidate.observed_pdb_name} / {candidate.observed_pdb_guid} / age={int(candidate.observed_pdb_age)} / {candidate.observed_architecture}")
            print(f"  symbol_match_type   : {candidate.symbol_match_type}")
            print(f"  symbol_warning      : {candidate.symbol_warning}")
        return 0
    except ExperimentalLifecycleError as exc:
        print(f"refused: {exc.error_code}: {exc.message}", file=sys.stderr)
        return 2


def cmd_status_experimental(args: argparse.Namespace) -> int:
    """Return the experimental trust state for a case/evidence pair."""
    with SessionLocal() as db:
        state = trust_state(db, case_id=args.case_id, evidence_id=args.evidence_id)
    if args.json:
        _print_json(state)
    else:
        print("Experimental trust state:")
        for key, value in state.items():
            print(f"  {key:>22}: {value}")
    return 0


def cmd_inspect_experimental_pdb(args: argparse.Namespace) -> int:
    from pathlib import Path

    try:
        with SessionLocal() as db:
            result = inspect_experimental_pdb_for_requirement(
                db,
                requirement_id=args.requirement_id,
                file_path=Path(args.file),
                safe_override=args.safe_override,
            )
    except (ExperimentalImportError, Exception) as exc:
        if args.json:
            _print_json({
                "status": "invalid",
                "error_code": getattr(exc, "code", "EXPERIMENTAL_IMPORT_REJECTED"),
                "sanitized_message": getattr(exc, "message", str(exc)),
            })
        else:
            print(f"ERROR: {getattr(exc, 'code', 'EXPERIMENTAL_IMPORT_REJECTED')}: {getattr(exc, 'message', exc)}", file=sys.stderr)
        return 2
    if args.json:
        _print_json(result)
    else:
        print("Experimental PDB candidate is eligible.")
        print(f"  requirement_id      : {result['requirement_id']}")
        print(f"  required age        : {result['required_identity']['pdb_age']}")
        print(f"  observed age        : {result['observed_identity']['pdb_age']}")
        print(f"  sha256              : {result['sha256']}")
        print(f"  size_bytes          : {result['size_bytes']}")
    return 0


def _cli_print_experimental_result(result: dict, *, as_json: bool) -> int:
    if as_json:
        _print_json(result)
    else:
        print(f"status             : {result.get('status')}")
        if result.get("requirement_id"):
            print(f"requirement_id     : {result['requirement_id']}")
        if result.get("candidate_id"):
            print(f"candidate_id       : {result['candidate_id']}")
        if result.get("cached_symbol_id"):
            print(f"cached_symbol_id   : {result['cached_symbol_id']}")
        if result.get("required_identity"):
            print(f"required_age       : {result['required_identity'].get('pdb_age')}")
        if result.get("observed_identity"):
            print(f"observed_age       : {result['observed_identity'].get('pdb_age')}")
        if result.get("sha256"):
            print(f"sha256             : {result['sha256']}")
        if result.get("size_bytes") is not None:
            print(f"size_bytes         : {result['size_bytes']}")
        if result.get("sanitized_message"):
            print(f"sanitized_message  : {result['sanitized_message']}")
    return 0 if result.get("status") in {"ready", "dry_run", "eligible"} else 2


def cmd_import_experimental_pdb(args: argparse.Namespace) -> int:
    from pathlib import Path
    from app.cli.memory_symbols_runtime import prompt_for_confirmation

    try:
        with SessionLocal() as db:
            preflight = cli_import_experimental_pdb_for_requirement(
                db,
                requirement_id=args.requirement_id,
                file_path=Path(args.file),
                operator_label=args.operator_label,
                safe_override=args.safe_override,
                dry_run=True,
            )
            if args.dry_run:
                return _cli_print_experimental_result(preflight, as_json=args.json)
            if not args.json:
                print("== Operator experimental symbol import (sanitized) ==")
                print(f"  required age : {preflight['required_identity']['pdb_age']}")
                print(f"  observed age : {preflight['observed_identity']['pdb_age']}")
                print(f"  sha256       : {preflight['sha256']}")
                print(f"  size_bytes   : {preflight['size_bytes']}")
            if not prompt_for_confirmation("Type 'yes' to confirm, or Ctrl+C to abort: ", assume_yes=args.yes):
                print("Aborted.")
                return 1
            result = cli_import_experimental_pdb_for_requirement(
                db,
                requirement_id=args.requirement_id,
                file_path=Path(args.file),
                operator_label=args.operator_label,
                safe_override=args.safe_override,
                dry_run=False,
            )
    except ExperimentalImportError as exc:
        return _cli_print_experimental_result(
            {"status": "import_rejected", "error_code": exc.code, "sanitized_message": exc.message},
            as_json=args.json,
        )
    return _cli_print_experimental_result(result, as_json=args.json)


def cmd_import_experimental_isf(args: argparse.Namespace) -> int:
    from pathlib import Path
    from app.cli.memory_symbols_runtime import prompt_for_confirmation

    try:
        with SessionLocal() as db:
            preflight = cli_import_experimental_isf_for_requirement(
                db,
                requirement_id=args.requirement_id,
                file_path=Path(args.file),
                operator_label=args.operator_label,
                safe_override=args.safe_override,
                dry_run=True,
            )
            if args.dry_run:
                return _cli_print_experimental_result(preflight, as_json=args.json)
            if not args.json:
                print("== Operator experimental ISF import (sanitized) ==")
                print(f"  required age : {preflight['required_identity']['pdb_age']}")
                print(f"  observed age : {preflight['observed_identity']['pdb_age']}")
                print(f"  sha256       : {preflight['sha256']}")
                print(f"  size_bytes   : {preflight['size_bytes']}")
            if not prompt_for_confirmation("Type 'yes' to confirm, or Ctrl+C to abort: ", assume_yes=args.yes):
                print("Aborted.")
                return 1
            result = cli_import_experimental_isf_for_requirement(
                db,
                requirement_id=args.requirement_id,
                file_path=Path(args.file),
                operator_label=args.operator_label,
                safe_override=args.safe_override,
                dry_run=False,
            )
    except ExperimentalImportError as exc:
        return _cli_print_experimental_result(
            {"status": "import_rejected", "error_code": exc.code, "sanitized_message": exc.message},
            as_json=args.json,
        )
    return _cli_print_experimental_result(result, as_json=args.json)


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

    p_backfill = sub.add_parser(
        "backfill",
        help=(
            "Reconstruct missing MemorySymbolRequirement rows from history. "
            "Idempotent. Never executes Volatility, never downloads symbols."
        ),
    )
    p_backfill.add_argument("--case-id", default=None, help="Limit to a single case.")
    p_backfill.add_argument("--evidence-id", default=None, help="Limit to a single evidence.")
    p_backfill.set_defaults(func=cmd_backfill)

    # ------------------------------------------------------------------
    # Operator-only exact symbol import (no HTTP route)
    # ------------------------------------------------------------------
    p_inspect_pdb = sub.add_parser(
        "inspect-pdb",
        help=(
            "Read a candidate PDB and print its identity, SHA-256 and size. "
            "Performs no database writes, no cache promotion, no conversion."
        ),
    )
    p_inspect_pdb.add_argument("--file", required=True, help="Path to the PDB to inspect.")
    p_inspect_pdb.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    p_inspect_pdb.add_argument(
        "--safe-override",
        action="store_true",
        help="Bypass the operator-import-root check (use only in trusted environments).",
    )
    p_inspect_pdb.set_defaults(func=cmd_inspect_pdb)

    p_inspect_isf = sub.add_parser(
        "inspect-isf",
        help=(
            "Read a candidate ISF and print its identity, SHA-256 and schema. "
            "Performs no database writes."
        ),
    )
    p_inspect_isf.add_argument("--file", required=True, help="Path to the ISF to inspect.")
    p_inspect_isf.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    p_inspect_isf.add_argument(
        "--safe-override",
        action="store_true",
        help="Bypass the operator-import-root check.",
    )
    p_inspect_isf.set_defaults(func=cmd_inspect_isf)

    p_import_pdb = sub.add_parser(
        "import-pdb",
        help=(
            "Operator-only: import an exact authorized PDB for a stored requirement. "
            "Reuses the canonical recovery / cache / provenance / fan-out services. "
            "Does not enable the admin HTTP route."
        ),
    )
    p_import_pdb.add_argument("--requirement-id", required=True, help="MemorySymbolRequirement UUID.")
    p_import_pdb.add_argument("--file", required=True, help="Path to the authorized PDB.")
    p_import_pdb.add_argument("--operator", required=True, help="Operator label recorded in provenance.")
    p_import_pdb.add_argument(
        "--import-job-id", default=None,
        help="Optional deterministic import job id.  Default: random 8-byte hex.",
    )
    p_import_pdb.add_argument("--dry-run", action="store_true", help="Validate only; do not write.")
    p_import_pdb.add_argument("--yes", action="store_true", help="Skip the interactive confirmation prompt.")
    p_import_pdb.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    p_import_pdb.add_argument(
        "--safe-override",
        action="store_true",
        help="Bypass the operator-import-root check.",
    )
    p_import_pdb.set_defaults(func=cmd_import_pdb)

    p_import_isf = sub.add_parser(
        "import-isf",
        help=(
            "Operator-only: import an exact authorized ISF for a stored requirement. "
            "Reuses the canonical recovery / cache / provenance / fan-out services. "
            "Does not enable the admin HTTP route."
        ),
    )
    p_import_isf.add_argument("--requirement-id", required=True, help="MemorySymbolRequirement UUID.")
    p_import_isf.add_argument("--file", required=True, help="Path to the authorized ISF.")
    p_import_isf.add_argument("--operator", required=True, help="Operator label recorded in provenance.")
    p_import_isf.add_argument(
        "--import-job-id", default=None,
        help="Optional deterministic import job id.  Default: random 8-byte hex.",
    )
    p_import_isf.add_argument("--dry-run", action="store_true", help="Validate only; do not write.")
    p_import_isf.add_argument("--yes", action="store_true", help="Skip the interactive confirmation prompt.")
    p_import_isf.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    p_import_isf.add_argument(
        "--safe-override",
        action="store_true",
        help="Bypass the operator-import-root check.",
    )
    p_import_isf.set_defaults(func=cmd_import_isf)

    p_status_req = sub.add_parser(
        "status-requirement",
        help=(
            "Operator-facing summary of a requirement by requirement_id. "
            "Never prints internal filesystem paths, credentials, or secrets."
        ),
    )
    p_status_req.add_argument("--requirement-id", required=True, help="MemorySymbolRequirement UUID.")
    p_status_req.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    p_status_req.set_defaults(func=cmd_status_requirement)

    # ------------------------------------------------------------------
    # Experimental mismatched-symbol analysis
    # ------------------------------------------------------------------
    p_inspect_exp_pdb = sub.add_parser(
        "inspect-experimental-pdb",
        help="Inspect a mismatched experimental PDB against a stored requirement.",
    )
    p_inspect_exp_pdb.add_argument("--file", required=True)
    p_inspect_exp_pdb.add_argument("--requirement-id", required=True)
    p_inspect_exp_pdb.add_argument("--json", action="store_true")
    p_inspect_exp_pdb.add_argument("--safe-override", action="store_true")
    p_inspect_exp_pdb.set_defaults(func=cmd_inspect_experimental_pdb)

    p_import_exp_pdb = sub.add_parser(
        "import-experimental-pdb",
        help="Import a mismatched experimental PDB for a stored requirement.",
    )
    p_import_exp_pdb.add_argument("--file", required=True)
    p_import_exp_pdb.add_argument("--requirement-id", required=True)
    p_import_exp_pdb.add_argument("--operator-label", required=True)
    p_import_exp_pdb.add_argument("--dry-run", action="store_true")
    p_import_exp_pdb.add_argument("--yes", action="store_true")
    p_import_exp_pdb.add_argument("--json", action="store_true")
    p_import_exp_pdb.add_argument("--safe-override", action="store_true")
    p_import_exp_pdb.set_defaults(func=cmd_import_experimental_pdb)

    p_import_exp_isf = sub.add_parser(
        "import-experimental-isf",
        help="Import a mismatched experimental ISF for a stored requirement.",
    )
    p_import_exp_isf.add_argument("--file", required=True)
    p_import_exp_isf.add_argument("--requirement-id", required=True)
    p_import_exp_isf.add_argument("--operator-label", required=True)
    p_import_exp_isf.add_argument("--dry-run", action="store_true")
    p_import_exp_isf.add_argument("--yes", action="store_true")
    p_import_exp_isf.add_argument("--json", action="store_true")
    p_import_exp_isf.add_argument("--safe-override", action="store_true")
    p_import_exp_isf.set_defaults(func=cmd_import_experimental_isf)

    p_register_exp = sub.add_parser(
        "register-experimental-candidate",
        help=(
            "Register an existing exact candidate cache row as an "
            "experimental mismatched-symbol candidate.  The candidate "
            "is NEVER linked to the exact symbol path.  Requires the "
            "experimental feature flag to be enabled."
        ),
    )
    p_register_exp.add_argument("--case-id", required=True)
    p_register_exp.add_argument("--evidence-id", required=True)
    p_register_exp.add_argument("--cached-symbol-id", required=True)
    p_register_exp.add_argument(
        "--source-host-path", default=None,
        help="Audit-only.  Where the file lived on the host.  Never used for I/O.",
    )
    p_register_exp.add_argument("--actor", default="server-operator")
    p_register_exp.add_argument("--json", action="store_true")
    p_register_exp.set_defaults(func=cmd_register_experimental_candidate)

    p_status_exp = sub.add_parser(
        "status-experimental",
        help="Return the experimental trust state for a case/evidence pair.",
    )
    p_status_exp.add_argument("--case-id", required=True)
    p_status_exp.add_argument("--evidence-id", required=True)
    p_status_exp.add_argument("--json", action="store_true")
    p_status_exp.set_defaults(func=cmd_status_experimental)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
