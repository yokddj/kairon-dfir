"""Tests for Memory Preparation Phase 3 (async architecture): evidence-
scoped Linux ISF validation running on the memory-worker, with the
backend API process never writing to /volatility-cache.

Covers:
1. create_linux_symbol_validation_job() -- backend-side enqueue. Runs
   with a read-only cache mount in mind: never calls
   inspect_linux_isf()/import_linux_isf() itself, only ever touches
   Postgres and the (backend-writable) staging file.
2. execute_linux_symbol_validation() -- the worker-side task: the four
   terminal states, atomic promotion order, cache collision, staging
   cleanup, idempotent re-validation, and a REAL timeout (via a
   monkeypatched subprocess_isolation.run_isolated raising
   SubprocessIsolationTimeout, proving the task handles it exactly like
   any other definitive failure -- see test_subprocess_isolation.py for
   proof the underlying kill itself is real, not simulated here).
3. get_linux_symbol_validation_status() -- polling read, including lazy
   staleness reconciliation for a worker that died mid-job.
4. The POST/GET route handlers -- enqueue-only semantics, duplicate
   rejection, and a static proof the POST route never imports the
   cache-writing functions.
5. Preparation SYMBOLS_REQUIRED -> READY once a job reaches valid, and
   cached reuse for a second evidence.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, UploadFile
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, utc_now_naive
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.memory import MemoryEvidenceLinuxSymbolLink
from app.services.memory.linux_symbol_evidence import (
    DuplicateValidationJobError,
    STATUS_INVALID,
    STATUS_QUEUED,
    STATUS_UNSUPPORTED,
    STATUS_VALID,
    STATUS_VALIDATING,
    STATUS_VALIDATION_FAILED,
    create_linux_symbol_validation_job,
    execute_linux_symbol_validation,
    get_linux_symbol_link,
    get_linux_symbol_validation_status,
    has_accepted_isf_extension,
)
from app.services.memory.preparation import PreparationState, get_preparation_status

CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
OTHER_CASE_ID = "cccccccc-3333-4333-8333-cccccccccccc"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _case(db, case_id: str = CASE_ID) -> None:
    db.add(Case(id=case_id, name="Case", description=None))
    db.commit()


def _evidence(
    db,
    *,
    evidence_id: str = EVIDENCE_ID,
    case_id: str = CASE_ID,
    filename: str = "dump.raw",
    stored_path: str,
    evidence_type: EvidenceType = EvidenceType.memory_dump,
    detected_format: str | None = "elf_core",
    metadata_json: dict | None = None,
    size_bytes: int = 4096,
) -> Evidence:
    item = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename=filename,
        stored_path=stored_path,
        original_path=stored_path,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=evidence_type,
        sha256="0" * 64,
        size_bytes=size_bytes,
        ingest_status=IngestStatus.completed,
        detected_host=None,
        detection_status="confirmed_memory",
        operator_override=False,
        detected_format=detected_format,
        path_validation={},
        ingest_source={},
        metadata_json=metadata_json or {},
        error_log={},
    )
    db.add(item)
    db.commit()
    return item


def _write(tmp_path: Path, name: str, content: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


def _linux_dump_bytes() -> bytes:
    return b"\x7fELF" + b"\x00" * 4092


def _windows_dump_bytes() -> bytes:
    return b"PAGEDU64" + b"\x00" * 4088


def _isf_json(*, kernel_release: str, architecture: str = "x64", build_id: str | None = "build-a") -> bytes:
    build_id_field = f', "build_id": "{build_id}"' if build_id else ""
    return (
        '{"metadata":{"linux":{"kernel_release":"%s","architecture":"%s"%s}},"symbols":{},"types":{}}'
        % (kernel_release, architecture, build_id_field)
    ).encode("utf-8")


def _isf_settings(cache_root: Path, *, manual_import_enabled: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        memory_native_probe_cache_path=cache_root,
        memory_linux_symbol_manual_import_enabled=manual_import_enabled,
        memory_linux_symbol_isf_upload_max_bytes=8 * 1024 * 1024,
        memory_linux_symbol_isf_decompressed_max_bytes=8 * 1024 * 1024,
        memory_linux_symbol_validation_timeout_seconds=30,
        memory_linux_symbol_validation_termination_grace_seconds=5,
        memory_symbol_import_quarantine_path=cache_root / "quarantine",
        memory_linux_symbol_staging_path=cache_root / "linux-symbol-staging",
    )


def _known_identity_metadata(*, kernel_release: str = "6.8.0-test", architecture: str = "x64", build_id: str = "build-a") -> dict:
    return {"linux_symbol_identity": {"kernel_release": kernel_release, "architecture": architecture, "build_id": build_id}}


def _cache_dir(tmp_path: Path) -> Path:
    root = tmp_path / "cache"
    (root / "symbols" / "linux").mkdir(parents=True)
    return root


def _patch_settings(monkeypatch: pytest.MonkeyPatch, settings: SimpleNamespace) -> None:
    """execute_linux_symbol_validation and get_linux_symbol_validation_status
    both call app.core.config.get_settings() internally, matching how the
    real RQ task / API route are invoked with zero extra config
    plumbing -- patch the factory globally for the duration of a test."""
    import app.core.config as config_module

    monkeypatch.setattr(config_module, "get_settings", lambda: settings)


# ---------------------------------------------------------------------------
# has_accepted_isf_extension
# ---------------------------------------------------------------------------


class TestAcceptedExtension:
    @pytest.mark.parametrize("filename", ["kernel.json", "KERNEL.JSON", "kernel.json.xz", "kernel.JSON.XZ"])
    def test_accepted(self, filename: str) -> None:
        assert has_accepted_isf_extension(filename) is True

    @pytest.mark.parametrize("filename", ["vmlinux", "System.map", "kernel.pdb", "kernel.zip", "kernel.xz", "kernel"])
    def test_rejected(self, filename: str) -> None:
        assert has_accepted_isf_extension(filename) is False


# ---------------------------------------------------------------------------
# create_linux_symbol_validation_job (backend API process, enqueue only)
# ---------------------------------------------------------------------------


class TestCreateValidationJob:
    def test_creates_a_queued_job(self, tmp_path: Path) -> None:
        db = _db()
        _case(db)
        evidence = _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))
        staging = _write(tmp_path, "staged.json", _isf_json(kernel_release="6.8.0-test"))

        job = create_linux_symbol_validation_job(db, evidence, staging_path=staging)

        assert job.status == STATUS_QUEUED
        assert job.staging_path == str(staging)
        assert job.queued_at is not None

    def test_rejects_a_second_submission_while_non_terminal(self, tmp_path: Path) -> None:
        db = _db()
        _case(db)
        evidence = _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))
        staging1 = _write(tmp_path, "s1.json", _isf_json(kernel_release="6.8.0-test"))
        create_linux_symbol_validation_job(db, evidence, staging_path=staging1)

        staging2 = _write(tmp_path, "s2.json", _isf_json(kernel_release="6.8.0-test"))
        with pytest.raises(DuplicateValidationJobError):
            create_linux_symbol_validation_job(db, evidence, staging_path=staging2)

    def test_allows_a_new_submission_after_the_previous_job_is_terminal(self, tmp_path: Path) -> None:
        db = _db()
        _case(db)
        evidence = _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))
        staging1 = _write(tmp_path, "s1.json", _isf_json(kernel_release="6.8.0-test"))
        job1 = create_linux_symbol_validation_job(db, evidence, staging_path=staging1)
        job1.status = STATUS_VALIDATION_FAILED
        db.commit()

        staging2 = _write(tmp_path, "s2.json", _isf_json(kernel_release="6.8.0-test"))
        job2 = create_linux_symbol_validation_job(db, evidence, staging_path=staging2)

        assert job2.id == job1.id  # same row, reused -- no duplicate rows per evidence
        assert job2.status == STATUS_QUEUED

    def test_never_calls_cache_writing_functions(self) -> None:
        """The backend API process must never write to /volatility-cache
        (read-only mount) -- proven statically: create_linux_symbol_validation_job's
        own source never calls import_linux_isf/inspect_linux_isf (those
        are only called from execute_linux_symbol_validation, the
        worker-side function)."""
        import ast
        import inspect as py_inspect

        from app.services.memory import linux_symbol_evidence as module

        source = py_inspect.getsource(module.create_linux_symbol_validation_job)
        tree = ast.parse(source)
        called_names = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        assert "import_linux_isf" not in called_names
        assert "inspect_linux_isf" not in called_names


# ---------------------------------------------------------------------------
# execute_linux_symbol_validation (memory-worker process only)
# ---------------------------------------------------------------------------


class TestExecuteValidationFourStates:
    def test_valid_promotes_links_and_backfills_identity(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = _db()
        _case(db)
        evidence = _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))
        cache_root = _cache_dir(tmp_path)
        _patch_settings(monkeypatch, _isf_settings(cache_root))
        staging = _write(tmp_path, "staged.json", _isf_json(kernel_release="6.8.0-test"))
        job = create_linux_symbol_validation_job(db, evidence, staging_path=staging)

        execute_linux_symbol_validation(job.id, db=db)

        db.refresh(job)
        assert job.status == STATUS_VALID
        assert job.cache_key is not None
        assert Path(job.isf_path).exists()
        assert job.staging_path is None
        assert not staging.exists()
        db.refresh(evidence)
        assert evidence.metadata_json["linux_symbol_identity"]["kernel_release"] == "6.8.0-test"
        link = get_linux_symbol_link(db, evidence.id)
        assert link is not None
        assert link.id == job.id

    def test_invalid_on_identity_mismatch_never_promotes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = _db()
        _case(db)
        evidence = _evidence(
            db,
            stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())),
            metadata_json=_known_identity_metadata(kernel_release="5.15.0-required"),
        )
        cache_root = _cache_dir(tmp_path)
        _patch_settings(monkeypatch, _isf_settings(cache_root))
        staging = _write(tmp_path, "staged.json", _isf_json(kernel_release="6.8.0-wrong"))
        job = create_linux_symbol_validation_job(db, evidence, staging_path=staging)

        execute_linux_symbol_validation(job.id, db=db)

        db.refresh(job)
        assert job.status == STATUS_INVALID
        assert "kernel_release" in job.reason
        assert job.detected_identity_json["kernel_release"] == "6.8.0-wrong"
        assert job.expected_identity_json["kernel_release"] == "5.15.0-required"
        assert job.staging_path is None
        assert not staging.exists()
        assert get_linux_symbol_link(db, evidence.id) is None
        assert list((cache_root / "symbols" / "linux").iterdir()) == []

    def test_unsupported_for_non_linux_isf(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = _db()
        _case(db)
        evidence = _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))
        cache_root = _cache_dir(tmp_path)
        _patch_settings(monkeypatch, _isf_settings(cache_root))
        staging = _write(
            tmp_path, "staged.json",
            b'{"metadata": {"linux": {"platform": "windows", "kernel_release": "x"}}, "symbols": {}}',
        )
        job = create_linux_symbol_validation_job(db, evidence, staging_path=staging)

        execute_linux_symbol_validation(job.id, db=db)

        db.refresh(job)
        assert job.status == STATUS_UNSUPPORTED
        assert get_linux_symbol_link(db, evidence.id) is None
        assert not staging.exists()

    def test_validation_failed_for_malformed_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = _db()
        _case(db)
        evidence = _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))
        cache_root = _cache_dir(tmp_path)
        _patch_settings(monkeypatch, _isf_settings(cache_root))
        staging = _write(tmp_path, "staged.json", b"not json")
        job = create_linux_symbol_validation_job(db, evidence, staging_path=staging)

        execute_linux_symbol_validation(job.id, db=db)

        db.refresh(job)
        assert job.status == STATUS_VALIDATION_FAILED
        assert get_linux_symbol_link(db, evidence.id) is None
        assert not staging.exists()


class TestExecuteValidationTimeoutIsHandledLikeAnyFailure:
    def test_a_real_isolation_timeout_marks_validation_failed_and_cleans_up(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Does not re-prove the kill itself is real -- that is
        test_subprocess_isolation.py's job. This proves the WORKER TASK
        correctly treats a SubprocessIsolationTimeout exactly like any
        other definitive validation failure: no promotion, staging
        cleaned up, job left in a terminal, non-stuck state."""
        db = _db()
        _case(db)
        evidence = _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))
        cache_root = _cache_dir(tmp_path)
        _patch_settings(monkeypatch, _isf_settings(cache_root))
        staging = _write(tmp_path, "staged.json", _isf_json(kernel_release="6.8.0-test"))
        job = create_linux_symbol_validation_job(db, evidence, staging_path=staging)

        from app.services.memory import subprocess_isolation as isolation_module
        from app.services.memory.subprocess_isolation import SubprocessIsolationTimeout

        def _raise_timeout(*args, **kwargs):
            raise SubprocessIsolationTimeout("simulated timeout")

        # run_isolated is imported inside _inspect_isolated() at call time
        # (a local `from ... import run_isolated`), so patching it on its
        # OWN module -- not on linux_symbol_evidence, which never binds
        # the name at module scope -- is what actually takes effect.
        monkeypatch.setattr(isolation_module, "run_isolated", _raise_timeout)

        execute_linux_symbol_validation(job.id, db=db)

        db.refresh(job)
        assert job.status == STATUS_VALIDATION_FAILED
        assert "time" in job.reason.lower()
        assert job.staging_path is None
        assert not staging.exists()
        assert get_linux_symbol_link(db, evidence.id) is None
        assert list((cache_root / "symbols" / "linux").iterdir()) == []


class TestExecuteValidationDedupAndCollision:
    def test_reuploading_identical_isf_reports_cached(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = _db()
        _case(db)
        evidence = _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))
        cache_root = _cache_dir(tmp_path)
        _patch_settings(monkeypatch, _isf_settings(cache_root))
        isf_bytes = _isf_json(kernel_release="6.8.0-test")

        staging1 = _write(tmp_path, "s1.json", isf_bytes)
        job1 = create_linux_symbol_validation_job(db, evidence, staging_path=staging1)
        execute_linux_symbol_validation(job1.id, db=db)
        db.refresh(job1)
        assert job1.cached is False

        staging2 = _write(tmp_path, "s2.json", isf_bytes)
        job2 = create_linux_symbol_validation_job(db, evidence, staging_path=staging2)
        execute_linux_symbol_validation(job2.id, db=db)
        db.refresh(job2)
        assert job2.status == STATUS_VALID
        assert job2.cached is True
        assert job2.id == job1.id  # same row, no duplicate link rows

    def test_second_evidence_reuses_the_same_cached_isf_without_a_new_job(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _db()
        _case(db)
        evidence_a = _evidence(db, evidence_id="dddddddd-4444-4444-8444-dddddddddddd", stored_path=str(_write(tmp_path, "a.img", _linux_dump_bytes())))
        evidence_b = _evidence(
            db, evidence_id="eeeeeeee-5555-4555-8555-eeeeeeeeeeee", stored_path=str(_write(tmp_path, "b.img", _linux_dump_bytes())),
            metadata_json=_known_identity_metadata(kernel_release="6.8.0-test"),
        )
        cache_root = _cache_dir(tmp_path)
        _patch_settings(monkeypatch, _isf_settings(cache_root))
        from app.services.memory import analysis_plan as analysis_plan_module
        monkeypatch.setattr(analysis_plan_module, "get_settings", lambda: SimpleNamespace(memory_native_probe_cache_path=cache_root))
        isf_bytes = _isf_json(kernel_release="6.8.0-test")

        staging_a = _write(tmp_path, "a.json", isf_bytes)
        job_a = create_linux_symbol_validation_job(db, evidence_a, staging_path=staging_a)
        execute_linux_symbol_validation(job_a.id, db=db)

        # Evidence B never gets its own validation job -- Phase 1's
        # unmodified resolve_linux_symbols() already finds the cached,
        # compatible ISF via the identity it was seeded with.
        assert get_linux_symbol_link(db, evidence_b.id) is None
        after = get_preparation_status(db, evidence_b.id)
        assert after.readiness is PreparationState.READY
        assert "already available" in after.human_message


# ---------------------------------------------------------------------------
# get_linux_symbol_validation_status (polling read + lazy reconciliation)
# ---------------------------------------------------------------------------


class TestGetValidationStatus:
    def test_returns_none_for_a_missing_job(self, tmp_path: Path) -> None:
        db = _db()
        _case(db)
        evidence = _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))
        assert get_linux_symbol_validation_status(db, evidence.id, "no-such-id") is None

    def test_returns_the_current_state_for_a_queued_job(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = _db()
        _case(db)
        evidence = _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))
        cache_root = _cache_dir(tmp_path)
        _patch_settings(monkeypatch, _isf_settings(cache_root))
        staging = _write(tmp_path, "s.json", _isf_json(kernel_release="6.8.0-test"))
        job = create_linux_symbol_validation_job(db, evidence, staging_path=staging)

        outcome = get_linux_symbol_validation_status(db, evidence.id, job.id)
        assert outcome.status == STATUS_QUEUED

    def test_a_stale_validating_job_is_reconciled_to_validation_failed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Simulates the memory-worker process itself dying mid-job
        (not just the isolated validation subprocess timing out, which
        already has its own real kill path) -- the row would otherwise
        stay stuck in 'validating' forever. Proves 'restart con job
        persistente': the row survives, and the NEXT read (no separate
        scheduled sweep needed) notices the staleness and terminates it
        cleanly."""
        db = _db()
        _case(db)
        evidence = _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))
        cache_root = _cache_dir(tmp_path)
        settings = _isf_settings(cache_root)
        settings.memory_linux_symbol_validation_timeout_seconds = 1
        settings.memory_linux_symbol_validation_termination_grace_seconds = 1
        _patch_settings(monkeypatch, settings)
        staging = _write(tmp_path, "s.json", _isf_json(kernel_release="6.8.0-test"))
        job = create_linux_symbol_validation_job(db, evidence, staging_path=staging)
        job.status = STATUS_VALIDATING
        job.started_at = utc_now_naive() - timedelta(hours=1)
        db.commit()

        outcome = get_linux_symbol_validation_status(db, evidence.id, job.id)

        assert outcome.status == STATUS_VALIDATION_FAILED
        db.refresh(job)
        assert job.status == STATUS_VALIDATION_FAILED
        assert job.staging_path is None
        assert not staging.exists()

    def test_a_recently_validating_job_is_not_reconciled(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = _db()
        _case(db)
        evidence = _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))
        cache_root = _cache_dir(tmp_path)
        _patch_settings(monkeypatch, _isf_settings(cache_root))
        staging = _write(tmp_path, "s.json", _isf_json(kernel_release="6.8.0-test"))
        job = create_linux_symbol_validation_job(db, evidence, staging_path=staging)
        job.status = STATUS_VALIDATING
        job.started_at = utc_now_naive()
        db.commit()

        outcome = get_linux_symbol_validation_status(db, evidence.id, job.id)

        assert outcome.status == STATUS_VALIDATING


# ---------------------------------------------------------------------------
# Preparation SYMBOLS_REQUIRED -> READY (Phase 1's get_preparation_status
# is untouched -- proves the identity backfill alone is sufficient)
# ---------------------------------------------------------------------------


class TestPreparationFlipsToReady:
    def test_symbols_required_becomes_ready_after_a_valid_job(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = _db()
        _case(db)
        cache_root = _cache_dir(tmp_path)
        _patch_settings(monkeypatch, _isf_settings(cache_root))
        from app.services.memory import analysis_plan as analysis_plan_module
        monkeypatch.setattr(analysis_plan_module, "get_settings", lambda: SimpleNamespace(memory_native_probe_cache_path=cache_root))
        evidence = _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))

        before = get_preparation_status(db, evidence.id)
        assert before.readiness is PreparationState.SYMBOLS_REQUIRED

        staging = _write(tmp_path, "s.json", _isf_json(kernel_release="6.8.0-test"))
        job = create_linux_symbol_validation_job(db, evidence, staging_path=staging)
        execute_linux_symbol_validation(job.id, db=db)

        after = get_preparation_status(db, evidence.id)
        assert after.readiness is PreparationState.READY
        assert after.can_start_analysis is True


# ---------------------------------------------------------------------------
# Route handlers: enqueue-only POST, GET status, evidence scoping.
# ---------------------------------------------------------------------------


def _upload_file(path: Path, filename: str) -> UploadFile:
    return UploadFile(path.open("rb"), filename=filename)


class TestValidateEndpointNeverWritesTheCache:
    def test_route_source_never_calls_cache_writing_functions(self) -> None:
        import ast
        import inspect as py_inspect

        from app.api import routes_memory as module

        source = py_inspect.getsource(module.validate_linux_evidence_symbols)
        tree = ast.parse(source)
        called_names = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        assert "import_linux_isf" not in called_names
        assert "inspect_linux_isf" not in called_names
        assert "validate_and_link_linux_isf" not in called_names  # the old, removed synchronous function


@pytest.mark.anyio
class TestValidateEndpointEnqueue:
    async def test_case_not_found_is_404(self, tmp_path: Path) -> None:
        from app.api.routes_memory import validate_linux_evidence_symbols

        db = _db()
        with pytest.raises(HTTPException) as exc_info:
            await validate_linux_evidence_symbols(
                "no-such-case", EVIDENCE_ID, file=_upload_file(_write(tmp_path, "k.json", _isf_json(kernel_release="6.8.0-test")), "k.json"), db=db,
            )
        assert exc_info.value.status_code == 404

    async def test_windows_evidence_is_rejected_as_wrong_platform(self, tmp_path: Path) -> None:
        from app.api.routes_memory import validate_linux_evidence_symbols

        db = _db()
        _case(db)
        _evidence(db, stored_path=str(_write(tmp_path, "win.dmp", _windows_dump_bytes())), detected_format=None)

        with pytest.raises(HTTPException) as exc_info:
            await validate_linux_evidence_symbols(
                CASE_ID, EVIDENCE_ID, file=_upload_file(_write(tmp_path, "k.json", _isf_json(kernel_release="6.8.0-test")), "k.json"), db=db,
            )
        assert exc_info.value.status_code == 400
        assert exc_info.value.detail["error_code"] == "MEMORY_LINUX_SYMBOLS_WRONG_PLATFORM"

    async def test_disabled_manual_import_is_403(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.api import routes_memory

        db = _db()
        _case(db)
        _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))
        monkeypatch.setattr(routes_memory, "get_settings", lambda: SimpleNamespace(memory_linux_symbol_manual_import_enabled=False))

        with pytest.raises(HTTPException) as exc_info:
            await routes_memory.validate_linux_evidence_symbols(
                CASE_ID, EVIDENCE_ID, file=_upload_file(_write(tmp_path, "k.json", _isf_json(kernel_release="6.8.0-test")), "k.json"), db=db,
            )
        assert exc_info.value.status_code == 403

    async def test_wrong_extension_is_422_without_staging_or_enqueueing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.api import routes_memory
        from app.services.memory import analysis_plan as analysis_plan_module

        db = _db()
        _case(db)
        cache_root = _cache_dir(tmp_path)
        monkeypatch.setattr(routes_memory, "get_settings", lambda: _isf_settings(cache_root))
        monkeypatch.setattr(analysis_plan_module, "get_settings", lambda: SimpleNamespace(memory_native_probe_cache_path=cache_root))
        evidence = _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))

        with pytest.raises(HTTPException) as exc_info:
            await routes_memory.validate_linux_evidence_symbols(
                CASE_ID, EVIDENCE_ID, file=_upload_file(_write(tmp_path, "vmlinux", b"not-an-isf"), "vmlinux"), db=db,
            )
        assert exc_info.value.status_code == 422
        assert get_linux_symbol_link(db, evidence.id) is None

    async def test_valid_extension_enqueues_and_returns_queued(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.api import routes_memory
        from app.services.memory import analysis_plan as analysis_plan_module

        db = _case_and_evidence(tmp_path)
        cache_root = _cache_dir(tmp_path)
        monkeypatch.setattr(routes_memory, "get_settings", lambda: _isf_settings(cache_root))
        monkeypatch.setattr(analysis_plan_module, "get_settings", lambda: SimpleNamespace(memory_native_probe_cache_path=cache_root))
        enqueued: list[str] = []
        monkeypatch.setattr(routes_memory, "enqueue_linux_symbol_validation", lambda job_id: enqueued.append(job_id) or "rq-job-1")

        result = await routes_memory.validate_linux_evidence_symbols(
            CASE_ID, EVIDENCE_ID,
            file=_upload_file(_write(tmp_path, "kernel.json", _isf_json(kernel_release="6.8.0-test")), "kernel.json"),
            db=db,
        )

        assert result["status"] == "queued"
        assert result["validation_id"]
        assert enqueued == [result["validation_id"]]
        job = db.get(MemoryEvidenceLinuxSymbolLink, result["validation_id"])
        assert job.status == STATUS_QUEUED
        assert job.worker_task_id == "rq-job-1"

    async def test_second_submission_while_non_terminal_is_409(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.api import routes_memory
        from app.services.memory import analysis_plan as analysis_plan_module

        db = _case_and_evidence(tmp_path)
        cache_root = _cache_dir(tmp_path)
        monkeypatch.setattr(routes_memory, "get_settings", lambda: _isf_settings(cache_root))
        monkeypatch.setattr(analysis_plan_module, "get_settings", lambda: SimpleNamespace(memory_native_probe_cache_path=cache_root))
        monkeypatch.setattr(routes_memory, "enqueue_linux_symbol_validation", lambda job_id: "rq-job-1")

        await routes_memory.validate_linux_evidence_symbols(
            CASE_ID, EVIDENCE_ID,
            file=_upload_file(_write(tmp_path, "k1.json", _isf_json(kernel_release="6.8.0-test")), "k1.json"), db=db,
        )
        with pytest.raises(HTTPException) as exc_info:
            await routes_memory.validate_linux_evidence_symbols(
                CASE_ID, EVIDENCE_ID,
                file=_upload_file(_write(tmp_path, "k2.json", _isf_json(kernel_release="6.8.0-test")), "k2.json"), db=db,
            )
        assert exc_info.value.status_code == 409

    async def test_valid_upload_then_worker_execution_then_status_poll(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """End-to-end through the real route handlers: POST enqueues,
        the worker function processes it (called directly here, exactly
        as app.workers.tasks.run_linux_symbol_validation would), and GET
        reflects the terminal VALID state."""
        from app.api import routes_memory
        from app.services.memory import analysis_plan as analysis_plan_module

        db = _case_and_evidence(tmp_path)
        cache_root = _cache_dir(tmp_path)
        settings = _isf_settings(cache_root)
        monkeypatch.setattr(routes_memory, "get_settings", lambda: settings)
        monkeypatch.setattr(analysis_plan_module, "get_settings", lambda: SimpleNamespace(memory_native_probe_cache_path=cache_root))
        _patch_settings(monkeypatch, settings)  # execute_linux_symbol_validation reads app.core.config.get_settings() directly
        monkeypatch.setattr(routes_memory, "enqueue_linux_symbol_validation", lambda job_id: "rq-job-1")

        enqueue_result = await routes_memory.validate_linux_evidence_symbols(
            CASE_ID, EVIDENCE_ID,
            file=_upload_file(_write(tmp_path, "kernel.json", _isf_json(kernel_release="6.8.0-test")), "kernel.json"),
            db=db,
        )
        validation_id = enqueue_result["validation_id"]

        pending = routes_memory.get_linux_evidence_symbol_validation(CASE_ID, EVIDENCE_ID, validation_id, db=db)
        assert pending["status"] == STATUS_QUEUED

        execute_linux_symbol_validation(validation_id, db=db)

        final = routes_memory.get_linux_evidence_symbol_validation(CASE_ID, EVIDENCE_ID, validation_id, db=db)
        assert final["status"] == "valid"
        assert final["compatible"] is True
        assert final["detected_identity"]["kernel_release"] == "6.8.0-test"
        assert final["cache_key"] is not None

    async def test_get_status_for_missing_validation_is_404(self, tmp_path: Path) -> None:
        from app.api.routes_memory import get_linux_evidence_symbol_validation

        db = _case_and_evidence(tmp_path)
        with pytest.raises(HTTPException) as exc_info:
            get_linux_evidence_symbol_validation(CASE_ID, EVIDENCE_ID, "no-such-id", db=db)
        assert exc_info.value.status_code == 404


def _case_and_evidence(tmp_path: Path):
    db = _db()
    _case(db)
    _evidence(db, stored_path=str(_write(tmp_path, "linux.img", _linux_dump_bytes())))
    return db
