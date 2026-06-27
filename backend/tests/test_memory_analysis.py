import json
import os
import subprocess
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi import UploadFile
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import routes_evidence
from app.api import routes_memory
from app.core.database import Base
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType, IngestStatus
from app.models.memory import MemoryArtifactSummary, MemoryPluginRun, MemoryScanRun, MemoryUpload
from app.services.memory import backend_readiness
from app.services.memory import execution as memory_execution
from app.services.memory.evidence_access import MemoryStorageAccessError
from app.services.memory import indexing as memory_indexing
from app.services.memory import normalizers as memory_normalizers
from app.services.memory import overview as memory_overview
from app.services.memory import storage as memory_storage
from app.services.memory import upload_readiness
from app.services.memory import upload_capacity
from app.services.memory import upload_lifecycle
from app.services.memory import validation as memory_validation
from app.services.memory import volatility_runner
from app.services.memory import symbol_control
from app.services.memory import worker_capability
from app.core import storage as core_storage
from app.schemas.memory import MemoryStartScanRequest
from app.schemas.memory import MemorySymbolAcquireRequest
from pydantic import ValidationError


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    db = Session()
    try:
        yield db
    finally:
        db.close()


CASE_ID = "aaaaaaaa-1111-4111-8111-111111111111"
MEMORY_EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-222222222222"
DISK_EVIDENCE_ID = "cccccccc-3333-4333-8333-333333333333"


class _UploadSlotStub:
    def __init__(self, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def refresh(self, **_kwargs):
        return None


def _accepted_capacity(size: int, *, phase: str, bytes_already_staged: int = 0):
    return SimpleNamespace(finalization_strategy="atomic_rename", staging_and_final_same_filesystem=True)


def _case(db, case_id: str = CASE_ID, name: str = "Memory Case") -> Case:
    item = Case(id=case_id, name=name)
    db.add(item)
    db.commit()
    return item


def _evidence(db, case_id: str = CASE_ID, evidence_id: str = MEMORY_EVIDENCE_ID, evidence_type=EvidenceType.memory_dump, stored_path: str = "/tmp/evidence") -> Evidence:
    item = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename="memory.mem" if evidence_type == EvidenceType.memory_dump else "disk.evtx",
        stored_path=stored_path,
        original_path=stored_path,
        evidence_type=evidence_type,
        sha256="0" * 64,
        size_bytes=1024,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    db.add(item)
    db.commit()
    return item


def _set_disk_count(monkeypatch: pytest.MonkeyPatch, count: int) -> None:
    monkeypatch.setattr(memory_overview, "count_documents", lambda _index: {"count": count})


def _symbol_settings(tmp_path: Path, **overrides):
    values = {
        "memory_symbol_mode": "offline_only",
        "memory_symbol_managed_download_enabled": False,
        "memory_symbol_network_isolation_ready": False,
        "memory_symbol_admin_authorization_enforced": False,
        "memory_symbol_admin_authorization_required": True,
        "memory_symbol_allowed_hosts": "",
        "memory_symbol_initial_host": "msdl.microsoft.com",
        "memory_symbol_redirect_host_suffixes": [".blob.core.windows.net"],
        "memory_symbol_cache_root": str(tmp_path),
        "memory_symbol_cache_max_bytes": 1024,
    }
    values.update(overrides)
    return SimpleNamespace(
        **values,
        memory_symbol_execution_mode=str(values["memory_symbol_mode"]),
        memory_symbol_hosts=[host for host in str(values["memory_symbol_allowed_hosts"]).split(",") if host],
        memory_symbol_cache_path=Path(values["memory_symbol_cache_root"]),
    )


def test_managed_symbol_acquisition_is_disabled_by_default(tmp_path: Path) -> None:
    accepted, code, _ = symbol_control.acquisition_gate(_symbol_settings(tmp_path))
    assert accepted is False
    assert code == "SYMBOL_ACQUISITION_DISABLED"


def test_managed_symbol_acquisition_requires_deployment_egress_isolation(tmp_path: Path) -> None:
    settings = _symbol_settings(
        tmp_path,
        memory_symbol_mode="managed_download",
        memory_symbol_managed_download_enabled=True,
        memory_symbol_allowed_hosts="msdl.microsoft.com",
    )
    accepted, code, _ = symbol_control.acquisition_gate(settings)
    assert accepted is False
    assert code == symbol_control.NETWORK_ISOLATION_REQUIRED


def test_managed_symbol_acquisition_requires_administrator_authorization(tmp_path: Path) -> None:
    settings = _symbol_settings(
        tmp_path,
        memory_symbol_mode="managed_download",
        memory_symbol_managed_download_enabled=True,
        memory_symbol_network_isolation_ready=True,
        memory_symbol_allowed_hosts="msdl.microsoft.com",
    )
    accepted, code, _ = symbol_control.acquisition_gate(settings)
    assert accepted is False
    assert code == symbol_control.LOCAL_APPROVAL_DISABLED


def test_symbol_acquisition_schema_rejects_operator_url() -> None:
    with pytest.raises(ValidationError):
        MemorySymbolAcquireRequest.model_validate(
            {"authorization_acknowledged": True, "url": "https://example.invalid/symbol.pdb"}
        )


def test_symbol_cache_status_is_bounded_and_does_not_follow_symlinks(tmp_path: Path) -> None:
    (tmp_path / "kernel.json").write_bytes(b"{}")
    outside = tmp_path.parent / "outside-symbol.json"
    outside.write_bytes(b"private")
    (tmp_path / "escape.json").symlink_to(outside)
    result = symbol_control.cache_status(settings=_symbol_settings(tmp_path))
    assert result["total_bytes"] == 2
    assert result["symbol_count"] == 1
    assert "path" not in result


def test_symbol_readiness_requires_recorded_symbols_failure(db_session, tmp_path: Path) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    run = MemoryScanRun(
        case_id=CASE_ID,
        evidence_id=evidence.id,
        profile="metadata_only",
        status="failed",
        error_log={"code": "SYMBOLS_UNAVAILABLE", "message": "sanitized"},
    )
    db_session.add(run)
    db_session.commit()
    result = symbol_control.evidence_symbol_readiness(db_session, CASE_ID, evidence.id, settings=_symbol_settings(tmp_path))
    assert result == {
        "symbols_required": True,
        "symbol_identifier_present": False,
        "acquisition_available": False,
        "acquisition_status": "symbols_required",
        "can_analyze_offline": False,
        "pending_request_id": None,
    }


def test_memory_overview_empty_case(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    _set_disk_count(monkeypatch, 0)

    overview = memory_overview.get_case_memory_overview(db_session, CASE_ID)

    assert overview["mode"] == "empty"
    assert overview["has_memory_evidence"] is False
    assert overview["has_disk_events"] is False


def test_memory_overview_disk_only_case(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    _set_disk_count(monkeypatch, 12)

    overview = memory_overview.get_case_memory_overview(db_session, CASE_ID)

    assert overview["mode"] == "disk_only"
    assert overview["has_disk_events"] is True


def test_memory_overview_memory_only_case(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    _evidence(db_session)
    _set_disk_count(monkeypatch, 0)

    overview = memory_overview.get_case_memory_overview(db_session, CASE_ID)

    assert overview["mode"] == "memory_only"
    assert overview["has_memory_evidence"] is True


def test_memory_overview_hybrid_case(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    _evidence(db_session)
    _set_disk_count(monkeypatch, 4)

    overview = memory_overview.get_case_memory_overview(db_session, CASE_ID)

    assert overview["mode"] == "hybrid"
    assert overview["has_disk_events"] is True
    assert overview["has_memory_evidence"] is True


def test_standard_memory_upload_streams_to_canonical_storage(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    data = b"abc" * 4096
    upload = UploadFile(filename="../authorized.raw", file=BytesIO(data), size=len(data))
    settings = SimpleNamespace(
        backend_data_dir=tmp_path / "data",
        backend_temp_dir=tmp_path / "data" / "tmp",
        memory_upload_enabled=True,
        memory_upload_max_bytes=len(data) + 10,
        memory_upload_chunk_size_bytes=1024,
        memory_upload_extensions={".raw", ".mem", ".vmem", ".dmp", ".lime"},
        memory_upload_staging_path=tmp_path / "data" / "tmp" / "memory-uploads",
        memory_evidence_shared_gid=os.getgid(),
    )
    monkeypatch.setattr(core_storage, "settings", settings)
    monkeypatch.setattr(core_storage, "assert_memory_upload_capacity", _accepted_capacity)
    monkeypatch.setattr(core_storage, "MemoryUploadSlot", _UploadSlotStub)
    monkeypatch.setattr(routes_evidence, "settings", settings)
    monkeypatch.setattr(upload_lifecycle, "get_settings", lambda: settings)
    replace_calls: list[tuple[Path, Path]] = []
    real_replace = core_storage.os.replace
    monkeypatch.setattr(core_storage.os, "replace", lambda source, target: (replace_calls.append((Path(source), Path(target))), real_replace(source, target))[1])
    enqueue_calls: list[str] = []
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda evidence_id: enqueue_calls.append(evidence_id))

    evidence = routes_evidence.upload_evidence(CASE_ID, upload, folder_upload=False, folder_name=None, evidence_intent=None, packaging=None, ingest_mode=None, provided_host="HOSTA", evtx_profile=None, memory_authorization_acknowledged=True, db=db_session)

    assert evidence.evidence_type == EvidenceType.memory_dump
    assert evidence.ingest_status == IngestStatus.completed
    assert evidence.sha256 == core_storage.hashlib.sha256(data).hexdigest()
    assert evidence.size_bytes == len(data)
    assert evidence.original_filename == "authorized.raw"
    assert evidence.stored_path.endswith(f"/evidence/{CASE_ID}/{evidence.id}/original/memory-image.raw")
    assert Path(evidence.stored_path).read_bytes() == data
    assert Path(evidence.stored_path).stat().st_mode & 0o777 == 0o640
    assert Path(evidence.stored_path).parent.stat().st_mode & 0o7777 == 0o2750
    assert Path(evidence.stored_path).stat().st_size == len(data)
    assert not list(settings.memory_upload_staging_path.glob("*.part"))
    assert len(replace_calls) == 1
    assert enqueue_calls == []


def test_memory_upload_rejects_oversized_file_without_evidence(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    upload = UploadFile(filename="too-large.mem", file=BytesIO(b"123456789"), size=9)
    settings = SimpleNamespace(
        backend_data_dir=tmp_path / "data",
        backend_temp_dir=tmp_path / "data" / "tmp",
        memory_upload_enabled=True,
        memory_upload_max_bytes=4,
        memory_upload_chunk_size_bytes=3,
        memory_upload_extensions={".raw", ".mem", ".vmem", ".dmp", ".lime"},
        memory_upload_staging_path=tmp_path / "data" / "tmp" / "memory-uploads",
    )
    monkeypatch.setattr(core_storage, "settings", settings)
    monkeypatch.setattr(core_storage, "assert_memory_upload_capacity", _accepted_capacity)
    monkeypatch.setattr(core_storage, "MemoryUploadSlot", _UploadSlotStub)
    monkeypatch.setattr(routes_evidence, "settings", settings)
    monkeypatch.setattr(upload_lifecycle, "get_settings", lambda: settings)

    with pytest.raises(Exception) as exc_info:
        routes_evidence.upload_evidence(CASE_ID, upload, folder_upload=False, folder_name=None, evidence_intent=None, packaging=None, ingest_mode=None, provided_host="HOSTA", evtx_profile=None, memory_authorization_acknowledged=True, db=db_session)

    assert getattr(exc_info.value, "status_code", None) == 413
    assert db_session.query(Evidence).count() == 0
    assert not list((settings.backend_data_dir / "evidence").rglob("*.mem"))


def test_memory_upload_finalization_capacity_failure_cleans_only_controlled_staging(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    data = b"memory-data"
    upload = UploadFile(filename="authorized.mem", file=BytesIO(data), size=len(data))
    settings = SimpleNamespace(
        backend_data_dir=tmp_path / "data",
        backend_temp_dir=tmp_path / "data" / "tmp",
        memory_upload_enabled=True,
        memory_upload_max_bytes=1024,
        memory_upload_chunk_size_bytes=4,
        memory_upload_extensions={".raw", ".mem", ".vmem", ".dmp", ".lime"},
        memory_upload_staging_path=tmp_path / "data" / "tmp" / "memory-uploads",
    )
    settings.memory_upload_staging_path.mkdir(parents=True)
    unrelated = settings.memory_upload_staging_path / "unrelated.part"
    unrelated.write_bytes(b"keep")
    monkeypatch.setattr(core_storage, "settings", settings)
    monkeypatch.setattr(routes_evidence, "settings", settings)
    monkeypatch.setattr(upload_lifecycle, "get_settings", lambda: settings)
    monkeypatch.setattr(core_storage, "MemoryUploadSlot", _UploadSlotStub)

    def capacity(size: int, *, phase: str, bytes_already_staged: int = 0):
        if phase == "finalization":
            raise upload_capacity.MemoryCapacityError("insufficient_storage", "capacity race")
        return _accepted_capacity(size, phase=phase, bytes_already_staged=bytes_already_staged)

    monkeypatch.setattr(core_storage, "assert_memory_upload_capacity", capacity)

    with pytest.raises(Exception) as exc_info:
        routes_evidence.upload_evidence(CASE_ID, upload, folder_upload=False, folder_name=None, evidence_intent=None, packaging=None, ingest_mode=None, provided_host="HOSTA", evtx_profile=None, memory_authorization_acknowledged=True, db=db_session)

    assert getattr(exc_info.value, "status_code", None) == 507
    assert db_session.query(Evidence).count() == 0
    assert db_session.query(MemoryScanRun).count() == 0
    assert len(list(settings.memory_upload_staging_path.glob("*.memory-upload.part"))) == 1
    assert unrelated.read_bytes() == b"keep"
    assert not list((settings.backend_data_dir / "evidence").rglob("memory-image.mem"))
    assert db_session.query(MemoryUpload).one().retryable is True


def test_memory_upload_registration_failure_preserves_canonical_file_for_recovery(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    data = b"memory-data"
    upload = UploadFile(filename="authorized.mem", file=BytesIO(data), size=len(data))
    settings = SimpleNamespace(
        backend_data_dir=tmp_path / "data",
        backend_temp_dir=tmp_path / "data" / "tmp",
        memory_upload_enabled=True,
        memory_upload_max_bytes=1024,
        memory_upload_chunk_size_bytes=4,
        memory_upload_extensions={".raw", ".mem", ".vmem", ".dmp", ".lime"},
        memory_upload_staging_path=tmp_path / "data" / "tmp" / "memory-uploads",
    )
    monkeypatch.setattr(core_storage, "settings", settings)
    monkeypatch.setattr(routes_evidence, "settings", settings)
    monkeypatch.setattr(upload_lifecycle, "get_settings", lambda: settings)
    monkeypatch.setattr(core_storage, "MemoryUploadSlot", _UploadSlotStub)
    monkeypatch.setattr(core_storage, "assert_memory_upload_capacity", _accepted_capacity)
    monkeypatch.setattr(routes_evidence, "register_memory_evidence", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("database commit failed")))

    with pytest.raises(Exception) as exc_info:
        routes_evidence.upload_evidence(CASE_ID, upload, folder_upload=False, folder_name=None, evidence_intent=None, packaging=None, ingest_mode=None, provided_host="HOSTA", evtx_profile=None, memory_authorization_acknowledged=True, db=db_session)

    assert getattr(exc_info.value, "status_code", None) == 500
    assert db_session.query(Evidence).count() == 0
    assert db_session.query(MemoryScanRun).count() == 0
    assert len(list((settings.backend_data_dir / "evidence").rglob("memory-image.mem"))) == 1
    upload_state = db_session.query(MemoryUpload).one()
    assert upload_state.status == "failed"
    assert upload_state.retryable is True
    recovered = upload_lifecycle.register_memory_evidence(upload_state.id, db=db_session)
    same = upload_lifecycle.register_memory_evidence(upload_state.id, db=db_session)
    assert recovered.id == same.id == upload_state.evidence_id
    assert db_session.query(Evidence).count() == 1


def test_memory_upload_verification_timeout_preserves_complete_staging(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = b"memory-data"
    upload = UploadFile(filename="authorized.mem", file=BytesIO(data), size=len(data))
    settings = SimpleNamespace(
        backend_data_dir=tmp_path / "data",
        backend_temp_dir=tmp_path / "data" / "tmp",
        memory_upload_max_bytes=1024,
        memory_max_upload_size=1024,
        memory_upload_chunk_size_bytes=4,
        memory_upload_extensions={".mem"},
        memory_upload_staging_path=tmp_path / "data" / "tmp" / "memory-uploads",
        memory_upload_verification_timeout_seconds=1,
        memory_upload_finalization_timeout_seconds=1,
    )
    monkeypatch.setattr(core_storage, "settings", settings)
    monkeypatch.setattr(core_storage, "MemoryUploadSlot", _UploadSlotStub)
    monkeypatch.setattr(core_storage, "assert_memory_upload_capacity", _accepted_capacity)
    monotonic_values = iter([0.0, 2.0])
    monkeypatch.setattr(core_storage.time, "monotonic", lambda: next(monotonic_values))

    with pytest.raises(core_storage.MemoryUploadError) as exc_info:
        core_storage.save_memory_upload(CASE_ID, upload, upload_id="dddddddd-4444-4444-8444-444444444444", evidence_id="eeeeeeee-5555-4555-8555-555555555555")

    assert exc_info.value.code == "verification_timeout"
    staged = list(settings.memory_upload_staging_path.glob("*.memory-upload.part"))
    assert len(staged) == 1 and staged[0].read_bytes() == data


def test_memory_upload_finalization_timeout_preserves_valid_canonical(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = b"memory-data"
    upload = UploadFile(filename="authorized.mem", file=BytesIO(data), size=len(data))
    evidence_id = "ffffffff-6666-4666-8666-666666666666"
    settings = SimpleNamespace(
        backend_data_dir=tmp_path / "data",
        backend_temp_dir=tmp_path / "data" / "tmp",
        memory_upload_max_bytes=1024,
        memory_max_upload_size=1024,
        memory_upload_chunk_size_bytes=4,
        memory_upload_extensions={".mem"},
        memory_upload_staging_path=tmp_path / "data" / "tmp" / "memory-uploads",
        memory_upload_verification_timeout_seconds=1,
        memory_upload_finalization_timeout_seconds=1,
    )
    monkeypatch.setattr(core_storage, "settings", settings)
    monkeypatch.setattr(core_storage, "MemoryUploadSlot", _UploadSlotStub)
    monkeypatch.setattr(core_storage, "assert_memory_upload_capacity", _accepted_capacity)
    monotonic_values = iter([0.0, 0.0, 0.0, 0.0, 0.0, 2.0])
    monkeypatch.setattr(core_storage.time, "monotonic", lambda: next(monotonic_values))

    with pytest.raises(core_storage.MemoryUploadError) as exc_info:
        core_storage.save_memory_upload(CASE_ID, upload, upload_id="99999999-7777-4777-8777-777777777777", evidence_id=evidence_id)

    canonical = settings.backend_data_dir / "evidence" / CASE_ID / evidence_id / "original" / "memory-image.mem"
    assert exc_info.value.code == "finalization_timeout"
    assert canonical.read_bytes() == data
    assert not list(settings.memory_upload_staging_path.glob("*.memory-upload.part"))


def test_memory_upload_disabled_rejects_memory_extension(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    upload = UploadFile(filename="memory.mem", file=BytesIO(b"data"))
    settings = SimpleNamespace(
        backend_data_dir=tmp_path / "data",
        backend_temp_dir=tmp_path / "data" / "tmp",
        memory_upload_enabled=False,
        memory_upload_extensions={".raw", ".mem", ".vmem", ".dmp", ".lime"},
    )
    monkeypatch.setattr(core_storage, "settings", settings)
    monkeypatch.setattr(routes_evidence, "settings", settings)

    with pytest.raises(Exception) as exc_info:
        routes_evidence.upload_evidence(CASE_ID, upload, folder_upload=False, folder_name=None, evidence_intent=None, packaging=None, ingest_mode=None, provided_host="HOSTA", evtx_profile=None, db=db_session)

    assert getattr(exc_info.value, "status_code", None) == 403
    assert db_session.query(Evidence).count() == 0


def test_memory_scan_requires_authorization_acknowledgement_when_enabled(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=True, memory_allow_external_tool_execution=True))

    with pytest.raises(Exception) as exc_info:
        routes_memory.start_memory_scan(evidence.id, MemoryStartScanRequest(profile="metadata_only"), case_id=evidence.case_id, db=db_session)

    assert getattr(exc_info.value, "status_code", None) == 400
    assert "Authorization acknowledgement" in str(getattr(exc_info.value, "detail", ""))
    assert db_session.query(MemoryScanRun).count() == 0


def test_memory_scan_disabled_by_default(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=False))

    response = routes_memory.start_memory_scan(evidence.id, MemoryStartScanRequest(authorization_acknowledged=True), case_id=evidence.case_id, db=db_session)

    assert response.status == "disabled"
    assert response.accepted is False
    assert db_session.query(MemoryScanRun).count() == 0


def test_memory_scan_rejects_non_memory_evidence(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session, evidence_id=DISK_EVIDENCE_ID, evidence_type=EvidenceType.evtx)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=True))

    with pytest.raises(Exception) as exc_info:
        routes_memory.start_memory_scan(evidence.id, MemoryStartScanRequest(authorization_acknowledged=True), case_id=evidence.case_id, db=db_session)

    assert getattr(exc_info.value, "status_code", None) == 400


def test_memory_scan_external_execution_disabled_rejects_without_run(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=True, memory_allow_external_tool_execution=False))

    with pytest.raises(Exception) as exc_info:
        routes_memory.start_memory_scan(evidence.id, MemoryStartScanRequest(authorization_acknowledged=True), case_id=evidence.case_id, db=db_session)

    assert getattr(exc_info.value, "status_code", None) == 403
    assert db_session.query(MemoryScanRun).count() == 0


def test_memory_scan_queues_metadata_only_when_enabled(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=True, memory_allow_external_tool_execution=True))
    monkeypatch.setattr(routes_memory, "get_memory_backend_overview", lambda: {"backends": [{"backend": "volatility3", "ready": True}]})
    monkeypatch.setattr(routes_memory, "validate_memory_execution_request", lambda _db, _evidence_id: object())
    monkeypatch.setattr(memory_execution, "validate_memory_execution_request", lambda _db, _evidence_id: SimpleNamespace(evidence=evidence))
    monkeypatch.setattr(routes_memory, "enqueue_memory_metadata_scan", lambda _run_id: "job-1")

    response = routes_memory.start_memory_scan(evidence.id, MemoryStartScanRequest(authorization_acknowledged=True), case_id=evidence.case_id, db=db_session)
    run = db_session.query(MemoryScanRun).one()
    plugin_run = db_session.query(MemoryPluginRun).one()

    assert response.accepted is True
    assert response.status == "queued"
    assert run.profile == "metadata_only"
    assert run.backend == "volatility3"
    assert run.plugin_count == 1
    assert run.worker_task_id == "job-1"
    assert plugin_run.plugin == "windows.info"


def test_memory_profiles_resolve_server_side(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory_execution.backend_readiness, "get_settings", lambda: _backend_settings(memory_process_profile_enabled=True))

    assert memory_execution.resolve_profile_plugins("metadata_only") == ["windows.info"]
    assert memory_execution.resolve_profile_plugins("processes_basic") == ["windows.info", "windows.pslist", "windows.pstree", "windows.cmdline"]
    assert memory_execution.resolve_profile_plugins("processes_extended") == ["windows.info", "windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline"]


def test_process_profile_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory_execution.backend_readiness, "get_settings", lambda: _backend_settings(memory_process_profile_enabled=False))

    with pytest.raises(memory_validation.MemoryExecutionValidationError) as exc_info:
        memory_execution.resolve_profile_plugins("processes_basic")

    assert exc_info.value.code == "PROCESS_PROFILE_DISABLED"


def test_unknown_memory_profile_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory_execution.backend_readiness, "get_settings", lambda: _backend_settings(memory_process_profile_enabled=True))

    with pytest.raises(memory_validation.MemoryExecutionValidationError) as exc_info:
        memory_execution.resolve_profile_plugins("windows.netscan")

    assert exc_info.value.code == "UNKNOWN_PROFILE"


def test_memory_evidence_does_not_create_normalized_events(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=False))

    routes_memory.start_memory_scan(evidence.id, None, case_id=evidence.case_id, db=db_session)

    assert db_session.query(Artifact).filter(Artifact.evidence_id == evidence.id).count() == 0
    assert db_session.query(MemoryArtifactSummary).filter(MemoryArtifactSummary.evidence_id == evidence.id).count() == 0


def test_memory_evidence_does_not_write_to_existing_events_index(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=False))
    monkeypatch.setattr(memory_overview, "count_documents", lambda _index: {"count": 0})

    routes_memory.start_memory_scan(evidence.id, None, case_id=evidence.case_id, db=db_session)
    overview = memory_overview.get_case_memory_overview(db_session, CASE_ID)

    assert overview["has_disk_events"] is False
    assert overview["has_memory_results"] is False


def _backend_settings(**overrides) -> SimpleNamespace:
    values = {
        "memory_analysis_enabled": False,
        "memory_allow_external_tool_execution": False,
        "memory_backend_check_timeout_seconds": 10,
        "memory_backend_status_cache_seconds": 60,
        "preferred_memory_backend": "volatility3",
        "volatility3_command": "vol",
        "memprocfs_command": "memprocfs",
        "allowed_memory_profiles": ["metadata_only", "processes_basic", "processes_extended"],
        "allowed_memory_plugins": ["windows.info", "windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline"],
        "default_memory_profile": "metadata_only",
        "memory_process_profile_enabled": False,
        "memory_max_process_rows": 100000,
        "memory_max_command_line_length": 16384,
        "memory_max_raw_field_length": 65536,
        "memory_execution_mode": "external_command",
        "memory_queue_name": "memory",
        "memory_require_dedicated_worker": True,
        "memory_symbol_network_access_enabled": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _completed(stdout: str = "Volatility 3 Framework 2.8.0\n", stderr: str = "", returncode: int = 0) -> SimpleNamespace:
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


def test_backend_readiness_memory_feature_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(memory_analysis_enabled=False))
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: "/usr/bin/vol")
    monkeypatch.setattr(backend_readiness.subprocess, "run", lambda *_args, **_kwargs: _completed())

    status = backend_readiness.check_volatility3_backend()

    assert status["status"] == "disabled"
    assert status["available"] is True
    assert status["ready"] is False


def test_backend_readiness_external_execution_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(memory_analysis_enabled=True, memory_allow_external_tool_execution=False))
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: "/usr/bin/vol")
    monkeypatch.setattr(backend_readiness.subprocess, "run", lambda *_args, **_kwargs: _completed())

    status = backend_readiness.check_volatility3_backend()

    assert status["status"] == "blocked"
    assert status["available"] is True
    assert status["ready"] is False
    assert "disabled" in status["message"]


def test_backend_readiness_command_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(volatility3_command=""))

    status = backend_readiness.check_volatility3_backend()

    assert status["configured"] is False
    assert status["status"] == "not_configured"
    assert status["error_code"] == "not_configured"


def test_backend_readiness_executable_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(volatility3_command="vol"))
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: None)

    status = backend_readiness.check_volatility3_backend()

    assert status["configured"] is True
    assert status["executable_found"] is False
    assert status["status"] == "not_found"


def test_backend_readiness_executable_found_and_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(memory_analysis_enabled=True, memory_allow_external_tool_execution=True))
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: "/usr/bin/vol")
    monkeypatch.setattr(backend_readiness.subprocess, "run", lambda args, **kwargs: _completed("Volatility 3 Framework 2.8.0\n"))

    status = backend_readiness.check_volatility3_backend()

    assert status["executable_found"] is True
    assert status["available"] is True
    assert status["ready"] is True
    assert status["status"] == "available"
    assert status["version"] == "Volatility 3 Framework 2.8.0"
    assert status["command_display"] == "vol"


def test_backend_readiness_harmless_check_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_timeout(*_args, **_kwargs):
        raise backend_readiness.subprocess.TimeoutExpired(cmd=["vol", "--help"], timeout=1)

    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings())
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: "/usr/bin/vol")
    monkeypatch.setattr(backend_readiness.subprocess, "run", raise_timeout)

    status = backend_readiness.check_volatility3_backend()

    assert status["status"] == "check_failed"
    assert status["error_code"] == "check_timeout"


def test_backend_readiness_harmless_check_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings())
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: "/usr/bin/vol")
    monkeypatch.setattr(backend_readiness.subprocess, "run", lambda *_args, **_kwargs: _completed(stderr="/secret/path failure", returncode=2))

    status = backend_readiness.check_volatility3_backend()

    assert status["status"] == "check_failed"
    assert status["version"] is None


def test_backend_readiness_sanitizes_error_output() -> None:
    assert "/home/alex/secret" not in backend_readiness.sanitize_backend_error("failed at /home/alex/secret/tool")


@pytest.mark.parametrize("command", ["vol --help", "vol;id", "vol|id", "vol && id", "./vol"])
def test_backend_readiness_rejects_suspicious_configured_commands(command: str) -> None:
    configured, executable, display, error = backend_readiness.resolve_configured_executable(command)

    assert configured is False
    assert executable is None
    assert display is not None
    assert error == "invalid_command"


def test_volatility_minimal_environment_preserves_offline_writable_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", "/volatility-cache")

    environment = volatility_runner._minimal_environment()

    assert environment["XDG_CACHE_HOME"] == "/volatility-cache"
    assert environment["VOLATILITY_OFFLINE"] == "1"
    assert "DATABASE_URL" not in environment


def test_backend_readiness_cache_prevents_repeated_subprocess_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    backend_readiness.clear_memory_backend_readiness_cache()
    calls = {"count": 0}

    def fake_run(*_args, **_kwargs):
        calls["count"] += 1
        return _completed()

    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings())
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(backend_readiness.subprocess, "run", fake_run)
    monkeypatch.setattr(backend_readiness.time, "monotonic", lambda: 100.0)

    first = backend_readiness.get_memory_backend_overview()
    second = backend_readiness.get_memory_backend_overview()

    assert first is second
    assert calls["count"] == 2


def test_backend_readiness_cache_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    backend_readiness.clear_memory_backend_readiness_cache()
    calls = {"count": 0}
    now = {"value": 100.0}

    def fake_run(*_args, **_kwargs):
        calls["count"] += 1
        return _completed()

    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(memory_backend_status_cache_seconds=1))
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(backend_readiness.subprocess, "run", fake_run)
    monkeypatch.setattr(backend_readiness.time, "monotonic", lambda: now["value"])

    backend_readiness.get_memory_backend_overview()
    now["value"] = 102.0
    backend_readiness.get_memory_backend_overview()

    assert calls["count"] == 4


def test_backend_readiness_endpoint_does_not_create_runs_or_write_indexes(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    backend_readiness.clear_memory_backend_readiness_cache()
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings())
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: None)

    response = routes_memory.get_memory_backends()

    assert response["ready_backend_count"] == 0
    assert db_session.query(MemoryScanRun).count() == 0


def test_backend_readiness_response_does_not_expose_full_sensitive_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(volatility3_command="/opt/private/tools/vol"))
    monkeypatch.setattr(backend_readiness.Path, "is_file", lambda _self: True)
    monkeypatch.setattr(backend_readiness.subprocess, "run", lambda *_args, **_kwargs: _completed())

    status = backend_readiness.check_volatility3_backend()

    assert status["command_display"] == "vol"
    assert "/opt/private" not in str(status)


def test_memory_validation_rejects_non_regular_file(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence_dir = tmp_path / "data" / "evidence" / CASE_ID / MEMORY_EVIDENCE_ID
    evidence_dir.mkdir(parents=True)
    evidence = _evidence(db_session, stored_path=str(evidence_dir))
    monkeypatch.setattr(memory_validation, "get_settings", lambda: SimpleNamespace(backend_data_dir=tmp_path / "data", allowed_evidence_roots=[] , memory_max_upload_size=10_000))

    with pytest.raises(memory_validation.MemoryExecutionValidationError) as exc_info:
        memory_validation.validate_memory_execution_request(db_session, evidence.id)

    assert exc_info.value.code == "UNSAFE_EVIDENCE_FILE"


def test_memory_validation_accepts_regular_uploaded_file(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence_file = tmp_path / "data" / "evidence" / CASE_ID / MEMORY_EVIDENCE_ID / "original" / "memory.mem"
    evidence_file.parent.mkdir(parents=True)
    evidence_file.write_bytes(b"synthetic")
    evidence = _evidence(db_session, stored_path=str(evidence_file))
    evidence.size_bytes = len(b"synthetic")
    db_session.commit()
    monkeypatch.setattr(memory_validation, "get_settings", lambda: SimpleNamespace(backend_data_dir=tmp_path / "data", allowed_evidence_roots=[] , memory_max_upload_size=10_000))

    validated = memory_validation.validate_memory_execution_request(db_session, evidence.id)

    assert validated.path == evidence_file.resolve()


def test_memory_validation_uses_memory_upload_limit_for_uploaded_file(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence_file = tmp_path / "data" / "evidence" / CASE_ID / MEMORY_EVIDENCE_ID / "original" / "memory.mem"
    evidence_file.parent.mkdir(parents=True)
    evidence_file.write_bytes(b"synthetic")
    evidence = _evidence(db_session, stored_path=str(evidence_file))
    evidence.size_bytes = len(b"synthetic")
    db_session.commit()
    monkeypatch.setattr(
        memory_validation,
        "get_settings",
        lambda: SimpleNamespace(
            backend_data_dir=tmp_path / "data",
            allowed_evidence_roots=[],
            memory_max_upload_size=4,
            memory_upload_max_bytes=10,
        ),
    )

    validated = memory_validation.validate_memory_execution_request(db_session, evidence.id)

    assert validated.size_bytes == len(b"synthetic")


def test_memory_upload_readiness_reports_five_gib_limit_without_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = SimpleNamespace(
        memory_upload_enabled=True,
        memory_upload_max_bytes=5 * 1024 * 1024 * 1024,
        memory_max_upload_size=5 * 1024 * 1024 * 1024,
        memory_upload_staging_path=tmp_path / "data" / "tmp" / "memory-uploads",
        backend_data_dir=tmp_path / "data",
        memory_output_root=None,
        memory_plugin_output_max_bytes=10 * 1024 * 1024,
        memory_upload_extensions={".raw", ".mem", ".vmem", ".dmp", ".lime"},
        memory_analysis_enabled=True,
    )
    monkeypatch.setattr(upload_readiness, "get_settings", lambda: settings)
    monkeypatch.setattr(upload_capacity, "get_settings", lambda: settings)
    monkeypatch.setattr(upload_readiness, "get_memory_backend_overview", lambda: {"backends": [{"backend": "volatility3", "ready": True, "dedicated_worker_online": True}]})
    monkeypatch.setattr(upload_capacity, "_snapshot", lambda _path: upload_capacity.FilesystemSnapshot(device=1, available_bytes=13 * 1024 * 1024 * 1024))

    result = upload_readiness.get_memory_upload_readiness(CASE_ID, selected_size_bytes=5 * 1024 * 1024 * 1024)

    assert result["max_upload_bytes"] == 5368709120
    assert result["max_upload_display"] == "5 GiB"
    assert result["can_accept_selected_size"] is True
    assert ".aff4" not in result["allowed_extensions"]
    assert "/private" not in str(result)
    assert str(tmp_path) not in str(result)


def test_memory_upload_readiness_blocks_insufficient_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = SimpleNamespace(
        memory_upload_enabled=True,
        memory_upload_max_bytes=5 * 1024 * 1024 * 1024,
        memory_max_upload_size=5 * 1024 * 1024 * 1024,
        memory_upload_staging_path=tmp_path / "data" / "tmp" / "memory-uploads",
        backend_data_dir=tmp_path / "data",
        memory_output_root=None,
        memory_plugin_output_max_bytes=10 * 1024 * 1024,
        memory_upload_extensions={".raw", ".mem", ".vmem", ".dmp", ".lime"},
        memory_analysis_enabled=True,
    )
    monkeypatch.setattr(upload_readiness, "get_settings", lambda: settings)
    monkeypatch.setattr(upload_capacity, "get_settings", lambda: settings)
    monkeypatch.setattr(upload_readiness, "get_memory_backend_overview", lambda: {"backends": [{"backend": "volatility3", "ready": True, "dedicated_worker_online": True}]})
    monkeypatch.setattr(upload_capacity, "_snapshot", lambda _path: upload_capacity.FilesystemSnapshot(device=1, available_bytes=7 * 1024 * 1024 * 1024))

    result = upload_readiness.get_memory_upload_readiness(CASE_ID, selected_size_bytes=5 * 1024 * 1024 * 1024)

    assert result["can_accept_selected_size"] is False
    assert result["required_capacity_bytes"] == (5 * 1024 * 1024 * 1024) + upload_capacity.SAFETY_MARGIN_BYTES + upload_capacity.MIN_OUTPUT_ALLOWANCE_BYTES


def test_memory_scan_prevents_duplicate_active_run(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    db_session.add(MemoryScanRun(case_id=CASE_ID, evidence_id=evidence.id, profile="metadata_only", status="running"))
    db_session.commit()
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=True, memory_allow_external_tool_execution=True))
    monkeypatch.setattr(routes_memory, "get_memory_backend_overview", lambda: {"backends": [{"backend": "volatility3", "ready": True}]})
    monkeypatch.setattr(routes_memory, "validate_memory_execution_request", lambda _db, _evidence_id: object())

    with pytest.raises(Exception) as exc_info:
        routes_memory.start_memory_scan(evidence.id, MemoryStartScanRequest(authorization_acknowledged=True), case_id=evidence.case_id, db=db_session)

    assert getattr(exc_info.value, "status_code", None) == 409


def test_volatility_runner_uses_fixed_argv_and_shell_false(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_path = tmp_path / "memory.mem"
    evidence_path.write_bytes(b"synthetic")
    calls: dict = {}
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)

    class FakeProcess:
        pid = 12345
        returncode = 0

        def communicate(self, timeout):
            calls["timeout"] = timeout
            return b'{"Kernel Base":"0xf8000000"}', b""

    def fake_popen(args, **kwargs):
        calls["args"] = args
        calls["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(volatility_runner, "get_settings", lambda: SimpleNamespace(volatility3_command="vol", memory_plugin_timeout_seconds=5, memory_plugin_output_max_bytes=10_000))
    monkeypatch.setattr(volatility_runner, "resolve_configured_executable", lambda _command: (True, "/usr/bin/vol", "vol", None))
    monkeypatch.setattr(volatility_runner.subprocess, "Popen", fake_popen)

    result = volatility_runner.run_windows_info(evidence_path, tmp_path)

    assert calls["args"] == ["/usr/bin/vol", "--offline", "-f", str(evidence_path), "-r", "json", "windows.info"]
    assert calls["kwargs"]["shell"] is False
    assert result.argv_display == ["vol", "--offline", "-f", "[evidence]", "-r", "json", "windows.info"]


def test_volatility_runner_uses_fixed_process_plugin_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_path = tmp_path / "memory.mem"
    evidence_path.write_bytes(b"synthetic")
    calls: dict = {}
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)

    class FakeProcess:
        pid = 12345
        returncode = 0

        def communicate(self, timeout):
            return b"[]", b""

    monkeypatch.setattr(volatility_runner, "get_settings", lambda: SimpleNamespace(volatility3_command="vol", memory_plugin_timeout_seconds=5, memory_plugin_output_max_bytes=10_000))
    monkeypatch.setattr(volatility_runner, "resolve_configured_executable", lambda _command: (True, "/usr/bin/vol", "vol", None))
    monkeypatch.setattr(volatility_runner.subprocess, "Popen", lambda args, **kwargs: calls.update({"args": args, "kwargs": kwargs}) or FakeProcess())

    volatility_runner.run_plugin("windows.pslist", evidence_path, tmp_path)

    assert calls["args"] == ["/usr/bin/vol", "--offline", "-f", str(evidence_path), "-r", "json", "windows.pslist"]
    assert calls["kwargs"]["shell"] is False


def test_volatility_runner_rejects_unallowed_plugin(tmp_path: Path) -> None:
    with pytest.raises(volatility_runner.VolatilityRunnerError) as exc_info:
        volatility_runner.build_plugin_argv("/usr/bin/vol", tmp_path / "memory.mem", "windows.cachedump")

    assert exc_info.value.code == "PLUGIN_NOT_ALLOWED"


def test_volatility_runner_uses_server_controlled_offline_symbol_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_path = tmp_path / "memory.mem"
    evidence_path.write_bytes(b"synthetic")
    cache_root = tmp_path / "cache"
    calls: dict = {}

    class FakeProcess:
        pid = 12345
        returncode = 0

        def communicate(self, timeout):
            return b"{}", b""

    monkeypatch.setenv("XDG_CACHE_HOME", str(cache_root))
    monkeypatch.setattr(volatility_runner, "get_settings", lambda: SimpleNamespace(volatility3_command="vol", memory_plugin_timeout_seconds=5, memory_plugin_output_max_bytes=10_000, memory_symbol_network_access_enabled=False))
    monkeypatch.setattr(volatility_runner, "resolve_configured_executable", lambda _command: (True, "/usr/bin/vol", "vol", None))
    monkeypatch.setattr(volatility_runner.subprocess, "Popen", lambda args, **kwargs: calls.update({"args": args}) or FakeProcess())

    volatility_runner.run_windows_info(evidence_path, tmp_path / "work")

    assert calls["args"][:6] == ["/usr/bin/vol", "--offline", "--cache-path", str(cache_root / "volatility3"), "--symbol-dirs", str(cache_root / "volatility3" / "symbols")]
    assert (cache_root / "volatility3" / "symbols").is_dir()


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        (b"Unable to validate the plugin requirements: ['plugins.Info.kernel.symbol_table_name']", "SYMBOLS_UNAVAILABLE"),
        (b"Unable to validate plugin requirement", "PLUGIN_REQUIREMENTS_UNSATISFIED"),
        (b"No suitable translation layer was found", "UNSUPPORTED_MEMORY_IMAGE"),
        (b"Unable to validate layer requirement", "INVALID_MEMORY_LAYER"),
        (b"OSError: [Errno 30] Read-only file system while preparing symbol PDB", "MEMORY_SYMBOL_CACHE_NOT_WRITABLE"),
    ],
)
def test_volatility_failure_classification(stderr: bytes, expected: str) -> None:
    assert volatility_runner._classify_failure(stderr)[0] == expected


def test_volatility_runner_timeout_terminates_process_group(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_path = tmp_path / "memory.mem"
    evidence_path.write_bytes(b"synthetic")
    signals: list[int] = []

    class FakeProcess:
        pid = 12345
        returncode = None

        def communicate(self, timeout):
            raise subprocess.TimeoutExpired(cmd=["vol"], timeout=timeout)

        def wait(self, timeout):
            raise TimeoutError()

        def kill(self):
            signals.append(9)

    monkeypatch.setattr(volatility_runner, "get_settings", lambda: SimpleNamespace(volatility3_command="vol", memory_plugin_timeout_seconds=1, memory_plugin_output_max_bytes=10_000))
    monkeypatch.setattr(volatility_runner, "resolve_configured_executable", lambda _command: (True, "/usr/bin/vol", "vol", None))
    monkeypatch.setattr(volatility_runner.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    monkeypatch.setattr(volatility_runner.os, "killpg", lambda _pid, sig: signals.append(sig))

    with pytest.raises(volatility_runner.VolatilityRunnerError) as exc_info:
        volatility_runner.run_windows_info(evidence_path, tmp_path)

    assert exc_info.value.code == "PLUGIN_TIMEOUT"
    assert signals


def test_volatility_runner_output_size_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_path = tmp_path / "memory.mem"
    evidence_path.write_bytes(b"synthetic")

    class FakeProcess:
        pid = 12345
        returncode = 0

        def communicate(self, timeout):
            return b"x" * 20, b""

    monkeypatch.setattr(volatility_runner, "get_settings", lambda: SimpleNamespace(volatility3_command="vol", memory_plugin_timeout_seconds=1, memory_plugin_output_max_bytes=10))
    monkeypatch.setattr(volatility_runner, "resolve_configured_executable", lambda _command: (True, "/usr/bin/vol", "vol", None))
    monkeypatch.setattr(volatility_runner.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())

    with pytest.raises(volatility_runner.VolatilityRunnerError) as exc_info:
        volatility_runner.run_windows_info(evidence_path, tmp_path)

    assert exc_info.value.code == "OUTPUT_TOO_LARGE"


def test_windows_info_normalizer_handles_missing_fields() -> None:
    document = memory_normalizers.normalize_windows_info(
        [
            {"Variable": "Kernel Base", "Value": "0xf8000000", "__children": []},
            {"Variable": "MachineType", "Value": "34404", "__children": []},
        ],
        case_id=CASE_ID,
        evidence_id=MEMORY_EVIDENCE_ID,
        memory_run_id="run-1",
        memory_plugin_run_id="plugin-1",
        backend_version="Volatility 3 Framework 2.8.0",
    )

    assert document["memory_artifact_type"] == "memory_system_info"
    assert document["plugin"] == "windows.info"
    assert document["os"]["kernel_base"] == "0xf8000000"
    assert document["os"]["machine_type"] == "x64"
    assert document["memory"]["dtb"] is None


def test_process_normalizers_merge_pslist_pstree_psscan_cmdline() -> None:
    pslist = memory_normalizers.normalize_windows_pslist([
        {"PID": 4, "PPID": 0, "ImageFileName": "System", "Offset(V)": "0x1000"},
        {"PID": 1000, "PPID": 4, "ImageFileName": "sample-app.exe", "Offset(V)": "0x2000", "CreateTime": "2026-06-16T00:00:00Z"},
    ])
    pstree = memory_normalizers.normalize_windows_pstree([
        {"PID": 1000, "PPID": 4, "Name": "sample-app.exe", "Offset(V)": "0x2000", "CreateTime": "2026-06-16T00:00:00Z"},
    ])
    psscan = memory_normalizers.normalize_windows_psscan([
        {"PID": 2000, "PPID": 1000, "ImageFileName": "finished-task.exe", "Offset(P)": "0x3000", "ExitTime": "2026-06-16T00:05:00Z"},
    ])
    cmdline = memory_normalizers.normalize_windows_cmdline([
        {"PID": 1000, "Args": "C:\\\\Program Files\\\\Example\\\\sample-app.exe --safe-mode", "Offset(V)": "0x2000", "CreateTime": "2026-06-16T00:00:00Z"},
    ])

    merged = memory_normalizers.merge_memory_process_results([pslist, pstree, psscan, cmdline], case_id=CASE_ID, evidence_id=MEMORY_EVIDENCE_ID, memory_run_id="run-1")

    assert len(merged["processes"]) == 3
    sample = next(item for item in merged["processes"] if item["process"]["pid"] == 1000)
    assert sample["process"]["command_line"].endswith("--safe-mode")
    assert sample["visibility"]["pslist"] is True
    assert sample["visibility"]["pstree"] is True
    scanned_only = next(item for item in merged["processes"] if item["process"]["pid"] == 2000)
    assert scanned_only["visibility"]["psscan"] is True
    assert scanned_only["state"]["hidden_candidate"] is False
    assert "not_present_in_pslist_result" in scanned_only["warnings"]
    assert len(merged["edges"]) == 1


def test_process_normalizer_invalid_pid_warns() -> None:
    normalized = memory_normalizers.normalize_windows_pslist([{"PID": "not-a-pid", "ImageFileName": "example.exe"}])

    assert normalized["processes"] == []
    assert "missing_or_invalid_pid" in normalized["warnings"]


def test_execution_indexing_failure_retains_raw_output(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence_file = tmp_path / "data" / "evidence" / CASE_ID / MEMORY_EVIDENCE_ID / "original" / "memory.mem"
    evidence_file.parent.mkdir(parents=True)
    evidence_file.write_bytes(b"synthetic")
    evidence = _evidence(db_session, stored_path=str(evidence_file))
    run = MemoryScanRun(case_id=CASE_ID, evidence_id=evidence.id, backend="volatility3", profile="metadata_only", status="queued", requested_plugin_count=1, plugin_count=1)
    db_session.add(run)
    db_session.commit()
    db_session.add(MemoryPluginRun(memory_scan_run_id=run.id, case_id=CASE_ID, evidence_id=evidence.id, plugin="windows.info", status="pending"))
    db_session.commit()

    class SessionContext:
        def __enter__(self):
            return db_session

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(memory_execution, "SessionLocal", lambda: SessionContext())
    monkeypatch.setattr(memory_execution, "validate_memory_execution_request", lambda _db, _evidence_id: SimpleNamespace(evidence=evidence, path=evidence_file, size_bytes=evidence_file.stat().st_size))
    monkeypatch.setattr(memory_execution.backend_readiness, "check_volatility3_backend", lambda: {"ready": True, "version": "Volatility 3 Framework 2.8.0"})
    valid_windows_info = [
        {"Variable": "Kernel Base", "Value": "0xf8000000", "__children": []},
        {"Variable": "NtMajorVersion", "Value": "10", "__children": []},
        {"Variable": "NtMinorVersion", "Value": "0", "__children": []},
        {"Variable": "MachineType", "Value": "34404", "__children": []},
    ]
    monkeypatch.setattr(memory_execution, "run_plugin", lambda _plugin, _path, _work_dir: SimpleNamespace(argv_display=["vol", "-f", "[evidence]", "-r", "json", "windows.info"], stdout=json.dumps(valid_windows_info).encode("utf-8"), stderr=b"", duration_ms=7))
    monkeypatch.setattr(memory_execution, "index_memory_system_info", lambda _case_id, _document: (_ for _ in ()).throw(RuntimeError("/secret/index failed")))
    monkeypatch.setattr(memory_execution, "memory_run_dir", lambda _case_id, _evidence_id, run_id: tmp_path / "data" / "evidence" / CASE_ID / MEMORY_EVIDENCE_ID / "memory" / "runs" / run_id)
    monkeypatch.setattr(memory_execution, "relative_to_data_dir", lambda path: str(path.relative_to(tmp_path / "data")))
    monkeypatch.setattr(memory_execution, "write_atomic_bytes", lambda path, data, **_kwargs: {"path": str(path.relative_to(tmp_path / "data")), "sha256": "a" * 64, "size": len(data)})
    monkeypatch.setattr(memory_execution, "write_atomic_json", lambda path, payload, **_kwargs: {"path": str(path.relative_to(tmp_path / "data")), "sha256": "b" * 64, "size": 12})

    memory_execution.run_memory_metadata_scan(run.id)
    db_session.refresh(run)
    plugin_run = db_session.query(MemoryPluginRun).filter(MemoryPluginRun.memory_scan_run_id == run.id).one()

    assert run.status == "completed_with_errors"
    assert run.error_log["code"] == "INDEXING_FAILED"
    assert plugin_run.status == "completed"
    assert plugin_run.output_sha256
    assert "/secret" not in run.error_log["message"]


def test_output_permission_failure_stops_before_plugin_execution(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence_file = tmp_path / "data" / "evidence" / CASE_ID / MEMORY_EVIDENCE_ID / "original" / "memory.mem"
    evidence_file.parent.mkdir(parents=True)
    evidence_file.write_bytes(b"synthetic")
    evidence = _evidence(db_session, stored_path=str(evidence_file))
    run = MemoryScanRun(case_id=CASE_ID, evidence_id=evidence.id, backend="volatility3", profile="metadata_only", status="queued", requested_plugin_count=1, plugin_count=1)
    db_session.add(run)
    db_session.commit()
    plugin_run = MemoryPluginRun(memory_scan_run_id=run.id, case_id=CASE_ID, evidence_id=evidence.id, plugin="windows.info", status="pending")
    db_session.add(plugin_run)
    db_session.commit()

    class SessionContext:
        def __enter__(self):
            return db_session

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(memory_execution, "SessionLocal", lambda: SessionContext())
    monkeypatch.setattr(memory_execution, "validate_memory_execution_request", lambda _db, _evidence_id: SimpleNamespace(evidence=evidence, path=evidence_file, size_bytes=evidence_file.stat().st_size))
    monkeypatch.setattr(memory_execution.backend_readiness, "check_volatility3_backend", lambda: {"ready": True, "version": "Volatility 3 Framework 2.28.0"})
    monkeypatch.setattr(memory_execution, "validate_current_process_output_access", lambda: (_ for _ in ()).throw(MemoryStorageAccessError("MEMORY_OUTPUT_PERMISSION_DENIED", "The memory worker cannot write isolated analysis output.")))
    monkeypatch.setattr(memory_execution, "run_plugin", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("plugin must not start")))

    memory_execution.run_memory_metadata_scan(run.id)
    db_session.refresh(run)
    db_session.refresh(plugin_run)

    assert run.status == "failed"
    assert run.error_log["code"] == "MEMORY_OUTPUT_PERMISSION_DENIED"
    assert run.plugins_completed == 0
    assert run.plugins_failed == 0
    assert plugin_run.status == "pending"


def test_windows_info_failure_marks_one_failed_and_later_plugins_skipped(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence_file = tmp_path / "memory.mem"
    evidence_file.write_bytes(b"synthetic")
    evidence = _evidence(db_session, stored_path=str(evidence_file))
    run = MemoryScanRun(case_id=CASE_ID, evidence_id=evidence.id, backend="volatility3", profile="processes_basic", status="queued", requested_plugin_count=4, plugin_count=4, metadata_json={"plugins": ["windows.info", "windows.pslist", "windows.pstree", "windows.cmdline"]})
    db_session.add(run)
    db_session.commit()
    for plugin in ["windows.info", "windows.pslist", "windows.pstree", "windows.cmdline"]:
        db_session.add(MemoryPluginRun(memory_scan_run_id=run.id, case_id=CASE_ID, evidence_id=evidence.id, plugin=plugin, status="pending"))
    db_session.commit()

    class SessionContext:
        def __enter__(self):
            return db_session

        def __exit__(self, *_args):
            return False

    calls: list[str] = []
    monkeypatch.setattr(memory_execution, "SessionLocal", lambda: SessionContext())
    monkeypatch.setattr(memory_execution, "validate_memory_execution_request", lambda _db, _id: SimpleNamespace(evidence=evidence, path=evidence_file, size_bytes=evidence_file.stat().st_size))
    monkeypatch.setattr(memory_execution, "validate_current_process_output_access", lambda: tmp_path)
    monkeypatch.setattr(memory_execution.backend_readiness, "check_volatility3_backend", lambda: {"ready": True, "version": "Volatility 3 Framework 2.28.0"})
    monkeypatch.setattr(memory_execution, "memory_run_dir", lambda *_args: tmp_path / "run")
    monkeypatch.setattr(memory_execution, "relative_to_data_dir", lambda _path: "memory-output/run")
    monkeypatch.setattr(memory_execution, "write_atomic_json", lambda *_args, **_kwargs: {})

    def fail_info(plugin, *_args):
        calls.append(plugin)
        raise volatility_runner.VolatilityRunnerError("SYMBOLS_UNAVAILABLE", "windows.info could not resolve required symbols.", stderr=b"symbol requirement", return_code=1, stdout_length=0, stderr_length=18)

    monkeypatch.setattr(memory_execution, "run_plugin", fail_info)

    memory_execution.run_memory_metadata_scan(run.id)
    db_session.refresh(run)
    plugin_runs = {item.plugin: item for item in db_session.query(MemoryPluginRun).filter(MemoryPluginRun.memory_scan_run_id == run.id).all()}

    assert calls == ["windows.info"]
    assert run.status == "failed"
    assert run.plugins_completed == 0
    assert run.plugins_failed == 1
    assert run.error_log["code"] == "SYMBOLS_UNAVAILABLE"
    assert plugin_runs["windows.info"].status == "failed"
    assert plugin_runs["windows.info"].metadata_json["return_code"] == 1
    assert {plugin_runs[name].status for name in ("windows.pslist", "windows.pstree", "windows.cmdline")} == {"skipped_dependency"}
    assert run.plugins_skipped == 3


def test_invalid_volatility_json_is_classified_before_normalization(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session, stored_path=str(tmp_path / "memory.mem"))
    run = MemoryScanRun(case_id=CASE_ID, evidence_id=evidence.id, backend="volatility3", profile="metadata_only", status="running")
    db_session.add(run)
    db_session.commit()
    plugin_run = MemoryPluginRun(memory_scan_run_id=run.id, case_id=CASE_ID, evidence_id=evidence.id, plugin="windows.info", status="pending")
    db_session.add(plugin_run)
    db_session.commit()
    monkeypatch.setattr(memory_execution, "run_plugin", lambda *_args: SimpleNamespace(stdout=b"not-json", stderr=b"", duration_ms=4, argv_display=["vol", "windows.info"]))
    monkeypatch.setattr(memory_execution, "write_atomic_bytes", lambda *_args, **_kwargs: {"path": "raw.json", "sha256": "a" * 64, "size": 8})

    with pytest.raises(volatility_runner.VolatilityRunnerError) as exc_info:
        memory_execution._execute_plugin(db_session, run, plugin_run, "windows.info", tmp_path / "memory.mem", tmp_path)

    assert exc_info.value.code == "VOLATILITY_OUTPUT_INVALID"
    assert exc_info.value.return_code == 0


def test_indexing_uses_memory_index_only(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {}

    class Indices:
        def exists(self, index):
            calls["exists"] = index
            return True

    class Client:
        indices = Indices()

        def index(self, index, id, body, refresh):
            calls["index"] = index
            calls["id"] = id
            calls["body"] = body
            return {"_id": id, "result": "created"}

    monkeypatch.setattr(memory_indexing, "get_opensearch_client", lambda: Client())

    memory_indexing.index_memory_system_info(CASE_ID, {"memory_plugin_run_id": "plugin-1", "memory_run_id": "run-1"})

    assert calls["index"] == f"dfir-memory-{CASE_ID}"


def test_dedicated_worker_readiness_does_not_require_backend_vol(monkeypatch: pytest.MonkeyPatch) -> None:
    class RedisStub:
        @classmethod
        def from_url(cls, _url):
            return cls()

        def ping(self):
            return True

    capability = {
        "healthy": True,
        "queue": "memory",
        "volatility_version": "Volatility 3 Framework 2.28.0",
        "supported_profiles": ["metadata_only", "processes_basic", "processes_extended"],
        "supported_plugins": ["windows.info", "windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline"],
        "symbol_network_enabled": False,
    }
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(memory_execution_mode="dedicated_worker", memory_analysis_enabled=True, memory_allow_external_tool_execution=True, memory_process_profile_enabled=True, redis_url="redis://redis:6379/0"))
    monkeypatch.setattr(backend_readiness, "Redis", RedisStub)
    monkeypatch.setattr(backend_readiness, "list_memory_worker_capabilities", lambda _redis: [capability])
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: None)

    status = backend_readiness.check_volatility3_backend()

    assert status["ready"] is True
    assert status["execution_mode"] == "dedicated_worker"
    assert status["dedicated_worker_online"] is True
    assert status["backend_version"] == "Volatility 3 Framework 2.28.0"


def test_dedicated_worker_offline_is_not_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    class RedisStub:
        @classmethod
        def from_url(cls, _url):
            return cls()

        def ping(self):
            return True

    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(memory_execution_mode="dedicated_worker", memory_analysis_enabled=True, memory_allow_external_tool_execution=True, redis_url="redis://redis:6379/0"))
    monkeypatch.setattr(backend_readiness, "Redis", RedisStub)
    monkeypatch.setattr(backend_readiness, "list_memory_worker_capabilities", lambda _redis: [])

    status = backend_readiness.check_volatility3_backend()

    assert status["ready"] is False
    assert status["dedicated_worker_online"] is False
    assert status["error_code"] == "memory_worker_offline"


def test_external_mode_observes_optional_memory_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    class RedisStub:
        @classmethod
        def from_url(cls, _url):
            return cls()

        def ping(self):
            return True

    capability = {
        "healthy": True,
        "queue": "memory",
        "volatility_version": "Volatility 3 Framework 2.28.0",
        "supported_profiles": ["metadata_only"],
        "supported_plugins": ["windows.info"],
        "symbol_network_enabled": False,
    }
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(memory_execution_mode="external_command", memory_analysis_enabled=False, redis_url="redis://redis:6379/0"))
    monkeypatch.setattr(backend_readiness, "Redis", RedisStub)
    monkeypatch.setattr(backend_readiness, "list_memory_worker_capabilities", lambda _redis: [capability])
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: None)

    status = backend_readiness.check_volatility3_backend()

    assert status["ready"] is False
    assert status["status"] == "not_found"
    assert status["dedicated_worker_online"] is True
    assert status["backend_version"] == "Volatility 3 Framework 2.28.0"


def test_memory_worker_capability_prefers_installed_package_version(monkeypatch: pytest.MonkeyPatch) -> None:
    class Result:
        returncode = 0
        stdout = "Change the default path (/volatility-cache)\n"
        stderr = ""

    monkeypatch.setattr(worker_capability, "get_settings", lambda: _backend_settings(volatility3_command="vol"))
    monkeypatch.setattr(worker_capability.shutil, "which", lambda _command: "/usr/local/bin/vol")
    monkeypatch.setattr(worker_capability.subprocess, "run", lambda *_args, **_kwargs: Result())
    monkeypatch.setattr(worker_capability.metadata, "version", lambda package: "2.28.0" if package == "volatility3" else None)

    capability = worker_capability.build_memory_worker_capability()

    assert capability["healthy"] is True
    assert capability["volatility_version"] == "Volatility 3 Framework 2.28.0"


def test_memory_enqueue_uses_dedicated_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.workers import tasks as worker_tasks

    calls = []

    class QueueStub:
        def __init__(self, name):
            self.name = name

        def enqueue(self, func_name, run_id, job_timeout):
            calls.append((self.name, func_name, run_id, job_timeout))
            return SimpleNamespace(id=f"{self.name}-job")

    monkeypatch.setattr(worker_tasks, "settings", SimpleNamespace(memory_execution_mode="dedicated_worker", memory_job_timeout_seconds=900))
    monkeypatch.setattr(worker_tasks, "memory_queue", QueueStub("memory"))
    monkeypatch.setattr(worker_tasks, "analysis_queue", QueueStub("dfir-analysis"))

    job_id = worker_tasks.enqueue_memory_metadata_scan("run-1")

    assert job_id == "memory-job"
    assert calls == [("memory", "app.workers.tasks.run_memory_metadata_scan", "run-1", 900)]


def test_memory_output_dir_relative_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    output_root = tmp_path / "memory-output"
    monkeypatch.setattr(memory_storage, "get_settings", lambda: SimpleNamespace(backend_data_dir=tmp_path / "data", memory_output_root=output_root, memory_plugin_output_max_bytes=1024))

    run_dir = memory_storage.memory_run_dir(CASE_ID, MEMORY_EVIDENCE_ID, "run-1")
    info = memory_storage.write_atomic_bytes(run_dir / "windows.info.json", b"{}")

    assert info["path"] == f"memory-output/evidence/{CASE_ID}/{MEMORY_EVIDENCE_ID}/memory/runs/run-1/windows.info.json"


def test_renormalize_canonical_entities_rejects_foreign_evidence_run(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    case = _case(db_session)
    ev_a = _evidence(db_session, case_id=case.id, evidence_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    ev_b = _evidence(db_session, case_id=case.id, evidence_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    run_b = MemoryScanRun(case_id=case.id, evidence_id=ev_b.id, profile="processes_basic", status="completed")
    db_session.add(run_b)
    db_session.commit()
    called = {"fetch": 0}
    monkeypatch.setattr(routes_memory.canonical_entities, "fetch_legacy_process_documents", lambda *_a, **_k: called.__setitem__("fetch", called["fetch"] + 1) or [])
    with pytest.raises(HTTPException) as exc:
        routes_memory.renormalize_canonical_entities(case.id, ev_a.id, routes_memory._RenormalizeRequest(run_id=run_b.id, dry_run=True), db_session)
    assert exc.value.status_code == 404
    assert called["fetch"] == 0


def test_renormalize_canonical_entities_accepts_matching_evidence_run(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    case = _case(db_session)
    ev_a = _evidence(db_session, case_id=case.id, evidence_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    run_a = MemoryScanRun(case_id=case.id, evidence_id=ev_a.id, profile="processes_basic", status="completed")
    db_session.add(run_a)
    db_session.commit()
    monkeypatch.setattr(routes_memory.canonical_entities, "fetch_legacy_process_documents", lambda *_a, **_k: [{"id": "doc-1"}])
    monkeypatch.setattr(routes_memory.canonical_entities, "renormalize_documents", lambda *_a, **_k: {"summary": {"source_documents": 1, "normalization_version": "v1"}})
    payload = routes_memory.renormalize_canonical_entities(case.id, ev_a.id, routes_memory._RenormalizeRequest(run_id=run_a.id, dry_run=True), db_session)
    assert payload["materialization_status"] == "dry_run"


def test_recompute_canonical_tree_rejects_foreign_case_or_evidence_run_without_opensearch_calls(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    case_a = _case(db_session, case_id="aaaaaaaa-1111-4111-8111-111111111111")
    case_b = _case(db_session, case_id="bbbbbbbb-2222-4222-8222-222222222222")
    ev_a = _evidence(db_session, case_id=case_a.id, evidence_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    ev_b = _evidence(db_session, case_id=case_a.id, evidence_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    ev_c = _evidence(db_session, case_id=case_b.id, evidence_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    run_b = MemoryScanRun(case_id=case_a.id, evidence_id=ev_b.id, profile="processes_basic", status="completed")
    run_c = MemoryScanRun(case_id=case_b.id, evidence_id=ev_c.id, profile="processes_basic", status="completed")
    db_session.add_all([run_b, run_c])
    db_session.commit()
    called = {"fetch": 0, "client": 0}
    monkeypatch.setattr(routes_memory.canonical_entities, "fetch_canonical_entities", lambda *_a, **_k: called.__setitem__("fetch", called["fetch"] + 1) or {"items": []})
    monkeypatch.setattr(routes_memory, "get_opensearch_client", lambda: called.__setitem__("client", called["client"] + 1), raising=False)
    for bad_run in (run_b.id, run_c.id, "dddddddd-dddd-4ddd-8ddd-dddddddddddd"):
        with pytest.raises(HTTPException) as exc:
            routes_memory.recompute_canonical_tree(case_a.id, ev_a.id, routes_memory._RenormalizeRequest(run_id=bad_run, dry_run=True), db_session)
        assert exc.value.status_code == 404
    assert called["fetch"] == 0
    assert called["client"] == 0
