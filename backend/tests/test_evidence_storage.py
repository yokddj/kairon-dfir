from pathlib import Path
from types import SimpleNamespace
from datetime import UTC, datetime

from fastapi import UploadFile

from app.api import routes_evidence
from app.core import evidence_paths as evidence_paths_module
from app.core import storage as storage_module
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.schemas.evidence import EvidenceRead
from app.schemas.debug_export import DebugExportRequest
from app.services.debug_export import _DebugPackContext
from app.services.debug_export import _build_ingest_summary


class FakeSession:
    def __init__(self, case: Case | None = None, evidence: Evidence | None = None, artifacts: list | None = None):
        self.case = case
        self.evidence = evidence
        self.artifacts = artifacts or []
        self.deleted = []

    def get(self, model, key):
        if model is Case and self.case and self.case.id == key:
            return self.case
        if model is Evidence and self.evidence and self.evidence.id == key:
            return self.evidence
        return None

    def add(self, value):
        if isinstance(value, Evidence):
            self.evidence = value

    def commit(self):
        return None

    def refresh(self, _value):
        return None

    def delete(self, value):
        self.deleted.append(value)
        if isinstance(value, Evidence) and self.evidence and value.id == self.evidence.id:
            self.evidence = None

    def query(self, _model):
        class _FakeQuery:
            def filter(self, *_args, **_kwargs):
                return self

            def update(self, *_args, **_kwargs):
                return 0

            def delete(self, *_args, **_kwargs):
                return 0

            def all(inner_self):  # noqa: ANN001
                return list(getattr(self, "artifacts", []))

        return _FakeQuery()


def _patch_allowed_roots(monkeypatch, tmp_path: Path):
    allowed_root = tmp_path / "evidence"
    allowed_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(evidence_paths_module.settings, "dfir_allow_host_path_import", True)
    monkeypatch.setattr(evidence_paths_module.settings, "dfir_allowed_evidence_roots", str(allowed_root))
    monkeypatch.setattr(storage_module.settings, "backend_data_dir", tmp_path / "appdata")
    monkeypatch.setattr(routes_evidence.settings, "backend_data_dir", tmp_path / "appdata")
    return allowed_root


def test_recompute_evidence_status_marks_searchable_failed_evidence_ready(monkeypatch):
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="HOSTA.7z",
        stored_path="/tmp/HOSTA.7z",
        evidence_type=EvidenceType.raw_collection,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256="a" * 64,
        size_bytes=1,
        ingest_status=IngestStatus.failed,
        metadata_json={
            "warnings": ["host_identity_skipped_for_parallel_bulk"],
            "error_log": {"fatal_type": "infrastructure_blocked_opensearch", "fatal": "OpenSearch blocked"},
            "latest_ingest_run_id": "ingest-1",
        },
        error_log={},
    )
    db = FakeSession(evidence=evidence)
    monkeypatch.setattr(routes_evidence, "_count_evidence_indexed_docs", lambda _item: 71033)

    result = routes_evidence._recompute_evidence_status(evidence, db)

    assert result["previous_status"] == "failed"
    assert result["new_status"] == "completed_with_errors"
    assert result["investigation_ready"] is True
    assert result["indexed_documents"] == 71033
    assert evidence.metadata_json["searchable_documents_count"] == 71033
    assert evidence.metadata_json["status_reason"] == "reconciled_failed_status_with_searchable_documents"


def test_recompute_evidence_status_keeps_unsearchable_failed_evidence_failed(monkeypatch):
    evidence = Evidence(
        id="evidence-2",
        case_id="case-1",
        original_filename="empty.zip",
        stored_path="/tmp/empty.zip",
        evidence_type=EvidenceType.raw_collection,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256="b" * 64,
        size_bytes=1,
        ingest_status=IngestStatus.failed,
        metadata_json={"error_log": {"fatal": "failed"}},
        error_log={},
    )
    db = FakeSession(evidence=evidence)
    monkeypatch.setattr(routes_evidence, "_count_evidence_indexed_docs", lambda _item: 0)

    result = routes_evidence._recompute_evidence_status(evidence, db)

    assert result["new_status"] == "failed"
    assert result["investigation_ready"] is False
    assert evidence.metadata_json["status_reason"] == "no_searchable_documents_indexed"


def test_mft_diagnostic_detects_present_but_not_indexed_mft(monkeypatch):
    evidence = Evidence(
        id="evidence-mft",
        case_id="case-1",
        original_filename="HOSTA.7z",
        stored_path="/tmp/HOSTA.7z",
        evidence_type=EvidenceType.raw_collection,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256="c" * 64,
        size_bytes=1,
        ingest_status=IngestStatus.completed_with_errors,
        metadata_json={
            "ingest_plan": {
                "disabled_candidates": [
                    {
                        "display_name": "$MFT",
                        "source_path": "HOSTA/C/$MFT",
                        "artifact_type": "ntfs_raw",
                        "parser": "ntfs_raw",
                        "status": "unsupported",
                        "reason": "not_selected",
                        "enabled": False,
                    }
                ]
            }
        },
        error_log={},
    )
    db = FakeSession(evidence=evidence)
    monkeypatch.setattr(routes_evidence, "_load_evidence_manifest", lambda _item: {"artifacts": [], "files": []})
    monkeypatch.setattr(routes_evidence, "_safe_count_mft_docs", lambda _item: 0)
    monkeypatch.setattr(routes_evidence, "_mft_backend_available", lambda: True)

    diagnostic = routes_evidence.build_mft_diagnostic(evidence, db)

    assert diagnostic["mft_present_in_evidence"] is True
    assert diagnostic["mft_detected_by_inventory"] is True
    assert diagnostic["mft_selected_for_indexing"] is False
    assert diagnostic["mft_indexed_docs"] == 0
    assert diagnostic["mft_skipped_reason"] == "not_selected"
    assert diagnostic["mft_backend_available"] is True


def test_mft_diagnostic_reports_absent_cleanly(monkeypatch):
    evidence = Evidence(
        id="evidence-no-mft",
        case_id="case-1",
        original_filename="triage.zip",
        stored_path="/tmp/triage.zip",
        evidence_type=EvidenceType.raw_collection,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256="d" * 64,
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    db = FakeSession(evidence=evidence)
    monkeypatch.setattr(routes_evidence, "_load_evidence_manifest", lambda _item: {"artifacts": [], "files": []})
    monkeypatch.setattr(routes_evidence, "_safe_count_mft_docs", lambda _item: 0)

    diagnostic = routes_evidence.build_mft_diagnostic(evidence, db)

    assert diagnostic["mft_present_in_evidence"] is False
    assert diagnostic["mft_skipped_reason"] == "not_present"
    assert diagnostic["recommended_action"].startswith("No action needed")


def test_validate_allowed_path_file(monkeypatch, tmp_path: Path):
    allowed_root = _patch_allowed_roots(monkeypatch, tmp_path)
    sample = allowed_root / "case.zip"
    sample.write_bytes(b"PK\x03\x04test")

    result = evidence_paths_module.validate_external_path(str(sample))

    assert result["valid"] is True
    assert result["is_file"] is True
    assert result["within_allowed_root"] is True
    assert result["resolved_path"] == str(sample.resolve())


def test_reject_outside_allowed_roots(monkeypatch, tmp_path: Path):
    _patch_allowed_roots(monkeypatch, tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")

    result = evidence_paths_module.validate_external_path(str(outside))

    assert result["valid"] is False
    assert result["error"] == "path_outside_allowed_roots"
    assert result["suggested_action"] == "use_allowed_root"
    assert "allowed evidence roots" in (result["message"] or "")


def test_reject_symlink_escape(monkeypatch, tmp_path: Path):
    allowed_root = _patch_allowed_roots(monkeypatch, tmp_path)
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    escape = allowed_root / "escape"
    escape.symlink_to(outside_dir, target_is_directory=True)

    result = evidence_paths_module.validate_external_path(str(escape))

    assert result["valid"] is False
    assert result["error"] == "symlink_escape"


def test_validate_windows_client_path(monkeypatch, tmp_path: Path):
    _patch_allowed_roots(monkeypatch, tmp_path)
    result = evidence_paths_module.validate_external_path(r"C:\Users\alex\Desktop\Evidence")
    assert result["valid"] is False
    assert result["looks_like_client_path"] is True
    assert result["path_style"] == "windows"
    assert result["suggested_action"] == "upload_file"
    assert "Windows path from your local computer" in (result["message"] or "")


def test_validate_windows_unc_path(monkeypatch, tmp_path: Path):
    _patch_allowed_roots(monkeypatch, tmp_path)
    result = evidence_paths_module.validate_external_path(r"\\server\share\case001")
    assert result["valid"] is False
    assert result["looks_like_client_path"] is True
    assert result["path_style"] == "windows_unc"
    assert result["suggested_action"] == "mount_folder"


def test_validate_macos_client_path(monkeypatch, tmp_path: Path):
    _patch_allowed_roots(monkeypatch, tmp_path)
    result = evidence_paths_module.validate_external_path("/Users/alex/Desktop/Evidence")
    assert result["valid"] is False
    assert result["path_style"] == "macos"
    assert result["suggested_action"] == "upload_file"


def test_validate_linux_home_outside_allowed_roots(monkeypatch, tmp_path: Path):
    _patch_allowed_roots(monkeypatch, tmp_path)
    result = evidence_paths_module.validate_external_path("/home/alex/Evidence")
    assert result["valid"] is False
    assert result["within_allowed_root"] is False
    assert result["path_style"] == "linux_home"
    assert result["suggested_action"] == "use_allowed_root"


def test_validate_allowed_root_missing(monkeypatch, tmp_path: Path):
    allowed_root = _patch_allowed_roots(monkeypatch, tmp_path)
    result = evidence_paths_module.validate_external_path(str(allowed_root / "missing"))
    assert result["valid"] is False
    assert result["within_allowed_root"] is True
    assert result["exists"] is False


def test_validate_response_keeps_backward_compatible_fields(monkeypatch, tmp_path: Path):
    allowed_root = _patch_allowed_roots(monkeypatch, tmp_path)
    sample = allowed_root / "case.zip"
    sample.write_bytes(b"PK\x03\x04test")
    result = evidence_paths_module.validate_external_path(str(sample))
    for field in ("valid", "exists", "readable", "within_allowed_root"):
        assert field in result


def test_evidence_read_exposes_raw_collection_for_mounted_raw_archive() -> None:
    evidence = Evidence(
        id="ev-1",
        case_id="case-1",
        original_filename="EVTX-ATTACK-SAMPLES.zip",
        stored_path="/mnt/evidence/EVTX-ATTACK-SAMPLES.zip",
        original_path="/mnt/evidence/EVTX-ATTACK-SAMPLES.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        storage_mode=EvidenceStorageMode.mounted_path,
        is_external=True,
        copy_to_storage=False,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed_with_errors,
        source_tool="raw_collection",
        path_validation={},
        ingest_source={"mode": "mounted_path"},
        metadata_json={"collection_kind": "raw_evidence_collection", "source_type": "raw_collection"},
        error_log={},
        created_at=datetime.now(UTC),
    )

    payload = EvidenceRead.model_validate(evidence)

    assert payload.evidence_type == EvidenceType.raw_collection
    assert payload.source_tool == "raw_collection"


def test_debug_pack_ingest_summary_exposes_raw_collection_for_mounted_raw_archive() -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="ev-1",
        case_id="case-1",
        original_filename="EVTX-ATTACK-SAMPLES.zip",
        stored_path="/mnt/evidence/EVTX-ATTACK-SAMPLES.zip",
        original_path="/mnt/evidence/EVTX-ATTACK-SAMPLES.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        storage_mode=EvidenceStorageMode.mounted_path,
        is_external=True,
        copy_to_storage=False,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        source_tool="raw_collection",
        path_validation={},
        metadata_json={"selected_candidates": 278, "collection_kind": "raw_evidence_collection", "source_type": "raw_collection"},
        error_log={},
    )
    rows = _build_ingest_summary(
        _DebugPackContext(case=case, evidences=[evidence], request=DebugExportRequest(scope="evidence"), export_timestamp=evidence.created_at),
        {"ev-1": {"stats": {}}},
    )

    assert rows[0]["evidence_type"] == "raw_collection"
    assert rows[0]["source_tool"] == "raw_collection"


def test_register_mounted_directory_evidence(monkeypatch, tmp_path: Path):
    allowed_root = _patch_allowed_roots(monkeypatch, tmp_path)
    source_dir = allowed_root / "CASE001"
    source_dir.mkdir()
    (source_dir / "events.jsonl").write_text('{"ArtifactType":"dns_cache","Name":"www.microsoft.com.","RecordType":"A","Data":"20.1.1.1"}\n', encoding="utf-8")
    case = Case(id="case-1", name="Case 1")
    db = FakeSession(case=case)
    monkeypatch.setattr(routes_evidence, "log_activity", lambda *args, **kwargs: None)
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda *_args, **_kwargs: None)

    evidence = routes_evidence.register_evidence_path(
        "case-1",
        routes_evidence.RegisterPathRequest(path=str(source_dir), name="CASE001 mounted evidence", copy_to_storage=False, start_ingest=False, provided_host="HOSTA"),
        db,
    )

    assert evidence.storage_mode == EvidenceStorageMode.mounted_path
    assert evidence.is_external is True
    assert evidence.copy_to_storage is False
    assert evidence.stored_path == str(source_dir.resolve())
    assert evidence.original_path == str(source_dir.resolve())
    assert source_dir.exists()


def test_register_mounted_single_file_evidence(monkeypatch, tmp_path: Path):
    allowed_root = _patch_allowed_roots(monkeypatch, tmp_path)
    source_file = allowed_root / "events.csv"
    source_file.write_text("ArtifactType,Name\n", encoding="utf-8")
    case = Case(id="case-1", name="Case 1")
    db = FakeSession(case=case)
    monkeypatch.setattr(routes_evidence, "log_activity", lambda *args, **kwargs: None)
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda *_args, **_kwargs: None)

    evidence = routes_evidence.register_evidence_path(
        "case-1",
        routes_evidence.RegisterPathRequest(path=str(source_file), name="mounted single file", copy_to_storage=False, start_ingest=False, provided_host="HOSTA"),
        db,
    )

    assert evidence.storage_mode == EvidenceStorageMode.mounted_path
    assert evidence.is_external is True
    assert evidence.copy_to_storage is False
    assert evidence.stored_path == str(source_file.resolve())
    assert evidence.original_path == str(source_file.resolve())


def test_register_mounted_single_evtx_evidence_builds_selected_ingest_candidate(monkeypatch, tmp_path: Path):
    allowed_root = _patch_allowed_roots(monkeypatch, tmp_path)
    source_file = allowed_root / "Security.evtx"
    source_file.write_bytes(b"ElfFile\x00test")
    case = Case(id="case-1", name="Case 1")
    db = FakeSession(case=case)
    monkeypatch.setattr(routes_evidence, "log_activity", lambda *args, **kwargs: None)
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda *_args, **_kwargs: None)

    evidence = routes_evidence.register_evidence_path(
        "case-1",
        routes_evidence.RegisterPathRequest(path=str(source_file), name="mounted evtx", copy_to_storage=False, start_ingest=False, provided_host="HOSTA"),
        db,
    )

    plan = dict(evidence.metadata_json.get("ingest_plan") or {})
    selected = list(plan.get("selected_candidates") or [])

    assert evidence.evidence_type == EvidenceType.evtx
    assert evidence.source_tool == "windows_event_log"
    assert plan.get("selected_by_artifact_type") == {"windows_event": 1}
    assert plan.get("selected_by_parser") == {"evtx_raw": 1}
    assert len(selected) == 1
    assert selected[0]["artifact_type"] == "windows_event"
    assert selected[0]["parser"] == "evtx_raw"
    assert selected[0]["reason"] == "single_evtx_file_detected"
    assert selected[0]["relative_path"] == "Security.evtx"


def test_upload_single_evtx_sets_detected_type_and_selected_candidate(monkeypatch, tmp_path: Path):
    stored_path = tmp_path / "System.evtx"
    stored_path.write_bytes(b"ElfFile\x00upload")
    case = Case(id="case-1", name="Case 1")
    db = FakeSession(case=case)
    monkeypatch.setattr(routes_evidence, "save_upload", lambda case_id, file: ("ev-1", stored_path, stored_path.stat().st_size))
    monkeypatch.setattr(routes_evidence, "sha256_file", lambda _path: "00")
    monkeypatch.setattr(routes_evidence, "log_activity", lambda *args, **kwargs: None)
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda *_args, **_kwargs: None)

    upload = UploadFile(filename="System.evtx", file=SimpleNamespace())
    evidence = routes_evidence.upload_evidence("case-1", upload, False, None, "raw", "single_file", db)
    plan = dict(evidence.metadata_json.get("ingest_plan") or {})

    assert evidence.evidence_type == EvidenceType.evtx
    assert evidence.source_tool == "windows_event_log"
    assert plan.get("selected_by_artifact_type") == {"windows_event": 1}
    assert plan.get("selected_by_parser") == {"evtx_raw": 1}
    assert evidence.ingest_source.get("evidence_intent") == "raw"
    assert evidence.ingest_source.get("packaging") == "single_file"


def test_upload_parsed_jsonl_records_intent_and_packaging(monkeypatch, tmp_path: Path):
    stored_path = tmp_path / "events.jsonl"
    stored_path.write_text('{"event":"ok"}\n', encoding="utf-8")
    case = Case(id="case-1", name="Case 1")
    db = FakeSession(case=case)
    monkeypatch.setattr(routes_evidence, "save_upload", lambda case_id, file: ("ev-1", stored_path, stored_path.stat().st_size))
    monkeypatch.setattr(routes_evidence, "sha256_file", lambda _path: "00")
    monkeypatch.setattr(routes_evidence, "log_activity", lambda *args, **kwargs: None)
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda *_args, **_kwargs: None)

    upload = UploadFile(filename="events.jsonl", file=SimpleNamespace())
    evidence = routes_evidence.upload_evidence("case-1", upload, False, None, "parsed", "single_file", db)

    assert evidence.evidence_type == EvidenceType.jsonl
    assert evidence.ingest_source.get("evidence_intent") == "parsed"
    assert evidence.ingest_source.get("packaging") == "single_file"
    assert evidence.metadata_json.get("evidence_intent") == "parsed"
    assert evidence.metadata_json.get("packaging") == "single_file"


def test_register_mounted_archive_evidence(monkeypatch, tmp_path: Path):
    import zipfile

    allowed_root = _patch_allowed_roots(monkeypatch, tmp_path)
    source_zip = allowed_root / "archive.zip"
    with zipfile.ZipFile(source_zip, "w") as container:
        container.writestr("events.jsonl", "{}\n")
    case = Case(id="case-1", name="Case 1")
    db = FakeSession(case=case)
    monkeypatch.setattr(routes_evidence, "log_activity", lambda *args, **kwargs: None)
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda *_args, **_kwargs: None)

    evidence = routes_evidence.register_evidence_path(
        "case-1",
        routes_evidence.RegisterPathRequest(path=str(source_zip), name="mounted archive", copy_to_storage=False, start_ingest=False, provided_host="HOSTA"),
        db,
    )

    assert evidence.storage_mode == EvidenceStorageMode.mounted_path
    assert evidence.is_external is True
    assert evidence.copy_to_storage is False
    assert evidence.stored_path == str(source_zip.resolve())
    assert evidence.original_path == str(source_zip.resolve())


def test_delete_external_evidence_does_not_delete_source_folder(monkeypatch, tmp_path: Path):
    allowed_root = _patch_allowed_roots(monkeypatch, tmp_path)
    source_dir = allowed_root / "large-test"
    source_dir.mkdir()
    (source_dir / "sample.jsonl").write_text("{}\n", encoding="utf-8")
    evidence = Evidence(
        id="ev-1",
        case_id="case-1",
        original_filename="large-test",
        stored_path=str(source_dir),
        original_path=str(source_dir),
        storage_mode=EvidenceStorageMode.mounted_path,
        is_external=True,
        copy_to_storage=False,
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=0,
        file_count=1,
        ingest_status=IngestStatus.completed,
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
    )
    db = FakeSession(evidence=evidence)
    internal_root = storage_module.build_evidence_root("case-1", "ev-1")
    (internal_root / "manifest.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(routes_evidence, "delete_events_by_evidence", lambda *args, **kwargs: None)
    monkeypatch.setattr(routes_evidence, "log_activity", lambda *args, **kwargs: None)

    routes_evidence.delete_evidence("ev-1", db)

    assert source_dir.exists()


def test_reprocess_previous_selection_returns_run_id_without_sync_cleanup(monkeypatch, tmp_path: Path):
    _patch_allowed_roots(monkeypatch, tmp_path)
    evidence = Evidence(
        id="ev-1",
        case_id="case-1",
        original_filename="EVTX-ATTACK-SAMPLES.zip",
        stored_path=str(tmp_path / "EVTX-ATTACK-SAMPLES.zip"),
        original_path=str(tmp_path / "EVTX-ATTACK-SAMPLES.zip"),
        evidence_type=EvidenceType.velociraptor_zip,
        storage_mode=EvidenceStorageMode.mounted_path,
        is_external=True,
        copy_to_storage=False,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        source_tool="raw_collection",
        path_validation={},
            metadata_json={
                "provided_host": "HOSTA",
                "collection_kind": "raw_evidence_collection",
            "source_type": "raw_collection",
            "artifact_retry_runs": [{"run_id": "retry-1"}],
            "ingest_plan": {
                "selected_by_artifact_type": {"windows_event": 278},
                "selected_by_parser": {"evtx_raw": 278},
            },
        },
        error_log={},
    )
    db = FakeSession(evidence=evidence)
    enqueue_calls: list[str] = []

    monkeypatch.setattr(routes_evidence, "_ensure_rebuilt_ingest_plan", lambda _db, item: item)
    monkeypatch.setattr(routes_evidence, "_is_raw_collection_with_discovery", lambda item, metadata: True)
    monkeypatch.setattr(routes_evidence, "_is_raw_collection_with_discovery", lambda item, metadata: True)
    monkeypatch.setattr(routes_evidence, "get_last_successful_plan", lambda item, metadata: {"selected_candidates": [{"candidate_id": "evtx-1"}]})
    monkeypatch.setattr(routes_evidence, "_rehydrate_raw_collection_metadata", lambda item, metadata: None)
    monkeypatch.setattr(routes_evidence, "capture_reprocess_baseline", lambda _db, item: {"baseline": True})
    monkeypatch.setattr(
        routes_evidence,
        "build_reprocess_preview",
        lambda item, metadata, current_metadata, mode: {"previous_plan_available": True, "selected_candidates": [{"candidate_id": "evtx-1"}]},
    )
    monkeypatch.setattr(routes_evidence, "_preview_selected_candidate_ids", lambda preview: ["evtx-1"])
    monkeypatch.setattr(
        routes_evidence,
        "_apply_reprocess_selection_metadata",
        lambda item, existing_metadata, selected_candidate_ids, mode, parser_options=None: {
            **existing_metadata,
            "ingest_plan": {
                "selected_by_artifact_type": {"windows_event": 278},
                "selected_by_parser": {"evtx_raw": 278},
            },
        },
    )
    monkeypatch.setattr(routes_evidence, "persist_requested_plan", lambda metadata, requested_plan: metadata)
    monkeypatch.setattr(routes_evidence, "_preserve_run_history", lambda existing_metadata, new_metadata: {**new_metadata, "artifact_retry_runs": list(existing_metadata.get("artifact_retry_runs") or [])})
    monkeypatch.setattr(routes_evidence, "_capture_reingest_baseline", lambda item, existing_metadata, previous_manifest: {"manifest": True})
    monkeypatch.setattr(routes_evidence, "_write_initial_manifest", lambda item: None)
    monkeypatch.setattr(routes_evidence, "log_activity", lambda *args, **kwargs: None)
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda evidence_id: enqueue_calls.append(evidence_id))
    monkeypatch.setattr(routes_evidence, "delete_events_by_evidence", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("delete_events_by_evidence must not run synchronously")))
    monkeypatch.setattr(routes_evidence, "reset_extracted_dir", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("reset_extracted_dir must not run synchronously")))
    monkeypatch.setattr(routes_evidence, "reset_staging_dir", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("reset_staging_dir must not run synchronously")))
    monkeypatch.setattr(routes_evidence, "evidence_staging_dir", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("evidence_staging_dir must not run synchronously")))

    result = routes_evidence.reprocess_evidence(
        "ev-1",
        routes_evidence.ReprocessEvidenceRequest(mode="previous_selection", parser_options={}, preserve_analyst_state=True),
        db,
    )

    assert result["status"] == "queued"
    assert result["mode"] == "previous_selection"
    assert result["run_id"].startswith("ingest-")
    assert enqueue_calls == ["ev-1"]
    assert evidence.metadata_json["artifact_retry_runs"] == [{"run_id": "retry-1"}]
    assert evidence.metadata_json["reconciliation_baseline_pending"]["preserve_analyst_state"] is True
    assert "reconciliation_baseline" not in evidence.metadata_json
    assert evidence.metadata_json["reprocess_cleanup_pending"]["preserve_staging"] is True
    assert evidence.metadata_json["reprocess_cleanup_pending"]["reset_staging_dir"] is False
    assert "selected_files_processed" not in evidence.metadata_json
    assert "current_action" not in evidence.metadata_json


def test_reprocess_returns_existing_active_run_without_duplicate_enqueue(monkeypatch, tmp_path: Path):
    _patch_allowed_roots(monkeypatch, tmp_path)
    evidence = Evidence(
        id="ev-1",
        case_id="case-1",
        original_filename="EVTX-ATTACK-SAMPLES.zip",
        stored_path=str(tmp_path / "EVTX-ATTACK-SAMPLES.zip"),
        original_path=str(tmp_path / "EVTX-ATTACK-SAMPLES.zip"),
        evidence_type=EvidenceType.velociraptor_zip,
        storage_mode=EvidenceStorageMode.mounted_path,
        is_external=True,
        copy_to_storage=False,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.pending,
        source_tool="raw_collection",
        path_validation={},
        metadata_json={
            "current_ingest_run_id": "ingest-existing",
            "reprocess_request": {
                "run_id": "ingest-existing",
                "mode": "previous_selection",
            },
            "ingest_plan": {
                "selected_by_artifact_type": {"windows_event": 278},
                "selected_by_parser": {"evtx_raw": 278},
            },
        },
        error_log={},
    )
    db = FakeSession(evidence=evidence)
    enqueue_calls: list[str] = []

    monkeypatch.setattr(routes_evidence, "_ensure_rebuilt_ingest_plan", lambda _db, item: item)
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda evidence_id: enqueue_calls.append(evidence_id))

    result = routes_evidence.reprocess_evidence(
        "ev-1",
        routes_evidence.ReprocessEvidenceRequest(mode="previous_selection", parser_options={}, preserve_analyst_state=True),
        db,
    )

    assert result == {
        "accepted": True,
        "evidence_id": "ev-1",
        "run_id": "ingest-existing",
        "status": "queued",
        "mode": "previous_selection",
    }
    assert enqueue_calls == []
    assert evidence.metadata_json["current_ingest_run_id"] == "ingest-existing"


def test_debug_pack_ingest_summary_includes_storage_metadata():
    evidence = Evidence(
        id="ev-1",
        case_id="case-1",
        original_filename="sample",
        stored_path="/mnt/evidence/sample",
        original_path="/mnt/evidence/sample",
        storage_mode=EvidenceStorageMode.mounted_path,
        is_external=True,
        copy_to_storage=False,
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=123,
        file_count=12,
        ingest_status=IngestStatus.completed,
        path_validation={"within_allowed_root": True},
        ingest_source={"mode": "mounted_path"},
        metadata_json={},
        error_log={},
    )
    context = SimpleNamespace(evidences=[evidence])

    rows = _build_ingest_summary(context, {"ev-1": {"stats": {}}})

    assert rows[0]["storage_mode"] == "mounted_path"
    assert rows[0]["is_external"] is True
    assert rows[0]["copy_to_storage"] is False
    assert rows[0]["original_path"] == "/mnt/evidence/sample"


def test_debug_pack_ingest_summary_includes_single_evtx_plan_counts() -> None:
    evidence = Evidence(
        id="ev-1",
        case_id="case-1",
        original_filename="Security.evtx",
        stored_path="/mnt/evidence/Security.evtx",
        original_path="/mnt/evidence/Security.evtx",
        storage_mode=EvidenceStorageMode.mounted_path,
        is_external=True,
        copy_to_storage=False,
        evidence_type=EvidenceType.evtx,
        sha256="00",
        size_bytes=123,
        file_count=1,
        ingest_status=IngestStatus.completed,
        source_tool="windows_event_log",
        path_validation={"within_allowed_root": True},
        ingest_source={"mode": "mounted_path"},
        metadata_json={
            "ingest_plan": {
                "selected_by_artifact_type": {"windows_event": 1},
                "selected_by_parser": {"evtx_raw": 1},
                "selected_candidates": [{"artifact_type": "windows_event", "parser": "evtx_raw"}],
            }
        },
        error_log={},
    )
    context = SimpleNamespace(evidences=[evidence])

    rows = _build_ingest_summary(context, {"ev-1": {"stats": {}}})

    assert rows[0]["evidence_type"] == "evtx"
    assert rows[0]["source_tool"] == "windows_event_log"
    assert rows[0]["selected_by_artifact_type"] == {"windows_event": 1}
