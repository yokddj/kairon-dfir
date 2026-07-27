from datetime import datetime

from pydantic import BaseModel

from app.schemas.evidence_preflight import PreflightReport


class EvidenceUploadSessionRead(BaseModel):
    id: str
    case_id: str
    status: str
    original_filename: str
    is_folder: bool
    is_server_path: bool
    size_bytes: int
    expected_size_bytes: int | None = None
    bytes_received: int = 0
    sha256: str | None = None
    client_sha256: str | None = None
    client_sha256_mismatch: bool = False
    declared_platform: str | None = None
    expires_at: datetime
    created_at: datetime
    updated_at: datetime
    last_activity_at: datetime | None = None
    failure_message: str | None = None
    promoted_evidence_id: str | None = None
    category: str | None = None
    backend: str = "legacy"
    # Best-effort finalize progress checkpoint, derived read-only from the
    # session's associated EvidenceOperation.stage (the canonical persisted
    # source -- see app.services.evidence_operations.get_operation_stage);
    # never stored a second time on this row. None until finalize starts
    # writing it, and not meaningful outside of an in-flight finalize call.
    current_stage: str | None = None

    model_config = {"from_attributes": True}


class EvidenceUploadSessionCreateResponse(BaseModel):
    session: EvidenceUploadSessionRead
    preflight: PreflightReport
    health: dict | None = None


class UnifiedUploadInfo(BaseModel):
    memory_upload_id: str
    chunk_size_bytes: int
    total_chunks: int
    default_concurrency: int
    max_concurrency: int


class EvidenceUploadSessionStageResponse(BaseModel):
    session: EvidenceUploadSessionRead
    health: dict | None = None
    unified: UnifiedUploadInfo | None = None


class EvidenceUploadSessionInitRequest(BaseModel):
    filename: str
    expected_size_bytes: int
    declared_platform: str | None = None
    client_sha256: str | None = None
    # Only consulted when intake_category names a kind registered in
    # app.services.evidence_unified_upload.UNIFIED_UPLOAD_KINDS
    # ("memory_dump", "disk_image", "archive") AND that kind's own flag is
    # enabled -- see create_unified_upload_session. Any other intake
    # category (folder, server_path, multi-file/multi-segment selections)
    # ignores these fields and takes the unchanged legacy byte-offset path.
    intake_category: str | None = None
    host_id: str | None = None
    provided_host: str | None = None
    memory_authorization_acknowledged: bool = False
    notes: str | None = None
    # Wizard Advanced Options (WIZARD_ADVANCED_OPTIONS_ENABLED). Only
    # consulted by unified kinds whose workflow handler actually reads them
    # (currently: archive -- see evidence_archive_workflow.py); ignored by
    # memory_dump/disk_image's handlers. Defaults preserve current behavior
    # exactly (evidence_intent="raw", ingest_mode=full_forensic) when omitted.
    evidence_intent: str | None = None
    ingest_mode: str | None = None
    forced_evidence_kind: str | None = None
    evtx_profile: str | None = None


class EvidenceUploadSessionAppendResponse(BaseModel):
    session: EvidenceUploadSessionRead
    offset: int


class EvidenceUploadSessionFinalizeResponse(BaseModel):
    session: EvidenceUploadSessionRead
    preflight: PreflightReport
    health: dict | None = None


class ActivityOperationRead(BaseModel):
    id: str
    case_id: str
    kind: str
    category: str
    status: str
    stage: str
    label: str
    progress: float | None = None
    bytes_received: int | None = None
    expected_size_bytes: int | None = None
    current_owner: str
    created_at: datetime | str | None = None
    updated_at: datetime | str | None = None
    last_activity_at: datetime | str | None = None
    elapsed_seconds: float | None = None
    details: dict = {}


class ActivityCenterResponse(BaseModel):
    case_id: str
    summary: dict[str, int]
    operations: list[ActivityOperationRead]


class PreflightRerunRequest(BaseModel):
    declared_platform: str | None = None


class PromoteUploadSessionRequest(BaseModel):
    provided_platform: str | None = None
    host_id: str | None = None
    provided_host: str | None = None
    evtx_profile: str | None = None
    memory_authorization_acknowledged: bool = False
    folder_name: str | None = None
    labels: list[str] = []
    notes: str | None = None
    # Wizard Advanced Options (WIZARD_ADVANCED_OPTIONS_ENABLED). Only
    # threaded into promote_upload_session's single-file legacy-compat
    # (bare-else) branch -- see its docstring. Folder/server_path/disk_image/
    # memory_dump branches ignore these; defaults preserve current behavior
    # exactly (evidence_intent="raw", ingest_mode=full_forensic) when omitted.
    evidence_intent: str | None = None
    ingest_mode: str | None = None
    forced_evidence_kind: str | None = None


class UnifiedResumeDetails(BaseModel):
    memory_upload_id: str
    chunk_size_bytes: int
    total_chunks: int
    received_chunks: list[int] = []
    missing_chunks: list[int] = []
    default_concurrency: int
    max_concurrency: int
    expected_sha256: str | None = None
    verification_chunk_index: int | None = None
    verification_chunk_size: int | None = None
    verification_chunk_sha256: str | None = None


class ResumableUploadSessionRead(BaseModel):
    id: str
    case_id: str
    backend: str
    category: str | None = None
    original_filename: str
    expected_size_bytes: int | None = None
    bytes_received: int = 0
    progress_percent: float | None = None
    status: str
    current_stage: str | None = None
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    resumable: bool
    cancellable: bool
    promoted_evidence_id: str | None = None
    failure_message: str | None = None
    unified: UnifiedResumeDetails | None = None


class ResumableUploadSessionsResponse(BaseModel):
    case_id: str
    sessions: list[ResumableUploadSessionRead]
