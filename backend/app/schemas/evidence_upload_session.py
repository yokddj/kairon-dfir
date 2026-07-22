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
    # Only consulted when UNIFIED_UPLOAD_EVIDENCE_MEMORY_DUMP is enabled and
    # intake_category == "memory_dump" -- see
    # app.services.evidence_unified_memory.create_unified_memory_dump_session.
    # All other intake categories ignore these fields and take the
    # unchanged legacy byte-offset path.
    intake_category: str | None = None
    host_id: str | None = None
    provided_host: str | None = None
    memory_authorization_acknowledged: bool = False
    notes: str | None = None


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
