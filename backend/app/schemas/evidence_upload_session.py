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
    sha256: str | None = None
    client_sha256: str | None = None
    client_sha256_mismatch: bool = False
    declared_platform: str | None = None
    expires_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


class EvidenceUploadSessionCreateResponse(BaseModel):
    session: EvidenceUploadSessionRead
    preflight: PreflightReport
    health: dict | None = None


class EvidenceUploadSessionStageResponse(BaseModel):
    session: EvidenceUploadSessionRead
    health: dict | None = None


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
