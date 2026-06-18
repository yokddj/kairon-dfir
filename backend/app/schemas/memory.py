from datetime import datetime

from pydantic import BaseModel


class MemoryCapabilityRead(BaseModel):
    memory_analysis_enabled: bool
    external_tool_execution_enabled: bool = False
    tools_auto_install_enabled: bool = False
    message: str


class MemoryBackendStatusRead(BaseModel):
    backend: str
    display_name: str
    configured: bool
    executable_found: bool
    execution_allowed: bool
    available: bool
    ready: bool
    version: str | None = None
    command_display: str | None = None
    status: str
    message: str
    checked_at: datetime
    error_code: str | None = None


class MemoryBackendOverviewRead(BaseModel):
    memory_analysis_enabled: bool
    external_execution_allowed: bool
    backends: list[MemoryBackendStatusRead]
    preferred_backend: str | None = None
    ready_backend_count: int
    message: str


class MemoryEvidenceRead(BaseModel):
    id: str
    case_id: str
    original_filename: str
    evidence_type: str
    size_bytes: int
    ingest_status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class MemoryScanRunRead(BaseModel):
    id: str
    case_id: str
    evidence_id: str
    backend: str | None = None
    profile: str
    status: str
    plugin_count: int = 0
    plugins_completed: int = 0
    plugins_failed: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    output_dir: str | None = None
    metadata_json: dict = {}
    error_log: dict = {}
    created_at: datetime

    model_config = {"from_attributes": True}


class MemoryOverviewRead(BaseModel):
    case_id: str
    memory_analysis_enabled: bool
    has_memory_evidence: bool
    has_memory_results: bool
    has_disk_events: bool
    mode: str
    evidences: list[MemoryEvidenceRead]
    runs: list[MemoryScanRunRead]
    message: str


class MemoryStartScanRequest(BaseModel):
    backend: str | None = None
    profile: str = "metadata_only"


class MemoryStartScanResponse(BaseModel):
    accepted: bool = False
    evidence_id: str
    run_id: str | None = None
    status: str
    message: str
    run: MemoryScanRunRead | None = None
