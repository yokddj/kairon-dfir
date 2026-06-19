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
    execution_mode: str | None = None
    dedicated_worker_required: bool = False
    dedicated_worker_online: bool = False
    queue: str | None = None
    queue_reachable: bool = False
    backend_available: bool | None = None
    backend_version: str | None = None
    supported_profiles: list[str] = []
    supported_plugins: list[str] = []
    symbol_network_enabled: bool | None = None
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
    requested_plugin_count: int = 0
    plugin_count: int = 0
    plugins_completed: int = 0
    plugins_failed: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int | None = None
    output_dir: str | None = None
    metadata_json: dict = {}
    error_log: dict = {}
    backend_version: str | None = None
    worker_task_id: str | None = None
    cancellation_requested: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}


class MemoryPluginRunRead(BaseModel):
    id: str
    memory_scan_run_id: str
    case_id: str
    evidence_id: str
    plugin: str
    status: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int | None = None
    row_count: int = 0
    output_relative_path: str | None = None
    output_sha256: str | None = None
    output_size: int | None = None
    error_code: str | None = None
    error_message: str | None = None
    metadata_json: dict = {}
    created_at: datetime

    model_config = {"from_attributes": True}


class MemoryRunDetailRead(MemoryScanRunRead):
    plugin_runs: list[MemoryPluginRunRead] = []


class MemoryOverviewRead(BaseModel):
    case_id: str
    memory_analysis_enabled: bool
    memory_process_profile_enabled: bool = False
    has_memory_evidence: bool
    has_memory_results: bool
    has_disk_events: bool
    mode: str
    evidences: list[MemoryEvidenceRead]
    runs: list[MemoryScanRunRead]
    message: str


class MemoryUploadReadinessRead(BaseModel):
    case_id: str
    upload_enabled: bool
    max_upload_bytes: int
    max_upload_display: str
    allowed_extensions: list[str]
    staging_available_bytes: int
    canonical_storage_available_bytes: int
    memory_output_available_bytes: int
    recommended_max_upload_bytes: int
    required_capacity_bytes: int
    can_accept_selected_size: bool
    finalization_strategy: str | None = None
    analysis_enabled: bool
    dedicated_worker_online: bool
    backend_ready: bool
    message: str


class MemoryStartScanRequest(BaseModel):
    profile: str = "metadata_only"
    authorization_acknowledged: bool = False

    model_config = {"extra": "forbid"}


class MemoryStartScanResponse(BaseModel):
    accepted: bool = False
    evidence_id: str
    run_id: str | None = None
    status: str
    message: str
    run: MemoryScanRunRead | None = None


class MemorySystemInfoRead(BaseModel):
    case_id: str
    evidence_id: str
    memory_run_id: str
    memory_plugin_run_id: str
    source_layer: str
    memory_artifact_type: str
    backend: str
    plugin: str
    host: dict
    os: dict
    memory: dict
    parsed_at: datetime
    raw: dict = {}


class MemoryProcessRead(BaseModel):
    document_id: str | None = None
    case_id: str
    evidence_id: str
    memory_run_id: str
    source_layer: str
    memory_artifact_type: str
    backend: str
    plugins: list[str]
    process: dict
    memory: dict
    visibility: dict
    state: dict
    parsed_at: datetime
    raw: dict = {}
    warnings: list[str] = []


class MemoryProcessListRead(BaseModel):
    items: list[MemoryProcessRead]
    total: int
    page: int
    page_size: int


class MemoryProcessEdgeRead(BaseModel):
    document_id: str | None = None
    case_id: str
    evidence_id: str
    memory_run_id: str
    source_layer: str
    memory_artifact_type: str
    parent_pid: int | None = None
    child_pid: int | None = None
    edge_type: str
    source_plugin: str
    confidence: str
    parsed_at: datetime
    warnings: list[str] = []


class MemoryProcessTreeRead(BaseModel):
    run_id: str
    nodes: list[MemoryProcessRead]
    edges: list[MemoryProcessEdgeRead]
    orphan_count: int
    root_count: int
    warnings: list[str]
    source_plugins: list[str]
    total_process_count: int
