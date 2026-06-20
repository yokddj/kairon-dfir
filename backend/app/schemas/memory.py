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


class MemoryEvidenceReadinessRead(BaseModel):
    exists: bool
    regular_file: bool
    readable_by_memory_worker: bool
    size_matches: bool
    output_writable_by_memory_worker: bool
    worker_online: bool
    backend_ready: bool
    can_analyze: bool
    error_code: str | None = None
    sanitized_message: str
    symbols_required: bool = False
    symbol_identifier_present: bool = False
    acquisition_available: bool = False
    acquisition_status: str | None = None
    can_analyze_offline: bool = False


class MemorySymbolAcquireRequest(BaseModel):
    authorization_acknowledged: bool = False

    model_config = {"extra": "forbid"}


class MemorySymbolAcquireResponse(BaseModel):
    request_id: str | None = None
    status: str
    symbol_mode: str
    source: str
    error_code: str | None = None
    message: str


class MemorySymbolRequestCreateRequest(BaseModel):
    authorization_acknowledged: bool = False

    model_config = {"extra": "forbid"}


class MemorySymbolRequestCreateResponse(BaseModel):
    request_id: str
    status: str
    source_category: str
    pending_request_id: str | None = None
    requirement_fingerprint: str
    error_code: str | None = None
    message: str


class MemorySymbolCacheStatusRead(BaseModel):
    mode: str
    managed_download_enabled: bool
    acquisition_enabled: bool
    network_isolation_ready: bool
    administrator_authorization_available: bool
    local_approval_enabled: bool
    pending_requests: int
    awaiting_operator_approval: int
    approved_pending: int
    fetcher_online: bool
    total_bytes: int
    configured_max_bytes: int
    max_bytes: int
    available_bytes: int
    symbol_count: int
    pdb_count: int
    isf_count: int
    active_requests: int
    failed_requests: int
    last_success_at: datetime | None = None
    error_code: str | None = None
    message: str


class MemorySymbolRequestStatusRead(BaseModel):
    request_id: str
    requirement_id: str
    case_id: str | None = None
    evidence_id: str | None = None
    status: str
    source_category: str
    requirement_fingerprint: str
    downloaded_bytes: int
    redirect_count: int
    error_code: str | None = None
    sanitized_message: str | None = None
    created_at: datetime
    updated_at: datetime
    approved_at: datetime | None = None
    approval_expires_at: datetime | None = None
    approval_consumed_at: datetime | None = None
    queued_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    acquisition_id: str | None = None


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
    plugins_skipped: int = 0
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


class MemoryUploadStatusRead(BaseModel):
    upload_id: str
    status: str
    bytes_received: int
    expected_bytes: int
    evidence_id: str | None = None
    failure_code: str | None = None
    message: str
    updated_at: datetime
    retryable: bool


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


class MemoryProcessEntityRead(BaseModel):
    document_id: str | None = None
    document_type: str = "memory_process_entity"
    case_id: str
    evidence_id: str
    scan_run_id: str
    host_id: str | None = None
    process_entity_id: str
    process: dict
    visibility: dict
    sources: list[str] = []
    source_plugins: list[str] = []
    observation_count: int = 0
    observation_summary: dict = {}
    confidence: str = "low"
    first_seen_run_id: str | None = None
    latest_run_id: str | None = None
    findings: list[str] = []
    findings_summary: list[str] = []
    normalization_version: str = "memory_process_canonical_v1"
    materialized_from_run_id: str | None = None
    parent_entity_id: str | None = None
    child_count: int = 0
    tree: dict = {}
    indexed_at: datetime | None = None


class MemoryProcessObservationRead(BaseModel):
    document_id: str | None = None
    document_type: str = "memory_process_observation"
    case_id: str
    evidence_id: str
    scan_run_id: str
    process_entity_id: str
    plugin_run_id: str | None = None
    plugin_name: str
    source_record_id: str | None = None
    observed: dict
    raw_status: str = "ok"
    source_fields: dict = {}
    confidence: str = "low"
    indexed_at: datetime | None = None


class MemoryProcessEdgeEntityRead(BaseModel):
    document_id: str | None = None
    document_type: str = "memory_process_edge"
    case_id: str
    evidence_id: str
    scan_run_id: str
    parent_entity_id: str
    child_entity_id: str
    edge_type: str = "parent_child"
    source_plugin: str | None = None
    confidence: str = "medium"
    parent_pid: int | None = None
    child_pid: int | None = None


class MemoryProcessEntityListRead(BaseModel):
    items: list[MemoryProcessEntityRead]
    total: int
    page: int
    page_size: int
    selected_run: str | None = None
    normalization_version: str = "memory_process_canonical_v1"
    total_observations: int = 0
    facets: dict = {}


class MemoryProcessEntityDetailRead(BaseModel):
    entity: MemoryProcessEntityRead
    observations: list[MemoryProcessObservationRead] = []
    parent: MemoryProcessEntityRead | None = None
    children: list[MemoryProcessEntityRead] = []
    tree_path: list[str] = []
    alternate_command_lines: list[str] = []
    findings: list[str] = []
    source_record_refs: list[str] = []


class MemoryProcessTreeEntityRead(BaseModel):
    run_id: str
    nodes: list[dict]
    edges: list[MemoryProcessEdgeEntityRead] = []
    metrics: dict
    total_entities: int
    omitted_count: int = 0
    truncation_reason: str | None = None


class MemoryRenormalizeSummaryRead(BaseModel):
    case_id: str
    evidence_id: str
    run_id: str
    source_documents: int
    candidate_entities: int
    observation_count: int
    duplicate_groups_collapsed: int
    invalid_records: int
    ambiguous_pid_groups: int
    expected_edges: int
    tree_metrics: dict
    normalization_version: str = "memory_process_canonical_v1"
    materialization_status: str = "pending"


class MemoryRunOptionsRead(BaseModel):
    run_id: str
    profile: str
    status: str
    created_at: datetime
    completed_at: datetime | None = None
    plugin_count: int = 0
    plugins_completed: int = 0
    plugins_failed: int = 0
    selected: bool = False


class MemoryRunSelectorRead(BaseModel):
    runs: list[MemoryRunOptionsRead]
    default_run_id: str | None = None
    combined_historical_available: bool = False
