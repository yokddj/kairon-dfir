from pydantic import BaseModel, Field


class PreflightWarning(BaseModel):
    message: str
    severity: str  # "information" | "recommendation"


class PreflightEvidenceOption(BaseModel):
    id: str
    label: str
    path: str
    category: str
    format_key: str | None = None
    size_bytes: int | None = None


class PreflightVolumeDiagnostic(BaseModel):
    """Per-volume disk-image discovery result, translated into
    analyst-facing language -- see
    app.services.evidence_preflight._translate_volume_diagnostic. Never
    carries a raw Python/pytsk3 exception message."""

    volume_id: int
    size_bytes: int | None = None
    filesystem: str | None = None
    ok: bool
    status: str  # "readable" | "unreadable" | "encrypted" | "container"
    explanation: str
    detected_signature: str | None = None
    kind: str = "partition"  # "partition" | "logical_volume"
    name: str | None = None  # the logical volume's own name, kind == "logical_volume" only
    container_volume_id: int | None = None  # kind == "logical_volume": which volume_id it was found inside


class PreflightClassification(BaseModel):
    category: str
    format_key: str | None = None
    confidence: str
    reason: str
    chain: list[str] = []
    container: str | None = None
    contained_object: str | None = None
    platform: str
    hostname: str | None = None
    distro: str | None = None
    version: str | None = None
    volumes: int | None = None
    partitions: int | None = None
    logical_volumes: int | None = None
    filesystems: list[str] = []
    installations: int | None = None
    expected_parsers: list[str] = []
    warnings: list[PreflightWarning] = []
    volume_diagnostics: list[PreflightVolumeDiagnostic] = []


class PreflightResourceCheck(BaseModel):
    file_size_bytes: int
    compressed_size_bytes: int | None = None
    estimated_extracted_bytes: int | None = None
    estimated_temp_storage_bytes: int | None = None
    estimated_final_size_bytes: int | None = None
    estimated_processing_seconds: int | None = None
    estimated_duration_bucket: str | None = None  # "fast" | "medium" | "long" | "very_long"
    estimated_artifact_count: int | None = None
    detected_archive_depth: int | None = None
    detected_backing_chain_depth: int | None = None
    available_disk_space_bytes: int
    configured_upload_limit_bytes: int
    configured_extraction_limit_bytes: int
    configured_archive_depth_limit: int
    configured_backing_chain_limit: int
    temp_directory: str


class PreflightStatusCheck(BaseModel):
    label: str
    ok: bool
    detail: str


class PreflightDiagnostic(BaseModel):
    problem: str
    reason: str
    current_configuration: dict[str, str] = {}
    required_configuration: dict[str, str] = {}
    configuration_key: str | None = None
    configuration_file: str | None = None
    how_to_fix: list[str] = []
    severity: str = "blocking"  # "blocking" | "recommendation"


class PreflightReport(BaseModel):
    token: str
    original_filename: str
    classification: PreflightClassification
    pipeline_preview: list[str]
    resource_check: PreflightResourceCheck
    status: str  # "ready" | "warning" | "blocked"
    status_checks: list[PreflightStatusCheck]
    diagnostics: list[PreflightDiagnostic] = []
    evidence_options: list[PreflightEvidenceOption] = Field(default_factory=list)
