from dataclasses import asdict, dataclass, field


@dataclass
class VelociraptorEvidenceCandidate:
    id: str
    category: str
    artifact_type: str
    parser_status: str
    display_name: str
    original_path: str
    local_path: str
    normalized_windows_path: str | None = None
    user: str | None = None
    browser: str | None = None
    provider: str | None = None
    profile: str | None = None
    account: str | None = None
    account_email: str | None = None
    sync_root: str | None = None
    sid: str | None = None
    hive_type: str | None = None
    app_id: str | None = None
    destination_type: str | None = None
    lnk_location: str | None = None
    filename: str | None = None
    executable_name_guess: str | None = None
    prefetch_hash_guess: str | None = None
    parser: str | None = None
    task_name: str | None = None
    task_path: str | None = None
    original_i_path: str | None = None
    original_r_path: str | None = None
    local_i_path: str | None = None
    local_r_path: str | None = None
    normalized_windows_i_path: str | None = None
    normalized_windows_r_path: str | None = None
    has_metadata_file: bool | None = None
    has_content_file: bool | None = None
    pair_id: str | None = None
    size: int | None = None
    mtime: str | None = None
    confidence: str = "medium"
    supported: bool = False
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)
    companion_files: list[str] = field(default_factory=list)
    container_type: str | None = None
    container_path: str | None = None
    local_staging_path: str | None = None
    extraction_status: str = "not_extracted"

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class VelociraptorDiscoveryResult:
    collection_root: str
    hostname: str | None
    candidates: list[VelociraptorEvidenceCandidate]
    summary: dict
    total_files_scanned: int
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "collection_root": self.collection_root,
            "hostname": self.hostname,
            "candidates": [candidate.as_dict() for candidate in self.candidates],
            "summary": self.summary,
            "total_files_scanned": self.total_files_scanned,
            "warnings": self.warnings,
        }
