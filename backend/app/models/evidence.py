import enum
from datetime import datetime

from sqlalchemy import BigInteger, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, UUIDMixin, utc_now_naive


class EvidenceType(str, enum.Enum):
    raw_collection = "raw_collection"
    velociraptor_zip = "velociraptor_zip"
    kape_archive = "kape_archive"
    parsed_folder = "parsed_folder"
    csv = "csv"
    json = "json"
    jsonl = "jsonl"
    txt = "txt"
    evtx = "evtx"
    memory_dump = "memory_dump"
    pcap = "pcap"
    linux_triage = "linux_triage"
    macos_triage = "macos_triage"
    yara_rules = "yara_rules"
    sigma_rules = "sigma_rules"
    unknown = "unknown"


class IngestStatus(str, enum.Enum):
    pending = "pending"
    processing = "processing"
    completed = "completed"
    completed_with_errors = "completed_with_errors"
    failed = "failed"


class EvidenceStorageMode(str, enum.Enum):
    uploaded = "uploaded"
    mounted_path = "mounted_path"
    shared_path = "shared_path"
    external_reference = "external_reference"


class EvidenceIntegrityStatus(str, enum.Enum):
    unknown = "unknown"
    verified = "verified"
    mismatch = "mismatch"
    missing_file = "missing_file"
    error = "error"


class EvidenceCustodyEventType(str, enum.Enum):
    uploaded = "uploaded"
    hash_computed = "hash_computed"
    processing_started = "processing_started"
    processing_completed = "processing_completed"
    processing_failed = "processing_failed"
    integrity_checked = "integrity_checked"
    manifest_exported = "manifest_exported"
    metadata_updated = "metadata_updated"


class Evidence(UUIDMixin, Base):
    __tablename__ = "evidences"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    stored_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    original_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    evidence_type: Mapped[EvidenceType] = mapped_column(Enum(EvidenceType), default=EvidenceType.unknown, nullable=False)
    storage_mode: Mapped[EvidenceStorageMode] = mapped_column(Enum(EvidenceStorageMode), default=EvidenceStorageMode.uploaded, nullable=False)
    is_external: Mapped[bool] = mapped_column(default=False, nullable=False)
    copy_to_storage: Mapped[bool] = mapped_column(default=True, nullable=False)
    sha256: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    # Memory image detection fields.  Populated by the memory
    # image probe; nullable for evidence that is not a memory
    # candidate.
    detected_format: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detection_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detection_confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    detection_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    probe_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    operator_override: Mapped[bool] = mapped_column(default=False, nullable=False)
    operator_override_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    operator_override_at: Mapped[datetime | None] = mapped_column(nullable=True)
    probed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detected_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    uploaded_by_user_id: Mapped[str | None] = mapped_column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    uploaded_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)
    first_seen_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_processed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    integrity_status: Mapped[EvidenceIntegrityStatus] = mapped_column(Enum(EvidenceIntegrityStatus), default=EvidenceIntegrityStatus.unknown, nullable=False)
    integrity_checked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    notes: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    file_count: Mapped[int | None] = mapped_column(nullable=True)
    ingest_status: Mapped[IngestStatus] = mapped_column(Enum(IngestStatus), default=IngestStatus.pending, nullable=False)
    detected_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detected_user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    host_id: Mapped[str | None] = mapped_column(ForeignKey("case_hosts.id", ondelete="SET NULL"), nullable=True, index=True)
    host_assignment_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    host_assignment_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    host_assignment_confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    host_assignment_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    host_assignment_updated_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    host_assignment_updated_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source_tool: Mapped[str | None] = mapped_column(String(255), nullable=True)
    path_validation: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    ingest_source: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    error_log: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(nullable=True)

    case = relationship("Case", back_populates="evidences")
    artifacts = relationship("Artifact", back_populates="evidence", cascade="all, delete-orphan")
    detections = relationship("DetectionResult", back_populates="evidence")
    activity_events = relationship("AppActivityEvent", back_populates="evidence")
    rule_runs = relationship("RuleRun", back_populates="evidence")
    memory_scan_runs = relationship("MemoryScanRun", back_populates="evidence", cascade="all, delete-orphan")
    memory_artifact_summaries = relationship("MemoryArtifactSummary", back_populates="evidence", cascade="all, delete-orphan")
    host = relationship("CaseHost", back_populates="evidences")
    uploaded_by = relationship("User")
    custody_events = relationship("EvidenceCustodyEvent", back_populates="evidence", cascade="all, delete-orphan")


class EvidenceCustodyEvent(UUIDMixin, Base):
    __tablename__ = "evidence_custody_events"

    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type: Mapped[EvidenceCustodyEventType] = mapped_column(Enum(EvidenceCustodyEventType), nullable=False, index=True)
    actor_user_id: Mapped[str | None] = mapped_column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False, index=True)
    summary: Mapped[str] = mapped_column(String(512), nullable=False)
    details_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)

    evidence = relationship("Evidence", back_populates="custody_events")
    actor = relationship("User")


def resolve_public_evidence_type(
    evidence_type: EvidenceType | str | None,
    *,
    source_tool: str | None = None,
    metadata: dict | None = None,
) -> EvidenceType:
    metadata = dict(metadata or {})
    collection_kind = str(metadata.get("collection_kind") or "").strip().lower()
    source_type = str(metadata.get("source_type") or "").strip().lower()
    source_tool_normalized = str(source_tool or "").strip().lower()
    if (
        source_tool_normalized == "raw_collection"
        or source_type == "raw_collection"
        or collection_kind == "raw_evidence_collection"
    ):
        return EvidenceType.raw_collection
    if isinstance(evidence_type, EvidenceType):
        return evidence_type
    if evidence_type:
        try:
            return EvidenceType(str(evidence_type))
        except ValueError:
            return EvidenceType.unknown
    return EvidenceType.unknown


from app.models import memory as _memory_models  # noqa: E402,F401
