import enum
from datetime import datetime

from sqlalchemy import BigInteger, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, UUIDMixin, utc_now_naive
from app.core.evidence_platforms import EvidencePlatform, detect_evidence_platform as core_detect_evidence_platform
from app.core.evidence_platforms import normalize_evidence_platform as core_normalize_evidence_platform
from app.core.evidence_platforms import resolve_evidence_platform as core_resolve_evidence_platform


class EvidenceType(str, enum.Enum):
    raw_collection = "raw_collection"
    velociraptor_zip = "velociraptor_zip"
    kape_archive = "kape_archive"
    parsed_folder = "parsed_folder"
    disk_image = "disk_image"
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
    host_assigned = "host_assigned"
    host_unassigned = "host_unassigned"
    host_created = "host_created"
    host_assignment_changed = "host_assignment_changed"
    companion_attached = "companion_attached"
    companion_removed = "companion_removed"


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
    provided_platform: Mapped[str] = mapped_column(String(32), default=EvidencePlatform.auto.value, nullable=False)
    detected_platform: Mapped[str] = mapped_column(String(32), default=EvidencePlatform.unknown.value, nullable=False)
    effective_platform: Mapped[str] = mapped_column(String(32), default=EvidencePlatform.unknown.value, nullable=False)
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
    disk_image = relationship("DiskImage", uselist=False, cascade="all, delete-orphan", back_populates="evidence")
    activity_events = relationship("AppActivityEvent", back_populates="evidence")
    rule_runs = relationship("RuleRun", back_populates="evidence")
    memory_scan_runs = relationship("MemoryScanRun", back_populates="evidence", cascade="all, delete-orphan")
    memory_artifact_summaries = relationship("MemoryArtifactSummary", back_populates="evidence", cascade="all, delete-orphan")
    host = relationship("CaseHost", back_populates="evidences")
    uploaded_by = relationship("User")
    custody_events = relationship("EvidenceCustodyEvent", back_populates="evidence", cascade="all, delete-orphan")
    companion_files = relationship("EvidenceCompanionFile", back_populates="evidence", cascade="all, delete-orphan")


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


class EvidenceCompanionFile(UUIDMixin, Base):
    """A secondary acquisition-format file materialized alongside a primary
    Evidence file -- e.g. a VMware ``.vmsn``/``.vmss`` snapshot metadata
    file next to a ``.vmem`` memory dump.

    Named generically (not ``LinuxVmwareCompanion`` or similar) because a
    companion belongs to the *acquisition format*, not the guest OS --
    Volatility 3's VMware layer stacker discovers ``.vmss``/``.vmsn`` the
    same way regardless of whether the guest is Linux or Windows. Only
    ``companion_type`` values ``vmware_vmsn``/``vmware_vmss`` are produced
    today; the table shape does not assume VMware or any single format.

    Phase 1 policy: at most ONE active companion per evidence
    (``evidence_id`` unique). Uploading a new companion -- of the same or a
    different type -- replaces whatever was previously attached, including
    removing the old file from disk. This sidesteps the ambiguity of
    tracking two simultaneous companions when Volatility itself only ever
    consults one (it always prefers a ``.vmss`` over a ``.vmsn`` when both
    are physically present -- see ``VmwareStacker.stack()`` in
    ``volatility3/framework/layers/vmware.py``): if a stale file of the
    higher-precedence type were left on disk after a "replace", Volatility
    would keep silently using the old one. A single active row makes that
    scenario structurally impossible instead of relying on cleanup
    discipline.
    """

    __tablename__ = "evidence_companion_files"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    # "vmware_vmsn" | "vmware_vmss" today. Stored as a plain string (not a
    # SQLAlchemy Enum) so a future companion format never requires a
    # native-enum schema migration -- same convention as every other
    # small-fixed-vocabulary column in the memory subsystem
    # (e.g. MemoryEvidenceLinuxSymbolLink.link_source).
    companion_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    # Client-supplied filename, sanitized for display only -- never used to
    # derive an on-disk path. See ``internal_filename`` for the path Kairon
    # actually writes and Volatility actually reads.
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    # The canonical on-disk basename Volatility's VmwareStacker expects:
    # the primary evidence's own canonical basename with its extension
    # swapped (``memory-image.vmem`` -> ``memory-image.vmss``), never the
    # original uploaded filename.
    internal_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    # Path relative to ``settings.backend_data_dir``, mirroring
    # ``MemoryUpload.canonical_relative_path``.
    relative_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # "manual_upload" today; kept as a free string (not an enum) for the
    # same forward-compatibility reason as companion_type.
    source_method: Mapped[str] = mapped_column(String(32), nullable=False, default="manual_upload")
    uploaded_by_user_id: Mapped[str | None] = mapped_column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(default=utc_now_naive, onupdate=utc_now_naive, nullable=False)

    evidence = relationship("Evidence", back_populates="companion_files")
    uploaded_by = relationship("User")


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


def normalize_evidence_platform(value: EvidencePlatform | str | None) -> str:
    return core_normalize_evidence_platform(value)


def detect_evidence_platform(*, filename: str | None = None, paths: list[str] | None = None, evidence_type: str | None = None) -> str:
    return core_detect_evidence_platform(filename=filename, paths=paths, evidence_type=evidence_type)


def resolve_evidence_platform(
    provided_platform: EvidencePlatform | str | None,
    detected_platform: EvidencePlatform | str | None,
    *,
    evidence_type: str | None = None,
) -> tuple[str, str, str]:
    return core_resolve_evidence_platform(provided_platform, detected_platform, evidence_type=evidence_type)


from app.models import memory as _memory_models  # noqa: E402,F401
