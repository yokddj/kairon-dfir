from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, JSONVariant, TimestampMixin, UUIDMixin, utc_now

# Active states an expiry sweep should consider for cleanup; terminal states
# ("promoted", "cancelled", "expired") are left for the caller's discretion
# once reached (promoted sessions' staged copy is already removed at
# promotion time; cancelled/expired sessions' storage is removed immediately
# when they transition, mirroring app.services.memory.upload_sessions).
ACTIVE_EVIDENCE_UPLOAD_SESSION_STATUSES = ("staged",)


class EvidenceUploadSessionStatus(str, enum.Enum):
    staged = "staged"
    promoted = "promoted"
    cancelled = "cancelled"
    expired = "expired"


class EvidenceUploadSession(UUIDMixin, TimestampMixin, Base):
    """A file staged for the ingestion wizard's Preflight step, kept on disk
    until the analyst confirms Start Processing (promote), cancels, or the
    session expires - so the same bytes never have to be transmitted twice.

    This is deliberately a small, separate model from MemoryUpload's
    resumable/chunked session machinery: memory uploads already have their
    own mature, security-reviewed session system for chunked large-file
    transfer, and this model does not touch it. EvidenceUploadSession only
    covers the single-shot staging this wizard needs for archives, folders,
    and disk images; the memory-dump wizard flow still uses the existing
    MemoryUpload session underneath.
    """

    __tablename__ = "evidence_upload_sessions"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=EvidenceUploadSessionStatus.staged.value, index=True)
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    staged_path: Mapped[str] = mapped_column(Text, nullable=False)
    is_folder: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_server_path: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    client_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    declared_platform: Mapped[str | None] = mapped_column(String(32), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    promoted_evidence_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failure_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
