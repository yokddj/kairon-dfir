from datetime import datetime

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, UUIDMixin, utc_now_naive


class Artifact(UUIDMixin, Base):
    __tablename__ = "artifacts"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    artifact_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    disk_image_id: Mapped[str | None] = mapped_column(ForeignKey("disk_images.id", ondelete="SET NULL"), nullable=True, index=True)
    disk_volume_id: Mapped[str | None] = mapped_column(ForeignKey("disk_volumes.id", ondelete="SET NULL"), nullable=True, index=True)
    os_installation_id: Mapped[str | None] = mapped_column(ForeignKey("os_installations.id", ondelete="SET NULL"), nullable=True, index=True)
    original_source_path: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    logical_source_path: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    acquisition_method: Mapped[str | None] = mapped_column(String(128), nullable=True)
    parser: Mapped[str] = mapped_column(String(128), nullable=False)
    record_count: Mapped[int] = mapped_column(default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(64), default="detected", nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)

    case = relationship("Case", back_populates="artifacts")
    evidence = relationship("Evidence", back_populates="artifacts")
    detections = relationship("DetectionResult", back_populates="artifact")
