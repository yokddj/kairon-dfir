from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, UUIDMixin, utc_now_naive


class DiskImage(UUIDMixin, Base):
    __tablename__ = "disk_images"

    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True, unique=True)
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    format: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    sha256: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    segment_count: Mapped[int] = mapped_column(default=1, nullable=False)
    status: Mapped[str] = mapped_column(String(64), default="uploaded", nullable=False, index=True)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    tool_metadata: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    warnings_json: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    error_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)

    evidence = relationship("Evidence", back_populates="disk_image")
    volumes = relationship("DiskVolume", back_populates="disk_image", cascade="all, delete-orphan")


class DiskVolume(UUIDMixin, Base):
    __tablename__ = "disk_volumes"

    disk_image_id: Mapped[str] = mapped_column(ForeignKey("disk_images.id", ondelete="CASCADE"), nullable=False, index=True)
    partition_index: Mapped[int] = mapped_column(nullable=False, default=0)
    offset_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    length_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    partition_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    filesystem_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    uuid: Mapped[str | None] = mapped_column(String(128), nullable=True)
    encrypted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    readable: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(64), default="discovered", nullable=False, index=True)
    warnings_json: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    error_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)

    disk_image = relationship("DiskImage", back_populates="volumes")
    installations = relationship("OSInstallation", back_populates="disk_volume", cascade="all, delete-orphan")


class OSInstallation(UUIDMixin, Base):
    __tablename__ = "os_installations"

    disk_volume_id: Mapped[str] = mapped_column(ForeignKey("disk_volumes.id", ondelete="CASCADE"), nullable=False, index=True)
    platform: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    distro: Mapped[str | None] = mapped_column(String(255), nullable=True)
    root_path: Mapped[str] = mapped_column(String(1024), nullable=False, default="/")
    confidence: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    detection_reasons: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)

    disk_volume = relationship("DiskVolume", back_populates="installations")
