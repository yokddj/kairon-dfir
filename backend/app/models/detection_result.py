from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, UUIDMixin, utc_now_naive


class DetectionResult(UUIDMixin, Base):
    __tablename__ = "detection_results"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidences.id", ondelete="SET NULL"), nullable=True, index=True)
    artifact_id: Mapped[str | None] = mapped_column(ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True, index=True)
    rule_id: Mapped[str | None] = mapped_column(ForeignKey("rules.id", ondelete="SET NULL"), nullable=True, index=True)
    rule_set_id: Mapped[str | None] = mapped_column(ForeignKey("rule_sets.id", ondelete="SET NULL"), nullable=True, index=True)
    engine: Mapped[str] = mapped_column(String(64), nullable=False)
    source_engine: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rule_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rule_author: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rule_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    event_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    event_index: Mapped[str | None] = mapped_column(String(255), nullable=True)
    opensearch_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    target_type: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False, index=True)
    target_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    matched_at: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    matched_stable_event_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    matched_file_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    matched_process_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    host_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="new", nullable=False, index=True)
    analyst_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    matched_fields: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    matched_strings: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    condition_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    false_positives: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    references: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    tags: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    mitre: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    related_event_ids: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    related_finding_ids: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    related_iocs: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    dedup_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    engine_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    data_quality: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    raw: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utc_now_naive, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    case = relationship("Case", back_populates="detections")
    evidence = relationship("Evidence", back_populates="detections")
    artifact = relationship("Artifact", back_populates="detections")
    rule = relationship("Rule", back_populates="detections")
    rule_set = relationship("RuleSet", back_populates="detections")
