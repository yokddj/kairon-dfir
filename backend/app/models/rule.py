import enum

from sqlalchemy import Boolean, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, TimestampMixin, UUIDMixin


class RuleEngine(str, enum.Enum):
    yara = "yara"
    sigma = "sigma"
    heuristic = "heuristic"


class Rule(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "rules"

    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    rule_set_id: Mapped[str | None] = mapped_column(ForeignKey("rule_sets.id", ondelete="SET NULL"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    engine: Mapped[RuleEngine] = mapped_column(Enum(RuleEngine), nullable=False)
    namespace: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    author: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rule_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="valid", nullable=False, index=True)
    references: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    false_positives: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    tags: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    mitre: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    validation_errors: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONVariant, default=dict, nullable=False)

    case = relationship("Case", back_populates="rules")
    rule_set = relationship("RuleSet", back_populates="rules")
    detections = relationship("DetectionResult", back_populates="rule")
    rule_runs = relationship("RuleRun", back_populates="rule")
