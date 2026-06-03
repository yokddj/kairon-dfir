from sqlalchemy import Boolean, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, TimestampMixin, UUIDMixin
from app.models.rule import RuleEngine


class RuleSet(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "rule_sets"

    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    engine: Mapped[RuleEngine] = mapped_column(Enum(RuleEngine), nullable=False)
    namespace: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    content_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    rules_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tags: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONVariant, default=dict, nullable=False)

    case = relationship("Case", back_populates="rule_sets")
    rules = relationship("Rule", back_populates="rule_set")
    detections = relationship("DetectionResult", back_populates="rule_set")
    rule_runs = relationship("RuleRun", back_populates="rule_set")
