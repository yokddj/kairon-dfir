import enum

from sqlalchemy import Enum, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import TimestampMixin, UUIDMixin, Base


class CaseStatus(str, enum.Enum):
    open = "open"
    closed = "closed"
    archived = "archived"


class CaseMode(str, enum.Enum):
    investigation = "investigation"
    demo = "demo"
    training = "training"
    validation = "validation"


class Case(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "cases"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[CaseStatus] = mapped_column(Enum(CaseStatus), default=CaseStatus.open, nullable=False)
    mode: Mapped[CaseMode] = mapped_column(Enum(CaseMode), default=CaseMode.investigation, nullable=False)
    timezone: Mapped[str | None] = mapped_column(String(128), nullable=True)

    evidences = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    artifacts = relationship("Artifact", back_populates="case", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="case", cascade="all, delete-orphan")
    tags = relationship("Tag", back_populates="case", cascade="all, delete-orphan")
    rules = relationship("Rule", back_populates="case", cascade="all, delete-orphan")
    rule_sets = relationship("RuleSet", back_populates="case", cascade="all, delete-orphan")
    rule_runs = relationship("RuleRun", back_populates="case", cascade="all, delete-orphan")
    detections = relationship("DetectionResult", back_populates="case", cascade="all, delete-orphan")
    activity_events = relationship("AppActivityEvent", back_populates="case", cascade="all, delete-orphan")
    analysis_jobs = relationship("CaseAnalysisJob", back_populates="case", cascade="all, delete-orphan")
    reports = relationship("CaseReport", back_populates="case", cascade="all, delete-orphan")
    host_identities = relationship("CaseHost", back_populates="case", cascade="all, delete-orphan")
    memory_scan_runs = relationship("MemoryScanRun", back_populates="case", cascade="all, delete-orphan")
    memory_artifact_summaries = relationship("MemoryArtifactSummary", back_populates="case", cascade="all, delete-orphan")


from app.models import memory as _memory_models  # noqa: E402,F401
