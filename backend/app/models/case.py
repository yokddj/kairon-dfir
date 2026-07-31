import enum

from sqlalchemy import Enum, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import JSONVariant, TimestampMixin, UUIDMixin, Base


class CaseStatus(str, enum.Enum):
    open = "open"
    active = "active"
    on_hold = "on_hold"
    closed = "closed"
    archived = "archived"


class CasePriority(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class CaseMode(str, enum.Enum):
    investigation = "investigation"
    demo = "demo"
    training = "training"
    validation = "validation"


class Case(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "cases"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[CaseStatus] = mapped_column(Enum(CaseStatus, native_enum=False, length=32), default=CaseStatus.active, nullable=False)
    priority: Mapped[CasePriority] = mapped_column(Enum(CasePriority, native_enum=False, length=32), default=CasePriority.medium, nullable=False)
    case_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    management_tags: Mapped[list] = mapped_column(JSONVariant, default=list, nullable=False)
    mode: Mapped[CaseMode] = mapped_column(Enum(CaseMode), default=CaseMode.investigation, nullable=False)
    timezone: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Analyst-set override for the manual INVESTIGATE/REPORT workflow stages
    # ("Start investigation" / "Generate report"). NULL = no override (stays
    # at investigation_ready once automatically ready). See
    # app.services.case_state.derive_case_investigation_state.
    investigation_phase_override: Mapped[str | None] = mapped_column(String(32), nullable=True)

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
