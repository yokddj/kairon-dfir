from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin, UUIDMixin


class CaseHost(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "case_hosts"
    __table_args__ = (
        UniqueConstraint("case_id", "canonical_name", name="uq_case_hosts_case_canonical_name"),
    )

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    canonical_name: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="observed")
    first_seen: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_seen: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    case = relationship("Case", back_populates="host_identities")
    aliases = relationship("CaseHostAlias", back_populates="case_host", cascade="all, delete-orphan")
    audit_entries = relationship("CaseHostIdentityAudit", back_populates="case_host", cascade="all, delete-orphan")
