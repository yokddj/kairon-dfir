from sqlalchemy import Boolean, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin, UUIDMixin


class CaseHostAlias(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "case_host_aliases"
    __table_args__ = (
        UniqueConstraint("case_id", "normalized_alias", name="uq_case_host_aliases_case_normalized_alias"),
    )

    case_host_id: Mapped[str] = mapped_column(ForeignKey("case_hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    alias: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_alias: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="observed")
    confidence: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    first_seen: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_seen: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    case_host = relationship("CaseHost", back_populates="aliases")
    case = relationship("Case")
