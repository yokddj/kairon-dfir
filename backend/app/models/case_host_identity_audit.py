from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, TimestampMixin, UUIDMixin


class CaseHostIdentityAudit(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "case_host_identity_audit"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    case_host_id: Mapped[str | None] = mapped_column(ForeignKey("case_hosts.id", ondelete="CASCADE"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    old_value: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    new_value: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    reason: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    analyst: Mapped[str | None] = mapped_column(String(255), nullable=True)

    case_host = relationship("CaseHost", back_populates="audit_entries")
    case = relationship("Case")
