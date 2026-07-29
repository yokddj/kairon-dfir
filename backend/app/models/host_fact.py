from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, JSONVariant, TimestampMixin, UUIDMixin

# A HostFact row is one *observation* of a fact about a host, not the
# resolved fact itself -- resolution across sources happens at read time
# (see app.services.host_facts.resolve_host_facts). Per-row status reflects
# what was known about cross-source agreement at write time:
#   confirmed   -- at least one other independent source agrees
#   observed    -- the only observation so far for this (host, fact_type)
#   conflicting -- disagrees with another source for the same (host, fact_type)
#   invalid     -- a source was found and parsed, but its value did not
#                  validate (e.g. not a known IANA zone)
# "missing" is not a per-row status: it describes the absence of any row
# for a (host, fact_type) pair, reported only by the resolution API.
HOST_FACT_STATUSES = ("confirmed", "observed", "conflicting", "invalid")


class HostFact(UUIDMixin, TimestampMixin, Base):
    """A single, connected observation feeding the generic Host Facts layer.

    Host Facts do not duplicate evidence: the raw file content already lives
    on disk and its full normalized record already lives in the search
    index (see the artifact's own family, e.g. ``linux_timezone``). This
    table stores only the small, structured fact each observation asserts,
    referencing its source via foreign keys so it stays connected to the
    case/evidence/artifact chain instead of becoming a second, disconnected
    persistence model.
    """

    __tablename__ = "host_facts"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_id: Mapped[str | None] = mapped_column(ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True, index=True)
    host_id: Mapped[str | None] = mapped_column(ForeignKey("case_hosts.id", ondelete="SET NULL"), nullable=True, index=True)

    fact_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    parser: Mapped[str] = mapped_column(String(128), nullable=False)
    source_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    raw_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    normalized_value: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="observed", index=True)

    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    event_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provenance: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
