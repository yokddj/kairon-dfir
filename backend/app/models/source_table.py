from sqlalchemy import JSON, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, UUIDMixin


class SourceTable(UUIDMixin, TimestampMixin, Base):
    """A CSV/TSV file indexed whole, with its own columns, in its own index.

    Opt-in per evidence (wizard) or per file (evidence detail). The normal
    ingest still normalizes the file into the case events index; this is an
    extra view that Search, Timeline and detections never read. A row with
    ``source_path == "*"`` is a pending "every CSV of this evidence" request
    that the build job expands once the evidence has artifacts.
    """

    __tablename__ = "source_tables"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    source_path: Mapped[str] = mapped_column(String(4096), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    artifact_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # pending | building | ready | failed | unavailable
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)
    columns: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    row_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    index_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
