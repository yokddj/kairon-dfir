import enum
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, JSONVariant, UUIDMixin, utc_now_naive


class DetectionStatus(str, enum.Enum):
    """status was always a bare String(32), never an enum column -- this
    documents the real values in use rather than changing the column type.
    Finding.status went the native-Postgres-enum route and had to be
    migrated back to varchar (see migrations.py v26) because adding a new
    value meant an ALTER TYPE; keeping this one a plain string with
    Python-side validation avoids repeating that."""

    new = "new"
    reviewed = "reviewed"
    confirmed = "confirmed"
    dismissed = "dismissed"
    false_positive = "false_positive"
    archived = "archived"
    promoted_to_finding = "promoted_to_finding"
    stale = "stale"
    stale_event_link = "stale_event_link"


# Statuses a human sets by analyst judgment, via PATCH /api/detections/{id}
# or the bulk-action endpoints (Detections.tsx: "Mark reviewed" / "Confirm" /
# "Dismiss" / "Reopen", plus the legacy archive/false_positive bulk actions
# that exist server-side but aren't wired to a live UI control today).
# Unlike Finding, detections aren't worked through a staged pipeline in
# practice -- an analyst moves freely between "reviewed"/"confirmed"/
# "dismissed"/etc. in either direction, and the live bulk-update endpoint
# already applies mark_reviewed/mark_dismissed/mark_new unconditionally
# from any prior status. So this validates only what's unambiguously wrong
# (an unrecognized string, or a value that belongs to backend automation),
# rather than inventing a staged graph real usage doesn't follow.
DETECTION_HUMAN_STATUSES = frozenset({"new", "reviewed", "confirmed", "dismissed", "false_positive", "archived"})

# Set only by backend automation, never by a person through a PATCH body:
# "stale"/"stale_event_link" by reprocess cleanup and reconciliation
# (workers/tasks.py, services/reconciliation.py) and a broken-link check on
# GET /api/detections/{id}/event; "promoted_to_finding" by the dedicated
# POST /api/detections/{id}/promote-to-finding endpoint, alongside creating
# the Finding it points to. A PATCH targeting one of these directly would
# either desync it from the automation that's supposed to own it, or (for
# promoted_to_finding) claim a Finding exists when none was created.
DETECTION_AUTOMATED_STATUSES = frozenset({"stale", "stale_event_link", "promoted_to_finding"})


def validate_detection_transition(current: str, target: str) -> None:
    if current == target:
        return
    if target in DETECTION_AUTOMATED_STATUSES:
        raise ValueError(f"{target} is set automatically and cannot be assigned directly")
    if target not in DETECTION_HUMAN_STATUSES:
        raise ValueError(f"Unknown detection status: {target}")


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
