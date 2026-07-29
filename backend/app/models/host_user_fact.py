from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, JSONVariant, TimestampMixin, UUIDMixin

# A HostUserFact row is one *observation* about a local account (or, for
# source_kind "group_definition", about a group's own gid/name -- not tied
# to a specific account). Resolution into one inventory entry per username
# happens at read time (see app.services.host_users.resolve_host_users),
# mirroring app.models.host_fact.HostFact -- but the value shape here is a
# bundle of fields naturally produced together by one artifact line (a
# passwd row already carries uid/gid/home/shell/gecos together), not a
# single normalized_value, so this is a sibling table rather than a reuse
# of HostFact's own schema.
HOST_USER_FACT_SOURCE_KINDS = ("passwd", "shadow", "lastlog", "group_membership", "group_definition")


class HostUserFact(UUIDMixin, TimestampMixin, Base):
    """A single, connected observation feeding the Host User Inventory layer.

    Never stores password hashes or raw shadow content -- password_status is
    a classification (locked/set/empty) derived once at parse time in
    app.ingest.linux.identity, and the hash itself never reaches this table.
    """

    __tablename__ = "host_user_facts"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidences.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_id: Mapped[str | None] = mapped_column(ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True, index=True)
    host_id: Mapped[str | None] = mapped_column(ForeignKey("case_hosts.id", ondelete="SET NULL"), nullable=True, index=True)

    # Entity key. Null only for "group_definition" rows, which describe a
    # group's gid/name rather than a specific account.
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source_kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    parser: Mapped[str] = mapped_column(String(128), nullable=False)
    source_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    # passwd fields
    uid: Mapped[str | None] = mapped_column(String(32), nullable=True)
    primary_gid: Mapped[str | None] = mapped_column(String(32), nullable=True)
    gecos: Mapped[str | None] = mapped_column(String(255), nullable=True)
    home: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    shell: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # shadow field -- classification only, never the hash
    password_status: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # lastlog fields
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_login_terminal: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # group fields -- group_definition rows carry group_name/group_gid with
    # username=None; group_membership rows carry all three for one member.
    group_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    group_gid: Mapped[str | None] = mapped_column(String(32), nullable=True)

    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    event_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provenance: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
