from collections.abc import Generator
from datetime import datetime, timezone
import os
from uuid import uuid4

from sqlalchemy import JSON, DateTime, MetaData, create_engine, inspect, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app.core.config import get_settings


settings = get_settings()
engine = create_engine(
    settings.database_url,
    future=True,
    pool_pre_ping=True,
    connect_args={"prepare_threshold": None},
)

if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=lambda: engine.dispose())

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

metadata = MetaData()


class Base(DeclarativeBase):
    metadata = metadata


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_naive() -> datetime:
    return utc_now().replace(tzinfo=None)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )


class UUIDMixin:
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))


JSONVariant = JSON().with_variant(JSONB, "postgresql")


def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app.models import activity, app_setting, artifact, case, case_analysis_job, case_host, case_host_alias, case_host_identity_audit, case_report, detection_result, evidence, event_marking, finding, incident_timeline_draft, memory, rule, rule_import_run, rule_run, rule_set, tag, timeline_bookmark  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_compatible_schema()


def _ensure_compatible_schema() -> None:
    if engine.dialect.name != "postgresql":
        return

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                DO $$
                BEGIN
                  IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ingeststatus') THEN
                    IF NOT EXISTS (
                      SELECT 1
                      FROM pg_enum
                      WHERE enumtypid = 'ingeststatus'::regtype
                        AND enumlabel = 'completed_with_errors'
                    ) THEN
                      ALTER TYPE ingeststatus ADD VALUE 'completed_with_errors';
                    END IF;
                  END IF;
                END
                $$;
                """
            )
        )
        connection.execute(
            text(
                """
                DO $$
                BEGIN
                  IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'rulerunstatus') THEN
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'rulerunstatus'::regtype AND enumlabel = 'cancelled'
                    ) THEN
                      ALTER TYPE rulerunstatus ADD VALUE 'cancelled';
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'rulerunstatus'::regtype AND enumlabel = 'stale'
                    ) THEN
                      ALTER TYPE rulerunstatus ADD VALUE 'stale';
                    END IF;
                  END IF;
                END
                $$;
                """
            )
        )
        connection.execute(
            text(
                """
                DO $$
                BEGIN
                  IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ruleimportrunstatus') THEN
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'ruleimportrunstatus'::regtype AND enumlabel = 'saving'
                    ) THEN
                      ALTER TYPE ruleimportrunstatus ADD VALUE 'saving';
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'ruleimportrunstatus'::regtype AND enumlabel = 'cancelled'
                    ) THEN
                      ALTER TYPE ruleimportrunstatus ADD VALUE 'cancelled';
                    END IF;
                  END IF;
                END
                $$;
                """
            )
        )
        connection.execute(
            text(
                """
                DO $$
                BEGIN
                  IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'findingstatus') THEN
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'findingstatus'::regtype AND enumlabel = 'new'
                    ) THEN
                      ALTER TYPE findingstatus ADD VALUE 'new';
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'findingstatus'::regtype AND enumlabel = 'reviewed'
                    ) THEN
                      ALTER TYPE findingstatus ADD VALUE 'reviewed';
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'findingstatus'::regtype AND enumlabel = 'dismissed'
                    ) THEN
                      ALTER TYPE findingstatus ADD VALUE 'dismissed';
                    END IF;
                  END IF;
                END
                $$;
                """
            )
        )

        if "detection_results" in existing_tables:
            detection_columns = {column["name"] for column in inspector.get_columns("detection_results")}
            if "source_engine" not in detection_columns:
                connection.execute(text("ALTER TABLE detection_results ADD COLUMN source_engine VARCHAR(64)"))
                connection.execute(text("UPDATE detection_results SET source_engine = engine WHERE source_engine IS NULL"))
            if "confidence" not in detection_columns:
                connection.execute(text("ALTER TABLE detection_results ADD COLUMN confidence DOUBLE PRECISION"))
            if "status" not in detection_columns:
                connection.execute(text("ALTER TABLE detection_results ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT 'new'"))
            if "rule_set_id" not in detection_columns:
                connection.execute(text("ALTER TABLE detection_results ADD COLUMN rule_set_id UUID"))
            if "event_index" not in detection_columns:
                connection.execute(text("ALTER TABLE detection_results ADD COLUMN event_index VARCHAR(255)"))
            if "opensearch_id" not in detection_columns:
                connection.execute(text("ALTER TABLE detection_results ADD COLUMN opensearch_id VARCHAR(255)"))
            if "target_type" not in detection_columns:
                connection.execute(text("ALTER TABLE detection_results ADD COLUMN target_type VARCHAR(32) NOT NULL DEFAULT 'unknown'"))
                connection.execute(
                    text(
                        """
                        UPDATE detection_results
                        SET target_type = CASE
                            WHEN event_id IS NOT NULL THEN 'event'
                            WHEN target_path IS NOT NULL THEN 'file'
                            ELSE 'unknown'
                        END
                        WHERE target_type IS NULL OR target_type = 'unknown'
                        """
                    )
                )
            if "deleted_at" not in detection_columns:
                connection.execute(text("ALTER TABLE detection_results ADD COLUMN deleted_at TIMESTAMP WITH TIME ZONE"))
            if "archived_at" not in detection_columns:
                connection.execute(text("ALTER TABLE detection_results ADD COLUMN archived_at TIMESTAMP WITH TIME ZONE"))
            additions = {
                "rule_title": "VARCHAR(255)",
                "rule_version": "VARCHAR(64)",
                "rule_author": "VARCHAR(255)",
                "rule_level": "VARCHAR(32)",
                "matched_at": "VARCHAR(64)",
                "matched_stable_event_id": "VARCHAR(255)",
                "matched_file_hash": "VARCHAR(128)",
                "matched_process_node_id": "VARCHAR(255)",
                "host_name": "VARCHAR(255)",
                "analyst_note": "TEXT",
                "matched_fields": "JSONB NOT NULL DEFAULT '{}'::jsonb",
                "matched_strings": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "condition_summary": "TEXT",
                "description": "TEXT",
                "false_positives": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "references": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "tags": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "mitre": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "related_event_ids": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "related_finding_ids": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "related_iocs": "JSONB NOT NULL DEFAULT '{}'::jsonb",
                "risk_score": "DOUBLE PRECISION",
                "dedup_fingerprint": "VARCHAR(255)",
                "engine_version": "VARCHAR(64)",
                "data_quality": "JSONB NOT NULL DEFAULT '[]'::jsonb",
            }
            for column_name, column_type in additions.items():
                if column_name not in detection_columns:
                    connection.execute(text(f'ALTER TABLE detection_results ADD COLUMN "{column_name}" {column_type}'))
        if "rules" in existing_tables:
            rule_columns = {column["name"] for column in inspector.get_columns("rules")}
            if "rule_set_id" not in rule_columns:
                connection.execute(text("ALTER TABLE rules ADD COLUMN rule_set_id UUID"))
            additions = {
                "title": "VARCHAR(255)",
                "source": "VARCHAR(64)",
                "author": "VARCHAR(255)",
                "rule_version": "VARCHAR(64)",
                "level": "VARCHAR(32)",
                "content_hash": "VARCHAR(128)",
                "status": "VARCHAR(32) NOT NULL DEFAULT 'valid'",
                "references": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "false_positives": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "mitre": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "validation_errors": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "metadata": "JSONB NOT NULL DEFAULT '{}'::jsonb",
            }
            for column_name, column_type in additions.items():
                if column_name not in rule_columns:
                    connection.execute(text(f'ALTER TABLE rules ADD COLUMN "{column_name}" {column_type}'))
        if "rule_runs" in existing_tables:
            rule_run_columns = {column["name"] for column in inspector.get_columns("rule_runs")}
            if "rule_set_id" not in rule_run_columns:
                connection.execute(text("ALTER TABLE rule_runs ADD COLUMN rule_set_id UUID"))
            additions = {
                "scope": "VARCHAR(32) NOT NULL DEFAULT 'case'",
                "total_rules": "INTEGER NOT NULL DEFAULT 0",
                "processed_rules": "INTEGER NOT NULL DEFAULT 0",
                "total_events": "INTEGER NOT NULL DEFAULT 0",
                "scanned_events": "INTEGER NOT NULL DEFAULT 0",
                "total_files": "INTEGER NOT NULL DEFAULT 0",
                "current_phase": "VARCHAR(64)",
                "heartbeat_at": "VARCHAR(64)",
                "last_error": "VARCHAR(2048)",
                "cancel_requested": "BOOLEAN NOT NULL DEFAULT FALSE",
            }
            for column_name, column_type in additions.items():
                if column_name not in rule_run_columns:
                    connection.execute(text(f'ALTER TABLE rule_runs ADD COLUMN "{column_name}" {column_type}'))
        if "rule_import_runs" in existing_tables:
            rule_import_columns = {column["name"] for column in inspector.get_columns("rule_import_runs")}
            additions = {
                "cancelled_at": "VARCHAR(64)",
                "processed_rules": "INTEGER NOT NULL DEFAULT 0",
                "current_phase": "VARCHAR(64)",
                "cancel_requested": "BOOLEAN NOT NULL DEFAULT FALSE",
            }
            for column_name, column_type in additions.items():
                if column_name not in rule_import_columns:
                    connection.execute(text(f'ALTER TABLE rule_import_runs ADD COLUMN "{column_name}" {column_type}'))
        if "cases" in existing_tables:
            case_columns = {column["name"] for column in inspector.get_columns("cases")}
            if "timezone" not in case_columns:
                connection.execute(text("ALTER TABLE cases ADD COLUMN timezone VARCHAR(128)"))
            if "mode" not in case_columns:
                connection.execute(text("ALTER TABLE cases ADD COLUMN mode VARCHAR(32) NOT NULL DEFAULT 'investigation'"))
            connection.execute(
                text(
                    """
                    UPDATE cases
                    SET mode = 'validation'
                    WHERE id = 'c01c0be4-2381-4208-8af6-266e2579a893'
                      AND (mode IS NULL OR mode = 'investigation')
                    """
                )
            )
        if "case_hosts" in existing_tables:
            host_columns = {column["name"] for column in inspector.get_columns("case_hosts")}
            additions = {
                "display_name": "VARCHAR(255)",
                "confidence": "VARCHAR(32) NOT NULL DEFAULT 'medium'",
                "source": "VARCHAR(64) NOT NULL DEFAULT 'observed'",
                "first_seen": "VARCHAR(64)",
                "last_seen": "VARCHAR(64)",
                "event_count": "INTEGER NOT NULL DEFAULT 0",
                "evidence_count": "INTEGER NOT NULL DEFAULT 0",
            }
            for column_name, column_type in additions.items():
                if column_name not in host_columns:
                    connection.execute(text(f'ALTER TABLE case_hosts ADD COLUMN "{column_name}" {column_type}'))
        if "case_host_aliases" in existing_tables:
            alias_columns = {column["name"] for column in inspector.get_columns("case_host_aliases")}
            additions = {
                "source": "VARCHAR(64) NOT NULL DEFAULT 'observed'",
                "confidence": "VARCHAR(32) NOT NULL DEFAULT 'medium'",
                "first_seen": "VARCHAR(64)",
                "last_seen": "VARCHAR(64)",
                "event_count": "INTEGER NOT NULL DEFAULT 0",
                "is_primary": "BOOLEAN NOT NULL DEFAULT FALSE",
            }
            for column_name, column_type in additions.items():
                if column_name not in alias_columns:
                    connection.execute(text(f'ALTER TABLE case_host_aliases ADD COLUMN "{column_name}" {column_type}'))
        if "findings" in existing_tables:
            finding_columns = {column["name"] for column in inspector.get_columns("findings")}
            additions = {
                "event_ids": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "detection_ids": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "evidence_id": "UUID",
                "finding_type": "VARCHAR(128)",
                "confidence": "VARCHAR(32)",
                "source": "VARCHAR(64)",
                "correlation_version": "VARCHAR(32)",
                "fingerprint": "VARCHAR(255)",
                "risk_score": "INTEGER NOT NULL DEFAULT 0",
                "time_start": "TIMESTAMP WITH TIME ZONE",
                "time_end": "TIMESTAMP WITH TIME ZONE",
                "timeline": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "related_event_ids": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "related_stable_event_ids": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "related_artifact_ids": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "related_evidence_ids": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "related_process_node_ids": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "related_files": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "related_domains": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "related_ips": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "related_users": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "related_hosts": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "reasons": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "tags": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "mitre": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "recommended_triage": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "data_quality": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "last_seen_at": "TIMESTAMP WITH TIME ZONE",
                "occurrence_count": "INTEGER NOT NULL DEFAULT 1",
            }
            for column_name, column_type in additions.items():
                if column_name not in finding_columns:
                    connection.execute(text(f'ALTER TABLE findings ADD COLUMN "{column_name}" {column_type}'))
        if "timeline_bookmarks" in existing_tables:
            bookmark_columns = {column["name"] for column in inspector.get_columns("timeline_bookmarks")}
            additions = {
                "summary": "TEXT",
                "note": "TEXT",
                "finding_id": "UUID",
                "stable_event_id": "VARCHAR(255)",
                "created_by": "VARCHAR(255)",
                "order_index": "INTEGER NOT NULL DEFAULT 0",
                "include_in_report": "BOOLEAN NOT NULL DEFAULT TRUE",
                "remap_status": "VARCHAR(32) NOT NULL DEFAULT 'current'",
            }
            for column_name, column_type in additions.items():
                if column_name not in bookmark_columns:
                    connection.execute(text(f"ALTER TABLE timeline_bookmarks ADD COLUMN {column_name} {column_type}"))
        if "case_reports" in existing_tables:
            report_columns = {column["name"] for column in inspector.get_columns("case_reports")}
            additions = {
                "evidence_id": "UUID",
                "generated_at": "TIMESTAMP WITH TIME ZONE",
                "author": "VARCHAR(255)",
                "report_type": "VARCHAR(64) NOT NULL DEFAULT 'investigation'",
                "format": "VARCHAR(32) NOT NULL DEFAULT 'markdown'",
                "mode": "VARCHAR(64)",
                "source_ingest_run_id": "VARCHAR(255)",
                "output_path": "VARCHAR(2048)",
                "size_bytes": "BIGINT",
                "time_range": "JSONB NOT NULL DEFAULT '{}'::jsonb",
                "filters": "JSONB NOT NULL DEFAULT '{}'::jsonb",
                "sections_enabled": "JSONB NOT NULL DEFAULT '{}'::jsonb",
                "analyst_notes": "JSONB NOT NULL DEFAULT '{}'::jsonb",
                "selected_finding_ids": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "selected_key_event_ids": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "selected_process_chain_ids": "JSONB NOT NULL DEFAULT '[]'::jsonb",
                "include_raw_appendix": "BOOLEAN NOT NULL DEFAULT FALSE",
                "include_debug_metadata": "BOOLEAN NOT NULL DEFAULT FALSE",
                "metadata_json": "JSONB NOT NULL DEFAULT '{}'::jsonb",
            }
            for column_name, column_type in additions.items():
                if column_name not in report_columns:
                    connection.execute(text(f"ALTER TABLE case_reports ADD COLUMN {column_name} {column_type}"))
        connection.execute(
            text(
                """
                DO $$
                BEGIN
                  IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'casereportstatus') THEN
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'casereportstatus'::regtype AND enumlabel = 'queued'
                    ) THEN
                      ALTER TYPE casereportstatus ADD VALUE 'queued';
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'casereportstatus'::regtype AND enumlabel = 'running'
                    ) THEN
                      ALTER TYPE casereportstatus ADD VALUE 'running';
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'casereportstatus'::regtype AND enumlabel = 'completed'
                    ) THEN
                      ALTER TYPE casereportstatus ADD VALUE 'completed';
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'casereportstatus'::regtype AND enumlabel = 'completed_with_errors'
                    ) THEN
                      ALTER TYPE casereportstatus ADD VALUE 'completed_with_errors';
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'casereportstatus'::regtype AND enumlabel = 'completed_with_warnings'
                    ) THEN
                      ALTER TYPE casereportstatus ADD VALUE 'completed_with_warnings';
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'casereportstatus'::regtype AND enumlabel = 'failed'
                    ) THEN
                      ALTER TYPE casereportstatus ADD VALUE 'failed';
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'casereportstatus'::regtype AND enumlabel = 'cancelled'
                    ) THEN
                      ALTER TYPE casereportstatus ADD VALUE 'cancelled';
                    END IF;
                  END IF;
                  IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'evidencestoragemode') THEN
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'evidencestoragemode'::regtype AND enumlabel = 'uploaded'
                    ) THEN
                      ALTER TYPE evidencestoragemode ADD VALUE 'uploaded';
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'evidencestoragemode'::regtype AND enumlabel = 'mounted_path'
                    ) THEN
                      ALTER TYPE evidencestoragemode ADD VALUE 'mounted_path';
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'evidencestoragemode'::regtype AND enumlabel = 'shared_path'
                    ) THEN
                      ALTER TYPE evidencestoragemode ADD VALUE 'shared_path';
                    END IF;
                    IF NOT EXISTS (
                      SELECT 1 FROM pg_enum
                      WHERE enumtypid = 'evidencestoragemode'::regtype AND enumlabel = 'external_reference'
                    ) THEN
                      ALTER TYPE evidencestoragemode ADD VALUE 'external_reference';
                    END IF;
                  END IF;
                END
                $$;
                """
            )
        )
        if "evidences" in existing_tables:
            evidence_columns = {column["name"] for column in inspector.get_columns("evidences")}
            additions = {
                "original_path": "VARCHAR(2048)",
                "storage_mode": "VARCHAR(64) NOT NULL DEFAULT 'uploaded'",
                "is_external": "BOOLEAN NOT NULL DEFAULT FALSE",
                "copy_to_storage": "BOOLEAN NOT NULL DEFAULT TRUE",
                "file_count": "BIGINT",
                "path_validation": "JSONB NOT NULL DEFAULT '{}'::jsonb",
                "ingest_source": "JSONB NOT NULL DEFAULT '{}'::jsonb",
            }
            for column_name, column_type in additions.items():
                if column_name not in evidence_columns:
                    connection.execute(text(f"ALTER TABLE evidences ADD COLUMN {column_name} {column_type}"))
