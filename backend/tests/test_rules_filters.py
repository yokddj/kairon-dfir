from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.api import routes_rules
from app.models.case import Case
from app.models.detection_result import DetectionResult
from app.models.rule import Rule, RuleEngine
from app.models.rule_run import RuleRun, RuleRunStatus


CASE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
RULE_1_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
RULE_2_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
RUN_ID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return Session()


def test_list_detections_can_filter_by_rule_run_id() -> None:
    db = _session()
    db.add(Case(id=CASE_ID, name="Case"))
    db.add(
        Rule(
            id=RULE_1_ID,
            case_id=CASE_ID,
            name="Encoded PowerShell",
            title="Encoded PowerShell",
            engine=RuleEngine.sigma,
            content="title: Encoded PowerShell",
            content_hash="hash-1",
            enabled=True,
            status="valid",
        )
    )
    db.add(
        Rule(
            id=RULE_2_ID,
            case_id=CASE_ID,
            name="Other Rule",
            title="Other Rule",
            engine=RuleEngine.sigma,
            content="title: Other Rule",
            content_hash="hash-2",
            enabled=True,
            status="valid",
        )
    )
    run = RuleRun(
        id=RUN_ID,
        case_id=CASE_ID,
        rule_id=RULE_1_ID,
        rule_set_id=None,
        evidence_id=None,
        engine="sigma",
        status=RuleRunStatus.completed,
        matched=1,
        created_detections=1,
        duplicates=0,
        scanned_files=0,
        skipped_files=0,
        errors=[],
        metadata_json={},
        started_at="2026-05-21T10:00:00Z",
        finished_at="2026-05-21T10:05:00Z",
    )
    db.add(run)
    db.add(
        DetectionResult(
            case_id=CASE_ID,
            rule_id=RULE_1_ID,
            rule_set_id=None,
            evidence_id=None,
            artifact_id=None,
            engine="sigma",
            source_engine="sigma",
            rule_name="Encoded PowerShell",
            severity="high",
            target_type="event",
            event_id="evt-1",
            event_index="case-events",
            opensearch_id="os-1",
            message="match",
            created_at=datetime(2026, 5, 21, 10, 1, tzinfo=UTC),
        )
    )
    db.add(
        DetectionResult(
            case_id=CASE_ID,
            rule_id=RULE_2_ID,
            rule_set_id=None,
            evidence_id=None,
            artifact_id=None,
            engine="sigma",
            source_engine="sigma",
            rule_name="Other Rule",
            severity="medium",
            target_type="event",
            event_id="evt-2",
            event_index="case-events",
            opensearch_id="os-2",
            message="other match",
            created_at=datetime(2026, 5, 21, 10, 2, tzinfo=UTC),
        )
    )
    db.commit()

    result = routes_rules._list_detections_response(
        db=db,
        case_id=CASE_ID,
        source="sigma",
        engine=None,
        rule_id=None,
        rule_run_id=RUN_ID,
        import_run_id=None,
        source_pack=None,
        severity=None,
        status_value=None,
        rule_name=None,
        evidence_id=None,
        host=None,
        artifact_type=None,
        matched_object_type=None,
        q=None,
        has_linked_event=None,
        has_file_target=None,
        created_from=None,
        created_to=None,
        orphaned_only=False,
        include_deleted=False,
        include_stale=False,
        include_event_preview=False,
        page=1,
        page_size=50,
        sort_field="created_at",
        sort_direction="desc",
    )

    assert result["total"] == 1
    assert result["items"][0]["rule_id"] == RULE_1_ID
