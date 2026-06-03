from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.routes_rules import delete_bulk_detections, preview_bulk_detections, update_bulk_detections
from app.core.database import Base
from app.models.case import Case
from app.models.detection_result import DetectionResult
from app.models.finding import Finding, FindingSeverity
from app.models.rule import Rule, RuleEngine
from app.models.rule_run import RuleRun, RuleRunStatus
from app.schemas.rule import DetectionBulkActionRequestV2, DetectionBulkPreviewRequest


CASE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
RULE_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
RULE_2_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
RUN_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return Session()


def _seed(db):
    db.add(Case(id=CASE_ID, name="Case"))
    db.add(
        Rule(
            id=RULE_ID,
            case_id=CASE_ID,
            name="Sigma A",
            title="Sigma A",
            engine=RuleEngine.sigma,
            source="uploaded",
            content="title: Sigma A",
            enabled=True,
            metadata_json={"import_run_id": "import-1", "source_pack": "pack-a"},
        )
    )
    db.add(
        Rule(
            id=RULE_2_ID,
            case_id=CASE_ID,
            name="Sigma B",
            title="Sigma B",
            engine=RuleEngine.sigma,
            source="uploaded",
            content="title: Sigma B",
            enabled=True,
        )
    )
    db.add(RuleRun(id=RUN_ID, case_id=CASE_ID, rule_id=RULE_ID, engine="sigma", status=RuleRunStatus.completed, scope="case"))
    db.add_all(
        [
            DetectionResult(
                id="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1",
                case_id=CASE_ID,
                rule_id=RULE_ID,
                engine="sigma",
                source_engine="sigma",
                rule_name="Sigma A",
                severity="high",
                status="new",
                target_type="event",
                raw={"rule_run_id": RUN_ID, "rule_import_run_id": "import-1", "rule_source_pack": "pack-a"},
            ),
            DetectionResult(
                id="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee2",
                case_id=CASE_ID,
                rule_id=RULE_2_ID,
                engine="sigma",
                source_engine="sigma",
                rule_name="Sigma B",
                severity="low",
                status="reviewed",
                target_type="event",
                raw={},
            ),
        ]
    )
    db.commit()


def test_preview_by_rule_run_and_import_run() -> None:
    db = _session()
    _seed(db)

    by_run = preview_bulk_detections(DetectionBulkPreviewRequest(mode="rule_run", case_id=CASE_ID, rule_run_id=RUN_ID), db)
    assert by_run.matched == 1
    assert by_run.by_status["new"] == 1

    by_import = preview_bulk_detections(DetectionBulkPreviewRequest(mode="import_run", case_id=CASE_ID, import_run_id="import-1"), db)
    assert by_import.matched == 1
    assert by_import.by_rule[0].title == "Sigma A"


def test_bulk_mark_reviewed_matching() -> None:
    db = _session()
    _seed(db)

    result = update_bulk_detections(
        DetectionBulkActionRequestV2(
            action="mark_reviewed",
            mode="matching",
            case_id=CASE_ID,
            filters={"status": "new"},
        ),
        db,
    )
    assert result.updated == 1
    assert db.get(DetectionResult, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1").status == "reviewed"


def test_large_delete_requires_confirmation_and_keeps_findings() -> None:
    db = _session()
    _seed(db)
    db.add(Finding(case_id=CASE_ID, title="Finding", severity=FindingSeverity.medium, detection_ids=["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1"]))
    db.commit()

    failed = False
    try:
        delete_bulk_detections(
            DetectionBulkActionRequestV2(
                action="delete",
                mode="matching",
                case_id=CASE_ID,
                filters={"case_id": CASE_ID},
            ),
            db,
        )
    except Exception:
        failed = True
    assert failed is True

    result = delete_bulk_detections(
        DetectionBulkActionRequestV2(
            action="delete",
            mode="matching",
            case_id=CASE_ID,
            filters={"case_id": CASE_ID},
            confirm="DELETE DETECTIONS",
        ),
        db,
    )
    assert result.deleted == 2
    assert db.query(Finding).count() == 1


def test_orphaned_detection_preview_works_after_rule_delete() -> None:
    db = _session()
    _seed(db)
    db.delete(db.get(Rule, RULE_ID))
    db.commit()

    preview = preview_bulk_detections(DetectionBulkPreviewRequest(mode="orphaned_rules", case_id=CASE_ID), db)
    assert preview.matched == 1
    assert preview.orphaned_rule_count == 1
