from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.routes_rules import (
    _import_run_detail,
    bulk_cancel_rule_runs,
    bulk_delete_rule_sets,
    bulk_delete_rule_runs,
    bulk_delete_rules,
    bulk_mark_stale_runs,
    bulk_update_rules,
    cancel_rule_run,
    delete_rule_run,
    mark_abandoned_rule_runs_stale,
    mark_rule_run_stale,
    preview_bulk_rules,
    retry_rule_run,
)
from app.core.database import Base
from app.models.case import Case
from app.models.detection_result import DetectionResult
from app.models.rule import Rule, RuleEngine
from app.models.rule_import_run import RuleImportRun, RuleImportRunStatus
from app.models.rule_run import RuleRun, RuleRunStatus
from app.models.rule_set import RuleSet
from app.schemas.rule import RuleBulkActionRequest, RuleRunBulkActionRequest, RuleRunBulkDeleteRequest, RuleSetBulkDeleteRequest

CASE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
RULE_1_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1"
RULE_2_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2"
RULE_3_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb3"
PACK_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
RUN_1_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
RUN_2_ID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return Session()


def _seed_case(db):
    case = Case(id=CASE_ID, name="Case")
    db.add(case)
    db.commit()
    return case


def test_bulk_delete_matching_sigma_rules_by_namespace_and_keep_detections() -> None:
    db = _session()
    _seed_case(db)
    rule_1 = Rule(id=RULE_1_ID, case_id=CASE_ID, name="Sigma A", engine=RuleEngine.sigma, namespace="ns-1", source="uploaded", content="title: a", enabled=True)
    rule_2 = Rule(id=RULE_2_ID, case_id=CASE_ID, name="Sigma B", engine=RuleEngine.sigma, namespace="ns-1", source="uploaded", content="title: b", enabled=True)
    rule_3 = Rule(id=RULE_3_ID, case_id=CASE_ID, name="Sigma C", engine=RuleEngine.sigma, namespace="ns-2", source="uploaded", content="title: c", enabled=True)
    db.add_all([rule_1, rule_2, rule_3])
    db.add(DetectionResult(id="ffffffff-ffff-4fff-8fff-ffffffffffff", case_id=CASE_ID, rule_id=RULE_1_ID, engine="sigma", source_engine="sigma", rule_name="Sigma A", target_type="event", raw={}))
    db.commit()

    result = bulk_delete_rules(
            RuleBulkActionRequest(mode="matching", engine="sigma", namespace="ns-1", case_id=CASE_ID, scope="all", confirm="DELETE RULES"),
            db,
        )

    assert result.matched == 2
    assert result.deleted == 2
    assert db.get(Rule, RULE_1_ID) is None
    assert db.get(Rule, RULE_2_ID) is None
    assert db.get(Rule, RULE_3_ID) is not None
    assert db.get(DetectionResult, "ffffffff-ffff-4fff-8fff-ffffffffffff") is not None


def test_delete_all_imported_rules_requires_confirmation_and_protects_builtin_heuristics() -> None:
    db = _session()
    _seed_case(db)
    uploaded = Rule(id=RULE_1_ID, case_id=CASE_ID, name="YARA One", engine=RuleEngine.yara, source="uploaded", content="rule one { condition: true }", enabled=True)
    builtin_heur = Rule(id=RULE_2_ID, case_id=CASE_ID, name="Heuristic", engine=RuleEngine.heuristic, source="builtin", content="{}", enabled=True)
    db.add_all([uploaded, builtin_heur])
    db.commit()

    failed = False
    try:
        bulk_delete_rules(RuleBulkActionRequest(mode="all_imported", engine="all", case_id=CASE_ID, scope="all"), db)
    except Exception:
        failed = True
    assert failed is True

    result = bulk_delete_rules(
        RuleBulkActionRequest(mode="all_imported", engine="all", case_id=CASE_ID, scope="all", confirm="DELETE IMPORTED RULES"),
        db,
    )
    assert result.deleted == 1
    assert db.get(Rule, RULE_1_ID) is None
    assert db.get(Rule, RULE_2_ID) is not None


def test_delete_all_imported_rules_requires_distinct_confirmation_phrase() -> None:
    db = _session()
    _seed_case(db)
    db.add(Rule(id=RULE_1_ID, case_id=CASE_ID, name="YARA One", engine=RuleEngine.yara, source="uploaded", content="rule one { condition: true }", enabled=True))
    db.commit()

    failed = False
    try:
        bulk_delete_rules(
            RuleBulkActionRequest(mode="all_imported", engine="all", case_id=CASE_ID, scope="all", confirm="DELETE RULES"),
            db,
        )
    except Exception:
        failed = True
    assert failed is True


def test_bulk_enable_disable_selected_rules() -> None:
    db = _session()
    _seed_case(db)
    rule_1 = Rule(id=RULE_1_ID, case_id=CASE_ID, name="Sigma A", engine=RuleEngine.sigma, source="uploaded", content="title: a", enabled=True)
    rule_2 = Rule(id=RULE_2_ID, case_id=CASE_ID, name="Sigma B", engine=RuleEngine.sigma, source="uploaded", content="title: b", enabled=True)
    db.add_all([rule_1, rule_2])
    db.commit()

    disabled = bulk_update_rules(RuleBulkActionRequest(mode="selected", rule_ids=[RULE_1_ID, RULE_2_ID], enabled=False), db)
    assert disabled.updated == 2
    assert db.get(Rule, RULE_1_ID).enabled is False

    enabled = bulk_update_rules(RuleBulkActionRequest(mode="selected", rule_ids=[RULE_1_ID], enabled=True), db)
    assert enabled.updated == 1
    assert db.get(Rule, RULE_1_ID).enabled is True


def test_bulk_preview_and_delete_by_import_run() -> None:
    db = _session()
    _seed_case(db)
    db.add_all(
        [
            Rule(id=RULE_1_ID, case_id=CASE_ID, name="Sigma A", engine=RuleEngine.sigma, source="uploaded", content="title: a", enabled=True, metadata_json={"import_run_id": "import-1", "source_pack": "pack-a"}),
            Rule(id=RULE_2_ID, case_id=CASE_ID, name="Sigma B", engine=RuleEngine.sigma, source="uploaded", content="title: b", enabled=True, metadata_json={"import_run_id": "import-1", "source_pack": "pack-a"}),
            Rule(id=RULE_3_ID, case_id=CASE_ID, name="Sigma C", engine=RuleEngine.sigma, source="uploaded", content="title: c", enabled=True, metadata_json={"import_run_id": "import-2", "source_pack": "pack-b"}),
        ]
    )
    db.commit()

    preview = preview_bulk_rules(RuleBulkActionRequest(mode="matching", case_id=CASE_ID, scope="all", import_run_id="import-1"), db)
    assert preview.matched == 2
    assert preview.by_source_pack["pack-a"] == 2

    result = bulk_delete_rules(
        RuleBulkActionRequest(mode="matching", case_id=CASE_ID, scope="all", import_run_id="import-1", confirm="DELETE RULES"),
        db,
    )
    assert result.deleted == 2
    assert db.get(Rule, RULE_3_ID) is not None


def test_deleting_pack_deletes_child_rules() -> None:
    db = _session()
    _seed_case(db)
    pack = RuleSet(id=PACK_ID, case_id=CASE_ID, name="Pack", engine=RuleEngine.yara, content="rules", rules_count=2, enabled=True)
    child_1 = Rule(id=RULE_1_ID, case_id=CASE_ID, rule_set_id=PACK_ID, name="YARA A", engine=RuleEngine.yara, source="uploaded", content="rule a { condition: true }", enabled=True)
    child_2 = Rule(id=RULE_2_ID, case_id=CASE_ID, rule_set_id=PACK_ID, name="YARA B", engine=RuleEngine.yara, source="uploaded", content="rule b { condition: true }", enabled=True)
    db.add_all([pack, child_1, child_2])
    db.commit()

    result = bulk_delete_rule_sets(
            RuleSetBulkDeleteRequest(mode="selected", pack_ids=[PACK_ID], confirm="DELETE RULE PACKS"),
            db,
        )
    assert result.deleted == 1
    assert db.get(RuleSet, PACK_ID) is None
    assert db.get(Rule, RULE_1_ID) is None
    assert db.get(Rule, RULE_2_ID) is None


def test_mass_imported_rule_delete_requires_global_library_confirmation() -> None:
    db = _session()
    _seed_case(db)
    db.add_all(
        [
            Rule(id=f"bbbbbbbb-bbbb-4bbb-8bbb-{index:012d}", name=f"Sigma {index}", engine=RuleEngine.sigma, source="uploaded", content="title: a", enabled=True)
            for index in range(30)
        ]
    )
    db.commit()

    failed = False
    try:
        bulk_delete_rules(RuleBulkActionRequest(mode="all_imported", engine="sigma", scope="global", confirm="DELETE IMPORTED RULES"), db)
    except Exception:
        failed = True
    assert failed is True

    result = bulk_delete_rules(
        RuleBulkActionRequest(mode="all_imported", engine="sigma", scope="global", confirm="DELETE GLOBAL RULE LIBRARY"),
        db,
    )
    assert result.deleted == 30


def test_global_rule_pack_delete_requires_global_library_confirmation() -> None:
    db = _session()
    _seed_case(db)
    pack = RuleSet(id=PACK_ID, name="Global Sigma Pack", engine=RuleEngine.sigma, content="rules", rules_count=1, enabled=True)
    child = Rule(id=RULE_1_ID, rule_set_id=PACK_ID, name="Sigma A", engine=RuleEngine.sigma, source="uploaded", content="title: a", enabled=True)
    db.add_all([pack, child])
    db.commit()

    failed = False
    try:
        bulk_delete_rule_sets(RuleSetBulkDeleteRequest(mode="selected", pack_ids=[PACK_ID], confirm="DELETE RULE PACKS"), db)
    except Exception:
        failed = True
    assert failed is True

    result = bulk_delete_rule_sets(
        RuleSetBulkDeleteRequest(mode="selected", pack_ids=[PACK_ID], confirm="DELETE GLOBAL RULE LIBRARY"),
        db,
    )
    assert result.deleted == 1
    assert db.get(RuleSet, PACK_ID) is None


def test_active_import_detail_exposes_live_progress_fields() -> None:
    run = RuleImportRun(
        id="import-active",
        engine="sigma",
        source_name="sigma_all_rules.zip",
        source_type="archive",
        status=RuleImportRunStatus.saving,
        total_files=3284,
        processed_files=170,
        total_rules_found=3283,
        processed_rules=170,
        imported_count=0,
        updated_count=0,
        duplicate_count=0,
        skipped_count=0,
        invalid_count=0,
        compiled_count=0,
        unsupported_count=0,
        warning_count=0,
        error_count=0,
        current_phase="saving_rules",
        current_file="rules/windows/process_creation/test.yml",
        cancel_requested=False,
        warnings_summary=[],
        errors_summary=[],
        created_rule_ids=[],
        updated_rule_ids=[],
        duplicate_rule_ids=[],
        invalid_items=[],
        unsupported_items=[],
        import_options={},
        details_json={},
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    detail = _import_run_detail(run)

    assert detail.is_terminal is False
    assert detail.progress_pct == 5.2
    assert detail.processed_files == 170
    assert detail.total_files == 3284
    assert detail.total_rules_found == 3283
    assert detail.files_per_sec is None
    assert detail.rules_per_sec is None


def test_terminal_import_detail_exposes_final_progress_and_performance() -> None:
    run = RuleImportRun(
        id="import-complete",
        engine="sigma",
        source_name="sigma_all_rules.zip",
        source_type="archive",
        status=RuleImportRunStatus.completed_with_warnings,
        total_files=3284,
        processed_files=3284,
        total_rules_found=3283,
        processed_rules=3283,
        imported_count=3283,
        updated_count=0,
        duplicate_count=0,
        skipped_count=1,
        invalid_count=0,
        compiled_count=3222,
        unsupported_count=61,
        warning_count=0,
        error_count=0,
        current_phase="completed",
        cancel_requested=False,
        warnings_summary=[],
        errors_summary=[],
        created_rule_ids=[],
        updated_rule_ids=[],
        duplicate_rule_ids=[],
        invalid_items=[],
        unsupported_items=[],
        import_options={},
        details_json={"performance": {"files_per_second": 1.852, "rules_per_second": 1.851}},
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    detail = _import_run_detail(run)

    assert detail.is_terminal is True
    assert detail.progress_pct == 100.0
    assert detail.imported_count == 3283
    assert detail.files_per_sec == 1.852
    assert detail.rules_per_sec == 1.851


def test_cancel_mark_stale_and_retry_rule_run(monkeypatch) -> None:
    db = _session()
    _seed_case(db)
    enqueued: list[dict] = []
    monkeypatch.setattr("app.api.routes_rules.enqueue_rule_run", lambda **kwargs: enqueued.append(kwargs))
    rule = Rule(id=RULE_1_ID, case_id=CASE_ID, name="Sigma A", engine=RuleEngine.sigma, source="uploaded", content="title: a", enabled=True)
    run = RuleRun(id=RUN_1_ID, case_id=CASE_ID, rule_id=RULE_1_ID, engine="sigma", status=RuleRunStatus.running, scope="case", total_rules=1, current_phase="matching_events", started_at=datetime.now(UTC).isoformat(), metadata_json={"scan_options": {}, "scope": "case"})
    db.add_all([rule, run])
    db.commit()

    cancel_result = cancel_rule_run(RUN_1_ID, db)
    assert cancel_result.run.cancel_requested is True

    stale_result = mark_rule_run_stale(RUN_1_ID, db)
    assert stale_result.run.status == RuleRunStatus.stale
    assert stale_result.run.stale_reason == "Marked stale by analyst: no heartbeat"

    retry_result = retry_rule_run(RUN_1_ID, db)
    assert retry_result.run.id != RUN_1_ID
    assert retry_result.run.retried_from_run_id == RUN_1_ID
    assert retry_result.run.status == RuleRunStatus.queued
    assert enqueued and enqueued[0]["run_id"] == retry_result.run.id


def test_bulk_run_actions_include_cancel_and_mark_stale() -> None:
    db = _session()
    _seed_case(db)
    run_1 = RuleRun(id=RUN_1_ID, case_id=CASE_ID, engine="sigma", status=RuleRunStatus.queued, scope="case")
    run_2 = RuleRun(
        id=RUN_2_ID,
        case_id=CASE_ID,
        engine="sigma",
        status=RuleRunStatus.running,
        scope="case",
        started_at=(datetime.now(UTC) - timedelta(minutes=40)).isoformat(),
        heartbeat_at=(datetime.now(UTC) - timedelta(minutes=30)).isoformat(),
    )
    db.add_all([run_1, run_2])
    db.commit()

    cancel_result = bulk_cancel_rule_runs(RuleRunBulkActionRequest(mode="selected", run_ids=[RUN_1_ID, RUN_2_ID]), db)
    assert cancel_result.updated == 2
    assert db.get(RuleRun, RUN_1_ID).status == RuleRunStatus.cancelled
    assert db.get(RuleRun, RUN_2_ID).cancel_requested is True

    stale_result = bulk_mark_stale_runs(RuleRunBulkActionRequest(mode="matching", case_id=CASE_ID, statuses=["running", "queued"], older_than_minutes=10), db)
    assert stale_result.updated >= 1
    assert db.get(RuleRun, RUN_2_ID).status == RuleRunStatus.stale


def test_active_rule_runs_cannot_be_deleted() -> None:
    db = _session()
    _seed_case(db)
    run = RuleRun(id=RUN_1_ID, case_id=CASE_ID, engine="sigma", status=RuleRunStatus.running, scope="case")
    db.add(run)
    db.commit()

    failed = False
    try:
        delete_rule_run(RUN_1_ID, db)
    except Exception:
        failed = True
    assert failed is True
    assert db.get(RuleRun, RUN_1_ID) is not None


def test_bulk_delete_rule_runs_skips_active_runs() -> None:
    db = _session()
    _seed_case(db)
    active = RuleRun(id=RUN_1_ID, case_id=CASE_ID, engine="sigma", status=RuleRunStatus.running, scope="case")
    finished = RuleRun(id=RUN_2_ID, case_id=CASE_ID, engine="sigma", status=RuleRunStatus.failed, scope="case")
    db.add_all([active, finished])
    db.commit()

    result = bulk_delete_rule_runs(RuleRunBulkDeleteRequest(mode="selected", run_ids=[RUN_1_ID, RUN_2_ID]), db)

    assert result.deleted == 1
    assert result.skipped == 1
    assert result.skipped_reasons["active_run"] == 1
    assert db.get(RuleRun, RUN_1_ID) is not None
    assert db.get(RuleRun, RUN_2_ID) is None


def test_mark_abandoned_rule_runs_stale_marks_old_active_runs() -> None:
    db = _session()
    _seed_case(db)
    old_run = RuleRun(
        id=RUN_1_ID,
        case_id=CASE_ID,
        engine="sigma",
        status=RuleRunStatus.running,
        scope="case",
        started_at=(datetime.now(UTC) - timedelta(minutes=30)).isoformat(),
        heartbeat_at=(datetime.now(UTC) - timedelta(minutes=20)).isoformat(),
    )
    fresh_run = RuleRun(
        id=RUN_2_ID,
        case_id=CASE_ID,
        engine="sigma",
        status=RuleRunStatus.running,
        scope="case",
        started_at=datetime.now(UTC).isoformat(),
        heartbeat_at=datetime.now(UTC).isoformat(),
    )
    db.add_all([old_run, fresh_run])
    db.commit()

    result = mark_abandoned_rule_runs_stale(case_id=CASE_ID, older_than_minutes=10, db=db)
    assert result.updated == 1
    assert db.get(RuleRun, RUN_1_ID).status == RuleRunStatus.stale
    assert db.get(RuleRun, RUN_2_ID).status == RuleRunStatus.running
