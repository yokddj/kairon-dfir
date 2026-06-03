from __future__ import annotations

from datetime import datetime, timedelta, UTC

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.routes_rules import _serialize_rule_run, list_rules, run_case_rules
from app.core.database import Base
from app.models.case import Case
from app.models.rule import Rule, RuleEngine
from app.models.rule_run import RuleRun, RuleRunStatus
from app.schemas.rule import RulesRunRequest
from app.workers import tasks


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return Session()


def test_rule_run_serialization_exposes_progress_and_warnings() -> None:
    db = _session()
    db.add(Case(id="case-1", name="Case"))
    run = RuleRun(
        id="run-1",
        case_id="case-1",
        engine="sigma",
        status=RuleRunStatus.completed,
        scope="case",
        total_rules=10,
        processed_rules=10,
        total_events=1200,
        scanned_events=1200,
        total_files=0,
        matched=25,
        created_detections=7,
        duplicates=2,
        scanned_files=0,
        skipped_files=0,
        errors=[],
        current_phase="completed",
        heartbeat_at="2026-05-21T10:01:00Z",
        started_at="2026-05-21T10:00:00Z",
        finished_at="2026-05-21T10:02:00Z",
        metadata_json={"warnings": ["partial_fields"], "events_scanned": 1200},
    )
    db.add(run)
    db.commit()

    payload = _serialize_rule_run(run)
    assert payload.status == RuleRunStatus.completed
    assert payload.percent_complete == 100.0
    assert payload.total_rules == 10
    assert payload.processed_rules == 10
    assert payload.total_events == 1200
    assert payload.scanned_events == 1200
    assert payload.elapsed_seconds == 120
    assert payload.warnings == ["partial_fields"]
    assert payload.metadata_json["case_compatibility"]["applicable_to_case"] == 10


def test_rule_run_running_without_heartbeat_is_exposed_as_stale() -> None:
    db = _session()
    db.add(Case(id="case-1", name="Case"))
    stale_heartbeat = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()
    run = RuleRun(
        id="run-2",
        case_id="case-1",
        engine="yara",
        status=RuleRunStatus.running,
        scope="evidence",
        total_rules=12,
        processed_rules=3,
        total_files=40,
        scanned_files=8,
        skipped_files=0,
        errors=[],
        current_phase="scanning_files",
        heartbeat_at=stale_heartbeat,
        started_at=(datetime.now(UTC) - timedelta(minutes=12)).isoformat(),
        metadata_json={},
    )
    db.add(run)
    db.commit()

    payload = _serialize_rule_run(run)
    assert payload.status == RuleRunStatus.stale
    assert payload.stale is True
    assert payload.percent_complete == 20.0


def test_rule_run_serialization_separates_case_compatibility_reasons() -> None:
    db = _session()
    db.add(Case(id="case-1", name="Case"))
    run = RuleRun(
        id="run-3",
        case_id="case-1",
        engine="sigma",
        status=RuleRunStatus.completed,
        scope="all",
        total_rules=20,
        processed_rules=5,
        metadata_json={
            "total_rules_executed": 5,
            "rules_runtime_error": 1,
            "skipped_by_reason": {
                "skipped_unsupported_platform": 7,
                "skipped_unsupported_logsource": 4,
                "skipped_missing_fields": 3,
                "skipped_too_broad": 1,
            },
        },
    )
    db.add(run)
    db.commit()

    payload = _serialize_rule_run(run)
    case_compatibility = payload.metadata_json["case_compatibility"]
    assert case_compatibility["applicable_to_case"] == 5
    assert case_compatibility["skipped_platform"] == 7
    assert case_compatibility["skipped_logsource"] == 4
    assert case_compatibility["skipped_missing_fields_in_case"] == 3
    assert case_compatibility["skipped_too_broad"] == 1
    assert case_compatibility["runtime_error"] == 1


def test_list_rules_totals_support_imported_vs_enabled_inventory() -> None:
    db = _session()
    db.add(Case(id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", name="Case"))
    db.add_all(
        [
            Rule(
                id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
                case_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                name="Sigma One",
                engine=RuleEngine.sigma,
                content="title: one",
                enabled=True,
                severity="high",
            ),
            Rule(
                id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2",
                case_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                name="Sigma Two",
                engine=RuleEngine.sigma,
                content="title: two",
                enabled=False,
                severity="medium",
            ),
            Rule(
                id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb3",
                case_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                name="Yara One",
                engine=RuleEngine.yara,
                content="rule one { condition: true }",
                enabled=True,
                severity="medium",
            ),
        ]
    )
    db.commit()

    imported_sigma = list_rules(case_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", engine="sigma", enabled=None, scope="all", page=1, page_size=1, db=db)
    enabled_sigma = list_rules(case_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", engine="sigma", enabled=True, scope="all", page=1, page_size=1, db=db)

    assert imported_sigma.total == 2
    assert enabled_sigma.total == 1


def test_run_case_rules_defaults_to_all_scope_and_includes_global_sigma(monkeypatch) -> None:
    db = _session()
    case_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    global_rule_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1"
    db.add(Case(id=case_id, name="Case"))
    db.add(
        Rule(
            id=global_rule_id,
            case_id=None,
            name="Global Sigma",
            engine=RuleEngine.sigma,
            content="""
title: Global Sigma
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: powershell.exe
  condition: selection
""",
            enabled=True,
            severity="high",
        )
    )
    db.commit()

    monkeypatch.setattr("app.api.routes_rules.enqueue_rules_run", lambda **kwargs: "job-1")
    monkeypatch.setattr("app.api.routes_rules.log_activity", lambda *args, **kwargs: None)

    response = run_case_rules(case_id=case_id, payload=RulesRunRequest(engine="sigma"), db=db)

    assert response["accepted"] is True
    assert response["status"] == "queued"
    assert response["queued_rules"] == 1

    run = db.query(RuleRun).order_by(RuleRun.created_at.desc()).first()
    assert run is not None
    assert run.scope == "all"
    assert (run.metadata_json or {}).get("requested_rule_ids") == [global_rule_id]


def test_batch_rule_run_sets_running_immediately_and_completes(monkeypatch) -> None:
    db = _session()
    case_id = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1"
    rule_id = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbb2"
    run_id = "cccccccc-3333-4333-8333-ccccccccccc3"
    db.add(Case(id=case_id, name="Case"))
    db.add(
        Rule(
            id=rule_id,
            case_id=case_id,
            name="Sigma One",
            engine=RuleEngine.sigma,
            content="""
title: Sigma One
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
  condition: selection
""",
            enabled=True,
            severity="high",
        )
    )
    db.add(
        RuleRun(
            id=run_id,
            case_id=case_id,
            engine="multi",
            status=RuleRunStatus.queued,
            scope="case",
            total_rules=1,
            current_phase="queued",
            metadata_json={"requested_rule_ids": [rule_id], "scan_options": {}},
        )
    )
    db.commit()
    Session = sessionmaker(bind=db.get_bind(), autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    monkeypatch.setattr(tasks, "SessionLocal", Session)
    monkeypatch.setattr(
        tasks,
        "_build_sigma_case_profile_for_scope",
        lambda *args, **kwargs: {
            "total_events": 13,
            "source_products": ["windows"],
            "channels_present": {"Security": 13},
            "artifact_types_present": {"windows_event": 13},
            "available_fields": ["windows.event_id"],
            "field_coverage": {"windows.event_id": 13},
        },
    )
    monkeypatch.setattr(
        tasks,
        "run_rule_on_case",
        lambda *args, **kwargs: {
            "status": "completed",
            "matched": 0,
            "created_detections": 0,
            "duplicates": 0,
            "scanned_events": 13,
            "scanned_files": 0,
            "skipped_files": 0,
            "errors": [],
            "warnings": [],
        },
    )

    tasks.run_rules_on_case(case_id, [], [rule_id], False, {}, run_id)

    run = Session().get(RuleRun, run_id)
    assert run.status == RuleRunStatus.completed
    assert run.started_at is not None
    assert run.heartbeat_at is not None
    assert run.processed_rules == 1
    assert run.scanned_events == 13
    assert (run.metadata_json or {}).get("candidate_event_evaluations") == 13


def test_batch_rule_run_with_zero_rules_completes_with_warning(monkeypatch) -> None:
    db = _session()
    case_id = "dddddddd-4444-4444-8444-ddddddddddd4"
    run_id = "eeeeeeee-5555-4555-8555-eeeeeeeeeee5"
    missing_rule_id = "ffffffff-6666-4666-8666-fffffffffff6"
    db.add(Case(id=case_id, name="Case"))
    db.add(
        RuleRun(
            id=run_id,
            case_id=case_id,
            engine="multi",
            status=RuleRunStatus.queued,
            scope="case",
            total_rules=0,
            current_phase="queued",
            metadata_json={"requested_rule_ids": [missing_rule_id], "scan_options": {}},
        )
    )
    db.commit()
    Session = sessionmaker(bind=db.get_bind(), autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    monkeypatch.setattr(tasks, "SessionLocal", Session)

    tasks.run_rules_on_case(case_id, [], [missing_rule_id], False, {}, run_id)

    run = Session().get(RuleRun, run_id)
    assert run.status == RuleRunStatus.completed
    assert run.total_rules == 0
    assert run.current_phase == "completed"
    assert "No enabled rules selected." in (run.metadata_json or {}).get("warnings", [])


def test_batch_rule_run_propagates_parent_run_id_to_child_detection_metadata(monkeypatch) -> None:
    db = _session()
    case_id = "aaaa1010-1111-4111-8111-101010101010"
    rule_id = "bbbb2020-2222-4222-8222-202020202020"
    run_id = "cccc3030-3333-4333-8333-303030303030"
    db.add(Case(id=case_id, name="Case"))
    db.add(
        Rule(
            id=rule_id,
            case_id=case_id,
            name="Sigma One",
            engine=RuleEngine.sigma,
            content="""
title: Sigma One
logsource:
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
""",
            enabled=True,
            severity="medium",
        )
    )
    db.add(
        RuleRun(
            id=run_id,
            case_id=case_id,
            engine="multi",
            status=RuleRunStatus.queued,
            scope="evidence",
            total_rules=1,
            current_phase="queued",
            metadata_json={"requested_rule_ids": [rule_id], "scan_options": {"evidence_id": "evidence-1"}},
        )
    )
    db.commit()
    Session = sessionmaker(bind=db.get_bind(), autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    monkeypatch.setattr(tasks, "SessionLocal", Session)
    monkeypatch.setattr(
        tasks,
        "_build_sigma_case_profile_for_scope",
        lambda *args, **kwargs: {
            "total_events": 1,
            "source_products": ["windows"],
            "channels_present": {"Security": 1},
            "artifact_types_present": {"windows_event": 1},
            "available_fields": ["windows.event_id"],
            "field_coverage": {"windows.event_id": 1},
        },
    )
    seen: dict[str, object] = {}

    def _fake_run_rule_on_case(*args, **kwargs):
        seen["scan_options"] = kwargs.get("scan_options")
        return {
            "status": "completed",
            "matched": 0,
            "created_detections": 0,
            "duplicates": 0,
            "scanned_events": 1,
            "scanned_files": 0,
            "skipped_files": 0,
            "errors": [],
            "warnings": [],
        }

    monkeypatch.setattr(tasks, "run_rule_on_case", _fake_run_rule_on_case)

    tasks.run_rules_on_case(case_id, [], [rule_id], False, {"evidence_id": "evidence-1"}, run_id)

    assert isinstance(seen.get("scan_options"), dict)
    assert seen["scan_options"]["_aggregate_rule_run_id"] == run_id


def test_batch_rule_run_exception_marks_failed(monkeypatch) -> None:
    db = _session()
    case_id = "aaaa7777-7777-4777-8777-aaaa77777777"
    rule_id = "bbbb8888-8888-4888-8888-bbbb88888888"
    run_id = "cccc9999-9999-4999-8999-cccc99999999"
    db.add(Case(id=case_id, name="Case"))
    db.add(
        Rule(
            id=rule_id,
            case_id=case_id,
            name="Sigma One",
            engine=RuleEngine.sigma,
            content="""
title: Sigma One
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
  condition: selection
""",
            enabled=True,
            severity="high",
        )
    )
    db.add(
        RuleRun(
            id=run_id,
            case_id=case_id,
            engine="multi",
            status=RuleRunStatus.queued,
            scope="case",
            total_rules=1,
            current_phase="queued",
            metadata_json={"requested_rule_ids": [rule_id], "scan_options": {}},
        )
    )
    db.commit()
    Session = sessionmaker(bind=db.get_bind(), autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    monkeypatch.setattr(tasks, "SessionLocal", Session)
    monkeypatch.setattr(
        tasks,
        "_build_sigma_case_profile_for_scope",
        lambda *args, **kwargs: {
            "total_events": 5,
            "source_products": ["windows"],
            "channels_present": {"Security": 5},
            "artifact_types_present": {"windows_event": 5},
            "available_fields": ["windows.event_id"],
            "field_coverage": {"windows.event_id": 5},
        },
    )

    def boom(*args, **kwargs):
        raise RuntimeError("sigma compile failed")

    monkeypatch.setattr(tasks, "run_rule_on_case", boom)

    try:
        tasks.run_rules_on_case(case_id, [], [rule_id], False, {}, run_id)
    except RuntimeError as exc:
        assert "sigma compile failed" in str(exc)

    run = Session().get(RuleRun, run_id)
    assert run.status == RuleRunStatus.failed
    assert run.current_phase == "failed"
    assert "sigma compile failed" in (run.last_error or "")


def test_batch_rule_run_prefilters_sigma_rules_before_execution(monkeypatch) -> None:
    db = _session()
    case_id = "aaaa1212-7777-4777-8777-121212121212"
    runnable_rule_id = "bbbb1313-8888-4888-8888-131313131313"
    skipped_rule_id = "cccc1414-9999-4999-8999-141414141414"
    run_id = "dddd1515-aaaa-4aaa-8aaa-151515151515"
    db.add(Case(id=case_id, name="Case"))
    db.add_all(
        [
            Rule(
                id=runnable_rule_id,
                case_id=case_id,
                name="Windows Process Creation",
                engine=RuleEngine.sigma,
                content="""
title: Windows Process Creation
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: cmd.exe
  condition: selection
""",
                enabled=True,
                severity="high",
            ),
            Rule(
                id=skipped_rule_id,
                case_id=case_id,
                name="Linux Auditd",
                engine=RuleEngine.sigma,
                content="""
title: Linux Auditd
logsource:
  product: linux
  service: auditd
detection:
  selection:
    Image|endswith: bash
  condition: selection
""",
                enabled=True,
                severity="medium",
            ),
            RuleRun(
                id=run_id,
                case_id=case_id,
                engine="multi",
                status=RuleRunStatus.queued,
                scope="case",
                total_rules=2,
                current_phase="queued",
                metadata_json={"requested_rule_ids": [runnable_rule_id, skipped_rule_id], "scan_options": {}},
            ),
        ]
    )
    db.commit()
    Session = sessionmaker(bind=db.get_bind(), autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    monkeypatch.setattr(tasks, "SessionLocal", Session)
    monkeypatch.setattr(
        tasks,
        "_build_sigma_case_profile_for_scope",
        lambda *args, **kwargs: {
            "total_events": 10,
            "source_products": ["windows", "sysmon"],
            "channels_present": {"Microsoft-Windows-Sysmon/Operational": 10},
            "artifact_types_present": {"windows_event": 10},
            "available_fields": ["windows.event_id", "process.path", "process.command_line"],
            "field_coverage": {"windows.event_id": 10, "process.path": 10, "process.command_line": 10},
        },
    )

    calls: list[dict] = []

    def fake_run_rule_on_case(rule_id, case_id, evidence_id=None, dry_run=False, run_id=None, rule_set_id=None, scan_options=None):
        calls.append({"rule_id": rule_id, "scan_options": scan_options or {}})
        return {
            "status": "completed",
            "matched": 1,
            "created_detections": 1,
            "duplicates": 0,
            "scanned_events": 4,
            "scanned_files": 0,
            "skipped_files": 0,
            "errors": [],
            "warnings": [],
            "candidate_events_prefiltered": 4,
        }

    monkeypatch.setattr(tasks, "run_rule_on_case", fake_run_rule_on_case)

    tasks.run_rules_on_case(case_id, [], [runnable_rule_id, skipped_rule_id], False, {}, run_id)

    run = Session().get(RuleRun, run_id)
    assert run.status == RuleRunStatus.completed
    assert len(calls) == 1
    assert calls[0]["rule_id"] == runnable_rule_id
    assert (run.metadata_json or {}).get("total_rules_considered") == 2
    assert (run.metadata_json or {}).get("rules_considered") == 2
    assert (run.metadata_json or {}).get("total_rules_runnable") == 1
    assert (run.metadata_json or {}).get("rules_runnable_in_scope") == 1
    assert (run.metadata_json or {}).get("total_rules_executed") == 1
    assert (run.metadata_json or {}).get("total_rules_skipped") == 1
    assert (run.metadata_json or {}).get("candidate_event_evaluations") == 4
    assert (run.metadata_json or {}).get("events_in_scope") == 10
    assert (run.metadata_json or {}).get("matches_found") == 1
    assert (run.metadata_json or {}).get("display_status") == "completed_with_warnings"
    assert (run.metadata_json or {}).get("skipped_by_reason", {}).get("unsupported_platform") == 1


def test_batch_rule_rule_runtime_error_does_not_fail_whole_run(monkeypatch) -> None:
    db = _session()
    case_id = "eeee1616-1111-4111-8111-161616161616"
    ok_rule_id = "ffff1717-2222-4222-8222-171717171717"
    bad_rule_id = "aaaa1818-3333-4333-8333-181818181818"
    run_id = "bbbb1919-4444-4444-8444-191919191919"
    db.add(Case(id=case_id, name="Case"))
    db.add_all(
        [
            Rule(
                id=ok_rule_id,
                case_id=case_id,
                name="Windows Ok",
                engine=RuleEngine.sigma,
                content="""
title: Windows Ok
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
  condition: selection
""",
                enabled=True,
                severity="high",
            ),
            Rule(
                id=bad_rule_id,
                case_id=case_id,
                name="Windows Bad",
                engine=RuleEngine.sigma,
                content="""
title: Windows Bad
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
  condition: selection
""",
                enabled=True,
                severity="high",
            ),
            RuleRun(
                id=run_id,
                case_id=case_id,
                engine="multi",
                status=RuleRunStatus.queued,
                scope="case",
                total_rules=2,
                current_phase="queued",
                metadata_json={"requested_rule_ids": [ok_rule_id, bad_rule_id], "scan_options": {}},
            ),
        ]
    )
    db.commit()
    Session = sessionmaker(bind=db.get_bind(), autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    monkeypatch.setattr(tasks, "SessionLocal", Session)
    monkeypatch.setattr(
        tasks,
        "_build_sigma_case_profile_for_scope",
        lambda *args, **kwargs: {
            "total_events": 20,
            "source_products": ["windows"],
            "channels_present": {"Security": 20},
            "artifact_types_present": {"windows_event": 20},
            "available_fields": ["windows.event_id", "process.command_line"],
            "field_coverage": {"windows.event_id": 20, "process.command_line": 20},
        },
    )

    def fake_run_rule_on_case(rule_id, case_id, evidence_id=None, dry_run=False, run_id=None, rule_set_id=None, scan_options=None):
        if rule_id == bad_rule_id:
            return {
                "status": "failed",
                "matched": 0,
                "created_detections": 0,
                "duplicates": 0,
                "scanned_events": 5,
                "scanned_files": 0,
                "skipped_files": 0,
                "errors": ["RequestError(400, 'bad sigma query')"],
                "warnings": [],
                "candidate_events_prefiltered": 5,
            }
        return {
            "status": "completed",
            "matched": 2,
            "created_detections": 0,
            "duplicates": 2,
            "scanned_events": 7,
            "scanned_files": 0,
            "skipped_files": 0,
            "errors": [],
            "warnings": [],
            "candidate_events_prefiltered": 7,
        }

    monkeypatch.setattr(tasks, "run_rule_on_case", fake_run_rule_on_case)

    tasks.run_rules_on_case(case_id, [], [ok_rule_id, bad_rule_id], False, {}, run_id)

    run = Session().get(RuleRun, run_id)
    metadata = run.metadata_json or {}
    assert run.status == RuleRunStatus.completed
    assert metadata.get("display_status") == "completed_with_warnings"
    assert metadata.get("rules_runtime_error") == 1
    assert metadata.get("matches_found") == 2
    assert run.duplicates == 2
    assert metadata.get("candidate_event_evaluations") == 12
    assert metadata.get("events_in_scope") == 20
    assert "RequestError(400, 'bad sigma query')" in (metadata.get("runtime_errors") or [])


def test_batch_run_counts_child_runtime_errors_without_failing_batch(monkeypatch) -> None:
    db = _session()
    case_id = "aaaa2020-2020-4020-8020-aaaa20202020"
    rule_id = "bbbb2020-2020-4020-8020-bbbb20202020"
    run_id = "cccc2020-2020-4020-8020-cccc20202020"
    db.add(Case(id=case_id, name="Case"))
    db.add(
        Rule(
            id=rule_id,
            case_id=case_id,
            name="Sigma Runtime Warning",
            engine=RuleEngine.sigma,
            content="""
title: Sigma Runtime Warning
logsource:
  product: windows
detection:
  selection:
    EventID: 4688
  condition: selection
""",
            enabled=True,
            severity="high",
        )
    )
    db.add(
        RuleRun(
            id=run_id,
            case_id=case_id,
            engine="multi",
            status=RuleRunStatus.queued,
            scope="case",
            total_rules=1,
            current_phase="queued",
            metadata_json={"requested_rule_ids": [rule_id], "scan_options": {}},
        )
    )
    db.commit()
    Session = sessionmaker(bind=db.get_bind(), autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    monkeypatch.setattr(tasks, "SessionLocal", Session)
    monkeypatch.setattr(
        tasks,
        "_build_sigma_case_profile_for_scope",
        lambda *args, **kwargs: {
            "total_events": 10,
            "source_products": ["windows"],
            "channels_present": {"Security": 10},
            "artifact_types_present": {"windows_event": 10},
            "available_fields": ["windows.event_id"],
            "field_coverage": {"windows.event_id": 10},
        },
    )
    monkeypatch.setattr(
        tasks,
        "run_rule_on_case",
        lambda *args, **kwargs: {
            "status": "completed",
            "matched": 2,
            "created_detections": 0,
            "duplicates": 2,
            "runtime_errors_count": 1,
            "runtime_errors": ["Detection creation failed for rule Sigma Runtime Warning: orphan evidence"],
            "scanned_events": 10,
            "scanned_files": 0,
            "skipped_files": 0,
            "errors": [],
            "warnings": ["Detection creation failed for rule Sigma Runtime Warning: orphan evidence"],
        },
    )

    tasks.run_rules_on_case(case_id, [], [rule_id], False, {}, run_id)

    run = Session().get(RuleRun, run_id)
    metadata = run.metadata_json or {}
    assert run.status == RuleRunStatus.completed
    assert metadata.get("display_status") == "completed_with_warnings"
    assert metadata.get("rules_runtime_error") == 1
    assert metadata.get("matches_found") == 2
    assert run.duplicates == 2


def test_batch_run_aggregates_sigma_performance_and_noisy_rule_metrics(monkeypatch) -> None:
    db = _session()
    case_id = "aaaa3030-3030-4030-8030-aaaa30303030"
    rule_id = "bbbb3030-3030-4030-8030-bbbb30303030"
    run_id = "cccc3030-3030-4030-8030-cccc30303030"
    db.add(Case(id=case_id, name="Case"))
    db.add(
        Rule(
            id=rule_id,
            case_id=case_id,
            name="Sigma Perf",
            engine=RuleEngine.sigma,
            content="""
title: Sigma Perf
logsource:
  product: windows
detection:
  selection:
    EventID: 4688
  condition: selection
""",
            enabled=True,
            severity="high",
        )
    )
    db.add(
        RuleRun(
            id=run_id,
            case_id=case_id,
            engine="multi",
            status=RuleRunStatus.queued,
            scope="case",
            total_rules=1,
            current_phase="queued",
            metadata_json={"requested_rule_ids": [rule_id], "scan_options": {}},
        )
    )
    db.commit()
    Session = sessionmaker(bind=db.get_bind(), autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    monkeypatch.setattr(tasks, "SessionLocal", Session)
    monkeypatch.setattr(
        tasks,
        "_build_sigma_case_profile_for_scope",
        lambda *args, **kwargs: {
            "total_events": 42,
            "source_products": ["windows"],
            "channels_present": {"Security": 42},
            "artifact_types_present": {"windows_event": 42},
            "available_fields": ["windows.event_id"],
            "field_coverage": {"windows.event_id": 42},
        },
    )
    monkeypatch.setattr(
        tasks,
        "run_rule_on_case",
        lambda *args, **kwargs: {
            "status": "completed",
            "matched": 1000,
            "created_detections": 250,
            "duplicates": 750,
            "runtime_errors_count": 0,
            "runtime_errors": [],
            "scanned_events": 2000,
            "scanned_files": 0,
            "skipped_files": 0,
            "errors": [],
            "warnings": ["Rule Sigma Perf produced too many matches and was capped."],
            "query_time_ms_total": 120,
            "dedupe_time_ms_total": 35,
            "write_time_ms_total": 40,
            "bulk_insert_batches": 1,
            "bulk_duplicate_lookups": 1,
            "noisy_rules_count": 1,
            "capped_rules_count": 1,
            "top_noisy_rules": [{"rule_id": rule_id, "rule_name": "Sigma Perf", "matches_found": 1000}],
            "current_rule_duration_ms": 240,
        },
    )

    tasks.run_rules_on_case(case_id, [], [rule_id], False, {}, run_id)

    run = Session().get(RuleRun, run_id)
    metadata = run.metadata_json or {}
    assert run.status == RuleRunStatus.completed
    assert metadata.get("query_time_ms_total") == 120
    assert metadata.get("dedupe_time_ms_total") == 35
    assert metadata.get("write_time_ms_total") == 40
    assert metadata.get("bulk_insert_batches") == 1
    assert metadata.get("bulk_duplicate_lookups") == 1
    assert metadata.get("noisy_rules_count") == 1
    assert metadata.get("capped_rules_count") == 1
    assert metadata.get("top_noisy_rules")[0]["rule_name"] == "Sigma Perf"


def test_rule_run_serialization_exposes_sigma_mode_and_broadness_metrics() -> None:
    db = _session()
    db.add(Case(id="case-sigma-mode", name="Case"))
    run = RuleRun(
        id="run-sigma-mode",
        case_id="case-sigma-mode",
        engine="sigma",
        status=RuleRunStatus.completed,
        scope="case",
        total_rules=4,
        processed_rules=4,
        total_events=5000,
        scanned_events=1200,
        matched=250,
        created_detections=80,
        duplicates=170,
        current_phase="completed",
        metadata_json={
            "sigma_run_mode": "fast_triage",
            "sigma_run_mode_config": {"max_candidate_events_per_rule": 5000},
            "candidate_count_estimate": 12000,
            "candidate_event_evaluations": 1200,
            "noisy_rules_count": 2,
            "capped_rules_count": 1,
            "skipped_too_broad_count": 1,
            "matches_capped_count": 1,
            "detections_capped_count": 1,
        },
    )
    db.add(run)
    db.commit()

    payload = _serialize_rule_run(run)
    assert payload.metadata_json["sigma_run_mode"] == "fast_triage"
    assert payload.metadata_json["candidate_count_estimate"] == 12000
    assert payload.metadata_json["skipped_too_broad_count"] == 1
    assert payload.metadata_json["matches_capped_count"] == 1
    assert payload.metadata_json["detections_capped_count"] == 1


def test_batch_run_aggregates_skipped_too_broad_and_sigma_mode(monkeypatch) -> None:
    db = _session()
    case_id = "aaaa4040-4040-4040-8040-aaaa40404040"
    rule_id = "bbbb4040-4040-4040-8040-bbbb40404040"
    run_id = "cccc4040-4040-4040-8040-cccc40404040"
    db.add(Case(id=case_id, name="Case"))
    db.add(
        Rule(
            id=rule_id,
            case_id=case_id,
            name="Sigma Broad",
            engine=RuleEngine.sigma,
            content="""
title: Sigma Broad
logsource:
  product: windows
detection:
  selection:
    EventID: 4688
  condition: selection
""",
            enabled=True,
            severity="medium",
        )
    )
    db.add(
        RuleRun(
            id=run_id,
            case_id=case_id,
            engine="multi",
            status=RuleRunStatus.queued,
            scope="case",
            total_rules=1,
            current_phase="queued",
            metadata_json={"requested_rule_ids": [rule_id], "scan_options": {"sigma_run_mode": "fast_triage"}},
        )
    )
    db.commit()
    Session = sessionmaker(bind=db.get_bind(), autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    monkeypatch.setattr(tasks, "SessionLocal", Session)
    monkeypatch.setattr(tasks, "_build_sigma_case_profile_for_scope", lambda *args, **kwargs: {"total_events": 100})
    monkeypatch.setattr(
        tasks,
        "preflight_compiled_sigma_rule",
        lambda *args, **kwargs: {
            "status": "ready",
            "reason": None,
            "logsource": {"product": "windows"},
            "missing_fields": [],
            "fields": ["windows.event_id"],
            "prefilter": {"event_ids": [4688]},
        },
    )
    monkeypatch.setattr(
        tasks,
        "run_rule_on_case",
        lambda *args, **kwargs: {
            "status": "skipped",
            "matched": 0,
            "created_detections": 0,
            "duplicates": 0,
            "scanned_events": 0,
            "scanned_files": 0,
            "skipped_files": 0,
            "errors": [],
            "warnings": ["Rule Sigma Broad was skipped in fast_triage mode because it is too broad."],
            "skipped_by_reason": {"too_broad": 1},
            "skipped_too_broad_count": 1,
            "sigma_run_mode": "fast_triage",
            "top_noisy_rules": [{"rule_id": rule_id, "rule_name": "Sigma Broad", "status": "skipped_too_broad"}],
        },
    )

    tasks.run_rules_on_case(case_id, [], [rule_id], False, {"sigma_run_mode": "fast_triage"}, run_id)

    run = Session().get(RuleRun, run_id)
    metadata = run.metadata_json or {}
    assert metadata.get("sigma_run_mode") == "fast_triage"
    assert metadata.get("skipped_too_broad_count") == 1
    assert metadata.get("skipped_by_reason", {}).get("too_broad") == 1
