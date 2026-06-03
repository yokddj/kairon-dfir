from __future__ import annotations

from pathlib import Path
import tempfile
from datetime import datetime, UTC
import pytest

from sqlalchemy import event
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.activity import log_activity
from app.core.database import Base
from app.core.detections import create_detection_if_missing, create_detections_bulk_if_missing, get_existing_detection_keys
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.detection_result import DetectionResult
from app.models.evidence import Evidence, EvidenceType
from app.models.rule import Rule, RuleEngine
from app.models.rule_run import RuleRun, RuleRunStatus
from app.models.rule_set import RuleSet
from fastapi import HTTPException

from app.rules_engine import yara_engine
from app.rules_engine.sigma import (
    build_sigma_case_profile,
    build_sigma_rule_prefilter,
    compile_sigma_rule,
    document_matches_sigma_logsource,
    evaluate_sigma_rule,
    evaluate_compiled_sigma_rule,
    parse_sigma_rule,
    preflight_compiled_sigma_rule,
    preflight_sigma_rule,
    validate_sigma_rule_content,
)
from app.api.routes_rules import _queue_case_rules_run, _resolve_sigma_smoke_rules, _sigma_smoke_preflight_results, delete_bulk_detections, detections_summary, update_bulk_detections
from app.schemas.debug_export import DebugExportRequest
from app.schemas.rule import DetectionBulkActionRequestV2, DetectionBulkFilterSet, RulesRunRequest, SigmaSmokeRequest
from app.services.debug_export import _DebugPackContext, _build_detections_report, _build_rules_run_report

CASE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
EVIDENCE_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
RULE_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return Session()


def test_queue_case_rules_run_rejects_evidence_without_indexed_docs(monkeypatch) -> None:
    db = _session()
    case = Case(id=CASE_ID, name="Case")
    evidence = Evidence(
        id=EVIDENCE_ID,
        case_id=CASE_ID,
        original_filename="collection.zip",
        stored_path="/tmp/collection.zip",
        sha256="abc",
        size_bytes=1,
        evidence_type=EvidenceType.unknown,
        ingest_status="completed",
    )
    rule = Rule(
        id=RULE_ID,
        case_id=CASE_ID,
        name="sigma-test",
        engine=RuleEngine.sigma,
        content="title: Test\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n",
        enabled=True,
    )
    db.add_all([case, evidence, rule])
    db.commit()

    monkeypatch.setattr("app.api.routes_rules.count_documents", lambda *args, **kwargs: {"count": 0})

    with pytest.raises(HTTPException) as exc:
        _queue_case_rules_run(
            db,
            case_id=CASE_ID,
            payload=RulesRunRequest(mode="on_demand", scope="evidence", evidence_id=EVIDENCE_ID, rule_types=["sigma"]),
        )

    assert exc.value.status_code == 409
    assert "no indexed documents" in str(exc.value.detail).lower()


def test_detection_summary_groups_by_rule_status_and_host() -> None:
    db = _session()
    db.add(Case(id=CASE_ID, name="Case"))
    db.add(
        Evidence(
            id=EVIDENCE_ID,
            case_id=CASE_ID,
            original_filename="collection.zip",
            stored_path="/tmp/collection.zip",
            sha256="abc",
            size_bytes=1,
            evidence_type=EvidenceType.unknown,
            ingest_status="completed",
        )
    )
    db.add_all(
        [
            DetectionResult(
                id="a1111111-1111-4111-8111-111111111111",
                case_id=CASE_ID,
                evidence_id=EVIDENCE_ID,
                engine="sigma",
                source_engine="sigma",
                rule_id=RULE_ID,
                rule_name="Encoded PowerShell",
                rule_title="Encoded PowerShell",
                severity="high",
                event_id="evt-1",
                target_type="event",
                host_name="HOSTA",
                status="new",
                message="encoded command",
                raw={"artifact_type": "windows_event", "source_file": "Security.evtx", "rule_run_id": "run-1", "event_preview": {"user": "alice"}},
            ),
            DetectionResult(
                id="b2222222-2222-4222-8222-222222222222",
                case_id=CASE_ID,
                evidence_id=EVIDENCE_ID,
                engine="sigma",
                source_engine="sigma",
                rule_id=RULE_ID,
                rule_name="Encoded PowerShell",
                rule_title="Encoded PowerShell",
                severity="high",
                event_id="evt-2",
                target_type="event",
                host_name="HOSTA",
                status="reviewed",
                message="encoded command",
                raw={"artifact_type": "windows_event", "source_file": "Security.evtx", "rule_run_id": "run-1", "event_preview": {"user": "bob"}},
            ),
            DetectionResult(
                id="c3333333-3333-4333-8333-333333333333",
                case_id=CASE_ID,
                evidence_id=EVIDENCE_ID,
                engine="sigma",
                source_engine="sigma",
                rule_id="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                rule_name="Suspicious Download",
                rule_title="Suspicious Download",
                severity="medium",
                event_id="evt-3",
                target_type="event",
                host_name="HOSTB",
                status="dismissed",
                message="download",
                raw={"artifact_type": "browser", "source_file": "History", "rule_run_id": "run-2", "event_preview": {"user": "alice"}},
            ),
            DetectionResult(
                id="f6666666-6666-4666-8666-666666666666",
                case_id=CASE_ID,
                evidence_id=EVIDENCE_ID,
                engine="sigma",
                source_engine="sigma",
                rule_id=RULE_ID,
                rule_name="Encoded PowerShell",
                rule_title="Encoded PowerShell",
                severity="high",
                event_id="evt-4",
                target_type="event",
                host_name="HOSTA",
                status="new",
                deleted_at=datetime.now(UTC),
                message="soft deleted",
                raw={"artifact_type": "windows_event", "source_file": "Security.evtx", "rule_run_id": "run-1", "event_preview": {"user": "alice"}},
            ),
        ]
    )
    db.commit()

    result = detections_summary(case_id=CASE_ID, status_value=None, limit=50, db=db)

    assert result["total"] == 3
    assert result["state"] == {"active": 3, "soft_deleted": 1, "dismissed": 1, "reviewed": 1, "confirmed": 0}
    assert result["by_severity"] == {"high": 2, "medium": 1}
    assert result["by_status"] == {"new": 1, "reviewed": 1, "dismissed": 1}
    assert result["by_rule"][0]["rule_name"] == "Encoded PowerShell"
    assert result["by_rule"][0]["count"] == 2
    assert result["by_rule"][0]["new_count"] == 1
    assert result["by_rule"][0]["reviewed_count"] == 1
    assert result["by_host"][0] == {"key": "HOSTA", "count": 2}
    assert result["by_user"][0] == {"key": "alice", "count": 2}
    assert result["by_artifact_type"][0] == {"key": "windows_event", "count": 2}
    assert result["top_noisy_rules"][0]["percentage"] == 66.67


def test_detection_group_bulk_review_updates_matching_rule_only() -> None:
    db = _session()
    db.add(Case(id=CASE_ID, name="Case"))
    db.add_all(
        [
            DetectionResult(
                id="d4444444-4444-4444-8444-444444444444",
                case_id=CASE_ID,
                engine="sigma",
                rule_id=RULE_ID,
                rule_name="Encoded PowerShell",
                severity="high",
                target_type="event",
                status="new",
                raw={},
            ),
            DetectionResult(
                id="e5555555-5555-4555-8555-555555555555",
                case_id=CASE_ID,
                engine="sigma",
                rule_id="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                rule_name="Other Rule",
                severity="high",
                target_type="event",
                status="new",
                raw={},
            ),
        ]
    )
    db.commit()

    response = update_bulk_detections(
        DetectionBulkActionRequestV2(
            action="mark_reviewed",
            mode="matching",
            filters=DetectionBulkFilterSet(case_id=CASE_ID, rule_name="Encoded PowerShell"),
        ),
        db,
    )

    assert response.matched == 1
    assert response.updated == 1
    assert db.get(DetectionResult, "d4444444-4444-4444-8444-444444444444").status == "reviewed"
    assert db.get(DetectionResult, "d4444444-4444-4444-8444-444444444444").deleted_at is None
    assert db.get(DetectionResult, "e5555555-5555-4555-8555-555555555555").status == "new"


def test_detection_group_bulk_dismiss_does_not_soft_delete() -> None:
    db = _session()
    db.add(Case(id=CASE_ID, name="Case"))
    db.add(
        DetectionResult(
            id="d4444444-4444-4444-8444-444444444444",
            case_id=CASE_ID,
            engine="sigma",
            rule_id=RULE_ID,
            rule_name="Encoded PowerShell",
            severity="high",
            target_type="event",
            status="new",
            raw={},
        )
    )
    db.commit()

    response = update_bulk_detections(
        DetectionBulkActionRequestV2(
            action="mark_dismissed",
            mode="matching",
            filters=DetectionBulkFilterSet(case_id=CASE_ID, rule_name="Encoded PowerShell"),
        ),
        db,
    )

    detection = db.get(DetectionResult, "d4444444-4444-4444-8444-444444444444")
    assert response.updated == 1
    assert detection.status == "dismissed"
    assert detection.deleted_at is None


def test_detection_bulk_delete_requires_counted_confirmation() -> None:
    db = _session()
    db.add(Case(id=CASE_ID, name="Case"))
    for idx in range(2):
        db.add(
            DetectionResult(
                id=f"d4444444-4444-4444-8444-44444444444{idx}",
                case_id=CASE_ID,
                engine="sigma",
                rule_id=RULE_ID,
                rule_name="Encoded PowerShell",
                severity="high",
                target_type="event",
                status="new",
                raw={},
            )
        )
    db.commit()

    with pytest.raises(HTTPException):
        delete_bulk_detections(
            DetectionBulkActionRequestV2(
                mode="matching",
                filters=DetectionBulkFilterSet(case_id=CASE_ID, rule_name="Encoded PowerShell"),
                confirm="DELETE DETECTIONS",
            ),
            db,
        )

    response = delete_bulk_detections(
        DetectionBulkActionRequestV2(
            mode="matching",
            filters=DetectionBulkFilterSet(case_id=CASE_ID, rule_name="Encoded PowerShell"),
            confirm="DELETE 2 DETECTIONS",
        ),
        db,
    )

    assert response.deleted == 2
    assert db.query(DetectionResult).filter(DetectionResult.deleted_at.is_not(None)).count() == 2


def test_queue_case_rules_run_rejects_duplicate_active_evidence_run(monkeypatch) -> None:
    db = _session()
    case = Case(id=CASE_ID, name="Case")
    evidence = Evidence(
        id=EVIDENCE_ID,
        case_id=CASE_ID,
        original_filename="collection.zip",
        stored_path="/tmp/collection.zip",
        sha256="abc",
        size_bytes=1,
        evidence_type=EvidenceType.unknown,
        ingest_status="completed",
    )
    rule = Rule(
        id=RULE_ID,
        case_id=CASE_ID,
        name="sigma-test",
        engine=RuleEngine.sigma,
        content="title: Test\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n",
        enabled=True,
    )
    active_run = RuleRun(
        id="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        case_id=CASE_ID,
        evidence_id=EVIDENCE_ID,
        engine="multi",
        scope="evidence",
        status=RuleRunStatus.running,
        matched=0,
        total_rules=1,
        processed_rules=0,
        total_events=0,
        scanned_events=0,
        total_files=0,
        created_detections=0,
        duplicates=0,
        scanned_files=0,
        skipped_files=0,
        metadata_json={},
    )
    db.add_all([case, evidence, rule, active_run])
    db.commit()

    monkeypatch.setattr("app.api.routes_rules.count_documents", lambda *args, **kwargs: {"count": 53})

    with pytest.raises(HTTPException) as exc:
        _queue_case_rules_run(
            db,
            case_id=CASE_ID,
            payload=RulesRunRequest(mode="on_demand", scope="evidence", evidence_id=EVIDENCE_ID, rule_types=["sigma"]),
        )

    assert exc.value.status_code == 409
    assert "already active" in str(exc.value.detail).lower()


def test_queue_case_rules_run_persists_on_demand_metadata(monkeypatch) -> None:
    db = _session()
    case = Case(id=CASE_ID, name="Case")
    evidence = Evidence(
        id=EVIDENCE_ID,
        case_id=CASE_ID,
        original_filename="collection.zip",
        stored_path="/tmp/collection.zip",
        sha256="abc",
        size_bytes=1,
        evidence_type=EvidenceType.unknown,
        ingest_status="completed",
    )
    rule = Rule(
        id=RULE_ID,
        case_id=CASE_ID,
        name="sigma-test",
        engine=RuleEngine.sigma,
        content="title: Test\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n",
        enabled=True,
    )
    db.add_all([case, evidence, rule])
    db.commit()

    monkeypatch.setattr("app.api.routes_rules.count_documents", lambda *args, **kwargs: {"count": 53})
    monkeypatch.setattr("app.api.routes_rules.enqueue_rules_run", lambda **kwargs: "job-123")
    monkeypatch.setattr("app.api.routes_rules.log_activity", lambda *args, **kwargs: None)

    result = _queue_case_rules_run(
        db,
        case_id=CASE_ID,
        payload=RulesRunRequest(mode="on_demand", scope="evidence", evidence_id=EVIDENCE_ID, rule_types=["sigma"]),
        requested_via="evidence_on_demand",
    )

    assert result["accepted"] is True
    queued = db.get(RuleRun, result["run_id"])
    assert queued is not None
    assert queued.evidence_id == EVIDENCE_ID
    assert queued.metadata_json["mode"] == "on_demand"
    assert queued.metadata_json["requested_via"] == "evidence_on_demand"
    assert queued.metadata_json["requested_by"] == "manual"
    assert queued.metadata_json["indexed_events_input_count"] == 53


def test_validate_valid_sigma_rule() -> None:
    result = validate_sigma_rule_content(
        """
title: Encoded PowerShell
id: sigma-encoded-ps
level: high
detection:
  selection:
    Image|endswith: powershell.exe
    CommandLine|contains: -EncodedCommand
  condition: selection
"""
    )
    assert result["valid"] is True
    assert result["rules_count"] == 1


def test_reject_invalid_sigma_yaml() -> None:
    try:
        validate_sigma_rule_content("title: broken\ndetection: not-a-map")
    except ValueError as exc:
        assert "detection section" in str(exc)
    else:
        raise AssertionError("Expected invalid Sigma YAML to raise")


def test_sigma_encoded_powershell_match_and_field_mapping() -> None:
    rule = parse_sigma_rule(
        """
title: Encoded PowerShell
id: sigma-encoded-ps
level: high
detection:
  selection:
    Image|endswith: powershell.exe
    CommandLine|contains: -EncodedCommand
    EventID: 4688
  condition: selection
"""
    )[0]
    event = {
        "windows": {"event_id": "4688"},
        "process": {"path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "command_line": "powershell.exe -EncodedCommand AAAA"},
    }
    result = evaluate_sigma_rule(rule, event)
    assert result["matched"] is True
    assert set(result["matched_fields"]) == {"Image|endswith", "CommandLine|contains", "EventID"}


def test_sigma_selection_and_not_filter() -> None:
    rule = parse_sigma_rule(
        """
title: Office Spawns PowerShell
detection:
  selection:
    ParentImage|endswith: WINWORD.EXE
    Image|endswith: powershell.exe
  filter:
    CommandLine|contains: benign
  condition: selection and not filter
"""
    )[0]
    bad = {
        "process": {
            "parent_path": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "powershell.exe benign test",
        }
    }
    good = {
        "process": {
            "parent_path": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "powershell.exe -EncodedCommand AAAA",
        }
    }
    assert evaluate_sigma_rule(rule, bad)["matched"] is False
    assert evaluate_sigma_rule(rule, good)["matched"] is True


def test_sigma_case_profile_detects_windows_sysmon_fields() -> None:
    profile = build_sigma_case_profile(
        [
            {
                "artifact": {"type": "windows_event", "parser": "evtx_raw"},
                "windows": {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon"},
                "process": {"path": r"C:\\Windows\\System32\\cmd.exe", "command_line": "cmd.exe /c whoami"},
                "host": {"name": "hosta"},
            },
            {
                "artifact": {"type": "windows_event", "parser": "evtx_raw"},
                "windows": {"event_id": 13, "channel": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon"},
                "registry": {"key_path": r"HKCU\\Software\\Classes\\mscfile\\shell\\open\\command", "value_data": "cmd.exe"},
            },
        ],
        total_events=2,
    )
    assert profile["total_events"] == 2
    assert "windows" in profile["source_products"]
    assert "sysmon" in profile["source_products"]
    assert "windows.event_id" in profile["available_fields"]
    assert "process.command_line" in profile["available_fields"]
    assert "registry.key_path" in profile["available_fields"]


def test_sigma_preflight_classifies_windows_rule_as_runnable() -> None:
    rule = parse_sigma_rule(
        """
title: Suspicious Process
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: cmd.exe
    CommandLine|contains: whoami
  condition: selection
"""
    )[0]
    profile = build_sigma_case_profile(
        [
            {
                "artifact": {"type": "windows_event", "parser": "evtx_raw"},
                "windows": {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational"},
                "process": {"path": r"C:\\Windows\\System32\\cmd.exe", "command_line": "cmd.exe /c whoami"},
            }
        ],
        total_events=1,
    )
    preflight = preflight_sigma_rule(rule, profile)
    assert preflight["status"] == "runnable"
    assert build_sigma_rule_prefilter(rule, profile)["event_ids"] == [1]


def test_sigma_smoke_preflight_explains_field_mapping(monkeypatch) -> None:
    db = _session()
    case = Case(id=CASE_ID, name="Case")
    rule = Rule(
        id=RULE_ID,
        case_id=None,
        name="powershell-bypass",
        title="PowerShell Bypass",
        engine=RuleEngine.sigma,
        enabled=True,
        content="""
title: PowerShell Bypass
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-ep bypass'
  condition: selection
""",
    )
    db.add_all([case, rule])
    db.commit()

    monkeypatch.setattr(
        "app.workers.tasks._build_sigma_case_profile_for_scope",
        lambda *args, **kwargs: build_sigma_case_profile(
            [
                {
                    "artifact": {"type": "windows_event", "parser": "evtxecmd_csv"},
                    "windows": {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational"},
                    "process": {"path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "command_line": "powershell.exe -ep bypass"},
                }
            ],
            total_events=1,
        ),
    )
    monkeypatch.setattr("app.workers.tasks._build_sigma_search_body", lambda *args, **kwargs: {"query": {"match_all": {}}})
    monkeypatch.setattr("app.api.routes_rules.count_documents", lambda *args, **kwargs: {"count": 1})

    payload = SigmaSmokeRequest(case_id=CASE_ID, mode="single_rule", rule_id=RULE_ID)
    rules = _resolve_sigma_smoke_rules(db, payload)
    results, _profile = _sigma_smoke_preflight_results(db, payload, rules)

    assert len(results) == 1
    assert results[0].status == "ready"
    assert results[0].scanned_events == 1
    assert results[0].field_mappings["CommandLine"] == ["process.command_line"]
    assert results[0].expected_logsource == {"product": "windows", "category": "process_creation"}


def test_sigma_smoke_max_rules_enforced() -> None:
    db = _session()
    db.add(Case(id=CASE_ID, name="Case"))
    for index in range(2):
        db.add(
            Rule(
                id=f"cccccccc-cccc-4ccc-8ccc-ccccccccccc{index}",
                case_id=None,
                name=f"sigma-{index}",
                engine=RuleEngine.sigma,
                enabled=True,
                content="title: Test\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n",
            )
        )
    db.commit()

    with pytest.raises(HTTPException) as exc:
        _resolve_sigma_smoke_rules(db, SigmaSmokeRequest(case_id=CASE_ID, mode="subset", max_rules=1))

    assert exc.value.status_code == 400
    assert "capped" in str(exc.value.detail)


def test_detection_summary_filters_smoke_run_type() -> None:
    db = _session()
    db.add(Case(id=CASE_ID, name="Case"))
    db.add_all(
        [
            DetectionResult(
                id="aaaaaaaa-1111-4111-8111-111111111111",
                case_id=CASE_ID,
                rule_id=RULE_ID,
                engine="sigma",
                source_engine="sigma",
                rule_name="Smoke",
                target_type="event",
                raw={"run_type": "smoke", "rule_run_id": "run-smoke"},
            ),
            DetectionResult(
                id="bbbbbbbb-2222-4222-8222-222222222222",
                case_id=CASE_ID,
                rule_id=RULE_ID,
                engine="sigma",
                source_engine="sigma",
                rule_name="Normal",
                target_type="event",
                raw={"rule_run_id": "run-normal"},
            ),
        ]
    )
    db.commit()

    summary = detections_summary(case_id=CASE_ID, run_type="smoke", status_value=None, limit=50, db=db)

    assert summary["total"] == 1
    assert summary["by_rule"][0]["rule_name"] == "Smoke"


def test_sigma_compilation_can_be_reused_for_preflight_and_matching() -> None:
    rule = parse_sigma_rule(
        """
title: Suspicious Process
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: cmd.exe
    CommandLine|contains: whoami
  condition: selection
"""
    )[0]
    compiled = compile_sigma_rule(rule)
    assert compiled["compile_status"] == "compiled"
    profile = build_sigma_case_profile(
        [
            {
                "artifact": {"type": "windows_event", "parser": "evtx_raw"},
                "windows": {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational"},
                "process": {"path": r"C:\\Windows\\System32\\cmd.exe", "command_line": "cmd.exe /c whoami"},
            }
        ],
        total_events=1,
    )
    assert preflight_compiled_sigma_rule(compiled, profile)["status"] == "runnable"
    event = {
        "windows": {"event_id": "1"},
        "process": {"path": r"C:\Windows\System32\cmd.exe", "command_line": "cmd.exe /c whoami"},
    }
    assert evaluate_compiled_sigma_rule(compiled, event)["matched"] is True


def test_process_creation_rule_does_not_match_sysmon_file_create() -> None:
    rule = parse_sigma_rule(
        """
title: Whoami.EXE Execution From Privileged Process
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\whoami.exe'
    User|contains:
      - 'NT AUTHORITY\\SYSTEM'
      - 'TrustedInstaller'
  condition: selection
"""
    )[0]
    compiled = compile_sigma_rule(rule)
    file_create_event = {
        "artifact": {"type": "windows_event", "parser": "evtxecmd_csv"},
        "windows": {"event_id": 11, "channel": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon"},
        "event": {"type": "sysmon_file_created", "action": "FileCreate"},
        "user": {"name": "NT AUTHORITY\\SYSTEM"},
        "file": {"path": r"C:\Windows\Temp\whoami.exe"},
    }

    logsource_ok, reason = document_matches_sigma_logsource(compiled["sigma_logsource"], file_create_event)
    assert logsource_ok is False
    assert reason == "logsource_mismatch"
    result = evaluate_compiled_sigma_rule(compiled, file_create_event)
    assert result["matched"] is False
    assert result["skip_reason"] == "logsource_mismatch"
    assert result["actual_event_source"]["event_id"] == 11


def test_process_creation_rule_matches_valid_sysmon_process_create() -> None:
    rule = parse_sigma_rule(
        """
title: Whoami.EXE Execution From Privileged Process
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\whoami.exe'
    User|contains:
      - 'NT AUTHORITY\\SYSTEM'
      - 'TrustedInstaller'
  condition: selection
"""
    )[0]
    compiled = compile_sigma_rule(rule)
    process_event = {
        "artifact": {"type": "windows_event", "parser": "evtxecmd_csv"},
        "windows": {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon"},
        "event": {"type": "process_creation", "action": "Process Create"},
        "user": {"name": "NT AUTHORITY\\SYSTEM"},
        "process": {"path": r"C:\Windows\System32\whoami.exe", "name": "whoami.exe"},
    }

    result = evaluate_compiled_sigma_rule(compiled, process_event)
    assert result["matched"] is True
    assert set(result["matched_fields"]) == {"Image|endswith", "User|contains"}
    assert result["expected_logsource"] == {"product": "windows", "category": "process_creation"}
    assert result["actual_event_source"]["event_id"] == 1


def test_sigma_preflight_skips_incompatible_platform_and_missing_fields() -> None:
    mac_rule = parse_sigma_rule(
        """
title: Mac Process
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image|endswith: bash
  condition: selection
"""
    )[0]
    windows_profile = build_sigma_case_profile(
        [{"artifact": {"type": "windows_event", "parser": "evtx_raw"}, "windows": {"event_id": 4688, "channel": "Security"}, "process": {"path": "powershell.exe"}}],
        total_events=1,
    )
    mac_preflight = preflight_sigma_rule(mac_rule, windows_profile)
    assert mac_preflight["status"] == "skipped_unsupported_platform"

    missing_field_rule = parse_sigma_rule(
        """
title: Registry Rule
logsource:
  product: windows
  category: registry_set
detection:
  selection:
    TargetObject|contains: \\\\Run
    Details|contains: powershell
  condition: selection
"""
    )[0]
    missing_preflight = preflight_sigma_rule(missing_field_rule, windows_profile)
    assert missing_preflight["status"] == "skipped_missing_fields"
    assert "TargetObject" in missing_preflight["missing_fields"]


def test_sigma_preflight_accepts_supported_one_of_condition() -> None:
    rule = parse_sigma_rule(
        """
title: Unsupported Condition
logsource:
  product: windows
detection:
  selection_a:
    Image|endswith: cmd.exe
  selection_b:
    Image|endswith: powershell.exe
  condition: 1 of selection_*
"""
    )[0]
    profile = build_sigma_case_profile(
        [{"artifact": {"type": "windows_event", "parser": "evtx_raw"}, "windows": {"event_id": 4688, "channel": "Security"}, "process": {"path": "cmd.exe"}}],
        total_events=1,
    )
    preflight = preflight_sigma_rule(rule, profile)
    assert preflight["status"] == "runnable"


def test_create_detection_sanitizes_orphaned_evidence_reference() -> None:
    db = _session()
    db.add(Case(id=CASE_ID, name="Case"))
    db.commit()

    detection, created = create_detection_if_missing(
        db,
        case_id=CASE_ID,
        evidence_id="deadbeef-dead-4ead-8ead-deaddeaddead",
        artifact_id=None,
        rule_id=None,
        rule_set_id=None,
        engine="sigma",
        source_engine="sigma",
        rule_name="Sigma Orphan",
        severity="medium",
        confidence=0.5,
        event_id="event-1",
        event_index="dfir-events-test",
        opensearch_id="os-hit-1",
        target_type="event",
        target_path=None,
        message="orphan evidence reference",
    )

    assert created is True
    assert detection.evidence_id is None


def test_log_activity_sanitizes_orphaned_evidence_reference() -> None:
    db = _session()
    db.add(Case(id=CASE_ID, name="Case"))
    db.commit()

    event = log_activity(
        db,
        activity_type="detection_created",
        title="Detection created",
        message="orphan evidence reference",
        case_id=CASE_ID,
        evidence_id="deadbeef-dead-4ead-8ead-deaddeaddead",
        metadata={"detection_id": "det-1"},
    )

    assert event.evidence_id is None


def test_detection_dedup_rerun_preserves_state() -> None:
    db = _session()
    db.add(Case(id=CASE_ID, name="Case"))
    db.commit()
    detection, created = create_detection_if_missing(
        db,
        case_id=CASE_ID,
        evidence_id=None,
        artifact_id=None,
        rule_id=RULE_ID,
        rule_set_id=None,
        engine="sigma",
        source_engine="sigma",
        rule_name="Encoded PowerShell",
        severity="high",
        confidence=0.9,
        event_id="evt-1",
        event_index="case-1-events",
        opensearch_id="os-1",
        target_type="event",
        target_path=None,
        message="match",
        dedup_fingerprint="fp-1",
        engine_version="rules_v2",
    )
    assert created is True
    detection.status = "dismissed"
    db.commit()
    detection2, created2 = create_detection_if_missing(
        db,
        case_id=CASE_ID,
        evidence_id=None,
        artifact_id=None,
        rule_id=RULE_ID,
        rule_set_id=None,
        engine="sigma",
        source_engine="sigma",
        rule_name="Encoded PowerShell",
        severity="high",
        confidence=0.9,
        event_id="evt-1",
        event_index="case-1-events",
        opensearch_id="os-1",
        target_type="event",
        target_path=None,
        message="match",
        dedup_fingerprint="fp-1",
        engine_version="rules_v2",
    )
    assert created2 is False
    assert detection2.id == detection.id
    assert detection2.status == "dismissed"


def test_detection_rerun_recreates_soft_deleted_detection() -> None:
    db = _session()
    db.add(Case(id=CASE_ID, name="Case"))
    db.commit()
    detection, created = create_detection_if_missing(
        db,
        case_id=CASE_ID,
        evidence_id=None,
        artifact_id=None,
        rule_id=RULE_ID,
        rule_set_id=None,
        engine="sigma",
        source_engine="sigma",
        rule_name="Encoded PowerShell",
        severity="high",
        confidence=0.9,
        event_id="evt-1",
        event_index="case-1-events",
        opensearch_id="os-1",
        target_type="event",
        target_path=None,
        message="match",
        dedup_fingerprint="fp-1",
        engine_version="rules_v2",
    )
    assert created is True
    detection.deleted_at = datetime.now(UTC)
    db.commit()
    detection2, created2 = create_detection_if_missing(
        db,
        case_id=CASE_ID,
        evidence_id=None,
        artifact_id=None,
        rule_id=RULE_ID,
        rule_set_id=None,
        engine="sigma",
        source_engine="sigma",
        rule_name="Encoded PowerShell",
        severity="high",
        confidence=0.9,
        event_id="evt-1",
        event_index="case-1-events",
        opensearch_id="os-1",
        target_type="event",
        target_path=None,
        message="match",
        dedup_fingerprint="fp-1",
        engine_version="rules_v2",
    )
    assert created2 is True
    assert detection2.id != detection.id
    assert detection2.deleted_at is None
    assert db.query(DetectionResult).count() == 2


def test_detection_rerun_revives_stale_detection() -> None:
    db = _session()
    db.add(Case(id=CASE_ID, name="Case"))
    db.commit()
    detection, created = create_detection_if_missing(
        db,
        case_id=CASE_ID,
        evidence_id=None,
        artifact_id=None,
        rule_id=RULE_ID,
        rule_set_id=None,
        engine="sigma",
        source_engine="sigma",
        rule_name="Encoded PowerShell",
        severity="high",
        confidence=0.9,
        event_id="evt-old",
        event_index="case-1-events",
        opensearch_id="os-old",
        target_type="event",
        target_path=None,
        message="match",
        matched_stable_event_id="stable-evt-1",
        dedup_fingerprint="fp-1",
        engine_version="rules_v2",
    )
    assert created is True
    detection.status = "stale"
    db.commit()
    detection2, created2 = create_detection_if_missing(
        db,
        case_id=CASE_ID,
        evidence_id=None,
        artifact_id=None,
        rule_id=RULE_ID,
        rule_set_id=None,
        engine="sigma",
        source_engine="sigma",
        rule_name="Encoded PowerShell",
        severity="high",
        confidence=0.9,
        event_id="evt-new",
        event_index="case-1-events",
        opensearch_id="os-new",
        target_type="event",
        target_path=None,
        message="match",
        matched_stable_event_id="stable-evt-1",
        dedup_fingerprint="fp-1",
        engine_version="rules_v2",
    )
    assert created2 is False
    assert detection2.id == detection.id
    assert detection2.status == "new"
    assert detection2.event_id == "evt-new"


def test_bulk_duplicate_lookup_uses_single_query() -> None:
    db = _session()
    db.add(Case(id=CASE_ID, name="Case"))
    db.commit()
    for fingerprint in ("fp-a", "fp-b", "fp-c"):
        create_detection_if_missing(
            db,
            case_id=CASE_ID,
            evidence_id=None,
            artifact_id=None,
            rule_id=RULE_ID,
            rule_set_id=None,
            engine="sigma",
            source_engine="sigma",
            rule_name="Bulk Lookup",
            severity="high",
            confidence=0.9,
            event_id=fingerprint,
            event_index="case-1-events",
            opensearch_id=f"os-{fingerprint}",
            target_type="event",
            target_path=None,
            message="match",
            dedup_fingerprint=fingerprint,
            engine_version="rules_v2",
        )
    statements: list[str] = []

    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
        statements.append(statement)

    event.listen(db.get_bind(), "before_cursor_execute", before_cursor_execute)
    try:
        existing = get_existing_detection_keys(db, case_id=CASE_ID, dedup_fingerprints=["fp-a", "fp-b", "fp-c"])
    finally:
        event.remove(db.get_bind(), "before_cursor_execute", before_cursor_execute)
    assert set(existing) == {"fp-a", "fp-b", "fp-c"}
    select_statements = [statement for statement in statements if "FROM detection_results" in statement]
    assert len(select_statements) == 1


def test_bulk_detection_insert_only_creates_missing_and_preserves_dismissed() -> None:
    db = _session()
    db.add(Case(id=CASE_ID, name="Case"))
    db.commit()
    existing, created = create_detection_if_missing(
        db,
        case_id=CASE_ID,
        evidence_id=None,
        artifact_id=None,
        rule_id=RULE_ID,
        rule_set_id=None,
        engine="sigma",
        source_engine="sigma",
        rule_name="Bulk Insert",
        severity="high",
        confidence=0.9,
        event_id="evt-1",
        event_index="case-1-events",
        opensearch_id="os-1",
        target_type="event",
        target_path=None,
        message="match",
        dedup_fingerprint="fp-existing",
        engine_version="rules_v2",
    )
    assert created is True
    existing.status = "dismissed"
    db.commit()

    result = create_detections_bulk_if_missing(
        db,
        case_id=CASE_ID,
        detection_payloads=[
            {
                "case_id": CASE_ID,
                "evidence_id": None,
                "artifact_id": None,
                "rule_id": RULE_ID,
                "rule_set_id": None,
                "engine": "sigma",
                "source_engine": "sigma",
                "rule_name": "Bulk Insert",
                "severity": "high",
                "confidence": 0.9,
                "event_id": "evt-1",
                "event_index": "case-1-events",
                "opensearch_id": "os-1",
                "target_type": "event",
                "target_path": None,
                "message": "match",
                "dedup_fingerprint": "fp-existing",
                "engine_version": "rules_v2",
            },
            {
                "case_id": CASE_ID,
                "evidence_id": None,
                "artifact_id": None,
                "rule_id": RULE_ID,
                "rule_set_id": None,
                "engine": "sigma",
                "source_engine": "sigma",
                "rule_name": "Bulk Insert",
                "severity": "high",
                "confidence": 0.9,
                "event_id": "evt-2",
                "event_index": "case-1-events",
                "opensearch_id": "os-2",
                "target_type": "event",
                "target_path": None,
                "message": "match",
                "dedup_fingerprint": "fp-new",
                "engine_version": "rules_v2",
            },
        ],
    )

    assert result["created_count"] == 1
    assert result["duplicate_count"] == 1
    refreshed_existing = db.get(DetectionResult, existing.id)
    assert refreshed_existing is not None
    assert refreshed_existing.status == "dismissed"
    assert db.query(DetectionResult).count() == 2


def test_yara_validate_or_unavailable_state_clear() -> None:
    result = yara_engine.validate_yara_content('rule marker { strings: $a = "malicious_test_marker" condition: $a }')
    if yara_engine.yara_available():
        assert result["valid"] is True
    else:
        assert result["available"] is False
        assert result["errors"]


def test_yara_marker_match_size_limit_and_symlink_escape() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        temp_root = Path(tmp_dir)
        original_data_dir = yara_engine.settings.backend_data_dir
        yara_engine.settings.backend_data_dir = temp_root
        try:
            evidence = Evidence(
                id=EVIDENCE_ID,
                case_id=CASE_ID,
                original_filename="sample",
                stored_path=str(temp_root / "sample.zip"),
                sha256="00",
                size_bytes=1,
                evidence_type=EvidenceType.unknown,
            )
            evidence_root = temp_root / "evidence" / CASE_ID / EVIDENCE_ID / "extracted"
            evidence_root.mkdir(parents=True, exist_ok=True)
            marker = evidence_root / "marker.bin"
            marker.write_text("malicious_test_marker", encoding="utf-8")
            large = evidence_root / "large.bin"
            large.write_bytes(b"A" * (2 * 1024 * 1024))
            outside = temp_root / "outside.bin"
            outside.write_text("malicious_test_marker", encoding="utf-8")
            link = evidence_root / "outside-link.bin"
            try:
                link.symlink_to(outside)
            except Exception:
                link = None

            class _FakeCompiled:
                def match(self, path: str, timeout: int = 0):
                    return [type("Match", (), {"rule": "marker", "strings": []})()] if "marker.bin" in path else []

            original_yara = yara_engine.yara
            yara_engine.yara = object()
            result = yara_engine._run_compiled_yara_on_evidence(  # type: ignore[attr-defined]
                _FakeCompiled(),
                evidence,
                scan_options={"max_file_size_mb": 1, "selected_paths": ["extracted"], "max_files": 100},
            )
            yara_engine.yara = original_yara
            assert result["matched_files"] == 1
            assert result["skipped_by_reason"]["too_large"] >= 1
            if link is not None:
                assert result["skipped_by_reason"].get("symlink", 0) >= 1
        finally:
            yara_engine.settings.backend_data_dir = original_data_dir


def test_debug_reports_include_detections_and_runs() -> None:
    db = _session()
    case = Case(id=CASE_ID, name="Case")
    db.add(case)
    db.add(
        DetectionResult(
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            artifact_id=None,
            rule_id=RULE_ID,
            rule_set_id=None,
            engine="sigma",
            source_engine="sigma",
            rule_name="Encoded PowerShell",
            rule_title="Encoded PowerShell",
            severity="high",
            confidence=0.9,
            event_id="evt-1",
            event_index="case-1-events",
            opensearch_id="os-1",
            target_type="event",
            target_path=None,
            matched_at="2026-05-18T19:00:00Z",
            host_name="movistar-pc",
            message="match",
            status="new",
            dedup_fingerprint="fp-1",
            engine_version="rules_v2",
            raw={},
        )
    )
    db.add(
        RuleRun(
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            engine="multi",
            status=RuleRunStatus.completed,
            matched=2,
            created_detections=1,
            duplicates=1,
            scanned_files=3,
            skipped_files=2,
            errors=[],
            metadata_json={"rule_types": ["sigma", "yara"], "rules_evaluated": 2, "events_scanned": 10, "files_scanned": 3, "warnings": []},
        )
    )
    db.commit()
    context = _DebugPackContext(case=case, evidences=[], request=DebugExportRequest(scope="case", evidence_id=EVIDENCE_ID), export_timestamp=datetime.now(UTC))
    detections_report = _build_detections_report(db, context)
    rules_run_report = _build_rules_run_report(db, context)
    assert detections_report["detections_total"] == 1
    assert detections_report["by_source"]["sigma"] == 1
    assert rules_run_report["rules_evaluated"] == 2
    assert rules_run_report["detections_created"] == 1
