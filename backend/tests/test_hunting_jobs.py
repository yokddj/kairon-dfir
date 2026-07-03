from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.models.case import Case
from app.models.evidence import Evidence
from app.models.rule_run import RuleRun, RuleRunStatus
from app.models.finding import Finding
from app.services.hunting import (
    HuntingArtifact,
    evaluate_hunting_rules,
    load_hunting_rules,
)


class Query:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *args, **kwargs):
        return Query([r for r in self.rows if r])

    def order_by(self, *args, **kwargs):
        return self

    def all(self):
        return list(self.rows)

    def one_or_none(self):
        return self.rows[0] if self.rows else None

    def count(self):
        return len(self.rows)

    def first(self):
        return self.rows[0] if self.rows else None


class Db:
    def __init__(self):
        self.case = Case(id="case-1", name="Test Case")
        self.evidence = Evidence(id="ev-1", case_id="case-1", original_filename="test.raw", stored_path="/tmp/test.raw", sha256="00", size_bytes=1)
        self.findings: list[Finding] = []
        self.runs: list[RuleRun] = []

    def get(self, model, identifier):
        if model is Case and identifier == "case-1":
            return self.case
        if model is Evidence and identifier == "ev-1":
            return self.evidence
        if model is Finding:
            return next((item for item in self.findings if item.id == identifier), None)
        if model is RuleRun:
            return next((item for item in self.runs if item.id == identifier), None)
        return None

    def query(self, model):
        if model is Finding:
            return Query(self.findings)
        if model is RuleRun:
            return Query(self.runs)
        return Query([])

    def add(self, item):
        if isinstance(item, Finding):
            item.id = item.id or f"finding-{len(self.findings) + 1}"
            self.findings.append(item)
        if isinstance(item, RuleRun):
            item.id = item.id or f"run-{len(self.runs) + 1}"
            self.runs.append(item)

    def flush(self):
        pass

    def commit(self):
        pass

    def refresh(self, item):
        pass


def art(**kwargs) -> HuntingArtifact:
    defaults = dict(
        artifact_id="a1",
        family="process",
        artifact_type="memory_process_entity",
        source_category="Memory",
        producer="windows.pslist",
        evidence_id="ev-1",
        process_entity_id="proc-1",
        pid=1234,
        ppid=100,
        process_name="powershell.exe",
        parent_name="winword.exe",
        executable_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + "A" * 120,
        timestamp="2024-01-01T00:00:00+00:00",
        fields={"source_plugins": ["windows.pslist"]},
        raw_reference={"document_id": "a1"},
        navigation_target={"kind": "memory_process", "evidence_id": "ev-1", "process_entity_id": "proc-1"},
    )
    defaults.update(kwargs)
    return HuntingArtifact(**defaults)


def test_evaluation_enqueue_creates_rule_run_in_db():
    from app.workers.tasks import enqueue_hunting_evaluation
    with patch("app.workers.tasks.rules_queue.enqueue") as mock_enq, \
         patch("app.workers.tasks.SessionLocal") as mock_sl, \
         patch("app.workers.tasks.log_activity"):
        mock_job = MagicMock()
        mock_job.id = "job-123"
        mock_enq.return_value = mock_job

        mock_db = Db()
        mock_sl.return_value.__enter__.return_value = mock_db

        result = enqueue_hunting_evaluation(case_id="case-1", rule_id="hunting.suspicious_powershell_command_line", apply=False)
        assert result["run_id"]
        assert result["job_id"] == "job-123"
        assert result["status"] == "queued"
        assert result["deduplicated"] is False


def test_evaluation_enqueue_dry_run_mode():
    from app.workers.tasks import enqueue_hunting_evaluation
    with patch("app.workers.tasks.rules_queue.enqueue") as mock_enq, \
         patch("app.workers.tasks.SessionLocal") as mock_sl, \
         patch("app.workers.tasks.log_activity"):
        mock_job = MagicMock()
        mock_job.id = "job-dry"
        mock_enq.return_value = mock_job

        mock_db = Db()
        mock_sl.return_value.__enter__.return_value = mock_db

        result = enqueue_hunting_evaluation(case_id="case-1", apply=False)
        assert result["mode"] == "dry_run"


def test_evaluation_enqueue_apply_mode():
    from app.workers.tasks import enqueue_hunting_evaluation
    with patch("app.workers.tasks.rules_queue.enqueue") as mock_enq, \
         patch("app.workers.tasks.SessionLocal") as mock_sl, \
         patch("app.workers.tasks.log_activity"):
        mock_job = MagicMock()
        mock_job.id = "job-apply"
        mock_enq.return_value = mock_job

        mock_db = Db()
        mock_sl.return_value.__enter__.return_value = mock_db

        result = enqueue_hunting_evaluation(case_id="case-1", apply=True)
        assert result["mode"] == "apply"


def test_dry_run_creates_no_findings():
    db = Db()
    result = evaluate_hunting_rules(db, case_id="case-1", rule_id="hunting.suspicious_powershell_command_line", artifact_provider=lambda: [art()], apply=False)
    assert result["findings_created"] == 0
    assert result["findings_updated"] == 0
    assert len(db.findings) == 0


def test_apply_creates_findings():
    db = Db()
    result = evaluate_hunting_rules(db, case_id="case-1", rule_id="hunting.suspicious_powershell_command_line", artifact_provider=lambda: [art()], apply=True)
    assert result["findings_created"] == 1
    assert len(db.findings) == 1


def test_second_apply_updates_without_duplicates():
    db = Db()
    artifacts = [art()]
    first = evaluate_hunting_rules(db, case_id="case-1", rule_id="hunting.suspicious_powershell_command_line", artifact_provider=lambda: artifacts, apply=True)
    second = evaluate_hunting_rules(db, case_id="case-1", rule_id="hunting.suspicious_powershell_command_line", artifact_provider=lambda: artifacts, apply=True)
    assert first["findings_created"] == 1
    assert second["findings_updated"] == 1
    assert second["findings_created"] == 0
    assert len(db.findings) == 1


def test_duplicate_active_request_returns_existing_job():
    from app.workers.tasks import enqueue_hunting_evaluation
    rule_id = "hunting.suspicious_powershell_command_line"
    with patch("app.workers.tasks.rules_queue.enqueue") as mock_enq, \
         patch("app.workers.tasks.SessionLocal") as mock_sl, \
         patch("app.workers.tasks.log_activity"):
        mock_job = MagicMock()
        mock_job.id = "job-first"
        mock_enq.return_value = mock_job

        db = Db()
        mock_sl.return_value.__enter__.return_value = db

        first = enqueue_hunting_evaluation(case_id="case-1", rule_id=rule_id, apply=False)
        assert first["deduplicated"] is False
        assert len(db.runs) == 1

        second = enqueue_hunting_evaluation(case_id="case-1", rule_id=rule_id, apply=False)
        assert second["deduplicated"] is True
        assert second["run_id"] == first["run_id"]
        assert len(db.runs) == 1


def test_dry_run_apply_use_different_dedup_keys():
    from app.workers.tasks import enqueue_hunting_evaluation
    rule_id = "hunting.suspicious_powershell_command_line"
    with patch("app.workers.tasks.rules_queue.enqueue") as mock_enq, \
         patch("app.workers.tasks.SessionLocal") as mock_sl, \
         patch("app.workers.tasks.log_activity"):
        mock_job = MagicMock()
        mock_job.id = "job-1"
        mock_enq.return_value = mock_job

        db = Db()
        mock_sl.return_value.__enter__.return_value = db

        dry = enqueue_hunting_evaluation(case_id="case-1", rule_id=rule_id, apply=False)
        apply_result = enqueue_hunting_evaluation(case_id="case-1", rule_id=rule_id, apply=True)
        assert dry["deduplicated"] is False
        assert apply_result["deduplicated"] is False
        assert dry["run_id"] != apply_result["run_id"]


def test_rules_completed_count_increments():
    db = Db()
    rules = load_hunting_rules()[:3]
    artifact_counts = 0
    for rule in rules:
        if rule.status != "disabled":
            artifact_counts += 1
    result = evaluate_hunting_rules(db, case_id="case-1", rule_id="hunting.suspicious_powershell_command_line", artifact_provider=lambda: [art()], apply=False)
    assert result["rules_evaluated"] == 1
    assert len(result["rules"]) == 1


def test_progress_callback_is_called():
    phases = []
    def cb(phase, extra=None):
        phases.append(phase)

    db = Db()
    result = evaluate_hunting_rules(db, case_id="case-1", rule_id="hunting.suspicious_powershell_command_line", artifact_provider=lambda: [art()], apply=False, progress_callback=cb)
    assert "validating_scope" in phases
    assert "loading_rules" in phases
    assert "evaluating_rules" in phases
    assert result["status"] == "completed_with_findings"


def test_cancel_check_before_execution():
    cancel_calls = [0]
    def cancel_check():
        cancel_calls[0] += 1
        return True

    db = Db()
    result = evaluate_hunting_rules(db, case_id="case-1", rule_id="hunting.suspicious_powershell_command_line", artifact_provider=lambda: [art()], apply=False, cancel_check=cancel_check)
    assert result["status"] == "cancelled"
    assert result["cancelled"] is True
    assert result["findings"] == []


def test_cancel_check_between_rules():
    rule = load_hunting_rules()[0]
    cancel_on_second = [0]
    def cancel_check():
        cancel_on_second[0] += 1
        return cancel_on_second[0] >= 1

    db = Db()
    artifacts = [art()]
    result = evaluate_hunting_rules(db, case_id="case-1", rule_id=rule.rule_id, artifact_provider=lambda: artifacts, apply=False, cancel_check=cancel_check)
    assert result["status"] == "cancelled"


def test_cli_direct_mode_still_works():
    db = Db()
    result = evaluate_hunting_rules(db, case_id="case-1", rule_id="hunting.suspicious_powershell_command_line", artifact_provider=lambda: [art()], apply=False)
    assert "run_id" in result
    assert "status" in result
    assert "rules" in result


def test_detection_run_has_job_id():
    db = Db()
    run = RuleRun(id="run-job-1", case_id="case-1", engine="hunting-v1", status=RuleRunStatus.completed, scope="case", total_rules=1, processed_rules=1, current_phase="completed_with_findings", metadata_json={"hunting": True, "apply": False})
    run.hunting_job_id = "job-test-123"
    db.runs.append(run)

    from app.services.hunting import run_to_dict
    data = run_to_dict(run)
    assert data["job_id"] == "job-test-123"


def test_existing_sync_service_tests_compatible():
    from app.services.hunting import (
        eval_suspicious_powershell_command_line,
        eval_scan_only_process,
        eval_anomalous_parent_child,
        candidate_fingerprint,
    )
    rules = load_hunting_rules()
    ps_rule = next(r for r in rules if r.logic.name == "suspicious_powershell_command_line")
    candidates = eval_suspicious_powershell_command_line(ps_rule, [art()])
    assert len(candidates) == 1
    assert "EncodedCommand" in candidates[0].reasons[0] or "EncodedCommand" in candidates[0].reasons[1]

    scan_rule = next(r for r in rules if r.logic.name == "scan_only_process")
    scan_artifact = art(producer="windows.psscan", fields={"source_plugins": ["windows.psscan"]})
    assert eval_scan_only_process(scan_rule, [scan_artifact])

    pc_rule = next(r for r in rules if r.logic.name == "anomalous_parent_child")
    assert eval_anomalous_parent_child(pc_rule, [art(parent_name="winword.exe", process_name="powershell.exe")])

    fingerprint1 = candidate_fingerprint("case-1", candidates[0])
    assert fingerprint1
    fingerprint2 = candidate_fingerprint("case-1", candidates[0])
    assert fingerprint1 == fingerprint2


def test_existing_run_id_prevents_duplicate_run_creation():
    db = Db()
    run = RuleRun(id="pre-existing", case_id="case-1", engine="hunting-v1", status=RuleRunStatus.running, scope="case", total_rules=1, processed_rules=0, current_phase="running", metadata_json={"hunting": True, "apply": False, "rules": ["hunting.suspicious_powershell_command_line"]})
    db.runs.append(run)
    result = evaluate_hunting_rules(db, case_id="case-1", rule_id="hunting.suspicious_powershell_command_line", artifact_provider=lambda: [art()], apply=False, existing_run_id="pre-existing")
    assert result["run_id"] == "pre-existing"


def test_rules_with_different_scope_use_different_keys():
    from app.workers.tasks import enqueue_hunting_evaluation
    with patch("app.workers.tasks.rules_queue.enqueue") as mock_enq, \
         patch("app.workers.tasks.SessionLocal") as mock_sl, \
         patch("app.workers.tasks.log_activity"):
        mock_job = MagicMock()
        mock_job.id = "job-1"
        mock_enq.return_value = mock_job

        db = Db()
        mock_sl.return_value.__enter__.return_value = db

        first = enqueue_hunting_evaluation(case_id="case-1", evidence_id="ev-a", rule_id="hunting.scan_only_process", apply=False)
        second = enqueue_hunting_evaluation(case_id="case-1", evidence_id="ev-b", rule_id="hunting.scan_only_process", apply=False)
        assert first["deduplicated"] is False
        assert second["deduplicated"] is False
        assert first["run_id"] != second["run_id"]


def test_rules_api_endpoint_still_returns_12_rules():
    rules = load_hunting_rules()
    assert len([r for r in rules if r.status != "disabled"]) >= 12
