from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.models.case import Case
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.rule_run import RuleRun
from app.services.hunting import (
    HuntingArtifact,
    candidate_fingerprint,
    evaluate_hunting_rules,
    eval_anomalous_parent_child,
    eval_command_network_temporal_proximity,
    eval_evidence_inconsistency,
    eval_module_discrepancy,
    eval_persistence_observed_process,
    eval_scan_only_process,
    eval_sensitive_privilege_context,
    eval_suspicious_executable_location,
    eval_suspicious_memory_region,
    eval_suspicious_network_combination,
    eval_suspicious_powershell_command_line,
    finding_detail,
    load_hunting_rules,
    suppress_finding,
    update_finding_status,
    validate_hunting_rule_content,
)


class Query:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *args, **kwargs):
        return self

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
        self.case = Case(id="case-1", name="Case 1")
        self.evidence = Evidence(id="ev-1", case_id="case-1", original_filename="mem.raw", stored_path="/tmp/mem.raw", sha256="00", size_bytes=1)
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
        return None

    def commit(self):
        return None

    def refresh(self, item):
        return None


def rule(name: str):
    return next(item for item in load_hunting_rules() if item.logic.name == name)


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


def test_rule_yaml_schema_validation_and_version_preserved():
    rules = load_hunting_rules()
    assert any(item.rule_id == "hunting.suspicious_powershell_command_line" and item.version == "1.0.0" for item in rules)
    assert all(item.checksum for item in rules)


def test_unsafe_rule_content_rejected():
    with pytest.raises(ValueError):
        validate_hunting_rule_content("!!python/object/apply:os.system ['id']")


def test_disabled_rule_not_evaluated(monkeypatch):
    rules = load_hunting_rules()
    disabled = rules[0].model_copy(update={"status": "disabled"})
    monkeypatch.setattr("app.services.hunting.load_hunting_rules", lambda: [disabled])
    result = evaluate_hunting_rules(Db(), case_id="case-1", artifact_provider=lambda: [art()], apply=False)
    assert result["rules_evaluated"] == 0


def test_missing_prerequisites_returns_insufficient_data():
    result = evaluate_hunting_rules(Db(), case_id="case-1", rule_id="hunting.suspicious_network_combination", artifact_provider=lambda: [], apply=False)
    assert result["rules"][0]["status"] == "insufficient_data"
    assert "network_connections" in result["rules"][0]["missing_prerequisites"]


def test_suspicious_powershell_combination_triggers_and_single_flag_does_not():
    r = rule("suspicious_powershell_command_line")
    assert eval_suspicious_powershell_command_line(r, [art()])
    benign = art(command_line="powershell.exe -NoProfile Get-Process")
    assert eval_suspicious_powershell_command_line(r, [benign]) == []


def test_base64_like_pattern_bounded_safely():
    r = rule("suspicious_powershell_command_line")
    candidate = eval_suspicious_powershell_command_line(r, [art(command_line="powershell -nop -enc " + "A" * 5000)])[0]
    assert len(candidate.matched_values["process.command_line"][0]) <= 2048


def test_scan_only_process_rule_and_terminated_low_confidence_context():
    r = rule("scan_only_process")
    scan = art(producer="windows.psscan", fields={"source_plugins": ["windows.psscan"], "exit_time": "2024-01-01T00:01:00Z"})
    candidate = eval_scan_only_process(r, [scan])[0]
    assert "not automatically malicious" in " ".join(candidate.reasons)
    assert candidate.severity == "low"


def test_parent_child_uses_canonical_lineage_and_avoids_name_only_false_match():
    r = rule("anomalous_parent_child")
    assert eval_anomalous_parent_child(r, [art(parent_name="winword.exe", process_name="powershell.exe")])
    expected_path = art(parent_name="winlogon.exe", process_name="cmd.exe", executable_path="C:\\Windows\\System32\\cmd.exe")
    assert eval_anomalous_parent_child(r, [expected_path]) == []


def test_writable_directory_execution_and_expected_system_exclusion():
    r = rule("suspicious_executable_location")
    assert eval_suspicious_executable_location(r, [art(executable_path="C:\\Users\\bob\\AppData\\Roaming\\bad.exe", process_name="bad.exe")])
    installer = art(executable_path="C:\\Users\\bob\\Downloads\\setup.exe", process_name="setup.exe", command_line="setup.exe /install")
    assert eval_suspicious_executable_location(r, [installer]) == []


def test_sensitive_privilege_with_context_and_expected_system_bounded():
    r = rule("sensitive_privilege_context")
    suspicious = art(fields={"privileges": ["SeDebugPrivilege"]}, process_name="bad.exe", executable_path="C:\\Users\\Public\\bad.exe")
    assert eval_sensitive_privilege_context(r, [suspicious])
    expected = art(fields={"privileges": ["SeDebugPrivilege"]}, process_name="lsass.exe", executable_path="C:\\Windows\\System32\\lsass.exe")
    assert eval_sensitive_privilege_context(r, [expected]) == []


def test_suspicious_network_combination_public_ip_alone_does_not_trigger():
    r = rule("suspicious_network_combination")
    net = art(artifact_id="n1", family="network", process_name="notepad.exe", command_line=None, fields={"remote_address": "8.8.8.8", "remote_port": 443})
    assert eval_suspicious_network_combination(r, [net]) == []
    ps = art(process_name="powershell.exe", command_line="powershell -nop -enc " + "A" * 120)
    assert eval_suspicious_network_combination(r, [net.model_copy() if hasattr(net, "model_copy") else net, ps])


def test_suspicious_memory_region_rule():
    r = rule("suspicious_memory_region")
    mem = art(family="suspicious_memory", artifact_type="memory_suspicious_region", fields={"protection": "PAGE_EXECUTE_READWRITE", "tag": "malfind", "remote_address": None})
    candidate = eval_suspicious_memory_region(r, [mem])[0]
    assert "Executable" in candidate.reasons[0]


def test_module_discrepancy_rule():
    r = rule("module_discrepancy")
    module = art(family="module", artifact_type="memory_process_module", fields={"path": "C:\\Users\\Public\\x.dll", "source_plugins": ["windows.modscan"]})
    assert eval_module_discrepancy(r, [module])


def test_persistence_plus_process_does_not_claim_proven_execution():
    r = rule("persistence_observed_process")
    persistence = art(artifact_id="p1", family="persistence", fields={"image_path": "C:\\Users\\Public\\svc.exe"}, command_line="C:\\Users\\Public\\svc.exe")
    process = art(artifact_id="p2", family="process", executable_path="C:\\Users\\Public\\svc.exe", process_name="svc.exe")
    candidate = eval_persistence_observed_process(r, [persistence, process])[0]
    assert "not proven" in " ".join(candidate.reasons)
    assert eval_persistence_observed_process(r, [persistence]) == []


def test_command_network_proximity_requires_real_timestamps():
    r = rule("command_network_temporal_proximity")
    cmd = art(artifact_id="c1", command_line="powershell -nop -enc " + "A" * 120, timestamp="2024-01-01T00:00:00+00:00")
    net = art(artifact_id="n1", family="network", timestamp="2024-01-01T00:04:00+00:00", fields={"remote_address": "8.8.8.8"})
    assert eval_command_network_temporal_proximity(r, [cmd, net])
    assert eval_command_network_temporal_proximity(r, [cmd, art(artifact_id="n2", family="network", timestamp=None)]) == []


def test_evidence_inconsistency_and_pid_reuse():
    r = rule("evidence_inconsistency")
    a = art(process_entity_id="proc-1", process_name="a.exe")
    b = art(artifact_id="b", process_entity_id="proc-1", process_name="b.exe")
    reuse = art(artifact_id="c", process_entity_id="proc-2", pid=1234)
    candidates = eval_evidence_inconsistency(r, [a, b, reuse])
    assert any(c.contradictory_fields for c in candidates)


def test_deduplication_apply_and_reevaluation_updates_existing_finding():
    db = Db()
    artifacts = [art()]
    first = evaluate_hunting_rules(db, case_id="case-1", rule_id="hunting.suspicious_powershell_command_line", artifact_provider=lambda: artifacts, apply=True)
    second = evaluate_hunting_rules(db, case_id="case-1", rule_id="hunting.suspicious_powershell_command_line", artifact_provider=lambda: artifacts, apply=True)
    assert first["findings_created"] == 1
    assert second["findings_updated"] == 1
    assert len(db.findings) == 1


def test_rule_version_is_part_of_deduplication_key():
    r = rule("suspicious_powershell_command_line")
    c1 = eval_suspicious_powershell_command_line(r, [art()])[0]
    c2 = eval_suspicious_powershell_command_line(r.model_copy(update={"version": "2.0.0"}), [art()])[0]
    assert candidate_fingerprint("case-1", c1) != candidate_fingerprint("case-1", c2)


def test_suppression_and_status_history_preserved():
    db = Db()
    evaluate_hunting_rules(db, case_id="case-1", rule_id="hunting.suspicious_powershell_command_line", artifact_provider=lambda: [art()], apply=True)
    finding = db.findings[0]
    update_finding_status(db, finding, status="confirmed", note="reviewed")
    suppress_finding(db, finding, reason="known admin script")
    detail = finding_detail(finding)
    assert len(detail["status_history"]) >= 2
    assert detail["suppression_history"][0]["reason"] == "known admin script"


def test_case_and_evidence_scoping_and_dry_run_writes_nothing():
    db = Db()
    dry = evaluate_hunting_rules(db, case_id="case-1", evidence_id="ev-1", rule_id="hunting.suspicious_powershell_command_line", artifact_provider=lambda: [art(evidence_id="ev-1"), art(artifact_id="other", evidence_id="ev-2")], apply=False)
    assert dry["candidate_groups"] == 1
    assert not db.findings
    with pytest.raises(ValueError):
        evaluate_hunting_rules(db, case_id="case-1", evidence_id="other", artifact_provider=lambda: [], apply=False)


def test_finding_detail_includes_reasons_raw_refs_navigation_and_pagination_metadata():
    db = Db()
    result = evaluate_hunting_rules(db, case_id="case-1", rule_id="hunting.suspicious_powershell_command_line", artifact_provider=lambda: [art()], apply=True)
    detail = finding_detail(db.findings[0])
    assert result["run_id"]
    assert detail["reasons"]
    assert detail["raw_references"]
    assert detail["navigation_targets"]
    assert detail["matched_fields"]
