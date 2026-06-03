from types import SimpleNamespace

from fastapi import HTTPException
import pytest

from app.api import routes_findings
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.schemas.finding import FindingCreate, FindingUpdate
from app.services import correlation_engine


class _FakeQuery:
    def __init__(self, items):
        self._items = items

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def all(self):
        return self._items


class _FakeDb:
    def __init__(self, *, case_exists: bool = True, detections: list | None = None):
        self.case_exists = case_exists
        self.detections = detections or []

    def get(self, model, identifier):
        if model is Case and self.case_exists:
            return SimpleNamespace(id=identifier)
        return None

    def query(self, model):
        return _FakeQuery(self.detections)


def test_normalize_finding_create_generates_default_title_from_single_event() -> None:
    original_fetch = routes_findings.fetch_event_by_id
    routes_findings.fetch_event_by_id = lambda case_id, event_id, **kwargs: {"event": {"type": "logon_success", "message": "Successful logon: CONTOSO\\alice"}}  # type: ignore[assignment]
    try:
        payload = FindingCreate(event_ids=["evt-1"])
        result = routes_findings._normalize_finding_create("case-1", payload, _FakeDb())
    finally:
        routes_findings.fetch_event_by_id = original_fetch  # type: ignore[assignment]
    assert result["title"] == "Successful logon: CONTOSO\\alice"
    assert result["event_ids"] == ["evt-1"]


def test_normalize_finding_create_merges_detection_event_ids() -> None:
    detections = [
        SimpleNamespace(id="det-1", case_id="case-1", event_id="evt-1", rule_name="Built-in: Suspicious command line"),
        SimpleNamespace(id="det-2", case_id="case-1", event_id=None, rule_name="Built-in: RDP activity"),
    ]
    original_fetch = routes_findings.fetch_event_by_id
    routes_findings.fetch_event_by_id = lambda case_id, event_id, **kwargs: {"event": {"type": "process_creation", "message": "Process created"}} if event_id == "evt-1" else None  # type: ignore[assignment]
    try:
        payload = FindingCreate(detection_ids=["det-1", "det-2"])
        result = routes_findings._normalize_finding_create("case-1", payload, _FakeDb(detections=detections))
    finally:
        routes_findings.fetch_event_by_id = original_fetch  # type: ignore[assignment]
    assert result["detection_ids"] == ["det-1", "det-2"]
    assert result["event_ids"] == ["evt-1"]
    assert result["title"] == "Process created"


def test_normalize_finding_create_rejects_missing_events_without_detections() -> None:
    original_fetch = routes_findings.fetch_event_by_id
    routes_findings.fetch_event_by_id = lambda case_id, event_id, **kwargs: None  # type: ignore[assignment]
    try:
        try:
            routes_findings._normalize_finding_create("case-1", FindingCreate(event_ids=["missing-1"]), _FakeDb())
        except HTTPException as exc:
            assert exc.status_code == 400
            assert "missing_event_ids" in exc.detail
        else:
            raise AssertionError("Expected missing event selection to fail")
    finally:
        routes_findings.fetch_event_by_id = original_fetch  # type: ignore[assignment]


def test_normalize_finding_create_requires_event_or_detection_reference() -> None:
    try:
        routes_findings._normalize_finding_create("case-1", FindingCreate(), _FakeDb())
    except HTTPException as exc:
        assert exc.status_code == 400
        assert "at least one event or detection" in str(exc.detail)
    else:
        raise AssertionError("Expected missing references to fail")


def test_correlate_case_accepts_missing_body() -> None:
    original_runner = routes_findings.run_correlation_engine
    original_logger = routes_findings.log_activity
    calls: dict = {}
    try:
        def _runner(db, case_id, **kwargs):  # noqa: ANN001
            calls["runner"] = {"db": db, "case_id": case_id, **kwargs}
            return {"report": {"findings_generated": 0}}

        def _logger(*args, **kwargs):  # noqa: ANN002, ANN003
            calls["log"] = kwargs

        routes_findings.run_correlation_engine = _runner  # type: ignore[assignment]
        routes_findings.log_activity = _logger  # type: ignore[assignment]
        result = routes_findings.correlate_case("case-1", payload=None, db=_FakeDb())
    finally:
        routes_findings.run_correlation_engine = original_runner  # type: ignore[assignment]
        routes_findings.log_activity = original_logger  # type: ignore[assignment]
    assert result["report"]["findings_generated"] == 0
    assert calls["runner"]["case_id"] == "case-1"
    assert calls["runner"]["evidence_id"] is None
    assert calls["runner"]["finding_types"] is None
    assert calls["runner"]["force"] is False


class _CorrelationDb:
    def __init__(self) -> None:
        self.case = Case(id="case-1", name="Case 1")
        self.evidences = [Evidence(id="ev-1", case_id="case-1", original_filename="sample.zip", stored_path="/tmp/sample.zip", sha256="00", size_bytes=1)]
        self.findings: list[Finding] = []

    def get(self, model, identifier):  # noqa: ANN001
        if model is Case and identifier == self.case.id:
            return self.case
        if model is Finding:
            for item in self.findings:
                if item.id == identifier:
                    return item
        return None

    def query(self, model):  # noqa: ANN001
        if model is Evidence:
            return _FakeQuery(self.evidences)
        if model is Finding:
            return _FakeQuery(self.findings)
        return _FakeQuery([])

    def add(self, item):  # noqa: ANN001
        if not getattr(item, "id", None):
            item.id = f"finding-{len(self.findings) + 1}"
        self.findings.append(item)

    def delete(self, item):  # noqa: ANN001
        self.findings = [current for current in self.findings if current is not item]

    def commit(self):
        return None

    def refresh(self, item):  # noqa: ANN001
        return None


def _correlation_events() -> list[dict]:
    return [
        {
            "id": "browser-1",
            "case_id": "case-1",
            "evidence_id": "ev-1",
            "@timestamp": "2026-05-15T10:00:00Z",
            "artifact": {"type": "browser"},
            "event": {"type": "file_downloaded", "severity": "medium"},
            "download": {"target_path": "C:\\Users\\dfir\\Downloads\\payload.exe"},
            "file": {"path": "C:\\Users\\dfir\\Downloads\\payload.exe"},
            "risk_score": 40,
        },
        {
            "id": "proc-1",
            "case_id": "case-1",
            "evidence_id": "ev-1",
            "@timestamp": "2026-05-15T10:05:00Z",
            "artifact": {"type": "process"},
            "event": {"type": "process_start"},
            "execution": {"is_execution_confirmed": True, "source": "process_creation"},
            "process": {"path": "C:\\Users\\dfir\\Downloads\\payload.exe", "name": "payload.exe"},
            "risk_score": 95,
        },
        {
            "id": "def-1",
            "case_id": "case-1",
            "evidence_id": "ev-1",
            "@timestamp": "2026-05-15T10:10:00Z",
            "artifact": {"type": "defender"},
            "event": {"type": "security_detection", "severity": "high"},
            "detection": {"path": "C:\\Users\\dfir\\Downloads\\payload.exe"},
            "risk_score": 90,
        },
        {
            "id": "dns-1",
            "case_id": "case-1",
            "evidence_id": "ev-1",
            "@timestamp": "2026-05-15T11:05:00Z",
            "artifact": {"type": "dns"},
            "event": {"type": "dns_query"},
            "dns": {"domain": "raw.githubusercontent.com"},
            "process": {"name": "powershell.exe"},
        },
        {
            "id": "srum-1",
            "case_id": "case-1",
            "evidence_id": "ev-1",
            "@timestamp": "2026-05-15T11:30:00Z",
            "artifact": {"type": "srum"},
            "event": {"type": "network_usage"},
            "srum": {"application": "powershell.exe", "bytes_sent": 5000000},
        },
        {
            "id": "autorun-1",
            "case_id": "case-1",
            "evidence_id": "ev-1",
            "@timestamp": "2026-05-15T09:00:00Z",
            "artifact": {"type": "autorun"},
            "event": {"type": "autorun"},
            "persistence": {"mechanism": "run_key", "command": "C:\\Users\\dfir\\Downloads\\payload.exe"},
        },
        {
            "id": "cloud-1",
            "case_id": "case-1",
            "evidence_id": "ev-1",
            "@timestamp": "2026-05-15T12:00:00Z",
            "artifact": {"type": "cloud"},
            "event": {"type": "cloud_upload"},
            "cloud": {"local_path": "C:\\Users\\dfir\\OneDrive\\passwords.xlsx", "remote_path": "/Shared/passwords.xlsx", "shared": True},
        },
        {
            "id": "usb-1",
            "case_id": "case-1",
            "evidence_id": "ev-1",
            "@timestamp": "2026-05-15T12:10:00Z",
            "artifact": {"type": "usb"},
            "event": {"type": "usb_connected"},
            "usb": {"device_type": "mass_storage", "serial": "USB123"},
            "volume": {"drive_letter": "E:"},
        },
        {
            "id": "mft-1",
            "case_id": "case-1",
            "evidence_id": "ev-1",
            "@timestamp": "2026-05-15T12:20:00Z",
            "artifact": {"type": "mft"},
            "event": {"type": "file_observed"},
            "file": {"path": "C:\\Users\\dfir\\Documents\\backup.7z"},
        },
        {
            "id": "recycle-1",
            "case_id": "case-1",
            "evidence_id": "ev-1",
            "@timestamp": "2026-05-15T13:00:00Z",
            "artifact": {"type": "recycle_bin"},
            "event": {"type": "file_deleted"},
            "file": {"path": "C:\\Users\\dfir\\Downloads\\payload.exe"},
        },
    ]


def _process_bundle() -> dict:
    return {
        "graph": {
            "nodes": [
                {"id": "office", "name": "WINWORD.EXE", "path": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE", "risk_score": 20, "source_events": ["proc-office"], "first_seen": "2026-05-15T11:00:00Z", "badges": []},
                {"id": "ps", "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "command_line": "powershell.exe -NoP -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand AAAA", "risk_score": 95, "source_events": ["proc-ps"], "first_seen": "2026-05-15T11:00:00Z", "risk_reasons": ["Process uses encoded PowerShell"], "badges": ["powershell", "encoded_command", "network_activity"]},
                {"id": "browser", "name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "risk_score": 10, "source_events": ["proc-browser"], "first_seen": "2026-05-15T10:04:00Z", "badges": []},
                {"id": "payload", "name": "payload.exe", "path": "C:\\Users\\dfir\\Downloads\\payload.exe", "risk_score": 92, "source_events": ["proc-1"], "first_seen": "2026-05-15T10:05:00Z", "risk_reasons": ["Process from Downloads", "Process associated with Defender detection"], "badges": ["browser_child", "defender_detection"]},
            ],
            "edges": [
                {"source": "office", "target": "ps", "confidence": "high", "reason": "sysmon_parent_process_guid"},
                {"source": "browser", "target": "payload", "confidence": "high", "reason": "sysmon_parent_process_guid"},
            ],
            "summary": {"nodes_count": 4, "edges_count": 2, "warnings": [], "suspicious_chain_count": 2},
        },
        "report": {},
        "sample_chains": [{"root": "office", "chain": ["office", "ps"]}],
    }


def test_run_correlation_engine_generates_core_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _CorrelationDb()
    monkeypatch.setattr(correlation_engine, "_iter_events_for_case", lambda case_id, evidence_id=None: _correlation_events())
    monkeypatch.setattr(correlation_engine, "build_process_tree_bundle", lambda case, evidences, scope, evidence_id=None: _process_bundle())
    result = correlation_engine.run_correlation_engine(db, "case-1", evidence_id="ev-1")
    finding_types = {item["finding_type"] for item in result["findings"]}
    assert "download_execute_detect" in finding_types
    assert "office_powershell" in finding_types
    assert "powershell_network" in finding_types
    assert "persistence_execution" in finding_types
    assert "cloud_exfil_candidate" in finding_types
    assert "usb_exfil_candidate" in finding_types
    assert "execution_cleanup" in finding_types
    assert "suspicious_process_chain" in finding_types
    download = next(item for item in result["findings"] if item["finding_type"] == "download_execute_detect")
    assert download["severity"] in {"high", "critical"}
    assert download["confidence"] == "high"
    assert len(download["related_event_ids"]) == 3


def test_run_correlation_engine_filename_only_and_dedup_preserves_status(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _CorrelationDb()
    events = [
        {
            "id": "browser-1",
            "case_id": "case-1",
            "@timestamp": "2026-05-15T10:00:00Z",
            "artifact": {"type": "browser"},
            "event": {"type": "file_downloaded"},
            "file": {"path": "C:\\Users\\dfir\\Downloads\\payload.exe"},
        },
        {
            "id": "proc-1",
            "case_id": "case-1",
            "@timestamp": "2026-05-15T10:05:00Z",
            "artifact": {"type": "process"},
            "event": {"type": "process_start"},
            "execution": {"is_execution_confirmed": True, "source": "process_creation"},
            "process": {"path": "D:\\Temp\\payload.exe"},
            "risk_score": 75,
        },
        {
            "id": "def-1",
            "case_id": "case-1",
            "@timestamp": "2026-05-15T10:10:00Z",
            "artifact": {"type": "defender"},
            "event": {"type": "security_detection"},
            "detection": {"path": "E:\\Quarantine\\payload.exe"},
        },
    ]
    monkeypatch.setattr(correlation_engine, "_iter_events_for_case", lambda case_id, evidence_id=None: events)
    monkeypatch.setattr(correlation_engine, "build_process_tree_bundle", lambda case, evidences, scope, evidence_id=None: {"graph": {"nodes": [], "edges": [], "summary": {}}, "report": {}, "sample_chains": []})
    first = correlation_engine.run_correlation_engine(db, "case-1")
    finding = next(item for item in first["findings"] if item["finding_type"] == "download_execute_detect")
    assert finding["confidence"] in {"medium", "low"}
    assert "filename_only_match" in finding["data_quality"]
    db.findings[0].status = FindingStatus.reviewed
    second = correlation_engine.run_correlation_engine(db, "case-1")
    assert len(second["findings"]) == len(first["findings"])
    assert db.findings[0].status == FindingStatus.reviewed


def test_run_correlation_engine_force_does_not_reset_status(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _CorrelationDb()
    monkeypatch.setattr(correlation_engine, "_iter_events_for_case", lambda case_id, evidence_id=None: _correlation_events())
    monkeypatch.setattr(correlation_engine, "build_process_tree_bundle", lambda case, evidences, scope, evidence_id=None: _process_bundle())
    first = correlation_engine.run_correlation_engine(db, "case-1", evidence_id="ev-1")
    assert first["findings"]
    db.findings[0].status = FindingStatus.dismissed
    second = correlation_engine.run_correlation_engine(db, "case-1", evidence_id="ev-1", force=True)
    assert len(second["findings"]) == len(first["findings"])
    assert db.findings[0].status == FindingStatus.dismissed


def test_run_correlation_engine_removes_stale_correlation_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _CorrelationDb()
    monkeypatch.setattr(correlation_engine, "_iter_events_for_case", lambda case_id, evidence_id=None: _correlation_events())
    monkeypatch.setattr(correlation_engine, "build_process_tree_bundle", lambda case, evidences, scope, evidence_id=None: _process_bundle())

    stale = Finding(
        case_id="case-1",
        evidence_id=None,
        title="Suspicious process chain: msedge.exe -> msedge.exe",
        description="legacy noise",
        severity=FindingSeverity.high,
        status=FindingStatus.new,
        source="correlation_engine",
        finding_type="suspicious_process_chain",
        confidence="high",
        fingerprint="stale-msedge-fingerprint",
        related_evidence_ids=["ev-1"],
        related_files=["C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"],
    )
    stale.id = "finding-stale"
    db.findings.append(stale)

    result = correlation_engine.run_correlation_engine(db, "case-1", evidence_id="ev-1")

    assert result["report"]["stale_findings_removed"] == 1
    assert all(item.id != "finding-stale" for item in db.findings)
    assert all("msedge.exe -> msedge.exe" not in item.title for item in db.findings)


def test_case_finding_routes_list_detail_and_patch() -> None:
    db = _CorrelationDb()
    item = Finding(case_id="case-1", title="Correlated", description="x", severity=FindingSeverity.high, status=FindingStatus.new, source="correlation_engine", finding_type="download_execute_detect", confidence="high")
    item.id = "finding-1"
    db.findings.append(item)
    listed = routes_findings.list_findings("case-1", severity=None, confidence=None, status_filter=None, finding_type=None, evidence_id=None, db=db)
    assert len(listed) == 1
    assert listed[0].id == "finding-1"
    detail = routes_findings.get_finding("case-1", "finding-1", db=db)
    assert detail.id == "finding-1"
    updated = routes_findings.update_case_finding("case-1", "finding-1", FindingUpdate(status=FindingStatus.dismissed), db=db)
    assert updated.status == FindingStatus.dismissed
