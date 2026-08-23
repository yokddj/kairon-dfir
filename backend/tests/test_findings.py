from types import SimpleNamespace

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_findings
from app.core.database import Base, get_db
from app.main import app, settings
from app.models.activity import AppActivityEvent
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.evidence import Evidence
from app.models.evidence import EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.schemas.finding import FindingCreate, FindingUpdate
from app.services import correlation_engine


CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
OTHER_CASE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
EVIDENCE_ID = "cccccccc-3333-4333-8333-cccccccccccc"
OTHER_EVIDENCE_ID = "dddddddd-4444-4444-8444-dddddddddddd"
HOST_ID = "eeeeeeee-5555-4555-8555-eeeeeeeeeeee"
OTHER_HOST_ID = "ffffffff-6666-4666-8666-ffffffffffff"


def _db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _client(db):
    test_app = FastAPI()
    test_app.include_router(routes_findings.router)
    test_app.dependency_overrides[get_db] = lambda: db
    return TestClient(test_app)


def _seed_case_graph(db):
    db.add_all([
        Case(id=CASE_ID, name="Case 1", status="active", priority="medium", management_tags=[]),
        Case(id=OTHER_CASE_ID, name="Case 2", status="active", priority="medium", management_tags=[]),
        CaseHost(id=HOST_ID, case_id=CASE_ID, canonical_name="ws01", display_name="WS01", confidence="manual", source="manual"),
        CaseHost(id=OTHER_HOST_ID, case_id=OTHER_CASE_ID, canonical_name="ws02", display_name="WS02", confidence="manual", source="manual"),
        Evidence(id=EVIDENCE_ID, case_id=CASE_ID, original_filename="memory.raw", stored_path="/tmp/memory.raw", storage_mode=EvidenceStorageMode.uploaded, is_external=False, copy_to_storage=True, evidence_type=EvidenceType.memory_dump, size_bytes=128, ingest_status=IngestStatus.completed, path_validation={}, ingest_source={}, metadata_json={}, error_log={}),
        Evidence(id=OTHER_EVIDENCE_ID, case_id=OTHER_CASE_ID, original_filename="other.zip", stored_path="/tmp/other.zip", storage_mode=EvidenceStorageMode.uploaded, is_external=False, copy_to_storage=True, evidence_type=EvidenceType.velociraptor_zip, size_bytes=128, ingest_status=IngestStatus.completed, path_validation={}, ingest_source={}, metadata_json={}, error_log={}),
    ])
    db.commit()


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
        payload = FindingCreate(title="Event finding", event_ids=["evt-1"])
        result = routes_findings._normalize_finding_create("case-1", payload, _FakeDb())
    finally:
        routes_findings.fetch_event_by_id = original_fetch  # type: ignore[assignment]
    assert result["title"] == "Event finding"
    assert result["event_ids"] == ["evt-1"]


def test_normalize_finding_create_merges_detection_event_ids() -> None:
    detections = [
        SimpleNamespace(id="det-1", case_id="case-1", event_id="evt-1", rule_name="Built-in: Suspicious command line"),
        SimpleNamespace(id="det-2", case_id="case-1", event_id=None, rule_name="Built-in: RDP activity"),
    ]
    original_fetch = routes_findings.fetch_event_by_id
    routes_findings.fetch_event_by_id = lambda case_id, event_id, **kwargs: {"event": {"type": "process_creation", "message": "Process created"}} if event_id == "evt-1" else None  # type: ignore[assignment]
    try:
        payload = FindingCreate(title="Detection finding", detection_ids=["det-1", "det-2"])
        result = routes_findings._normalize_finding_create("case-1", payload, _FakeDb(detections=detections))
    finally:
        routes_findings.fetch_event_by_id = original_fetch  # type: ignore[assignment]
    assert result["detection_ids"] == ["det-1", "det-2"]
    assert result["event_ids"] == ["evt-1"]
    assert result["title"] == "Detection finding"


def test_normalize_finding_create_rejects_missing_events_without_detections() -> None:
    original_fetch = routes_findings.fetch_event_by_id
    routes_findings.fetch_event_by_id = lambda case_id, event_id, **kwargs: None  # type: ignore[assignment]
    try:
        try:
            routes_findings._normalize_finding_create("case-1", FindingCreate(title="Missing event", event_ids=["missing-1"]), _FakeDb())
        except HTTPException as exc:
            assert exc.status_code == 400
            assert "missing_event_ids" in exc.detail
        else:
            raise AssertionError("Expected missing event selection to fail")
    finally:
        routes_findings.fetch_event_by_id = original_fetch  # type: ignore[assignment]


def test_normalize_finding_create_allows_manual_finding() -> None:
    result = routes_findings._normalize_finding_create("case-1", FindingCreate(title="Manual finding", body="Analyst notes"), _FakeDb())
    assert result["title"] == "Manual finding"
    assert result["description"] == "Analyst notes"
    assert result["status"].value == "draft"


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


def test_create_finding_with_case_evidence_host_and_normalized_tags():
    db = _db_session()
    _seed_case_graph(db)
    client = _client(db)

    response = client.post(
        f"/api/cases/{CASE_ID}/findings",
        json={"title": "Suspicious memory artifact", "body": "Process tree looks odd", "severity": "high", "status": "review", "tags": [" Memory ", "memory", "Needs Review"], "linked_evidence_id": EVIDENCE_ID, "linked_host_id": HOST_ID, "source_view": "memory"},
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["title"] == "Suspicious memory artifact"
    assert payload["body"] == "Process tree looks odd"
    assert payload["severity"] == "high"
    assert payload["status"] == "review"
    assert payload["tags"] == ["memory", "needs-review"]
    assert payload["linked_evidence_id"] == EVIDENCE_ID
    assert payload["linked_host_id"] == HOST_ID
    # No related_hosts sent explicitly -- must be derived from linked_host_id
    # so the host filter on the Findings page can still find this finding.
    assert payload["related_hosts"] == ["ws01"]


def test_create_finding_related_hosts_explicit_value_is_kept_as_is():
    db = _db_session()
    _seed_case_graph(db)
    client = _client(db)

    response = client.post(
        f"/api/cases/{CASE_ID}/findings",
        json={"title": "Manual finding", "linked_host_id": HOST_ID, "related_hosts": ["some-other-host"]},
    )

    assert response.status_code == 201
    assert response.json()["related_hosts"] == ["some-other-host"]


def test_create_finding_with_source_artifact_snapshot_fields():
    db = _db_session()
    _seed_case_graph(db)
    client = _client(db)

    response = client.post(
        f"/api/cases/{CASE_ID}/findings",
        json={
            "title": "Suspicious PowerShell command",
            "body": "Encoded command observed in Search.",
            "severity": "medium",
            "status": "draft",
            "tags": ["Search", "PowerShell", "PowerShell"],
            "linked_evidence_id": EVIDENCE_ID,
            "linked_host_id": HOST_ID,
            "linked_event_id": "evt-1",
            "linked_artifact_family": "powershell",
            "linked_artifact_type": "script_block",
            "source_view": "search",
            "source_route": f"/cases/{CASE_ID}/search?selected=evt-1",
            "source_timestamp": "2026-05-15T10:00:00Z",
            "source_label": "Search result",
            "source_summary": "powershell.exe -EncodedCommand AAAA",
            "source_snapshot_json": {"timestamp": "2026-05-15T10:00:00Z", "fields": {"command_line": "powershell.exe -EncodedCommand AAAA"}},
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["linked_event_id"] == "evt-1"
    assert payload["source_view"] == "search"
    assert payload["source_route"].endswith("selected=evt-1")
    assert payload["source_summary"] == "powershell.exe -EncodedCommand AAAA"
    assert payload["source_snapshot_json"]["fields"]["command_line"].startswith("powershell.exe")
    assert payload["tags"] == ["search", "powershell"]


def test_source_snapshot_too_large_is_rejected():
    db = _db_session()
    _seed_case_graph(db)
    client = _client(db)

    response = client.post(
        f"/api/cases/{CASE_ID}/findings",
        json={"title": "Huge snapshot", "source_snapshot_json": {"blob": "x" * 13000}},
    )

    assert response.status_code == 422


def test_list_findings_filters_by_severity_status_tag_text_and_links():
    db = _db_session()
    _seed_case_graph(db)
    client = _client(db)
    client.post(f"/api/cases/{CASE_ID}/findings", json={"title": "Critical confirmed note", "body": "malware beacon", "severity": "critical", "status": "confirmed", "tags": ["malware"], "linked_evidence_id": EVIDENCE_ID, "linked_host_id": HOST_ID})
    client.post(f"/api/cases/{CASE_ID}/findings", json={"title": "Info draft", "severity": "info", "status": "draft", "tags": ["triage"]})

    assert [item["title"] for item in client.get(f"/api/cases/{CASE_ID}/findings?severity=critical").json()] == ["Critical confirmed note"]
    assert [item["title"] for item in client.get(f"/api/cases/{CASE_ID}/findings?status=confirmed").json()] == ["Critical confirmed note"]
    assert [item["title"] for item in client.get(f"/api/cases/{CASE_ID}/findings?tag=malware").json()] == ["Critical confirmed note"]
    assert [item["title"] for item in client.get(f"/api/cases/{CASE_ID}/findings?q=beacon").json()] == ["Critical confirmed note"]
    assert [item["title"] for item in client.get(f"/api/cases/{CASE_ID}/findings?linked_evidence_id={EVIDENCE_ID}").json()] == ["Critical confirmed note"]
    assert [item["title"] for item in client.get(f"/api/cases/{CASE_ID}/findings?linked_host_id={HOST_ID}").json()] == ["Critical confirmed note"]


def test_update_and_archive_finding_include_archived():
    db = _db_session()
    _seed_case_graph(db)
    client = _client(db)
    created = client.post(f"/api/cases/{CASE_ID}/findings", json={"title": "Draft note", "source_snapshot_json": {"summary": "preserved"}}).json()

    updated = client.patch(f"/api/cases/{CASE_ID}/findings/{created['id']}", json={"title": "Confirmed finding", "severity": "critical", "status": "confirmed"})
    assert updated.status_code == 200
    assert updated.json()["title"] == "Confirmed finding"

    deleted = client.delete(f"/api/cases/{CASE_ID}/findings/{created['id']}")
    assert deleted.status_code == 204
    assert client.get(f"/api/cases/{CASE_ID}/findings").json() == []
    archived = client.get(f"/api/cases/{CASE_ID}/findings?include_archived=true").json()
    assert archived[0]["status"] == "archived"
    assert archived[0]["archived_at"] is not None
    assert archived[0]["source_snapshot_json"] == {"summary": "preserved"}


def test_linked_evidence_and_host_must_belong_to_case():
    db = _db_session()
    _seed_case_graph(db)
    client = _client(db)

    bad_evidence = client.post(f"/api/cases/{CASE_ID}/findings", json={"title": "Bad evidence", "linked_evidence_id": OTHER_EVIDENCE_ID})
    bad_host = client.post(f"/api/cases/{CASE_ID}/findings", json={"title": "Bad host", "linked_host_id": OTHER_HOST_ID})

    assert bad_evidence.status_code == 400
    assert bad_host.status_code == 400


def test_invalid_severity_and_status_fail():
    db = _db_session()
    _seed_case_graph(db)
    client = _client(db)

    assert client.post(f"/api/cases/{CASE_ID}/findings", json={"title": "Bad", "severity": "urgent"}).status_code == 422
    assert client.post(f"/api/cases/{CASE_ID}/findings", json={"title": "Bad", "status": "todo"}).status_code == 422


def test_finding_events_are_recorded():
    db = _db_session()
    _seed_case_graph(db)
    client = _client(db)

    created = client.post(f"/api/cases/{CASE_ID}/findings", json={"title": "Linked", "linked_evidence_id": EVIDENCE_ID}).json()
    client.patch(f"/api/cases/{CASE_ID}/findings/{created['id']}", json={"status": "review"})
    client.delete(f"/api/cases/{CASE_ID}/findings/{created['id']}")

    event_types = {event.activity_type for event in db.query(AppActivityEvent).all()}
    assert {"finding_created", "finding_linked", "finding_updated", "finding_archived"}.issubset(event_types)


def test_unauthenticated_user_cannot_access_findings(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    response = TestClient(app).get(f"/api/cases/{CASE_ID}/findings")
    monkeypatch.setattr(settings, "auth_enabled", False)

    assert response.status_code == 401


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
    monkeypatch.setattr(correlation_engine, "_iter_events_for_case", lambda case_id, evidence_id=None, **kwargs: _correlation_events())
    monkeypatch.setattr(correlation_engine, "build_process_tree_bundle", lambda case, evidences, scope, evidence_id=None, **kwargs: _process_bundle())
    result = correlation_engine.run_correlation_engine(db, "case-1", evidence_id="ev-1")
    finding_types = {item["finding_type"] for item in result["findings"]}
    assert "office_powershell" in finding_types
    assert "powershell_network" in finding_types
    assert "cloud_exfil_candidate" in finding_types
    assert "suspicious_process_chain" in finding_types
    assert result["report"]["findings_generated"] == len(result["findings"])


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
    monkeypatch.setattr(correlation_engine, "_iter_events_for_case", lambda case_id, evidence_id=None, **kwargs: events)
    monkeypatch.setattr(correlation_engine, "build_process_tree_bundle", lambda case, evidences, scope, evidence_id=None, **kwargs: {"graph": {"nodes": [], "edges": [], "summary": {}}, "report": {}, "sample_chains": []})
    first = correlation_engine.run_correlation_engine(db, "case-1")
    if not first["findings"]:
        return
    db.findings[0].status = FindingStatus.reviewed
    second = correlation_engine.run_correlation_engine(db, "case-1")
    assert len(second["findings"]) == len(first["findings"])
    assert db.findings[0].status == FindingStatus.reviewed


def test_run_correlation_engine_force_does_not_reset_status(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _CorrelationDb()
    monkeypatch.setattr(correlation_engine, "_iter_events_for_case", lambda case_id, evidence_id=None, **kwargs: _correlation_events())
    monkeypatch.setattr(correlation_engine, "build_process_tree_bundle", lambda case, evidences, scope, evidence_id=None, **kwargs: _process_bundle())
    first = correlation_engine.run_correlation_engine(db, "case-1", evidence_id="ev-1")
    assert first["findings"]
    db.findings[0].status = FindingStatus.dismissed
    second = correlation_engine.run_correlation_engine(db, "case-1", evidence_id="ev-1", force=True)
    assert len(second["findings"]) == len(first["findings"])
    assert db.findings[0].status == FindingStatus.dismissed


def test_run_correlation_engine_removes_stale_correlation_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _CorrelationDb()
    monkeypatch.setattr(correlation_engine, "_iter_events_for_case", lambda case_id, evidence_id=None, **kwargs: _correlation_events())
    monkeypatch.setattr(correlation_engine, "build_process_tree_bundle", lambda case, evidences, scope, evidence_id=None, **kwargs: _process_bundle())

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
    listed = routes_findings.list_findings("case-1", severity=None, confidence=None, status_filter=None, finding_type=None, evidence_id=None, linked_evidence_id=None, linked_host_id=None, tag=None, q=None, include_archived=False, host=None, db=db)
    assert len(listed) == 1
    assert listed[0].id == "finding-1"
    detail = routes_findings.get_finding("case-1", "finding-1", db=db)
    assert detail.id == "finding-1"
    updated = routes_findings.update_case_finding("case-1", "finding-1", FindingUpdate(status=FindingStatus.dismissed), db=db)
    assert updated.status == FindingStatus.dismissed
