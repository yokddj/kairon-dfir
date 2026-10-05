from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.services.ai.context import build_case_context


class FakeQuery:
    def __init__(self, items):
        self.items = list(items)

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def limit(self, count):
        return FakeQuery(self.items[:count])

    def count(self):
        return len(self.items)

    def all(self):
        return list(self.items)


class FakeDb:
    def __init__(self, *, case, hosts=None, evidences=None, artifacts=None, findings=None):
        self.case = case
        self.hosts = hosts or []
        self.evidences = evidences or []
        self.artifacts = artifacts or []
        self.findings = findings or []

    def get(self, model, identifier):
        if model is Case and identifier == self.case.id:
            return self.case
        return None

    def query(self, model):
        if model is CaseHost:
            return FakeQuery(self.hosts)
        if model is Evidence:
            return FakeQuery(self.evidences)
        if model is Finding:
            return FakeQuery(self.findings)
        return FakeQuery(self.artifacts)


def _host(name: str) -> CaseHost:
    return CaseHost(id=f"host-{name}", case_id="case-1", display_name=name, event_count=10, evidence_count=1)


def _evidence(name: str) -> Evidence:
    return Evidence(
        id=f"ev-{name}",
        case_id="case-1",
        original_filename=name,
        stored_path=f"/tmp/{name}",
        original_path=f"/tmp/{name}",
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="00",
        size_bytes=10,
        file_count=1,
        ingest_status=IngestStatus.completed,
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
    )


def _finding(name: str) -> Finding:
    return Finding(id=f"f-{name}", case_id="case-1", title=name, severity=FindingSeverity.medium, status=FindingStatus.new)


def _case() -> Case:
    return Case(id="case-1", name="Hostalpha", status="open")


def test_build_case_context_lists_everything_when_within_limits():
    db = FakeDb(case=_case(), hosts=[_host("desktop-01")], evidences=[_evidence("collection.zip")], findings=[_finding("Office spawned PowerShell")])

    context = build_case_context(db, "case-1")

    assert "desktop-01" in context
    assert "Note: showing" not in context


def test_build_case_context_discloses_truncation_instead_of_silently_dropping_items():
    # The model must not treat this briefing as complete case coverage -- if a case
    # has more hosts/evidence/findings than the briefing caps show, it needs to say
    # so rather than reasoning as if the missing ones don't exist.
    db = FakeDb(
        case=_case(),
        hosts=[_host(f"host-{i}") for i in range(30)],
        evidences=[_evidence(f"file-{i}.zip") for i in range(30)],
        findings=[_finding(f"finding-{i}") for i in range(30)],
    )

    context = build_case_context(db, "case-1")

    assert "showing 25 of 30 hosts" in context
    assert "showing 25 of 30 evidence items" in context
    assert "showing 25 of 30 findings" in context
