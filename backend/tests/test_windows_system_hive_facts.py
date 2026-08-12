"""Windows Host Facts from the SYSTEM registry hive.

Follows the same FakeKey/FakeValue/FakeHive test-double pattern already
established for WindowsServiceRawParser in tests/test_ingest.py, mimicking
just enough of python-registry's Registry.Registry interface
(.open/.root/.subkey/.subkeys/.values/.name/.value) to exercise the real
parser code without needing an actual hive file on disk.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.ingest.artifact_normalizers import normalize_evtx_row
from app.ingest.host_facts_extraction import extract_host_fact_documents
from app.ingest.normalizer import base_document
from app.ingest.raw_parsers.system_hive_identity_parser import WindowsSystemHiveIdentityRawParser
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services.host_facts import create_host_fact_observations, resolve_host_facts

CASE_ID = "3d3d3d3d-1111-4111-8111-3d3d3d3d3d3d"
HOST_ID = "4e4e4e4e-1111-4111-8111-4e4e4e4e4e4e"
EVIDENCE_ID = "5f5f5f5f-2222-4222-8222-5f5f5f5f5f5f"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _case(db):
    db.add(Case(id=CASE_ID, name="Case", description=None))
    db.commit()


def _evidence(db):
    db.add(
        Evidence(
            id=EVIDENCE_ID, case_id=CASE_ID, original_filename="WS01.zip", stored_path="/tmp/WS01.zip",
            original_path="/tmp/WS01.zip", storage_mode=EvidenceStorageMode.uploaded, is_external=False,
            copy_to_storage=True, evidence_type=EvidenceType.raw_collection, sha256="0" * 64, size_bytes=128,
            ingest_status=IngestStatus.completed, detected_host=None, host_id=HOST_ID,
            path_validation={}, ingest_source={}, metadata_json={}, error_log={},
        )
    )
    db.commit()


def _evtx_doc(computer: str) -> dict:
    row = {
        "EventID": "1",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider": "Microsoft-Windows-Sysmon",
        "Computer": computer,
        "ProcessId": "1234",
        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
        "UtcTime": "2024-03-22 12:21:24.171",
    }
    artifact_meta = {
        "artifact_type": "windows_event",
        "parser": "evtxecmd_csv",
        "source_tool": "evtxecmd",
        "source_format": "evtx_csv",
        "source_path": "C/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
        "ingest_run_id": "run-1",
    }
    document = base_document(CASE_ID, EVIDENCE_ID, "6a6a6a6a-3333-4333-8333-6a6a6a6a6a6a", row, artifact_meta)
    return normalize_evtx_row(document, row, artifact_meta)


class FakeValue:
    def __init__(self, name: str, value):
        self._name = name
        self._value = value

    def name(self):
        return self._name

    def value(self):
        return self._value


class FakeKey:
    def __init__(self, name: str, values=None, subkeys=None):
        self._name = name
        self._values = values or []
        self._subkeys = {key.name(): key for key in (subkeys or [])}

    def name(self):
        return self._name

    def values(self):
        return self._values

    def subkeys(self):
        return list(self._subkeys.values())

    def subkey(self, name: str):
        key = self._subkeys.get(name)
        if key is None:
            raise Exception(f"Registry key not found: {name}")  # noqa: TRY002
        return key


def _computer_name_key(name: str) -> FakeKey:
    return FakeKey("ComputerName", values=[FakeValue("ComputerName", name)])


def _timezone_key(key_name: str | None) -> FakeKey:
    values = [FakeValue("Bias", 4294967236)]
    if key_name is not None:
        values.append(FakeValue("TimeZoneKeyName", key_name))
    return FakeKey("TimeZoneInformation", values=values)


def _desktop_editions_key(*, build_number="22621", major="10", minor="0", arch="amd64") -> FakeKey:
    values = [
        FakeValue("BuildNumber", build_number),
        FakeValue("MajorVersion", major),
        FakeValue("MinorVersion", minor),
    ]
    if arch is not None:
        values.append(FakeValue("BuildArch", arch))
    return FakeKey("DesktopEditions", values=values)


def _full_hive(*, computer_name="WS01", timezone_key_name="Romance Standard Time", build_number="22621", arch="amd64") -> object:
    control = FakeKey(
        "Control",
        subkeys=[
            FakeKey("ComputerName", subkeys=[_computer_name_key(computer_name)]),
            _timezone_key(timezone_key_name),
        ],
    )
    control_set = FakeKey("ControlSet001", subkeys=[control])
    select = FakeKey("Select", values=[FakeValue("Current", 1)])
    software = FakeKey(
        "Software",
        subkeys=[FakeKey("Microsoft", subkeys=[FakeKey("BuildLayers", subkeys=[_desktop_editions_key(build_number=build_number, arch=arch)])])],
    )
    root = FakeKey("ROOT", subkeys=[select, control_set, software])

    class FakeHive:
        def root(self):
            return root

        def open(self, path: str):
            node = root
            for part in path.split("\\"):
                node = node.subkey(part)
            return node

    return FakeHive()


def _parse(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, hive) -> object:
    fake_module = SimpleNamespace(Registry=lambda _: hive)
    monkeypatch.setattr("app.ingest.raw_parsers.system_hive_identity_parser._load_registry_module", lambda: fake_module)
    path = tmp_path / "SYSTEM"
    path.write_bytes(b"fake")
    parser = WindowsSystemHiveIdentityRawParser()
    return parser.parse(
        path,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        artifact_meta={
            "artifact_type": "windows_system_hive_facts",
            "name": "SYSTEM",
            "source_path": "C:\\Windows\\System32\\config\\SYSTEM",
            "parser": "windows_system_hive_facts",
        },
    )


def _facts_by_type(result) -> dict[str, dict]:
    return {doc["host_fact"]["fact_type"]: doc["host_fact"] for doc in result.events}


class TestExtraction:
    def test_all_facts_extracted_from_a_full_hive(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        result = _parse(monkeypatch, tmp_path, _full_hive())
        assert result.parser_status == "parsed_native"
        facts = _facts_by_type(result)
        assert facts["host.hostname"]["normalized_value"] == "WS01"
        assert facts["host.hostname"]["artifact_type"] == "system_hive_computername"
        assert facts["host.timezone"]["normalized_value"] == "Romance Standard Time"
        assert facts["host.distribution"]["normalized_value"] == "Windows"
        assert facts["host.distribution_version"]["normalized_value"] == "10.0.22621"
        assert facts["host.architecture"]["normalized_value"] == "x64"
        assert facts["host.architecture"]["raw_value"] == "amd64"

    def test_hostname_never_becomes_an_fqdn(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # ComputerName carries no domain suffix -- this parser must never
        # emit host.fqdn from the SYSTEM hive.
        result = _parse(monkeypatch, tmp_path, _full_hive())
        facts = _facts_by_type(result)
        assert "host.fqdn" not in facts

    def test_missing_timezone_key_name_produces_no_timezone_fact(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # Pre-Vista-shaped hive: only Bias/DaylightBias exist, no
        # TimeZoneKeyName -- must never fall back to inferring a regional
        # zone from the raw offset.
        result = _parse(monkeypatch, tmp_path, _full_hive(timezone_key_name=None))
        facts = _facts_by_type(result)
        assert "host.timezone" not in facts
        assert "timezonekeyname_missing" in result.warnings

    def test_missing_buildlayers_key_produces_no_version_or_arch_facts(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        control = FakeKey("Control", subkeys=[FakeKey("ComputerName", subkeys=[_computer_name_key("WS01")]), _timezone_key("Romance Standard Time")])
        control_set = FakeKey("ControlSet001", subkeys=[control])
        select = FakeKey("Select", values=[FakeValue("Current", 1)])
        root = FakeKey("ROOT", subkeys=[select, control_set])  # no Software subtree at all

        class FakeHive:
            def root(self):
                return root

            def open(self, path: str):
                node = root
                for part in path.split("\\"):
                    node = node.subkey(part)
                return node

        result = _parse(monkeypatch, tmp_path, FakeHive())
        facts = _facts_by_type(result)
        assert "host.distribution" not in facts
        assert "host.distribution_version" not in facts
        assert "host.architecture" not in facts
        assert facts["host.hostname"]["normalized_value"] == "WS01"
        assert "buildlayers_desktopeditions_key_not_found" in result.warnings

    def test_missing_select_current_produces_no_hostname_or_timezone_but_still_gets_version(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        control = FakeKey("Control", subkeys=[FakeKey("ComputerName", subkeys=[_computer_name_key("WS01")]), _timezone_key("Romance Standard Time")])
        control_set = FakeKey("ControlSet001", subkeys=[control])
        select = FakeKey("Select", values=[])  # no Current value
        software = FakeKey("Software", subkeys=[FakeKey("Microsoft", subkeys=[FakeKey("BuildLayers", subkeys=[_desktop_editions_key()])])])
        root = FakeKey("ROOT", subkeys=[select, control_set, software])

        class FakeHive:
            def root(self):
                return root

            def open(self, path: str):
                node = root
                for part in path.split("\\"):
                    node = node.subkey(part)
                return node

        result = _parse(monkeypatch, tmp_path, FakeHive())
        facts = _facts_by_type(result)
        assert "host.hostname" not in facts
        assert "host.timezone" not in facts
        assert facts["host.distribution_version"]["normalized_value"] == "10.0.22621"
        assert "select_current_missing" in result.warnings

    def test_hive_open_failure_is_a_soft_failure(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        def _raise(_):
            raise RuntimeError("corrupt hive")

        fake_module = SimpleNamespace(Registry=_raise)
        monkeypatch.setattr("app.ingest.raw_parsers.system_hive_identity_parser._load_registry_module", lambda: fake_module)
        path = tmp_path / "SYSTEM"
        path.write_bytes(b"fake")
        parser = WindowsSystemHiveIdentityRawParser()
        result = parser.parse(path, case_id="case-1", evidence_id="ev-1", artifact_id="art-1", artifact_meta={"source_path": "C:\\Windows\\System32\\config\\SYSTEM"})
        assert result.parser_status == "failed_unsupported"
        assert result.events == []

    def test_zero_facts_found_is_parsed_empty_not_a_hard_failure(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        root = FakeKey("ROOT", subkeys=[FakeKey("Select", values=[])])

        class FakeHive:
            def root(self):
                return root

            def open(self, path: str):
                node = root
                for part in path.split("\\"):
                    node = node.subkey(part)
                return node

        result = _parse(monkeypatch, tmp_path, FakeHive())
        assert result.parser_status == "parsed_empty"
        assert result.events == []


class TestEndToEndPersistence:
    def test_registry_facts_flow_through_the_generic_dispatcher(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        result = _parse(monkeypatch, tmp_path, _full_hive())
        host_fact_documents = extract_host_fact_documents(result.events)
        fact_types = {doc["host_fact"]["fact_type"] for doc in host_fact_documents}
        assert fact_types == {"host.hostname", "host.timezone", "host.distribution", "host.distribution_version", "host.architecture"}

    def test_registry_and_evtx_hostname_agree_without_conflict(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        db = _db()
        _case(db)
        _evidence(db)
        result = _parse(monkeypatch, tmp_path, _full_hive(computer_name="WS01"))
        registry_docs = extract_host_fact_documents(result.events)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="7b7b7b7b-4444-4444-8444-7b7b7b7b7b7b", host_id=HOST_ID, observed_at=None,
            documents=registry_docs,
        )
        evtx_docs = extract_host_fact_documents([_evtx_doc("WS01.megacorp.local")])
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="8c8c8c8c-5555-4555-8555-8c8c8c8c8c8c", host_id=HOST_ID, observed_at=None,
            documents=evtx_docs,
        )
        resolved = resolve_host_facts(db, case_id=CASE_ID, host_id=HOST_ID, fact_type="host.hostname")[0]
        assert resolved["status"] == "confirmed"
        assert resolved["conflicting"] == []
        # SYSTEM hive outranks the EVTX Computer field.
        assert resolved["preferred_value"] == "WS01"

    def test_registry_and_evtx_hostname_conflict_is_visible(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        db = _db()
        _case(db)
        _evidence(db)
        result = _parse(monkeypatch, tmp_path, _full_hive(computer_name="WS02"))
        registry_docs = extract_host_fact_documents(result.events)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="7b7b7b7b-4444-4444-8444-7b7b7b7b7b7b", host_id=HOST_ID, observed_at=None,
            documents=registry_docs,
        )
        evtx_docs = extract_host_fact_documents([_evtx_doc("WS01.megacorp.local")])
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="8c8c8c8c-5555-4555-8555-8c8c8c8c8c8c", host_id=HOST_ID, observed_at=None,
            documents=evtx_docs,
        )
        resolved = resolve_host_facts(db, case_id=CASE_ID, host_id=HOST_ID, fact_type="host.hostname")[0]
        assert resolved["status"] == "conflicting"

    def test_idempotent_across_reprocess(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        db = _db()
        _case(db)
        _evidence(db)

        def _ingest():
            result = _parse(monkeypatch, tmp_path, _full_hive())
            docs = extract_host_fact_documents(result.events)
            create_host_fact_observations(
                db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="7b7b7b7b-4444-4444-8444-7b7b7b7b7b7b", host_id=HOST_ID, observed_at=None,
                documents=docs,
            )

        _ingest()
        from app.models.host_fact import HostFact

        first_count = db.query(HostFact).count()
        _ingest()
        second_count = db.query(HostFact).count()
        assert second_count == first_count
