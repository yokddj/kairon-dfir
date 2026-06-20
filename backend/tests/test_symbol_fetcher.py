import ipaddress
import struct
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType, IngestStatus
from app.models.memory import MemoryPluginRun, MemoryScanRun, MemorySymbolRequirement
from app.services.memory import symbol_control
from app.services.memory.symbol_fetcher import MSF7_SIGNATURE, SymbolFetchError, SymbolIdentity, official_symbol_url, read_pdb_identity, validate_destination, validate_pdb
from app.services.memory.volatility_runner import build_plugin_argv


def _db():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _identity() -> SymbolIdentity:
    return SymbolIdentity("inventedkrnl.pdb", "00112233445566778899AABBCCDDEEFF", 3, "x64")


def _synthetic_pdb(path: Path, identity: SymbolIdentity) -> None:
    block_size = 512
    content = bytearray(block_size * 5)
    content[:32] = MSF7_SIGNATURE
    struct.pack_into("<6I", content, 32, block_size, 1, 5, 16, 0, 2)
    struct.pack_into("<I", content, block_size * 2, 3)
    directory = struct.pack("<III", 2, 0xFFFFFFFF, 28) + struct.pack("<I", 4)
    content[block_size * 3:block_size * 3 + len(directory)] = directory
    pdb_header = struct.pack("<III", 20000404, 0, identity.age) + uuid.UUID(hex=identity.guid).bytes_le
    content[block_size * 4:block_size * 4 + len(pdb_header)] = pdb_header
    path.write_bytes(content)


def test_official_url_uses_only_validated_identity() -> None:
    url = official_symbol_url(_identity())
    assert url == "https://msdl.microsoft.com/download/symbols/inventedkrnl.pdb/00112233445566778899AABBCCDDEEFF3/inventedkrnl.pdb"
    with pytest.raises(SymbolFetchError):
        official_symbol_url(SymbolIdentity("../kernel.pdb", _identity().guid, 1, "x64"))


@pytest.mark.parametrize("url", [
    "http://msdl.microsoft.com/x",
    "https://msdl.microsoft.com.attacker.example/x",
    "https://microsoft-symbols.example/x",
    "https://blob.core.windows.net.attacker.example/x",
    "https://127.0.0.1/x",
    "https://localhost/x",
    "https://msdl.microsoft.com:444/x",
])
def test_destination_policy_rejects_unsafe_hosts(url: str) -> None:
    with pytest.raises(SymbolFetchError):
        validate_destination(url, initial=True, initial_host="msdl.microsoft.com", redirect_suffixes=[".blob.core.windows.net"])


def test_destination_policy_accepts_narrow_official_redirect() -> None:
    host, _, port = validate_destination(
        "https://vsblobprodscussu5shard38.blob.core.windows.net/symbols/file?sig=redacted",
        initial=False,
        initial_host="msdl.microsoft.com",
        redirect_suffixes=[".blob.core.windows.net"],
    )
    assert host.endswith(".blob.core.windows.net")
    assert port == 443


@pytest.mark.parametrize("raw", ["127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.19", "::1", "fe80::1", "fc00::1"])
def test_private_and_local_addresses_are_not_global(raw: str) -> None:
    assert not ipaddress.ip_address(raw).is_global


def test_synthetic_pdb_guid_and_age_validation(tmp_path: Path) -> None:
    identity = _identity()
    path = tmp_path / "synthetic.pdb"
    _synthetic_pdb(path, identity)
    assert read_pdb_identity(path) == (identity.guid, identity.age)
    validate_pdb(path, identity)
    with pytest.raises(SymbolFetchError, match="identity"):
        validate_pdb(path, SymbolIdentity(identity.pdb_name, "F" * 32, identity.age, "x64"))


def test_invalid_pdb_rejected(tmp_path: Path) -> None:
    path = tmp_path / "invalid.pdb"
    path.write_bytes(b"not a pdb")
    with pytest.raises(SymbolFetchError) as exc:
        read_pdb_identity(path)
    assert exc.value.code == "SYMBOL_PDB_INVALID"


def test_requirement_is_deduplicated_without_evidence_data() -> None:
    db = _db()
    case = Case(id="aaaaaaaa-1111-4111-8111-111111111111", name="Synthetic")
    evidence = Evidence(id="bbbbbbbb-2222-4222-8222-222222222222", case_id=case.id, original_filename="synthetic.mem", stored_path="relative", original_path="relative", evidence_type=EvidenceType.memory_dump, sha256="0" * 64, size_bytes=1, ingest_status=IngestStatus.completed, metadata_json={}, error_log={})
    db.add_all([case, evidence])
    db.commit()
    run = MemoryScanRun(case_id=case.id, evidence_id=evidence.id, profile="metadata_only", status="failed", error_log={"code": "SYMBOLS_UNAVAILABLE"})
    db.add(run)
    db.commit()
    plugin = MemoryPluginRun(memory_scan_run_id=run.id, case_id=case.id, evidence_id=evidence.id, plugin="windows.info", status="failed")
    db.add(plugin)
    db.commit()
    payload = {"pdb_name": _identity().pdb_name, "pdb_guid": _identity().guid, "pdb_age": _identity().age, "architecture": "x64"}
    first = symbol_control.record_symbol_requirement(db, run, plugin.id, payload)
    second = symbol_control.record_symbol_requirement(db, run, plugin.id, payload)
    assert first.id == second.id
    assert db.query(MemorySymbolRequirement).count() == 1
    assert "path" not in first.__dict__
    assert "sha256" not in first.__dict__


def test_normal_memory_argv_remains_offline() -> None:
    argv = build_plugin_argv("vol", Path("/controlled/evidence"), "windows.info", offline=True, cache_path=Path("/cache"), symbol_path=Path("/symbols"))
    assert "--offline" in argv
    assert "http" not in " ".join(argv)


def test_symbol_fetcher_compose_has_cache_only_mount() -> None:
    compose_path = Path(__file__).parents[2] / "docker-compose.yml"
    if not compose_path.exists():
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = compose_path.read_text()
    service = compose.split("  symbol-fetcher:", 1)[1].split("  frontend:", 1)[0]
    assert "memory-symbol-cache:/volatility-cache" in service
    assert "data/evidence" not in service
    assert "memory-output" not in service
    assert "ports:" not in service
    assert "read_only: true" in service
    assert "no-new-privileges:true" in service
    assert "- ALL" in service
    assert 'user: "10001:10001"' in service
    assert "memory-symbols" in service
