"""GET /api/cases/{case_id}/disk-image-installations -- a flat, case-wide
view of every detected OS installation so the frontend can label events by
which installation produced them (the live system vs. a secondary root such
as a manually extracted Volume Shadow Copy)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.routes_evidence import list_case_disk_image_installations
from app.core.database import Base
from app.models.case import Case
from app.models.disk_image import DiskImage, DiskVolume, OSInstallation
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType


@pytest.fixture
def sqlite_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    db = Session()
    try:
        yield db
    finally:
        db.close()


def _seed_case_with_installations(db) -> str:
    case_id = str(uuid.uuid4())
    evidence_id = str(uuid.uuid4())
    db.add(Case(id=case_id, name="Test Case"))
    evidence = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename="disk.vhd",
        evidence_type=EvidenceType.disk_image,
        storage_mode=EvidenceStorageMode.uploaded,
        stored_path="/tmp/disk.vhd",
        size_bytes=1_000_000,
    )
    db.add(evidence)
    disk_image = DiskImage(id=str(uuid.uuid4()), evidence_id=evidence_id, original_filename="disk.vhd", format="vhd")
    db.add(disk_image)
    volume = DiskVolume(id=str(uuid.uuid4()), disk_image_id=disk_image.id, partition_index=1, offset_bytes=32256, length_bytes=1_000_000)
    db.add(volume)
    db.add(OSInstallation(id=str(uuid.uuid4()), disk_volume_id=volume.id, platform="windows", root_path="/C", confidence="high"))
    db.add(
        OSInstallation(
            id=str(uuid.uuid4()),
            disk_volume_id=volume.id,
            platform="windows",
            root_path="/VSS1",
            confidence="high",
            metadata_json={
                "installation_root_kind": "secondary_top_level_folder",
                "secondary_root_folder": "VSS1",
                "note": "Detected under a non-drive-letter top-level folder...",
            },
        )
    )
    db.commit()
    return case_id, evidence_id


def test_lists_installations_across_a_cases_disk_images(sqlite_session):
    case_id, evidence_id = _seed_case_with_installations(sqlite_session)

    result = list_case_disk_image_installations(case_id, sqlite_session)

    by_root = {item.root_path: item for item in result}
    assert set(by_root) == {"/C", "/VSS1"}
    assert by_root["/C"].is_secondary is False
    assert by_root["/C"].note is None
    assert by_root["/VSS1"].is_secondary is True
    assert by_root["/VSS1"].note is not None
    assert by_root["/VSS1"].evidence_id == evidence_id


def test_returns_empty_list_for_a_case_with_no_disk_images(sqlite_session):
    empty_case_id = str(uuid.uuid4())
    sqlite_session.add(Case(id=empty_case_id, name="Empty Case"))
    sqlite_session.commit()

    result = list_case_disk_image_installations(empty_case_id, sqlite_session)

    assert result == []


def test_does_not_leak_installations_from_another_case(sqlite_session):
    _seed_case_with_installations(sqlite_session)
    other_case_id = str(uuid.uuid4())
    sqlite_session.add(Case(id=other_case_id, name="Other Case"))
    sqlite_session.commit()

    result = list_case_disk_image_installations(other_case_id, sqlite_session)

    assert result == []
