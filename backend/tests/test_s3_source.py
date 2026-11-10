"""Evidence imported from an S3 bucket (app.services.s3_source, app.api.routes_s3).

No request ever reaches AWS: boto3's client is replaced by a fake that answers like S3."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_evidence_preflight, routes_s3
from app.core.config import get_settings
from app.core.database import Base, get_db
from app.models.case import Case
from app.models.evidence_upload_session import EvidenceUploadSession
from app.services import s3_source
from app.services.ai import crypto

settings = get_settings()
CASE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
PAYLOAD = b"PK\x03\x04" + b"evidence" * 4096


class _ClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code, "Message": "secret-internal-detail"}}


class FakeS3:
    """The calls s3_source makes, over one in-memory bucket."""

    def __init__(self, objects: dict[str, bytes] | None = None) -> None:
        self.objects = objects if objects is not None else {"cases/001/collection.zip": PAYLOAD, "cases/001/notes/readme.txt": b"x", "cases/002/": b""}
        self.calls: list[tuple[str, dict]] = []

    def _check(self, bucket: str) -> None:
        if bucket != "evidence-bucket":
            raise _ClientError("NoSuchBucket")

    def head_bucket(self, Bucket):  # noqa: N803
        self.calls.append(("head_bucket", {"Bucket": Bucket}))
        self._check(Bucket)

    def list_buckets(self):
        return {"Buckets": [{"Name": "evidence-bucket"}]}

    def list_objects_v2(self, **kwargs):
        self.calls.append(("list_objects_v2", kwargs))
        self._check(kwargs["Bucket"])
        prefix = kwargs.get("Prefix", "")
        contents, prefixes = [], set()
        for key, data in sorted(self.objects.items()):
            if not key.startswith(prefix):
                continue
            rest = key[len(prefix):]
            if "/" in rest.rstrip("/") or (rest.endswith("/") and rest):
                prefixes.add(prefix + rest.split("/", 1)[0] + "/")
                continue
            contents.append({"Key": key, "Size": len(data), "LastModified": datetime(2026, 11, 1, tzinfo=timezone.utc), "StorageClass": "STANDARD"})
        return {"Contents": contents, "CommonPrefixes": [{"Prefix": item} for item in sorted(prefixes)], "IsTruncated": False}

    def head_object(self, Bucket, Key):  # noqa: N803
        self.calls.append(("head_object", {"Bucket": Bucket, "Key": Key}))
        self._check(Bucket)
        if Key not in self.objects:
            raise _ClientError("404")
        return {"ContentLength": len(self.objects[Key]), "ETag": '"abc123"', "StorageClass": "STANDARD"}

    def get_object(self, **kwargs):
        self.calls.append(("get_object", kwargs))
        return {"Body": io.BytesIO(self.objects[kwargs["Key"]])}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    make_session = sessionmaker(bind=engine, future=True)
    db = make_session()
    db.add(Case(id=CASE_ID, name="S3 Case", description="", status="active", priority="medium", management_tags=[]))
    db.commit()
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    monkeypatch.setattr(settings, "backend_max_upload_size", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "auth_enabled", False)
    monkeypatch.setattr(settings, "s3_source_enabled", True)
    monkeypatch.setattr(settings, "session_secret_key", "test-session-secret")
    monkeypatch.setattr(settings, "ai_secret_key", "")
    fake = FakeS3()
    monkeypatch.setattr(s3_source, "build_client", lambda config: fake if s3_source._is_configured(config) else (_ for _ in ()).throw(s3_source.S3SourceError("not configured")))
    queued: list[str] = []
    monkeypatch.setattr("app.workers.tasks.enqueue_s3_import", lambda session_id: queued.append(session_id) or "job-1")
    monkeypatch.setattr("app.services.audit.log_audit", lambda *a, **k: None)
    monkeypatch.setattr(routes_s3, "log_audit", lambda *a, **k: None)
    monkeypatch.setattr("app.core.database.SessionLocal", make_session)
    app = FastAPI()
    app.include_router(routes_s3.router)
    app.include_router(routes_evidence_preflight.router)
    app.dependency_overrides[get_db] = lambda: db
    return {"db": db, "client": TestClient(app), "fake": fake, "queued": queued, "make_session": make_session}


def _configure(client: TestClient) -> dict:
    response = client.put("/api/s3/config", json={"region": "eu-west-1", "access_key_id": "AKIAEXAMPLE", "secret_access_key": "super-secret-value-1234", "default_bucket": "evidence-bucket"})
    assert response.status_code == 200
    return response.json()


def test_the_secret_is_sealed_with_its_own_key_and_never_returned(env) -> None:
    public = _configure(env["client"])
    assert public["has_secret_access_key"] and public["secret_access_key_masked"] == "********1234"
    assert "super-secret" not in str(public)
    stored = s3_source.load_config(env["db"])
    assert crypto.is_sealed(stored["secret_access_key"]) and "super-secret" not in stored["secret_access_key"]
    # Not readable with the AI assistant's key: each purpose derives its own.
    with pytest.raises(crypto.CredentialCryptoError):
        crypto.open_sealed(stored["secret_access_key"])
    assert env["client"].get("/api/s3/config").json()["secret_access_key_masked"] == "********1234"


def test_saving_without_a_secret_keeps_it_and_an_empty_one_clears_it(env) -> None:
    _configure(env["client"])
    kept = env["client"].put("/api/s3/config", json={"region": "us-east-1"}).json()
    assert kept["has_secret_access_key"] and kept["region"] == "us-east-1"
    cleared = env["client"].put("/api/s3/config", json={"secret_access_key": ""}).json()
    assert not cleared["has_secret_access_key"] and not cleared["configured"]


def test_an_endpoint_must_be_a_url(env) -> None:
    response = env["client"].put("/api/s3/config", json={"endpoint_url": "minio.lab:9000"})
    assert response.status_code == 400 and "https://" in response.json()["detail"]
    ok = env["client"].put("/api/s3/config", json={"endpoint_url": "http://minio.lab:9000/", "path_style": True}).json()
    assert ok["endpoint_url"] == "http://minio.lab:9000" and ok["path_style"] is True


def test_connection_test_uses_unsaved_values_and_hides_s3_internals(env) -> None:
    _configure(env["client"])
    assert env["client"].post("/api/s3/test", json={"bucket": "evidence-bucket"}).json()["ok"] is True
    failed = env["client"].post("/api/s3/test", json={"bucket": "other"}).json()
    assert failed == {"ok": False, "error": "The bucket does not exist."}


def test_browsing_lists_folders_and_objects_of_one_level(env) -> None:
    _configure(env["client"])
    top = env["client"].get(f"/api/cases/{CASE_ID}/s3/objects").json()
    assert top["bucket"] == "evidence-bucket" and top["prefixes"] == ["cases/"] and top["objects"] == []
    folder = env["client"].get(f"/api/cases/{CASE_ID}/s3/objects", params={"prefix": "cases/001/"}).json()
    assert folder["prefixes"] == ["cases/001/notes/"]
    assert [(item["name"], item["size"]) for item in folder["objects"]] == [("collection.zip", len(PAYLOAD))]


def test_the_wizard_learns_whether_s3_is_usable_without_the_secrets(env, monkeypatch) -> None:
    assert env["client"].get(f"/api/cases/{CASE_ID}/s3/status").json() == {"enabled": True, "configured": False, "default_bucket": ""}
    _configure(env["client"])
    assert env["client"].get(f"/api/cases/{CASE_ID}/s3/status").json() == {"enabled": True, "configured": True, "default_bucket": "evidence-bucket"}
    monkeypatch.setattr(settings, "s3_source_enabled", False)
    assert env["client"].get(f"/api/cases/{CASE_ID}/s3/status").json() == {"enabled": False, "configured": False, "default_bucket": ""}


def test_everything_is_refused_while_the_feature_is_off(env, monkeypatch) -> None:
    _configure(env["client"])
    monkeypatch.setattr(settings, "s3_source_enabled", False)
    assert env["client"].get(f"/api/cases/{CASE_ID}/s3/objects").status_code == 403
    response = env["client"].post(f"/api/cases/{CASE_ID}/s3/import", json={"key": "cases/001/collection.zip"})
    assert response.status_code == 403 and "S3_SOURCE_ENABLED" in response.json()["detail"]
    assert env["queued"] == []


def test_import_creates_a_new_upload_session_for_the_object_and_queues_the_download(env) -> None:
    _configure(env["client"])
    response = env["client"].post(f"/api/cases/{CASE_ID}/s3/import", json={"key": "cases/001/collection.zip"})
    assert response.status_code == 200
    session_id = response.json()["session"]["id"]
    assert env["queued"] == [session_id]
    session = env["db"].get(EvidenceUploadSession, session_id)
    assert session.original_filename == "collection.zip" and session.expected_size_bytes == len(PAYLOAD)
    assert session.metadata_json["upload_mode"] == "s3"
    assert session.metadata_json["s3_source"] == {"bucket": "evidence-bucket", "key": "cases/001/collection.zip", "endpoint_url": None, "etag": "abc123", "version_id": None, "size": len(PAYLOAD)}
    # The browser cannot resume a server-side download.
    assert routes_evidence_preflight._resumable_entry(session, env["db"]).resumable is False
    # A second import of the same object is its own session, never the first one reused.
    again = env["client"].post(f"/api/cases/{CASE_ID}/s3/import", json={"key": "cases/001/collection.zip"}).json()["session"]["id"]
    assert again != session_id


def test_folders_and_missing_objects_are_refused(env) -> None:
    _configure(env["client"])
    assert env["client"].post(f"/api/cases/{CASE_ID}/s3/import", json={"key": "cases/002/"}).status_code == 400
    missing = env["client"].post(f"/api/cases/{CASE_ID}/s3/import", json={"key": "cases/none.zip"})
    assert missing.status_code == 400 and missing.json()["detail"] == "The bucket or object was not found."


def test_the_worker_downloads_the_exact_object_then_runs_the_normal_preflight(env, monkeypatch) -> None:
    _configure(env["client"])
    session_id = env["client"].post(f"/api/cases/{CASE_ID}/s3/import", json={"key": "cases/001/collection.zip"}).json()["session"]["id"]
    preflights: list[str] = []
    monkeypatch.setattr("app.workers.tasks.run_evidence_upload_preflight", lambda sid: preflights.append(sid) or {"status": "completed"})
    assert s3_source.run_import(session_id) == {"status": "completed"}
    assert preflights == [session_id]
    with env["make_session"]() as db:
        session = db.get(EvidenceUploadSession, session_id)
        assert Path(session.staged_path).read_bytes() == PAYLOAD
        assert session.bytes_received == len(PAYLOAD)
    get_call = next(kwargs for name, kwargs in env["fake"].calls if name == "get_object")
    assert get_call == {"Bucket": "evidence-bucket", "Key": "cases/001/collection.zip", "IfMatch": '"abc123"'}


def test_a_download_that_does_not_match_the_listed_size_fails_the_session(env, monkeypatch) -> None:
    _configure(env["client"])
    session_id = env["client"].post(f"/api/cases/{CASE_ID}/s3/import", json={"key": "cases/001/collection.zip"}).json()["session"]["id"]
    env["fake"].objects["cases/001/collection.zip"] = PAYLOAD[:100]
    monkeypatch.setattr("app.workers.tasks.run_evidence_upload_preflight", lambda sid: pytest.fail("no preflight for a broken download"))
    result = s3_source.run_import(session_id)
    assert result["status"] == "failed" and "stopped at 100" in result["error"]
    with env["make_session"]() as db:
        session = db.get(EvidenceUploadSession, session_id)
        assert session.status == "failed" and session.failure_message.startswith("S3 download failed")
        assert not Path(session.staged_path).exists()
