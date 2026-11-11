"""Evidence imported from Azure Blob Storage (app.services.azure_blob_source, app.api.routes_azure_blob).

No request ever reaches Azure: the BlobServiceClient is replaced by a fake that answers like the
SDK (walk_blobs pages, blob properties, a chunked downloader, SDK exceptions with error codes)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from azure.core.exceptions import ClientAuthenticationError, ResourceModifiedError, ResourceNotFoundError
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_azure_blob, routes_evidence_preflight
from app.core.app_settings import get_setting
from app.core.config import get_settings
from app.core.database import Base, get_db
from app.models.case import Case
from app.models.evidence_upload_session import EvidenceUploadSession
from app.services import azure_blob_source

settings = get_settings()
CASE_ID = "cccccccc-3333-4333-8333-cccccccccccc"
PAYLOAD = b"PK\x03\x04" + b"evidence" * 4096
ACCOUNT_URL = "https://irstorage.blob.core.windows.net"


def _sdk_error(cls, code: str):
    error = cls(message=f"{code}: secret-internal-detail")
    error.error_code = code
    return error


class FakeBlobService:
    """The calls azure_blob_source makes, over one in-memory container."""

    def __init__(self) -> None:
        self.blobs = {
            "cases/001/collection.zip": (PAYLOAD, "Hot"),
            "cases/001/notes/readme.txt": (b"x", "Hot"),
            "cases/001/cold.vhd": (b"disk", "Archive"),
        }
        self.calls: list[tuple[str, dict]] = []
        self.etag = '"0x8DC1"'

    def _check(self, container: str) -> None:
        if container != "evidence":
            raise _sdk_error(ResourceNotFoundError, "ContainerNotFound")

    def list_containers(self, **kwargs):
        return SimpleNamespace(by_page=lambda: iter([[SimpleNamespace(name="evidence")]]))

    def get_container_client(self, container):
        service = self

        class Container:
            def get_container_properties(self):  # noqa: F811 -- must not be needed
                raise AssertionError("the connection test must not need Get Container Properties")

            def walk_blobs(self, name_starts_with=None, delimiter="/", results_per_page=None):
                service.calls.append(("walk_blobs", {"container": container, "prefix": name_starts_with}))
                service._check(container)
                prefix = name_starts_with or ""
                items, prefixes = [], set()
                for name, (data, tier) in sorted(service.blobs.items()):
                    if not name.startswith(prefix):
                        continue
                    rest = name[len(prefix):]
                    if "/" in rest:
                        prefixes.add(prefix + rest.split("/", 1)[0] + "/")
                        continue
                    items.append(SimpleNamespace(name=name, size=len(data), last_modified=datetime(2026, 11, 1, tzinfo=timezone.utc), blob_tier=tier, blob_type="BlockBlob"))
                listing = [SimpleNamespace(name=item) for item in sorted(prefixes)] + items

                class Paged:
                    def by_page(self, continuation_token=None):
                        service.calls.append(("by_page", {"token": continuation_token}))
                        pages = iter([listing])

                        class P:
                            continuation_token = "next-page-token"

                            def __next__(self_inner):
                                return next(pages)

                            def __iter__(self_inner):
                                return self_inner

                        return P()

                return Paged()

            def get_blob_client(self, blob, version_id=None):
                return service._blob(container, blob, version_id)

        return Container()

    def get_blob_client(self, container, blob):
        return self._blob(container, blob, None)

    def _blob(self, container, blob, version_id):
        service = self

        class Blob:
            def get_blob_properties(self):
                service.calls.append(("get_blob_properties", {"container": container, "blob": blob}))
                service._check(container)
                if blob not in service.blobs:
                    raise _sdk_error(ResourceNotFoundError, "BlobNotFound")
                data, tier = service.blobs[blob]
                return SimpleNamespace(size=len(data), etag=service.etag, version_id=None, blob_tier=tier, blob_type="BlockBlob")

            def download_blob(self, **kwargs):
                service.calls.append(("download_blob", {"blob": blob, "version_id": version_id, **{k: str(v) for k, v in kwargs.items()}}))
                if kwargs.get("etag") and kwargs["etag"] != service.etag:
                    raise ResourceModifiedError(message="ConditionNotMet")
                data = service.blobs[blob][0]
                return SimpleNamespace(chunks=lambda: iter([data[i:i + 4096] for i in range(0, len(data), 4096)]))

        return Blob()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    make_session = sessionmaker(bind=engine, future=True)
    db = make_session()
    db.add(Case(id=CASE_ID, name="Azure Case", description="", status="active", priority="medium", management_tags=[]))
    db.commit()
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    monkeypatch.setattr(settings, "backend_max_upload_size", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "auth_enabled", False)
    monkeypatch.setattr(settings, "azure_blob_source_enabled", True)
    monkeypatch.setattr(settings, "session_secret_key", "test-session-secret")
    monkeypatch.setattr(settings, "ai_secret_key", "")
    fake = FakeBlobService()
    built: list[dict] = []

    def build(config):
        if not azure_blob_source.is_configured(config):
            raise azure_blob_source.AzureBlobSourceError("not configured")
        built.append(config)
        return fake

    monkeypatch.setattr(azure_blob_source, "build_service_client", build)
    queued: list[str] = []
    monkeypatch.setattr("app.workers.tasks.enqueue_azure_blob_import", lambda session_id: queued.append(session_id) or "job-1")
    monkeypatch.setattr("app.services.audit.log_audit", lambda *a, **k: None)
    monkeypatch.setattr(routes_azure_blob, "log_audit", lambda *a, **k: None)
    monkeypatch.setattr("app.core.database.SessionLocal", make_session)
    app = FastAPI()
    app.include_router(routes_azure_blob.router)
    app.include_router(routes_evidence_preflight.router)
    app.dependency_overrides[get_db] = lambda: db
    return {"db": db, "client": TestClient(app), "fake": fake, "queued": queued, "make_session": make_session, "built": built}


def _configure(client: TestClient, **overrides) -> dict:
    body = {"account_url": ACCOUNT_URL, "auth_method": "account_key", "secret": "account-key-value-1234==", "default_container": "evidence", **overrides}
    response = client.put("/api/azure-blob/config", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_the_secret_is_sealed_and_never_returned(env) -> None:
    public = _configure(env["client"])
    assert public["has_secret"] is True and public["configured"] is True
    assert "account-key-value-1234" not in str(public) and public["secret_masked"]
    stored = get_setting(env["db"], azure_blob_source.AZURE_BLOB_SETTING_KEY, {})
    assert "account-key-value-1234" not in str(stored)
    assert env["client"].get("/api/azure-blob/config").json()["has_secret"] is True


def test_the_account_name_comes_from_the_url_or_an_emulator_path() -> None:
    assert azure_blob_source.derived_account_name({"account_url": ACCOUNT_URL}) == "irstorage"
    assert azure_blob_source.derived_account_name({"account_url": "http://azurite:10000/devstoreaccount1"}) == "devstoreaccount1"
    assert azure_blob_source.derived_account_name({"account_url": ACCOUNT_URL, "account_name": "other"}) == "other"


def test_switching_the_auth_method_drops_the_other_kind_of_secret(env) -> None:
    _configure(env["client"])
    public = env["client"].put("/api/azure-blob/config", json={"auth_method": "sas_token"}).json()
    assert public["has_secret"] is False and public["configured"] is False
    public = env["client"].put("/api/azure-blob/config", json={"secret": "?sv=2024-11-04&sp=rl&sig=abc"}).json()
    assert public["configured"] is True
    # The leading "?" a portal-copied SAS carries is not part of the token.
    config = azure_blob_source.load_config(env["db"])
    from app.services.ai.crypto import open_sealed

    assert open_sealed(config["secret"], info=azure_blob_source._CREDENTIAL_INFO).startswith("sv=")


def test_a_service_principal_needs_tenant_and_client(env) -> None:
    public = _configure(env["client"], auth_method="service_principal", secret="client-secret-value")
    assert public["configured"] is False
    public = env["client"].put("/api/azure-blob/config", json={"tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-2222-3333-4444-555555555555"}).json()
    assert public["configured"] is True


def test_the_account_url_must_be_a_url(env) -> None:
    response = env["client"].put("/api/azure-blob/config", json={"account_url": "irstorage.blob.core.windows.net"})
    assert response.status_code == 400 and "https://" in response.json()["detail"]


def test_connection_test_hides_sdk_internals(env) -> None:
    _configure(env["client"])
    assert env["client"].post("/api/azure-blob/test", json={}).json()["ok"] is True
    missing = env["client"].post("/api/azure-blob/test", json={"container": "nope"}).json()
    assert missing == {"ok": False, "error": "The container does not exist."}


def test_browsing_lists_folders_and_blobs_of_one_level(env) -> None:
    _configure(env["client"])
    root = env["client"].get(f"/api/cases/{CASE_ID}/azure-blob/objects").json()
    assert root["container"] == "evidence" and root["prefixes"] == ["cases/"] and root["objects"] == []
    level = env["client"].get(f"/api/cases/{CASE_ID}/azure-blob/objects", params={"prefix": "cases/001/"}).json()
    assert level["prefixes"] == ["cases/001/notes/"]
    by_name = {item["name"]: item for item in level["objects"]}
    assert by_name["collection.zip"]["size"] == len(PAYLOAD) and by_name["collection.zip"]["archived"] is False
    assert by_name["cold.vhd"]["archived"] is True
    assert level["next_token"] == "next-page-token"


def test_the_wizard_learns_whether_azure_is_usable_without_the_secrets(env, monkeypatch) -> None:
    _configure(env["client"])
    status = env["client"].get(f"/api/cases/{CASE_ID}/azure-blob/status").json()
    assert status == {"enabled": True, "configured": True, "default_container": "evidence", "account_name": "irstorage"}
    monkeypatch.setattr(settings, "azure_blob_source_enabled", False)
    assert env["client"].get(f"/api/cases/{CASE_ID}/azure-blob/status").json()["configured"] is False


def test_everything_is_refused_while_the_feature_is_off(env, monkeypatch) -> None:
    _configure(env["client"])
    monkeypatch.setattr(settings, "azure_blob_source_enabled", False)
    assert env["client"].get(f"/api/cases/{CASE_ID}/azure-blob/objects").status_code == 403
    assert env["client"].post(f"/api/cases/{CASE_ID}/azure-blob/import", json={"blob": "cases/001/collection.zip"}).status_code == 403


def test_import_creates_a_new_upload_session_and_queues_the_download(env) -> None:
    _configure(env["client"])
    response = env["client"].post(f"/api/cases/{CASE_ID}/azure-blob/import", json={"blob": "cases/001/collection.zip", "declared_platform": "windows"})
    assert response.status_code == 200, response.text
    session = response.json()["session"]
    assert session["original_filename"] == "collection.zip" and session["expected_size_bytes"] == len(PAYLOAD)
    assert env["queued"] == [session["id"]]
    stored = env["db"].get(EvidenceUploadSession, session["id"]).metadata_json
    assert stored["upload_mode"] == "azure_blob"
    assert stored["azure_blob_source"]["etag"] == "0x8DC1" and stored["azure_blob_source"]["container"] == "evidence"
    # A second import of the same blob is a new session, never a resume of the first.
    again = env["client"].post(f"/api/cases/{CASE_ID}/azure-blob/import", json={"blob": "cases/001/collection.zip"}).json()["session"]
    assert again["id"] != session["id"]


def test_archived_folders_and_missing_blobs_are_refused(env) -> None:
    _configure(env["client"])
    archived = env["client"].post(f"/api/cases/{CASE_ID}/azure-blob/import", json={"blob": "cases/001/cold.vhd"})
    assert archived.status_code == 400 and "Archive tier" in archived.json()["detail"]
    folder = env["client"].post(f"/api/cases/{CASE_ID}/azure-blob/import", json={"blob": "cases/001/"})
    assert folder.status_code == 400
    missing = env["client"].post(f"/api/cases/{CASE_ID}/azure-blob/import", json={"blob": "cases/none.zip"})
    assert missing.status_code == 400 and missing.json()["detail"] == "The blob no longer exists in the container."


def test_the_worker_downloads_the_exact_blob_then_runs_the_normal_preflight(env, monkeypatch) -> None:
    _configure(env["client"])
    session_id = env["client"].post(f"/api/cases/{CASE_ID}/azure-blob/import", json={"blob": "cases/001/collection.zip"}).json()["session"]["id"]
    preflights: list[str] = []
    monkeypatch.setattr("app.workers.tasks.run_evidence_upload_preflight", lambda sid: preflights.append(sid) or {"status": "completed"})
    assert azure_blob_source.run_import(session_id) == {"status": "completed"}
    assert preflights == [session_id]
    with env["make_session"]() as db:
        session = db.get(EvidenceUploadSession, session_id)
        assert Path(session.staged_path).read_bytes() == PAYLOAD
        assert session.bytes_received == len(PAYLOAD)
    download = next(kwargs for name, kwargs in env["fake"].calls if name == "download_blob")
    assert download["etag"] == '"0x8DC1"' and "IfNotModified" in download["match_condition"]


def test_a_blob_changed_after_it_was_picked_fails_the_session(env, monkeypatch) -> None:
    _configure(env["client"])
    session_id = env["client"].post(f"/api/cases/{CASE_ID}/azure-blob/import", json={"blob": "cases/001/collection.zip"}).json()["session"]["id"]
    env["fake"].etag = '"0x8DC2"'  # overwritten in Azure meanwhile
    monkeypatch.setattr("app.workers.tasks.run_evidence_upload_preflight", lambda sid: pytest.fail("no preflight for a changed blob"))
    result = azure_blob_source.run_import(session_id)
    assert result["status"] == "failed" and "changed after it was picked" in result["error"]
    with env["make_session"]() as db:
        session = db.get(EvidenceUploadSession, session_id)
        assert session.status == "failed" and session.failure_message.startswith("Azure Blob download failed")
        assert not Path(session.staged_path).exists()


def test_sdk_errors_become_safe_messages() -> None:
    assert "permission" in str(azure_blob_source._client_error(_sdk_error(ClientAuthenticationError, "AuthorizationPermissionMismatch")))
    assert "expired" in str(azure_blob_source._client_error(_sdk_error(ClientAuthenticationError, "AuthenticationFailed")))
    message = str(azure_blob_source._client_error(ClientAuthenticationError(message="AADSTS7000215: Invalid client secret secret-internal-detail")))
    assert "Entra ID" in message and "secret-internal-detail" not in message
