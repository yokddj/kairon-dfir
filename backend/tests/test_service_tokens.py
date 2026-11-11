"""Service tokens: a read-only, every-case credential for non-interactive
clients (an MCP server, a script) that cannot carry a browser session
cookie. See app.services.service_tokens and the AuthMiddleware branch in
app.main that accepts Authorization: Bearer as an alternative to the cookie.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import get_db
from app.core import database as database_module
from app.core.database import Base
from app.main import app, settings
from app.models.case import Case
from app.models.service_token import ServiceToken
from app.models.user import User
from app.services import service_tokens
from app.services.auth_dependencies import ServiceTokenPrincipal, get_effective_case_role, require_admin
from app.services.auth_utils import hash_token


CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"


def _db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


# --- the service layer: create / authenticate / revoke ---------------------


def test_create_token_returns_the_plaintext_once_and_stores_only_its_hash():
    db = _db_session()

    row, plaintext = service_tokens.create_token(db, name="integration", created_by="admin-1")

    assert plaintext.startswith("kairon_svc_")
    assert row.token_hash == hash_token(plaintext)
    assert plaintext not in row.token_hash
    assert row.token_prefix in plaintext
    assert row.scope == service_tokens.READ_ONLY_ALL_CASES
    assert row.expires_at is None


def test_authenticate_accepts_a_valid_bearer_token():
    db = _db_session()
    _row, plaintext = service_tokens.create_token(db, name="integration", created_by=None)

    found = service_tokens.authenticate(db, f"Bearer {plaintext}")

    assert found is not None
    assert found.name == "integration"


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "not-bearer-at-all",
        "Bearer ",
        "Bearer wrong-token-value",
    ],
)
def test_authenticate_rejects_anything_that_is_not_a_known_token(header):
    db = _db_session()
    service_tokens.create_token(db, name="integration", created_by=None)

    assert service_tokens.authenticate(db, header) is None


def test_authenticate_rejects_a_revoked_token():
    db = _db_session()
    row, plaintext = service_tokens.create_token(db, name="integration", created_by=None)
    service_tokens.revoke_token(db, row.id)

    assert service_tokens.authenticate(db, f"Bearer {plaintext}") is None


def test_authenticate_rejects_an_expired_token():
    db = _db_session()
    row, plaintext = service_tokens.create_token(db, name="integration", created_by=None, expires_in_days=1)
    row.expires_at = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    db.commit()

    assert service_tokens.authenticate(db, f"Bearer {plaintext}") is None


def test_revoking_twice_is_a_no_op_not_an_error():
    db = _db_session()
    row, _plaintext = service_tokens.create_token(db, name="integration", created_by=None)

    first = service_tokens.revoke_token(db, row.id)
    second = service_tokens.revoke_token(db, row.id)

    assert first.revoked_at is not None
    assert second.revoked_at == first.revoked_at


def test_revoking_an_unknown_id_returns_none():
    db = _db_session()
    assert service_tokens.revoke_token(db, "does-not-exist") is None


def test_serialize_never_includes_the_hash_or_a_usable_token():
    db = _db_session()
    row, _plaintext = service_tokens.create_token(db, name="integration", created_by=None)

    payload = service_tokens.serialize(row)

    assert "token_hash" not in payload
    assert "token" not in payload
    assert payload["token_prefix"] == row.token_prefix


# --- the principal: every case, never admin ---------------------------------


def test_service_token_principal_is_never_admin():
    db = _db_session()
    row, _plaintext = service_tokens.create_token(db, name="integration", created_by=None)

    principal = ServiceTokenPrincipal(row)

    assert principal.is_admin is False


def test_service_token_principal_resolves_every_case_role_from_its_scope():
    db = _db_session()
    row, _plaintext = service_tokens.create_token(db, name="integration", created_by=None)
    principal = ServiceTokenPrincipal(row)

    role = get_effective_case_role(principal, "any-case-at-all", db)

    assert role == service_tokens.READ_ONLY_ALL_CASES


def test_a_human_user_without_a_grant_is_unaffected_by_the_service_token_branch():
    """The isinstance check must not accidentally widen a regular user's access."""
    db = _db_session()

    class FakeUser:
        is_admin = False
        id = "user-1"

    assert get_effective_case_role(FakeUser(), "some-case", db) is None


# --- end to end through the real middleware ---------------------------------


@pytest.fixture
def db_for_middleware(monkeypatch):
    db = _db_session()
    db.add(Case(id=CASE_ID, name="Case"))
    db.commit()
    Session = sessionmaker(bind=db.get_bind(), autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    monkeypatch.setattr(database_module, "SessionLocal", Session)
    monkeypatch.setattr(settings, "auth_enabled", True)
    yield db


def test_a_valid_service_token_reaches_a_case_scoped_endpoint(db_for_middleware):
    db = db_for_middleware
    _row, plaintext = service_tokens.create_token(db, name="integration", created_by=None)
    client = TestClient(app)

    response = client.get(f"/api/cases/{CASE_ID}", headers={"Authorization": f"Bearer {plaintext}"})

    assert response.status_code == 200


def test_an_invalid_service_token_is_rejected(db_for_middleware):
    client = TestClient(app)

    response = client.get(f"/api/cases/{CASE_ID}", headers={"Authorization": "Bearer not-a-real-token"})

    assert response.status_code == 401


def test_a_revoked_service_token_is_rejected(db_for_middleware):
    db = db_for_middleware
    row, plaintext = service_tokens.create_token(db, name="integration", created_by=None)
    service_tokens.revoke_token(db, row.id)
    client = TestClient(app)

    response = client.get(f"/api/cases/{CASE_ID}", headers={"Authorization": f"Bearer {plaintext}"})

    assert response.status_code == 401


def test_a_service_token_cannot_write(db_for_middleware):
    """Enforced centrally, not just by which tools call it: a raw POST with
    a valid token must still be refused."""
    db = db_for_middleware
    _row, plaintext = service_tokens.create_token(db, name="integration", created_by=None)
    client = TestClient(app)

    response = client.patch(
        f"/api/cases/{CASE_ID}",
        json={"name": "Renamed"},
        headers={"Authorization": f"Bearer {plaintext}", "Origin": "http://testserver"},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Service tokens are read-only"}


@pytest.mark.parametrize("path", ["/api/admin/performance", "/api/admin/performance/resources", "/api/system/settings", "/api/storage/allowed-roots"])
def test_a_service_token_cannot_read_the_administration_api(db_for_middleware, path):
    """Read-only is not enough: deployment tuning, performance and storage
    configuration are for administrators, not for an integration."""
    db = db_for_middleware
    _row, plaintext = service_tokens.create_token(db, name="integration", created_by=None)
    response = TestClient(app).get(path, headers={"Authorization": f"Bearer {plaintext}"})
    assert response.status_code == 403
    assert response.json() == {"detail": "Service tokens cannot use the administration API"}


def test_a_service_token_reaches_any_case_without_a_grant(db_for_middleware):
    """By design: see app.services.service_tokens for why this is not
    case-by-case the way human access is."""
    db = db_for_middleware
    other_case_id = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
    db.add(Case(id=other_case_id, name="Another case"))
    db.commit()
    _row, plaintext = service_tokens.create_token(db, name="integration", created_by=None)
    client = TestClient(app)

    response = client.get(f"/api/cases/{other_case_id}", headers={"Authorization": f"Bearer {plaintext}"})

    assert response.status_code == 200


def test_last_used_at_is_recorded_on_a_successful_request(db_for_middleware):
    db = db_for_middleware
    row, plaintext = service_tokens.create_token(db, name="integration", created_by=None)
    assert row.last_used_at is None
    client = TestClient(app)

    client.get(f"/api/cases/{CASE_ID}", headers={"Authorization": f"Bearer {plaintext}"})

    db.expire_all()
    refreshed = db.get(ServiceToken, row.id)
    assert refreshed.last_used_at is not None


# --- admin endpoints ---------------------------------------------------------


@pytest.fixture
def db_for_admin():
    db = _db_session()
    admin = User(username="admin", password_hash="x", is_admin=True, is_active=True)
    db.add(admin)
    db.commit()
    # These endpoints require an admin session, which this test is not
    # exercising -- see test_case_authorization.py and test_findings.py's
    # test_unauthenticated_user_cannot_access_findings for that. Overriding
    # the dependencies directly is the same pattern used throughout this
    # suite (e.g. test_case_management.py's _client) for routes reached via
    # app.main.app rather than a bare router.
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_admin] = lambda: admin
    try:
        yield db, admin
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(require_admin, None)


def test_admin_can_create_list_and_revoke_a_service_token(db_for_admin):
    db, _admin = db_for_admin
    client = TestClient(app)

    created = client.post("/api/admin/service-tokens", json={"name": "integration"})
    assert created.status_code == 201
    body = created.json()
    assert body["token"].startswith("kairon_svc_")
    token_id = body["id"]

    listed = client.get("/api/admin/service-tokens").json()
    assert any(item["id"] == token_id for item in listed)
    assert all("token" not in item for item in listed)

    revoked = client.delete(f"/api/admin/service-tokens/{token_id}")
    assert revoked.status_code == 200
    assert revoked.json()["revoked_at"] is not None


def test_creating_a_service_token_rejects_a_blank_name(db_for_admin):
    client = TestClient(app)

    response = client.post("/api/admin/service-tokens", json={"name": "   "})

    assert response.status_code == 400


def test_revoking_an_unknown_service_token_is_404(db_for_admin):
    client = TestClient(app)

    response = client.delete("/api/admin/service-tokens/does-not-exist")

    assert response.status_code == 404
