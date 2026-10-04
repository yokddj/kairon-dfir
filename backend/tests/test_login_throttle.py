"""Sign-in throttling slows password guessing without ever refusing anyone else."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.api import routes_auth
from app.core.client_ip import client_ip
from app.core.database import get_db
from app.main import app
from app.services.auth_utils import hash_password

PASSWORD = "correct horse battery"
USERS = {name: SimpleNamespace(id=f"id-{name}", username=name, display_name=name, email=None, is_admin=False, is_active=True,
                               password_hash=hash_password(PASSWORD), last_login_at=None) for name in ("alice", "bob")}


class _Query:
    def __init__(self):
        self.name = None

    def filter(self, condition):
        self.name = condition.right.value
        return self

    def first(self):
        return USERS.get(self.name)

    def count(self):
        return len(USERS)


class _Db:
    def query(self, _model):
        return _Query()

    def add(self, _obj):
        pass

    def commit(self):
        pass


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    routes_auth._failed_logins.clear()
    monkeypatch.setattr(routes_auth, "log_audit", lambda *a, **k: None)
    app.dependency_overrides[get_db] = lambda: _Db()
    yield
    app.dependency_overrides.pop(get_db, None)
    routes_auth._failed_logins.clear()


# Requests arrive as they do through the bundled Nginx: from a private proxy address with X-Real-IP.
client = TestClient(app, client=("172.19.0.8", 50000))


def _login(username: str, password: str, ip: str = "192.0.2.10"):
    return client.post("/api/auth/login", json={"username": username, "password": password}, headers={"X-Real-IP": ip})


def _fail(times: int, username: str = "alice", ip: str = "192.0.2.10") -> None:
    for _ in range(times):
        assert _login(username, "wrong", ip).status_code == 401


def test_repeated_failures_on_one_account_from_one_address_are_slowed_down():
    _fail(routes_auth._LOGIN_FAILURE_LIMIT)
    refused = _login("alice", "wrong")
    assert refused.status_code == 429
    assert "Try again in" in refused.json()["detail"] and int(refused.headers["Retry-After"]) > 0


def test_the_account_owner_from_another_address_is_never_refused():
    _fail(routes_auth._LOGIN_FAILURE_LIMIT)
    assert _login("alice", PASSWORD, ip="192.0.2.20").status_code == 200


def test_other_users_from_the_same_address_are_never_refused():
    _fail(routes_auth._LOGIN_FAILURE_LIMIT, username="alice")
    assert _login("bob", PASSWORD).status_code == 200


def test_successful_sign_ins_never_count():
    for _ in range(routes_auth._LOGIN_FAILURE_LIMIT * 3):
        assert _login("alice", PASSWORD).status_code == 200


def test_a_success_clears_the_earlier_failures():
    _fail(routes_auth._LOGIN_FAILURE_LIMIT - 1)
    assert _login("alice", PASSWORD).status_code == 200
    _fail(routes_auth._LOGIN_FAILURE_LIMIT - 1)
    assert _login("alice", PASSWORD).status_code == 200


def test_the_username_is_matched_regardless_of_case_and_spaces():
    _fail(routes_auth._LOGIN_FAILURE_LIMIT, username="alice")
    assert _login(" ALICE ", "wrong").status_code == 429


def test_failures_expire_after_the_window(monkeypatch):
    _fail(routes_auth._LOGIN_FAILURE_LIMIT)
    later = routes_auth.time.time() + routes_auth._LOGIN_FAILURE_WINDOW + 1
    monkeypatch.setattr(routes_auth.time, "time", lambda: later)
    assert _login("alice", PASSWORD).status_code == 200


def test_the_tracked_pairs_are_bounded(monkeypatch):
    monkeypatch.setattr(routes_auth, "_MAX_TRACKED_PAIRS", 50)
    old = routes_auth.time.time() - routes_auth._LOGIN_FAILURE_WINDOW - 10
    for n in range(50):
        routes_auth._failed_logins[("198.51.100.1", f"user{n}")] = [old]
    _fail(1)
    assert len(routes_auth._failed_logins) == 1


def test_needs_setup_is_not_rate_limited():
    for _ in range(30):
        assert client.get("/api/auth/needs-setup").status_code == 200


def _request(peer: str, real_ip: str | None) -> Request:
    headers = [(b"x-real-ip", real_ip.encode())] if real_ip else []
    return Request({"type": "http", "client": (peer, 1234), "headers": headers})


@pytest.mark.parametrize(
    "peer, header, expected",
    [
        ("172.19.0.8", "192.0.2.50", "192.0.2.50"),     # through the bundled Nginx
        ("127.0.0.1", "192.0.2.50", "192.0.2.50"),      # a proxy on the same machine
        ("172.19.0.8", None, "172.19.0.8"),
        ("172.19.0.8", "not-an-ip", "172.19.0.8"),
        ("8.8.8.8", "192.0.2.50", "8.8.8.8"),           # a public peer cannot choose its address
    ],
)
def test_the_real_client_address(peer, header, expected):
    assert client_ip(_request(peer, header)) == expected
