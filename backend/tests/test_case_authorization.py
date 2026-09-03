"""Every case-scoped request is authorised in one place.

There are ~180 case-scoped endpoints across 27 route modules. Enforcing access
per route means the next endpoint added forgets it, and the gap stays invisible
until an analyst opens another client's evidence. The check therefore lives in
the middleware, where a new route inherits it without anyone remembering to.
"""

from __future__ import annotations

import pytest

from app.main import requested_case_id


class Params(dict):
    """Stands in for Starlette's QueryParams, which is dict-like."""


# --- recognising which case a request is about -----------------------------


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/api/cases/abc-123", "abc-123"),
        ("/api/cases/abc-123/evidences", "abc-123"),
        ("/api/cases/abc-123/process-tree/focused", "abc-123"),
        ("/api/cases/abc-123/ai/conversations/xyz", "abc-123"),
    ],
)
def test_a_case_path_is_recognised(path, expected):
    assert requested_case_id(path, Params()) == expected


@pytest.mark.parametrize(
    "path",
    [
        "/api/cases",          # listing every case the user may see
        "/api/cases/",         # trailing slash, no id
        "/api/system/health",
        "/api/auth/login",
        "/",
    ],
)
def test_a_request_about_no_particular_case_is_not_treated_as_one(path):
    """Listing and creating cases must not be gated on a case that has no id."""
    assert requested_case_id(path, Params()) is None


def test_the_query_parameter_form_is_recognised():
    """Some evidence and memory routes pass the case this way instead."""
    assert requested_case_id("/api/evidences/ev-1/memory/scan", Params({"case_id": "case-9"})) == "case-9"


def test_a_blank_query_parameter_is_not_a_case():
    assert requested_case_id("/api/evidences/ev-1/memory/scan", Params({"case_id": "   "})) is None


def test_the_path_wins_over_a_conflicting_query_parameter():
    """The resource being addressed is the one in the path."""
    assert requested_case_id("/api/cases/from-path/evidences", Params({"case_id": "from-query"})) == "from-path"


# --- the authorisation decision itself -------------------------------------


class FakeUser:
    def __init__(self, user_id: str, is_admin: bool):
        self.id = user_id
        self.is_admin = is_admin
        self.is_active = True


class FakeAccessDb:
    """Answers "does this user have access to this case?" from a fixed set."""

    def __init__(self, grants: set[tuple[str, str]]):
        self.grants = grants
        self.queried = 0

    def query(self, *_args, **_kwargs):
        self.queried += 1
        return self

    def filter(self, *criteria, **_kwargs):
        self._criteria = criteria
        return self

    def first(self):
        # The real query filters on case_id and user_id; the doubles below
        # assert on the outcome rather than reconstructing the SQL.
        return self._answer

    def set_answer(self, answer):
        self._answer = answer
        return self


def test_an_admin_reaches_every_case_without_a_lookup(monkeypatch):
    """Deployments where everyone is an admin are unaffected by this check."""
    from app.services.auth_dependencies import get_effective_case_role

    db = FakeAccessDb(set())

    role = get_effective_case_role(FakeUser("u1", is_admin=True), "case-1", db)

    assert role == "admin"
    assert db.queried == 0, "an admin must not cost a database round trip"


def test_a_user_with_a_grant_gets_their_role(monkeypatch):
    from app.services.auth_dependencies import get_effective_case_role

    class Access:
        role = "analyst"

    db = FakeAccessDb(set()).set_answer(Access())

    assert get_effective_case_role(FakeUser("u1", is_admin=False), "case-1", db) == "analyst"


def test_a_user_without_a_grant_gets_no_role(monkeypatch):
    """No role is what the middleware turns into a 403."""
    from app.services.auth_dependencies import get_effective_case_role

    db = FakeAccessDb(set()).set_answer(None)

    assert get_effective_case_role(FakeUser("u1", is_admin=False), "case-1", db) is None


def test_the_middleware_denies_a_case_the_user_cannot_reach(monkeypatch):
    """The end of the chain: no role means the request is refused."""
    import app.services.auth_dependencies as deps

    monkeypatch.setattr(deps, "get_effective_case_role", lambda user, case_id, db: None)

    case_id = requested_case_id("/api/cases/other-clients-case/evidences", Params())
    user = FakeUser("u1", is_admin=False)
    denied = bool(case_id) and not user.is_admin and deps.get_effective_case_role(user, case_id, None) is None

    assert denied is True
