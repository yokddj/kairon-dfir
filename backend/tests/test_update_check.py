"""The update check compares the running commit with the followed branch, at most once per interval."""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.app_settings import get_setting
from app.core.config import get_settings
from app.core.database import Base
from app.services import update_check

RUNNING = "a" * 40
settings = get_settings()


def _commit(sha: str, title: str, parents: int = 1) -> dict:
    return {"sha": sha, "parents": [{}] * parents, "commit": {"message": f"{title}\n\nBody", "committer": {"date": "2026-11-27T10:00:00Z"}}}


@pytest.fixture()
def db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(update_check, "running_commit", lambda: RUNNING)
    monkeypatch.setattr(settings, "update_check_enabled", True)
    monkeypatch.setattr(settings, "update_check_repository", "example/kairon")
    monkeypatch.setattr(settings, "update_check_branch", "main")
    return sessionmaker(bind=engine, future=True)()


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_new_commits_on_the_branch_are_an_update(db) -> None:
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        commits = [_commit("1" * 40, "First change"), _commit("2" * 40, "Merge pull request #9", parents=2), _commit("3" * 40, "Second change")]
        return httpx.Response(200, json={"status": "ahead", "ahead_by": 3, "behind_by": 0, "commits": commits})

    status = update_check.update_status(db, client=_client(handler))
    assert seen == [f"https://api.github.com/repos/example/kairon/compare/{RUNNING}...main"]
    assert status["state"] == "update_available" and status["commits_behind"] == 3
    # Newest first, merge commits left out.
    assert [item["title"] for item in status["commits"]] == ["Second change", "First change"]
    assert status["running_commit"] == RUNNING[:12]


def test_the_result_is_reused_until_the_interval_passes(db, monkeypatch) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200, json={"status": "identical", "ahead_by": 0, "behind_by": 0, "commits": []})

    assert update_check.update_status(db, client=_client(handler))["state"] == "up_to_date"
    assert update_check.update_status(db, client=_client(handler))["state"] == "up_to_date"
    assert len(calls) == 1
    later = update_check._now() + timedelta(hours=7)
    monkeypatch.setattr(update_check, "_now", lambda: later)
    update_check.update_status(db, client=_client(handler))
    assert len(calls) == 2
    # Forced from the System page.
    update_check.update_status(db, force=True, client=_client(handler))
    assert len(calls) == 3


def test_no_network_keeps_the_last_good_answer(db) -> None:
    ok = _client(lambda request: httpx.Response(200, json={"status": "ahead", "ahead_by": 2, "behind_by": 0, "commits": [_commit("1" * 40, "Change")]}))
    update_check.update_status(db, client=ok)

    def offline(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    status = update_check.update_status(db, force=True, client=_client(offline))
    assert status["state"] == "update_available" and status["commits_behind"] == 2
    assert "Could not reach GitHub" in status["last_error"]


def test_no_network_without_a_previous_answer_is_unreachable(db) -> None:
    def offline(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    assert update_check.update_status(db, client=_client(offline))["state"] == "unreachable"


def test_a_commit_github_does_not_have_is_not_comparable(db) -> None:
    status = update_check.update_status(db, client=_client(lambda request: httpx.Response(404, json={})))
    assert status["state"] == "not_comparable"


def test_disabled_or_unknown_commit_asks_nothing(db, monkeypatch) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request expected")

    monkeypatch.setattr(settings, "update_check_enabled", False)
    assert update_check.update_status(db, client=_client(fail))["state"] == "disabled"
    monkeypatch.setattr(settings, "update_check_enabled", True)
    monkeypatch.setattr(update_check, "running_commit", lambda: None)
    assert update_check.update_status(db, client=_client(fail))["state"] == "unknown_commit"
    assert get_setting(db, update_check.STATE_KEY) is None


def test_the_running_commit_comes_from_the_image_file_first(tmp_path, monkeypatch) -> None:
    path = tmp_path / ".kairon-commit"
    monkeypatch.setattr(update_check, "COMMIT_FILE", path)
    monkeypatch.setenv("KAIRON_COMMIT", "unknown")
    assert update_check.running_commit() is None
    path.write_text("B" * 40 + "\n", encoding="utf-8")
    assert update_check.running_commit() == "b" * 40
    path.write_text("unknown\n", encoding="utf-8")
    monkeypatch.setenv("KAIRON_COMMIT", "c" * 40)
    assert update_check.running_commit() == "c" * 40
