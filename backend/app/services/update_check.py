"""Tells administrators when the branch this instance follows has commits it does not run yet.

An instance is a git checkout that follows a branch (main by default) and is upgraded with
scripts/upgrade.sh, so "an update" is a commit on that branch newer than the one the images were
built from. The check asks GitHub's public compare API, at most once per interval, and only while
an administrator has the UI open; the result is kept in the database so every worker process and
restart shares it. Nothing about the instance is sent: the request carries the two commit ids and
a generic user agent. Labs without internet just keep the last result (or none); the failure is
reported only on the System page, never as an alert.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.app_settings import get_setting, set_setting
from app.core.config import get_settings
from app.core.instance_settings import effective_value

STATE_KEY = "UPDATE_CHECK_STATE"
# Written by backend/Dockerfile from the KAIRON_COMMIT build argument. Read before the environment
# variable because docker compose overrides that one with "unknown" when it is started without
# KAIRON_COMMIT exported (by hand, outside setup.sh), while the file always matches the image.
COMMIT_FILE = Path("/app/.kairon-commit")
FAILED_RETRY = timedelta(hours=1)
MAX_LISTED_COMMITS = 30
REQUEST_TIMEOUT_SECONDS = 8.0
_SHA = re.compile(r"^[0-9a-f]{7,40}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def running_commit() -> str | None:
    candidates = []
    try:
        candidates.append(COMMIT_FILE.read_text(encoding="utf-8").strip())
    except OSError:
        pass
    candidates.append(os.environ.get("KAIRON_COMMIT", "").strip())
    for value in candidates:
        if _SHA.match(value.lower()):
            return value.lower()
    return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _commit_summary(item: dict[str, Any]) -> dict[str, Any]:
    commit = item.get("commit") or {}
    message = str(commit.get("message") or "")
    return {
        "sha": str(item.get("sha") or "")[:12],
        "title": message.splitlines()[0] if message else "",
        "date": (commit.get("committer") or {}).get("date") or (commit.get("author") or {}).get("date"),
        "is_merge": len(item.get("parents") or []) > 1,
    }


def fetch_comparison(repository: str, branch: str, commit: str, client: httpx.Client | None = None) -> dict[str, Any]:
    """Compares the running commit with the branch head. Returns the state to store."""
    url = f"https://api.github.com/repos/{repository}/compare/{commit}...{branch}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "kairon-dfir-update-check"}
    own_client = client is None
    client = client or httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=True)
    try:
        response = client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        return {"state": "unreachable", "error": f"Could not reach GitHub ({type(exc).__name__})."}
    finally:
        if own_client:
            client.close()
    if response.status_code == 404:
        # The running commit is not on GitHub (local commits not pushed yet): nothing to compare.
        return {"state": "not_comparable", "error": f"Commit {commit[:12]} is not in {repository}."}
    if response.status_code != 200:
        return {"state": "unreachable", "error": f"GitHub answered {response.status_code}."}
    try:
        payload = response.json()
    except ValueError:
        return {"state": "unreachable", "error": "GitHub sent an unreadable answer."}
    status = str(payload.get("status") or "")
    ahead_by = int(payload.get("ahead_by") or 0)
    commits = [_commit_summary(item) for item in payload.get("commits") or [] if isinstance(item, dict)]
    head = commits[-1] if commits else None
    # The compare API lists the oldest commit first; the newest are the ones worth reading.
    listed = [item for item in reversed(commits) if not item["is_merge"]][:MAX_LISTED_COMMITS]
    return {
        "state": "update_available" if ahead_by > 0 else "up_to_date",
        "compare_status": status,
        "commits_behind": ahead_by,
        "commits_ahead": int(payload.get("behind_by") or 0),
        "latest_commit": head,
        "commits": listed,
        "compare_url": f"https://github.com/{repository}/compare/{commit[:12]}...{branch}",
    }


def _config(db: Session) -> dict[str, Any]:
    settings = get_settings()
    repository = str(settings.update_check_repository or "").strip()
    return {
        "enabled": bool(effective_value(db, "UPDATE_CHECK_ENABLED")),
        "repository": repository if _REPOSITORY.match(repository) else "",
        "branch": str(settings.update_check_branch or "main").strip() or "main",
        "interval": timedelta(hours=max(1, int(settings.update_check_interval_hours or 6))),
    }


def update_status(db: Session, *, force: bool = False, client: httpx.Client | None = None) -> dict[str, Any]:
    config = _config(db)
    commit = running_commit()
    base = {
        "enabled": config["enabled"],
        "repository": config["repository"],
        "branch": config["branch"],
        "running_commit": commit[:12] if commit else None,
        "interval_hours": int(config["interval"].total_seconds() // 3600),
    }
    if not config["enabled"]:
        return {**base, "state": "disabled"}
    if not config["repository"]:
        return {**base, "state": "not_configured"}
    if commit is None:
        # Built outside setup.sh/upgrade.sh, the images do not know their commit.
        return {**base, "state": "unknown_commit"}

    stored = get_setting(db, STATE_KEY, {}) or {}
    stored = stored if isinstance(stored, dict) else {}
    same_target = stored.get("for_commit") == commit and stored.get("repository") == config["repository"] and stored.get("branch") == config["branch"]
    checked_at = _parse_iso(stored.get("checked_at"))
    if same_target and checked_at and not force:
        wait = FAILED_RETRY if stored.get("state") == "unreachable" else config["interval"]
        if _now() - checked_at < wait:
            return {**base, **_public(stored)}

    result = fetch_comparison(config["repository"], config["branch"], commit, client=client)
    record = {**result, "for_commit": commit, "repository": config["repository"], "branch": config["branch"], "checked_at": _iso(_now())}
    if result["state"] == "unreachable" and same_target and stored.get("state") in {"update_available", "up_to_date"}:
        # Keep the last good answer; only note that the latest attempt failed.
        record = {**stored, "checked_at": record["checked_at"], "last_error": result["error"], "last_good_check_at": stored.get("last_good_check_at") or stored.get("checked_at")}
    elif result["state"] in {"update_available", "up_to_date"}:
        record["last_good_check_at"] = record["checked_at"]
    set_setting(db, STATE_KEY, record)
    return {**base, **_public(record)}


def _public(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key not in {"for_commit", "repository", "branch"}}
