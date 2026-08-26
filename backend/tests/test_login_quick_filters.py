from __future__ import annotations

from pathlib import Path

from app.services.search_service import (
    FAILED_LOGIN_EVENT_TYPES,
    LINUX_LOGIN_EVENT_TYPES,
    LOGIN_EVENT_TYPES,
    PRIVILEGED_LOGON_EVENT_TYPES,
    WINDOWS_LOGIN_EVENT_TYPES,
    quick_filters,
)

NORMALIZERS = Path(__file__).resolve().parents[1] / "app" / "ingest" / "artifact_normalizers.py"


def test_login_quick_filters_are_offered() -> None:
    ids = {item["id"] for item in quick_filters()}
    assert {"logins", "failed_logins", "privileged_logons"} <= ids


def test_login_filters_cover_both_windows_and_linux() -> None:
    """A Logins filter that only understood Windows would return nothing on a
    Linux case, which an analyst reads as "nobody logged in" rather than "this
    filter does not cover this platform"."""
    assert set(WINDOWS_LOGIN_EVENT_TYPES) <= set(LOGIN_EVENT_TYPES)
    assert set(LINUX_LOGIN_EVENT_TYPES) <= set(LOGIN_EVENT_TYPES)
    # every filter must have at least one event type from each platform
    for values in (LOGIN_EVENT_TYPES, FAILED_LOGIN_EVENT_TYPES, PRIVILEGED_LOGON_EVENT_TYPES):
        assert set(values) & set(WINDOWS_LOGIN_EVENT_TYPES + ["special_privileges_assigned"]), values
        assert set(values) & set(LINUX_LOGIN_EVENT_TYPES + ["privilege_authentication"]), values


def test_linux_event_types_still_match_the_normalizer() -> None:
    """The Linux values are produced by artifact_normalizers' linux_auth branch.

    Pinned against that source so renaming an auth_event_type there fails here
    instead of silently emptying the filter on every Linux case.
    """
    source = NORMALIZERS.read_text(encoding="utf-8")
    for event_type in LINUX_LOGIN_EVENT_TYPES + ["privilege_authentication"]:
        assert f'"{event_type}"' in source, f"{event_type} no longer produced by the Linux normalizer"


def test_failed_logins_include_the_inconsistently_typed_4625() -> None:
    """Some 4625 records normalize to "event_id_4625" instead of "logon_failed".
    Verified on a real case: including it is the difference between 11 failed
    logons and 10, and the missing one is invisible either way."""
    assert "logon_failed" in FAILED_LOGIN_EVENT_TYPES
    assert "event_id_4625" in FAILED_LOGIN_EVENT_TYPES
