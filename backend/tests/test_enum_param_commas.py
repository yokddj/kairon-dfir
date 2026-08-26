from __future__ import annotations

from app.services.search_service import build_search_v2_params


def test_comma_joined_enum_params_are_split() -> None:
    """The UI writes multi-value filters comma-joined into the URL, but the API
    only accepted repeated params: replaying that same query string matched a
    literal "a,b,c" and returned zero results with no warning."""
    params = build_search_v2_params(event_type="logon_success,logon_failed,invalid_user")
    assert params["event_type"] == ["logon_success", "logon_failed", "invalid_user"]


def test_repeated_params_still_work() -> None:
    params = build_search_v2_params(event_type=["logon_success", "logon_failed"])
    assert params["event_type"] == ["logon_success", "logon_failed"]


def test_mixed_and_padded_values_are_normalised() -> None:
    params = build_search_v2_params(artifact_type=["mft, prefetch", " lnk "])
    assert params["artifact_type"] == ["mft", "prefetch", "lnk"]


def test_free_text_params_are_never_split_on_commas() -> None:
    """A comma is a legitimate character in a path or a query, so splitting
    those would corrupt the search instead of fixing it."""
    params = build_search_v2_params(q="dir a,b", file_path=["C:\\tmp\\a,b.txt"], host="HOST,1")
    assert params["q"] == "dir a,b"
    assert params["file_path"] == ["C:\\tmp\\a,b.txt"]
    assert params["host"] == "HOST,1"


def test_empty_and_none_stay_empty() -> None:
    assert build_search_v2_params(event_type=None)["event_type"] == []
    assert build_search_v2_params(event_type="")["event_type"] == []
    assert build_search_v2_params(event_type=",,")["event_type"] == []
