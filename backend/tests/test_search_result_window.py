"""Paging never offers a page that the OpenSearch result window would refuse."""
from __future__ import annotations

import pytest

from app.services.search_service import OPENSEARCH_RESULT_WINDOW_LIMIT, _next_page_reachable


@pytest.mark.parametrize(
    "offset, page_size, shown, total, expected",
    [
        (0, 50, 50, 120, True),
        (100, 50, 20, 120, False),                       # last page of a small result
        (9900, 50, 50, 187_845, True),                   # the page ending at 10,000 is still reachable
        (9950, 50, 50, 187_845, False),                  # the next one would start past the window
        (9800, 100, 100, 187_845, True),
        (9900, 100, 100, 187_845, False),
        (0, 50, 0, 0, False),
    ],
)
def test_next_page_is_offered_only_inside_the_window(offset, page_size, shown, total, expected):
    assert _next_page_reachable(offset, page_size, shown, total) is expected


def test_the_window_is_ten_thousand():
    assert OPENSEARCH_RESULT_WINDOW_LIMIT == 10_000


def test_a_linux_result_is_summarised_by_its_log_line_not_the_field_dump():
    from app.services.search_service import _format_event_result

    hit = {"_id": "1", "_source": {
        "@timestamp": "2019-10-05T11:20:59+00:00", "message": "btmp login failure user=root terminal=ssh:notty source=203.0.113.9",
        "raw_summary": "artifact_family=linux_auth | artifact_type=btmp | source_file=var/log/btmp",
        "event": {"type": "login_failure"}, "artifact": {"type": "linux_auth"}, "linux": {"artifact_family": "linux_auth"}, "host": {}, "user": {},
    }}
    assert _format_event_result(hit)["summary"].startswith("btmp login failure user=root")
