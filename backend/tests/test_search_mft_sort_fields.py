"""MFT rows only ever exposed one derived @timestamp for sorting, even
though normalize_mft_row (app/ingest/artifact_normalizers.py) already
records all four NTFS MACB timestamps on both $STANDARD_INFORMATION and
$FILE_NAME as separate fields (mft.si_created/si_modified/si_accessed/
si_changed, mft.fn_created/fn_modified/fn_accessed/fn_changed). This
verifies each is now a valid, accepted sort field."""

from __future__ import annotations

import pytest

from app.api.routes_search import SORT_FIELD_MAP, build_search_query
from app.schemas.event import SearchRequest

MFT_SORT_FIELDS = [
    "mft.si_created",
    "mft.si_modified",
    "mft.si_accessed",
    "mft.si_changed",
    "mft.fn_created",
    "mft.fn_modified",
    "mft.fn_accessed",
    "mft.fn_changed",
]


@pytest.mark.parametrize("field", MFT_SORT_FIELDS)
def test_mft_macb_field_is_in_the_sort_field_map(field):
    assert SORT_FIELD_MAP.get(field) == field


@pytest.mark.parametrize("field", MFT_SORT_FIELDS)
def test_build_search_query_accepts_each_mft_macb_sort_field(field):
    payload = SearchRequest(case_id="case-1", sort_by=field, sort_order="asc")

    query = build_search_query(payload)

    assert query["sort"] == [{field: {"order": "asc", "missing": "_last"}}]
