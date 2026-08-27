from __future__ import annotations

import json
from typing import Any

from app.services.search_service import _build_text_query


def test_a_single_stem_still_falls_back_to_substring_matching() -> None:
    """The analyzer keeps "comsvcs.dll" as one token, so the bare stem only
    reaches it through the wildcard subfield."""
    body = json.dumps(_build_text_query("comsvcs"))

    assert "search_text.wildcard" in body
    assert "simple_query_string" in body


def test_two_terms_where_one_is_a_substring_are_not_dropped() -> None:
    """simple_query_string ANDs its terms, and the substring fallback only ever
    covered one word -- so "rundll32 comsvcs" matched nothing at all even with
    both strings present in the index."""
    query = _build_text_query("rundll32 comsvcs")
    body = json.dumps(query)

    assert body.count("search_text.wildcard") >= 2, "each term needs its own substring clause"
    # Every term must match: two terms are a conjunction, not an either/or.
    inner = [clause for clause in query["bool"]["should"] if "bool" in clause and "must" in clause["bool"]]
    assert len(inner) == 1
    assert len(inner[0]["bool"]["must"]) == 2


def test_terms_carrying_query_syntax_are_left_to_the_parser() -> None:
    """A wildcard expansion of an unescaped metacharacter is not safe."""
    query = _build_text_query('comsvcs OR "something else"')

    assert "simple_query_string" in json.dumps(query)
    assert query.get("simple_query_string") is not None


def test_a_term_shorter_than_three_characters_is_not_expanded() -> None:
    """A two-character substring scan matches most of the index."""
    query = _build_text_query("ab cd")

    assert query.get("simple_query_string") is not None
