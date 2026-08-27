from __future__ import annotations

from app.rules_engine.sigma import analyze_sigma_engine_compatibility


def _rule(detection: dict) -> dict:
    return {"title": "t", "logsource": {"service": "apache"}, "detection": detection}


def test_a_keyword_only_rule_is_refused() -> None:
    """A detection of bare keywords names no field, so it compiles to a query
    with no clauses -- and a query with no clauses matches every document.

    Four such rules each hit their 1000-detection cap on a case that had nothing
    to do with Apache, Nginx or Exchange: 4000 findings that looked like the
    rules were working. Free-text matching is a real Sigma feature worth
    supporting one day; until then refusing is the only honest option.
    """
    result = analyze_sigma_engine_compatibility(
        _rule({"keywords": ["exit signal Segmentation Fault"], "condition": "keywords"})
    )

    assert result["executable_by_current_engine"] is False
    assert result["engine_status"] == "keyword_only_detection"
    assert "keyword_only_detection" in result["unsupported_features"]


def test_a_bare_list_selection_is_refused_too() -> None:
    """"selection: [Install-TransportAgent]" is the same shape without the name."""
    result = analyze_sigma_engine_compatibility(_rule({"selection": ["Install-TransportAgent"], "condition": "selection"}))

    assert result["executable_by_current_engine"] is False
    assert result["engine_status"] == "keyword_only_detection"


def test_a_rule_naming_a_field_is_unaffected() -> None:
    result = analyze_sigma_engine_compatibility(
        {"title": "t", "logsource": {"product": "windows"}, "detection": {"sel": {"EventID": 7045}, "condition": "sel"}}
    )

    assert result["executable_by_current_engine"] is True


def test_an_empty_detection_is_not_reported_as_keyword_only() -> None:
    """That has its own existing reason and should keep it."""
    result = analyze_sigma_engine_compatibility({"title": "t", "logsource": {}, "detection": {}})

    assert result["engine_status"] != "keyword_only_detection"
