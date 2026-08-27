from __future__ import annotations

from app.rules_engine.sigma import (
    SIGMA_FIELD_MAP,
    analyze_sigma_engine_compatibility,
    _detect_unmapped_fields,
)


def _rule(detection: dict) -> dict:
    return {"title": "t", "logsource": {"product": "windows"}, "detection": detection}


def test_a_rule_using_only_mapped_fields_is_executable() -> None:
    result = analyze_sigma_engine_compatibility(
        _rule({"sel": {"EventID": 4688, "CommandLine|contains": "whoami"}, "condition": "sel"})
    )
    assert result["executable_by_current_engine"] is True
    assert result["unmapped_fields"] == []


def test_an_unmapped_field_makes_the_rule_non_executable() -> None:
    """A rule that can never fire must say so rather than sit there looking armed.

    An unmapped Sigma field fell through to the raw name and was queried as if
    it were a document key. Kairon's schema has no such key, so the rule matched
    nothing and reported no problem -- and nobody goes looking for a detection
    rule that is silently never firing.
    """
    result = analyze_sigma_engine_compatibility(
        _rule({"sel": {"EventID": 7045, "ServiceFileName|contains": "evil"}, "condition": "sel"})
    )
    assert result["executable_by_current_engine"] is False
    assert result["engine_status"] == "unmapped_field"
    assert result["unmapped_fields"] == ["ServiceFileName"]
    assert "unmapped_field:ServiceFileName" in result["unsupported_features"]


def test_the_offending_field_is_named_so_it_can_be_mapped_later() -> None:
    result = analyze_sigma_engine_compatibility(
        _rule({"sel": {"LogonType": 3, "SomethingElse": "x"}, "condition": "sel"})
    )
    assert result["unmapped_fields"] == ["LogonType", "SomethingElse"]
    assert "LogonType" in result["engine_reason"]


def test_fields_that_fall_back_to_search_text_are_not_treated_as_unmapped() -> None:
    result = analyze_sigma_engine_compatibility(
        _rule({"sel": {"ScriptBlockText|contains": "Invoke-Mimikatz"}, "condition": "sel"})
    )
    assert result["unmapped_fields"] == []
    assert result["executable_by_current_engine"] is True


def test_a_field_mapped_only_onto_event_data_cannot_be_queried() -> None:
    """windows.event_data is indexed with "enabled": false, so a mapping that
    points only there looks correct and can never match."""
    assert _detect_unmapped_fields(_rule({"sel": {"OnlyEventData": "x"}, "condition": "sel"})) == ["OnlyEventData"]

    original = dict(SIGMA_FIELD_MAP)
    try:
        SIGMA_FIELD_MAP["OnlyEventData"] = ["windows.event_data.OnlyEventData"]
        assert _detect_unmapped_fields(_rule({"sel": {"OnlyEventData": "x"}, "condition": "sel"})) == ["OnlyEventData"]
    finally:
        SIGMA_FIELD_MAP.clear()
        SIGMA_FIELD_MAP.update(original)


def test_a_mapping_with_one_real_target_stays_executable() -> None:
    result = analyze_sigma_engine_compatibility(
        _rule({"sel": {"TargetFilename|endswith": ".exe"}, "condition": "sel"})
    )
    assert result["unmapped_fields"] == []
