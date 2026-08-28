from __future__ import annotations

from app.rules_engine.sigma import (
    analyze_sigma_engine_compatibility,
    apply_value_transforms,
    evaluate_sigma_rule,
    expand_windash_values,
    parse_field_modifiers,
)


def _rule(field: str, value: object) -> dict:
    return {"title": "t", "logsource": {"product": "windows"}, "detection": {"sel": {field: value}, "condition": "sel"}}


def _document(command_line: str) -> dict:
    return {"process": {"command_line": command_line}}


class TestParseFieldModifiers:
    def test_a_chain_separates_the_comparison_from_the_transform(self) -> None:
        """The pieces do different jobs: one decides how to compare, the rest
        rewrite the value. Reading only a trailing suffix conflated them, so a
        rule using windash was reported as using an unsupported modifier and
        never ran -- 76 rules of a real SigmaHQ pack."""
        assert parse_field_modifiers("CommandLine|contains|windash") == ("CommandLine", "contains", {"windash"})

    def test_a_bare_field_has_neither(self) -> None:
        assert parse_field_modifiers("CommandLine") == ("CommandLine", None, set())

    def test_the_transform_can_come_first(self) -> None:
        base, modifier, transforms = parse_field_modifiers("CommandLine|windash|contains")
        assert base == "CommandLine"
        assert modifier == "contains"
        assert transforms == {"windash"}


class TestWindashExpansion:
    def test_every_dash_variant_windows_accepts(self) -> None:
        """Attackers swap these precisely because detections hardcode one."""
        expanded = expand_windash_values(["-enc"])
        assert "-enc" in expanded
        assert "/enc" in expanded
        assert "–enc" in expanded
        assert "—enc" in expanded

    def test_a_value_with_no_dash_is_returned_unchanged(self) -> None:
        assert expand_windash_values(["whoami"]) == ["whoami"]

    def test_expansion_does_not_repeat_itself(self) -> None:
        expanded = expand_windash_values(["-a"])
        assert len(expanded) == len(set(expanded))

    def test_without_the_transform_values_are_untouched(self) -> None:
        assert apply_value_transforms(["-enc"], set()) == ["-enc"]


class TestWindashMatching:
    def test_each_variant_matches(self) -> None:
        rule = _rule("CommandLine|contains|windash", "-enc")
        for command_line in ("powershell -enc AAA", "powershell /enc AAA", "powershell –enc AAA"):
            assert evaluate_sigma_rule(rule, _document(command_line))["matched"] is True, command_line

    def test_an_unrelated_command_still_does_not_match(self) -> None:
        """The expansion must widen the dash, not the rest of the value."""
        rule = _rule("CommandLine|contains|windash", "-enc")
        assert evaluate_sigma_rule(rule, _document("powershell -noprofile"))["matched"] is False

    def test_the_rule_is_reported_executable(self) -> None:
        result = analyze_sigma_engine_compatibility(_rule("CommandLine|contains|windash", "-enc"))
        assert result["executable_by_current_engine"] is True
        assert not any("windash" in feature for feature in result["unsupported_features"])

    def test_a_genuinely_unsupported_modifier_is_still_refused(self) -> None:
        result = analyze_sigma_engine_compatibility(_rule("CommandLine|base64offset|contains", "x"))
        assert result["executable_by_current_engine"] is False
