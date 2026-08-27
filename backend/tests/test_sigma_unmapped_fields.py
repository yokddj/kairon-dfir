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
        _rule({"sel": {"EventID": 10, "CallTrace|contains": "UNKNOWN"}, "condition": "sel"})
    )
    assert result["executable_by_current_engine"] is False
    assert result["engine_status"] == "unmapped_field"
    assert result["unmapped_fields"] == ["CallTrace"]
    assert "unmapped_field:CallTrace" in result["unsupported_features"]


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


def test_a_chain_of_modifiers_does_not_hide_the_field_name() -> None:
    """"CommandLine|contains|all" is still the CommandLine field.

    _split_field_and_modifier removes one suffix, which is right for deciding
    whether a modifier is supported but leaves "CommandLine|contains" -- a name
    no map will ever hold. Judging mappability on that stump reported 615
    ordinary rules from a real SigmaHQ pack as unusable, which is a worse
    failure than the silence this check exists to replace.
    """
    assert _detect_unmapped_fields(_rule({"sel": {"CommandLine|contains|all": ["a", "b"]}, "condition": "sel"})) == []
    assert _detect_unmapped_fields(_rule({"sel": {"CommandLine|contains|windash": "x"}, "condition": "sel"})) == []
    assert _detect_unmapped_fields(_rule({"sel": {"ScriptBlockText|contains|all": ["a"]}, "condition": "sel"})) == []


def test_an_unmappable_field_is_still_caught_through_a_modifier_chain() -> None:
    assert _detect_unmapped_fields(
        _rule({"sel": {"CallTrace|contains|all": ["a"]}, "condition": "sel"})
    ) == ["CallTrace"]


def test_a_rule_with_a_chained_modifier_stays_executable() -> None:
    result = analyze_sigma_engine_compatibility(
        _rule({"sel": {"CommandLine|contains|all": ["whoami", "/all"]}, "condition": "sel"})
    )
    assert result["unmapped_fields"] == []


class TestFieldsAddedFromRealMeasurement:
    """Each of these was verified against a live index before being mapped:
    the target field must exist and hold the shape the Sigma field means."""

    def test_service_install_rules_can_be_evaluated(self) -> None:
        # 7045 is how a remote-execution tool announces itself; these three
        # fields are what Sigma rules key on to catch it.
        for field in ("ServiceName", "ServiceFileName", "ImagePath"):
            result = analyze_sigma_engine_compatibility(
                _rule({"sel": {f"{field}|contains": "evil"}, "condition": "sel"})
            )
            assert result["unmapped_fields"] == [], field
            assert result["executable_by_current_engine"] is True, field

    def test_object_access_and_channel_rules_can_be_evaluated(self) -> None:
        for field in ("ObjectName", "ObjectType", "EventLog"):
            result = analyze_sigma_engine_compatibility(_rule({"sel": {field: "x"}, "condition": "sel"}))
            assert result["unmapped_fields"] == [], field

    def test_integrity_level_points_at_the_word_form_not_the_sid(self) -> None:
        """Sigma rules match "High"; process.integrity_level holds a SID.

        The normalizer promotes Sysmon's word form to its own field, so the
        mapping targets that and never the SID -- pointing at the SID would
        compile a rule that runs and never matches, the exact silence this
        check exists to remove.
        """
        assert _detect_unmapped_fields(_rule({"sel": {"IntegrityLevel": "High"}, "condition": "sel"})) == []
        assert SIGMA_FIELD_MAP["IntegrityLevel"] == ["process.integrity_level_name"]
        assert "process.integrity_level" not in SIGMA_FIELD_MAP["IntegrityLevel"]

    def test_original_file_name_is_mappable_once_the_normalizer_promotes_it(self) -> None:
        """It blocked 559 rules while it lived only inside windows.event_data."""
        assert _detect_unmapped_fields(_rule({"sel": {"OriginalFileName": "PowerShell.EXE"}, "condition": "sel"})) == []

    def test_fields_with_nothing_to_point_at_stay_unmapped(self) -> None:
        for field in ("PipeName", "TargetImage", "CallTrace"):
            assert _detect_unmapped_fields(_rule({"sel": {field: "x"}, "condition": "sel"})) == [field], field

    def test_every_mapped_target_is_a_dotted_document_path(self) -> None:
        """Guards against pasting a Sigma name into the target list by mistake."""
        for sigma_field, targets in SIGMA_FIELD_MAP.items():
            assert targets, sigma_field
            for target in targets:
                assert target == target.lower() or "." in target, f"{sigma_field} -> {target}"


class TestListFormSelections:
    """Sigma lets a selection be a list of maps, to OR alternatives together."""

    def test_fields_inside_a_list_selection_are_seen(self) -> None:
        """Ignoring the list form judged a rule on half its logic.

        "Transferring Files with Credential Data via Network Shares" is
        EventID 5145 AND a RelativeTargetName naming a credential store. With
        the list-form half invisible it compiled to "any network share access"
        and produced 1000 detections on a single case -- burying the one
        genuine service-installation hit underneath. Over-matching is the more
        dangerous silence: the rule looks like it is working.
        """
        rule = _rule(
            {
                "selection_eid": {"EventID": 5145},
                "selection_object": [
                    {"RelativeTargetName|contains": ["\\lsass", "\\mimidrv"]},
                    {"RelativeTargetName": ["Windows\\NTDS\\ntds.dit"]},
                ],
                "condition": "all of selection_*",
            }
        )
        assert _detect_unmapped_fields(rule) == ["RelativeTargetName"]
        assert analyze_sigma_engine_compatibility(rule)["executable_by_current_engine"] is False

    def test_a_list_selection_of_mapped_fields_stays_executable(self) -> None:
        rule = _rule(
            {
                "selection": [{"CommandLine|contains": "whoami"}, {"Image|endswith": "\\net.exe"}],
                "condition": "selection",
            }
        )
        assert _detect_unmapped_fields(rule) == []
        assert analyze_sigma_engine_compatibility(rule)["executable_by_current_engine"] is True

    def test_unsupported_modifiers_inside_a_list_are_also_seen(self) -> None:
        rule = _rule({"selection": [{"CommandLine|base64offset": "x"}], "condition": "selection"})
        result = analyze_sigma_engine_compatibility(rule)
        assert result["executable_by_current_engine"] is False
        assert any("base64offset" in feature for feature in result["unsupported_features"])

    def test_non_mapping_entries_in_a_list_are_ignored(self) -> None:
        rule = _rule({"selection": ["a bare string", {"CommandLine": "x"}], "condition": "selection"})
        assert _detect_unmapped_fields(rule) == []


class TestLinuxCoverage:
    """Linux events are normalised into the linux.* block, not into the
    ECS-style process.* fields the Windows pipeline fills."""

    def test_command_line_reaches_the_linux_block(self) -> None:
        """Without this a Linux rule ran against a field only Windows fills.

        It was reported executable, it was queued, it queried a field that is
        empty on a Linux case, and it found nothing -- with no error and no
        skip. The rule looked armed and could never fire.
        """
        assert "linux.command" in SIGMA_FIELD_MAP["CommandLine"]

    def test_process_name_reaches_the_linux_block(self) -> None:
        assert "linux.process" in SIGMA_FIELD_MAP["Image"]
        assert "linux.process" in SIGMA_FIELD_MAP["ProcessName"]

    def test_the_windows_targets_are_kept_first(self) -> None:
        """Both platforms are matched with one OR; Windows must not regress."""
        assert SIGMA_FIELD_MAP["CommandLine"][0] == "process.command_line"
        assert SIGMA_FIELD_MAP["Image"][0] == "process.executable"


def test_the_runtime_mapper_reads_past_a_modifier_chain() -> None:
    """The analyser and the runtime mapper have to agree on a field's name.

    _mapped_sigma_fields stripped a single recognised suffix, so
    "CommandLine|contains|all" was queried as a document key of that literal
    name: a rule the analyser had just declared evaluable was skipped at run
    time for missing fields.
    """
    from app.rules_engine.sigma import _mapped_sigma_fields

    mapped, _ = _mapped_sigma_fields("CommandLine|contains|all")
    assert "process.command_line" in mapped
    mapped_plain, _ = _mapped_sigma_fields("CommandLine")
    assert mapped == mapped_plain
