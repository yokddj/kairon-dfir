from __future__ import annotations

from app.services import correlation_engine, timeline_service


class TestPhaseTaxonomy:
    def test_finding_type_carrying_its_phase_is_mapped(self) -> None:
        """A near-miss on a string must not cost the whole classification.

        The fallback used to require exact equality with the phase vocabulary,
        so a case whose findings are all typed "persistence_execution" had every
        one classified "unknown" because the phase is spelled "persistence".
        """
        phase, confidence = timeline_service._infer_incident_phase("", fallback="persistence_execution")
        assert phase == "persistence"
        assert confidence == "high"

    def test_multi_word_phase_is_not_shadowed_by_a_shorter_one(self) -> None:
        assert timeline_service._phase_from_finding_type("credential_access_dump") == "credential_access"
        assert timeline_service._phase_from_finding_type("attempted_lateral_movement") == "lateral_movement"

    def test_known_concept_without_a_phase_word_is_aliased(self) -> None:
        assert timeline_service._phase_from_finding_type("suspicious_process_chain") == "execution"
        assert timeline_service._phase_from_finding_type("kerberoasting") == "credential_access"

    def test_unmappable_type_stays_unknown(self) -> None:
        phase, confidence = timeline_service._infer_incident_phase("", fallback="something_we_never_defined")
        assert phase == "unknown"
        assert confidence == "low"


class TestPhaseKeywordsAreTradecraftOnly:
    def test_ordinary_windows_nouns_do_not_assign_a_phase(self) -> None:
        """Words that occur all over a healthy Windows box must not classify.

        These previously mapped to real phases, so every OneDrive updater task
        was labelled persistence and every file under Downloads was labelled
        collection -- confident, wrong, and applied to hosts that were fine.
        """
        for text in (
            "Scheduled task observed: OneDrive Per-Machine Standalone Update Task",
            "File opened from C:\\Users\\someone\\Downloads\\report.pdf",
            "Shortcut on the user Desktop",
        ):
            phase, _ = timeline_service._infer_incident_phase(text)
            assert phase == "unknown", text

    def test_real_tradecraft_still_classifies(self) -> None:
        assert timeline_service._infer_incident_phase("rubeus kerberoast against the DC")[0] == "credential_access"
        assert timeline_service._infer_incident_phase("psexec to the file server")[0] == "lateral_movement"
        assert timeline_service._infer_incident_phase("schtasks /create /tn updater")[0] == "persistence"
        assert timeline_service._infer_incident_phase("Set-MpPreference -DisableRealtimeMonitoring")[0] == "defense_evasion"

    def test_no_literal_case_indicator_survives_in_the_keyword_set(self) -> None:
        import inspect

        source = inspect.getsource(timeline_service._infer_incident_phase)
        # An IP literal in a generic classifier can only have come from one
        # investigation and can only ever match that investigation again.
        assert "200.234.235.200" not in source
        assert "management-passwords" not in source
        assert "check-updates" not in source


class TestPersistenceFindingTitles:
    def test_title_names_the_entry_not_just_its_mechanism(self) -> None:
        event = {"task": {"name": "UpdaterTask"}}
        label = correlation_engine._persistence_entity_label(event, None)
        assert correlation_engine._persistence_finding_title("scheduled_task", label) == (
            "Persistence matched execution: UpdaterTask (scheduled_task)"
        )

    def test_falls_back_to_the_executable_name(self) -> None:
        label = correlation_engine._persistence_entity_label({}, "C:\\Windows\\Temp\\stager.exe -run")
        assert label == "stager.exe -run"

    def test_without_any_label_the_old_shape_is_kept(self) -> None:
        assert correlation_engine._persistence_finding_title("windows_service", None) == (
            "Persistence matched execution: windows_service"
        )

    def test_two_entries_of_the_same_mechanism_get_different_titles(self) -> None:
        """The defect was 128 byte-identical rows in one timeline."""
        first = correlation_engine._persistence_finding_title(
            "windows_service", correlation_engine._persistence_entity_label({"service": {"name": "Spooler"}}, None)
        )
        second = correlation_engine._persistence_finding_title(
            "windows_service", correlation_engine._persistence_entity_label({"service": {"name": "EvilSvc"}}, None)
        )
        assert first != second
