from app.services.case_state import build_case_next_actions, derive_case_investigation_state


def test_derive_empty_case() -> None:
    state = derive_case_investigation_state(evidence_count=0)

    assert state["state"] == "empty_case"
    assert state["evidence_count"] == 0


def test_derive_evidence_uploaded_not_indexed() -> None:
    state = derive_case_investigation_state(evidence_count=1, indexed_docs=0)

    assert state["state"] == "evidence_uploaded_not_indexed"


def test_derive_indexing_in_progress() -> None:
    state = derive_case_investigation_state(
        evidence_count=1,
        indexed_docs=0,
        active_jobs=[{"step": "indexing_plan", "status": "queued"}],
    )

    assert state["state"] == "indexing_in_progress"
    assert state["active_job_count"] == 1


def test_derive_investigation_ready() -> None:
    state = derive_case_investigation_state(
        evidence_count=1,
        investigation_ready_evidence_count=1,
        indexed_docs=25,
    )

    assert state["state"] == "investigation_ready"


def test_candidate_timeline_alone_no_longer_auto_advances_to_investigate() -> None:
    # INVESTIGATE is a manual, analyst-driven stage ("Start investigation").
    # Candidate timeline items alone must never auto-promote the case past
    # investigation_ready.
    state = derive_case_investigation_state(
        evidence_count=1,
        indexed_docs=25,
        candidate_timeline_count=3,
    )

    assert state["state"] == "investigation_ready"


def test_findings_or_official_timeline_alone_no_longer_auto_advance_to_report() -> None:
    # REPORT is a manual, analyst-driven stage ("Generate report"). Findings
    # or official timeline items alone must never auto-promote the case.
    finding_state = derive_case_investigation_state(evidence_count=1, indexed_docs=25, findings_count=1)
    timeline_state = derive_case_investigation_state(evidence_count=1, indexed_docs=25, official_timeline_count=1)

    assert finding_state["state"] == "investigation_ready"
    assert timeline_state["state"] == "investigation_ready"


def test_manual_phase_investigating_advances_state() -> None:
    state = derive_case_investigation_state(
        evidence_count=1,
        indexed_docs=25,
        manual_phase="investigating",
    )

    assert state["state"] == "investigation_in_progress"


def test_manual_phase_report_advances_state() -> None:
    state = derive_case_investigation_state(
        evidence_count=1,
        indexed_docs=25,
        manual_phase="report",
    )

    assert state["state"] == "report_ready"


def test_manual_phase_is_ignored_before_the_case_is_ready() -> None:
    # A case still indexing (or with no evidence) must not jump straight to
    # INVESTIGATE/REPORT just because a stale override value is present.
    state = derive_case_investigation_state(
        evidence_count=1,
        indexed_docs=0,
        active_jobs=[{"step": "indexing_plan", "status": "queued"}],
        manual_phase="report",
    )

    assert state["state"] == "indexing_in_progress"


def test_next_actions_empty_case_prioritizes_add_evidence() -> None:
    state = derive_case_investigation_state(evidence_count=0)
    actions = build_case_next_actions("case-1", state)

    assert actions["primary"][0]["id"] == "add_evidence"
    assert actions["primary"][0]["enabled"] is True
    assert any(item["id"] == "search_suspicious_commands" and item["enabled"] is False for item in actions["unavailable"])
    assert any(item["id"] == "generate_report" and item["enabled"] is False for item in actions["unavailable"])


def test_next_actions_not_indexed_prioritizes_indexing() -> None:
    state = derive_case_investigation_state(evidence_count=1, indexed_docs=0)
    actions = build_case_next_actions("case-1", state, first_evidence_id="ev-1")

    assert actions["primary"][0]["id"] == "index_evidence"
    assert actions["primary"][0]["href"] == "/evidences/ev-1"
    assert any(item["id"] == "add_more_evidence" for item in actions["secondary"])


def test_next_actions_ready_include_add_more_evidence_and_investigation() -> None:
    state = derive_case_investigation_state(evidence_count=1, indexed_docs=20)
    actions = build_case_next_actions("case-1", state, defender_docs_count=3)
    ids = [item["id"] for item in [*actions["primary"], *actions["secondary"]]]

    assert "add_more_evidence" in ids
    assert "search_suspicious_commands" in ids
    assert "review_command_history" in ids
    assert "review_defender" in ids


def test_next_actions_report_ready_include_generate_report() -> None:
    state = derive_case_investigation_state(evidence_count=1, indexed_docs=20, findings_count=1, manual_phase="report")
    actions = build_case_next_actions("case-1", state)

    assert any(item["id"] == "generate_report" and item["enabled"] is True for item in actions["primary"])
