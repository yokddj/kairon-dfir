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


def test_derive_investigation_in_progress_from_candidates() -> None:
    state = derive_case_investigation_state(
        evidence_count=1,
        indexed_docs=25,
        candidate_timeline_count=3,
    )

    assert state["state"] == "investigation_in_progress"


def test_derive_report_ready_from_findings_or_official_timeline() -> None:
    finding_state = derive_case_investigation_state(evidence_count=1, indexed_docs=25, findings_count=1)
    timeline_state = derive_case_investigation_state(evidence_count=1, indexed_docs=25, official_timeline_count=1)

    assert finding_state["state"] == "report_ready"
    assert timeline_state["state"] == "report_ready"


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
    state = derive_case_investigation_state(evidence_count=1, indexed_docs=20, findings_count=1)
    actions = build_case_next_actions("case-1", state)

    assert any(item["id"] == "generate_report" and item["enabled"] is True for item in actions["primary"])
