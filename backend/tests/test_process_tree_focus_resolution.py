"""Finding the process the analyst asked for, even when the identity is not exact.

Opening a process graph from an event whose node was built by a different
source (Security 4688 vs Sysmon) used to give up entirely: the code refused to
try anything but the exact source_event_id, and the analyst got an empty graph
for a process plainly present in the tree.
"""

from __future__ import annotations

import pytest

from app.services.process_tree import (
    FOCUS_MATCH_EXPLANATIONS,
    _nearest_named_nodes,
    _node_matches_name,
    _resolve_focus_node,
    normalize_process_name,
)


def node(**overrides) -> dict:
    base = {
        "id": "guid-1",
        "pid": 4321,
        "name": "powershell.exe",
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -enc ABC",
        "source_event_id": "evt-1",
        "source_events": ["evt-1"],
    }
    base.update(overrides)
    return base


# --- name normalisation ----------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("powershell.exe", "powershell"),
        ("PowerShell.EXE", "powershell"),
        ("C:\\Windows\\System32\\cmd.exe", "cmd"),
        ("/usr/bin/bash", "bash"),
        ('"C:\\Program Files\\app\\thing.exe"', "thing"),
        ("  rundll32  ", "rundll32"),
        (None, ""),
    ],
)
def test_process_names_normalise_to_something_comparable(value, expected):
    """A full path and a bare name must compare equal."""
    assert normalize_process_name(value) == expected


def test_a_bare_name_matches_a_full_path_node():
    assert _node_matches_name(node(), "powershell") is True


def test_a_command_line_substring_matches():
    assert _node_matches_name(node(), "-enc") is True


def test_an_unrelated_name_does_not_match():
    assert _node_matches_name(node(), "notepad") is False


# --- progressive resolution ------------------------------------------------


def test_an_exact_event_wins():
    focus, strategy, others = _resolve_focus_node(
        [node()], process_guid=None, pid=None, source_event_id="evt-1", process_name=None
    )
    assert focus["id"] == "guid-1"
    assert strategy == "source_event"
    assert others == []


def test_an_unmatched_event_falls_back_to_pid_and_name():
    """The reported failure: this used to return nothing at all."""
    nodes = [node(source_event_id="other", source_events=["other"])]

    focus, strategy, _ = _resolve_focus_node(
        nodes, process_guid=None, pid=4321, source_event_id="evt-missing", process_name="powershell.exe"
    )

    assert focus is not None, "a node with the right PID and name must still be found"
    assert strategy == "pid_and_name"


def test_an_unmatched_guid_falls_back_to_name():
    nodes = [node(id="different-guid", pid=999, source_event_id="x", source_events=["x"])]

    focus, strategy, _ = _resolve_focus_node(
        nodes, process_guid="guid-that-is-not-here", pid=None, source_event_id=None, process_name="powershell"
    )

    assert focus is not None
    assert strategy == "name"


def test_pid_alone_resolves_when_no_name_was_given():
    nodes = [node(source_event_id="x", source_events=["x"])]

    focus, strategy, _ = _resolve_focus_node(
        nodes, process_guid=None, pid=4321, source_event_id=None, process_name=None
    )

    assert focus is not None
    assert strategy == "pid"


def test_a_real_process_beats_a_synthetic_duplicate():
    """Security 4688 produces edge-less synthetic nodes; prefer the real one."""
    synthetic = node(id="security:abc", command_line="", source_event_id="x", source_events=["x"])
    real = node(id="guid-real", source_event_id="y", source_events=["y"])

    focus, _, others = _resolve_focus_node(
        [synthetic, real], process_guid=None, pid=4321, source_event_id=None, process_name=None
    )

    assert focus["id"] == "guid-real"
    assert others and others[0]["id"] == "security:abc", "the other must still be offered"


def test_nothing_matches_returns_no_focus():
    focus, strategy, others = _resolve_focus_node(
        [node()], process_guid=None, pid=1, source_event_id=None, process_name="notepad"
    )

    assert focus is None
    assert strategy is None
    assert others == []


def test_every_relaxed_strategy_has_an_explanation():
    """A relaxed match must be able to tell the analyst it was relaxed."""
    for strategy in ("source_event", "process_guid", "pid_and_name", "pid", "name"):
        assert FOCUS_MATCH_EXPLANATIONS[strategy].strip()
    for strategy in ("pid_and_name", "pid", "name"):
        text = FOCUS_MATCH_EXPLANATIONS[strategy].lower()
        assert "exact" in text or "may be a different" in text or "confirm" in text


# --- candidates when nothing matched ---------------------------------------


def test_candidates_are_offered_for_a_name_that_matched_nothing_exactly():
    nodes = [node(pid=1, id="a"), node(pid=2, id="b", name="notepad.exe", path="", command_line="")]

    candidates = _nearest_named_nodes(nodes, "powershell")

    assert [c["id"] for c in candidates] == ["a"]


def test_a_truncated_name_still_offers_something():
    """"powersh" should not be a dead end when powershell.exe is right there."""
    candidates = _nearest_named_nodes([node()], "powersh")

    assert len(candidates) == 1


def test_with_no_name_the_busiest_processes_are_offered():
    nodes = [node(id="synthetic", command_line=""), node(id="real")]

    candidates = _nearest_named_nodes(nodes, None)

    assert candidates[0]["id"] == "real", "a real process should be offered before a synthetic one"


def test_a_genuinely_absent_name_offers_nothing_rather_than_noise():
    assert _nearest_named_nodes([node()], "definitely-not-here") == []


# --- the search filter itself ----------------------------------------------


def _name_terms(process_name: str) -> set[str]:
    """The wildcard values a name search actually sends to OpenSearch."""
    from app.services.process_tree import _process_focus_filter

    built = _process_focus_filter(process_name=process_name, pid=None, entity_id=None)
    return {
        clause["wildcard"][field]["value"]
        for clause in (built or {}).get("bool", {}).get("should", [])
        if "wildcard" in clause
        for field in clause["wildcard"]
    }


def test_a_pasted_full_path_also_searches_the_executable_name():
    """process.name only ever holds "cmd.exe", so the path alone matches nothing."""
    terms = _name_terms("C:\\Windows\\System32\\cmd.exe")

    assert "*cmd*" in terms, "the basename must be searched too"
    assert any("System32" in term for term in terms), "the literal input must still be searched"


def test_a_bare_name_searches_just_that():
    assert _name_terms("powershell") == {"*powershell*"}


def test_wildcards_in_the_input_cannot_escape_the_pattern():
    terms = _name_terms("power*shell?")

    assert all(term.count("*") == 2 and "?" not in term for term in terms)


# --- the node filter that decides what stays in the graph -------------------


def test_a_pasted_path_still_selects_the_node_it_names():
    """The graph went empty for a process that was plainly in it."""
    from app.services.process_tree import _filter_process_graph

    graph = {
        "nodes": [node(id="a"), node(id="b", pid=2, name="explorer.exe", path="", command_line="")],
        "edges": [],
        "summary": {},
    }

    filtered = _filter_process_graph(
        graph, process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    )

    assert [n["id"] for n in filtered["nodes"]] == ["a"]


def test_the_node_filter_ignores_case_and_extension():
    from app.services.process_tree import _filter_process_graph

    graph = {"nodes": [node(id="a")], "edges": [], "summary": {}}

    assert len(_filter_process_graph(graph, process_name="POWERSHELL")["nodes"]) == 1


def test_the_node_filter_still_returns_nothing_for_an_absent_process():
    """Relaxing the match must not turn every query into a match."""
    from app.services.process_tree import _filter_process_graph

    graph = {"nodes": [node(id="a")], "edges": [], "summary": {}}

    assert _filter_process_graph(graph, process_name="notepad")["nodes"] == []


# --- a search that matches evidence with no process node -------------------
#
# The process graph is built from process-creation records only. A script name
# that appears solely in PowerShell script-block logs matches real events but
# can never have a node, and "no nodes matched the focus filter" sent the
# analyst hunting for a graph that cannot exist.


class _StubContext:
    pass


def test_a_term_found_only_outside_the_graph_is_explained(monkeypatch):
    import app.services.process_tree as pt

    monkeypatch.setattr(
        pt,
        "_search_scope_events",
        lambda context, size=1, extra_filters=None: (
            [{"artifact": {"type": "powershell"}, "event": {"type": "script_block"}}],
            None,
            None,
        ),
    )

    hint = pt.describe_matches_outside_the_process_graph(_StubContext(), {"bool": {}})

    assert "none of them are process-creation records" in hint
    assert "powershell" in hint
    assert "Search or the timeline" in hint


def test_no_hint_when_the_term_is_absent_everywhere(monkeypatch):
    """A term genuinely not in the case must not be explained away."""
    import app.services.process_tree as pt

    monkeypatch.setattr(
        pt, "_search_scope_events", lambda context, size=1, extra_filters=None: ([], None, None)
    )

    assert pt.describe_matches_outside_the_process_graph(_StubContext(), {"bool": {}}) is None


def test_no_hint_without_a_focus_filter(monkeypatch):
    import app.services.process_tree as pt

    assert pt.describe_matches_outside_the_process_graph(_StubContext(), None) is None


def test_a_failing_lookup_never_breaks_the_response(monkeypatch):
    import app.services.process_tree as pt

    def boom(context, size=1, extra_filters=None):
        raise RuntimeError("index unavailable")

    monkeypatch.setattr(pt, "_search_scope_events", boom)

    assert pt.describe_matches_outside_the_process_graph(_StubContext(), {"bool": {}}) is None


def test_the_hint_replaces_the_bare_focus_filter_warning():
    from app.services.process_tree import _filter_process_graph

    graph = {"nodes": [node(id="a", name="explorer.exe", path="", command_line="")], "edges": [], "summary": {}}

    filtered = _filter_process_graph(
        graph, process_name="somescript.ps1", outside_graph_hint="It lives in powershell events."
    )

    warnings = filtered["summary"]["warnings"]
    assert "It lives in powershell events." in warnings
    assert "No process graph nodes matched the selected focus filter." not in warnings


def test_without_a_hint_the_original_warning_still_appears():
    from app.services.process_tree import _filter_process_graph

    graph = {"nodes": [node(id="a", name="explorer.exe", path="", command_line="")], "edges": [], "summary": {}}

    filtered = _filter_process_graph(graph, process_name="somescript.ps1")

    assert "No process graph nodes matched the selected focus filter." in filtered["summary"]["warnings"]


def test_a_node_built_from_a_matched_event_survives_the_filter():
    """The node's own summary may not carry the text the query matched."""
    from app.services.process_tree import _filter_process_graph

    graph = {
        "nodes": [node(id="a", name="powershell.exe", path="", command_line="powershell.exe")],
        "edges": [],
        "summary": {},
    }

    filtered = _filter_process_graph(
        graph, process_name="unrelated-name", matched_event_ids={"evt-1"}
    )

    assert [n["id"] for n in filtered["nodes"]] == ["a"]


def test_matched_event_ids_do_not_keep_unrelated_nodes():
    from app.services.process_tree import _filter_process_graph

    graph = {
        "nodes": [node(id="a", source_event_id="other", source_events=["other"])],
        "edges": [],
        "summary": {},
    }

    filtered = _filter_process_graph(graph, process_name="nope", matched_event_ids={"evt-1"})

    assert filtered["nodes"] == []
