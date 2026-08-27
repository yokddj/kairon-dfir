from __future__ import annotations

from types import SimpleNamespace

import yaml

from app.api.routes_rules import _drop_rules_this_engine_cannot_evaluate


def _rule(content: dict, engine: str = "sigma", name: str = "r"):
    return SimpleNamespace(id=name, name=name, engine=engine, content=yaml.safe_dump(content))


EVALUABLE = {"title": "ok", "logsource": {"product": "windows"}, "detection": {"sel": {"EventID": 7045}, "condition": "sel"}}
NOT_EVALUABLE = {
    "title": "bad",
    "logsource": {"product": "windows"},
    "detection": {
        "selection_eid": {"EventID": 5145},
        "selection_object": [{"RelativeTargetName|contains": ["\\lsass"]}],
        "condition": "all of selection_*",
    },
}


def test_a_rule_the_engine_cannot_answer_is_not_queued() -> None:
    """Compatibility was analysed at import and ignored at run time.

    The rule still ran, against a query compiled with its unreadable half
    dropped -- "EventID 5145 AND a credential-store filename" became "any
    network share access". Two such rules produced 2000 of 2271 detections on
    one case and buried the genuine hits.
    """
    kept, dropped = _drop_rules_this_engine_cannot_evaluate([_rule(EVALUABLE, name="good"), _rule(NOT_EVALUABLE, name="bad")])

    assert [rule.id for rule in kept] == ["good"]
    assert dropped == {"unmapped_field": 1}


def test_engines_other_than_sigma_are_left_alone() -> None:
    yara_rule = SimpleNamespace(id="y", name="y", engine="yara", content="rule x { condition: true }")
    kept, dropped = _drop_rules_this_engine_cannot_evaluate([yara_rule])

    assert [rule.id for rule in kept] == ["y"]
    assert dropped == {}


def test_unparseable_content_is_left_for_the_runner_to_report() -> None:
    """A broken rule is a different failure with its own reporting; dropping it
    here would hide it."""
    broken = SimpleNamespace(id="b", name="b", engine="sigma", content="{{ not yaml")
    kept, _ = _drop_rules_this_engine_cannot_evaluate([broken])

    assert [rule.id for rule in kept] == ["b"]


def test_the_reason_is_reported_so_the_run_can_explain_itself() -> None:
    _, dropped = _drop_rules_this_engine_cannot_evaluate(
        [_rule(NOT_EVALUABLE, name="a"), _rule(NOT_EVALUABLE, name="b")]
    )
    assert dropped["unmapped_field"] == 2


def test_nothing_is_dropped_when_every_rule_is_evaluable() -> None:
    kept, dropped = _drop_rules_this_engine_cannot_evaluate([_rule(EVALUABLE, name="a"), _rule(EVALUABLE, name="b")])
    assert len(kept) == 2
    assert dropped == {}
