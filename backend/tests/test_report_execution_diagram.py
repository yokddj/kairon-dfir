"""Execution diagrams in the report: the process tree behind a finding, drawn
from process-creation records only, as text in Markdown and a drawing in PDF."""

from __future__ import annotations

from types import SimpleNamespace

from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors

from app.services import report_execution_diagram as diagram
from app.services import report_service

TARGET = {"id": "p3", "name": "rundll32.exe", "pid": 340, "host": "SRV-01", "user": "SYSTEM", "first_seen": "2026-01-10T12:07:21Z",
          "command_line": r"rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 656 dump.bin full", "risk_score": 90, "parent_entity_id": "p2"}
STORY = {
    "target": TARGET,
    "quality": {"exact_story": True},
    "parents": [],
    "children": [],
    "visual_tree": {
        "nodes": [
            {"id": "p1", "name": "cmd.exe", "pid": 4420, "host": "SRV-01", "first_seen": "2026-01-10T12:07:20Z", "parent_entity_id": "p0", "parent_name": "services.exe", "parent_pid": 636},
            {"id": "p2", "name": "cmd.exe", "pid": 4920, "host": "SRV-01", "first_seen": "2026-01-10T12:07:20Z", "parent_entity_id": "p1"},
            TARGET,
            {"id": "p4", "name": "conhost.exe", "pid": 77, "host": "SRV-01", "first_seen": "2026-01-10T12:07:22Z", "parent_entity_id": "p3"},
            {"id": "p4b", "name": "conhost.exe", "pid": 77, "host": "SRV-01", "first_seen": "2026-01-10T12:07:22Z", "parent_entity_id": "p3"},
            {"id": "x9", "name": "unrelated.exe", "pid": 1, "host": "WS-01"},
        ],
        "edges": [{"source": "p1", "target": "p2"}, {"source": "p2", "target": "p3"}, {"source": "p3", "target": "p4"}, {"source": "p3", "target": "p4b"}],
    },
}
PALETTE = {"primary": colors.HexColor("#0f766e"), "ink": colors.black, "muted": colors.grey, "border": colors.lightgrey}


def test_tree_has_ancestors_the_process_and_its_children(monkeypatch) -> None:
    seeds = []

    def story(_case, _evidences, **kwargs):
        seeds.append(kwargs.get("source_event_id") or kwargs.get("process_guid"))
        return STORY if kwargs.get("source_event_id") == "ev-2" else {"target": None}

    monkeypatch.setattr("app.services.process_tree.build_execution_story", story)
    finding = SimpleNamespace(related_process_node_ids=[], event_ids=["ev-1", "ev-2", "ev-3"])
    tree = diagram.build_execution_tree(None, None, [], finding)
    assert seeds == ["ev-1", "ev-2"]
    assert [(node["name"], node["depth"], node["missing"], node["focus"]) for node in tree["nodes"]] == [
        ("services.exe", 0, True, False),
        ("cmd.exe", 1, False, False),
        ("cmd.exe", 2, False, False),
        ("rundll32.exe", 3, False, True),
        # Sysmon and 4688 records of one process are one box; unrelated processes are left out.
        ("conhost.exe", 4, False, False),
    ]
    text = diagram.render_tree_text(tree)
    assert "services.exe  PID 636  (not in the evidence)" in text and "<= finding" in text and "comsvcs.dll" in text
    drawing = diagram.execution_tree_drawing(tree, 480, PALETTE)
    assert isinstance(drawing, Drawing) and drawing.height == diagram.ROW * 5 + 4


def test_no_tree_without_a_process_record(monkeypatch) -> None:
    monkeypatch.setattr("app.services.process_tree.build_execution_story", lambda *_a, **_k: {"target": None})
    assert diagram.build_execution_tree(None, None, [], SimpleNamespace(related_process_node_ids=[], event_ids=["ev-1"])) is None


def test_report_section_carries_the_text_tree_and_the_pdf_draws_it(monkeypatch) -> None:
    monkeypatch.setattr("app.services.process_tree.build_execution_story", lambda *_a, **_k: STORY)
    finding = SimpleNamespace(id="f1", title="LSASS dumped", risk_score=90, reasons=[], timeline=[], related_process_node_ids=[], event_ids=["ev-2"])
    tree = diagram.build_execution_tree(None, None, [], finding)
    markdown = report_service._render_process_chains([finding], {"f1": tree})
    assert "<!-- execution-diagram:f1 -->" in markdown and "```text" in markdown and "rundll32.exe" in markdown
    story: list = []
    styles = report_service._build_pdf_styles(report_service._pdf_palette("#0f766e"))
    report_service._append_markdown_to_story(story, markdown, styles, report_service._pdf_palette("#0f766e"), diagrams={"f1": tree}, width=480)
    assert any(isinstance(item, Drawing) for item in story)
    # Without the tree the same block stays text.
    story = []
    report_service._append_markdown_to_story(story, markdown, styles, report_service._pdf_palette("#0f766e"))
    assert not any(isinstance(item, Drawing) for item in story)
    missing = report_service._render_process_chains([finding], {"f1": None})
    assert "No process-creation record" in missing
