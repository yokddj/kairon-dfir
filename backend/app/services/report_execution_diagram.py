"""Execution diagrams for the report: the process tree behind a finding.

For each finding the analyst picks under Process Chains, the process its
events point to is resolved the way the Execution Stories view does it (a
process GUID the finding holds, else the finding's events, first match wins),
and the tree around it is drawn: up to three ancestors, the process, and its
descendants up to three levels. Every node is a process-creation record of
the case; a parent that is named by its child but has no record of its own is
drawn as "not in the evidence", never invented. Markdown gets the same tree
as text; the PDF gets a drawing.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Any

from reportlab.graphics.shapes import Drawing, Line, Rect, String
from reportlab.lib import colors
from reportlab.pdfbase.pdfmetrics import stringWidth
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

MAX_ANCESTORS = 3
MAX_DEPTH = 3
MAX_NODES = 24
MAX_SEEDS = 6
MARKER = "<!-- execution-diagram:{key} -->"


def _node(raw: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "id": str(raw.get("id") or ""),
        "name": raw.get("name") or "unknown",
        "pid": raw.get("pid"),
        "host": raw.get("host"),
        "user": raw.get("user"),
        "time": raw.get("first_seen"),
        "command_line": raw.get("command_line"),
        "risk": int(raw.get("risk_score") or 0),
        "missing": False,
        **extra,
    }


def _story_for(case: Any, evidences: list[Any], finding: Any) -> dict[str, Any] | None:
    from app.services.process_tree import build_execution_story

    seeds = [("process_guid", value) for value in (finding.related_process_node_ids or [])[:3]]
    seeds += [("source_event_id", value) for value in (finding.event_ids or [])[:MAX_SEEDS]]
    for kind, value in seeds:
        try:
            story = build_execution_story(case, evidences, scope="case", max_nodes=80, parent_depth=MAX_ANCESTORS, child_depth=MAX_DEPTH, **{kind: str(value)})
        except Exception:  # noqa: BLE001 -- try the next seed; the report renders without a diagram
            logger.warning("execution diagram: story for %s %s failed", kind, value, exc_info=True)
            continue
        if story.get("target"):
            return story
    return None


def build_execution_tree(db: Session, case: Any, evidences: list[Any], finding: Any) -> dict[str, Any] | None:
    """The tree to draw for one finding, in drawing order, or None."""
    story = _story_for(case, evidences, finding)
    if not story:
        return None
    target = story["target"]
    visual = story.get("visual_tree") or {}
    by_id: dict[str, dict[str, Any]] = {str(node.get("id")): node for node in visual.get("nodes") or [] if node.get("id")}
    for node in [target, *(story.get("parents") or []), *(story.get("children") or [])]:
        if node.get("id"):
            by_id.setdefault(str(node["id"]), node)
    children: dict[str, list[str]] = {}
    for edge in visual.get("edges") or []:
        if edge.get("type", "parent_child") == "parent_child" and edge.get("source") and edge.get("target"):
            children.setdefault(str(edge["source"]), []).append(str(edge["target"]))
    for child in story.get("children") or []:
        if child.get("id") and str(child["id"]) not in children.get(str(target["id"]), []):
            children.setdefault(str(target["id"]), []).append(str(child["id"]))

    # Ancestors, root first.
    chain: list[dict[str, Any]] = []
    current = target
    for _ in range(MAX_ANCESTORS):
        parent_id = str(current.get("parent_entity_id") or "")
        parent = by_id.get(parent_id) if parent_id else None
        if parent is None:
            if current.get("parent_name"):
                chain.append({"id": f"missing:{parent_id or current.get('parent_pid')}", "name": current.get("parent_name"), "pid": current.get("parent_pid"),
                              "host": current.get("host"), "user": None, "time": None, "command_line": None, "risk": 0, "missing": True})
            break
        chain.append(_node(parent))
        current = parent
    chain.reverse()

    nodes: list[dict[str, Any]] = [{**node, "depth": depth, "focus": False} for depth, node in enumerate(chain)]
    base = len(chain)
    seen: set[tuple] = set()
    truncated = False

    def key(raw: dict[str, Any]) -> tuple:
        # The same process recorded by Sysmon and by 4688 is one box.
        return (str(raw.get("name") or "").lower(), raw.get("pid"), str(raw.get("host") or "").lower())

    def walk(node_id: str, depth: int) -> None:
        nonlocal truncated
        raw = by_id.get(node_id)
        if raw is None or key(raw) in seen:
            return
        if len(nodes) >= MAX_NODES:
            truncated = True
            return
        seen.add(key(raw))
        nodes.append({**_node(raw), "depth": base + depth, "focus": node_id == str(target["id"])})
        if depth >= MAX_DEPTH:
            if children.get(node_id):
                truncated = True
            return
        ordered = sorted(children.get(node_id, []), key=lambda child: str((by_id.get(child) or {}).get("first_seen") or ""))
        for child in ordered:
            walk(child, depth + 1)

    walk(str(target["id"]), 0)
    if not any(node["focus"] for node in nodes):
        return None
    quality = story.get("quality") or {}
    return {"nodes": nodes, "truncated": truncated, "exact": bool(quality.get("exact_story"))}


def _time(value: Any) -> str:
    text = str(value or "")
    return text[:19].replace("T", " ") if text else ""


def render_tree_text(tree: dict[str, Any]) -> str:
    """The tree as indented text, for the Markdown export."""
    lines = []
    for node in tree["nodes"]:
        prefix = "   " * max(node["depth"] - 1, 0) + ("└─ " if node["depth"] else "")
        parts = [str(node["name"])]
        if node.get("pid") not in (None, ""):
            parts.append(f"PID {node['pid']}")
        if node.get("missing"):
            parts.append("(not in the evidence)")
        if node.get("time"):
            parts.append(_time(node["time"]))
        if node.get("user"):
            parts.append(str(node["user"]))
        if node.get("focus"):
            parts.append("<= finding")
        line = prefix + "  ".join(parts)
        if node.get("command_line"):
            command = " ".join(str(node["command_line"]).split())
            line += "\n" + " " * len(prefix) + "   " + (command[:160] + ("..." if len(command) > 160 else ""))
        lines.append(line)
    return "\n".join(lines)


ROW = 27.0
BOX_H = 23.0
INDENT = 16.0


def _fit(text: str, font: str, size: float, width: float) -> str:
    if stringWidth(text, font, size) <= width:
        return text
    while text and stringWidth(text + "...", font, size) > width:
        text = text[:-1]
    return text + "..."


def execution_tree_drawing(tree: dict[str, Any], width: float, palette: dict[str, colors.Color]) -> Drawing:
    """The tree as a drawing: one box per process, connectors from each parent."""
    nodes = tree["nodes"]
    height = ROW * len(nodes) + 4
    drawing = Drawing(width, height)
    danger = colors.HexColor("#b91c1c")
    focus_fill = colors.Color(palette["primary"].red, palette["primary"].green, palette["primary"].blue, alpha=0.12)
    last_at_depth: dict[int, float] = {}
    for index, node in enumerate(nodes):
        top = height - 2 - index * ROW
        y = top - BOX_H
        x = node["depth"] * INDENT
        box_width = width - x
        middle = y + BOX_H / 2
        if node["depth"] and node["depth"] - 1 in last_at_depth:
            # Elbow from the parent's left edge down to this box.
            parent_x = (node["depth"] - 1) * INDENT + 6
            drawing.add(Line(parent_x, last_at_depth[node["depth"] - 1], parent_x, middle, strokeColor=palette["muted"], strokeWidth=0.6))
            drawing.add(Line(parent_x, middle, x, middle, strokeColor=palette["muted"], strokeWidth=0.6))
        border = palette["primary"] if node.get("focus") else danger if node.get("risk", 0) >= 70 else palette["border"]
        rect = Rect(x, y, box_width, BOX_H, rx=3, ry=3, strokeColor=border, strokeWidth=1.2 if node.get("focus") else 0.7,
                    fillColor=focus_fill if node.get("focus") else colors.white)
        if node.get("missing"):
            rect.strokeDashArray = [2, 2]
            rect.strokeColor = palette["muted"]
        drawing.add(rect)
        title_parts = [str(node["name"])]
        if node.get("pid") not in (None, ""):
            title_parts.append(f"PID {node['pid']}")
        title = "  ".join(title_parts)
        # One line of text sits in the middle of the box; two share it.
        text_y = y + 13.5 if node.get("command_line") else y + 8.5
        title_width = min(stringWidth(title, "Helvetica-Bold", 7.5), box_width * 0.55)
        drawing.add(String(x + 5, text_y, _fit(title, "Helvetica-Bold", 7.5, box_width * 0.55), fontName="Helvetica-Bold", fontSize=7.5, fillColor=palette["ink"]))
        meta = "not in the evidence" if node.get("missing") else "  ·  ".join(part for part in (_time(node.get("time")), str(node.get("host") or ""), str(node.get("user") or "")) if part)
        drawing.add(String(x + 12 + title_width, text_y, _fit(meta, "Helvetica", 6.5, box_width - title_width - 18), fontName="Helvetica", fontSize=6.5, fillColor=palette["muted"]))
        if node.get("command_line"):
            command = " ".join(str(node["command_line"]).split())
            drawing.add(String(x + 5, y + 4.5, _fit(command, "Courier", 6, box_width - 10), fontName="Courier", fontSize=6, fillColor=palette["ink"]))
        last_at_depth[node["depth"]] = y
        for depth in [depth for depth in last_at_depth if depth > node["depth"]]:
            del last_at_depth[depth]
    return drawing
