from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def parse_autoruns_xml_file(path: Path) -> list[dict]:
    tree = ET.parse(path)
    root = tree.getroot()
    rows: list[dict] = []
    for node in root.iter():
        tag = _strip_ns(node.tag).lower()
        if tag not in {"item", "entry", "autorun", "row"}:
            continue
        row: dict[str, str] = {}
        for key, value in node.attrib.items():
            row[_strip_ns(key)] = value
        for child in list(node):
            child_tag = _strip_ns(child.tag)
            row[child_tag] = (child.text or "").strip()
        if row:
            rows.append(row)
    if rows:
        return rows
    if list(root):
        row = {}
        for child in list(root):
            row[_strip_ns(child.tag)] = (child.text or "").strip()
        if row:
            return [row]
    return []


__all__ = ["parse_autoruns_xml_file"]
