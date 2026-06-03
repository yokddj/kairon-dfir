from __future__ import annotations

import re
from pathlib import Path


YARA_RULE_NAME_RE = re.compile(r"(?m)^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b")
YARA_RULE_START_RE = re.compile(r"(?m)^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b")
YARA_HEADER_KV_RE = re.compile(r"(?im)^\s*(?://|/\*+|\*+)?\s*([A-Za-z][A-Za-z0-9 _-]+)\s*:\s*(.+?)\s*(?:\*/)?\s*$")


def detect_yara_rules(content: str) -> list[str]:
    return [match.group(1) for match in YARA_RULE_NAME_RE.finditer(content)]


def parse_yara_forge_header(content: str) -> dict:
    metadata: dict[str, str | int] = {}
    header_slice = content[: min(len(content), 8000)]
    for match in YARA_HEADER_KV_RE.finditer(header_slice):
        key = match.group(1).strip().lower().replace(" ", "_").replace("-", "_")
        value = match.group(2).strip()
        if key == "number_of_rules":
            try:
                metadata[key] = int(value)
            except ValueError:
                metadata[key] = value
        else:
            metadata[key] = value
    if "yara_forge" in header_slice.lower():
        metadata.setdefault("package", "YARA-Forge")
    return metadata


def classify_yara_import(content: str, filename: str) -> dict:
    rule_names = detect_yara_rules(content)
    metadata = parse_yara_forge_header(content)
    lower = filename.lower()
    if "yara-forge" in lower or "yara_forge" in lower:
        metadata.setdefault("package", "YARA-Forge")
    metadata.setdefault("first_rules", rule_names[:50])
    return {
        "engine": "yara",
        "rules_count": len(rule_names),
        "rule_names": rule_names,
        "is_rule_pack": len(rule_names) > 1,
        "metadata": metadata,
    }


def _find_rule_block_end(content: str, start_index: int) -> int:
    brace_depth = 0
    in_string: str | None = None
    in_line_comment = False
    in_block_comment = False
    seen_open_brace = False
    i = start_index
    while i < len(content):
        char = content[i]
        nxt = content[i + 1] if i + 1 < len(content) else ""
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if char == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_string:
            if char == "\\":
                i += 2
                continue
            if char == in_string:
                in_string = None
            i += 1
            continue
        if char == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if char == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if char in {'"', "'"}:
            in_string = char
            i += 1
            continue
        if char == "{":
            seen_open_brace = True
            brace_depth += 1
        elif char == "}":
            if seen_open_brace:
                brace_depth -= 1
                if brace_depth == 0:
                    return i + 1
        i += 1
    return len(content)


def split_yara_rules(content: str, filename: str) -> list[tuple[str, str]]:
    matches = list(YARA_RULE_START_RE.finditer(content))
    if not matches:
        return []
    parts: list[tuple[str, str]] = []
    for match in matches:
        name = match.group(1)
        start = match.start()
        end = _find_rule_block_end(content, match.end())
        rule_text = content[start:end].strip()
        if rule_text:
            parts.append((name or Path(filename).stem, rule_text))
    return parts
