"""The details of MemProcFS's built-in YARA matches, joined to yara.csv's rows.

MemProcFS's forensic yara.csv has no column for the rule that matched: its "Description" is the
rule's ``description`` metadata, which Elastic's rules mostly lack, so a row says where something
matched but not what. The rule's name, its metadata (``threat_name``, ``severity``...), the process
or file object and every matched string with a hexdump around it are in
``\\forensic\\findevil\\yara.txt``, one record per match; the source of each rule that matched is in
``yara_rules.txt``. memprocfs_findevil saves both next to the CSVs, and this joins them to the CSV
rows by match index -- the same number FindEvil's YR_* rows end with ("<rule> [<index>]").

Record format (MemProcFS vmmyarautil.c), records separated by a line of dashes:

    Match Index:  0
    Rule:         Windows_Trojan_Example_1a2b3c4d
    Tags:         tag1, tag2
    Author:       Elastic Security        <- one line per metadata entry
    Threat_name:  Windows.Trojan.Example
    Memory Type:  Virtual Memory (VAD)    <- or "Type:  Object Memory" / "Type:  Physical Memory"
    ...
    Matches:
    [$a1]: 7ff6d1a01234
    ...hexdump...
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

YARA_TEXT = "yara.txt"
YARA_RULES = "yara_rules.txt"
_SEPARATOR = re.compile(r"^-{20,}\s*$", re.M)
_FIELD = re.compile(r"^([A-Za-z][A-Za-z0-9_ ]*?):\s+(.*)$")
# Lines that start the memory/process/match part of a record: metadata ends there.
_SECTION_STARTS = ("Type:", "Memory Type:", "Memory Tag:", "Base Address:", "PID:", "Matches:")
_RULE_HEAD = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)
_MAX_DETAILS = 16 * 1024
_MAX_RULE = 32 * 1024


def parse_records(text: str) -> dict[str, dict[str, Any]]:
    """{match index: {"rule", "tags", "meta": {name: value}, "details": record text}}."""
    records: dict[str, dict[str, Any]] = {}
    for block in _SEPARATOR.split(text):
        block = block.strip("\n")
        if not block.strip():
            continue
        lines = block.splitlines()
        header: dict[str, str] = {}
        meta: dict[str, str] = {}
        in_meta = False
        for line in lines:
            if line.startswith(_SECTION_STARTS):
                break
            match = _FIELD.match(line)
            if not match:
                continue
            name, value = match.group(1).strip(), match.group(2).strip()
            if not in_meta and name in ("Match Index", "Rule", "Tags"):
                header[name] = value
                in_meta = name == "Tags"
                continue
            if in_meta:
                meta[name.lower()] = value
        index = header.get("Match Index")
        if index is None or not header.get("Rule"):
            continue
        records[index] = {"rule": header["Rule"], "tags": header.get("Tags", ""), "meta": meta, "details": block[:_MAX_DETAILS]}
    return records


def parse_rules(text: str) -> dict[str, str]:
    """{rule name: its source} from yara_rules.txt."""
    heads = list(_RULE_HEAD.finditer(text))
    rules: dict[str, str] = {}
    for position, head in enumerate(heads):
        end = heads[position + 1].start() if position + 1 < len(heads) else len(text)
        rules[head.group(1)] = text[head.start():end].strip()[:_MAX_RULE]
    return rules


@lru_cache(maxsize=16)
def _load(directory: str, mtimes: tuple[float, float]) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    base = Path(directory)
    records = parse_records((base / YARA_TEXT).read_text(encoding="utf-8", errors="replace")) if (base / YARA_TEXT).is_file() else {}
    rules = parse_rules((base / YARA_RULES).read_text(encoding="utf-8", errors="replace")) if (base / YARA_RULES).is_file() else {}
    return records, rules


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def matched_strings(row: dict[str, str]) -> str:
    """yara.csv keeps up to five matched strings, each with its address."""
    parts = []
    for slot in range(5):
        value = (row.get(f"String{slot}") or "").strip()
        address = (row.get(f"Address{slot}") or "").strip()
        if value:
            parts.append(f"{value} @ {address}" if address else value)
    count = (row.get("AddressCount") or "").strip()
    if count.isdigit() and int(count) > len(parts) and parts:
        parts.append(f"(+{int(count) - len(parts)} more)")
    return "; ".join(parts)


def enrich(rows: list[dict[str, str]], directory: Path) -> list[dict[str, str]]:
    """yara.csv's rows with the rule, threat, severity, all matched strings, the location and,
    in ``_details`` / ``_rule_source``, the full record and the rule's source."""
    records, rules = _load(str(directory), (_mtime(directory / YARA_TEXT), _mtime(directory / YARA_RULES)))
    enriched = []
    for row in rows:
        record = records.get((row.get("MatchIndex") or "").strip()) or {}
        meta = record.get("meta") or {}
        rule = record.get("rule") or ""
        process = (row.get("ProcessName") or "").strip()
        location = f"{process} ({row.get('PID')})" if process else (row.get("MemoryTag") or row.get("MemoryType") or "").strip()
        enriched.append({
            **row,
            "Rule": rule or (row.get("Description") or "").strip(),
            "Threat": meta.get("threat_name", ""),
            "Severity": meta.get("severity", ""),
            "Location": location,
            "Strings": matched_strings(row),
            "_details": record.get("details", ""),
            "_rule_source": rules.get(rule, "") if rule else "",
        })
    return enriched
