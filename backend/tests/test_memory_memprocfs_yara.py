"""YARA matches show the rule, threat and matched strings MemProcFS keeps outside yara.csv.

Samples follow MemProcFS's own format (vmmyarautil.c): yara.csv has no rule column; yara.txt has
one record per match; yara_rules.txt the source of each rule that matched. Synthetic content.
"""

from __future__ import annotations

from pathlib import Path

from app.services.memory.memprocfs_findevil import FINDEVIL_TEXT_FILES, with_yara_threats
from app.services.memory.memprocfs_tables import TABLES_BY_KEY, table_rows
from app.services.memory.memprocfs_yara import enrich, matched_strings, parse_records, parse_rules

HEADER = "MatchIndex,Tags,Description,RuleAuthor,RuleVersion,MemoryType,MemoryTag,MemoryBaseAddress,ObjectAddress,PID,ProcessName,ProcessPath,CommandLine,User,Created,AddressCount,String0,Address0,String1,Address1,String2,Address2,String3,Address3,String4,Address4\n"
CSV = HEADER + (
    '0,"","","","",Object Memory,FILE:[\\Windows\\System32\\example.dll],"",ffffa0011d2e3f40,"","","","","","",1,\\IronPython.,ffffa0011d2e4000,"","","","","","","",""\n'
    '1,"","","Elastic Security","",Virtual Memory (VAD),Private,7ff6d1a00000,"",4242,rundll32.exe,\\Device\\HarddiskVolume3\\Windows\\System32\\rundll32.exe,"rundll32.exe x.dll,Start",DESKTOP\\user,2026-11-01 10:00:00 UTC,7,$a1,7ff6d1a01234,$a2,7ff6d1a05678,"","","","","",""\n'
)
SEPARATOR = "-" * 87
TEXT = f"""Match Index:  0
Rule:         Windows_Hacktool_Example_0aa1b2c3
Tags:         
Author:       Elastic Security
Threat_name:  Windows.Hacktool.Example
Severity:     60
Type:         Object Memory
Memory Tag:   FILE:[\\Windows\\System32\\example.dll]
Base Address: 0xffffa0011d2e3f40

Matches:
[string_0]: ffffa0011d2e4000

[string_0] ffffa0011d2e4000 (FILE):
Plain: "\\IronPython.Modules"
{SEPARATOR}

Match Index:  1
Rule:         Windows_Trojan_Example_1a2b3c4d
Tags:         memory, beacon
Author:       Elastic Security
Threat_name:  Windows.Trojan.Example
Severity:     100
Memory Type:  Virtual Memory (VAD)
Memory Tag:   Private
Base Address: 0x00007ff6d1a00000
PID:          4242
Process Name: rundll32.exe

Matches:
[$a1]: 7ff6d1a01234
[$a2]: 7ff6d1a05678
{SEPARATOR}

"""
RULES = """rule Windows_Hacktool_Example_0aa1b2c3 {
    meta:
        threat_name = "Windows.Hacktool.Example"
    strings:
        $a = "\\\\IronPython."
    condition:
        all of them
}


rule Windows_Trojan_Example_1a2b3c4d {
    meta:
        threat_name = "Windows.Trojan.Example"
    strings:
        $a1 = { 4D 5A }
        $a2 = { 50 45 }
    condition:
        all of them
}
"""


def _directory(tmp_path: Path, *, with_text: bool = True) -> Path:
    (tmp_path / "yara.csv").write_text(CSV, encoding="utf-8")
    if with_text:
        (tmp_path / "yara.txt").write_text(TEXT, encoding="utf-8")
        (tmp_path / "yara_rules.txt").write_text(RULES, encoding="utf-8")
    return tmp_path


def test_records_and_rules_are_parsed():
    records = parse_records(TEXT)
    assert records["0"]["rule"] == "Windows_Hacktool_Example_0aa1b2c3"
    assert records["1"]["meta"] == {"author": "Elastic Security", "threat_name": "Windows.Trojan.Example", "severity": "100"}
    assert records["1"]["tags"] == "memory, beacon"
    assert "[$a2]: 7ff6d1a05678" in records["1"]["details"]
    rules = parse_rules(RULES)
    assert set(rules) == {"Windows_Hacktool_Example_0aa1b2c3", "Windows_Trojan_Example_1a2b3c4d"}
    assert rules["Windows_Trojan_Example_1a2b3c4d"].startswith("rule Windows_Trojan_Example_1a2b3c4d")


def test_the_yara_table_names_the_rule_threat_and_every_string(tmp_path):
    rows, hidden = table_rows(_directory(tmp_path), TABLES_BY_KEY["yara"])
    assert hidden == 0
    file_match, process_match = rows
    assert file_match["Rule"] == "Windows_Hacktool_Example_0aa1b2c3" and file_match["Threat"] == "Windows.Hacktool.Example"
    assert file_match["Location"] == "FILE:[\\Windows\\System32\\example.dll]" and file_match["MemoryType"] == "Object Memory"
    assert process_match["Location"] == "rundll32.exe (4242)" and process_match["Severity"] == "100"
    assert process_match["Strings"] == "$a1 @ 7ff6d1a01234; $a2 @ 7ff6d1a05678; (+5 more)"
    assert "IronPython.Modules" in file_match["_details"] and "$a2 = { 50 45 }" in process_match["_rule_source"]
    shown = {column for column, _label in TABLES_BY_KEY["yara"].columns}
    assert {"Rule", "Threat", "Severity", "Location", "Strings"} <= shown


def test_without_yara_txt_the_csv_is_still_shown(tmp_path):
    rows, _hidden = table_rows(_directory(tmp_path, with_text=False), TABLES_BY_KEY["yara"])
    assert [row["Rule"] for row in rows] == ["", ""] and rows[1]["Strings"].startswith("$a1 @")
    assert rows[0]["_details"] == "" and rows[0]["_rule_source"] == ""


def test_matched_strings_without_addresses():
    assert matched_strings({"String0": "abc", "AddressCount": "1"}) == "abc"
    assert matched_strings({}) == ""


def test_findevil_yara_rows_get_the_threat():
    rows = [
        {"PID": "4242", "Process": "rundll32.exe", "Type": "YR_TROJAN", "Address": "7ff6d1a01234", "Description": "Windows_Trojan_Example_1a2b3c4d [1]"},
        {"PID": "4242", "Process": "rundll32.exe", "Type": "PRIVATE_RWX", "Address": "7ff6d1a00000", "Description": "[1]"},
    ]
    out = with_yara_threats(rows, TEXT)
    assert out[0]["Description"] == "Windows_Trojan_Example_1a2b3c4d [1] -- threat Windows.Trojan.Example, severity 100"
    assert out[1] == rows[1]
    assert with_yara_threats(rows, "") == rows


def test_the_child_saves_the_yara_text_files():
    assert FINDEVIL_TEXT_FILES == ("yara.txt", "yara_rules.txt")


def test_enrich_keeps_a_row_whose_record_is_missing(tmp_path):
    (tmp_path / "yara.txt").write_text(TEXT, encoding="utf-8")
    rows = enrich([{"MatchIndex": "9", "Description": "a description", "String0": "x"}], tmp_path)
    assert rows[0]["Rule"] == "a description" and rows[0]["Threat"] == ""
