"""Netfilter (iptables / ufw / firewalld) log lines. All addresses are documentation ranges."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import yaml

from app.core import opensearch as os_module
from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.linux.journal import _row_from_fields
from app.ingest.linux.netfilter import parse_netfilter
from app.ingest.linux.syslog import parse_syslog
from app.ingest.normalizer import base_document

UFW_BLOCK = (
    "[12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00 SRC=203.0.113.9 DST=192.0.2.10 "
    "LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 DF PROTO=TCP SPT=51234 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0"
)
FIREWALLD_REJECT = "FINAL_REJECT: IN=eth0 OUT= SRC=198.51.100.7 DST=192.0.2.10 LEN=76 TTL=64 PROTO=UDP SPT=5353 DPT=5353 LEN=56"
IPV6_DROP = "IPTABLES-DROPPED: IN= OUT=eth1 SRC=2001:db8::1 DST=2001:db8::2 PROTO=ICMPv6 TYPE=128 CODE=0"
UFW_ALLOW = "[UFW ALLOW] IN=lo OUT= SRC=127.0.0.1 DST=127.0.0.1 PROTO=TCP SPT=40000 DPT=80 ACK PSH"


def _syslog_line(message: str, process: str = "kernel") -> str:
    return f"Mar  1 10:20:30 web01 {process}: {message}"


def _doc(row: dict) -> dict:
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": row["artifact_family"]})
    return normalize_linux_row(base, row, source_path=row.get("source_file") or row.get("source_path", ""), artifact_type=row["artifact_family"])


# ------------------------------------------------------------------- extraction

def test_ufw_block_line():
    packet = parse_netfilter(UFW_BLOCK)
    assert packet == {
        "firewall_action": "block", "firewall_prefix": "[UFW BLOCK]",
        "source_ip": "203.0.113.9", "destination_ip": "192.0.2.10", "source_port": 51234, "destination_port": 22,
        "network_protocol": "tcp", "interface_in": "eth0", "interface_out": "", "tcp_flags": ["SYN"],
    }


def test_firewalld_reject_uses_the_ip_level_length_and_udp_ports():
    packet = parse_netfilter(FIREWALLD_REJECT)
    assert (packet["firewall_action"], packet["network_protocol"], packet["destination_port"]) == ("reject", "udp", 5353)
    assert packet["tcp_flags"] == []


def test_ipv6_and_icmp_without_ports():
    packet = parse_netfilter(IPV6_DROP)
    assert (packet["source_ip"], packet["destination_ip"], packet["network_protocol"]) == ("2001:db8::1", "2001:db8::2", "icmpv6")
    assert packet["source_port"] is None and packet["destination_port"] is None
    assert (packet["interface_in"], packet["interface_out"]) == ("", "eth1")


def test_allow_and_flags():
    packet = parse_netfilter(UFW_ALLOW)
    assert packet["firewall_action"] == "allow" and packet["tcp_flags"] == ["ACK", "PSH"]


@pytest.mark.parametrize(
    "prefix, action",
    [("[UFW BLOCK]", "block"), ("[UFW AUDIT]", "audit"), ("[UFW LIMIT BLOCK]", "block"), ("DROP:", "drop"),
     ("REJECT_IN:", "reject"), ("ACCEPTED ", "allow"), ("my-custom-prefix: ", "log"), ("", "log")],
)
def test_verdict_comes_from_the_log_prefix(prefix, action):
    line = f"{prefix} IN=eth0 OUT= SRC=203.0.113.9 DST=192.0.2.10 PROTO=TCP SPT=1 DPT=2"
    assert parse_netfilter(line)["firewall_action"] == action


@pytest.mark.parametrize(
    "message",
    [
        "eth0: link is up", "SRC=203.0.113.9 and nothing else", "Failed password for root from 203.0.113.9 port 22 ssh2",
        "IN=eth0 SRC= DST=192.0.2.10 PROTO=TCP", "SRC=203.0.113.9 DST=192.0.2.10 with no protocol or interface",
    ],
)
def test_other_text_is_not_mistaken_for_a_packet(message):
    assert parse_netfilter(message) is None


def test_out_of_range_ports_are_ignored():
    packet = parse_netfilter("IN=eth0 OUT= SRC=203.0.113.9 DST=192.0.2.10 PROTO=TCP SPT=99999 DPT=22")
    assert packet["source_port"] is None and packet["destination_port"] == 22


# ------------------------------------------------------------------- the parsers

def test_syslog_parser_expands_netfilter_lines_and_leaves_others_alone():
    rows = parse_syslog("\n".join([_syslog_line(UFW_BLOCK), _syslog_line("eth0: link is up")]), source_path="var/log/kern.log")
    assert rows[0]["firewall_action"] == "block" and rows[0]["destination_port"] == 22
    assert rows[0]["process"] == "kernel" and rows[0]["timestamp"] is not None
    assert "firewall_action" not in rows[1]


def test_journal_rows_are_expanded_too():
    row = _row_from_fields({"MESSAGE": UFW_BLOCK, "SYSLOG_IDENTIFIER": "kernel", "__REALTIME_TIMESTAMP": "1709288430123456"}, "journal.export")
    assert row["source_ip"] == "203.0.113.9" and row["firewall_action"] == "block"
    plain = _row_from_fields({"MESSAGE": "hello"}, "journal.export")
    assert "firewall_action" not in plain


@pytest.mark.parametrize("path", ["var/log/ufw.log", "var/log/ufw.log.1", "var/log/ufw.log.2.gz", "var/log/iptables.log"])
def test_ufw_and_iptables_logs_are_detected_as_syslog(path):
    assert looks_like_linux_artifact(path)[0] == "linux_syslog" and looks_like_linux_artifact(path)[2] == "linux_syslog_raw"


# ------------------------------------------------------------------ normalizing

def test_firewall_rows_fill_the_network_fields():
    row = parse_syslog(_syslog_line(UFW_BLOCK), source_path="var/log/ufw.log")[0]
    doc = _doc(row)
    assert doc["network"]["source_ip"] == "203.0.113.9" and doc["network"]["source_port"] == 51234
    assert doc["network"]["destination_ip"] == "192.0.2.10" and doc["network"]["destination_port"] == 22
    assert doc["network"]["protocol"] == "tcp"
    assert doc["destination"]["ip"] == "192.0.2.10" and doc["destination"]["port"] == 22
    assert doc["event"]["action"] == "firewall_block" and doc["event"]["outcome"] == "failure"
    assert doc["title"] == "Firewall block: 203.0.113.9:51234 -> 192.0.2.10:22 (tcp)"
    assert doc["linux"]["firewall_action"] == "block" and doc["linux"]["interface_in"] == "eth0"


def test_allow_is_a_success_and_plain_syslog_is_untouched():
    allow = _doc(parse_syslog(_syslog_line(UFW_ALLOW), source_path="var/log/ufw.log")[0])
    assert allow["event"]["outcome"] == "success"
    plain = _doc(parse_syslog(_syslog_line("eth0: link is up"), source_path="var/log/kern.log")[0])
    assert not plain["network"].get("source_ip") and plain["event"]["action"] != "firewall_log"


def test_a_ufw_block_is_searchable_text():
    doc = _doc(parse_syslog(_syslog_line(UFW_BLOCK), source_path="var/log/ufw.log")[0])
    assert "203.0.113.9" in doc["search_text"] and "block" in doc["search_text"]


def test_sigma_keyword_rule_for_syslog_fires_on_a_firewall_line():
    from app.rules_engine.sigma import compile_sigma_rule, evaluate_compiled_sigma_rule

    rule = yaml.safe_load("""
title: UFW blocks
logsource: {product: linux, service: syslog}
detection:
  keywords:
    - 'UFW BLOCK'
  condition: keywords
""")
    compiled = compile_sigma_rule(rule)
    hit = _doc(parse_syslog(_syslog_line(UFW_BLOCK), source_path="var/log/ufw.log")[0])
    miss = _doc(parse_syslog(_syslog_line(UFW_ALLOW), source_path="var/log/ufw.log")[0])
    assert evaluate_compiled_sigma_rule(compiled, hit)["matched"] is True
    assert evaluate_compiled_sigma_rule(compiled, miss)["matched"] is False


# -------------------------------------------------------------------- index map

@pytest.mark.parametrize("exists", [False, True], ids=["new-index", "existing-index-backfill"])
def test_firewall_fields_are_declared_in_the_index_mapping(monkeypatch, exists):
    client = MagicMock()
    monkeypatch.setattr(os_module, "get_opensearch_client", lambda **_: client)
    monkeypatch.setattr(os_module, "index_exists", lambda *_a, **_k: exists)
    monkeypatch.setattr(os_module, "_apply_safe_index_settings", lambda *_a, **_k: None, raising=False)
    os_module.ensure_case_index("11111111-1111-4111-8111-111111111111")
    call = client.indices.put_mapping if exists else client.indices.create
    properties = call.call_args.kwargs["body"].get("mappings", call.call_args.kwargs["body"])["properties"]["linux"]["properties"]
    assert {"firewall_action", "destination_ip", "network_protocol", "interface_in", "interface_out"} <= set(properties)
