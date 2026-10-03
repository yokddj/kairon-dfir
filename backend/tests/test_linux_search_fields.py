"""Search syntax: Linux fields and the shortcuts that make an address / process search find Linux events."""
from __future__ import annotations

import pytest

from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.apache import parse_apache
from app.ingest.linux.auth import parse_auth
from app.ingest.linux.fail2ban import parse_fail2ban
from app.ingest.linux.syslog import parse_syslog
from app.ingest.normalizer import base_document
from app.search.query_syntax import FIELD_ALIASES, FIELD_SPECS, QuerySyntaxError, SEARCH_SYNTAX_EXAMPLES, analyze_query_syntax


def _query(text: str) -> dict:
    return analyze_query_syntax(text, lambda value: {"simple_query_string": {"query": value}})["query"]


def _terms(query: dict) -> set[tuple[str, str]]:
    """Every (field, value) of the term clauses in a built query."""
    found: set[tuple[str, str]] = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "term" and isinstance(value, dict):
                    for field, expected in value.items():
                        found.add((field, str(expected.get("value") if isinstance(expected, dict) else expected)))
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(query)
    return found


def _doc(row: dict) -> dict:
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": row["artifact_family"]})
    return normalize_linux_row(base, row, source_path=row["source_file"], artifact_type=row["artifact_family"])


# ------------------------------------------------------------- the new fields

@pytest.mark.parametrize(
    "text, field",
    [
        ("linux.jail:sshd", "linux.jail"),
        ("linux.firewall_action:block", "linux.firewall_action"),
        ("linux.x_forwarded_for:198.51.100.77", "linux.x_forwarded_for"),
        ("linux.web_server:nginx", "linux.web_server"),
        ("linux.suspicious_indicators:reverse_shell", "linux.suspicious_indicators"),
        ("linux.audit_type:EXECVE", "linux.audit_type"),
        ("linux.timestamp_status:assumed_utc", "linux.timestamp_status"),
        ("network.source_ip:203.0.113.9", "network.source_ip"),
        ("network.destination_port:22", "network.destination_port"),
    ],
)
def test_linux_and_network_fields_are_queryable(text, field):
    assert any(f == field for f, _ in _terms(_query(text)))


@pytest.mark.parametrize(
    "alias, expected",
    [
        ("jail:sshd", {"linux.jail"}),
        ("verdict:block", {"linux.firewall_action"}),
        ("xff:198.51.100.77", {"linux.x_forwarded_for"}),
        ("webserver:nginx", {"linux.web_server"}),
        ("indicator:reverse_shell", {"linux.suspicious_indicators"}),
        ("audit:EXECVE", {"linux.audit_type"}),
        ("timequality:assumed_utc", {"linux.timestamp_status"}),
        ("proto:tcp", {"network.protocol", "linux.network_protocol"}),
        ("port:22", {"network.source_port", "network.destination_port"}),
    ],
)
def test_shortcuts_reach_the_linux_fields(alias, expected):
    assert {field for field, _ in _terms(_query(alias))} == expected


# ----------------------------------------------- the searches that missed events

def test_an_ip_search_covers_every_place_an_address_is_stored():
    fields = {field for field, _ in _terms(_query("ip:203.0.113.9"))}
    assert {"source.ip", "destination.ip", "network.source_ip", "network.destination_ip", "linux.source_ip", "linux.destination_ip"} <= fields


def test_process_user_and_host_shortcuts_also_search_the_linux_fields():
    assert {"process.name", "linux.process"} == {f for f, _ in _terms(_query("process:sshd"))}
    assert {"user.name", "linux.username"} == {f for f, _ in _terms(_query("user:alice"))}
    assert {"host.name", "linux.hostname"} == {f for f, _ in _terms(_query("host:web01"))}


def test_every_field_an_ip_search_reads_exists_on_the_events_it_must_find():
    """The addresses really sit where the shortcut looks, for the events that motivated it."""
    nginx = _doc(parse_apache('203.0.113.9 - - [01/Mar/2024:10:20:30 +0000] "GET / HTTP/1.1" 200 5 "-" "ua"', source_path="var/log/nginx/access.log")[0])
    ufw = _doc(parse_syslog("Mar  1 10:20:30 h kernel: [1.2] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=192.0.2.10 PROTO=TCP SPT=1 DPT=22", source_path="var/log/ufw.log")[0])
    ban = _doc(parse_fail2ban("2024-03-01 10:20:31,456 fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.9", source_path="var/log/fail2ban.log")[0])
    auth = _doc(parse_auth("Mar  1 10:20:30 h sshd[411]: Failed password for root from 203.0.113.9 port 51234 ssh2", source_path="var/log/auth.log")[0])
    for name, doc in {"nginx": nginx, "ufw": ufw, "fail2ban": ban, "auth": auth}.items():
        assert doc["network"]["source_ip"] == "203.0.113.9", name
    assert auth["network"]["source_port"] == 51234


def test_auth_event_without_an_address_leaves_the_field_unset():
    doc = _doc(parse_auth("Mar  1 10:20:30 h sshd[411]: pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)", source_path="var/log/auth.log")[0])
    assert not doc["network"].get("source_ip")


# ----------------------------------------------------------------- regressions

def test_unknown_fields_are_still_rejected():
    with pytest.raises(QuerySyntaxError):
        _query("not.a.field:x")


def test_existing_fields_and_aliases_keep_their_meaning():
    assert _terms(_query("artifact.type:linux_auth")) == {("artifact.type", "linux_auth")}
    assert {"host.name", "user.name", "process.name", "source.ip", "destination.ip"} <= set(FIELD_SPECS)
    assert FIELD_ALIASES["file"] == ["file.path", "file.name"]


def test_every_alias_points_only_at_declared_fields():
    for alias, targets in FIELD_ALIASES.items():
        assert all(target in FIELD_SPECS for target in targets), alias


def test_the_help_examples_all_parse():
    for example in SEARCH_SYNTAX_EXAMPLES:
        assert analyze_query_syntax(example, lambda value: {"simple_query_string": {"query": value}})["query"]


def test_the_ai_query_help_names_the_shortcuts():
    from app.services.ai.tools import QUERY_HELP

    for shortcut in ("verdict:", "jail:", "xff:", "indicator:", "ip:"):
        assert shortcut in QUERY_HELP
