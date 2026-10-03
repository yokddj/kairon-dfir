"""Sigma `webserver` rules over Apache / nginx access logs. Rules and requests are synthetic."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
import yaml

from app.core import opensearch as os_module
from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.apache import parse_apache
from app.ingest.linux.syslog import parse_syslog
from app.ingest.normalizer import base_document
from app.rules_engine.sigma import (
    MAX_LINUX_CANDIDATE_CLAUSES,
    SIGMA_FIELD_MAP,
    build_sigma_case_profile,
    build_sigma_query_from_compiled,
    compile_sigma_rule,
    evaluate_compiled_sigma_rule,
    preflight_sigma_rule,
)


def _line(method="GET", target="/index.html", status=200, referrer="-", agent="Mozilla/5.0", user="-", ip="203.0.113.9") -> str:
    return f'{ip} - {user} [01/Mar/2024:10:20:30 +0000] "{method} {target} HTTP/1.1" {status} 512 "{referrer}" "{agent}"'


def _doc(line: str, path: str = "var/log/nginx/access.log") -> dict:
    row = parse_apache(line, source_path=path)[0]
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": row["artifact_family"]})
    return normalize_linux_row(base, row, source_path=row["source_file"], artifact_type=row["artifact_family"])


def _compiled(text: str) -> dict:
    compiled = compile_sigma_rule(yaml.safe_load(text))
    assert compiled["compile_status"] == "compiled", compiled.get("compile_error")
    return compiled


def _fires(rule_text: str, doc: dict) -> bool:
    return bool(evaluate_compiled_sigma_rule(_compiled(rule_text), doc)["matched"])


TRAVERSAL = """
title: Path traversal in a request
logsource: {category: webserver}
detection:
  selection:
    cs-method: GET
    cs-uri-query|contains: ['../', '..%2f']
  condition: selection
level: high
"""
WEBSHELL = """
title: POST to a script returning 200
logsource: {category: webserver}
detection:
  selection:
    cs-method: POST
    cs-uri-stem|endswith: '.php'
    sc-status: 200
  condition: selection
"""
SCANNER = """
title: Scanner user agent
logsource: {category: webserver}
detection:
  selection:
    cs-user-agent|contains: ['sqlmap', 'nikto']
  condition: selection
"""


# ------------------------------------------------------------- the URL split

@pytest.mark.parametrize(
    "target, stem, query",
    [
        ("/a/b.php?x=1&y=2", "/a/b.php", "x=1&y=2"),
        ("/index.html", "/index.html", ""),
        ("/p?redirect=/a?b=c", "/p", "redirect=/a?b=c"),
        ("/trailing?", "/trailing", ""),
        ("/?q=%2e%2e%2f", "/", "q=%2e%2e%2f"),
    ],
)
def test_the_request_target_is_split_at_the_first_question_mark(target, stem, query):
    doc = _doc(_line(target=target))
    assert (doc["linux"]["url_stem"], doc["linux"]["url_query"]) == (stem, query)
    assert doc["linux"]["url_path"] == target and doc["url"]["path"] == target
    assert doc["url"]["query"] == (query or None)


def test_json_access_lines_are_split_too():
    record = json.dumps({"time_iso8601": "2024-03-01T10:20:30+00:00", "remote_addr": "203.0.113.9", "request": "GET /a.php?id=1 HTTP/1.1", "status": 200})
    doc = _doc(record)
    assert (doc["linux"]["url_stem"], doc["linux"]["url_query"]) == ("/a.php", "id=1")


# --------------------------------------------------------------- field mapping

@pytest.mark.parametrize(
    "field, expected",
    [
        ("cs-method", {"http.request.method", "linux.http_method"}),
        ("sc-status", {"http.response.status_code", "linux.http_status"}),
        ("cs-uri-stem", {"linux.url_stem"}),
        ("cs-uri-query", {"linux.url_query"}),
        ("cs-user-agent", {"user_agent.original", "linux.http_user_agent"}),
        ("c-useragent", {"user_agent.original", "linux.http_user_agent"}),
        ("cs-referer", {"linux.http_referrer"}),
        ("c-ip", {"network.source_ip", "source.ip", "linux.source_ip"}),
    ],
)
def test_w3c_names_map_to_the_web_fields(field, expected):
    assert set(SIGMA_FIELD_MAP[field]) == expected


# --------------------------------------------------------------------- matching

def test_a_traversal_rule_fires_on_the_query_only():
    assert _fires(TRAVERSAL, _doc(_line(target="/download?file=../../etc/passwd"))) is True
    assert _fires(TRAVERSAL, _doc(_line(target="/download?file=..%2f..%2fetc"))) is True
    assert _fires(TRAVERSAL, _doc(_line(target="/safe/../path.html"))) is False  # in the stem, not the query
    assert _fires(TRAVERSAL, _doc(_line(method="POST", target="/x?f=../"))) is False  # the method is part of the rule


def test_a_webshell_rule_uses_method_stem_and_status():
    assert _fires(WEBSHELL, _doc(_line(method="POST", target="/up/shell.php?cmd=id", status=200))) is True
    assert _fires(WEBSHELL, _doc(_line(method="POST", target="/up/shell.php", status=403))) is False
    assert _fires(WEBSHELL, _doc(_line(method="GET", target="/up/shell.php", status=200))) is False
    assert _fires(WEBSHELL, _doc(_line(method="POST", target="/up/page.html", status=200))) is False


def test_the_user_agent_is_matched_without_regard_to_case():
    assert _fires(SCANNER, _doc(_line(agent="SQLMap/1.7.2#stable"))) is True
    assert _fires(SCANNER, _doc(_line(agent="Mozilla/5.0 (X11) Nikto/2.5"))) is True
    assert _fires(SCANNER, _doc(_line(agent="Mozilla/5.0"))) is False


def test_status_lists_and_the_client_address():
    rule = """
title: Server errors from one address
logsource: {category: webserver}
detection:
  selection:
    sc-status: [500, 502, 503]
    c-ip: '203.0.113.9'
  condition: selection
"""
    assert _fires(rule, _doc(_line(status=502))) is True
    assert _fires(rule, _doc(_line(status=200))) is False
    assert _fires(rule, _doc(_line(status=502, ip="198.51.100.7"))) is False


def test_referrer_and_username_fields():
    rule = """
title: Request referred from a documentation host by a named user
logsource: {category: webserver}
detection:
  selection:
    cs-referer|startswith: 'https://phish.example.test'
    cs-username: alice
  condition: selection
"""
    assert _fires(rule, _doc(_line(referrer="https://phish.example.test/login", user="alice"))) is True
    assert _fires(rule, _doc(_line(referrer="https://good.example.test/", user="alice"))) is False


def test_it_works_on_apache_logs_as_well():
    assert _fires(SCANNER, _doc(_line(agent="nikto"), path="var/log/apache2/access.log")) is True


# ------------------------------------------------------------- the logsource gate

def test_error_log_lines_are_not_requests():
    error = _doc("2024/03/01 10:20:30 [error] 7#8: *1 open() failed, client: 203.0.113.9, server: x, request: \"GET /a?../ HTTP/1.1\", host: \"x\"", path="var/log/nginx/error.log")
    result = evaluate_compiled_sigma_rule(_compiled(TRAVERSAL), error)
    assert result["matched"] is False and result.get("skip_reason") == "logsource_mismatch"


def test_other_log_types_are_not_tested_against_web_rules():
    syslog = parse_syslog("Mar  1 10:20:30 h app[1]: GET /x?../ from 203.0.113.9", source_path="var/log/syslog")[0]
    base = base_document("c", "e", "a", syslog, {"artifact_type": "linux_syslog"})
    doc = normalize_linux_row(base, syslog, source_path="var/log/syslog", artifact_type="linux_syslog")
    result = evaluate_compiled_sigma_rule(_compiled(TRAVERSAL), doc)
    assert result["matched"] is False and result.get("skip_reason") in {"logsource_mismatch", "missing_logsource_fields"}


# --------------------------------------------------------------------- preflight

def _case(*lines: str, path: str = "var/log/nginx/access.log") -> dict:
    return build_sigma_case_profile([_doc(line, path) for line in lines])


def test_a_web_case_lets_web_rules_run():
    profile = _case(_line(), _line(method="POST", target="/p.php?id=1", status=500, referrer="https://example.test/", agent="UA/1", user="alice"))
    for rule in (TRAVERSAL, WEBSHELL, SCANNER):
        assert preflight_sigma_rule(yaml.safe_load(rule), profile)["status"].startswith("runnable"), rule


def test_a_rule_is_skipped_when_the_log_never_records_what_it_needs():
    rule = """
title: Needs the Host header
logsource: {category: webserver}
detection:
  selection:
    cs-host|re: '.{150}'
  condition: selection
"""
    assert preflight_sigma_rule(yaml.safe_load(rule), _case(_line()))["status"] == "skipped_missing_fields"


# ------------------------------------------------------------- candidate query

def _clauses(rule_text: str) -> list[dict]:
    return build_sigma_query_from_compiled(_compiled(rule_text))["query"]["bool"]["should"]


def test_linux_field_candidates_are_case_insensitive():
    clauses = _clauses(SCANNER)
    wild = [c["wildcard"]["linux.http_user_agent"] for c in clauses if "wildcard" in c and "linux.http_user_agent" in c["wildcard"]]
    assert sorted(w["value"] for w in wild) == ["*nikto*", "*sqlmap*"] and all(w["case_insensitive"] is True for w in wild)


def test_each_modifier_gets_its_clause_shape():
    rule = """
title: shapes
logsource: {category: webserver}
detection:
  selection:
    cs-uri-stem|startswith: '/admin'
    cs-uri-stem|endswith: '.php'
    cs-uri-query|re: 'id=[0-9]+'
    cs-method: DELETE
  condition: selection
"""
    kinds = {next(iter(c)) for c in _clauses(rule)}
    assert {"prefix", "wildcard", "regexp", "term"} <= kinds
    assert all(next(iter(c.values())).get("linux.url_stem", {}).get("case_insensitive", True) for c in _clauses(rule) if "linux.url_stem" in next(iter(c.values())))


def test_every_value_of_a_long_list_reaches_the_query():
    values = [f"agent-number-{i:03d}" for i in range(120)]
    rule = yaml.safe_dump({"title": "many", "logsource": {"category": "webserver"}, "detection": {"selection": {"cs-user-agent|contains": values}, "condition": "selection"}})
    wanted = {f"*{v}*" for v in values}
    got = {c["wildcard"]["linux.http_user_agent"]["value"] for c in _clauses(rule) if "wildcard" in c and "linux.http_user_agent" in c["wildcard"]}
    assert wanted == got


def test_too_many_values_fall_back_to_a_safe_broader_clause():
    values = [f"v{i}" for i in range(MAX_LINUX_CANDIDATE_CLAUSES + 50)]
    rule = yaml.safe_dump({"title": "huge", "logsource": {"category": "webserver"}, "detection": {"selection": {"cs-uri-query|contains": values}, "condition": "selection"}})
    assert _clauses(rule) == [{"exists": {"field": "linux.url_query"}}]


def test_a_backslash_in_a_value_is_escaped_for_the_wildcard():
    rule = yaml.safe_dump({"title": "bs", "logsource": {"category": "webserver"}, "detection": {"selection": {"cs-uri-query|contains": "a\\b"}, "condition": "selection"}})
    assert _clauses(rule)[0]["wildcard"]["linux.url_query"]["value"] == "*a\\\\b*"


def test_queries_on_non_linux_fields_are_unchanged():
    """Only linux.* keyword fields get case-insensitive clauses; a Windows field keeps its shape."""
    rule = """
title: windows style
logsource: {category: process_creation, product: windows}
detection:
  selection:
    Image|endswith: '\\\\cmd.exe'
  condition: selection
"""
    seen = 0
    for clause in _clauses(rule):
        body = next(iter(clause.values()))
        for field, value in body.items():
            if field.startswith("process."):
                seen += 1
                assert not (isinstance(value, dict) and "case_insensitive" in value)
    assert seen >= 2


# ---------------------------------------------------------------------- mapping

@pytest.mark.parametrize("exists", [False, True], ids=["new-index", "existing-index-backfill"])
def test_web_fields_are_declared_in_the_index_mapping(monkeypatch, exists):
    client = MagicMock()
    monkeypatch.setattr(os_module, "get_opensearch_client", lambda **_: client)
    monkeypatch.setattr(os_module, "index_exists", lambda *_a, **_k: exists)
    monkeypatch.setattr(os_module, "_apply_safe_index_settings", lambda *_a, **_k: None, raising=False)
    os_module.ensure_case_index("11111111-1111-4111-8111-111111111111")
    call = client.indices.put_mapping if exists else client.indices.create
    body = call.call_args.kwargs["body"]
    properties = body.get("mappings", body)["properties"]
    linux = properties["linux"]["properties"]
    assert {"http_method", "http_status", "http_user_agent", "http_referrer", "http_protocol", "url_path", "url_stem", "url_query", "bytes_sent"} <= set(linux)
    assert properties["http"]["properties"]["request"]["properties"]["method"] == {"type": "keyword"}
    assert properties["http"]["properties"]["response"]["properties"]["status_code"]["type"] == "integer"
    assert "original" in properties["user_agent"]["properties"]
