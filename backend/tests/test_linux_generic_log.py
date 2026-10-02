"""Generic Linux text-log parser: detection, format sniffing, timestamps, safety limits.

Every sample below is synthetic (documentation IP ranges, invented users and hosts).
"""
from __future__ import annotations

import bz2
import gzip
import json
import lzma
from datetime import datetime, timezone

import pytest

from app.ingest.linux import generic_log
from app.ingest.linux.dispatch import parse_linux_artifact_file
from app.ingest.linux.generic_log import detect_format, parse_generic_log, read_log_text
from app.ingest.linux.helpers import looks_like_linux_artifact

GENERIC = ("linux_generic_log", "generic_log", "linux_generic_raw")


# ---------------------------------------------------------------- detection

@pytest.mark.parametrize(
    "path",
    [
        "var/log/nginx/error.log",
        "var/log/nginx/access.log.3.gz",
        "var/log/fail2ban.log.2.gz",
        "var/log/ufw.log",
        "var/log/dmesg.0",
        "var/log/notes.txt",
        "var/log/app/run.log-20240101",
        "home/alice/app/out.log",
        "opt/shop/logs/app.log.1",
        "var/lib/docker/containers/abc123/abc123-json.log",
        "triage/host1/var/log/custom/service.log",
    ],
)
def test_generic_log_paths_are_detected(path):
    assert looks_like_linux_artifact(path) == GENERIC


@pytest.mark.parametrize(
    "path",
    [
        "var/log/journal/abc/system.journal",
        "usr/share/doc/pkg/changelog.log",
        "usr/bin/tool.log",
        "opt/app/catalog",
        "opt/app/catalog.logo",
        "C:/Windows/INF/setupapi.dev.log",
        "Users/bob/Desktop/notes.log",
        "home/alice/notes.txt",
        "var/log/README",
        "var/log/more_messages_pb2.py",
        "var/log/state.sqlite",
    ],
)
def test_generic_log_does_not_claim_unrelated_paths(path):
    assert looks_like_linux_artifact(path) != GENERIC


@pytest.mark.parametrize(
    "path, expected",
    [
        ("var/log/syslog", "linux_syslog_raw"),
        ("var/log/syslog.1", "linux_syslog_raw"),
        ("var/log/auth.log.2", "linux_auth_raw"),
        ("var/log/audit/audit.log", "linux_audit_raw"),
        ("var/log/apache2/access.log", "linux_apache_raw"),
        ("var/log/dpkg.log", "linux_packages_raw"),
        ("var/log/lastlog", "linux_lastlog_raw"),
    ],
)
def test_specific_parsers_keep_precedence(path, expected):
    result = looks_like_linux_artifact(path)
    assert result is not None and result[2] == expected


# ------------------------------------------------------------ format sniffing

ISO_LINES = [
    "2024-03-01T10:20:30Z sshd[411]: Failed password for invalid user mallory from 203.0.113.9",
    "2024-03-01T10:20:31Z cron[12]: job started",
]


def test_iso_format_with_explicit_timezone_is_exact():
    rows = parse_generic_log("\n".join(ISO_LINES), source_path="var/log/x.log")
    assert len(rows) == 2
    first = rows[0]
    assert first["log_format"] == "iso"
    assert first["timestamp"] == "2024-03-01T10:20:30+00:00"
    assert first["timestamp_status"] == "ok"
    assert first["process"] == "sshd" and first["pid"] == 411
    assert first["source_ip"] == "203.0.113.9"
    assert first["username"] == "mallory"
    assert first["artifact_family"] == "linux_generic_log"
    assert first["source_file"] == "var/log/x.log" and first["line_number"] == 1


def test_iso_without_timezone_is_marked_assumed_utc():
    row = parse_generic_log("2024-03-01 10:20:30,123 INFO started\n2024-03-01 10:20:31,000 INFO ok")[0]
    assert row["timestamp"] == "2024-03-01T10:20:30.123000+00:00"
    assert row["timestamp_status"] == "assumed_utc"
    assert row["severity"] == "info"


def test_iso_offset_is_converted_to_utc():
    row = parse_generic_log("2024-03-01T12:00:00+02:00 a\n2024-03-01T12:00:01+02:00 b")[0]
    assert row["timestamp"] == "2024-03-01T10:00:00+00:00"
    assert row["timestamp_status"] == "ok"


def test_nginx_error_style_slashed_date():
    text = "2024/03/01 10:20:30 [error] 7#7: *1 open() failed\n2024/03/01 10:20:31 [warn] 7#7: retry"
    rows = parse_generic_log(text)
    assert rows[0]["log_format"] == "iso"
    assert rows[0]["severity"] == "error"
    assert rows[1]["severity"] == "warning"


def test_syslog_format_infers_year_and_flags_it():
    now = datetime.now(tz=timezone.utc)
    text = "Jan  5 03:04:05 web01 sshd[9]: Accepted publickey for deploy from 198.51.100.7\nJan  5 03:04:06 web01 sshd[9]: session opened"
    rows = parse_generic_log(text)
    assert rows[0]["log_format"] == "syslog"
    assert rows[0]["host"] == "web01" and rows[0]["process"] == "sshd" and rows[0]["pid"] == 9
    assert rows[0]["timestamp_status"] == "assumed_year_utc"
    assert datetime.fromisoformat(rows[0]["timestamp"]) <= now


def test_syslog_future_month_rolls_back_a_year():
    now = datetime.now(tz=timezone.utc)
    future = (now.replace(day=1) + __import__("datetime").timedelta(days=40)).strftime("%b")
    row = parse_generic_log(f"{future}  1 00:00:00 h p[1]: m\n{future}  1 00:00:01 h p[1]: m")[0]
    assert datetime.fromisoformat(row["timestamp"]) <= now


def test_common_log_format_uses_bracket_timestamp_and_client_ip():
    text = (
        '203.0.113.5 - - [01/Mar/2024:10:20:30 +0100] "GET /admin HTTP/1.1" 403 12\n'
        '203.0.113.6 - - [01/Mar/2024:10:20:31 +0100] "GET / HTTP/1.1" 200 9'
    )
    rows = parse_generic_log(text)
    assert rows[0]["log_format"] == "clf"
    assert rows[0]["timestamp"] == "2024-03-01T09:20:30+00:00"
    assert rows[0]["timestamp_status"] == "ok"
    assert rows[0]["source_ip"] == "203.0.113.5"


def test_jsonl_extracts_known_fields():
    lines = [
        json.dumps({"time": "2024-03-01T10:20:30Z", "level": "ERROR", "msg": "login failed", "user": "eve", "remote_addr": "192.0.2.4", "service": "api"}),
        json.dumps({"ts": 1709288431, "msg": "retry"}),
    ]
    rows = parse_generic_log("\n".join(lines))
    assert rows[0]["log_format"] == "iso" or rows[0]["log_format"] == "json"
    first, second = rows
    assert first["timestamp"] == "2024-03-01T10:20:30+00:00"
    assert first["username"] == "eve" and first["source_ip"] == "192.0.2.4"
    assert first["severity"] == "error" and first["process"] == "api"
    assert first["message"] == "login failed"
    assert second["timestamp"] == "2024-03-01T10:20:31+00:00"
    assert second["timestamp_status"] == "ok"


def test_json_epoch_milliseconds():
    rows = parse_generic_log('{"timestamp": 1709288430000, "message": "a"}\n{"timestamp": 1709288431000, "message": "b"}')
    assert rows[0]["timestamp"] == "2024-03-01T10:20:30+00:00"


# --------------------------------------------------------- continuation / none

def test_continuation_lines_are_folded_into_previous_event():
    text = (
        "2024-03-01T10:00:00Z ERROR unhandled exception\n"
        "  at module.run (app.py:10)\n"
        "  at module.main (app.py:3)\n"
        "2024-03-01T10:00:05Z INFO recovered"
    )
    rows = parse_generic_log(text)
    assert len(rows) == 2
    assert "app.py:10" in rows[0]["message"] and "app.py:3" in rows[0]["message"]
    assert rows[0]["raw_excerpt"] == "2024-03-01T10:00:00Z ERROR unhandled exception"
    assert rows[1]["line_number"] == 4


def test_file_without_timestamps_is_indexed_undated():
    rows = parse_generic_log("starting worker\nloaded 3 plugins\nready")
    assert [r["log_format"] for r in rows] == ["none"] * 3
    assert all(r["timestamp"] is None and r["timestamp_status"] == "missing" for r in rows)
    assert [r["message"] for r in rows] == ["starting worker", "loaded 3 plugins", "ready"]


def test_implausible_dates_are_not_trusted():
    rows = parse_generic_log("1970-01-01T00:00:00Z boot\n1970-01-01T00:00:01Z boot2")
    assert all(r["timestamp"] is None for r in rows)


def test_detect_format_needs_a_majority():
    mostly_plain = ["2024-03-01T10:00:00Z a"] + ["plain line"] * 9
    assert detect_format(mostly_plain) == "none"
    assert detect_format(ISO_LINES) == "iso"
    assert detect_format([]) == "none"


def test_binary_content_yields_nothing():
    assert parse_generic_log("ELF\x00\x01\x02 binary blob") == []


def test_blank_and_whitespace_lines_are_skipped():
    rows = parse_generic_log("\n\n2024-03-01T10:00:00Z a\n   \n2024-03-01T10:00:01Z b\n")
    assert len(rows) == 2


def test_long_lines_are_clipped():
    rows = parse_generic_log("2024-03-01T10:00:00Z " + "x" * 5000 + "\n2024-03-01T10:00:01Z ok")
    assert len(rows[0]["message"]) <= generic_log.MAX_MESSAGE_CHARS
    assert len(rows[0]["raw_excerpt"]) <= generic_log.MAX_MESSAGE_CHARS


def test_truncation_adds_an_explicit_marker_row():
    rows = parse_generic_log("2024-03-01T10:00:00Z a\n2024-03-01T10:00:01Z b", truncated=True)
    assert len(rows) == 3
    assert "truncated" in rows[-1]["message"] and rows[-1]["timestamp"] is None


# ------------------------------------------------------------------- reading

BODY = "\n".join(ISO_LINES) + "\n"


@pytest.mark.parametrize(
    "name, writer",
    [
        ("plain.log", lambda p: p.write_text(BODY)),
        ("rotated.log.2.gz", lambda p: p.write_bytes(gzip.compress(BODY.encode()))),
        ("rotated.log.3.bz2", lambda p: p.write_bytes(bz2.compress(BODY.encode()))),
        ("rotated.log.4.xz", lambda p: p.write_bytes(lzma.compress(BODY.encode()))),
        # Compression is detected from the content, so a misleading name still works.
        ("compressed_but_named.log", lambda p: p.write_bytes(gzip.compress(BODY.encode()))),
    ],
)
def test_read_log_text_handles_compression_by_magic_bytes(tmp_path, name, writer):
    path = tmp_path / name
    writer(path)
    text, truncated = read_log_text(path)
    assert text == BODY and truncated is False


def test_read_log_text_enforces_the_decompressed_cap(tmp_path):
    path = tmp_path / "bomb.log.gz"
    path.write_bytes(gzip.compress(b"A" * 5_000_000))
    text, truncated = read_log_text(path, limit=1_000_000)
    assert len(text) == 1_000_000 and truncated is True


def test_damaged_gzip_keeps_what_was_readable(tmp_path):
    blob = gzip.compress((BODY * 2000).encode())
    path = tmp_path / "cut.log.gz"
    path.write_bytes(blob[: len(blob) // 2])
    text, truncated = read_log_text(path)
    assert truncated is True and "sshd" in text


# ------------------------------------------------------------------ dispatch

def test_dispatch_parses_a_compressed_generic_log_end_to_end(tmp_path):
    path = tmp_path / "service.log.1.gz"
    path.write_bytes(gzip.compress(BODY.encode()))
    rows = parse_linux_artifact_file(path, parser="linux_generic_raw", artifact_type="generic_log", source_path="var/log/svc/service.log.1.gz")
    assert len(rows) == 2
    assert rows[0]["source_file"] == "var/log/svc/service.log.1.gz"


def test_dispatch_binary_file_is_not_an_error(tmp_path):
    path = tmp_path / "blob.log"
    path.write_bytes(b"\x7fELF\x00\x00\x01" * 100)
    assert parse_linux_artifact_file(path, parser="linux_generic_raw", artifact_type="generic_log", source_path="var/log/blob.log") == []


def test_rows_normalize_through_the_linux_normalizer():
    from app.ingest.artifact_normalizers import normalize_linux_row
    from app.ingest.normalizer import base_document

    row = parse_generic_log("\n".join(ISO_LINES), source_path="var/log/x.log")[0]
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": "linux_generic_log"})
    doc = normalize_linux_row(base, row, source_path="var/log/x.log", artifact_type="linux_generic_log")
    assert doc["linux"]["log_format"] == "iso"
    assert doc["linux"]["timestamp_status"] == "ok"
    assert doc["linux"]["source_ip"] == "203.0.113.9"
