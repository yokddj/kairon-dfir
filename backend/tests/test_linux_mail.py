"""Postfix and Dovecot lines in mail.log / the journal. Hosts, users and addresses are synthetic."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.core import opensearch as os_module
from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.linux.journal import _row_from_fields
from app.ingest.linux.mail_logs import parse_mail_message
from app.ingest.linux.syslog import parse_syslog
from app.ingest.normalizer import base_document
from app.search.query_syntax import analyze_query_syntax

REJECT = "NOQUEUE: reject: RCPT from unknown[203.0.113.9]: 554 5.7.1 <x@example.test>: Relay access denied; from=<a@evil.test> to=<x@example.test> proto=ESMTP helo=<mail.evil.test>"
SASL_FAIL = "warning: unknown[203.0.113.9]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"
SASL_OK = "4C1A12F4D3: client=mail.example.test[198.51.100.7], sasl_method=PLAIN, sasl_username=alice@example.test"
DELIVERED = "9F2B3C4D5E: to=<bob@remote.test>, relay=mx.remote.test[192.0.2.5]:25, delay=1.2, delays=0.1/0/0.5/0.6, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 7A1)"
DEFERRED = "5D2B33A1C4: to=<c@remote.test>, relay=none, delay=5, dsn=4.4.1, status=deferred (connect to mx[192.0.2.9]:25: Connection timed out)"
BOUNCED = "6E3C44B2D5: to=<d@remote.test>, relay=mx.remote.test[192.0.2.5]:25, delay=2, dsn=5.1.1, status=bounced (host mx.remote.test said: 550 5.1.1 user unknown)"
IMAP_LOGIN = "imap-login: Login: user=<alice>, method=PLAIN, rip=203.0.113.9, lip=192.0.2.10, mpid=123, TLS, session=<abc>"
IMAP_FAIL = "imap-login: Disconnected (auth failed, 3 attempts in 4 secs): user=<bob>, method=PLAIN, rip=203.0.113.9, lip=192.0.2.10, TLS: x"


def _doc(row: dict) -> dict:
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": row["artifact_family"]})
    return normalize_linux_row(base, row, source_path=row.get("source_file") or row.get("source_path", ""), artifact_type=row["artifact_family"])


def _syslog(process: str, message: str) -> dict:
    return parse_syslog(f"Mar  1 10:20:30 mx01 {process}[4242]: {message}", source_path="var/log/mail.log")[0]


# ----------------------------------------------------------------------- postfix

def test_a_refused_relay_attempt():
    e = parse_mail_message("postfix/smtpd", REJECT)
    assert (e["event_action"], e["mail_status"], e["smtp_status"], e["queue_id"]) == ("mail_reject", "reject", 554, "NOQUEUE")
    assert (e["source_ip"], e["sender"], e["recipient"], e["helo"], e["mail_command"]) == ("203.0.113.9", "a@evil.test", "x@example.test", "mail.evil.test", "RCPT")
    assert "Relay access denied" in e["mail_reason"] and e["mail_client_host"] == ""


def test_an_smtp_authentication_failure_carries_the_attacker_and_method():
    e = parse_mail_message("postfix/smtpd", SASL_FAIL)
    assert (e["event_action"], e["mail_status"], e["source_ip"], e["authentication"]) == ("mail_auth_failed", "failed", "203.0.113.9", "LOGIN")


def test_an_ipv6_client():
    e = parse_mail_message("postfix/smtpd", "warning: unknown[2001:db8::1]: SASL PLAIN authentication failed: x")
    assert e["source_ip"] == "2001:db8::1" and e["authentication"] == "PLAIN"


def test_an_authenticated_submission_names_the_user_and_the_client():
    e = parse_mail_message("postfix/smtpd", SASL_OK)
    assert (e["event_action"], e["username"], e["authentication"], e["queue_id"]) == ("mail_received_authenticated", "alice@example.test", "PLAIN", "4C1A12F4D3")
    assert (e["source_ip"], e["mail_client_host"]) == ("198.51.100.7", "mail.example.test")


def test_the_queue_follows_one_message_from_arrival_to_delivery():
    queued = parse_mail_message("postfix/qmgr", "4C1A12F4D3: from=<alice@example.test>, size=1234, nrcpt=1 (queue active)")
    cleanup = parse_mail_message("postfix/cleanup", "4C1A12F4D3: message-id=<abc@mail.example.test>")
    assert (queued["event_action"], queued["sender"], queued["queue_id"]) == ("mail_queued", "alice@example.test", "4C1A12F4D3")
    assert (cleanup["event_action"], cleanup["message_id"]) == ("mail_cleanup", "abc@mail.example.test")


def test_delivery_outcomes():
    sent, deferred, bounced = (parse_mail_message("postfix/smtp", x) for x in (DELIVERED, DEFERRED, BOUNCED))
    assert (sent["mail_status"], sent["smtp_status"], sent["recipient"], sent["destination_ip"], sent["mail_relay"]) == ("sent", 250, "bob@remote.test", "192.0.2.5", "mx.remote.test")
    assert deferred["mail_status"] == "deferred" and deferred["recipient"] == "c@remote.test"
    assert bounced["mail_status"] == "bounced"


def test_a_number_inside_free_text_is_not_an_smtp_status():
    assert "smtp_status" not in parse_mail_message("postfix/smtp", DEFERRED)


@pytest.mark.parametrize(
    "message, action",
    [("connect from unknown[203.0.113.9]", "mail_connect"), ("disconnect from unknown[203.0.113.9] ehlo=1 auth=0/1 commands=1/2", "mail_disconnect"), ("lost connection after AUTH from unknown[203.0.113.9]", "mail_connection_problem")],
)
def test_connection_lines(message, action):
    e = parse_mail_message("postfix/smtpd", message)
    assert e["event_action"] == action and e["source_ip"] == "203.0.113.9"


# ----------------------------------------------------------------------- dovecot

def test_a_successful_imap_login():
    e = parse_mail_message("dovecot", IMAP_LOGIN)
    assert (e["event_action"], e["mail_status"], e["username"], e["source_ip"], e["destination_ip"], e["authentication"]) == ("mail_login", "success", "alice", "203.0.113.9", "192.0.2.10", "PLAIN")
    assert e["mail_component"] == "imap-login"


def test_a_failed_imap_login_names_the_target_account_and_the_source():
    e = parse_mail_message("dovecot", IMAP_FAIL)
    assert (e["event_action"], e["mail_status"], e["username"], e["source_ip"]) == ("mail_auth_failed", "failed", "bob", "203.0.113.9")
    assert "auth failed" in e["mail_reason"]


def test_a_backend_authentication_failure():
    e = parse_mail_message("dovecot", "auth: pam(carol,203.0.113.9): pam_authenticate() failed: Authentication failure (password mismatch?)")
    assert (e["event_action"], e["username"], e["source_ip"], e["authentication"]) == ("mail_auth_failed", "carol", "203.0.113.9", "pam")


def test_session_end_versus_login_process_disconnect():
    assert parse_mail_message("dovecot", "imap(alice)<1><s>: Disconnected: Logged out in=1 out=2")["event_action"] == "mail_logout"
    assert parse_mail_message("dovecot", "imap-login: Disconnected: Connection closed: user=<x>, rip=203.0.113.9")["event_action"] == "mail_disconnect"


def test_other_dovecot_process_tags_are_recognised():
    assert parse_mail_message("imap-login", "Login: user=<alice>, rip=203.0.113.9, lip=192.0.2.10")["event_action"] == "mail_login"


@pytest.mark.parametrize("process, message", [("sshd", "Accepted publickey for alice"), ("cron", "(root) CMD (x)"), ("postfix/smtpd", "something unrelated"), ("dovecot", "master: Dovecot v2.3 starting up"), (None, "x"), ("", "")])
def test_other_lines_are_not_mail_events(process, message):
    assert parse_mail_message(process, message) is None


def test_hostile_or_odd_text_never_raises():
    for message in ("", "=" * 5000, "<" * 3000, "NOQUEUE: reject: RCPT from : " + "x" * 5000, "client=" + "[" * 100, "status= to="):
        parse_mail_message("postfix/smtpd", message)
        parse_mail_message("dovecot", "imap-login: " + message)


# ------------------------------------------------------------------- the parsers

def test_mail_log_paths_are_read_as_syslog():
    for path in ("var/log/mail.log", "var/log/mail.log.1", "var/log/mail.log.2.gz", "var/log/maillog", "var/log/maillog-20240301", "var/log/mail.err"):
        assert looks_like_linux_artifact(path)[0] == "linux_syslog" and looks_like_linux_artifact(path)[1] == "mail_log", path


def test_syslog_rows_carry_the_mail_fields_and_keep_the_original_text():
    row = _syslog("postfix/smtpd", REJECT)
    assert row["event_action"] == "mail_reject" and row["source_ip"] == "203.0.113.9" and row["process"] == "postfix/smtpd"
    assert row["message"].startswith("NOQUEUE: reject: RCPT") and row["timestamp"] is not None


def test_ordinary_syslog_is_untouched():
    row = _syslog("sshd", "Accepted publickey for deploy")
    assert "mail_service" not in row


def test_journal_rows_are_enriched_by_the_unit_name():
    row = _row_from_fields({"MESSAGE": IMAP_FAIL, "SYSLOG_IDENTIFIER": "dovecot", "__REALTIME_TIMESTAMP": "1709288430123456"}, "j.export")
    assert row["mail_service"] == "dovecot" and row["event_action"] == "mail_auth_failed"
    other = _row_from_fields({"MESSAGE": "hello", "SYSLOG_IDENTIFIER": "app"}, "j.export")
    assert "mail_service" not in other


# ------------------------------------------------------------------- normalizing

def test_a_refused_relay_normalizes_to_email_and_network_fields():
    doc = _doc(_syslog("postfix/smtpd", REJECT))
    assert doc["network"]["source_ip"] == "203.0.113.9"
    assert doc["email"]["from"]["address"] == "a@evil.test" and doc["email"]["to"] == ["x@example.test"]
    assert doc["event"]["action"] == "mail_reject" and doc["event"]["outcome"] == "failure" and doc["event"]["severity"] == "low"
    assert doc["title"].startswith("Postfix reject") and doc["linux"]["mail_service"] == "postfix" and doc["linux"]["queue_id"] == "NOQUEUE"


def test_a_failed_login_is_medium_severity_whatever_the_line_says():
    smtp = _doc(_syslog("postfix/smtpd", SASL_FAIL))
    imap = _doc(_syslog("dovecot", IMAP_FAIL))
    assert smtp["event"]["severity"] == "medium" and imap["event"]["severity"] == "medium"
    assert imap["user"]["name"] == "bob" and imap["network"]["source_ip"] == "203.0.113.9" and imap["destination"]["ip"] == "192.0.2.10"
    assert imap["event"]["outcome"] == "failure"


def test_a_delivery_and_a_login_are_successes():
    sent = _doc(_syslog("postfix/smtp", DELIVERED))
    login = _doc(_syslog("dovecot", IMAP_LOGIN))
    assert sent["event"]["outcome"] == "success" and sent["event"]["severity"] == "info" and sent["destination"]["ip"] == "192.0.2.5"
    assert login["event"]["outcome"] == "success" and login["title"] == "Dovecot login: alice"


def test_a_level_higher_than_the_mail_floor_is_kept():
    row = parse_syslog("Mar  1 10:20:30 <mail.crit> mx01 postfix/smtpd[1]: " + SASL_FAIL, source_path="var/log/mail.log")[0]
    assert _doc(row)["event"]["severity"] == "high"


def test_the_plain_syslog_message_is_still_searchable_text():
    doc = _doc(_syslog("postfix/smtp", BOUNCED))
    assert "user unknown" in doc["message"] and doc["email"]["to"] == ["d@remote.test"] and doc["event"]["severity"] == "low"


# ------------------------------------------------------------------ search/mapping

@pytest.mark.parametrize(
    "query, field",
    [("sender:a@evil.test", "linux.sender"), ("recipient:*@example.test", "linux.recipient"), ("queue:4C1A12F4D3", "linux.queue_id"),
     ("mailstatus:bounced", "linux.mail_status"), ("mailservice:dovecot", "linux.mail_service"), ("relay:mx.remote.test", "linux.mail_relay"), ("action:mail_auth_failed", "event.action")],
)
def test_mail_shortcuts_are_searchable(query, field):
    assert field in str(analyze_query_syntax(query, lambda t: {"simple_query_string": {"query": t}})["query"])


@pytest.mark.parametrize("exists", [False, True], ids=["new-index", "existing-index-backfill"])
def test_mail_fields_are_declared_in_the_index_mapping(monkeypatch, exists):
    client = MagicMock()
    monkeypatch.setattr(os_module, "get_opensearch_client", lambda **_: client)
    monkeypatch.setattr(os_module, "index_exists", lambda *_a, **_k: exists)
    monkeypatch.setattr(os_module, "_apply_safe_index_settings", lambda *_a, **_k: None, raising=False)
    os_module.ensure_case_index("11111111-1111-4111-8111-111111111111")
    call = client.indices.put_mapping if exists else client.indices.create
    body = call.call_args.kwargs["body"]
    properties = body.get("mappings", body)["properties"]["linux"]["properties"]
    assert {"sender", "recipient", "queue_id", "smtp_status", "mail_service", "mail_status", "mail_relay", "authentication", "remote_ip"} <= set(properties)
