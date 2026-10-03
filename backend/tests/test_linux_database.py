"""MySQL / MariaDB and PostgreSQL logs. Users, hosts and addresses are synthetic."""
from __future__ import annotations

import gzip
import json
from unittest.mock import MagicMock

import pytest

from app.core import opensearch as os_module
from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.database_logs import database_engine, parse_database_log, statement_flags
from app.ingest.linux.dispatch import parse_linux_artifact_file
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.normalizer import base_document
from app.search.query_syntax import analyze_query_syntax


def _doc(row: dict) -> dict:
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": row["artifact_family"]})
    return normalize_linux_row(base, row, source_path=row["source_file"], artifact_type=row["artifact_family"])


# --------------------------------------------------------------------- detection

@pytest.mark.parametrize(
    "path, engine",
    [
        ("var/log/mysql/error.log", "mysql"), ("var/log/mysql/error.log.2.gz", "mysql"), ("var/log/mysql/mysql.log", "mysql"),
        ("var/log/mysql/mysql-slow.log", "mysql"), ("var/log/mysql/server_audit.log", "mysql"), ("var/log/mariadb/mariadb.log", "mysql"),
        ("var/log/mysqld.log", "mysql"), ("var/lib/mysql/db01.err", "mysql"),
        ("var/log/postgresql/postgresql-15-main.log", "postgresql"), ("var/log/postgresql/postgresql-15-main.csv", "postgresql"),
        ("var/log/postgresql/postgresql-15-main.json", "postgresql"), ("var/lib/pgsql/data/log/postgresql-Mon.log", "postgresql"),
        ("var/lib/postgresql/16/main/log/postgresql.json", "postgresql"), ("evidence/db1/var/log/mysql/error.log", "mysql"),
    ],
)
def test_database_paths_are_detected(path, engine):
    assert database_engine(path) == engine
    assert looks_like_linux_artifact(path) == ("linux_database", "database_log", "linux_database_raw")


@pytest.mark.parametrize("path", ["var/log/syslog", "var/log/mongodb/mongod.log", "var/log/redis/redis-server.log", "var/lib/mysql/mysql/user.MYD", "var/log/postgresql/", "home/u/mysql.log"])
def test_other_paths_are_not_database_logs(path):
    assert database_engine(path) is None and looks_like_linux_artifact(path)[0] != "linux_database" if looks_like_linux_artifact(path) else True


# --------------------------------------------------------------- MySQL error log

MYSQL_ERROR = (
    "2024-03-01T10:20:30.123456Z 12 [Warning] [MY-010055] [Server] IP address '203.0.113.9' could not be resolved: Name or service not known\n"
    "2024-03-01 10:20:31 14 [Warning] Access denied for user 'root'@'203.0.113.9' (using password: YES)\n"
    "2024-03-01T10:20:32.000000Z 15 [Note] [MY-010914] [Server] Aborted connection 15 to db: 'app' user: 'svc' host: '192.0.2.7' (Got timeout reading communication packets)\n"
    "2024-03-01T10:20:33.000000Z 0 [System] [MY-010931] [Server] /usr/sbin/mysqld: ready for connections.\n"
    "2024-03-01T10:20:34.000000Z 16 [Error] [MY-000067] [Server] Host '203.0.113.9' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'\n"
)


def _mysql(content: str, path: str = "var/log/mysql/error.log") -> list[dict]:
    return parse_database_log(content, source_path=path)


def test_a_failed_login_in_the_error_log_names_the_account_and_the_source():
    row = _mysql(MYSQL_ERROR)[1]
    assert (row["event_action"], row["db_status"], row["username"], row["source_ip"]) == ("db_auth_failed", "failed", "root", "203.0.113.9")
    assert row["authentication"] == "password=YES" and row["artifact_type"] == "mysql_error"


def test_error_log_times_are_exact_with_a_z_and_assumed_without():
    mysql8, mariadb = _mysql(MYSQL_ERROR)[0], _mysql(MYSQL_ERROR)[1]
    assert (mysql8["timestamp"], mysql8["timestamp_status"]) == ("2024-03-01T10:20:30.123456+00:00", "ok")
    assert (mariadb["timestamp"], mariadb["timestamp_status"]) == ("2024-03-01T10:20:31+00:00", "assumed_utc")


def test_error_log_levels_codes_and_other_events():
    rows = _mysql(MYSQL_ERROR)
    assert (rows[0]["db_level"], rows[0]["db_error_code"], rows[0]["db_thread_id"]) == ("warning", "MY-010055", "12")
    assert rows[0]["source_ip"] == "203.0.113.9"
    aborted = rows[2]
    assert (aborted["event_action"], aborted["db_name"], aborted["username"], aborted["source_ip"]) == ("db_connection_aborted", "app", "svc", "192.0.2.7")
    assert rows[4]["event_action"] == "db_host_blocked" and rows[4]["db_status"] == "failed"


def test_unmatched_error_log_lines_are_kept_undated():
    rows = _mysql("mysqld_safe Starting mysqld daemon\n" + MYSQL_ERROR.splitlines()[0] + "\n")
    assert rows[0]["timestamp"] is None and rows[0]["message"].startswith("mysqld_safe") and rows[1]["timestamp"] is not None


# ------------------------------------------------------------ MySQL general log

GENERAL = (
    "/usr/sbin/mysqld, Version: 8.0.36 (MySQL Community Server - GPL). started with:\n"
    "Time                 Id Command    Argument\n"
    "2024-03-01T10:20:30.123456Z\t   12 Connect\troot@203.0.113.9 on app using TCP/IP\n"
    "2024-03-01T10:20:31.123456Z\t   12 Query\tSELECT * FROM mysql.user\n WHERE user='x' UNION SELECT 1\n"
    "2024-03-01T10:20:32.123456Z\t   12 Init DB\tshop\n"
    "2024-03-01T10:20:33.123456Z\t   13 Connect\tAccess denied for user 'eve'@'198.51.100.7' (using password: NO)\n"
    "2024-03-01T10:20:34.123456Z\t   12 Quit\t\n"
)


def test_the_general_log_follows_a_session():
    rows = {(r["event_action"], r.get("db_thread_id")): r for r in _mysql(GENERAL, "var/log/mysql/mysql.log") if r.get("event_action")}
    connect = rows[("db_connect", "12")]
    assert (connect["username"], connect["source_ip"], connect["db_name"], connect["db_status"]) == ("root", "203.0.113.9", "app", "success")
    assert rows[("db_disconnect", "12")]["db_command"] == "Quit"
    failed = rows[("db_auth_failed", "13")]
    assert (failed["username"], failed["source_ip"], failed["db_status"]) == ("eve", "198.51.100.7", "failed")


def test_a_statement_is_kept_whole_across_lines_and_flagged():
    query = next(r for r in _mysql(GENERAL, "var/log/mysql/mysql.log") if r.get("event_action") == "db_query")
    assert query["db_statement"] == "SELECT * FROM mysql.user\nWHERE user='x' UNION SELECT 1"
    assert set(query["suspicious_indicators"]) == {"credential_table_access", "sql_injection_pattern"}
    assert query["timestamp"] == "2024-03-01T10:20:31.123456+00:00"


def test_the_server_banner_is_not_mistaken_for_events():
    banner = [r for r in _mysql(GENERAL, "var/log/mysql/mysql.log") if r["timestamp"] is None]
    assert len(banner) == 2 and banner[0]["message"].startswith("/usr/sbin/mysqld")


def test_the_older_layout_writes_the_time_only_when_it_changes():
    legacy = "240301 10:20:30\t    7 Connect\troot@localhost on \n\t    7 Query\tSELECT 1\n240301 10:20:31\t    7 Quit\t\n"
    rows = [r for r in _mysql(legacy, "var/log/mysql/mysql.log") if r.get("db_command")]
    assert [r["timestamp"] for r in rows] == ["2024-03-01T10:20:30+00:00", "2024-03-01T10:20:30+00:00", "2024-03-01T10:20:31+00:00"]
    assert all(r["timestamp_status"] == "assumed_utc" for r in rows)


# ---------------------------------------------------------------- slow query log

SLOW = (
    "# Time: 2024-03-01T10:20:30.123456Z\n# User@Host: app[app] @ web01 [192.0.2.7]  Id:    12\n"
    "# Query_time: 2.500000  Lock_time: 0.000100 Rows_sent: 1  Rows_examined: 1000000\n"
    "use shop;\nSET timestamp=1709288430;\nSELECT SLEEP(5);\n"
    "# Time: 2024-03-01T10:21:00.000000Z\n# User@Host: root[root] @  [203.0.113.9]  Id: 13\n"
    "# Query_time: 1.0  Lock_time: 0.0 Rows_sent: 0  Rows_examined: 0\nSET timestamp=1709288460;\nselect 1;\n"
)


def test_slow_queries_carry_their_cost_user_source_and_database():
    first, second = _mysql(SLOW, "var/log/mysql/mysql-slow.log")
    assert first["artifact_type"] == "mysql_slow" and first["event_action"] == "db_slow_query"
    assert (first["db_query_time"], first["db_rows_examined"], first["db_rows_sent"]) == (2.5, 1000000, 1)
    assert (first["username"], first["source_ip"], first["db_name"], first["db_statement"]) == ("app", "192.0.2.7", "shop", "SELECT SLEEP(5);")
    assert first["suspicious_indicators"] == ["sql_injection_pattern"] and second["db_statement"] == "select 1;"
    assert second["source_ip"] == "203.0.113.9"


def test_the_slow_log_set_timestamp_is_an_exact_time():
    first = _mysql(SLOW, "var/log/mysql/mysql-slow.log")[0]
    assert (first["timestamp"], first["timestamp_status"]) == ("2024-03-01T10:20:30+00:00", "ok")


# ------------------------------------------------------------------ audit plugin

AUDIT = (
    "20240301 10:20:30,db01,root,203.0.113.9,12,0,CONNECT,,,0\n"
    "20240301 10:20:31,db01,root,203.0.113.9,12,45,QUERY,app,'GRANT ALL ON *.* TO ''x''@''%''',0\n"
    "20240301 10:20:32,db01,eve,198.51.100.7,13,0,FAILED_CONNECT,,,1045\n"
    "20240301 10:20:33,db01,root,203.0.113.9,12,46,QUERY,app,'SELECT a,b FROM t WHERE x=''1,2''',0\n"
    "20240301 10:20:34,db01,root,203.0.113.9,12,0,DISCONNECT,,,0\n"
)


def test_the_audit_plugin_records_logins_failures_and_statements():
    rows = _mysql(AUDIT, "var/log/mysql/server_audit.log")
    assert [r["event_action"] for r in rows] == ["db_connect", "db_query", "db_auth_failed", "db_query", "db_disconnect"]
    assert rows[1]["db_statement"] == "GRANT ALL ON *.* TO 'x'@'%'" and rows[1]["suspicious_indicators"] == ["account_change"]
    assert rows[1]["db_name"] == "app" and rows[1]["username"] == "root" and rows[1]["source_ip"] == "203.0.113.9"
    failed = rows[2]
    assert (failed["username"], failed["db_status"], failed["db_retcode"], failed["source_ip"]) == ("eve", "failed", "1045", "198.51.100.7")
    assert rows[3]["db_statement"] == "SELECT a,b FROM t WHERE x='1,2'"  # a comma inside a quoted statement
    assert rows[0]["host"] == "db01" and rows[0]["timestamp_status"] == "assumed_utc"


# ----------------------------------------------------------------- PostgreSQL text

PG_TEXT = (
    "2024-03-01 10:20:30.123 UTC [1234] LOG:  connection received: host=203.0.113.9 port=51234\n"
    "2024-03-01 10:20:30.200 UTC [1234] alice@app LOG:  connection authorized: user=alice database=app\n"
    "2024-03-01 10:20:31.123 UTC [1240] mallory@app FATAL:  password authentication failed for user \"mallory\"\n"
    "2024-03-01 10:20:31.124 UTC [1241] FATAL:  no pg_hba.conf entry for host \"203.0.113.9\", user \"postgres\", database \"app\", SSL on\n"
    "2024-03-01 10:20:32.123 UTC [1235] bob@app ERROR:  syntax error at or near \"x\"\n"
    "2024-03-01 10:20:32.123 UTC [1235] bob@app STATEMENT:  COPY t TO PROGRAM 'id'\n"
    "2024-03-01 10:20:33.123 UTC [1236] bob@app LOG:  statement: DROP TABLE users;\n"
    "2024-03-01 10:20:34.123 UTC [1236] bob@app LOG:  disconnection: session time: 0:00:04 user=bob database=app host=203.0.113.9 port=51234\n"
)


def _pg(content: str, path: str = "var/log/postgresql/postgresql-15-main.log") -> list[dict]:
    return parse_database_log(content, source_path=path)


def test_postgres_connection_lines():
    rows = _pg(PG_TEXT)
    received, authorized = rows[0], rows[1]
    assert (received["event_action"], received["source_ip"], received["source_port"]) == ("db_connection_received", "203.0.113.9", 51234)
    assert (authorized["event_action"], authorized["username"], authorized["db_name"], authorized["db_status"]) == ("db_connect", "alice", "app", "success")
    assert received["timestamp"] == "2024-03-01T10:20:30.123000+00:00" and received["timestamp_status"] == "ok"


def test_postgres_authentication_failures():
    rows = _pg(PG_TEXT)
    assert (rows[2]["event_action"], rows[2]["username"], rows[2]["db_status"]) == ("db_auth_failed", "mallory", "failed")
    hba = rows[3]
    assert (hba["event_action"], hba["username"], hba["db_name"], hba["source_ip"]) == ("db_auth_failed", "postgres", "app", "203.0.113.9")


def test_a_statement_line_is_attached_to_the_error_above_it():
    error = _pg(PG_TEXT)[4]
    assert error["event_action"] == "db_error" and error["db_statement"] == "COPY t TO PROGRAM 'id'"
    assert error["suspicious_indicators"] == ["command_execution"] and "STATEMENT: COPY t TO PROGRAM" in error["message"]
    assert len([r for r in _pg(PG_TEXT) if "COPY" in r["message"]]) == 1


def test_logged_statements_and_disconnections():
    drop, disconnect = _pg(PG_TEXT)[5], _pg(PG_TEXT)[6]
    assert (drop["event_action"], drop["db_statement"], drop["suspicious_indicators"]) == ("db_query", "DROP TABLE users;", ["destructive_statement"])
    assert (disconnect["event_action"], disconnect["username"], disconnect["source_ip"]) == ("db_disconnect", "bob", "203.0.113.9")


def test_wrapped_statements_are_joined():
    rows = _pg("2024-03-01 10:20:33.123 UTC [1] LOG:  statement: SELECT a\n\tFROM t\n\tWHERE b = 1\n")
    assert rows[0]["db_statement"] == "SELECT a\nFROM t\nWHERE b = 1"


@pytest.mark.parametrize("tz, status", [("UTC", "ok"), ("GMT", "ok"), ("CEST", "assumed_utc"), ("+0200", "ok"), ("+02", "ok")])
def test_postgres_time_zones(tz, status):
    row = _pg(f"2024-03-01 12:00:00.000 {tz} [1] LOG:  checkpoint starting\n")[0]
    assert row["timestamp_status"] == status
    if tz in {"+0200", "+02"}:
        assert row["timestamp"] == "2024-03-01T10:00:00+00:00"


def test_a_prefix_without_a_user_still_parses():
    row = _pg("2024-03-01 10:20:30 UTC [77] ERROR:  relation \"x\" does not exist\n")[0]
    assert row["db_level"] == "error" and row["event_action"] == "db_error" and row["db_thread_id"] == "77"


# ------------------------------------------------------- PostgreSQL json and csv

def test_the_json_log():
    record = {"timestamp": "2024-03-01 10:20:30.123 UTC", "user": "alice", "dbname": "app", "pid": 1234, "remote_host": "203.0.113.9", "remote_port": 51234,
              "error_severity": "FATAL", "state_code": "28P01", "message": 'password authentication failed for user "alice"', "application_name": "psql"}
    row = _pg(json.dumps(record) + "\n", "var/lib/postgresql/16/main/log/postgresql.json")[0]
    assert (row["event_action"], row["username"], row["source_ip"], row["db_error_code"], row["timestamp"]) == ("db_auth_failed", "alice", "203.0.113.9", "28P01", "2024-03-01T10:20:30.123000+00:00")
    assert row["timestamp_status"] == "ok" and row["db_application"] == "psql"


def test_the_json_log_carries_the_statement():
    record = {"timestamp": "2024-03-01 10:20:30.123 UTC", "error_severity": "LOG", "message": "statement: SELECT 1", "query": "SELECT pg_read_file('/etc/passwd')", "user": "bob", "dbname": "app"}
    assert "file_access" in _pg(json.dumps(record) + "\n", "var/log/postgresql/pg.json")[0]["suspicious_indicators"]


def test_the_csv_log():
    fields = ["2024-03-01 10:20:30.123 UTC", "bob", "app", "1234", "203.0.113.9:51234", "sess.1", "1", "SELECT", "2024-03-01 10:00:00 UTC", "3/1", "0", "ERROR", "42601", 'syntax error at or near "x"', "", "", "", "", "", "SELECT x, y FROM t", "", "", "psql", "client backend"]
    import csv, io

    buffer = io.StringIO()
    csv.writer(buffer).writerow(fields)
    row = _pg(buffer.getvalue(), "var/log/postgresql/postgresql-15-main.csv")[0]
    assert (row["username"], row["db_name"], row["source_ip"], row["source_port"], row["db_error_code"]) == ("bob", "app", "203.0.113.9", 51234, "42601")
    assert row["db_statement"] == "SELECT x, y FROM t" and row["timestamp_status"] == "ok" and row["db_level"] == "error"


def test_malformed_json_and_csv_do_not_raise():
    assert _pg("not json\n{broken\n", "var/log/postgresql/pg.json")[0]["timestamp"] is None
    _pg('a,b,"unterminated\n', "var/log/postgresql/pg.csv")


# ----------------------------------------------------------------------- flags

@pytest.mark.parametrize(
    "statement, flag",
    [
        ("GRANT ALL PRIVILEGES ON *.* TO 'x'@'%' IDENTIFIED BY 'p'", "account_change"), ("CREATE USER bob WITH PASSWORD 'x'", "account_change"), ("ALTER ROLE bob SUPERUSER", "account_change"),
        ("SET PASSWORD FOR 'root'@'localhost' = 'x'", "account_change"),
        ("DROP DATABASE shop", "destructive_statement"), ("TRUNCATE TABLE users", "destructive_statement"), ("DELETE FROM users;", "destructive_statement"),
        ("SELECT LOAD_FILE('/etc/passwd')", "file_access"), ("SELECT 1 INTO OUTFILE '/tmp/x'", "file_access"), ("LOAD DATA LOCAL INFILE '/tmp/x' INTO TABLE t", "file_access"),
        ("SELECT pg_read_file('/etc/passwd')", "file_access"), ("COPY t FROM '/tmp/x'", "file_access"),
        ("COPY t FROM PROGRAM 'curl x | sh'", "command_execution"), ("SELECT sys_exec('id')", "command_execution"), ("CREATE FUNCTION f RETURNS STRING SONAME 'lib.so'", "command_execution"),
        ("SELECT user, authentication_string FROM mysql.user", "credential_table_access"), ("SELECT * FROM pg_shadow", "credential_table_access"),
        ("SELECT table_name FROM information_schema.tables", "schema_enumeration"),
        ("SELECT * FROM t WHERE id=1 UNION SELECT 1,2", "sql_injection_pattern"), ("SELECT * FROM t WHERE a='' OR '1'='1'", "sql_injection_pattern"),
        ("SELECT IF(1=1,SLEEP(5),0)", "sql_injection_pattern"), ("SELECT pg_sleep(10)", "sql_injection_pattern"), ("SELECT extractvalue(1,concat(0x7e,version()))", "sql_injection_pattern"),
    ],
)
def test_statement_indicators(statement, flag):
    assert flag in statement_flags(statement)


@pytest.mark.parametrize(
    "statement",
    ["SELECT id, name FROM users WHERE id = 5", "INSERT INTO orders (a) VALUES (1)", "UPDATE t SET a = 1 WHERE id = 2", "DELETE FROM t WHERE id = 3", "SELECT count(*) FROM information_schema_notes", "SELECT 'grant' AS word"],
)
def test_ordinary_statements_are_not_flagged(statement):
    assert statement_flags(statement) == []


# -------------------------------------------------------------- dispatch/normalize

def test_dispatch_reads_a_rotated_compressed_log(tmp_path):
    path = tmp_path / "error.log.1.gz"
    path.write_bytes(gzip.compress(MYSQL_ERROR.encode()))
    rows = parse_linux_artifact_file(path, parser="linux_database_raw", artifact_type="database_log", source_path="var/log/mysql/error.log.1.gz")
    assert len(rows) == 5 and rows[1]["event_action"] == "db_auth_failed"


def test_dispatch_marks_a_truncated_log(tmp_path):
    blob = gzip.compress((PG_TEXT * 400).encode())
    path = tmp_path / "pg.log.gz"
    path.write_bytes(blob[: len(blob) // 2])
    rows = parse_linux_artifact_file(path, parser="linux_database_raw", artifact_type="database_log", source_path="var/log/postgresql/postgresql-15-main.log.1.gz")
    assert rows and "truncated" in rows[-1]["message"]


def test_a_failed_login_normalizes_with_outcome_severity_and_source():
    doc = _doc(_mysql(MYSQL_ERROR)[1])
    assert doc["event"]["type"] == "mysql_error" and doc["event"]["action"] == "db_auth_failed" and doc["event"]["outcome"] == "failure"
    assert doc["event"]["severity"] == "medium" and doc["user"]["name"] == "root" and doc["network"]["source_ip"] == "203.0.113.9"
    assert doc["title"] == "mysql auth failed: root from 203.0.113.9"
    assert doc["linux"]["db_engine"] == "mysql" and doc["linux"]["db_status"] == "failed"


def test_a_flagged_statement_is_medium_and_a_plain_one_follows_its_level():
    flagged = _doc(_pg(PG_TEXT)[5])
    plain = _doc(_pg("2024-03-01 10:20:33.123 UTC [1] bob@app LOG:  statement: SELECT 1\n")[0])
    assert flagged["event"]["severity"] == "medium" and flagged["linux"]["suspicious_indicators"] == ["destructive_statement"]
    assert plain["event"]["severity"] == "info" and "SELECT 1" in plain["title"]


def test_levels_set_severity_for_other_rows():
    assert _doc(_pg("2024-03-01 10:20:33.123 UTC [1] PANIC:  could not write to file\n")[0])["event"]["severity"] == "high"
    assert _doc(_mysql("2024-03-01T10:20:34.000000Z 16 [Error] [MY-000067] [Server] something broke\n")[0])["event"]["severity"] == "medium"
    assert _doc(_mysql("2024-03-01T10:20:34.000000Z 0 [System] [MY-010931] [Server] ready for connections.\n")[0])["event"]["severity"] == "info"


def test_the_statement_stays_searchable_text():
    doc = _doc(_pg(PG_TEXT)[5])
    assert doc["linux"]["db_statement"] == "DROP TABLE users;" and "DROP TABLE users" in doc["message"]


# --------------------------------------------------------------- search/mapping

@pytest.mark.parametrize(
    "query, field",
    [("dbengine:postgresql", "linux.db_engine"), ("database:app", "linux.db_name"), ("dbcommand:Query", "linux.db_command"), ("dbstatus:failed", "linux.db_status"),
     ("dberror:28P01", "linux.db_error_code"), ("sql:drop", "linux.db_statement"), ("indicator:account_change", "linux.suspicious_indicators")],
)
def test_database_shortcuts_are_searchable(query, field):
    assert field in str(analyze_query_syntax(query, lambda t: {"simple_query_string": {"query": t}})["query"])


@pytest.mark.parametrize("exists", [False, True], ids=["new-index", "existing-index-backfill"])
def test_database_fields_are_declared_in_the_index_mapping(monkeypatch, exists):
    client = MagicMock()
    monkeypatch.setattr(os_module, "get_opensearch_client", lambda **_: client)
    monkeypatch.setattr(os_module, "index_exists", lambda *_a, **_k: exists)
    monkeypatch.setattr(os_module, "_apply_safe_index_settings", lambda *_a, **_k: None, raising=False)
    os_module.ensure_case_index("11111111-1111-4111-8111-111111111111")
    call = client.indices.put_mapping if exists else client.indices.create
    body = call.call_args.kwargs["body"]
    properties = body.get("mappings", body)["properties"]["linux"]["properties"]
    assert {"db_engine", "db_name", "db_command", "db_statement", "db_status", "db_error_code", "db_query_time", "db_rows_examined"} <= set(properties)
    assert properties["db_statement"]["type"] == "text"
