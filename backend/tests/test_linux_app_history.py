"""Database client and REPL histories (app.ingest.linux.app_history).

The file contents are byte-for-byte what the real clients wrote: MySQL 8.4, MariaDB 11, psql 16,
sqlite3 3.40 (Debian 12), Python 3.12 and 3.13, Node.js 22.
"""
from __future__ import annotations

import pytest

from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.app_history import parse_app_history
from app.ingest.linux.dispatch import parse_linux_artifact_file
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.normalizer import base_document
from app.services import command_history

MYSQL = b'_HiStOrY_V2_\nselect\\0401;\nselect\\040"a\\040b",\n\\040\\0402;\nselect\\040"a\\040b",\\040\\040\\0402;\ncreate\\040database\\040x;\nexit\n'
PSQL = b"select 1;\nselect 'a b',\x01  2;\n\\dt\n\\q\n"
PYTHON_313 = b"import os\ndef f():\r\n        return 1\r\n        \nprint(f())\nexit()\n"
NODE = b'.exit\nrequire("child_process").execSync("id")\nconst a = 1'


def _commands(content: bytes, path: str):
    return [row["command"] for row in parse_app_history(content.decode(), source_path=path)]


@pytest.mark.parametrize(
    ("path", "client"),
    [
        ("home/alice/.mysql_history", "mysql"),
        ("root/.mariadb_history", "mariadb"),
        ("var/lib/postgresql/.psql_history", "psql"),
        ("home/alice/.sqlite_history", "sqlite3"),
        ("home/alice/.python_history", "python"),
        ("home/alice/.node_repl_history", "node"),
    ],
)
def test_client_histories_are_routed(path, client):
    assert looks_like_linux_artifact(f"volume-1/{path}") == ("linux_app_history", f"{client}_history", "linux_app_history_raw")


def test_libedit_history_is_decoded():
    # MySQL and MariaDB keep each typed line and then the whole statement.
    assert _commands(MYSQL, "home/alice/.mysql_history") == [
        "select 1;", 'select "a b",', "  2;", 'select "a b",   2;', "create database x;", "exit",
    ]


def test_psql_multiline_query_is_one_entry():
    assert _commands(PSQL, "root/.psql_history") == ["select 1;", "select 'a b',\n  2;", "\\dt", "\\q"]


def test_python_313_multiline_entry_is_one_entry():
    rows = parse_app_history(PYTHON_313.decode(), source_path="home/bob/.python_history")
    assert [(row["line_number"], row["command"]) for row in rows] == [
        (1, "import os"), (2, "def f():\n        return 1"), (5, "print(f())"), (6, "exit()"),
    ]
    assert {row["username"] for row in rows} == {"bob"}


def test_node_history_is_put_in_typing_order():
    rows = parse_app_history(NODE.decode(), source_path="root/.node_repl_history")
    assert [(row["history_index"], row["line_number"], row["command"]) for row in rows] == [
        (1, 3, "const a = 1"), (2, 2, 'require("child_process").execSync("id")'), (3, 1, ".exit"),
    ]
    assert rows[0]["username"] == "root"
    assert rows[0]["timestamp"] is None and rows[0]["timestamp_status"] == "missing"


def test_dispatch_keeps_carriage_returns_and_normalizes(tmp_path):
    path = tmp_path / ".python_history"
    path.write_bytes(PYTHON_313)
    rows = parse_linux_artifact_file(path, parser="linux_app_history_raw", artifact_type="python_history", source_path="home/bob/.python_history")
    assert rows[1]["command"] == "def f():\n        return 1"
    base = base_document("case-1", "ev-1", "art-1", rows[1], {"artifact_type": "linux_app_history"})
    doc = normalize_linux_row(base, rows[1], source_path=rows[1]["source_file"], artifact_type="linux_app_history")
    assert doc["linux"]["app_client"] == "python"
    assert doc["linux"]["history_index"] == 2
    assert doc["event"]["type"] == "python_history"
    assert doc["title"].startswith("python: def f():")


def test_app_history_reaches_command_history():
    event = {
        "id": "doc-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "@timestamp": None,
        "host": {"name": "db01"},
        "artifact": {"type": "linux_app_history", "parser": "linux_app_history_raw"},
        "linux": {"artifact_type": "mysql_history", "app_client": "mysql", "username": "alice", "command": "drop database x;"},
    }
    items = command_history._commands_from_event("case-1", event)
    assert len(items) == 1
    assert items[0]["source_type"] == "linux_app_history"
    assert items[0]["launcher"] == "mysql"
    assert items[0]["user"] == "alice"
