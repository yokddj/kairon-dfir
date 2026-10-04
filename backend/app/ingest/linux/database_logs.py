"""MySQL / MariaDB and PostgreSQL logs.

A database server's own logs record who connected from where, who failed to, and, when the general
query log, the audit plugin or ``log_statement`` is on, what they ran. After a breach that is the
trail of a password-guessing run, a dumped table, a created account or a command run through the
database.

* MySQL / MariaDB: the error log (8.0 and MariaDB layouts), the general query log (8.0 and the older
  layout without a time on every line), the slow query log, and the MariaDB / Percona audit plugin
  (``server_audit.log``).
* PostgreSQL: the text log under the common ``log_line_prefix`` forms, ``csvlog`` and, from 15,
  ``jsonlog``.

SQL statements are flagged, never judged: ``suspicious_indicators`` lists generic, widely known
markers (account and privilege changes, destructive statements, file read or write through the
server, command execution, credential-table access, schema enumeration, injection patterns) for an
analyst to review. The text of the statement is kept as logged.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

ARTIFACT_FAMILY = "linux_database"
MAX_STATEMENT_CHARS = 4000
MAX_MESSAGE_CHARS = 2000

_MYSQL_DIR = r"(?:mysql|mariadb|percona)"
_PATTERNS = (
    ("mysql", re.compile(rf"(^|/)var/log/{_MYSQL_DIR}/[^/]+\.(?:log|err)(?:[.-]\w+)*$", re.I)),
    ("mysql", re.compile(r"(^|/)var/log/(?:mysqld|mariadb|mysql)\.log(?:[.-]\w+)*$", re.I)),
    ("mysql", re.compile(r"(^|/)var/lib/mysql/[^/]+\.(?:err|log)(?:[.-]\w+)*$", re.I)),
    ("postgresql", re.compile(r"(^|/)var/log/postgresql/[^/]+\.(?:log|csv|json)(?:[.-]\w+)*$", re.I)),
    ("postgresql", re.compile(r"(^|/)var/lib/(?:pgsql|postgresql)/(?:[\w.]+/)*(?:log|pg_log)/[^/]+\.(?:log|csv|json)(?:[.-]\w+)*$", re.I)),
)

# Generic markers a statement is checked against. Lowercase-insensitive.
_STATEMENT_FLAGS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("account_change", re.compile(r"\b(?:grant|revoke)\b.+\b(?:to|from|on)\b|\b(?:create|alter|drop)\s+(?:user|role)\b|\bset\s+password\b|\balter\s+system\b", re.I | re.S)),
    ("destructive_statement", re.compile(r"\bdrop\s+(?:database|schema|table)\b|\btruncate\b|\bdelete\s+from\s+\S+\s*;?\s*$", re.I)),
    ("file_access", re.compile(r"\bload_file\s*\(|\binto\s+(?:outfile|dumpfile)\b|\bload\s+data\s+(?:local\s+)?infile\b|\bpg_read_(?:binary_)?file\b|\blo_(?:import|export)\b|\bcopy\b[^;]*\b(?:from|to)\s+'/", re.I)),
    ("command_execution", re.compile(r"\bcopy\b[^;]*\bprogram\b|\bsys_(?:exec|eval)\b|\bxp_cmdshell\b|\bcreate\s+(?:or\s+replace\s+)?function\b[^;]*\bsoname\b|\bcreate\s+function\b[^;]*\blanguage\s+c\b", re.I | re.S)),
    ("credential_table_access", re.compile(r"\bmysql\.(?:user|db|global_priv)\b|\binformation_schema\.(?:user_privileges|schema_privileges)\b|\bpg_(?:shadow|authid|user)\b", re.I)),
    ("schema_enumeration", re.compile(r"\binformation_schema\.(?:tables|columns|schemata)\b|\bpg_catalog\.pg_(?:tables|class|database|namespace)\b", re.I)),
    ("sql_injection_pattern", re.compile(r"\bunion\s+(?:all\s+)?select\b|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1\b|\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b|\b(?:extractvalue|updatexml)\s*\(", re.I)),
)


def database_engine(source_path: str) -> str | None:
    """``mysql`` (MySQL, MariaDB, Percona), ``postgresql`` or None."""
    path = str(source_path or "").replace("\\", "/")
    for engine, pattern in _PATTERNS:
        if pattern.search(path):
            return engine
    return None


def statement_flags(statement: str) -> list[str]:
    return [name for name, pattern in _STATEMENT_FLAGS if pattern.search(statement[:MAX_STATEMENT_CHARS])]


def _ip(value: str) -> str:
    import ipaddress

    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return ""


def _row(engine: str, kind: str, source_path: str, line_number: int, *, timestamp: str | None, status: str, message: str, raw: str, **fields: Any) -> dict[str, Any]:
    statement = str(fields.get("db_statement") or "")
    flags = statement_flags(statement) if statement else []
    row: dict[str, Any] = {
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_type": kind,
        "source_file": source_path,
        "line_number": line_number,
        "timestamp": timestamp,
        "timestamp_status": status if timestamp else "missing",
        "message": message[:MAX_MESSAGE_CHARS],
        "raw_excerpt": raw[:MAX_MESSAGE_CHARS],
        "db_engine": engine,
        "suspicious_indicators": flags,
    }
    row.update({key: value for key, value in fields.items() if value not in (None, "")})
    if statement:
        row["db_statement"] = statement[:MAX_STATEMENT_CHARS]
    return row


def _iso(value: str, *, assume_utc_status: str = "assumed_utc") -> tuple[str | None, str]:
    """An ISO-like timestamp. A trailing Z or offset is exact; otherwise it is read as UTC and flagged."""
    text = value.strip().replace(" ", "T", 1)
    exact = text.endswith("Z") or bool(re.search(r"[+-]\d{2}:?\d{2}$", text[10:]))
    text = text[:-1] + "+00:00" if text.endswith("Z") else text
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text) if re.search(r"[+-]\d{4}$", text[10:]) else text
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None, "missing"
    if parsed.year < 1990:
        return None, "missing"
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(), "ok" if exact else assume_utc_status


def _legacy_mysql_time(value: str) -> tuple[str | None, str]:
    """``240301 10:20:30`` (two-digit year, no zone)."""
    match = re.match(r"^(\d{2})(\d{2})(\d{2})\s+(\d{1,2}):(\d{2}):(\d{2})$", value.strip())
    if not match:
        return None, "missing"
    year, month, day, hour, minute, second = (int(g) for g in match.groups())
    try:
        return datetime(2000 + year, month, day, hour, minute, second, tzinfo=timezone.utc).isoformat(), "assumed_utc"
    except ValueError:
        return None, "missing"


# ----------------------------------------------------------------------- MySQL / MariaDB

_MYSQL_ERROR_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\s?\d{1,2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?:(?P<thread>\d+)\s+)?\[(?P<level>[A-Za-z]+)\]\s+(?:\[(?P<code>MY-\d+)\]\s+)?(?:\[(?P<subsystem>[A-Za-z_ ]+)\]\s+)?(?P<msg>.*)$"
)
# MySQL 5.5 / 5.6 and older MariaDB: "160403 19:02:55 [Note] ..." or "160403 19:02:55 InnoDB: ...".
_MYSQL_ERROR_LEGACY_RE = re.compile(r"^(?P<ts>\d{6}\s+\d{1,2}:\d{2}:\d{2})\s+(?:\[(?P<level>[A-Za-z]+)\]\s+)?(?P<msg>.*)$")
_ACCESS_DENIED_RE = re.compile(r"Access denied for user '(?P<user>[^']*)'@'(?P<host>[^']*)'(?: \(using password: (?P<pw>YES|NO)\))?")
_ABORTED_RE = re.compile(r"Aborted connection (?P<id>\d+) to db: '(?P<db>[^']*)' user: '(?P<user>[^']*)' host: '(?P<host>[^']*)'(?: \((?P<reason>[^)]*)\))?")
_BLOCKED_RE = re.compile(r"Host '(?P<host>[^']*)' is blocked because of many connection errors")
_RESOLVE_RE = re.compile(r"IP address '(?P<host>[^']*)' could not be resolved")

_GENERAL_RE = re.compile(
    r"^(?:(?P<ts>\d{4}-\d{2}-\d{2}T\S+|\d{6}\s+\d{1,2}:\d{2}:\d{2}))?\t\s*(?P<id>\d+)\s+(?P<cmd>[A-Za-z][A-Za-z ]*?)(?:\t(?P<arg>.*))?$"
)
_CONNECT_ARG_RE = re.compile(r"^(?P<user>[^@\s]*)@(?P<host>\S*)(?: on (?P<db>\S*))?(?: using (?P<via>\S+))?")
_SLOW_USER_RE = re.compile(r"^# User@Host: (?P<user>[^\[\s]*)\[[^\]]*\] @ (?P<host>\S*)\s*\[(?P<ip>[^\]]*)\](?:\s+Id:\s*(?P<id>\d+))?")
_SLOW_STATS_RE = re.compile(r"Query_time: (?P<qt>[\d.]+)\s+Lock_time: (?P<lt>[\d.]+)\s+Rows_sent: (?P<sent>\d+)\s+Rows_examined: (?P<exam>\d+)")
_AUDIT_TS_RE = re.compile(r"^\d{8} \d{2}:\d{2}:\d{2},")

_MYSQL_LEVEL = {"note": "info", "system": "info", "warning": "warning", "error": "error", "info": "info"}


def _sniff_mysql(content: str, source_path: str) -> str:
    name = source_path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    head = [line for line in content.splitlines()[:60] if line.strip()]
    if any(_AUDIT_TS_RE.match(line) for line in head[:5]) and ("audit" in name or any(",QUERY," in l or ",CONNECT," in l or ",FAILED_CONNECT," in l for l in head)):
        return "mysql_audit"
    if any(line.startswith("# User@Host:") or line.startswith("# Time:") for line in head) or "slow" in name:
        return "mysql_slow"
    if any(_GENERAL_RE.match(line) and "\t" in line for line in head) and not any(_MYSQL_ERROR_RE.match(line) for line in head[:5]):
        return "mysql_general"
    return "mysql_error"


def _parse_mysql_error(content: str, source_path: str) -> list[dict]:
    rows: list[dict] = []
    for number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        match = _MYSQL_ERROR_RE.match(stripped)
        legacy = None if match else _MYSQL_ERROR_LEGACY_RE.match(stripped)
        if not match and not legacy:
            rows.append(_row("mysql", "mysql_error", source_path, number, timestamp=None, status="missing", message=stripped, raw=stripped))
            continue
        if match:
            stamp, status = _iso(match.group("ts"))
            level = match.group("level").lower()
            thread, code = match.group("thread"), match.group("code")
        else:
            stamp, status = _legacy_mysql_time(legacy.group("ts"))
            level = (legacy.group("level") or "note").lower()
            thread = code = None
        message = (match or legacy).group("msg")
        fields: dict[str, Any] = {
            "db_level": level,
            "severity": _MYSQL_LEVEL.get(level, level),
            "db_thread_id": thread,
            "db_error_code": code,
            "event_action": "db_log",
        }
        denied = _ACCESS_DENIED_RE.search(message)
        aborted = _ABORTED_RE.search(message)
        blocked = _BLOCKED_RE.search(message)
        resolve = _RESOLVE_RE.search(message)
        if denied:
            host = denied.group("host")
            fields.update(event_action="db_auth_failed", db_status="failed", username=denied.group("user") or None, source_ip=_ip(host), db_client_host=host if not _ip(host) else "", authentication=f"password={denied.group('pw')}" if denied.group("pw") else "")
        elif aborted:
            host = aborted.group("host")
            fields.update(event_action="db_connection_aborted", db_name=aborted.group("db"), username=aborted.group("user") or None, source_ip=_ip(host), db_thread_id=aborted.group("id"), db_reason=aborted.group("reason") or "")
        elif blocked:
            fields.update(event_action="db_host_blocked", db_status="failed", source_ip=_ip(blocked.group("host")), db_client_host=blocked.group("host"))
        elif resolve:
            fields.update(source_ip=_ip(resolve.group("host")))
        rows.append(_row("mysql", "mysql_error", source_path, number, timestamp=stamp, status=status, message=message, raw=stripped, **fields))
    return rows


def _parse_mysql_general(content: str, source_path: str) -> list[dict]:
    rows: list[dict] = []
    last: tuple[str | None, str] = (None, "missing")
    current: dict | None = None
    for number, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            continue
        match = _GENERAL_RE.match(line)
        if not match:
            # A statement spanning lines, or a server banner before the first event.
            if current is not None and current.get("db_statement") is not None:
                current["db_statement"] = (current["db_statement"] + "\n" + line.strip())[:MAX_STATEMENT_CHARS]
                current["message"] = f"{current['db_command']} {current['db_statement']}"[:MAX_MESSAGE_CHARS]
                current["suspicious_indicators"] = statement_flags(current["db_statement"])
            else:
                rows.append(_row("mysql", "mysql_general", source_path, number, timestamp=None, status="missing", message=line.strip(), raw=line))
            continue
        ts_text = match.group("ts")
        if ts_text:
            last = _iso(ts_text) if "T" in ts_text else _legacy_mysql_time(ts_text)
        stamp, status = last  # the older layout writes the time only when it changes
        command = match.group("cmd").strip()
        argument = (match.group("arg") or "").strip()
        fields: dict[str, Any] = {"db_thread_id": match.group("id"), "db_command": command, "event_action": "db_" + re.sub(r"\W+", "_", command.lower())}
        statement = ""
        if command == "Connect":
            denied = _ACCESS_DENIED_RE.search(argument)
            connect = _CONNECT_ARG_RE.match(argument)
            if denied:
                fields.update(event_action="db_auth_failed", db_status="failed", username=denied.group("user") or None, source_ip=_ip(denied.group("host")), db_client_host=denied.group("host") if not _ip(denied.group("host")) else "")
            elif connect:
                host = connect.group("host")
                fields.update(event_action="db_connect", db_status="success", username=connect.group("user") or None, source_ip=_ip(host), db_client_host=host if not _ip(host) else "", db_name=connect.group("db") or "")
        elif command in {"Query", "Prepare", "Execute"}:
            statement = argument
            fields["event_action"] = "db_query"
        elif command == "Init DB":
            fields.update(db_name=argument)
        elif command == "Change user":
            user = argument.split(" ", 1)[0]
            fields.update(event_action="db_change_user", username=user or None)
        elif command == "Quit":
            fields["event_action"] = "db_disconnect"
        row = _row("mysql", "mysql_general", source_path, number, timestamp=stamp, status=status, message=f"{command} {argument}".strip(), raw=line, db_statement=statement, **fields)
        if not statement:
            row.pop("db_statement", None)
        rows.append(row)
        current = row if statement else None
    return rows


def _parse_mysql_slow(content: str, source_path: str) -> list[dict]:
    rows: list[dict] = []
    block: dict[str, Any] = {}
    statement: list[str] = []
    start = 0
    raw: list[str] = []

    def flush() -> None:
        if not block and not statement:
            return
        text = "\n".join(statement).strip()
        stamp, status = block.get("time", (None, "missing"))
        if block.get("epoch"):
            stamp, status = datetime.fromtimestamp(block["epoch"], tz=timezone.utc).isoformat(), "ok"
        fields = {k: v for k, v in block.items() if k not in {"time", "epoch"}}
        rows.append(_row("mysql", "mysql_slow", source_path, start, timestamp=stamp, status=status,
                         message=f"Slow query ({block.get('db_query_time', '?')}s, {block.get('db_rows_examined', '?')} rows examined): {text}"[:MAX_MESSAGE_CHARS],
                         raw="\n".join(raw), db_statement=text, event_action="db_slow_query", **fields))

    for number, line in enumerate(content.splitlines(), start=1):
        stripped = line.rstrip()
        if stripped.startswith("# Time:"):
            flush()
            block, statement, raw, start = {}, [], [stripped], number
            value = stripped.split(":", 1)[1].strip()
            block["time"] = _iso(value) if "T" in value or "-" in value[:5] else _legacy_mysql_time(value)
        elif stripped.startswith("# User@Host:"):
            if not raw:
                block, statement, raw, start = {}, [], [], number
            raw.append(stripped)
            user = _SLOW_USER_RE.match(stripped)
            if user:
                ip = _ip(user.group("ip")) or _ip(user.group("host"))
                block.update(username=user.group("user") or None, source_ip=ip, db_client_host=user.group("host") if not ip else "", db_thread_id=user.group("id") or "")
        elif stripped.startswith("# Query_time:"):
            raw.append(stripped)
            stats = _SLOW_STATS_RE.search(stripped)
            if stats:
                block.update(db_query_time=float(stats.group("qt")), db_rows_sent=int(stats.group("sent")), db_rows_examined=int(stats.group("exam")))
        elif stripped.startswith("SET timestamp="):
            raw.append(stripped)
            match = re.match(r"SET timestamp=(\d+)", stripped)
            if match:
                block["epoch"] = int(match.group(1))
        elif stripped.startswith("use ") and stripped.endswith(";") and not statement:
            raw.append(stripped)
            block["db_name"] = stripped[4:-1].strip("`")
        elif stripped.startswith("#"):
            raw.append(stripped)
        elif stripped:
            raw.append(stripped)
            if not raw or start == 0:
                start = number
            statement.append(stripped)
    flush()
    return rows


def _parse_mysql_audit(content: str, source_path: str) -> list[dict]:
    rows: list[dict] = []
    for number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if not _AUDIT_TS_RE.match(stripped):
            rows.append(_row("mysql", "mysql_audit", source_path, number, timestamp=None, status="missing", message=stripped, raw=stripped))
            continue
        try:
            fields = next(csv.reader([stripped], quotechar="'", skipinitialspace=False))
        except (csv.Error, StopIteration):
            fields = stripped.split(",")
        fields += [""] * (10 - len(fields))
        when, serverhost, user, client, connid, queryid, operation, database, objectname, retcode = fields[:10]
        try:
            stamp = datetime.strptime(when, "%Y%m%d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            stamp = None
        failed = operation.upper().startswith("FAILED") or (retcode not in {"", "0"} and operation.upper() in {"CONNECT", "FAILED_CONNECT"})
        action = "db_auth_failed" if operation.upper() == "FAILED_CONNECT" else "db_connect" if operation.upper() == "CONNECT" else "db_disconnect" if operation.upper() == "DISCONNECT" else "db_query" if operation.upper() in {"QUERY", "QUERY_DDL", "QUERY_DML", "QUERY_DCL", "QUERY_DML_NO_SELECT"} else f"db_{operation.lower() or 'event'}"
        statement = objectname if operation.upper().startswith("QUERY") else ""
        rows.append(_row("mysql", "mysql_audit", source_path, number, timestamp=stamp, status="assumed_utc",
                         message=f"{operation} {objectname}".strip(), raw=stripped, db_statement=statement, event_action=action,
                         username=user or None, source_ip=_ip(client), db_client_host=client if not _ip(client) else "", db_thread_id=connid,
                         db_name=database, db_command=operation, db_retcode=retcode, db_status="failed" if failed else "", db_object=(objectname if not statement else "")[:512],
                         host=serverhost or None))
    return rows


# ------------------------------------------------------------------------ PostgreSQL

_PG_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)(?: (?P<tz>[A-Z]{2,5}|[+-]\d{2,4}))?\s*(?:\[(?P<pid>\d+)(?:-\d+)?\])?:?\s+"
    r"(?:(?P<user>[^@\s\[\]]*)@(?P<db>[^\s\[\]]*)\s+)?"
    r"(?P<level>DEBUG[1-5]?|INFO|NOTICE|WARNING|ERROR|LOG|FATAL|PANIC|STATEMENT|DETAIL|HINT|CONTEXT|QUERY|LOCATION):\s+(?P<msg>.*)$"
)
_PG_CONN_RE = re.compile(r"connection (?P<what>received|authorized|authenticated): (?P<rest>.*)$")
_PG_KV_RE = re.compile(r"(?P<key>[a-z_]+)=(?P<value>\"[^\"]*\"|\S+)")
_PG_AUTH_FAILED_RE = re.compile(r"(?:password|Peer|Ident|LDAP|PAM|GSSAPI|SCRAM|md5|trust|certificate) authentication failed for user \"(?P<user>[^\"]*)\"|no pg_hba\.conf entry for host \"(?P<host>[^\"]*)\", user \"(?P<hbauser>[^\"]*)\", database \"(?P<hbadb>[^\"]*)\"", re.I)
_PG_STATEMENT_RE = re.compile(r"^(?:statement|execute [^:]*|duration: [\d.]+ ms\s+(?:statement|execute [^:]*)): (?P<sql>.*)$", re.S | re.I)
_PG_TZ_OFFSETS = {"UTC": 0, "GMT": 0, "Z": 0}


_PG_TS_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*(?P<tz>Z|[A-Z]{2,5}|[+-]\d{2}(?::?\d{2})?)?$")


def _pg_ts(text: str) -> tuple[str | None, str]:
    """A PostgreSQL timestamp such as ``2024-03-01 10:20:30.123 UTC`` (``%m``, csvlog, jsonlog)."""
    match = _PG_TS_RE.match(text.strip())
    if not match:
        return None, "missing"
    return _pg_time(match.group("ts"), match.group("tz"))


def _pg_time(ts: str, tz: str | None) -> tuple[str | None, str]:
    text = ts.replace(" ", "T", 1)
    if tz and re.fullmatch(r"[+-]\d{2}(?::?\d{2})?", tz):
        digits = tz.replace(":", "")
        text += digits if len(digits) == 5 else digits + "00"
        return _iso(text)
    stamp, _ = _iso(text)
    # A zone abbreviation ("UTC", "GMT") is exact; any other (CEST, EST, ...) is ambiguous, so the
    # time is read as UTC and said to be assumed.
    return stamp, "ok" if tz in _PG_TZ_OFFSETS else "assumed_utc"


def _pg_message_fields(level: str, message: str, user: str | None, database: str | None, host: str | None = None, port: str | None = None) -> dict[str, Any]:
    fields: dict[str, Any] = {"event_action": "db_log", "username": user or None, "db_name": database or None, "db_level": level.lower()}
    if host:
        fields.update(source_ip=_ip(host), db_client_host=host if not _ip(host) else "")
    if port and port.isdigit():
        fields["source_port"] = int(port)
    conn = _PG_CONN_RE.match(message)
    if conn:
        pairs = {m.group("key"): m.group("value").strip('"') for m in _PG_KV_RE.finditer(conn.group("rest"))}
        what = conn.group("what")
        if pairs.get("host"):
            fields.update(source_ip=_ip(pairs["host"]) or fields.get("source_ip"), db_client_host=pairs["host"] if not _ip(pairs["host"]) else "")
        if pairs.get("port", "").isdigit():
            fields["source_port"] = int(pairs["port"])
        if pairs.get("user"):
            fields["username"] = pairs["user"]
        if pairs.get("database"):
            fields["db_name"] = pairs["database"]
        fields.update(event_action="db_connect" if what != "received" else "db_connection_received", db_status="success" if what != "received" else "")
        return fields
    failed = _PG_AUTH_FAILED_RE.search(message)
    if failed:
        fields.update(event_action="db_auth_failed", db_status="failed")
        if failed.group("user"):
            fields["username"] = failed.group("user")
        if failed.group("hbauser"):
            fields.update(username=failed.group("hbauser"), db_name=failed.group("hbadb"), source_ip=_ip(failed.group("host")), db_client_host=failed.group("host") if not _ip(failed.group("host")) else "")
        return fields
    if message.startswith("disconnection:"):
        pairs = {m.group("key"): m.group("value").strip('"') for m in _PG_KV_RE.finditer(message)}
        fields.update(event_action="db_disconnect", username=pairs.get("user") or fields.get("username"), db_name=pairs.get("database") or fields.get("db_name"), source_ip=_ip(pairs.get("host", "")) or fields.get("source_ip"))
        return fields
    statement = _PG_STATEMENT_RE.match(message)
    if statement:
        fields.update(event_action="db_query", db_statement=statement.group("sql"))
    elif level in {"ERROR", "FATAL", "PANIC"}:
        fields["event_action"] = "db_error"
    return fields


def _parse_pg_text(content: str, source_path: str) -> list[dict]:
    rows: list[dict] = []
    current: dict | None = None
    for number, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            continue
        match = _PG_LINE_RE.match(line)
        if not match:
            # A continuation: a wrapped statement or message, indented by a tab in PostgreSQL's own output.
            if current is not None:
                extra = line.strip()
                current["message"] = (current["message"] + "\n" + extra)[:MAX_MESSAGE_CHARS]
                if current.get("db_statement") is not None:
                    current["db_statement"] = (current["db_statement"] + "\n" + extra)[:MAX_STATEMENT_CHARS]
                    current["suspicious_indicators"] = statement_flags(current["db_statement"])
            else:
                rows.append(_row("postgresql", "postgres_log", source_path, number, timestamp=None, status="missing", message=line.strip(), raw=line))
            continue
        level = match.group("level")
        message = match.group("msg")
        if level in {"STATEMENT", "QUERY"} and current is not None:
            # The statement behind the ERROR / FATAL / LOG line just above it.
            current["db_statement"] = message[:MAX_STATEMENT_CHARS]
            current["suspicious_indicators"] = statement_flags(message)
            current["message"] = (current["message"] + f"\n{level}: {message}")[:MAX_MESSAGE_CHARS]
            continue
        if level in {"DETAIL", "HINT", "CONTEXT", "LOCATION"} and current is not None:
            current["message"] = (current["message"] + f"\n{level}: {message}")[:MAX_MESSAGE_CHARS]
            continue
        stamp, status = _pg_time(match.group("ts"), match.group("tz"))
        fields = _pg_message_fields(level, message, match.group("user"), match.group("db"))
        fields["db_thread_id"] = match.group("pid")
        fields["severity"] = level.lower()
        current = _row("postgresql", "postgres_log", source_path, number, timestamp=stamp, status=status, message=message, raw=line, **fields)
        rows.append(current)
    return rows


def _parse_pg_json(content: str, source_path: str) -> list[dict]:
    rows: list[dict] = []
    for number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except ValueError:
            record = None
        if not isinstance(record, dict) or "error_severity" not in record and "message" not in record:
            rows.append(_row("postgresql", "postgres_log", source_path, number, timestamp=None, status="missing", message=stripped, raw=stripped))
            continue
        stamp, status = _pg_ts(str(record["timestamp"])) if record.get("timestamp") else (None, "missing")
        level = str(record.get("error_severity") or "LOG")
        message = str(record.get("message") or "")
        fields = _pg_message_fields(level, message, record.get("user"), record.get("dbname"), record.get("remote_host"), str(record.get("remote_port") or ""))
        fields.update(db_thread_id=str(record.get("pid") or ""), severity=level.lower(), db_error_code=record.get("state_code") or "", db_application=record.get("application_name") or "")
        if record.get("query"):
            fields["db_statement"] = str(record["query"])
        rows.append(_row("postgresql", "postgres_log", source_path, number, timestamp=stamp, status=status, message=message + (f"\nDETAIL: {record['detail']}" if record.get("detail") else ""), raw=stripped, **fields))
    return rows


_PG_CSV_COLUMNS = (
    "log_time", "user_name", "database_name", "process_id", "connection_from", "session_id", "session_line_num", "command_tag",
    "session_start_time", "virtual_transaction_id", "transaction_id", "error_severity", "sql_state_code", "message", "detail", "hint",
    "internal_query", "internal_query_pos", "context", "query", "query_pos", "location", "application_name", "backend_type",
)


def _parse_pg_csv(content: str, source_path: str) -> list[dict]:
    rows: list[dict] = []
    reader = csv.reader(io.StringIO(content))
    number = 0
    try:
        for record in reader:
            number += 1
            if len(record) < 14:
                if record:
                    rows.append(_row("postgresql", "postgres_log", source_path, number, timestamp=None, status="missing", message=",".join(record), raw=",".join(record)))
                continue
            data = dict(zip(_PG_CSV_COLUMNS, record))
            stamp, status = _pg_ts(data["log_time"]) if data["log_time"] else (None, "missing")
            host, _, port = data["connection_from"].rpartition(":")
            level = data["error_severity"] or "LOG"
            fields = _pg_message_fields(level, data["message"], data["user_name"], data["database_name"], host or data["connection_from"], port)
            fields.update(db_thread_id=data["process_id"], severity=level.lower(), db_error_code=data["sql_state_code"], db_application=data["application_name"], db_command=data["command_tag"])
            if data["query"]:
                fields["db_statement"] = data["query"]
            rows.append(_row("postgresql", "postgres_log", source_path, number, timestamp=stamp, status=status, message=data["message"], raw=",".join(record), **fields))
    except csv.Error:
        pass
    return rows


def parse_database_log(content: str, *, source_path: str = "", truncated: bool = False) -> list[dict]:
    engine = database_engine(source_path)
    if engine is None:
        return []
    lowered = source_path.lower()
    first = next((line.strip() for line in content.splitlines() if line.strip()), "")
    if engine == "postgresql":
        if lowered.endswith(".json") or (first.startswith("{") and '"error_severity"' in first):
            rows = _parse_pg_json(content, source_path)
        elif ".csv" in lowered:
            rows = _parse_pg_csv(content, source_path)
        else:
            rows = _parse_pg_text(content, source_path)
    else:
        kind = _sniff_mysql(content, source_path)
        rows = {"mysql_audit": _parse_mysql_audit, "mysql_slow": _parse_mysql_slow, "mysql_general": _parse_mysql_general}.get(kind, _parse_mysql_error)(content, source_path)
    if truncated:
        rows.append(_row(engine, rows[-1]["artifact_type"] if rows else "database_log", source_path, len(content.splitlines()) + 1, timestamp=None, status="missing",
                         message="[kairon] log truncated: only the first part of this file was parsed (size limit or damaged archive)", raw=""))
    return rows
