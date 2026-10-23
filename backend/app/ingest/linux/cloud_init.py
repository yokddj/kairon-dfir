"""cloud-init: what a cloud image was told to do at first boot, and what it did.

cloud-init configures a cloud instance from *user-data* (written by whoever launched it) and
*vendor-data* (from the cloud provider): users and SSH keys, commands run at boot (``bootcmd``) and
at the end of the first boot (``runcmd``), files written, packages and repositories. An intruder
with access to the cloud console or metadata can use the same mechanism, and scripts dropped in
``/var/lib/cloud/scripts/per-boot`` run on every boot.

Sources:

* ``/var/log/cloud-init.log``: the debug log. Lines carry the module, the level and, where they
  apply, a command run, a file written or a user added. Each run starts with
  ``Cloud-init v. X running 'stage' at <RFC 2822 time with zone>``; recent versions write their log
  times in UTC, and the offset between that header and the line's own time is applied to the run,
  so a version that logs local time is corrected as well.
* ``/var/log/cloud-init-output.log``: the console output of each stage (script output, ``ci-info``
  tables). Lines take the time of the stage header before them.
* user-data and vendor-data as stored for each instance (``/var/lib/cloud/instances/<id>/
  user-data.txt``, ``vendor-data*.txt``) and the NoCloud seed (``/var/lib/cloud/seed/*/``): cloud-config
  YAML, shell scripts, boothooks, ``#include`` URL lists, MIME multipart and gzip are all decoded.
* scripts cloud-init runs: ``/var/lib/cloud/instances/<id>/scripts/*`` (``runcmd`` as written for
  the shell) and ``/var/lib/cloud/scripts/per-{boot,instance,once}/*``.
* system configuration: ``/etc/cloud/cloud.cfg`` and ``/etc/cloud/cloud.cfg.d/*.cfg``.
* instance state: ``/var/lib/cloud/data/{instance-id,previous-instance-id,status.json,result.json}``
  and ``/var/lib/cloud/instances/<id>/datasource``.

Commands, script lines and written file contents get the same generic ``suspicious_indicators`` as
app.ingest.linux.persistence: flags for review, never verdicts. Nothing is executed, and ``obj.pkl``
(a Python pickle) is never loaded. Plain-text passwords in user-data are not copied into rows; a row
records that one was set.
"""
from __future__ import annotations

import ast
import base64
import binascii
import email
import gzip
import json
import re
import shlex
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import yaml

from app.ingest.linux.persistence import suspicious_indicators

ARTIFACT_FAMILY = "linux_cloud_init"
MAX_TEXT = 2000
MAX_CONTINUATION_LINES = 200

_KINDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("cloud_init_log", re.compile(r"(^|/)var/log/cloud-init\.log(?:[.-]\d[^/]*)?$", re.I)),
    ("cloud_init_output", re.compile(r"(^|/)var/log/cloud-init-output\.log(?:[.-]\d[^/]*)?$", re.I)),
    ("user_data", re.compile(r"(^|/)var/lib/cloud/(?:instances/[^/]+/(?:user-data|vendor-data2?)\.txt|seed/[^/]+/(?:user-data|vendor-data))$", re.I)),
    ("cloud_script", re.compile(r"(^|/)var/lib/cloud/(?:instances/[^/]+/scripts|scripts/(?:per-boot|per-instance|per-once|vendor))/[^/]+$", re.I)),
    ("cloud_config", re.compile(r"(^|/)etc/cloud/cloud\.cfg(?:\.d/[^/]+\.cfg)?$", re.I)),
    ("cloud_instance", re.compile(r"(^|/)var/lib/cloud/(?:data/(?:instance-id|previous-instance-id|status\.json|result\.json)|instances/[^/]+/datasource)$", re.I)),
)

_INSTANCE_RE = re.compile(r"(?:^|/)var/lib/cloud/instances/([^/]+)/")
_LOG_LINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,(\d{1,6}))? - ([^\[\]:]+?)\[([A-Z]+)\]: ?(.*)$")
_HEADER_RE = re.compile(r"Cloud-init v\. (\S+) (?:running '([^']+)' at|finished at) ([^.]+?\d{2}:\d{2}:\d{2} [+-]\d{4})")
_COMMAND_RE = re.compile(r"^Running command (\[.*?\]|\S.*?) with allowed return codes")
_WRITE_RE = re.compile(r"^Writing to (\S+) - ")
_ADD_USER_RE = re.compile(r"^Adding user (\S+)")
_MODULE_RE = re.compile(r"^Running module (\S+) ")
_DATASOURCE_RE = re.compile(r"^Detected (DataSource\S+)|found data source: (DataSource\S+)", re.I)
# Top-level keys of the system cloud.cfg that only list modules or distro defaults.
_MODULE_LIST_KEYS = {"cloud_init_modules", "cloud_config_modules", "cloud_final_modules", "system_info", "datasource_list", "datasource", "reporting"}
_SECRET_KEYS = {"password", "passwd", "hashed_passwd", "plain_text_passwd"}


def cloud_init_kind(source_path: str) -> str | None:
    path = str(source_path or "").replace("\\", "/")
    if path.endswith((".txt.i", "obj.pkl")):
        return None
    for kind, pattern in _KINDS:
        if pattern.search(path):
            return kind
    return None


def _row(kind: str, source_path: str, **fields: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_type": kind,
        "source_file": source_path,
        "timestamp": None,
        "timestamp_status": "missing",
    }
    instance = _INSTANCE_RE.search(str(source_path or "").replace("\\", "/"))
    if instance:
        row["instance_id"] = instance.group(1)
    row.update(fields)
    if row.get("timestamp") and row["timestamp_status"] == "missing":
        row["timestamp_status"] = "ok"
    row["message"] = str(row.get("message") or "")[:MAX_TEXT]
    row["raw_excerpt"] = str(row.get("raw_excerpt") or row["message"])[:MAX_TEXT]
    if row.get("command"):
        row["command"] = str(row["command"])[:MAX_TEXT]
    return row


def _header_time(text: str) -> datetime | None:
    try:
        return parsedate_to_datetime(text).astimezone(timezone.utc)
    except (TypeError, ValueError, IndexError):
        return None


def _command_text(value: str) -> str:
    """``['useradd', 'deploy', '-m']`` (a Python list in the log) as a shell-quoted command line."""
    if value.startswith("["):
        try:
            parts = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            return value
        if isinstance(parts, (list, tuple)):
            return shlex.join(str(part) for part in parts)
    return value


# ------------------------------------------------------------------ logs


def _parse_log(content: str, *, source_path: str) -> list[dict]:
    rows: list[dict] = []
    offset: timedelta | None = None
    stage = None
    continuation = 0
    # The offset of a run is known only at its header; lines written before the first header
    # (a rotated file that starts mid-run) take the first header's offset.
    pending_start = 0
    for line_number, line in enumerate(content.splitlines(), start=1):
        match = _LOG_LINE_RE.match(line)
        if not match:
            if rows and line.strip() and continuation < MAX_CONTINUATION_LINES:
                # Tracebacks and wrapped output belong to the entry before them.
                previous = rows[-1]
                previous["message"] = f"{previous['message']}\n{line}"[:MAX_TEXT]
                previous["raw_excerpt"] = f"{previous['raw_excerpt']}\n{line}"[:MAX_TEXT]
                continuation += 1
            continue
        continuation = 0
        stamp, fraction, module, level, message = match.groups()
        logged = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        if fraction:
            logged += timedelta(microseconds=int(fraction.ljust(6, "0")[:6]))
        fields: dict[str, Any] = {"event_action": "log"}
        header = _HEADER_RE.search(message)
        if header:
            version, header_stage, when = header.groups()
            exact = _header_time(when)
            if exact is not None:
                # Whole quarter hours: the header has no sub-second part, the line does.
                minutes = round((logged - exact).total_seconds() / 900) * 15
                offset = timedelta(minutes=minutes)
                for earlier in rows[pending_start:]:
                    if earlier["timestamp_status"] == "unverified":
                        earlier["timestamp"] = (datetime.fromisoformat(earlier["timestamp"]) - offset).isoformat()
                        earlier["timestamp_status"] = "ok"
                pending_start = len(rows)
            stage = header_stage or stage
            fields = {"event_action": "stage_start" if header_stage else "stage_finish", "cloud_init_version": version}
        elif (command := _COMMAND_RE.match(message)) is not None:
            text = _command_text(command.group(1))
            fields = {"event_action": "command", "command": text, "suspicious_indicators": suspicious_indicators(text)}
        elif (written := _WRITE_RE.match(message)) is not None:
            fields = {"event_action": "file_write", "file_path": written.group(1)}
        elif (user := _ADD_USER_RE.match(message)) is not None:
            fields = {"event_action": "user_add", "username": user.group(1)}
        elif (module_match := _MODULE_RE.match(message)) is not None:
            fields = {"event_action": "module", "cloud_init_module": module_match.group(1)}
        elif (datasource := _DATASOURCE_RE.search(message)) is not None:
            fields = {"event_action": "datasource", "datasource": datasource.group(1) or datasource.group(2)}
        if offset is None:
            timestamp, status = logged.isoformat(), "unverified"
        else:
            timestamp, status = (logged - offset).isoformat(), "ok"
        rows.append(_row(
            "cloud_init_log", source_path,
            line_number=line_number, timestamp=timestamp, timestamp_status=status, severity=level.lower(),
            component=module.strip(), cloud_init_stage=stage, message=message, raw_excerpt=line, **fields,
        ))
    for row in rows:
        if row["timestamp_status"] == "unverified":
            # No run header anywhere in the file: cloud-init writes UTC, but this copy cannot show it.
            row["timestamp_status"] = "format_utc"
    return rows


def _parse_output(content: str, *, source_path: str) -> list[dict]:
    rows: list[dict] = []
    timestamp = None
    stage = None
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.rstrip()
        if not stripped.strip():
            continue
        fields: dict[str, Any] = {"event_action": "output"}
        header = _HEADER_RE.search(stripped)
        logged = _LOG_LINE_RE.match(stripped)
        if header:
            exact = _header_time(header.group(3))
            timestamp = exact.isoformat() if exact else timestamp
            stage = header.group(2) or stage
            fields = {"event_action": "stage_start" if header.group(2) else "stage_finish", "cloud_init_version": header.group(1)}
        elif logged:
            # A log line echoed to the console keeps its level.
            fields["severity"] = logged.group(4).lower()
        if not header:
            fields["suspicious_indicators"] = suspicious_indicators(stripped)
        rows.append(_row(
            "cloud_init_output", source_path,
            line_number=line_number, timestamp=timestamp, cloud_init_stage=stage, message=stripped, **fields,
        ))
    return rows


# ------------------------------------------------------------------ user-data


def _decode_payload(data: bytes) -> str:
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError):
            pass
    return data.decode("utf-8", errors="replace")


def _script_rows(text: str, *, kind: str, source_path: str, part: str | None, action: str, first_line: int = 1) -> list[dict]:
    rows = []
    for offset, line in enumerate(text.splitlines()):
        stripped = line.strip()
        if not stripped or (stripped.startswith("#") and not stripped.startswith("#!")):
            continue
        if stripped.startswith("#!"):
            continue  # the interpreter line itself
        rows.append(_row(
            kind, source_path,
            line_number=first_line + offset, event_action=action, command=stripped, message=stripped, raw_excerpt=line,
            user_data_part=part, suspicious_indicators=suspicious_indicators(stripped),
        ))
    return rows


def _construct(node: yaml.Node) -> Any:
    loader = yaml.SafeLoader("")
    try:
        return loader.construct_object(node, deep=True)
    finally:
        loader.dispose()


def _as_command(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return shlex.join(str(part) for part in value)
    return str(value)


def _summary(value: Any) -> str:
    text = json.dumps(value, default=str, ensure_ascii=False) if not isinstance(value, str) else value
    return text[:500]


def _write_file_content(entry: dict) -> str:
    content = entry.get("content")
    if content is None:
        return ""
    encoding = str(entry.get("encoding") or "").lower()
    raw = content.encode() if isinstance(content, str) else bytes(content) if isinstance(content, (bytes, bytearray)) else str(content).encode()
    try:
        if encoding in {"b64", "base64", "gz+base64", "gzip+base64", "gz+b64", "gzip+b64"}:
            raw = base64.b64decode(raw, validate=False)
        if encoding.startswith(("gz", "gzip")):
            raw = gzip.decompress(raw)
    except (binascii.Error, OSError, EOFError, ValueError):
        return content if isinstance(content, str) else ""
    return raw.decode("utf-8", errors="replace")


def _config_item_rows(key: str, node: yaml.Node, *, kind: str, source_path: str, part: str | None) -> list[dict]:
    """Rows for one top-level cloud-config key, each item keeping its own line number."""
    value = _construct(node)
    line = node.start_mark.line + 1
    common = {"kind": kind, "source_path": source_path, "part": part}
    items = list(zip(node.value, value)) if isinstance(node, yaml.SequenceNode) and isinstance(value, list) else []

    def row(item_line: int, **fields: Any) -> dict:
        return _row(common["kind"], common["source_path"], line_number=item_line, config_key=key, user_data_part=common["part"], **fields)

    rows: list[dict] = []
    if key in {"runcmd", "bootcmd"} and items:
        for item_node, item in items:
            command = _as_command(item)
            rows.append(row(item_node.start_mark.line + 1, event_action=key, command=command, message=f"{key}: {command}",
                            suspicious_indicators=suspicious_indicators(command)))
    elif key == "users" and items:
        for item_node, item in items:
            item_line = item_node.start_mark.line + 1
            if isinstance(item, str):
                rows.append(row(item_line, event_action="user", username=item, message=f"user: {item}"))
                continue
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            details = {k: item[k] for k in ("sudo", "groups", "shell", "lock_passwd", "uid", "primary_group", "system", "homedir") if k in item}
            secrets = sorted(k for k in _SECRET_KEYS if item.get(k))
            text = f"user: {name}" + (f" ({_summary(details)})" if details else "") + (f"; password set ({', '.join(secrets)})" if secrets else "")
            flags = ["passwordless_sudo"] if "NOPASSWD" in str(item.get("sudo") or "") else []
            rows.append(row(item_line, event_action="user", username=name, message=text, user_sudo=_summary(item.get("sudo")) if item.get("sudo") else None,
                            suspicious_indicators=flags))
            for ssh_key in item.get("ssh_authorized_keys") or []:
                rows.append(row(item_line, event_action="ssh_key", username=name, message=f"SSH key for {name}: {str(ssh_key)[:200]}",
                                ssh_key_comment=str(ssh_key).split()[-1] if len(str(ssh_key).split()) > 2 else None))
            for import_id in item.get("ssh_import_id") or []:
                rows.append(row(item_line, event_action="ssh_key", username=name, message=f"SSH keys imported for {name} from {import_id}"))
    elif key == "ssh_authorized_keys" and items:
        for item_node, item in items:
            rows.append(row(item_node.start_mark.line + 1, event_action="ssh_key", message=f"SSH key for the default user: {str(item)[:200]}",
                            ssh_key_comment=str(item).split()[-1] if len(str(item).split()) > 2 else None))
    elif key == "write_files" and items:
        for item_node, item in items:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path") or "")
            content = _write_file_content(item)
            details = ", ".join(f"{k}={item[k]}" for k in ("permissions", "owner", "encoding", "append", "defer") if k in item)
            rows.append(row(item_node.start_mark.line + 1, event_action="file_write", file_path=path,
                            message=f"write {path}" + (f" ({details})" if details else "") + (f": {content[:300]}" if content else ""),
                            suspicious_indicators=sorted(set(suspicious_indicators(content) + suspicious_indicators(path)))))
    elif key == "packages" and items:
        for item_node, item in items:
            rows.append(row(item_node.start_mark.line + 1, event_action="package", package=_as_command(item), message=f"package: {_as_command(item)}"))
    elif key in {"apt", "yum_repos", "zypper"} and isinstance(value, dict):
        sources = value.get("sources") if key == "apt" else value.get("repos") if key == "zypper" else value
        entries = sources.items() if isinstance(sources, dict) else enumerate(sources or []) if isinstance(sources, list) else []
        for name, repo in entries:
            if not isinstance(repo, dict):
                continue
            url = repo.get("source") or repo.get("baseurl") or repo.get("uri") or ""
            rows.append(row(line, event_action="repository", repository_url=str(url)[:1000], message=f"{key} repository {repo.get('name') or name}: {url}"))
        if not rows:
            rows.append(row(line, event_action="setting", message=f"{key}: {_summary(value)}"))
    elif key in _SECRET_KEYS or key == "chpasswd":
        users = []
        if isinstance(value, dict):
            users = [str(entry.get("name")) for entry in value.get("users") or [] if isinstance(entry, dict)]
            if isinstance(value.get("list"), str):
                users += [entry.split(":", 1)[0] for entry in value["list"].split() if ":" in entry]
            elif isinstance(value.get("list"), list):
                users += [str(entry).split(":", 1)[0] for entry in value["list"]]
        rows.append(row(line, event_action="password", message=f"{key}: password set" + (f" for {', '.join(users)}" if users else "")))
    elif key not in _MODULE_LIST_KEYS:
        flags = ["password_ssh_login"] if key == "ssh_pwauth" and value in (True, "true", "yes", 1) else []
        rows.append(row(line, event_action="setting", message=f"{key}: {_summary(value)}", suspicious_indicators=flags))
    return rows


def _cloud_config_rows(text: str, *, kind: str, source_path: str, part: str | None, first_line: int = 1) -> list[dict]:
    try:
        document = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        return [_row(kind, source_path, line_number=first_line, event_action="parse_error", user_data_part=part,
                     message=f"cloud-config could not be read: {str(exc).splitlines()[0]}", raw_excerpt=text[:MAX_TEXT])]
    if not isinstance(document, yaml.MappingNode):
        return []
    rows: list[dict] = []
    for key_node, value_node in document.value:
        key = str(_construct(key_node))
        for row in _config_item_rows(key, value_node, kind=kind, source_path=source_path, part=part):
            row["line_number"] = (row.get("line_number") or 1) + first_line - 1
            rows.append(row)
    return rows


def _user_data_rows(text: str, *, kind: str, source_path: str, part: str | None = None, first_line: int = 1, depth: int = 0) -> list[dict]:
    """Decode one user-data payload the way cloud-init recognises it: by its first line."""
    body = text.lstrip("﻿")
    first, _newline, rest = body.partition("\n")
    marker = first.strip().lower()
    if marker.startswith("## template:"):
        return _user_data_rows(rest, kind=kind, source_path=source_path, part=part, first_line=first_line + 1, depth=depth)
    if marker.startswith("#cloud-config-archive"):
        try:
            archive = yaml.safe_load(rest) or []
        except yaml.YAMLError:
            archive = []
        rows = []
        for index, entry in enumerate(archive if isinstance(archive, list) else []):
            content = entry.get("content") if isinstance(entry, dict) else entry
            if isinstance(content, str) and depth < 5:
                rows += _user_data_rows(content, kind=kind, source_path=source_path, part=f"archive-{index + 1}", depth=depth + 1)
        return rows
    if marker.startswith("#cloud-config"):
        return _cloud_config_rows(body, kind=kind, source_path=source_path, part=part, first_line=first_line)
    if marker.startswith("#cloud-boothook"):
        return _script_rows(rest, kind=kind, source_path=source_path, part=part, action="boothook", first_line=first_line + 1)
    if marker.startswith("#!"):
        return _script_rows(body, kind=kind, source_path=source_path, part=part, action="script", first_line=first_line)
    if marker.startswith("#include"):
        return [
            _row(kind, source_path, line_number=first_line + 1 + offset, event_action="include_url", user_data_part=part,
                 repository_url=line.strip(), message=f"include {line.strip()}")
            for offset, line in enumerate(rest.splitlines()) if line.strip() and not line.strip().startswith("#")
        ]
    if marker.startswith("#part-handler"):
        return _script_rows(rest, kind=kind, source_path=source_path, part=part, action="part_handler", first_line=first_line + 1)
    if re.match(r"^(content-type|mime-version):", marker) and depth < 5:
        message = email.message_from_string(body)
        rows = []
        for index, mime_part in enumerate(message.walk()):
            if mime_part.is_multipart():
                continue
            payload = mime_part.get_payload(decode=True)
            if not payload:
                continue
            name = mime_part.get_filename() or f"part-{index:03d}"
            content_type = mime_part.get_content_type()
            decoded = _decode_payload(payload)
            if content_type == "text/cloud-config" and not decoded.lstrip().lower().startswith("#cloud-config"):
                decoded = "#cloud-config\n" + decoded
            elif content_type in {"text/x-shellscript", "text/x-shellscript-per-boot", "text/x-shellscript-per-instance", "text/x-shellscript-per-once"} and not decoded.startswith("#!"):
                decoded = "#!/bin/sh\n" + decoded
            rows += _user_data_rows(decoded, kind=kind, source_path=source_path, part=f"{name} ({content_type})", depth=depth + 1)
        return rows
    if not body.strip():
        return []
    # Unrecognised content: cloud-init ignores it, but its lines are kept for review.
    return _script_rows(body, kind=kind, source_path=source_path, part=part, action="unrecognised", first_line=first_line)


# ------------------------------------------------------------------ instance state


def _parse_instance(content: str, *, source_path: str) -> list[dict]:
    name = str(source_path or "").replace("\\", "/").rsplit("/", 1)[-1]
    text = content.strip()
    if not text:
        return []
    if name in {"instance-id", "previous-instance-id"}:
        label = "previous instance" if name.startswith("previous") else "instance"
        return [_row("cloud_instance", source_path, line_number=1, event_action=name.replace("-", "_"), instance_id=text.splitlines()[0],
                     message=f"cloud-init {label} id: {text.splitlines()[0]}")]
    if name == "datasource":
        datasource = text.split(":", 1)[0].strip()
        return [_row("cloud_instance", source_path, line_number=1, event_action="datasource", datasource=datasource, message=text)]
    try:
        data = json.loads(text)
    except ValueError:
        return [_row("cloud_instance", source_path, line_number=1, event_action="parse_error", message=text[:500])]
    v1 = data.get("v1") if isinstance(data, dict) else None
    if not isinstance(v1, dict):
        return []
    rows = []
    if v1.get("datasource"):
        rows.append(_row("cloud_instance", source_path, line_number=1, event_action="datasource", datasource=str(v1["datasource"]).split(" ")[0],
                         message=f"datasource: {v1['datasource']}"))
    stages = {key: value for key, value in v1.items() if isinstance(value, dict)}
    for stage, details in stages.items():
        for error in details.get("errors") or []:
            rows.append(_row("cloud_instance", source_path, line_number=1, event_action="error", severity="error", cloud_init_stage=stage, message=f"{stage}: {error}"))
        for level, messages in (details.get("recoverable_errors") or {}).items():
            for text_message in messages or []:
                rows.append(_row("cloud_instance", source_path, line_number=1, event_action="recoverable_error", severity=str(level).lower(),
                                 cloud_init_stage=stage, message=f"{stage}: {text_message}"))
    for error in v1.get("errors") or []:
        rows.append(_row("cloud_instance", source_path, line_number=1, event_action="error", severity="error", message=str(error)))
    return rows


def parse_cloud_init(content: str, *, source_path: str = "", truncated: bool = False) -> list[dict[str, Any]]:
    kind = cloud_init_kind(source_path)
    if kind == "cloud_init_log":
        return _parse_log(content, source_path=source_path)
    if kind == "cloud_init_output":
        return _parse_output(content, source_path=source_path)
    if kind == "user_data":
        return _user_data_rows(content, kind=kind, source_path=source_path)
    if kind == "cloud_script":
        return _script_rows(content, kind=kind, source_path=source_path, part=None, action="script")
    if kind == "cloud_config":
        return _cloud_config_rows(content, kind=kind, source_path=source_path, part=None)
    if kind == "cloud_instance":
        return _parse_instance(content, source_path=source_path)
    return []
