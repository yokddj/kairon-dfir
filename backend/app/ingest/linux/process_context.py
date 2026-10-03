"""Derive Sigma-addressable process fields from Linux command records.

Shell history and auditd rows carry a command, not a structured process, so
``process.name`` / ``process.executable`` / ``process.command_line`` -- the fields
Sigma's ``Image`` and ``CommandLine`` map to -- were empty and every process_creation
rule that keys on ``Image`` could never match. This fills them from what the record
really contains, and never invents what it does not: a command typed as ``wget ...``
gets the name ``wget`` and no path, because the history file never recorded one.
"""
from __future__ import annotations

import posixpath
import shlex
from typing import Any

# Launchers that run the next word as the real command. "sudo wget x" executed wget.
_WRAPPERS = frozenset({"sudo", "doas", "env", "nohup", "time", "nice", "exec", "command", "setsid", "stdbuf", "ionice", "builtin", "xargs"})
# sudo/doas options that consume the following word ("-u root").
_WRAPPER_OPTIONS_WITH_ARG = frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-r", "-t", "-U", "-n"})
_MAX_COMMAND_CHARS = 4000


def _tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def split_command(command: str | None) -> tuple[str | None, str | None]:
    """Return ``(name, path)`` of the program a shell command line runs.

    ``path`` is only set when the word was written as a path (``/usr/bin/wget``,
    ``./payload``); ``name`` is its basename. Leading ``VAR=value`` assignments and
    launcher words such as ``sudo -u root`` are skipped.
    """
    words = _tokens(str(command or "")[:_MAX_COMMAND_CHARS])
    index = 0
    while index < len(words):
        word = words[index]
        if "=" in word and not word.startswith(("/", ".", "-")) and word.split("=", 1)[0].replace("_", "").isalnum():
            index += 1
            continue
        if word in _WRAPPERS or posixpath.basename(word) in _WRAPPERS:
            index += 1
            while index < len(words) and words[index].startswith("-"):
                consumes = words[index] in _WRAPPER_OPTIONS_WITH_ARG
                index += 2 if consumes else 1
            continue
        break
    if index >= len(words):
        return None, None
    program = words[index]
    name = posixpath.basename(program.rstrip("/")) or None
    return name, program if "/" in program else None


def apply_process_context(doc: dict[str, Any], row: dict[str, Any], family: str) -> None:
    """Populate ``doc['process']`` for Linux command-bearing rows (in place)."""
    process = doc.setdefault("process", {})
    if family == "linux_shell_history":
        command = str(row.get("command") or "").strip()
        if not command:
            return
        name, path = split_command(command)
        process["command_line"] = command
        process["name"] = name
        if path:
            process["path"] = path
            process["executable"] = path
        return
    if family != "linux_audit":
        return
    exe = row.get("exe")
    command_line = row.get("command_line")
    comm = row.get("comm")
    name = comm or (posixpath.basename(exe) if exe else None)
    if not name and command_line:
        name, _ = split_command(command_line)
    if name:
        process["name"] = name
    if exe:
        process["path"] = exe
        process["executable"] = exe
    elif command_line:
        _, typed_path = split_command(command_line)
        if typed_path:
            process["path"] = typed_path
            process["executable"] = typed_path
    if command_line:
        process["command_line"] = command_line
    if row.get("cwd"):
        process["working_directory"] = row["cwd"]
    if row.get("pid") is not None:
        process["pid"] = row["pid"]
    if row.get("ppid") is not None:
        process["ppid"] = row["ppid"]


def apply_sysmon_context(doc: dict[str, Any], row: dict[str, Any]) -> None:
    """Fill the standard process / network / file fields from a Sysmon for Linux event (in place).

    These are the fields Sigma's Image, CommandLine, ParentImage, User, DestinationIp and
    TargetFilename map to, and ``event.code`` / ``event.type`` are what its process_creation,
    network_connection and file_event categories look for.
    """
    code = row.get("sysmon_event_id")
    if not code:
        return
    doc["event"]["code"] = str(code)
    doc["event"]["type"] = row.get("event_label") or f"sysmon_event_{code}"
    doc["event"]["action"] = f"sysmon_{row.get('sysmon_event') or code}"
    doc["event"]["message"] = row.get("message") or doc["event"].get("message")
    doc["title"] = row.get("message") or doc.get("title")
    process = doc.setdefault("process", {})
    image = row.get("image")
    if image:
        process["path"] = image
        process["executable"] = image
        process["name"] = row.get("process") or posixpath.basename(image)
    if row.get("command_line"):
        process["command_line"] = row["command_line"]
    if row.get("current_directory"):
        process["current_directory"] = row["current_directory"]
        process["working_directory"] = row["current_directory"]
    if row.get("pid") is not None:
        process["pid"] = row["pid"]
    if row.get("process_guid"):
        process["entity_id"] = row["process_guid"]
    if row.get("parent_image"):
        process["parent_path"] = row["parent_image"]
        process["parent_name"] = posixpath.basename(row["parent_image"])
    if row.get("parent_command_line"):
        process["parent_command_line"] = row["parent_command_line"]
    if row.get("parent_pid") is not None:
        process["ppid"] = row["parent_pid"]
        process["parent_pid"] = row["parent_pid"]
    if row.get("parent_guid"):
        process["parent_entity_id"] = row["parent_guid"]
    if row.get("sha256"):
        process.setdefault("hashes", {})["sha256"] = row["sha256"]
    if row.get("username"):
        doc["user"]["name"] = row["username"]
    if code == 3:
        network = doc["network"]
        network["source_ip"] = row.get("source_ip") or None
        network["source_port"] = row.get("source_port")
        network["destination_ip"] = row.get("destination_ip") or None
        network["destination_port"] = row.get("destination_port")
        network["protocol"] = row.get("network_protocol") or None
        doc["destination"]["ip"] = row.get("destination_ip") or None
        doc["destination"]["port"] = row.get("destination_port")
        if row.get("destination_hostname"):
            doc["destination"]["hostname"] = row["destination_hostname"]
    elif code in {11, 23} and row.get("target_filename"):
        doc["file"]["path"] = row["target_filename"]
        doc["file"]["name"] = posixpath.basename(row["target_filename"])
