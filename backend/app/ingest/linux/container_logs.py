"""Container artifacts: Docker / containerd logs and container configuration.

* Docker ``json-file`` logs: ``/var/lib/docker/containers/<id>/<id>-json.log``, one JSON object
  per line (``{"log": "...\\n", "stream": "stdout", "time": "..."}``).
* CRI logs written by containerd / CRI-O for Kubernetes: ``/var/log/pods/<ns>_<pod>_<uid>/<container>/<n>.log``
  and the ``/var/log/containers/<pod>_<ns>_<container>-<id>.log`` links, one text line per entry
  (``2024-03-01T10:20:30.123456789Z stdout F message``).
* Docker's ``config.v2.json`` and ``hostconfig.json``: what a container is, runs, mounts and is
  allowed to do.

The configuration is where a container escape is prepared (privileged mode, the host's PID or
network namespace, the Docker socket or the host root mounted in). Lines of it are flagged, never
judged. Environment variable *values* are never stored, only their names, because they routinely
hold credentials.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

ARTIFACT_FAMILY = "linux_container"
MAX_MESSAGE_CHARS = 2000
MAX_PARTIAL_JOIN = 1_000_000
MAX_CONFIG_BYTES = 5 * 1024 * 1024
MAX_LIST_ITEMS = 200

_HEX_ID = r"[0-9a-f]{12,64}"
_DOCKER_LOG_RE = re.compile(rf"(^|/)var/lib/docker/containers/(?P<id>{_HEX_ID})/[^/]*-json\.log(?:[.-]\w+)*$", re.I)
_DOCKER_CONFIG_RE = re.compile(rf"(^|/)var/lib/docker/containers/(?P<id>{_HEX_ID})/config\.v2\.json$", re.I)
_DOCKER_HOSTCONFIG_RE = re.compile(rf"(^|/)var/lib/docker/containers/(?P<id>{_HEX_ID})/hostconfig\.json$", re.I)
_CRI_POD_RE = re.compile(r"(^|/)var/log/pods/(?P<ns>[^/_]+)_(?P<pod>[^/]+)_(?P<uid>[^/_]+)/(?P<container>[^/]+)/(?P<restart>\d+)\.log(?:[.-]\w+)*$", re.I)
_CRI_LINK_RE = re.compile(rf"(^|/)var/log/containers/(?P<pod>[^/_]+)_(?P<ns>[^/_]+)_(?P<container>[^/]+?)-(?P<id>{_HEX_ID})\.log(?:[.-]\w+)*$", re.I)
_CRI_LINE_RE = re.compile(r"^(?P<time>\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2}))\s+(?P<stream>stdout|stderr)\s+(?P<tag>[PF])\s?(?P<message>.*)$")
_LEVEL_RE = re.compile(r"\b(emerg|alert|crit|critical|fatal|err|error|warn|warning|notice|info|debug)\b", re.I)
_SEVERITY_ALIASES = {"critical": "crit", "err": "error", "warn": "warning"}

_DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "DAC_READ_SEARCH"}
_CONTAINER_SOCKETS = ("docker.sock", "containerd.sock", "crio.sock", "cri-dockerd.sock")
_SENSITIVE_HOST_PREFIXES = ("/etc", "/root", "/proc", "/sys", "/dev", "/boot", "/var/run", "/run", "/home", "/var/lib/docker", "/var/lib/kubelet")
_SECRET_NAME_RE = re.compile(r"PASS|SECRET|TOKEN|CREDENTIAL|API[_-]?KEY|PRIVATE[_-]?KEY", re.I)
# Flags that on their own warrant "high" rather than "medium" for the table's severity.
HIGH_SEVERITY_FLAGS = {"privileged_container", "docker_socket_mount", "host_root_mount"}


def container_kind(source_path: str) -> str | None:
    """``container_log``, ``container_config``, ``container_hostconfig`` or None."""
    path = str(source_path or "").replace("\\", "/")
    if _DOCKER_CONFIG_RE.search(path):
        return "container_config"
    if _DOCKER_HOSTCONFIG_RE.search(path):
        return "container_hostconfig"
    if _DOCKER_LOG_RE.search(path) or _CRI_POD_RE.search(path) or _CRI_LINK_RE.search(path):
        return "container_log"
    return None


def _identity(source_path: str) -> dict[str, str]:
    path = str(source_path or "").replace("\\", "/")
    for pattern in (_DOCKER_LOG_RE, _DOCKER_CONFIG_RE, _DOCKER_HOSTCONFIG_RE):
        match = pattern.search(path)
        if match:
            return {"container_id": match.group("id")}
    match = _CRI_POD_RE.search(path)
    if match:
        return {"k8s_namespace": match.group("ns"), "k8s_pod": match.group("pod"), "container_name": match.group("container")}
    match = _CRI_LINK_RE.search(path)
    if match:
        return {"k8s_namespace": match.group("ns"), "k8s_pod": match.group("pod"), "container_name": match.group("container"), "container_id": match.group("id")}
    return {}


def _timestamp(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    text = text[:-1] + "+00:00" if text.endswith("Z") else text
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    parsed = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat() if parsed.year >= 1990 else None


def _level(message: str) -> str | None:
    match = _LEVEL_RE.search(message[:80])
    if not match:
        return None
    word = match.group(1).lower()
    return _SEVERITY_ALIASES.get(word, word)


# ------------------------------------------------------------------------- logs

def _log_row(source_path: str, line_number: int, identity: dict[str, str], stamp: str | None, stream: str, message: str, raw: str) -> dict[str, Any]:
    from app.ingest.linux.generic_log import _enrich, _parse_json_line

    extras: dict[str, Any] = {}
    text = message.rstrip("\n")
    stripped = text.strip()
    if stripped.startswith("{"):
        # An application that logs JSON: lift its message and level out of the object.
        inner = _parse_json_line(stripped)
        if inner:
            text, extras = inner[2], dict(inner[3])
            extras.pop("json", None)
    extras = _enrich(text, extras)
    severity = extras.get("severity") or _level(text)
    row: dict[str, Any] = {
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_type": "container_log",
        "source_file": source_path,
        "line_number": line_number,
        "timestamp": stamp,
        "timestamp_status": "ok" if stamp else "missing",
        "message": text[:MAX_MESSAGE_CHARS],
        "raw_excerpt": raw[:MAX_MESSAGE_CHARS],
        "container_stream": stream,
        "process": identity.get("container_name") or extras.get("process"),
        "severity": severity,
        "username": extras.get("username"),
        "source_ip": extras.get("source_ip"),
        **identity,
    }
    return row


def _parse_docker_log(content: str, source_path: str, identity: dict[str, str]) -> list[dict]:
    rows: list[dict] = []
    pending: list[str] = []
    pending_meta: tuple[int, str | None, str, str] | None = None
    pending_size = 0
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            entry = json.loads(stripped)
        except ValueError:
            entry = None
        if not isinstance(entry, dict) or not isinstance(entry.get("log"), str):
            rows.append(_log_row(source_path, line_number, identity, None, "", stripped, stripped))
            continue
        piece = entry["log"]
        stream = str(entry.get("stream") or "")
        stamp = _timestamp(entry.get("time"))
        if pending_meta is None:
            pending_meta = (line_number, stamp, stream, stripped)
        if pending_size < MAX_PARTIAL_JOIN:
            pending.append(piece)
            pending_size += len(piece)
        # A Docker entry without a trailing newline is a fragment of a longer line.
        if piece.endswith("\n") or pending_size >= MAX_PARTIAL_JOIN:
            first_line, first_stamp, first_stream, raw = pending_meta
            rows.append(_log_row(source_path, first_line, identity, first_stamp, first_stream, "".join(pending), raw))
            pending, pending_meta, pending_size = [], None, 0
    if pending_meta is not None:
        first_line, first_stamp, first_stream, raw = pending_meta
        rows.append(_log_row(source_path, first_line, identity, first_stamp, first_stream, "".join(pending), raw))
    return rows


def _parse_cri_log(content: str, source_path: str, identity: dict[str, str]) -> list[dict]:
    rows: list[dict] = []
    pending: list[str] = []
    pending_meta: tuple[int, str | None, str, str] | None = None
    pending_size = 0
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.rstrip("\r\n")
        if not stripped.strip():
            continue
        match = _CRI_LINE_RE.match(stripped)
        if not match:
            rows.append(_log_row(source_path, line_number, identity, None, "", stripped.strip(), stripped.strip()))
            continue
        if pending_meta is None:
            pending_meta = (line_number, _timestamp(match.group("time")), match.group("stream"), stripped)
        if pending_size < MAX_PARTIAL_JOIN:
            pending.append(match.group("message"))
            pending_size += len(match.group("message"))
        if match.group("tag") == "F" or pending_size >= MAX_PARTIAL_JOIN:
            first_line, first_stamp, first_stream, raw = pending_meta
            rows.append(_log_row(source_path, first_line, identity, first_stamp, first_stream, "".join(pending), raw))
            pending, pending_meta, pending_size = [], None, 0
    if pending_meta is not None:
        first_line, first_stamp, first_stream, raw = pending_meta
        rows.append(_log_row(source_path, first_line, identity, first_stamp, first_stream, "".join(pending), raw))
    return rows


# ------------------------------------------------------------------ configuration

def _bind_flags(binds: list[Any]) -> set[str]:
    flags: set[str] = set()
    for bind in binds[:MAX_LIST_ITEMS]:
        # "host:container[:mode]" for a Docker bind; a dict for a mount-point entry.
        source = str(bind.get("Source") if isinstance(bind, dict) else str(bind).split(":", 1)[0])
        if not source.startswith("/"):
            continue  # a named volume, not a host path
        flags.add("host_path_mount")
        if source == "/":
            flags.add("host_root_mount")
        if any(source.endswith(sock) for sock in _CONTAINER_SOCKETS):
            flags.add("docker_socket_mount")
        if source.startswith(_SENSITIVE_HOST_PREFIXES):
            flags.add("sensitive_host_mount")
    return flags


def _host_flags(host: dict) -> set[str]:
    flags: set[str] = set()
    if host.get("Privileged") is True:
        flags.add("privileged_container")
    for key, flag in (("NetworkMode", "host_network"), ("PidMode", "host_pid"), ("IpcMode", "host_ipc"), ("UsernsMode", "host_userns")):
        if str(host.get(key) or "").lower() == "host":
            flags.add(flag)
    caps = host.get("CapAdd") if isinstance(host.get("CapAdd"), list) else []
    if _DANGEROUS_CAPS & {str(c).upper().removeprefix("CAP_") for c in caps}:
        flags.add("dangerous_capability")
    options = [str(o).lower() for o in (host.get("SecurityOpt") or [])] if isinstance(host.get("SecurityOpt"), list) else []
    if any(o in {"seccomp=unconfined", "apparmor=unconfined", "label=disable", "label:disable"} for o in options):
        flags.add("unconfined_security")
    if host.get("Devices"):
        flags.add("host_device")
    binds = host.get("Binds") if isinstance(host.get("Binds"), list) else []
    flags |= _bind_flags(binds)
    return flags


def _config_row(kind: str, source_path: str, identity: dict[str, str], document: dict) -> dict[str, Any]:
    config = document.get("Config") if isinstance(document.get("Config"), dict) else {}
    state = document.get("State") if isinstance(document.get("State"), dict) else {}
    host = document if kind == "container_hostconfig" else (document.get("HostConfig") if isinstance(document.get("HostConfig"), dict) else {})
    flags = _host_flags(host)
    mounts = document.get("MountPoints") if isinstance(document.get("MountPoints"), dict) else {}
    flags |= _bind_flags([m for m in mounts.values() if isinstance(m, dict) and m.get("Type", "bind") == "bind"])

    env = config.get("Env") if isinstance(config.get("Env"), list) else []
    env_names = [str(e).split("=", 1)[0] for e in env[:MAX_LIST_ITEMS]]
    if any(_SECRET_NAME_RE.search(name) for name in env_names):
        flags.add("secret_in_environment")
    if any(name == "LD_PRELOAD" for name in env_names):
        flags.add("ld_preload_env")

    name = str(document.get("Name") or "").lstrip("/")
    image = str(config.get("Image") or document.get("Image") or "")
    command = " ".join(str(part) for part in [document.get("Path"), *(document.get("Args") or [])] if part)[:2000] if isinstance(document.get("Args", []), list) else str(document.get("Path") or "")
    created = _timestamp(document.get("Created"))
    status = "running" if state.get("Running") else "exited" if state else ""
    modes = ", ".join(f"{key}={host[key]}" for key in ("NetworkMode", "PidMode") if host.get(key) not in (None, "", "default"))

    if kind == "container_hostconfig":
        message = f"Container host configuration{(' ' + identity['container_id'][:12]) if identity.get('container_id') else ''}" + (f": {modes}" if modes else "")
    else:
        message = f"Container {name or identity.get('container_id', '')[:12]} ({image or 'unknown image'}) {status}".strip() + (f": {command}" if command else "")
    if flags:
        message += f" [{', '.join(sorted(flags))}]"

    row: dict[str, Any] = {
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_type": kind,
        "source_file": source_path,
        "line_number": 1,
        "timestamp": created,
        "timestamp_status": "ok" if created else "missing",
        "message": message[:MAX_MESSAGE_CHARS],
        "raw_excerpt": "",
        "container_name": name or None,
        "container_image": image,
        "container_state": status,
        "container_exit_code": state.get("ExitCode") if isinstance(state.get("ExitCode"), int) else None,
        "container_command": command,
        "container_privileged": host.get("Privileged") is True,
        "network_mode": str(host.get("NetworkMode") or ""),
        "pid_mode": str(host.get("PidMode") or ""),
        "container_cap_add": [str(c) for c in (host.get("CapAdd") or [])[:MAX_LIST_ITEMS]] if isinstance(host.get("CapAdd"), list) else [],
        "container_env_names": env_names,
        "container_mounts": [str(b)[:300] for b in (host.get("Binds") or [])[:MAX_LIST_ITEMS]] if isinstance(host.get("Binds"), list) else [],
        "username": str(config.get("User") or "") or None,
        "suspicious_indicators": sorted(flags),
        **identity,
    }
    if document.get("ID") and not row.get("container_id"):
        row["container_id"] = str(document["ID"])
    return row


def _parse_config(content: str, source_path: str, identity: dict[str, str], kind: str) -> list[dict]:
    if len(content) > MAX_CONFIG_BYTES:
        return [{
            "artifact_family": ARTIFACT_FAMILY, "artifact_type": kind, "source_file": source_path, "line_number": 1,
            "timestamp": None, "timestamp_status": "missing", "raw_excerpt": "",
            "message": f"[kairon] container configuration of {len(content)} characters not parsed (limit {MAX_CONFIG_BYTES})", **identity,
        }]
    try:
        document = json.loads(content)
    except ValueError:
        return []
    return [_config_row(kind, source_path, identity, document)] if isinstance(document, dict) else []


def parse_container_artifact(content: str, *, source_path: str = "", truncated: bool = False) -> list[dict]:
    kind = container_kind(source_path)
    if kind is None:
        return []
    identity = _identity(source_path)
    if kind in {"container_config", "container_hostconfig"}:
        return _parse_config(content, source_path, identity, kind)
    first = next((line.strip() for line in content.splitlines() if line.strip()), "")
    rows = _parse_cri_log(content, source_path, identity) if _CRI_LINE_RE.match(first) else _parse_docker_log(content, source_path, identity)
    if truncated:
        rows.append(_log_row(source_path, len(content.splitlines()) + 1, identity, None, "", "[kairon] log truncated: only the first part of this file was parsed (size limit or damaged archive)", ""))
    return rows
