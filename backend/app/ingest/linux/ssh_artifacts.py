"""SSH artifact parser: authorized_keys, known_hosts, ssh_config, sshd_config."""
from __future__ import annotations
import re
from base64 import b64decode
from hashlib import sha256
from pathlib import Path

_CONFIG_KV_RE = re.compile(r"^\s*(\w+)(?:\s+(\S.*))?$", re.IGNORECASE)
_HOST_RE = re.compile(r"^\s*host\s+(.+)$", re.IGNORECASE)
_COMMENT_RE = re.compile(r"^\s*[#;]")


def _infer_username(source_path: str) -> str | None:
    path_str = str(source_path).replace("\\", "/")
    match = re.search(r"/home/([^/]+)/", path_str)
    if match:
        return match.group(1)
    if "/root/" in path_str:
        return "root"
    return None


def _redact_key(key_base64: str) -> str:
    if len(key_base64) > 32:
        return key_base64[:32] + "..."
    return key_base64[:16] + "..." if len(key_base64) > 16 else "[redacted]"


def _parse_authorized_keys(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    results: list[dict] = []
    inferred_user = username or _infer_username(source_path)
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or _COMMENT_RE.match(stripped):
            continue
        raw_excerpt = stripped[:2000]
        parts = stripped.split(None, 2)
        if len(parts) < 2:
            continue
        key_type = parts[0]
        key_base64 = parts[1]
        key_comment = parts[2] if len(parts) > 2 else ""
        fingerprint = _redact_key(key_base64)
        results.append({
            "artifact_family": "linux_ssh",
            "artifact_type": "authorized_keys",
            "source_file": source_path,
            "line_number": line_number,
            "key_type": key_type,
            "key_fingerprint": fingerprint,
            "key_comment": key_comment,
            "username": inferred_user,
            "message": f"SSH authorized_key: {key_type} {fingerprint} {key_comment}".strip(),
            "raw_excerpt": raw_excerpt,
        })
    return results


def _parse_known_hosts(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or _COMMENT_RE.match(stripped):
            continue
        raw_excerpt = stripped[:2000]
        parts = stripped.split(None, 2)
        if len(parts) < 2:
            continue
        host_pattern = parts[0]
        key_type = parts[1]
        results.append({
            "artifact_family": "linux_ssh",
            "artifact_type": "known_hosts",
            "source_file": source_path,
            "line_number": line_number,
            "host_pattern": host_pattern,
            "key_type": key_type,
            "key_fingerprint": "[redacted]",
            "message": f"Known host: {host_pattern} ({key_type})",
            "raw_excerpt": raw_excerpt,
        })
    return results


def _parse_ssh_config(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
    config_type: str = "ssh_config",
) -> list[dict]:
    results: list[dict] = []
    current_host: str | None = None
    current_options: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or _COMMENT_RE.match(stripped):
            continue
        raw_excerpt = stripped[:2000]
        host_match = _HOST_RE.match(stripped)
        if host_match:
            if current_options:
                for opt in current_options:
                    opt["host_pattern"] = current_host
                    opt["message"] = f"Host {current_host}: {opt['option']} = {opt['value']}" if opt.get("value") else f"Host {current_host}: {opt['option']}"
                    results.append(opt)
                current_options = []
            current_host = host_match.group(1).strip()
            continue
        kv_match = _CONFIG_KV_RE.match(stripped)
        if kv_match and current_host:
            option = kv_match.group(1).strip()
            value = kv_match.group(2) or ""
            current_options.append({
                "artifact_family": "linux_ssh",
                "artifact_type": config_type,
                "source_file": source_path,
                "line_number": line_number,
                "option": option,
                "value": value,
                "host_pattern": current_host,
                "message": f"Host {current_host}: {option} = {value}" if value else f"Host {current_host}: {option}",
                "raw_excerpt": raw_excerpt,
            })
        elif kv_match:
            option = kv_match.group(1).strip()
            value = kv_match.group(2) or ""
            results.append({
                "artifact_family": "linux_ssh",
                "artifact_type": config_type,
                "source_file": source_path,
                "line_number": line_number,
                "option": option,
                "value": value,
                "host_pattern": None,
                "message": f"{option} = {value}" if value else option,
                "raw_excerpt": raw_excerpt,
            })
    if current_options:
        for opt in current_options:
            opt["host_pattern"] = current_host
            opt["message"] = f"Host {current_host}: {opt['option']} = {opt['value']}" if opt.get("value") else f"Host {current_host}: {opt['option']}"
            results.append(opt)
    return results


def parse_ssh_artifacts(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    path_lower = str(source_path).replace("\\", "/").lower()
    if "authorized_keys" in path_lower:
        return _parse_authorized_keys(content, source_path=source_path, username=username)
    if "known_hosts" in path_lower:
        return _parse_known_hosts(content, source_path=source_path, username=username)
    if "ssh_config" in path_lower and "sshd_config" not in path_lower:
        return _parse_ssh_config(content, source_path=source_path, username=username, config_type="ssh_config")
    if "sshd_config" in path_lower:
        return _parse_ssh_config(content, source_path=source_path, username=username, config_type="sshd_config")
    if "ssh" in path_lower:
        return _parse_ssh_config(content, source_path=source_path, username=username, config_type="ssh_config")
    return _parse_authorized_keys(content, source_path=source_path, username=username)
