"""Identity parser: /etc/passwd, /etc/group, /etc/shadow."""
from __future__ import annotations
import re
from pathlib import Path

_COMMENT_RE = re.compile(r"^\s*#")
_EMPTY_RE = re.compile(r"^\s*$")


def parse_identity(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    path_lower = str(source_path).replace("\\", "/").lower()
    file_name = Path(source_path).name.lower() if source_path else ""

    if "shadow" in path_lower or file_name == "shadow":
        return _parse_shadow(content, source_path=source_path, username=username)
    if "group" in path_lower or file_name == "group":
        return _parse_group(content, source_path=source_path, username=username)
    return _parse_passwd(content, source_path=source_path, username=username)


def _parse_passwd(
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
        fields = stripped.split(":")
        if len(fields) < 7:
            continue
        uname, pw_placeholder, uid_str, gid_str, gecos, home, shell = fields[:7]
        if uname and uname.strip():
            results.append({
                "artifact_family": "linux_identity",
                "artifact_type": "passwd",
                "source_file": source_path,
                "line_number": line_number,
                "username": uname.strip(),
                "uid": uid_str.strip() if uid_str else None,
                "gid": gid_str.strip() if gid_str else None,
                "gecos": gecos.strip() if gecos else None,
                "home": home.strip() if home else None,
                "shell": shell.strip() if shell else None,
                "message": f"User: {uname.strip()} (UID:{uid_str} GID:{gid_str})",
                "raw_excerpt": raw_excerpt,
            })
    return results


def _parse_group(
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
        fields = stripped.split(":")
        if len(fields) < 4:
            continue
        group_name, _pw_placeholder, gid_str, members_raw = fields[:4]
        members = [m.strip() for m in members_raw.split(",") if m.strip()] if members_raw else []
        if group_name and group_name.strip():
            results.append({
                "artifact_family": "linux_identity",
                "artifact_type": "group",
                "source_file": source_path,
                "line_number": line_number,
                "group_name": group_name.strip(),
                "gid": gid_str.strip() if gid_str else None,
                "members": members,
                "message": f"Group: {group_name.strip()} (GID:{gid_str}) Members: {', '.join(members) if members else 'none'}",
                "raw_excerpt": raw_excerpt,
            })
    return results


def _parse_shadow(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    entries: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and not _COMMENT_RE.match(stripped):
            name = stripped.split(":", 1)[0] if ":" in stripped else stripped
            entries.append(name)
    raw_excerpt = content.strip()[:2000]
    return [{
        "artifact_family": "linux_identity",
        "artifact_type": "shadow",
        "source_file": source_path,
        "line_number": 1,
        "username": ", ".join(entries) if entries else None,
        "message": f"Shadow file present with {len(entries)} user entries (hashes not stored)",
        "raw_excerpt": raw_excerpt,
    }]
