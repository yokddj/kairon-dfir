"""Parser for Citrix NetScaler/ADC's ns.conf -- the flat list of CLI
commands ("add system user ...", "set ns hostName ...", "bind ssl vserver
...") that is both the running and, via its dated/versioned backups, the
historical configuration of the appliance.

Grammar note: NetScaler's CLI has no single public grammar this parser can
rely on, so object_subtype/object_name below are a best-effort heuristic
(the first alphabetic, non-flag token after the object type is treated as
a subtype; the next non-flag token after that is the name) -- good enough
to make every command searchable/filterable by verb, object, and name, not
a claim of exact per-command-type field extraction the way, say,
app.ingest.linux.sudoers parses a known sudoers grammar.
"""
from __future__ import annotations

import re
import shlex
from datetime import datetime, timezone

_HEADER_VERSION_RE = re.compile(r"^#NS(?P<version>\S+)\s+Build\s+(?P<build>\S+)", re.IGNORECASE)
_HEADER_SAVED_RE = re.compile(r"^#\s*Last modified by `save config`,\s*(?P<when>.+)$", re.IGNORECASE)
# ns.conf timestamps are written in the appliance's own ctime-style format,
# e.g. "Mon Jan 01 00:00:00 2026" -- no timezone offset is recorded in the
# file, so this is taken as-is (naive) rather than guessed at UTC.
_HEADER_SAVED_FORMAT = "%a %b %d %H:%M:%S %Y"
_ALPHA_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_MAX_RAW_EXCERPT = 4000


def _tokenize(line: str) -> list[str]:
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        # Unbalanced quote (rare, e.g. a value containing a stray `"`) --
        # fall back to whitespace splitting rather than dropping the line.
        return line.split()


def parse_ns_conf(content: str, *, source_path: str = "") -> list[dict]:
    is_backup = not source_path.lower().endswith("/ns.conf") and source_path.lower() != "ns.conf"
    results: list[dict] = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        raw_excerpt = raw_line[:_MAX_RAW_EXCERPT]
        if line.startswith("#"):
            if line_number <= 2:
                version_match = _HEADER_VERSION_RE.match(line)
                if version_match:
                    results.append({
                        "artifact_family": "netscaler_config",
                        "artifact_type": "ns_conf_header",
                        "source_file": source_path,
                        "line_number": line_number,
                        "command_verb": None,
                        "object_type": None,
                        "object_subtype": None,
                        "object_name": None,
                        "ns_version": version_match.group("version"),
                        "ns_build": version_match.group("build"),
                        "is_backup_config": is_backup,
                        "message": f"NetScaler {version_match.group('version')} Build {version_match.group('build')}",
                        "raw_excerpt": raw_excerpt,
                    })
                    continue
                saved_match = _HEADER_SAVED_RE.match(line)
                if saved_match:
                    timestamp_iso = None
                    try:
                        parsed_dt = datetime.strptime(saved_match.group("when").strip(), _HEADER_SAVED_FORMAT)
                        timestamp_iso = parsed_dt.replace(tzinfo=timezone.utc).isoformat()
                    except ValueError:
                        pass
                    results.append({
                        "artifact_family": "netscaler_config",
                        "artifact_type": "ns_conf_header",
                        "source_file": source_path,
                        "line_number": line_number,
                        "command_verb": None,
                        "object_type": None,
                        "object_subtype": None,
                        "object_name": None,
                        "timestamp": timestamp_iso,
                        "is_backup_config": is_backup,
                        "message": f"Config saved: {saved_match.group('when').strip()}",
                        "raw_excerpt": raw_excerpt,
                    })
                    continue
            continue
        tokens = _tokenize(line)
        if not tokens:
            continue
        verb = tokens[0].lower()
        object_type = tokens[1] if len(tokens) > 1 else None
        remaining = tokens[2:]
        object_subtype = None
        if remaining and not remaining[0].startswith("-") and _ALPHA_TOKEN_RE.match(remaining[0]):
            object_subtype = remaining[0]
            remaining = remaining[1:]
        object_name = None
        if remaining and not remaining[0].startswith("-"):
            object_name = remaining[0]
        message = " ".join(part for part in (verb, object_type, object_subtype) if part)
        if object_name:
            message = f"{message}: {object_name}"
        # "set ns hostName <name>" is the one ns.conf command that names the
        # appliance itself -- surfaced as a top-level hostname fact so this
        # row (and every other row downstream, via normalize_netscaler_row's
        # detected_host handoff) can carry the real host identity instead of
        # relying on a filename/path-derived guess.
        hostname = object_name if (verb == "set" and object_type == "ns" and (object_subtype or "").lower() == "hostname") else None
        results.append({
            "artifact_family": "netscaler_config",
            "artifact_type": "ns_conf_backup" if is_backup else "ns_conf",
            "source_file": source_path,
            "line_number": line_number,
            "command_verb": verb,
            "object_type": object_type,
            "object_subtype": object_subtype,
            "hostname": hostname,
            "object_name": object_name,
            "is_backup_config": is_backup,
            "message": message,
            "raw_excerpt": raw_excerpt,
        })
    return results
