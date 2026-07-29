"""Generic Linux host-timezone parser.

Covers every source_kind a Debian, Ubuntu, RHEL, CentOS, Fedora, or generic
Linux installation may expose for its configured timezone:

* ``/etc/timezone``            -- Debian/Ubuntu, one-line IANA zone name.
* ``/etc/localtime``           -- symlink to ``/usr/share/zoneinfo/<Zone>``
                                   (usually skipped by disk-image
                                   materialization, since the walker does not
                                   preserve symlinks -- see
                                   ``app.disk_images.service``) or, far more
                                   commonly in collected evidence, a
                                   dereferenced copy of the target TZif
                                   binary.
* ``/etc/sysconfig/clock``     -- older RHEL/CentOS ``ZONE="..."`` shell
                                   assignment.
* ``/etc/conf.d/clock``        -- Gentoo/Alpine-style ``TIMEZONE="..."``.
* ``timedatectl``/``hostnamectl`` command-output captures -- text containing
  a ``Time zone: <Zone> (<abbrev>, <offset>)`` line.

This module is the first, and intentionally narrow, consumer of the Host
Facts abstraction (see ``app.services.host_facts``): it only ever asserts
``host.timezone``. It never infers a zone name from a UTC offset or an
abbreviation, and it never guesses when a TZif binary cannot be matched
exactly against a known zone database.
"""
from __future__ import annotations

import hashlib
import re
import struct
import zoneinfo
from pathlib import Path

FACT_TYPE_TIMEZONE = "host.timezone"

_TZIF_MAGIC = b"TZif"
_TZIF_SUPPORTED_VERSIONS = {b"\x00", b"2", b"3", b"4"}
_TZIF_HEADER_STRUCT = struct.Struct(">4sc15xllllll")  # magic, version, 15 reserved, then 6 counts

# Systemd's real output is "Time zone: Europe/Madrid (CET, +0100)". Only the
# token immediately after the colon is ever used -- the parenthetical
# abbreviation/offset is provenance only and is never used to name the zone.
# Public: app.ingest.linux.os_info's hostnamectl handling reuses this same
# pattern instead of matching "Time zone:" a second, independent way.
TIME_ZONE_LINE_RE = re.compile(r"^\s*Time zone:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_TIME_ZONE_LINE_RE = TIME_ZONE_LINE_RE

# ZONE=... / TIMEZONE=... shell-assignment style, tolerant of quoting and
# surrounding whitespace. Matched with a regex, never evaluated as shell.
_SHELL_ASSIGNMENT_RE = re.compile(r"^\s*(?:export\s+)?(ZONE|TIMEZONE)\s*=\s*[\"']?([^\"'\r\n]+?)[\"']?\s*(?:#.*)?$", re.IGNORECASE | re.MULTILINE)

_ZONEINFO_SKIP_PREFIXES = ("posix/", "right/")
_ZONEINFO_SKIP_NAMES = {
    "posixrules",
    "iso3166.tab",
    "zone.tab",
    "zone1970.tab",
    "tzdata.zi",
    "leapseconds",
    "leap-seconds.list",
}

_zone_hash_index: dict[str, str] | None = None
_available_zone_names: frozenset[str] | None = None


def _available_zones() -> frozenset[str]:
    global _available_zone_names
    if _available_zone_names is None:
        try:
            _available_zone_names = frozenset(zoneinfo.available_timezones())
        except Exception:  # noqa: BLE001
            _available_zone_names = frozenset()
    return _available_zone_names


def _zoneinfo_roots() -> list[Path]:
    roots: list[Path] = []
    for candidate in zoneinfo.TZPATH:
        path = Path(candidate)
        if path.is_dir():
            roots.append(path)
    return roots


# Several IANA names are byte-identical TZif files (a fixed-offset zone
# carries no transition data to disambiguate it): Etc/UTC, Etc/UCT,
# Etc/Universal, Etc/Zulu, UTC, UCT, Universal and Zulu are all the same
# bytes on every tzdata release. Exact hashing genuinely cannot tell them
# apart -- this is not a matching bug. Rather than pick a winner by
# alphabetical accident, the handful of universally-recognized canonical
# spellings are preferred explicitly; this is still a choice *among
# validated exact matches*, never inference from an offset or abbreviation.
_CANONICAL_NAME_PREFERENCE = ("Etc/UTC", "UTC")


def _build_zone_hash_index() -> dict[str, str]:
    """Exact-match sha256(TZif bytes) -> canonical IANA zone name.

    Built once, lazily, from whatever system zoneinfo database is available
    in the current environment. Deliberately exact-match only: this is
    verification against a known-good source, not inference, and is skipped
    entirely (empty index) when no zoneinfo database is present.
    """
    global _zone_hash_index
    if _zone_hash_index is not None:
        return _zone_hash_index

    candidates: list[tuple[str, bytes]] = []  # (relative_zone_name, tzif_bytes)
    for root in _zoneinfo_roots():
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                continue
            if rel.startswith(_ZONEINFO_SKIP_PREFIXES) or rel in _ZONEINFO_SKIP_NAMES or rel.startswith("+"):
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if data.startswith(_TZIF_MAGIC):
                candidates.append((rel, data))

    index: dict[str, str] = {}
    # Preferred canonical spellings claim their digest first...
    for preferred in _CANONICAL_NAME_PREFERENCE:
        for rel, data in candidates:
            if rel == preferred:
                index.setdefault(hashlib.sha256(data).hexdigest(), rel)
    # ...then every other digest is filled in, first (sorted) name wins.
    for rel, data in candidates:
        index.setdefault(hashlib.sha256(data).hexdigest(), rel)

    _zone_hash_index = index
    return index


def match_tzif_to_zone_name(content: bytes) -> str | None:
    """Exact-match a TZif blob against the system zoneinfo database, or None."""
    index = _build_zone_hash_index()
    if not index:
        return None
    return index.get(hashlib.sha256(content).hexdigest())


def _validate_tzif_header(content: bytes) -> dict | None:
    """Validate the TZif magic + version + count fields (RFC 8536 section 3.1).

    Returns a small metadata dict on success, None if the header is not a
    structurally valid TZif file. This is a header/version/count-consistency
    check only -- it does not need to walk the full transition table to
    decide "this is a valid tzfile".
    """
    if len(content) < _TZIF_HEADER_STRUCT.size or not content.startswith(_TZIF_MAGIC):
        return None
    try:
        magic, version, isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt = _TZIF_HEADER_STRUCT.unpack_from(content, 0)
    except struct.error:
        return None
    if version not in _TZIF_SUPPORTED_VERSIONS:
        return None
    if any(count < 0 for count in (isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt)):
        return None
    if isutcnt not in (0, typecnt) or isstdcnt not in (0, typecnt):
        return None
    version_label = "1" if version == b"\x00" else version.decode("ascii", errors="replace")
    return {
        "version": version_label,
        "isutcnt": isutcnt,
        "isstdcnt": isstdcnt,
        "leapcnt": leapcnt,
        "timecnt": timecnt,
        "typecnt": typecnt,
        "charcnt": charcnt,
    }


def _clean_zone_candidate(value: str) -> str:
    return value.strip().strip("\"'").strip()


def validate_iana_zone(candidate: str) -> tuple[str | None, str]:
    """Return (normalized_value, confidence_penalty_reason).

    Only ever resolves a name that exists in the system's own IANA zone
    database -- never a name synthesized from an offset or abbreviation.
    Public: reused by app.ingest.linux.os_info's hostnamectl handling so
    the "Time zone:" line is validated identically wherever it is found,
    without duplicating this logic a second time.
    """
    cleaned = _clean_zone_candidate(candidate)
    if not cleaned:
        return None, "empty"
    zones = _available_zones()
    if zones and cleaned not in zones:
        return None, "not_a_known_iana_zone"
    if not zones:
        # No zone database available in this environment (should not happen
        # in normal deployment -- see runtime validation) -- accept a
        # syntactically plausible IANA-shaped name rather than reject
        # everything outright.
        if re.fullmatch(r"[A-Za-z0-9+_-]+(?:/[A-Za-z0-9+_.~-]+)*", cleaned):
            return cleaned, "unverified_no_zone_database"
        return None, "not_iana_shaped"
    return cleaned, ""


_validated_zone = validate_iana_zone  # internal alias, kept for brevity below


def _row(
    *,
    source_kind: str,
    source_path: str,
    raw_value: str,
    normalized_value: str | None,
    confidence: str,
    parse_status: str,
    reason: str = "",
    tzif_meta: dict | None = None,
) -> dict:
    display_value = normalized_value or raw_value or "(no value)"
    message = f"Linux timezone observation ({source_kind}): {display_value}"
    return {
        "artifact_family": "linux_timezone",
        "artifact_type": source_kind,
        "source_file": source_path,
        "fact_type": FACT_TYPE_TIMEZONE,
        "raw_value": raw_value[:2000] if raw_value else raw_value,
        "normalized_value": normalized_value,
        "confidence": confidence,
        "parse_status": parse_status,
        "reason": reason,
        "tzif_meta": tzif_meta,
        "message": message,
        "raw_excerpt": (raw_value or "")[:2000],
    }


def _parse_etc_timezone_text(content: str, source_path: str) -> list[dict]:
    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]
    if not lines:
        return [_row(source_kind="etc_timezone", source_path=source_path, raw_value="", normalized_value=None, confidence="high", parse_status="invalid", reason="empty_file")]
    raw = lines[0]
    normalized, reason = _validated_zone(raw)
    status = "valid" if normalized else "invalid"
    return [_row(source_kind="etc_timezone", source_path=source_path, raw_value=raw, normalized_value=normalized, confidence="high", parse_status=status, reason=reason)]


def _parse_shell_clock_file(content: str, source_path: str, *, source_kind: str) -> list[dict]:
    match = _SHELL_ASSIGNMENT_RE.search(content)
    if not match:
        return [_row(source_kind=source_kind, source_path=source_path, raw_value="", normalized_value=None, confidence="medium", parse_status="invalid", reason="no_zone_assignment_found")]
    raw = match.group(2)
    normalized, reason = _validated_zone(raw)
    status = "valid" if normalized else "invalid"
    return [_row(source_kind=source_kind, source_path=source_path, raw_value=raw, normalized_value=normalized, confidence="medium", parse_status=status, reason=reason)]


def _parse_time_zone_line(content: str, source_path: str, *, source_kind: str, required: bool) -> list[dict]:
    match = _TIME_ZONE_LINE_RE.search(content)
    if not match:
        if required:
            return [_row(source_kind=source_kind, source_path=source_path, raw_value="", normalized_value=None, confidence="high", parse_status="invalid", reason="no_time_zone_line_found")]
        return []
    raw = match.group(1)
    normalized, reason = _validated_zone(raw)
    status = "valid" if normalized else "invalid"
    return [_row(source_kind=source_kind, source_path=source_path, raw_value=raw, normalized_value=normalized, confidence="high", parse_status=status, reason=reason)]


def _looks_like_zoneinfo_symlink_target(text: str) -> str | None:
    stripped = text.strip()
    if not stripped or len(stripped) > 4096 or "\x00" in stripped:
        return None
    marker = "zoneinfo/"
    idx = stripped.rfind(marker)
    if idx == -1:
        return None
    candidate = stripped[idx + len(marker):].strip()
    if not candidate or "\n" in candidate:
        return None
    return candidate


def _parse_etc_localtime_text(content: str, source_path: str) -> list[dict]:
    candidate = _looks_like_zoneinfo_symlink_target(content)
    if candidate is None:
        return []
    normalized, reason = _validated_zone(candidate)
    status = "valid" if normalized else "invalid"
    return [_row(source_kind="etc_localtime_symlink", source_path=source_path, raw_value=content.strip()[:512], normalized_value=normalized, confidence="high", parse_status=status, reason=reason)]


def _parse_etc_localtime_binary(content: bytes, source_path: str) -> list[dict]:
    header = _validate_tzif_header(content)
    if header is None:
        # Not a TZif file. It may still be a symlink target serialized as
        # bytes by an archive/collection tool that does not preserve real
        # symlinks -- try decoding it as text before rejecting outright.
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return []
        return _parse_etc_localtime_text(text, source_path)
    zone_name = match_tzif_to_zone_name(content)
    if zone_name:
        return [_row(
            source_kind="etc_localtime_tzif", source_path=source_path,
            raw_value=zone_name, normalized_value=zone_name,
            confidence="high", parse_status="valid", tzif_meta=header,
        )]
    # A structurally valid TZif file that does not match any zone this
    # environment's own database knows about. This is the "store valid
    # tzfile, unknown zone; do not guess" case from the spec.
    return [_row(
        source_kind="etc_localtime_tzif", source_path=source_path,
        raw_value=f"TZif v{header['version']} ({header['typecnt']} types, {header['timecnt']} transitions)",
        normalized_value=None, confidence="low", parse_status="unknown_zone",
        reason="tzif_valid_no_exact_zone_match", tzif_meta=header,
    )]


def parse_timezone(content: bytes | str, *, source_path: str = "", username: str | None = None) -> list[dict]:
    """Parse a single timezone-source file into 0 or 1 observation rows.

    ``content`` is bytes only for ``/etc/localtime`` (registered as a binary
    artifact type in ``app.ingest.linux.dispatch``); every other source_kind
    arrives as decoded text, matching the convention already used by
    ``app.ingest.linux.os_info``.

    Note: ``hostnamectl`` output is *not* handled here even though it can
    carry a "Time zone:" line -- it is host-identity command output first
    and foremost (hostname, distribution, kernel, architecture), so its
    dispatch and parsing live in ``app.ingest.linux.os_info`` alongside
    those other facts, reusing ``validate_iana_zone``/``TIME_ZONE_LINE_RE``
    from this module for the timezone portion rather than duplicating it.
    """
    path_lower = str(source_path).replace("\\", "/").lower()
    name = path_lower.rsplit("/", 1)[-1]

    if isinstance(content, bytes):
        return _parse_etc_localtime_binary(content, source_path)

    if name == "timezone" or name.startswith("timezone."):
        return _parse_etc_timezone_text(content, source_path)
    if "/sysconfig/clock" in path_lower:
        return _parse_shell_clock_file(content, source_path, source_kind="sysconfig_clock")
    if "/conf.d/clock" in path_lower:
        return _parse_shell_clock_file(content, source_path, source_kind="conf_d_clock")
    if "timedatectl" in name:
        return _parse_time_zone_line(content, source_path, source_kind="timedatectl", required=True)
    if name == "localtime" or name.startswith("localtime."):
        return _parse_etc_localtime_text(content, source_path)
    return []
