"""OS/host-identity parser: /etc/hostname, hostnamectl output, /etc/os-release,
/etc/lsb-release, /etc/debian_version, /proc/version, uname output.

Second consumer of the Host Facts abstraction (see app.services.host_facts),
covering host.hostname, host.fqdn, host.distribution, host.distribution_version,
host.kernel and host.architecture. Timezone (host.timezone) stays owned by
app.ingest.linux.timezone except for the one line hostnamectl output shares
with it -- that line is validated here via timezone.validate_iana_zone /
timezone.TIME_ZONE_LINE_RE rather than a second, independent implementation.
"""
from __future__ import annotations
import re
from pathlib import Path

from app.ingest.linux.timezone import FACT_TYPE_TIMEZONE, TIME_ZONE_LINE_RE, validate_iana_zone

FACT_HOSTNAME = "host.hostname"
FACT_FQDN = "host.fqdn"
FACT_DISTRIBUTION = "host.distribution"
FACT_DISTRIBUTION_VERSION = "host.distribution_version"
FACT_KERNEL = "host.kernel"
FACT_ARCHITECTURE = "host.architecture"

_OS_RELEASE_RE = re.compile(r"^\s*(\w+)\s*=\s*\"?([^\"]*?)\"?\s*$")
_COMMENT_RE = re.compile(r"^\s*#")

# RFC 1123 hostname label, requiring at least two labels (i.e. a dot) to
# ever be considered an FQDN -- a bare "victoria" never qualifies, only an
# explicitly dotted value like "server01.example.com" does. Never used to
# derive a domain that was not already present in the observed value.
_FQDN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)

# hostnamectl's real output spells this "x86-64" (hyphen); uname and
# /proc/version spell it "x86_64"/"amd64" -- all recognized and normalized
# to the same canonical form.
_KNOWN_ARCH_TOKENS = r"(x86[_-]64|amd64|aarch64|arm64|armv\d[a-z]*|armhf|i[3-6]86|x86|ppc64le|s390x)"
_ARCH_TOKEN_RE = re.compile(_KNOWN_ARCH_TOKENS, re.IGNORECASE)
_ARCH_NORMALIZE = {
    "amd64": "x86_64", "x86_64": "x86_64", "x86-64": "x86_64",
    "i386": "x86", "i486": "x86", "i586": "x86", "i686": "x86", "x86": "x86",
    "arm64": "aarch64", "aarch64": "aarch64",
    "armhf": "arm", "arm": "arm",
    "ppc64le": "ppc64le",
    "s390x": "s390x",
}

_KERNEL_VERSION_LINE_RE = re.compile(r"version\s+(\S+)", re.IGNORECASE)
_KERNEL_BUILD_RE = re.compile(r"(#\S.*)$")
_UNAME_LINE_RE = re.compile(
    r"^Linux\s+(?P<hostname>\S+)\s+(?P<release>\S+)\s+(?P<build>.*?)\s*"
    + _KNOWN_ARCH_TOKENS + r"\s+GNU/Linux\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_HOSTNAMECTL_FIELD_RE = re.compile(r"^\s*([A-Za-z ]+?):\s*(.+?)\s*$", re.MULTILINE)


def _normalize_arch(raw: str) -> str | None:
    return _ARCH_NORMALIZE.get(raw.strip().lower())


def _looks_like_fqdn(value: str) -> bool:
    return bool(value) and bool(_FQDN_RE.match(value.strip()))


def _row(
    *,
    fact_type: str,
    source_kind: str,
    source_path: str,
    raw_value: str,
    normalized_value: str | None,
    confidence: str,
    parse_status: str,
    reason: str = "",
    extra: dict | None = None,
) -> dict:
    display_value = normalized_value or raw_value or "(no value)"
    row = {
        "artifact_family": "linux_os_info",
        "artifact_type": source_kind,
        "source_file": source_path,
        "fact_type": fact_type,
        "raw_value": raw_value[:2000] if raw_value else raw_value,
        "normalized_value": normalized_value,
        "confidence": confidence,
        "parse_status": parse_status,
        "reason": reason,
        "message": f"Linux {fact_type} observation ({source_kind}): {display_value}",
        "raw_excerpt": (raw_value or "")[:2000],
        # legacy fields some older consumers/tests still read directly
        "hostname": None,
        "os_name": None,
        "os_version": None,
        "kernel_version": None,
        "architecture": None,
        "detected_host": None,
    }
    if extra:
        row.update(extra)
    return row


def _hostname_rows(hostname_val: str, *, source_kind: str, source_path: str) -> list[dict]:
    hostname_val = hostname_val.strip()
    if not hostname_val:
        return [_row(fact_type=FACT_HOSTNAME, source_kind=source_kind, source_path=source_path, raw_value="", normalized_value=None, confidence="high", parse_status="invalid", reason="empty_value")]
    rows = [_row(
        fact_type=FACT_HOSTNAME, source_kind=source_kind, source_path=source_path,
        raw_value=hostname_val, normalized_value=hostname_val, confidence="high", parse_status="valid",
        extra={"hostname": hostname_val, "detected_host": hostname_val},
    )]
    if _looks_like_fqdn(hostname_val):
        rows.append(_row(
            fact_type=FACT_FQDN, source_kind=source_kind, source_path=source_path,
            raw_value=hostname_val, normalized_value=hostname_val, confidence="high", parse_status="valid",
        ))
    return rows


def _parse_os_release_fields(content: str) -> dict[str, str]:
    info: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or _COMMENT_RE.match(stripped):
            continue
        match = _OS_RELEASE_RE.match(stripped)
        if match:
            info[match.group(1).upper()] = match.group(2).strip().strip('"')
    return info


def _distribution_rows_from_os_release(info: dict[str, str], *, source_kind: str, source_path: str, confidence: str) -> list[dict]:
    rows: list[dict] = []
    dist_id = info.get("ID")
    pretty = info.get("PRETTY_NAME") or info.get("NAME")
    if dist_id or pretty:
        rows.append(_row(
            fact_type=FACT_DISTRIBUTION, source_kind=source_kind, source_path=source_path,
            raw_value=pretty or dist_id or "", normalized_value=(dist_id or "").lower() or None,
            confidence=confidence, parse_status="valid" if (dist_id or pretty) else "invalid",
            extra={"os_name": pretty or info.get("NAME") or dist_id},
        ))
    version_id = info.get("VERSION_ID")
    version = info.get("VERSION") or info.get("BUILD_ID")
    if version_id or version:
        rows.append(_row(
            fact_type=FACT_DISTRIBUTION_VERSION, source_kind=source_kind, source_path=source_path,
            raw_value=version or version_id or "", normalized_value=version_id or None,
            confidence=confidence, parse_status="valid" if (version_id or version) else "invalid",
            extra={"os_version": version or version_id, "reason": "" if version_id else "no_machine_readable_version_id"},
        ))
    return rows


def _kernel_and_arch_rows(kernel_release: str | None, build_string: str | None, arch_raw: str | None, *, source_kind: str, source_path: str, confidence: str) -> list[dict]:
    rows: list[dict] = []
    if kernel_release:
        raw = kernel_release if not build_string else f"{kernel_release} {build_string}"
        rows.append(_row(
            fact_type=FACT_KERNEL, source_kind=source_kind, source_path=source_path,
            raw_value=raw[:2000], normalized_value=kernel_release, confidence=confidence, parse_status="valid",
            extra={"kernel_version": kernel_release},
        ))
    if arch_raw:
        normalized = _normalize_arch(arch_raw)
        rows.append(_row(
            fact_type=FACT_ARCHITECTURE, source_kind=source_kind, source_path=source_path,
            raw_value=arch_raw, normalized_value=normalized, confidence=confidence,
            parse_status="valid" if normalized else "invalid",
            reason="" if normalized else "unrecognized_architecture_token",
            extra={"architecture": normalized or arch_raw},
        ))
    return rows


def _parse_hostnamectl(content: str, source_path: str) -> list[dict]:
    fields: dict[str, str] = {}
    for match in _HOSTNAMECTL_FIELD_RE.finditer(content):
        fields[match.group(1).strip().lower()] = match.group(2).strip()
    rows: list[dict] = []
    static_hostname = fields.get("static hostname")
    if static_hostname:
        rows.extend(_hostname_rows(static_hostname, source_kind="hostnamectl", source_path=source_path))
    operating_system = fields.get("operating system")
    if operating_system:
        rows.append(_row(
            fact_type=FACT_DISTRIBUTION, source_kind="hostnamectl", source_path=source_path,
            raw_value=operating_system, normalized_value=None, confidence="medium", parse_status="valid",
            reason="hostnamectl_pretty_name_only_no_machine_readable_id",
            extra={"os_name": operating_system},
        ))
    kernel_field = fields.get("kernel")
    if kernel_field:
        kernel_release = kernel_field.removeprefix("Linux ").strip() or kernel_field
        rows.append(_row(
            fact_type=FACT_KERNEL, source_kind="hostnamectl", source_path=source_path,
            raw_value=kernel_field, normalized_value=kernel_release, confidence="high", parse_status="valid",
            extra={"kernel_version": kernel_release},
        ))
    arch_field = fields.get("architecture")
    if arch_field:
        normalized = _normalize_arch(arch_field)
        rows.append(_row(
            fact_type=FACT_ARCHITECTURE, source_kind="hostnamectl", source_path=source_path,
            raw_value=arch_field, normalized_value=normalized, confidence="high",
            parse_status="valid" if normalized else "invalid",
            reason="" if normalized else "unrecognized_architecture_token",
            extra={"architecture": normalized or arch_field},
        ))
    tz_match = TIME_ZONE_LINE_RE.search(content)
    if tz_match:
        raw_tz = tz_match.group(1)
        normalized_tz, reason = validate_iana_zone(raw_tz)
        rows.append(_row(
            fact_type=FACT_TYPE_TIMEZONE, source_kind="hostnamectl", source_path=source_path,
            raw_value=raw_tz, normalized_value=normalized_tz, confidence="high",
            parse_status="valid" if normalized_tz else "invalid", reason=reason,
        ))
    return rows


def parse_os_info(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    path_lower = str(source_path).replace("\\", "/").lower()
    file_name = Path(source_path).name.lower() if source_path else ""

    if "hostnamectl" in file_name:
        return _parse_hostnamectl(content, source_path)

    if file_name == "hostname":
        hostname_val = content.strip().split("\n")[0].strip()
        return _hostname_rows(hostname_val, source_kind="hostname", source_path=source_path)

    if file_name == "os-release" or path_lower.endswith("/os-release"):
        info = _parse_os_release_fields(content)
        rows = _distribution_rows_from_os_release(info, source_kind="os_release", source_path=source_path, confidence="high")
        if rows:
            return rows
        return [_row(fact_type=FACT_DISTRIBUTION, source_kind="os_release", source_path=source_path, raw_value="", normalized_value=None, confidence="high", parse_status="invalid", reason="no_recognizable_fields")]

    if file_name == "lsb-release":
        info: dict[str, str] = {}
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or _COMMENT_RE.match(stripped):
                continue
            match = _OS_RELEASE_RE.match(stripped)
            if match:
                info[match.group(1).upper()] = match.group(2).strip().strip('"')
        # lsb-release uses DISTRIB_* keys instead of os-release's bare keys;
        # remap onto the same shape so the same row-builder logic applies.
        remapped = {
            "ID": info.get("DISTRIB_ID", "").lower() or None,
            "NAME": info.get("DISTRIB_ID"),
            "PRETTY_NAME": info.get("DISTRIB_DESCRIPTION") or info.get("DISTRIB_ID"),
            "VERSION_ID": info.get("DISTRIB_RELEASE"),
            "VERSION": info.get("DISTRIB_DESCRIPTION"),
        }
        remapped = {key: value for key, value in remapped.items() if value}
        rows = _distribution_rows_from_os_release(remapped, source_kind="lsb_release", source_path=source_path, confidence="medium")
        if rows:
            return rows
        return [_row(fact_type=FACT_DISTRIBUTION, source_kind="lsb_release", source_path=source_path, raw_value="", normalized_value=None, confidence="medium", parse_status="invalid", reason="no_recognizable_fields")]

    if file_name == "debian_version":
        version_val = content.strip().split("\n")[0].strip()
        rows: list[dict] = []
        if version_val:
            # The file's own existence and format is Debian-family-specific
            # by definition -- recording host.distribution="debian" here is
            # reading that signal, not inferring anything about the host
            # beyond what the presence of this exact file already asserts.
            rows.append(_row(
                fact_type=FACT_DISTRIBUTION, source_kind="debian_version", source_path=source_path,
                raw_value="debian_version file present", normalized_value="debian", confidence="medium",
                parse_status="valid", reason="distribution_inferred_from_debian_version_file_identity",
                extra={"os_name": "Debian"},
            ))
            rows.append(_row(
                fact_type=FACT_DISTRIBUTION_VERSION, source_kind="debian_version", source_path=source_path,
                raw_value=version_val, normalized_value=version_val, confidence="high", parse_status="valid",
                extra={"os_version": version_val},
            ))
            return rows
        return [_row(fact_type=FACT_DISTRIBUTION_VERSION, source_kind="debian_version", source_path=source_path, raw_value="", normalized_value=None, confidence="high", parse_status="invalid", reason="empty_file")]

    if "uname" in file_name:
        match = _UNAME_LINE_RE.search(content)
        if not match:
            return [_row(fact_type=FACT_KERNEL, source_kind="uname", source_path=source_path, raw_value=content.strip()[:500], normalized_value=None, confidence="high", parse_status="invalid", reason="unrecognized_uname_format")]
        arch_match = _ARCH_TOKEN_RE.search(match.group(0))
        return _kernel_and_arch_rows(
            match.group("release"), match.group("build") or None, arch_match.group(0) if arch_match else None,
            source_kind="uname", source_path=source_path, confidence="high",
        )

    if file_name == "version" and "proc" in path_lower:
        first_line = content.strip().split("\n")[0] if content.strip() else ""
        ver_match = _KERNEL_VERSION_LINE_RE.search(first_line)
        kernel_release = ver_match.group(1) if ver_match else None
        build_match = _KERNEL_BUILD_RE.search(first_line)
        build_string = build_match.group(1)[:300] if build_match else None
        # Architecture is looked for only inside the release token itself
        # (e.g. the "-amd64" in "5.10.0-9-amd64"), never across the whole
        # line -- /proc/version's parenthetical builder info can contain
        # an unrelated arch-looking substring (e.g. a build-farm hostname
        # like "buildd@lcy02-amd64-101") that has nothing to do with this
        # host's own architecture.
        arch_match = _ARCH_TOKEN_RE.search(kernel_release) if kernel_release else None
        rows = _kernel_and_arch_rows(
            kernel_release, build_string, arch_match.group(0) if arch_match else None,
            source_kind="kernel_version", source_path=source_path, confidence="high",
        )
        if rows:
            return rows
        return [_row(fact_type=FACT_KERNEL, source_kind="kernel_version", source_path=source_path, raw_value=first_line[:500], normalized_value=None, confidence="high", parse_status="invalid", reason="no_kernel_release_found")]

    return [_row(fact_type="", source_kind="os_info", source_path=source_path, raw_value=content.strip()[:2000], normalized_value=None, confidence="low", parse_status="invalid", reason="unrecognized_os_info_source", extra={"message": content.strip()[:2000]})]
