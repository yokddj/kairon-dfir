"""Disk-visible compromise indicators for Citrix NetScaler ADC/Gateway,
from CVE-2026-88771 (unauthenticated RCE via input validation failure) and
CVE-2026-88772 (DTLS memory overflow RCE/DoS), both CVSS v4.0 9.5 --
Unit42, published 2026-09-30:
https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/

Every string/path/hash below is quoted or hashed directly from that
report. The detectors are intentionally structural, not just hash
matches, so they stay useful for a variant of this campaign that changes
the implant's filename, passphrase, or RC4 key but reuses the same
staging directory, persistence mechanism, or log-write pattern.
"""
from __future__ import annotations

import hashlib
import re

_MAX_RAW_EXCERPT = 2000

# --- LogonPoint/custom/ web shell scan ------------------------------------

# The actual implant Unit42 recovered. A renamed/re-keyed variant of the
# same campaign won't match this filename -- see the content-based checks
# below, which don't depend on it.
_KNOWN_WEBSHELL_FILENAME = ".ctxs.receiver"
_KNOWN_PASSPHRASE = "Rhfajaf1H992"
_KNOWN_RC4_KEY = "7489a0f93c67fa5cdaeb4b921d90594d"
_SUSPICIOUS_COOKIE_NAMES = ("CsrfToken", "NSC_TASS")
_STATIC_ASSET_EXTENSIONS = {".css", ".png", ".gif", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".ttf"}
_PHP_EXEC_SINK_RE = re.compile(r"\b(passthru|shell_exec|system|exec|proc_open|popen|eval)\s*\(", re.IGNORECASE)


def scan_logonpoint_custom_file(content: str, *, source_path: str = "") -> list[dict]:
    name = source_path.rsplit("/", 1)[-1].lower()
    suffix = f".{name.rsplit('.', 1)[-1]}" if "." in name else ""
    reasons: list[str] = []
    severity = None

    if name == _KNOWN_WEBSHELL_FILENAME:
        reasons.append(f"filename matches known CVE-2026-88771 web shell '{_KNOWN_WEBSHELL_FILENAME}'")
        severity = "critical"
    if _KNOWN_PASSPHRASE in content:
        reasons.append("content contains the known implant auth passphrase")
        severity = "critical"
    if _KNOWN_RC4_KEY in content:
        reasons.append("content contains the known implant RC4 key")
        severity = "critical"
    for cookie_name in _SUSPICIOUS_COOKIE_NAMES:
        if cookie_name in content:
            reasons.append(f"content references the '{cookie_name}' command/auth cookie")
            severity = severity or "high"
    sink_match = _PHP_EXEC_SINK_RE.search(content)
    if sink_match:
        # Deliberately not gated on extension: the report's own persistence
        # mechanism disguises the web shell as a .css file (receiver.min.css,
        # receiver.min.<hex>.css) routed through Apache as PHP via the
        # tampered httpd.conf -- skipping "static" extensions here would
        # blind this exact check to the one file it most needs to catch.
        reasons.append(f"content calls PHP execution sink '{sink_match.group(1)}()'")
        severity = severity or "high"

    if not reasons:
        if suffix in _STATIC_ASSET_EXTENSIONS or suffix in {".html", ".htm", ""}:
            # LogonPoint/custom/ legitimately holds branding assets --
            # nothing suspicious found, nothing to flag.
            return []
        severity = "medium"
        reasons.append(f"unexpected '{suffix or 'no-extension'}' file in a directory meant for static branding assets")

    return [{
        "artifact_family": "netscaler_compromise",
        "artifact_type": "logonpoint_custom_file",
        "source_file": source_path,
        "finding_type": "suspicious_logonpoint_custom_file",
        "severity": severity,
        "reasons": reasons,
        "message": f"{source_path}: {'; '.join(reasons)}",
        "raw_excerpt": content[:_MAX_RAW_EXCERPT],
    }]


# --- /etc/httpd.conf tampering --------------------------------------------

# Stage of CVE-2026-88771 persistence: a perl one-liner patches this file
# to both route LogonPoint/custom/.ctxs.receiver's PHP execution and
# enable the PHP engine, which NetScaler ships disabled by default.
_FILES_BLOCK_RE = re.compile(r'<Files\s+"?([^">]+)"?\s*>', re.IGNORECASE)
_ALIAS_RE = re.compile(r"^\s*Alias(Match)?\s+(\S+)\s+(\S+)", re.IGNORECASE | re.MULTILINE)
_PHP_ENGINE_ON_RE = re.compile(r"php_flag\s+engine\s+on", re.IGNORECASE)


def parse_httpd_conf_for_tampering(content: str, *, source_path: str = "") -> list[dict]:
    findings: list[dict] = []
    for match in _FILES_BLOCK_RE.finditer(content):
        target = match.group(1)
        if "logonpoint" in target.lower() or target.lower() == _KNOWN_WEBSHELL_FILENAME:
            findings.append(_httpd_finding(source_path, "critical", f'<Files "{target}"> block references a LogonPoint custom path -- matches CVE-2026-88771 persistence', match.group(0)))
    for match in _ALIAS_RE.finditer(content):
        alias_path, alias_target = match.group(2), match.group(3)
        if "logonpoint/custom" in alias_path.lower() or "logonpoint/custom" in alias_target.lower():
            findings.append(_httpd_finding(source_path, "critical", f"{match.group(0).strip().split()[0]} directive routes through LogonPoint/custom/ -- matches CVE-2026-88771 persistence", match.group(0)))
    if _PHP_ENGINE_ON_RE.search(content):
        findings.append(_httpd_finding(source_path, "high", "PHP engine explicitly enabled (NetScaler ships it disabled) -- required for the CVE-2026-88771 PHP web shell to execute", "php_flag engine on"))
    return findings


def _httpd_finding(source_path: str, severity: str, message: str, raw_excerpt: str) -> dict:
    return {
        "artifact_family": "netscaler_compromise",
        "artifact_type": "httpd_conf",
        "source_file": source_path,
        "finding_type": "httpd_conf_tampering",
        "severity": severity,
        "reasons": [message],
        "message": message,
        "raw_excerpt": raw_excerpt[:_MAX_RAW_EXCERPT],
    }


# --- /var/log/ns.log exploitation pattern ---------------------------------

# CVE-2026-88771 stage 2: the malicious login attempt itself is logged
# here with this literal (non-standard, attacker-triggered) fragment.
_NS_LOG_EXPLOIT_RE = re.compile(r"pitboss PPE missed too many heartbeatsNSPPE;", re.IGNORECASE)


def parse_ns_log_for_exploitation(content: str, *, source_path: str = "") -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        if _NS_LOG_EXPLOIT_RE.search(line):
            results.append({
                "artifact_family": "netscaler_compromise",
                "artifact_type": "ns_log",
                "source_file": source_path,
                "line_number": line_number,
                "finding_type": "cve_2026_88771_exploitation_attempt",
                "severity": "critical",
                "reasons": ["line matches the CVE-2026-88771 stage-2 exploitation log pattern"],
                "message": "ns.log: CVE-2026-88771 exploitation attempt pattern matched",
                "raw_excerpt": line.strip()[:_MAX_RAW_EXCERPT],
            })
    return results


# --- /var/log/httpaccess-vpn.log payload smuggling ------------------------

# CVE-2026-88771 stage 1: a base64-encoded dropper is smuggled in through
# the request's User-Agent header, which Apache logs verbatim here. A
# real User-Agent string is rarely longer than ~200 chars or valid base64
# -- both together is the signal, not either alone (a long legitimate UA
# is common; valid-base64-shaped text that long in a UA field is not).
_BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/=]+$")
_MIN_SUSPICIOUS_UA_LENGTH = 200


def parse_httpaccess_vpn_log_for_payloads(content: str, *, source_path: str = "") -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        quoted_fields = re.findall(r'"([^"]*)"', line)
        if not quoted_fields:
            continue
        user_agent = quoted_fields[-1]
        if len(user_agent) >= _MIN_SUSPICIOUS_UA_LENGTH and _BASE64ISH_RE.match(user_agent.strip()):
            results.append({
                "artifact_family": "netscaler_compromise",
                "artifact_type": "httpaccess_vpn_log",
                "source_file": source_path,
                "line_number": line_number,
                "finding_type": "cve_2026_88771_payload_in_user_agent",
                "severity": "critical",
                "reasons": [f"User-Agent field is {len(user_agent)} chars of base64-shaped text -- matches the CVE-2026-88771 stage-1 dropper smuggling technique"],
                "message": "httpaccess-vpn.log: base64 payload smuggled via User-Agent",
                "raw_excerpt": line.strip()[:_MAX_RAW_EXCERPT],
            })
    return results


# --- /vpn/scripts/linux/*.deb hash check -----------------------------------

# nsg64.deb as recovered by Unit42 -- a trojanized NetScaler Gateway Plug-in
# installer serving as the CVE-2026-88772 (DTLS) web shell dropper. This
# directory legitimately ships several similarly-named stock installers
# (nsgclient*.deb, nsgsetup*.deb, ...); only an exact hash match is a
# confirmed indicator -- an unrecognized but differently-named/hashed .deb
# here is not flagged as malicious by this alone.
KNOWN_MALICIOUS_DEB_SHA256 = {
    "ae22ef2517b5c0fb47f78745b9cb5260acee0e751b89bcd354640ff8bc8d29ec": "nsg64.deb (CVE-2026-88772 DTLS web shell dropper, Unit42 2026-09-30)",
}


def check_deb_hash(data: bytes, *, source_path: str = "") -> list[dict]:
    digest = hashlib.sha256(data).hexdigest()
    label = KNOWN_MALICIOUS_DEB_SHA256.get(digest)
    if not label:
        return []
    return [{
        "artifact_family": "netscaler_compromise",
        "artifact_type": "vpn_linux_script_deb",
        "source_file": source_path,
        "finding_type": "known_malicious_deb_hash",
        "severity": "critical",
        "reasons": [f"SHA-256 matches known-malicious {label}"],
        "message": f"{source_path}: matches known-malicious {label}",
        "sha256": digest,
        "raw_excerpt": None,
    }]
