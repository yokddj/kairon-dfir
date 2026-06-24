"""Unit tests for the symbol egress gateway source/redirect policy."""
from __future__ import annotations

import pytest

from app.services.memory.symbol_egress_gateway import (
    APPROVED_INITIAL_HOST,
    APPROVED_INITIAL_PATH_PREFIX,
    APPROVED_METHODS,
    APPROVED_REDIRECT_SUFFIXES,
    DEFAULT_MAX_REDIRECTS,
    GatewayError,
    GatewaySettings,
    _build_initial_url,
    _validate_age,
    _validate_guid,
    _validate_host_policy,
    _validate_pdb_name,
    _validate_path,
    _validate_path_prefix,
    _validate_request_id,
)


def test_initial_url_matches_documented_pattern() -> None:
    url = _build_initial_url("ntkrnlmp.pdb", "9DC3FC69B1CA4B34707EBC57FD1D6126", 1, "msdl.microsoft.com")
    assert url == "https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/9DC3FC69B1CA4B34707EBC57FD1D61261/ntkrnlmp.pdb"


def test_validate_pdb_name_rejects_traversal() -> None:
    with pytest.raises(GatewayError):
        _validate_pdb_name("../kernel.pdb")
    with pytest.raises(GatewayError):
        _validate_pdb_name("ntdll.pdb%00.exe")


def test_validate_guid_normalizes() -> None:
    assert _validate_guid("9dc3fc69b1ca4b34707ebc57fd1d6126") == "9DC3FC69B1CA4B34707EBC57FD1D6126"
    with pytest.raises(GatewayError):
        _validate_guid("not-a-guid")


def test_validate_age_bounds() -> None:
    assert _validate_age(1) == 1
    assert _validate_age(0) == 0
    with pytest.raises(GatewayError):
        _validate_age(-1)
    with pytest.raises(GatewayError):
        _validate_age(0x100000000)


def test_validate_request_id_must_be_uuid() -> None:
    assert _validate_request_id("11111111-1111-4111-8111-111111111111").startswith("11111111-")
    with pytest.raises(GatewayError):
        _validate_request_id("not-a-uuid")


def test_validate_path_rejects_control_chars() -> None:
    assert _validate_path("/normal/path") == "/normal/path"
    with pytest.raises(GatewayError):
        _validate_path("/path\nwith\ncontrol")
    with pytest.raises(GatewayError):
        _validate_path("c:\\windows\\system32")


def test_validate_path_rejects_traversal_segments() -> None:
    # Plain ".." segment.
    with pytest.raises(GatewayError):
        _validate_path("/download/symbols/../etc/passwd")
    # Percent-encoded "..".
    with pytest.raises(GatewayError):
        _validate_path("/download/symbols/%2e%2e/secret")
    # Mixed-case percent encoding.
    with pytest.raises(GatewayError):
        _validate_path("/download/symbols/%2E%2E/secret")
    with pytest.raises(GatewayError):
        _validate_path("/download/symbols/%2e%2E/secret")


def test_validate_path_prefix_accepts_official_prefix() -> None:
    assert _validate_path_prefix("/download/symbols/ntkrnlmp.pdb", expected_prefix=APPROVED_INITIAL_PATH_PREFIX) == "/download/symbols/ntkrnlmp.pdb"
    assert _validate_path_prefix("/download/symbols/", expected_prefix=APPROVED_INITIAL_PATH_PREFIX) == "/download/symbols/"


def test_validate_path_prefix_rejects_other_paths() -> None:
    with pytest.raises(GatewayError):
        _validate_path_prefix("/", expected_prefix=APPROVED_INITIAL_PATH_PREFIX)
    with pytest.raises(GatewayError):
        _validate_path_prefix("/download/symbols", expected_prefix=APPROVED_INITIAL_PATH_PREFIX)
    with pytest.raises(GatewayError):
        _validate_path_prefix("/download/other/file", expected_prefix=APPROVED_INITIAL_PATH_PREFIX)
    with pytest.raises(GatewayError):
        _validate_path_prefix("/etc/passwd", expected_prefix=APPROVED_INITIAL_PATH_PREFIX)


def test_validate_path_prefix_rejects_traversal() -> None:
    with pytest.raises(GatewayError):
        _validate_path_prefix("/download/symbols/../etc/passwd", expected_prefix=APPROVED_INITIAL_PATH_PREFIX)


def test_host_policy_initial_only_msdl() -> None:
    _validate_host_policy("msdl.microsoft.com", initial=True, initial_host="msdl.microsoft.com", redirect_suffixes=[".blob.core.windows.net"])
    with pytest.raises(GatewayError):
        _validate_host_policy("msdl.microsoft.com.attacker.example", initial=True, initial_host="msdl.microsoft.com", redirect_suffixes=[".blob.core.windows.net"])


def test_host_policy_redirect_accepts_only_blob_subdomain() -> None:
    _validate_host_policy("a.b.blob.core.windows.net", initial=False, initial_host="msdl.microsoft.com", redirect_suffixes=[".blob.core.windows.net"])
    _validate_host_policy("symbols123.blob.core.windows.net", initial=False, initial_host="msdl.microsoft.com", redirect_suffixes=[".blob.core.windows.net"])
    with pytest.raises(GatewayError):
        _validate_host_policy("blob.core.windows.net", initial=False, initial_host="msdl.microsoft.com", redirect_suffixes=[".blob.core.windows.net"])
    with pytest.raises(GatewayError):
        _validate_host_policy("evilblob.core.windows.net", initial=False, initial_host="msdl.microsoft.com", redirect_suffixes=[".blob.core.windows.net"])
    with pytest.raises(GatewayError):
        _validate_host_policy("x.blob.core.windows.net.attacker.example", initial=False, initial_host="msdl.microsoft.com", redirect_suffixes=[".blob.core.windows.net"])
    with pytest.raises(GatewayError):
        _validate_host_policy("msdl.microsoft.com.attacker.example", initial=False, initial_host="msdl.microsoft.com", redirect_suffixes=[".blob.core.windows.net"])


def test_host_policy_does_not_match_substring() -> None:
    # exact label parsing, not substring.
    with pytest.raises(GatewayError):
        _validate_host_policy("notblob.core.windows.net", initial=False, initial_host="msdl.microsoft.com", redirect_suffixes=[".blob.core.windows.net"])


# ---------------------------------------------------------------------------
# Least-privilege policy constants
# ---------------------------------------------------------------------------


def test_policy_constants_are_exact() -> None:
    assert APPROVED_INITIAL_HOST == "msdl.microsoft.com"
    assert APPROVED_INITIAL_PATH_PREFIX == "/download/symbols/"
    assert APPROVED_METHODS == frozenset({"GET"})
    assert APPROVED_REDIRECT_SUFFIXES == frozenset({".blob.core.windows.net"})
    assert DEFAULT_MAX_REDIRECTS == 5


def test_host_policy_rejects_foo_microsoft_com() -> None:
    # No wildcard *.microsoft.com is allowed.
    with pytest.raises(GatewayError):
        _validate_host_policy("foo.microsoft.com", initial=True, initial_host="msdl.microsoft.com", redirect_suffixes=[".blob.core.windows.net"])


def test_host_policy_rejects_evilmsdl_microsoft_com() -> None:
    # Lookalike "evilmsdl.microsoft.com" must not be allowed.
    with pytest.raises(GatewayError):
        _validate_host_policy("evilmsdl.microsoft.com", initial=True, initial_host="msdl.microsoft.com", redirect_suffixes=[".blob.core.windows.net"])


def test_host_policy_rejects_ip_literal_initial() -> None:
    # IP literals are rejected at the URL layer; host policy still
    # rejects an exact IP literal as initial.
    with pytest.raises(GatewayError):
        _validate_host_policy("13.107.42.14", initial=True, initial_host="msdl.microsoft.com", redirect_suffixes=[".blob.core.windows.net"])


# ---------------------------------------------------------------------------
# GatewaySettings hardening
# ---------------------------------------------------------------------------


def test_settings_refuse_unapproved_initial_host(monkeypatch) -> None:
    monkeypatch.setenv("MEMORY_SYMBOL_EGRESS_GATEWAY_SECRET", "test-secret-1234")
    monkeypatch.setenv("MEMORY_SYMBOL_INITIAL_HOST", "attacker.example")
    with pytest.raises(RuntimeError, match="not the approved Microsoft symbol server"):
        GatewaySettings()


def test_settings_refuse_unapproved_path_prefix(monkeypatch) -> None:
    monkeypatch.setenv("MEMORY_SYMBOL_EGRESS_GATEWAY_SECRET", "test-secret-1234")
    monkeypatch.setenv("MEMORY_SYMBOL_INITIAL_PATH", "/admin/secrets")
    with pytest.raises(RuntimeError, match="not the approved /download/symbols/ prefix"):
        GatewaySettings()


def test_settings_refuse_unapproved_redirect_suffix(monkeypatch) -> None:
    monkeypatch.setenv("MEMORY_SYMBOL_EGRESS_GATEWAY_SECRET", "test-secret-1234")
    monkeypatch.setenv("MEMORY_SYMBOL_REDIRECT_SUFFIXES", ".blob.core.windows.net,.attacker.example")
    with pytest.raises(RuntimeError, match="not in the approved redirect allowlist"):
        GatewaySettings()


def test_settings_refuse_excessive_redirect_cap(monkeypatch) -> None:
    monkeypatch.setenv("MEMORY_SYMBOL_EGRESS_GATEWAY_SECRET", "test-secret-1234")
    monkeypatch.setenv("MEMORY_SYMBOL_MAX_REDIRECTS", "50")
    with pytest.raises(RuntimeError, match="outside the allowed range"):
        GatewaySettings()


def test_settings_accept_defaults(monkeypatch) -> None:
    monkeypatch.setenv("MEMORY_SYMBOL_EGRESS_GATEWAY_SECRET", "test-secret-1234")
    settings = GatewaySettings()
    assert settings.initial_host == "msdl.microsoft.com"
    assert settings.path_prefix == "/download/symbols/"
    assert settings.redirect_suffixes == [".blob.core.windows.net"]
    assert settings.max_redirects == 5
