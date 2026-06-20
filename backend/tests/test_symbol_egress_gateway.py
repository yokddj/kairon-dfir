"""Unit tests for the symbol egress gateway source/redirect policy."""
from __future__ import annotations

import pytest

from app.services.memory.symbol_egress_gateway import (
    GatewayError,
    _build_initial_url,
    _validate_age,
    _validate_guid,
    _validate_host_policy,
    _validate_pdb_name,
    _validate_path,
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
