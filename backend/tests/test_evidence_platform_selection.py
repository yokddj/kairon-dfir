import pytest
from fastapi import HTTPException

from app.api.routes_evidence import _resolve_requested_platform
from app.core.evidence_platforms import build_evidence_platform_profile, build_platform_capabilities, infer_platform_from_categories
from app.models.evidence import detect_evidence_platform, resolve_evidence_platform


def test_auto_platform_resolves_to_detected_windows() -> None:
    detected = detect_evidence_platform(paths=["Windows/System32/winevt/Logs/Security.evtx"])

    provided, detected, effective = resolve_evidence_platform("auto", detected)

    assert provided == "auto"
    assert detected == "windows"
    assert effective == "windows"


def test_effective_platform_never_auto_for_unknown_detection() -> None:
    provided, detected, effective = resolve_evidence_platform(None, "unknown")

    assert provided == "auto"
    assert detected == "unknown"
    assert effective == "unknown"


def test_linux_override_is_preserved_with_limited_parser_coverage() -> None:
    provided, detected, effective = _resolve_requested_platform("linux", filename="triage.tar.gz")

    assert provided == "linux"
    assert detected == "unknown"
    assert effective == "linux"


def test_macos_direct_selection_is_rejected() -> None:
    with pytest.raises(HTTPException) as exc_info:
        _resolve_requested_platform("macos", filename="macos_artifacts.zip")

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "macOS artifacts are not supported yet"


def test_memory_evidence_resolves_to_memory_platform() -> None:
    detected = detect_evidence_platform(filename="memory.lime", evidence_type="memory_dump")

    provided, detected, effective = resolve_evidence_platform("linux", detected, evidence_type="memory_dump")

    assert provided == "linux"
    assert detected == "memory"
    assert effective == "memory"


def test_mixed_collection_detection_and_profile_grouping() -> None:
    detected = detect_evidence_platform(paths=["Windows/System32/winevt/Logs/Security.evtx", "etc/passwd"])

    assert detected == "mixed"
    assert infer_platform_from_categories(["evtx", "linux_auth"]) == "mixed"

    profile = build_evidence_platform_profile("mixed", available_categories=["evtx", "linux_auth", "linux_journal"])

    assert profile["platform"] == "mixed"
    assert profile["platforms"] == ["windows", "linux"]
    assert any(group["platform"] == "windows" for group in profile["groups"])
    assert any(group["platform"] == "linux" for group in profile["groups"])


def test_linux_collection_users_directory_does_not_false_positive_to_macos() -> None:
    detected = detect_evidence_platform(paths=["filesystem/etc/passwd", "users/getent-passwd.txt", "logs/journal.export"])

    assert detected == "linux"


def test_platform_capabilities_are_aggregated_from_registry() -> None:
    capabilities = build_platform_capabilities(["linux", "memory"])

    assert capabilities["supportsJournal"] is True
    assert capabilities["supportsPackages"] is True
    assert capabilities["supportsMemory"] is True
    assert capabilities["supportsRegistry"] is True


def test_platform_profile_exposes_capabilities_and_artifact_metadata() -> None:
    profile = build_evidence_platform_profile("linux", available_categories=["linux_journal", "linux_auth", "linux_systemd"])

    assert profile["capabilities"]["supportsJournal"] is True
    assert profile["capabilities"]["supportsPersistence"] is True
    assert any(artifact["id"] == "linux_journal" for artifact in profile["artifacts"])
    assert any(group["id"] == "linux_logs" for group in profile["groups"])
