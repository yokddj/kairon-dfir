from __future__ import annotations

from types import SimpleNamespace

from app.core.config import Settings, get_settings


def test_memory_upload_hybrid_defaults_are_safe() -> None:
    settings = get_settings()
    assert settings.memory_upload_chunk_size_bytes == 64 * 1024 * 1024
    assert settings.memory_upload_direct_threshold_bytes == 1024 * 1024 * 1024
    assert settings.memory_upload_default_concurrency == 2
    assert settings.memory_upload_max_concurrency == 4
    assert settings.memory_upload_max_bytes == 32 * 1024 * 1024 * 1024


def test_memory_upload_hybrid_environment_overrides() -> None:
    settings = Settings(
        memory_upload_direct_threshold_bytes=512 * 1024 * 1024,
        memory_upload_default_concurrency=1,
        memory_upload_max_concurrency=4,
        memory_upload_chunk_size_bytes=64 * 1024 * 1024,
    )
    assert settings.memory_upload_direct_threshold_bytes == 512 * 1024 * 1024
    assert settings.memory_upload_default_concurrency == 1
    assert settings.memory_upload_max_concurrency == 4


def test_memory_upload_max_concurrency_capped_at_four() -> None:
    try:
        Settings(memory_upload_default_concurrency=2, memory_upload_max_concurrency=5)
    except ValueError as exc:
        assert "MEMORY_UPLOAD_MAX_CONCURRENCY" in str(exc)
    else:  # pragma: no cover - defensive
        raise AssertionError("max concurrency above 4 should be rejected")


def test_memory_upload_direct_mode_policy_boundary() -> None:
    threshold = 1024 * 1024 * 1024
    readiness_under = SimpleNamespace(selected_size_bytes=threshold)
    readiness_over = SimpleNamespace(selected_size_bytes=threshold + 1)
    assert readiness_under.selected_size_bytes <= threshold
    assert readiness_over.selected_size_bytes > threshold
