from app.api.routes_system import system_version
from app.core.config import get_settings


def test_system_version_exposes_public_beta_build_identity():
    payload = system_version()
    settings = get_settings()

    assert payload["app_version"] == settings.app_version
    assert payload["vendor_id"] == "yokddj"
    assert payload["build_channel"] == "public-beta"
    assert payload["build_fingerprint"] == "kairon-dfir-public-beta"
    assert payload["notice"] == settings.build_notice
