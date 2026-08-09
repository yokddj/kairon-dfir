from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.services.memory.linux_symbols import (
    LinuxSymbolError,
    LinuxSymbolIdentity,
    import_linux_isf,
    resolve_linux_symbols,
)


class _Settings(SimpleNamespace):
    @property
    def memory_symbol_import_quarantine_path(self) -> Path:
        return Path(self.backend_temp_dir) / "symbol-import-quarantine"


class _Admin:
    id = "admin-1"
    is_admin = True


class _Analyst:
    id = "analyst-1"
    is_admin = False


def _settings(tmp_path: Path, *, enabled: bool = True) -> SimpleNamespace:
    return _Settings(
        memory_linux_symbol_cache_root=str(tmp_path / "symbols" / "linux"),
        memory_linux_symbol_manual_import_enabled=enabled,
        memory_linux_symbol_isf_upload_max_bytes=1024 * 1024,
        backend_temp_dir=tmp_path / "tmp",
    )


def _write_isf(path: Path, *, release: str = "6.8.2-test", arch: str = "x64", build_id: str = "build-a") -> Path:
    path.write_text(json.dumps({
        "metadata": {
            "linux": {
                "kernel_release": release,
                "banner": f"Linux version {release}",
                "architecture": arch,
                "build_id": build_id,
            }
        },
        "symbols": {},
        "types": {},
    }))
    return path


def _required(release: str = "6.8.2-test", arch: str = "x64", build_id: str = "build-a") -> LinuxSymbolIdentity:
    return LinuxSymbolIdentity(architecture=arch, kernel_release=release, build_id=build_id)


def test_linux_isf_manual_import_validates_and_promotes(tmp_path: Path) -> None:
    isf = tmp_path / "kernel.json"
    _write_isf(isf)

    status = import_linux_isf(
        isf,
        original_filename="kernel.json",
        settings=_settings(tmp_path),
    )

    assert status.found is True
    assert status.identity == "linux | x64 | 6.8.2-test | build:build-a | Linux version 6.8.2-test"
    assert status.source == "manual_upload"
    assert status.sha256 is not None
    assert status.path is not None
    assert Path(status.path).is_file()

    resolved = resolve_linux_symbols(_settings(tmp_path), required_identity=_required())
    assert resolved.found is True
    assert resolved.valid is True
    assert resolved.compatible is True
    assert resolved.volatility_selectable is True
    assert resolved.identity == status.identity


def test_linux_isf_manual_import_rejects_non_linux_identity(tmp_path: Path) -> None:
    isf = tmp_path / "not-linux.json"
    isf.write_text(json.dumps({"metadata": {"windows": {"pdb": {"GUID": "A", "age": 1}}}}))

    with pytest.raises(LinuxSymbolError) as excinfo:
        import_linux_isf(isf, original_filename="not-linux.json", settings=_settings(tmp_path))

    assert excinfo.value.code == "KERNEL_IDENTITY_UNKNOWN"


def test_linux_isf_manual_import_obeys_feature_gate(tmp_path: Path) -> None:
    isf = tmp_path / "kernel.json"
    _write_isf(isf)

    with pytest.raises(LinuxSymbolError) as excinfo:
        import_linux_isf(isf, original_filename="kernel.json", settings=_settings(tmp_path, enabled=False))

    assert excinfo.value.code == "SYMBOL_MANUAL_IMPORT_DISABLED"


def test_linux_isf_rejects_invalid_json(tmp_path: Path) -> None:
    isf = tmp_path / "bad.json"
    isf.write_text("not-json")

    with pytest.raises(LinuxSymbolError) as excinfo:
        import_linux_isf(isf, original_filename="bad.json", settings=_settings(tmp_path))

    assert excinfo.value.code == "SYMBOL_PARSE_FAILED"


def test_linux_isf_rejects_invalid_structure(tmp_path: Path) -> None:
    isf = tmp_path / "bad.json"
    isf.write_text(json.dumps({"metadata": {"linux": {"kernel_release": "6.8"}}}))

    with pytest.raises(LinuxSymbolError) as excinfo:
        import_linux_isf(isf, original_filename="bad.json", settings=_settings(tmp_path))

    assert excinfo.value.code == "SYMBOL_UNSUPPORTED_FORMAT"


def test_linux_isf_duplicate_returns_existing_without_overwrite(tmp_path: Path) -> None:
    isf = _write_isf(tmp_path / "kernel.json")
    first = import_linux_isf(isf, original_filename="kernel.json", settings=_settings(tmp_path))
    second = import_linux_isf(isf, original_filename="kernel.json", settings=_settings(tmp_path))

    assert second.duplicate is True
    assert second.path == first.path
    assert second.sha256 == first.sha256


def test_linux_isf_collision_is_rejected(tmp_path: Path) -> None:
    first = _write_isf(tmp_path / "kernel-a.json")
    second = _write_isf(tmp_path / "kernel-b.json")
    second.write_text(second.read_text() + "\n")
    import_linux_isf(first, original_filename="kernel-a.json", settings=_settings(tmp_path))

    with pytest.raises(LinuxSymbolError) as excinfo:
        import_linux_isf(second, original_filename="kernel-b.json", settings=_settings(tmp_path))

    assert excinfo.value.code == "SYMBOL_CACHE_COLLISION"


def test_linux_isf_symlink_upload_rejected(tmp_path: Path) -> None:
    target = _write_isf(tmp_path / "target.json")
    link = tmp_path / "link.json"
    os.symlink(target, link)

    with pytest.raises(LinuxSymbolError) as excinfo:
        import_linux_isf(link, original_filename="link.json", settings=_settings(tmp_path))

    assert excinfo.value.code == "SYMBOL_IMPORT_REJECTED"


def test_linux_isf_size_limit_rejected(tmp_path: Path) -> None:
    isf = _write_isf(tmp_path / "kernel.json")
    settings = _settings(tmp_path)
    settings.memory_linux_symbol_isf_upload_max_bytes = 1

    with pytest.raises(LinuxSymbolError) as excinfo:
        import_linux_isf(isf, original_filename="kernel.json", settings=settings)

    assert excinfo.value.code == "SYMBOL_IMPORT_REJECTED"


def test_linux_isf_incompatible_cache_does_not_satisfy_readiness(tmp_path: Path) -> None:
    isf = _write_isf(tmp_path / "kernel.json", release="6.8.2-test")
    import_linux_isf(isf, original_filename="kernel.json", settings=_settings(tmp_path))

    resolved = resolve_linux_symbols(_settings(tmp_path), required_identity=_required(release="5.15.0-test"))

    assert resolved.found is True
    assert resolved.valid is True
    assert resolved.compatible is False
    assert resolved.reason_code == "symbols_incompatible"


def test_linux_isf_empty_cache_with_unknown_identity_reports_kernel_unknown(tmp_path: Path) -> None:
    resolved = resolve_linux_symbols(_settings(tmp_path), required_identity=None)

    assert resolved.reason_code == "kernel_identity_unknown"


def _linux_symbol_endpoint_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, user: object | None) -> TestClient:
    from app.api import routes_memory_recovery
    from app.services import auth_dependencies

    app = FastAPI()
    app.include_router(routes_memory_recovery.router)
    settings = _settings(tmp_path, enabled=True)
    monkeypatch.setattr(routes_memory_recovery, "get_settings", lambda: settings)
    app.dependency_overrides[routes_memory_recovery.require_admin_recovery_enabled] = lambda: None

    def _override_admin():
        if user is None:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if not getattr(user, "is_admin", False):
            raise HTTPException(status_code=403, detail="Admin required")
        return user

    app.dependency_overrides[auth_dependencies.require_admin] = _override_admin
    app.dependency_overrides[routes_memory_recovery.require_admin] = _override_admin
    return TestClient(app)


def test_linux_import_endpoint_rejects_unauthenticated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _linux_symbol_endpoint_client(tmp_path, monkeypatch, user=None)

    response = client.post("/api/admin/memory/symbols/linux/import-isf", files={"file": ("kernel.json", b"{}", "application/json")})

    assert response.status_code == 401


def test_linux_import_endpoint_rejects_non_admin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _linux_symbol_endpoint_client(tmp_path, monkeypatch, user=_Analyst())

    response = client.post("/api/admin/memory/symbols/linux/import-isf", files={"file": ("kernel.json", b"{}", "application/json")})

    assert response.status_code == 403


def test_linux_import_endpoint_accepts_admin_valid_upload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _linux_symbol_endpoint_client(tmp_path, monkeypatch, user=_Admin())
    payload = json.dumps({
        "metadata": {"linux": {"kernel_release": "6.8.2-test", "architecture": "x64", "build_id": "build-a"}},
        "symbols": {},
        "types": {},
    }).encode()

    response = client.post("/api/admin/memory/symbols/linux/import-isf", files={"file": ("kernel.json", payload, "application/json")})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert "6.8.2-test" in body["symbol_identity"]


def test_linux_import_endpoint_returns_typed_error_for_invalid_upload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _linux_symbol_endpoint_client(tmp_path, monkeypatch, user=_Admin())

    response = client.post("/api/admin/memory/symbols/linux/import-isf", files={"file": ("bad.json", b"not-json", "application/json")})

    assert response.status_code == 400
    assert response.json()["detail"]["error_code"] == "SYMBOL_PARSE_FAILED"
