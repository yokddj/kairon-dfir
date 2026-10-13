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


def test_linux_isf_manual_import_accepts_real_dwarf2json_symbols_array(tmp_path: Path) -> None:
    """Regression: a genuine Volatility 3 ISF, as produced by dwarf2json (the
    tool the framework itself ships), does NOT carry a flat
    metadata.linux.kernel_release/banner/build_id string -- it carries a
    metadata.linux.symbols[]/types[] array of source-artifact descriptors
    ({kind, name, hash_type, hash_value}), where `name` looks like
    "vmlinux-6.5.0-41-generic" or "System.map-6.5.0-41-generic". Before the
    fix, every real-world Linux ISF (not just this one) was rejected as
    KERNEL_IDENTITY_UNKNOWN because only the flat fields were ever read.
    """
    isf = tmp_path / "real-dwarf2json.json"
    isf.write_text(json.dumps({
        "metadata": {
            "linux": {
                "symbols": [
                    {"kind": "kernel-image", "name": "vmlinux-6.5.0-41-generic", "hash_type": "sha256", "hash_value": "a" * 64},
                    {"kind": "map-file", "name": "System.map-6.5.0-41-generic", "hash_type": "sha256", "hash_value": "b" * 64},
                ],
                "types": [
                    {"kind": "kernel-image", "name": "vmlinux-6.5.0-41-generic", "hash_type": "sha256", "hash_value": "a" * 64},
                ],
            },
            "producer": {"name": "dwarf2json", "version": "0.7.0"},
            "format": "6.2.0",
        },
        "symbols": {},
        "types": {},
    }))

    status = import_linux_isf(isf, original_filename="real-dwarf2json.json", settings=_settings(tmp_path))

    assert status.found is True
    assert "6.5.0-41-generic" in status.identity

    # The evidence-derived required identity carries only what a real,
    # symbol-independent probe can know up front (kernel release) --
    # architecture/build_id are unknown until symbols resolve, matching
    # production's expected_identity_from_evidence() output.
    resolved = resolve_linux_symbols(
        _settings(tmp_path),
        required_identity=LinuxSymbolIdentity(kernel_release="6.5.0-41-generic"),
    )
    assert resolved.found is True
    assert resolved.valid is True
    assert resolved.compatible is True


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


# --- ISFs made by dwarf2json, banners cut short by the memory scan, newer conversions ---

FULL_BANNER = (
    "Linux version 6.5.0-41-generic (buildd@lcy02-amd64-120) (x86_64-linux-gnu-gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0, "
    "GNU ld (GNU Binutils for Ubuntu) 2.38) #41~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Mon Jun  3 11:32:55 UTC 2 (Ubuntu 6.5.0-41.41~22.04.2-generic 6.5.13)"
)


def _dwarf2json_isf(path: Path) -> Path:
    import base64

    # What dwarf2json writes: no banner or architecture in metadata, only in the symbols.
    path.write_text(json.dumps({
        "metadata": {"format": "6.2.0", "producer": {"name": "dwarf2json", "version": "0.7.0"}, "linux": {"symbols": [{"kind": "system-map", "name": "System.map-6.5.0-41-generic"}]}},
        "base_types": {"pointer": {"size": 8, "signed": False, "kind": "int", "endian": "little"}},
        "symbols": {"linux_banner": {"address": 1, "constant_data": base64.b64encode(FULL_BANNER.encode() + b"\n\0").decode()}},
        "user_types": {},
        "enums": {},
    }))
    return path


def test_a_dwarf2json_isf_matches_an_image_whose_banner_the_scan_cut_short(tmp_path: Path) -> None:
    from app.services.memory.linux_symbols import inspect_linux_isf

    identity = inspect_linux_isf(_dwarf2json_isf(tmp_path / "ubuntu.json"), settings=_settings(tmp_path))
    assert (identity.kernel_release, identity.architecture, identity.banner) == ("6.5.0-41-generic", "x64", FULL_BANNER)
    required = LinuxSymbolIdentity(architecture="x86_64", kernel_release="6.5.0-41-generic", banner=FULL_BANNER[:250])
    assert identity.compatible_with(required)
    other_build = LinuxSymbolIdentity(architecture="x64", kernel_release="6.5.0-41-generic", banner=FULL_BANNER.replace("#41~22.04.2", "#41~22.04.1"))
    assert not identity.compatible_with(other_build)
    assert not identity.compatible_with(LinuxSymbolIdentity(architecture="x86", kernel_release="6.5.0-41-generic"))


def test_a_newer_kairon_conversion_replaces_the_cached_one(tmp_path: Path) -> None:
    def converted(path: Path, version: str, marker: str) -> Path:
        path.write_text(json.dumps({
            "metadata": {"producer": {"name": "kairon-vol2-profile", "version": version}, "linux": {"kernel_release": "2.6.26-2-686", "banner": "Linux version 2.6.26-2-686", "architecture": "x86"}},
            "symbols": {"marker": {"address": 1, "note": marker}},
            "types": {},
        }))
        return path

    settings = _settings(tmp_path)
    first = import_linux_isf(converted(tmp_path / "a.json", "1", "old"), original_filename="a.json", settings=settings)
    second = import_linux_isf(converted(tmp_path / "b.json", "2", "new"), original_filename="b.json", settings=settings)
    assert second.path == first.path
    assert "new" in Path(second.path).read_text()
    with pytest.raises(LinuxSymbolError):  # an older conversion never replaces a newer one
        import_linux_isf(converted(tmp_path / "c.json", "1", "older"), original_filename="c.json", settings=settings)


def test_a_newer_conversion_removes_an_older_one_cached_under_another_key(tmp_path: Path) -> None:
    def converted(path: Path, version: str, arch: str | None) -> Path:
        linux = {"kernel_release": "2.6.26-2-686", "banner": "Linux version 2.6.26-2-686 (Debian) #1 SMP"}
        if arch:
            linux["architecture"] = arch
        path.write_text(json.dumps({"metadata": {"producer": {"name": "kairon-vol2-profile", "version": version}, "linux": linux}, "symbols": {}, "types": {}}))
        return path

    settings = _settings(tmp_path)
    old = import_linux_isf(converted(tmp_path / "a.json", "1", None), original_filename="a.json", settings=settings)
    new = import_linux_isf(converted(tmp_path / "b.json", "2", "x86"), original_filename="b.json", settings=settings)
    assert new.path != old.path
    assert not Path(old.path).exists() and Path(new.path).is_file()
