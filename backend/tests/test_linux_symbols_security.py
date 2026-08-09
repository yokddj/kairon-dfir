"""Security regression coverage for app.services.memory.linux_symbols.

Phase 3 gap #1 (decompressed .xz size bomb) and gap #2 (unbounded
validation time) identified before exposing Linux ISF upload to
non-admin users. These tests exercise the real parsing/validation code
path (inspect_linux_isf / import_linux_isf / _load_isf), not mocks of
it, and assert the Windows symbol pipeline is untouched.
"""
from __future__ import annotations

import lzma
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.memory.linux_symbols import (
    LinuxSymbolError,
    import_linux_isf,
    inspect_linux_isf,
)

VALID_ISF_JSON = (
    b'{"metadata":{"linux":{"kernel_release":"6.8.0-test","architecture":"x64","build_id":"build-a"}},'
    b'"symbols":{},"types":{}}'
)


def _settings(
    cache_root: Path,
    *,
    max_bytes: int = 8 * 1024 * 1024,
    decompressed_max_bytes: int = 4 * 1024 * 1024,
    timeout_seconds: int = 30,
) -> SimpleNamespace:
    return SimpleNamespace(
        memory_native_probe_cache_path=cache_root,
        memory_linux_symbol_manual_import_enabled=True,
        memory_linux_symbol_isf_upload_max_bytes=max_bytes,
        memory_linux_symbol_isf_decompressed_max_bytes=decompressed_max_bytes,
        memory_linux_symbol_validation_timeout_seconds=timeout_seconds,
    )


def _cache_dir(tmp_path: Path) -> Path:
    root = tmp_path / "volatility-cache"
    linux_dir = root / "symbols" / "linux"
    linux_dir.mkdir(parents=True)
    return root


def _write(tmp_path: Path, name: str, content: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


def _xz_bytes(raw: bytes) -> bytes:
    return lzma.compress(raw, preset=9)


class TestDecompressedSizeLimit:
    def test_small_xz_that_expands_past_the_limit_is_rejected(self, tmp_path: Path) -> None:
        # 20 MB of highly compressible zero bytes shrinks to a tiny .xz --
        # a classic decompression-bomb shape. The limit is 4 MB decompressed.
        bomb_raw = b"\x00" * (20 * 1024 * 1024)
        compressed = _xz_bytes(bomb_raw)
        assert len(compressed) < 100 * 1024  # confirms this really is a small file on disk
        source = _write(tmp_path, "bomb.json.xz", compressed)
        settings = _settings(_cache_dir(tmp_path), decompressed_max_bytes=4 * 1024 * 1024)

        with pytest.raises(LinuxSymbolError) as exc_info:
            inspect_linux_isf(source, settings=settings)
        assert exc_info.value.code == "SYMBOL_IMPORT_REJECTED"
        assert "decompressed" in exc_info.value.message.lower()

    def test_bomb_via_import_linux_isf_never_writes_to_cache(self, tmp_path: Path) -> None:
        bomb_raw = b"\x00" * (20 * 1024 * 1024)
        compressed = _xz_bytes(bomb_raw)
        source = _write(tmp_path, "bomb.json.xz", compressed)
        cache_root = _cache_dir(tmp_path)
        settings = _settings(cache_root, decompressed_max_bytes=4 * 1024 * 1024)

        with pytest.raises(LinuxSymbolError):
            import_linux_isf(source, original_filename="bomb.json.xz", settings=settings)

        linux_cache = cache_root / "symbols" / "linux"
        assert list(linux_cache.iterdir()) == []

    def test_valid_xz_within_the_decompressed_limit_is_accepted(self, tmp_path: Path) -> None:
        compressed = _xz_bytes(VALID_ISF_JSON)
        source = _write(tmp_path, "kernel.json.xz", compressed)
        settings = _settings(_cache_dir(tmp_path), decompressed_max_bytes=4 * 1024 * 1024)

        identity = inspect_linux_isf(source, settings=settings)

        assert identity.kernel_release == "6.8.0-test"
        assert identity.architecture == "x64"

    def test_valid_xz_promotes_and_is_selectable(self, tmp_path: Path) -> None:
        compressed = _xz_bytes(VALID_ISF_JSON)
        source = _write(tmp_path, "kernel.json.xz", compressed)
        cache_root = _cache_dir(tmp_path)
        settings = _settings(cache_root, decompressed_max_bytes=4 * 1024 * 1024)

        status = import_linux_isf(source, original_filename="kernel.json.xz", settings=settings)

        assert status.valid is True
        assert status.path is not None
        assert Path(status.path).exists()
        assert Path(status.path).name.endswith(".json.xz")

    def test_plain_json_is_unaffected_by_the_decompressed_limit(self, tmp_path: Path) -> None:
        # Non-.xz uploads are already fully bounded by the compressed-size
        # check (same bytes on disk and in memory) -- confirm the new
        # decompressed-limit code path does not accidentally engage here.
        source = _write(tmp_path, "kernel.json", VALID_ISF_JSON)
        settings = _settings(_cache_dir(tmp_path), decompressed_max_bytes=8)  # absurdly low, must not apply

        identity = inspect_linux_isf(source, settings=settings)
        assert identity.kernel_release == "6.8.0-test"


class TestNoInternalTimeout:
    """inspect_linux_isf() deliberately has NO internal wall-clock timeout
    of its own anymore -- a thread-based timeout only stopped the
    *caller* from waiting while the work kept running in the background,
    which is not a real resource bound. The real, enforceable timeout now
    lives one layer up, at the OS process boundary: see
    test_subprocess_isolation.py for the genuine-kill test, and
    test_linux_symbol_evidence.py::TestWorkerTimeout for the worker task
    that runs inspect_linux_isf() inside that isolated subprocess.
    """

    def test_inspect_linux_isf_has_no_timeout_parameter(self, tmp_path: Path) -> None:
        import inspect as py_inspect

        signature = py_inspect.signature(inspect_linux_isf)
        assert "timeout_seconds" not in signature.parameters

    def test_a_slow_but_finite_validation_still_succeeds(self, tmp_path: Path) -> None:
        source = _write(tmp_path, "kernel.json", VALID_ISF_JSON)
        settings = _settings(_cache_dir(tmp_path))

        identity = inspect_linux_isf(source, settings=settings)
        assert identity.kernel_release == "6.8.0-test"


class TestNoPartialOrPromotedFileAfterFailure:
    @pytest.mark.parametrize(
        "content,filename",
        [
            (b"not json at all", "broken.json"),
            (b'{"metadata": {}}', "no-linux-block.json"),
            (b'{"metadata": {"linux": {}}}', "no-symbol-tables.json"),
            (b'{"metadata": {"linux": {"platform": "windows"}}, "symbols": {}}', "wrong-platform.json"),
            (b"", "empty.json"),
        ],
    )
    def test_every_rejection_reason_leaves_the_cache_directory_empty(
        self, tmp_path: Path, content: bytes, filename: str
    ) -> None:
        source = _write(tmp_path, filename, content)
        cache_root = _cache_dir(tmp_path)
        settings = _settings(cache_root)

        with pytest.raises(LinuxSymbolError):
            import_linux_isf(source, original_filename=filename, settings=settings)

        linux_cache = cache_root / "symbols" / "linux"
        assert list(linux_cache.iterdir()) == [], f"cache polluted after rejecting {filename}"

    def test_no_tmp_files_survive_a_rejected_upload(self, tmp_path: Path) -> None:
        source = _write(tmp_path, "broken.json", b"not json")
        cache_root = _cache_dir(tmp_path)
        settings = _settings(cache_root)

        with pytest.raises(LinuxSymbolError):
            import_linux_isf(source, original_filename="broken.json", settings=settings)

        linux_cache = cache_root / "symbols" / "linux"
        assert not any(p.name.startswith(".") for p in linux_cache.iterdir())


class TestErrorCodeTaxonomy:
    """Pin the classification each raise site now uses -- Phase 3's
    evidence-scoped endpoint maps these onto VALID/INVALID/UNSUPPORTED/
    VALIDATION_FAILED, so a silent code rename here would silently break
    that mapping."""

    def test_malformed_json_is_parse_failed(self, tmp_path: Path) -> None:
        source = _write(tmp_path, "broken.json", b"{not json")
        with pytest.raises(LinuxSymbolError) as exc_info:
            inspect_linux_isf(source, settings=_settings(_cache_dir(tmp_path)))
        assert exc_info.value.code == "SYMBOL_PARSE_FAILED"

    def test_non_linux_platform_is_unsupported_platform(self, tmp_path: Path) -> None:
        source = _write(
            tmp_path,
            "windows.json",
            b'{"metadata": {"linux": {"platform": "windows", "kernel_release": "x"}}, "symbols": {}}',
        )
        with pytest.raises(LinuxSymbolError) as exc_info:
            inspect_linux_isf(source, settings=_settings(_cache_dir(tmp_path)))
        assert exc_info.value.code == "SYMBOL_UNSUPPORTED_PLATFORM"

    def test_missing_symbol_tables_is_unsupported_format(self, tmp_path: Path) -> None:
        source = _write(
            tmp_path,
            "no-tables.json",
            b'{"metadata": {"linux": {"kernel_release": "6.8.0-test"}}}',
        )
        with pytest.raises(LinuxSymbolError) as exc_info:
            inspect_linux_isf(source, settings=_settings(_cache_dir(tmp_path)))
        assert exc_info.value.code == "SYMBOL_UNSUPPORTED_FORMAT"

    def test_no_kernel_identity_is_kernel_identity_unknown(self, tmp_path: Path) -> None:
        source = _write(
            tmp_path,
            "no-identity.json",
            b'{"metadata": {"linux": {}}, "symbols": {}}',
        )
        with pytest.raises(LinuxSymbolError) as exc_info:
            inspect_linux_isf(source, settings=_settings(_cache_dir(tmp_path)))
        assert exc_info.value.code == "KERNEL_IDENTITY_UNKNOWN"


class TestWindowsPipelineUnaffected:
    def test_linux_symbols_module_imports_no_windows_symbol_modules(self) -> None:
        import ast

        import app.services.memory.linux_symbols as module

        source = Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        windows_symbol_modules = {
            "app.services.memory.symbol_control",
            "app.services.memory.symbol_preparation",
            "app.services.memory.symbol_resolver",
            "app.services.memory.symbol_fetcher",
        }
        assert not (imported & windows_symbol_modules)
