"""Tests for the fixed windows.info normalizer."""
from __future__ import annotations

from app.services.memory import normalizers as norm


def _payload() -> list[dict]:
    return [
        {"Variable": "Kernel Base", "Value": "0xf8077da00000", "__children": []},
        {"Variable": "DTB", "Value": "0x1ae000", "__children": []},
        {
            "Variable": "Symbols",
            "Value": "file:///volatility-cache/volatility3/symbols/windows/ntkrnlmp.pdb/9DC3FC69B1CA4B34707EBC57FD1D6126-1.json.xz",
            "__children": [],
        },
        {"Variable": "Is64Bit", "Value": "True", "__children": []},
        {"Variable": "layer_name", "Value": "0 WindowsIntel32e", "__children": []},
        {"Variable": "memory_layer", "Value": "1 WindowsCrashDump64Layer", "__children": []},
        {"Variable": "base_layer", "Value": "2 FileLayer", "__children": []},
        {"Variable": "KdVersionBlock", "Value": "0xf8077e6099b0", "__children": []},
        {"Variable": "Major/Minor", "Value": "15.22621", "__children": []},
        {"Variable": "MachineType", "Value": "34404", "__children": []},
        {"Variable": "SystemTime", "Value": "2024-03-22 12:59:20+00:00", "__children": []},
        {"Variable": "NtMajorVersion", "Value": "10", "__children": []},
        {"Variable": "NtMinorVersion", "Value": "0", "__children": []},
        {"Variable": "NtProductType", "Value": "NtProductWinNt", "__children": []},
        {"Variable": "KeNumberProcessors", "Value": "4", "__children": []},
    ]


def test_normalize_extracts_os_fields() -> None:
    result = norm.normalize_windows_info(
        _payload(),
        case_id="c",
        evidence_id="e",
        memory_run_id="r",
        memory_plugin_run_id="pr",
        backend_version="2.28.0",
    )
    os = result["os"]
    assert os["family"] == "windows"
    assert os["windows_build"] == "22621"
    assert os["kernel_version"] == "10.0.22621"
    assert os["machine_type"] == "x64"
    assert os["nt_major_version"] == 10
    assert os["nt_minor_version"] == 0
    assert os["ke_number_processors"] == 4


def test_normalize_does_not_use_volatility_version_as_build() -> None:
    result = norm.normalize_windows_info(
        _payload(),
        case_id="c",
        evidence_id="e",
        memory_run_id="r",
        memory_plugin_run_id="pr",
        backend_version="Volatility 3 Framework 2.28.0",
    )
    # The Volatility version must not appear in the Windows build field.
    assert result["os"]["windows_build"] == "22621"
    assert "Volatility" not in (result["os"]["windows_build"] or "")
    # The Volatility version is captured separately as raw data.
    assert result["raw"]["backend_version"] == "Volatility 3 Framework 2.28.0"


def test_normalize_extracts_memory_fields() -> None:
    result = norm.normalize_windows_info(
        _payload(),
        case_id="c",
        evidence_id="e",
        memory_run_id="r",
        memory_plugin_run_id="pr",
        backend_version="2.28.0",
    )
    memory = result["memory"]
    assert memory["layer_name"] == "WindowsCrashDump64Layer"
    assert memory["dtb"] == "0x1ae000"
    assert memory["is_64_bit"] is True
    assert memory["system_time"] == "2024-03-22 12:59:20+00:00"
    # The symbol table should show the GUID without the file:// path noise.
    assert memory["kernel_symbols"] is not None
    assert "9DC3FC69B1CA4B34707EBC57FD1D6126-1" in memory["kernel_symbols"]


def test_normalize_handles_empty_payload() -> None:
    result = norm.normalize_windows_info(
        [],
        case_id="c",
        evidence_id="e",
        memory_run_id="r",
        memory_plugin_run_id="pr",
        backend_version="2.28.0",
    )
    assert result["os"]["family"] == "windows"
    assert result["os"]["windows_build"] is None
    assert result["memory"]["layer_name"] is None


def test_normalize_handles_missing_major_minor() -> None:
    payload = [
        {"Variable": "Kernel Base", "Value": "0xabc", "__children": []},
        {"Variable": "NtMajorVersion", "Value": "10", "__children": []},
        {"Variable": "NtMinorVersion", "Value": "0", "__children": []},
    ]
    result = norm.normalize_windows_info(
        payload,
        case_id="c",
        evidence_id="e",
        memory_run_id="r",
        memory_plugin_run_id="pr",
        backend_version="2.28.0",
    )
    assert result["os"]["windows_build"] == "10.0"
    assert result["os"]["kernel_version"] == "10.0.10.0"


def test_normalize_architecture_arm64() -> None:
    payload = [
        {"Variable": "MachineType", "Value": str(43620), "__children": []},
    ]
    result = norm.normalize_windows_info(
        payload,
        case_id="c",
        evidence_id="e",
        memory_run_id="r",
        memory_plugin_run_id="pr",
        backend_version="2.28.0",
    )
    assert result["os"]["machine_type"] == "ARM64"
