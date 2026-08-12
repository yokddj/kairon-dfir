"""Tests for the fixed windows.info normalizer."""
from __future__ import annotations

from app.ingest.host_facts_extraction import extract_host_fact_documents
from app.ingest.windows.memory_host_facts import extract_memory_windows_host_facts
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


class TestExtractMemoryWindowsHostFacts:
    def _system_info(self) -> dict:
        return norm.normalize_windows_info(
            _payload(),
            case_id="c",
            evidence_id="e",
            memory_run_id="run-1",
            memory_plugin_run_id="plugin-run-1",
            backend_version="2.28.0",
        )

    def test_distribution_version_and_architecture_extracted(self) -> None:
        facts = {doc["host_fact"]["fact_type"]: doc["host_fact"] for doc in extract_memory_windows_host_facts(self._system_info())}
        assert facts["host.distribution"]["normalized_value"] == "Windows"
        assert facts["host.distribution_version"]["normalized_value"] == "10.0.22621"
        assert facts["host.architecture"]["normalized_value"] == "x64"

    def test_hostname_and_fqdn_are_never_produced(self) -> None:
        # windows.info's own "host.name" field is fed by a fallback chain
        # whose only real-world value is NtProductType (a product-type
        # enum, not a computer name) -- this producer must not treat it as
        # an identity fact. See app.ingest.windows.memory_host_facts.
        facts = {doc["host_fact"]["fact_type"] for doc in extract_memory_windows_host_facts(self._system_info())}
        assert "host.hostname" not in facts
        assert "host.fqdn" not in facts

    def test_kernel_and_timezone_are_never_produced(self) -> None:
        # host.kernel would just duplicate distribution_version for Windows
        # (the NT kernel version and the OS version are the same number);
        # windows.info exposes no genuine timezone field at all (system_time
        # is the acquisition instant, not the machine's configured zone).
        facts = {doc["host_fact"]["fact_type"] for doc in extract_memory_windows_host_facts(self._system_info())}
        assert "host.kernel" not in facts
        assert "host.timezone" not in facts

    def test_provenance_carries_run_and_plugin_identifiers(self) -> None:
        documents = extract_memory_windows_host_facts(self._system_info())
        fact = documents[0]["host_fact"]
        assert fact["extra_provenance"]["memory_run_id"] == "run-1"
        assert fact["extra_provenance"]["memory_plugin_run_id"] == "plugin-run-1"
        assert fact["extra_provenance"]["plugin"] == "windows.info"

    def test_non_windows_family_produces_no_distribution_fact(self) -> None:
        system_info = self._system_info()
        system_info["os"]["family"] = "unknown"
        facts = {doc["host_fact"]["fact_type"] for doc in extract_memory_windows_host_facts(system_info)}
        assert "host.distribution" not in facts

    def test_documents_flow_through_the_generic_dispatcher(self) -> None:
        documents = extract_memory_windows_host_facts(self._system_info())
        dispatched = extract_host_fact_documents(documents)
        assert {doc["host_fact"]["fact_type"] for doc in dispatched} == {"host.distribution", "host.distribution_version", "host.architecture"}


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
