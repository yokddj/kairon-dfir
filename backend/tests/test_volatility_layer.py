"""Volatility gets a memory layer pinned to the page-table base MemProcFS finds."""

from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace

from app.services.memory import volatility_layer
from app.services.memory.memprocfs_dtb import parse_header
from app.services.memory.volatility_runner import build_plugin_argv

FOUND = {"page_map_offset": 0x1AE000, "architecture": "Intel64", "pae": False}


def _header(signature: bytes, dtb: int, *, pae: int = 0) -> bytes:
    header = bytearray(0x1000)
    header[:8] = signature
    if signature == b"PAGEDU64":
        struct.pack_into("<Q", header, 0x10, dtb)
    else:
        struct.pack_into("<I", header, 0x10, dtb)
        header[0x5C] = pae
    return bytes(header)


def test_the_crash_dump_header_memprocfs_presents_gives_the_dtb():
    assert parse_header(_header(b"PAGEDU64", 0x1AE000)) == FOUND
    assert parse_header(_header(b"PAGEDUMP", 0x39000, pae=1)) == {"page_map_offset": 0x39000, "architecture": "Intel32", "pae": True}
    assert parse_header(_header(b"PAGEDU64", 0)) is None
    assert parse_header(b"\x00" * 0x1000) is None


def test_a_raw_image_is_pinned_over_its_file(tmp_path: Path):
    image = tmp_path / "Physical Memory.dd"
    image.write_bytes(b"\x00" * 64)
    config = volatility_layer.layer_config(image, FOUND)
    assert config == {
        "kernel.layer_name.class": "volatility3.framework.layers.intel.WindowsIntel32e",
        "kernel.layer_name.page_map_offset": 0x1AE000,
        "kernel.layer_name.memory_layer.class": "volatility3.framework.layers.physical.FileLayer",
        "kernel.layer_name.memory_layer.location": image.resolve().as_uri(),
    }
    assert "%20" in config["kernel.layer_name.memory_layer.location"]


def test_a_crash_dump_is_pinned_over_volatilitys_crash_dump_layer(tmp_path: Path):
    image = tmp_path / "memory.dmp"
    image.write_bytes(_header(b"PAGEDU64", 0x1AE000))
    config = volatility_layer.layer_config(image, FOUND)
    assert config["kernel.layer_name.memory_layer.class"].endswith("crash.WindowsCrashDump64Layer")
    assert config["kernel.layer_name.memory_layer.base_layer.class"].endswith("physical.FileLayer")


def test_32_bit_paging_modes(tmp_path: Path):
    image = tmp_path / "x86.raw"
    image.write_bytes(b"\x00" * 64)
    assert volatility_layer.layer_config(image, {"page_map_offset": 1, "architecture": "Intel32", "pae": True})["kernel.layer_name.class"].endswith("WindowsIntelPAE")
    assert volatility_layer.layer_config(image, {"page_map_offset": 1, "architecture": "Intel32", "pae": False})["kernel.layer_name.class"].endswith("intel.WindowsIntel")


def test_containers_volatility_maps_its_own_way_are_left_alone(tmp_path: Path):
    for name, head in (("core.elf", b"\x7fELF"), ("lime.mem", b"EMiL"), ("hiberfil.sys", b"HIBR")):
        image = tmp_path / name
        image.write_bytes(head + b"\x00" * 60)
        assert volatility_layer.layer_config(image, FOUND) is None
    vmem = tmp_path / "vm.vmem"
    vmem.write_bytes(b"\x00" * 64)
    assert volatility_layer.layer_config(vmem, FOUND) is not None
    (tmp_path / "vm.vmss").write_bytes(b"\x00")
    assert volatility_layer.layer_config(vmem, FOUND) is None


def test_write_config_only_with_a_recorded_dtb(tmp_path: Path):
    image = tmp_path / "PhysicalMemory.dd"
    image.write_bytes(b"\x00" * 64)
    assert volatility_layer.write_config(tmp_path / "w", image, SimpleNamespace(metadata_json={})) is None
    written = volatility_layer.write_config(tmp_path / "w", image, SimpleNamespace(metadata_json={"volatility_layer": {**FOUND, "source": "MemProcFS"}}))
    assert written is not None and '"kernel.layer_name.page_map_offset": 1761280' in written.read_text()


def test_a_pinned_layer_replaces_the_file_argument(tmp_path: Path):
    """With -f as well, Volatility would scan for the page tables again."""
    config = tmp_path / "volatility-layer.json"
    argv = build_plugin_argv("vol", tmp_path / "PhysicalMemory.dd", "windows.pslist", layer_config=config)
    assert "-f" not in argv and argv[argv.index("-c") + 1] == str(config)
    assert "-f" in build_plugin_argv("vol", tmp_path / "PhysicalMemory.dd", "windows.pslist")
