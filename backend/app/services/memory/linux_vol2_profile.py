"""Convert a Volatility 2 Linux profile into a Volatility 3 ISF.

A Volatility 2 Linux profile is a zip with ``module.dwarf`` (the text output
of ``dwarfdump`` run over a module built against the kernel's headers) and
the kernel's ``System.map``. It describes the same things a Volatility 3 ISF
does -- structure layouts and symbol addresses -- so it can be translated
without the kernel's debug package. Profiles like this exist for many old
kernels that no ISF was ever published for, and CTFs often ship one.

What a profile does not carry is added here:

* the kernel banner, which Volatility 3 uses to pick the ISF: it is read
  from the memory image, and only accepted when System.map's
  ``linux_banner`` address points at it, so the profile is known to belong
  to this kernel;
* the types of the kernel globals Volatility 3 reads (``init_task``...),
  which dwarfdump of a module does not record;
* empty placeholders for the structures Volatility 3 always registers but
  older kernels do not have (``struct cred`` appeared in 2.6.29).

A zip that holds a Volatility 3 ISF instead (``.json`` or ``.json.xz``,
as ISFs are often shared) is unpacked as is; the validation that follows
checks it against the memory image like any uploaded ISF.

Run as ``python -m app.services.memory.linux_vol2_profile <zip> <image>
<banner> <out.json>`` in an isolated subprocess: it prints
``{"ok": true, ...}`` or ``{"ok": false, "code": ..., "message": ...}``.
"""
from __future__ import annotations

import base64
import json
import mmap
import re
import struct
import sys
import zipfile
from pathlib import Path
from typing import Any

MAX_DWARF_BYTES = 256 * 1024 * 1024
MAX_SYSTEM_MAP_BYTES = 64 * 1024 * 1024
MAX_ZIP_ENTRIES = 256
MAX_ISF_BYTES = 1024 * 1024 * 1024
MAX_BANNER_BYTES = 512
PHYSICAL_ALIGN = 0x200000

# Kernel globals Volatility 3's Linux plugins read as objects. A module's
# dwarfdump has their structure types but not the variables themselves.
GLOBAL_TYPES = {
    "init_task": {"kind": "struct", "name": "task_struct"},
    "init_mm": {"kind": "struct", "name": "mm_struct"},
    "init_net": {"kind": "struct", "name": "net"},
    "init_fs": {"kind": "struct", "name": "fs_struct"},
    "init_files": {"kind": "struct", "name": "files_struct"},
    "modules": {"kind": "struct", "name": "list_head"},
    "net_namespace_list": {"kind": "struct", "name": "list_head"},
    "super_blocks": {"kind": "struct", "name": "list_head"},
    "init_pid_ns": {"kind": "struct", "name": "pid_namespace"},
    "socket_file_ops": {"kind": "struct", "name": "file_operations"},
    "sockfs_dentry_operations": {"kind": "struct", "name": "dentry_operations"},
    "wall_to_monotonic": {"kind": "struct", "name": "timespec"},
    "xtime": {"kind": "struct", "name": "timespec"},
    "timekeeper": {"kind": "struct", "name": "timekeeper"},
    "mem_map": {"kind": "pointer", "subtype": {"kind": "struct", "name": "page"}},
    "pid_hash": {"kind": "pointer", "subtype": {"kind": "struct", "name": "hlist_head"}},
    "pidhash_shift": {"kind": "base", "name": "unsigned int"},
    "log_buf": {"kind": "pointer", "subtype": {"kind": "base", "name": "char"}},
    "log_buf_len": {"kind": "base", "name": "int"},
    "jiffies": {"kind": "base", "name": "long unsigned int"},
    # Read by Volatility's rootkit checks (check_modules, hidden_modules,
    # check_idt, tty_check, check_afinfo, keyboard_notifiers) and its
    # kernel/module address lookups. Only the address of _text, _etext and
    # idt_table is used, so a char marks it.
    "_text": {"kind": "base", "name": "char"},
    "_stext": {"kind": "base", "name": "char"},
    "_etext": {"kind": "base", "name": "char"},
    "idt_table": {"kind": "base", "name": "char"},
    "module_kset": {"kind": "pointer", "subtype": {"kind": "struct", "name": "kset"}},
    "module_addr_min": {"kind": "base", "name": "long unsigned int"},
    "module_addr_max": {"kind": "base", "name": "long unsigned int"},
    "mod_tree": {"kind": "struct", "name": "mod_tree_root"},
    "tty_drivers": {"kind": "struct", "name": "list_head"},
    "keyboard_notifier_list": {"kind": "struct", "name": "atomic_notifier_head"},
    "iomem_resource": {"kind": "struct", "name": "resource"},
    # Kernels before 4.18 keep the /proc/net seq_file operations in
    # per-protocol afinfo structures, later ones in plain seq_operations.
    **{name: {"kind": "struct", "name": "tcp_seq_afinfo"} for name in ("tcp4_seq_afinfo", "tcp6_seq_afinfo")},
    **{name: {"kind": "struct", "name": "udp_seq_afinfo"} for name in ("udp4_seq_afinfo", "udp6_seq_afinfo", "udplite4_seq_afinfo", "udplite6_seq_afinfo")},
    **{name: {"kind": "struct", "name": "seq_operations"} for name in ("raw_seq_ops", "udp_seq_ops", "udp6_seq_ops", "raw6_seq_ops", "tcp_seq_ops", "tcp4_seq_ops", "tcp6_seq_ops", "packet_seq_ops")},
}

# Structures Volatility 3's Linux symbol table registers unconditionally.
REQUIRED_TYPES = (
    "file", "list_head", "hlist_head", "mm_struct", "super_block", "task_struct", "vm_area_struct", "qstr",
    "dentry", "fs_struct", "files_struct", "kobject", "cred", "inode", "idr", "address_space", "page",
    "vfsmount", "net", "socket", "sock", "inet_sock", "unix_sock",
    # linux.sockstat registers these too
    "net_device", "in_device", "in_ifaddr", "inet6_dev", "inet6_ifaddr",
)

_LINE = re.compile(r"^<(\d+)><(\d+)(?:\+\d+)?><(DW_TAG_\w+)>(.*)$")
_ATTR = re.compile(r"DW_AT_(\w+)<(.*?)>(?= DW_AT_|\s*$)")
_REF = re.compile(r"<(\d+)>")
_RELEASE_FROM_BANNER = re.compile(r"^Linux version (\S+)")
_RELEASE_FROM_DIR = re.compile(r"(?:linux-headers-|/lib/modules/)([^/\s>]+)")


class Vol2ProfileError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def extract_zipped_isf(zip_path: Path, output: Path) -> bool:
    """Unpack a zip that holds one Volatility 3 ISF into ``output``; False when it holds none."""
    import lzma

    try:
        archive = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise Vol2ProfileError("SYMBOL_UNSUPPORTED_FORMAT", "The file is not a zip archive.") from exc
    with archive:
        entries = [info for info in archive.infolist() if not info.is_dir()]
        if len(entries) > MAX_ZIP_ENTRIES or any(info.filename.lower().endswith(".dwarf") for info in entries):
            return False
        isfs = [info for info in entries if info.filename.lower().endswith((".json", ".json.xz"))]
        if len(isfs) != 1:
            return False
        info = isfs[0]
        compressed = info.filename.lower().endswith(".xz")
        written = 0
        with archive.open(info) as source, output.open("wb") as target:
            reader = lzma.LZMAFile(source) if compressed else source
            while chunk := reader.read(1024 * 1024):
                written += len(chunk)
                if written > MAX_ISF_BYTES:
                    target.close()
                    output.unlink(missing_ok=True)
                    raise Vol2ProfileError("SYMBOL_UNSUPPORTED_FORMAT", "The ISF in the zip is too large.")
                target.write(chunk)
    return True


def read_profile(zip_path: Path) -> tuple[str, str, str]:
    """Return (module.dwarf text, System.map text, System.map file name)."""
    try:
        archive = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise Vol2ProfileError("SYMBOL_UNSUPPORTED_FORMAT", "The file is not a zip archive.") from exc
    with archive:
        entries = [info for info in archive.infolist() if not info.is_dir()]
        if len(entries) > MAX_ZIP_ENTRIES:
            raise Vol2ProfileError("SYMBOL_UNSUPPORTED_FORMAT", "The zip has too many entries to be a Volatility 2 profile.")
        dwarf = [info for info in entries if info.filename.lower().endswith(".dwarf")]
        system_map = [info for info in entries if Path(info.filename).name.lower().startswith("system.map")]
        if len(dwarf) != 1 or len(system_map) != 1:
            raise Vol2ProfileError(
                "SYMBOL_UNSUPPORTED_FORMAT",
                "A Volatility 2 Linux profile is a zip with one module.dwarf and one System.map.",
            )
        return (
            _read_member(archive, dwarf[0], MAX_DWARF_BYTES),
            _read_member(archive, system_map[0], MAX_SYSTEM_MAP_BYTES),
            Path(system_map[0].filename).name,
        )


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> str:
    if info.flag_bits & 0x1:
        raise Vol2ProfileError("SYMBOL_UNSUPPORTED_FORMAT", "Encrypted profiles are not supported.")
    if info.file_size > limit:
        raise Vol2ProfileError("SYMBOL_IMPORT_REJECTED", f"{info.filename} is larger than {limit} bytes.")
    with archive.open(info) as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise Vol2ProfileError("SYMBOL_IMPORT_REJECTED", f"{info.filename} is larger than {limit} bytes.")
    return data.decode("utf-8", "replace")


def parse_system_map(text: str) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3:
            try:
                symbols.setdefault(parts[2], int(parts[0], 16))
            except ValueError:
                continue
    return symbols


def _parse_dwarf(text: str) -> dict[tuple[int, int], dict[str, Any]]:
    """Index dwarfdump's text output by (compile unit, offset): references are CU-relative."""
    nodes: dict[tuple[int, int], dict[str, Any]] = {}
    stack: list[dict[str, Any]] = []
    unit = -1
    for raw in text.splitlines():
        match = _LINE.match(raw.strip())
        if not match:
            continue
        depth, offset, tag = int(match[1]), int(match[2]), match[3]
        if tag == "DW_TAG_compile_unit":
            unit += 1
        node = {"tag": tag, "attrs": dict(_ATTR.findall(match[4])), "children": [], "cu": unit, "off": offset}
        nodes[(unit, offset)] = node
        del stack[depth:]
        if stack:
            stack[-1]["children"].append(node)
        stack.append(node)
    return nodes


def _number(value: str) -> int:
    match = re.search(r"(-?\d+)\s*$", value.strip())
    return int(match[1]) if match else 0


class _TypeBuilder:
    def __init__(self, nodes: dict[tuple[int, int], dict[str, Any]]) -> None:
        self.nodes = nodes
        self.base_types: dict[str, dict[str, Any]] = {"void": {"size": 0, "signed": False, "kind": "void", "endian": "little"}}
        self.user_types: dict[str, dict[str, Any] | None] = {}
        self.enums: dict[str, dict[str, Any]] = {}
        self.definitions: dict[str, dict[str, Any]] = {}
        for node in nodes.values():
            attrs = node["attrs"]
            if node["tag"] in ("DW_TAG_structure_type", "DW_TAG_union_type") and attrs.get("name") and "declaration" not in attrs:
                self.definitions.setdefault(attrs["name"], node)

    def build(self) -> None:
        for node in self.nodes.values():
            if node["tag"] in ("DW_TAG_base_type", "DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_typedef", "DW_TAG_enumeration_type") and node["attrs"].get("name"):
                self.describe(node)

    def _target(self, node: dict[str, Any]) -> dict[str, Any] | None:
        value = node["attrs"].get("type")
        match = _REF.search(value) if value else None
        return self.nodes.get((node["cu"], int(match[1]))) if match else None

    def typedef_size(self, name: str) -> int | None:
        for node in self.nodes.values():
            if node["tag"] == "DW_TAG_typedef" and node["attrs"].get("name") == name:
                target = self._target(node)
                if target is not None and "byte_size" in target["attrs"]:
                    return _number(target["attrs"]["byte_size"])
        return None

    def describe(self, node: dict[str, Any] | None) -> dict[str, Any]:
        if node is None:
            return {"kind": "base", "name": "void"}
        tag, attrs = node["tag"], node["attrs"]
        if tag == "DW_TAG_base_type":
            name = attrs.get("name", "void")
            encoding = attrs.get("encoding", "")
            kind = "float" if "float" in encoding else "bool" if "boolean" in encoding else "char" if "char" in encoding else "int"
            self.base_types.setdefault(name, {
                "size": _number(attrs.get("byte_size", "0")),
                "signed": "unsigned" not in encoding and "boolean" not in encoding,
                "kind": kind,
                "endian": "little",
            })
            return {"kind": "base", "name": name}
        if tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type"):
            return self.describe(self._target(node))
        if tag == "DW_TAG_pointer_type":
            return {"kind": "pointer", "subtype": self.describe(self._target(node))}
        if tag == "DW_TAG_array_type":
            described = self.describe(self._target(node))
            counts = [
                _number(child["attrs"]["upper_bound"]) + 1 if "upper_bound" in child["attrs"] else 0
                for child in node["children"] if child["tag"] == "DW_TAG_subrange_type"
            ] or [0]
            for count in reversed(counts):
                described = {"kind": "array", "count": count, "subtype": described}
            return described
        if tag in ("DW_TAG_structure_type", "DW_TAG_union_type"):
            kind = "struct" if tag == "DW_TAG_structure_type" else "union"
            name = attrs.get("name")
            if name and "declaration" in attrs:
                node = self.definitions.get(name, node)
            name = name or f"unnamed_{node['cu']}_{node['off']:x}"
            if name not in self.user_types:
                self.user_types[name] = None  # a member pointing back at its own struct stops here
                self.user_types[name] = self._aggregate(node, kind)
            return {"kind": kind, "name": name}
        if tag == "DW_TAG_enumeration_type":
            name = attrs.get("name") or f"unnamed_enum_{node['cu']}_{node['off']:x}"
            if name not in self.enums:
                size = _number(attrs.get("byte_size", "4"))
                base = {1: "unsigned char", 2: "short unsigned int", 8: "long long unsigned int"}.get(size, "unsigned int")
                self.base_types.setdefault(base, {"size": size, "signed": False, "kind": "int", "endian": "little"})
                self.enums[name] = {
                    "size": size,
                    "base": base,
                    "constants": {child["attrs"]["name"]: _number(child["attrs"].get("const_value", "0")) for child in node["children"] if child["tag"] == "DW_TAG_enumerator" and "name" in child["attrs"]},
                }
            return {"kind": "enum", "name": name}
        if tag == "DW_TAG_subroutine_type":
            return {"kind": "function"}
        return {"kind": "base", "name": "void"}

    def _aggregate(self, node: dict[str, Any], kind: str) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        if "declaration" not in node["attrs"]:
            members = [child for child in node["children"] if child["tag"] == "DW_TAG_member"]
            for index, member in enumerate(members):
                attrs = member["attrs"]
                described = self.describe(self._target(member))
                if "bit_size" in attrs:
                    storage = _number(attrs.get("byte_size", "0")) or self.base_types.get(described.get("name", ""), {}).get("size", 4)
                    bits = _number(attrs["bit_size"])
                    # DWARF 2 counts bit_offset from the storage unit's most significant bit.
                    described = {"kind": "bitfield", "bit_length": bits, "bit_position": storage * 8 - _number(attrs.get("bit_offset", "0")) - bits, "type": described}
                fields[attrs.get("name") or f"unnamed_field_{index}"] = {"offset": _number(attrs.get("data_member_location", "0")), "type": described}
        return {"kind": kind, "size": _number(node["attrs"].get("byte_size", "0")), "fields": fields}


def _add_socket_alloc(user_types: dict[str, Any], pointer_size: int) -> None:
    """struct socket_alloc { struct socket socket; struct inode vfs_inode; } -- how
    linux.sockstat gets from a socket's inode to the socket. Profiles rarely include it."""
    socket, inode = user_types.get("socket"), user_types.get("inode")
    if "socket_alloc" in user_types or not socket or not inode or not socket["size"] or not inode["size"]:
        return
    inode_offset = -(-socket["size"] // pointer_size) * pointer_size
    user_types["socket_alloc"] = {
        "kind": "struct",
        "size": inode_offset + inode["size"],
        "fields": {
            "socket": {"offset": 0, "type": {"kind": "struct", "name": "socket"}},
            "vfs_inode": {"offset": inode_offset, "type": {"kind": "struct", "name": "inode"}},
        },
    }


def _known(described: dict[str, Any], builder: _TypeBuilder) -> bool:
    if described["kind"] == "pointer":
        return _known(described["subtype"], builder)
    if described["kind"] == "base":
        return described["name"] in builder.base_types
    return described["name"] in builder.user_types


def _release_at_least(release: str | None, minimum: tuple[int, ...]) -> bool:
    numbers = [int(part) for part in re.findall(r"\d+", (release or "").split("-", 1)[0])[:3]]
    return bool(numbers) and tuple(numbers) >= minimum


def _pointer_size(nodes: dict[tuple[int, int], dict[str, Any]]) -> int:
    for node in nodes.values():
        if node["tag"] == "DW_TAG_pointer_type" and "byte_size" in node["attrs"]:
            return _number(node["attrs"]["byte_size"])
    return 4


def _profile_release(system_map_name: str, dwarf_text: str) -> str | None:
    if "-" in system_map_name:
        release = system_map_name.split("-", 1)[1].strip()
        if release:
            return release
    match = _RELEASE_FROM_DIR.search(dwarf_text[:65536])
    return match[1] if match else None


# --- memory image ---------------------------------------------------------


def _image_ranges(view: mmap.mmap) -> tuple[str, list[tuple[int, int, int]]]:
    """Map the image's layout as (kind, [(address, file offset, length)]).

    kind is "physical" for raw and LiME images, "elf" for ELF cores (whose
    segments carry both a physical and a virtual address).
    """
    size = len(view)
    if view[:4] == b"EMiL":
        ranges, offset = [], 0
        while offset + 32 <= size and view[offset:offset + 4] == b"EMiL":
            start, end = struct.unpack_from("<QQ", view, offset + 8)
            ranges.append((start, offset + 32, end - start + 1))
            offset += 32 + end - start + 1
        return "physical", ranges
    if view[:4] == b"\x7fELF":
        is64 = view[4] == 2
        if is64:
            phoff, = struct.unpack_from("<Q", view, 0x20)
            phentsize, phnum = struct.unpack_from("<HH", view, 0x36)
        else:
            phoff, = struct.unpack_from("<I", view, 0x1C)
            phentsize, phnum = struct.unpack_from("<HH", view, 0x2A)
        ranges = []
        for index in range(min(phnum, 4096)):
            base = phoff + index * phentsize
            if is64:
                ptype, _, offset, vaddr, paddr, filesz = struct.unpack_from("<IIQQQQ", view, base)
            else:
                ptype, offset, vaddr, paddr, filesz = struct.unpack_from("<IIIII", view, base)
            if ptype == 1:
                ranges.append((paddr, offset, filesz))
                ranges.append((vaddr, offset, filesz))
        return "elf", ranges
    return "physical", [(0, 0, size)]


def _address_of(ranges: list[tuple[int, int, int]], file_offset: int) -> list[int]:
    return [address + file_offset - offset for address, offset, length in ranges if offset <= file_offset < offset + length]


def _kernel_bases(pointer_size: int) -> tuple[int, ...]:
    # Where the kernel's virtual addresses start relative to physical memory.
    return (0xFFFFFFFF80000000,) if pointer_size == 8 else (0xC0000000, 0x80000000, 0x40000000)


def _banner_at(address: int, banner_address: int, pointer_size: int, kind: str) -> bool:
    if address == banner_address:  # an ELF core's virtual address
        return True
    for base in _kernel_bases(pointer_size):
        shift = address - (banner_address - base)
        # Exact for a kernel loaded where it was linked; a relocated (or
        # KASLR) kernel moves in physical memory by the physical alignment.
        if shift == 0 or (kind == "physical" and shift % PHYSICAL_ALIGN == 0):
            return True
    return False


def find_banner(image_path: Path, banner_text: str, banner_address: int, pointer_size: int) -> bytes:
    """Return the banner bytes System.map's linux_banner points at in this image."""
    needle = banner_text.strip().encode("latin-1", "replace")
    if not needle.startswith(b"Linux version "):
        raise Vol2ProfileError("KERNEL_IDENTITY_UNKNOWN", "The memory image's kernel banner is not known.")
    with image_path.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as view:
        kind, ranges = _image_ranges(view)
        position = view.find(needle)
        while position != -1:
            end = view.find(b"\0", position, position + MAX_BANNER_BYTES)
            candidate = bytes(view[position:end + 1]) if end != -1 else b""
            if candidate and any(_banner_at(address, banner_address, pointer_size, kind) for address in _address_of(ranges, position)):
                return candidate
            position = view.find(needle, position + 1)
    raise Vol2ProfileError(
        "SYMBOL_PROFILE_MISMATCH",
        "This profile's System.map does not match the memory image: its linux_banner address does not hold the kernel banner.",
    )


# --- conversion -----------------------------------------------------------


def convert_profile(zip_path: Path, image_path: Path, banner_text: str) -> dict[str, Any]:
    if not banner_text:
        raise Vol2ProfileError("SYMBOL_BANNER_UNKNOWN", "Kairon has not found this memory image's kernel banner, which a Volatility 2 profile needs to be matched.")
    dwarf_text, system_map_text, system_map_name = read_profile(zip_path)
    symbols_by_name = parse_system_map(system_map_text)
    if "linux_banner" not in symbols_by_name or "init_task" not in symbols_by_name:
        raise Vol2ProfileError("SYMBOL_UNSUPPORTED_FORMAT", "System.map has no linux_banner or init_task symbol.")
    nodes = _parse_dwarf(dwarf_text)
    if not any(node["tag"] == "DW_TAG_structure_type" and node["attrs"].get("name") == "task_struct" and "declaration" not in node["attrs"] for node in nodes.values()):
        raise Vol2ProfileError("SYMBOL_UNSUPPORTED_FORMAT", "module.dwarf does not describe struct task_struct.")
    pointer_size = _pointer_size(nodes)

    banner = find_banner(image_path, banner_text, symbols_by_name["linux_banner"], pointer_size)
    banner_release = _RELEASE_FROM_BANNER.match(banner.decode("latin-1"))
    release = banner_release[1] if banner_release else None
    profile_release = _profile_release(system_map_name, dwarf_text)
    if release and profile_release and profile_release != release:
        raise Vol2ProfileError("SYMBOL_PROFILE_MISMATCH", f"This profile is for kernel {profile_release}, the memory image runs {release}.")

    builder = _TypeBuilder(nodes)
    builder.build()
    builder.base_types["pointer"] = {"size": pointer_size, "signed": False, "kind": "int", "endian": "little"}
    _add_socket_alloc(builder.user_types, pointer_size)
    for name in REQUIRED_TYPES:
        builder.user_types.setdefault(name, {"kind": "struct", "size": 0, "fields": {}})

    symbols: dict[str, dict[str, Any]] = {name: {"address": address} for name, address in symbols_by_name.items()}
    symbols["linux_banner"]["constant_data"] = base64.b64encode(banner).decode("ascii")
    for name, described in GLOBAL_TYPES.items():
        if name in symbols and _known(described, builder):
            symbols[name]["type"] = described
    if "total_sleep_time" in symbols:
        # Seconds in an unsigned long before 2.6.32, a timespec since: it moves process start times.
        sleep_type = {"kind": "struct", "name": "timespec"} if _release_at_least(release or profile_release, (2, 6, 32)) else {"kind": "base", "name": "long unsigned int"}
        if _known(sleep_type, builder):
            symbols["total_sleep_time"]["type"] = sleep_type
    if pointer_size == 4 and "pkmap_count" in symbols:
        # Volatility 3 tells PAE from non-PAE paging by pkmap_count's length (LAST_PKMAP).
        pae = (builder.typedef_size("pte_t") or 4) == 8
        symbols["pkmap_count"]["type"] = {"kind": "array", "count": 512 if pae else 1024, "subtype": {"kind": "base", "name": "int"}}
        builder.base_types.setdefault("int", {"size": 4, "signed": True, "kind": "int", "endian": "little"})

    banner_line = banner.rstrip(b"\0").strip().decode("latin-1")
    return {
        "metadata": {
            "format": "6.2.0",
            # Raised whenever the conversion's output changes: a newer conversion of a profile
            # replaces the cached one (app.services.memory.linux_symbols).
            "producer": {"name": "kairon-vol2-profile", "version": "2"},
            "linux": {
                "kernel_release": release or profile_release,
                "banner": banner_line,
                "converted_from": "volatility2-profile",
                "symbols": [{"kind": "system-map", "name": system_map_name}],
            },
        },
        "base_types": builder.base_types,
        "user_types": builder.user_types,
        "enums": builder.enums,
        "symbols": symbols,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print("usage: linux_vol2_profile.py <profile.zip> <memory image> <banner> <out.json>", file=sys.stderr)
        return 2
    try:
        if extract_zipped_isf(Path(argv[1]), Path(argv[4])):
            print(json.dumps({"ok": True, "zipped_isf": True}))
            return 0
        isf = convert_profile(Path(argv[1]), Path(argv[2]), argv[3])
    except Vol2ProfileError as exc:
        print(json.dumps({"ok": False, "code": exc.code, "message": exc.message}))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "code": "SYMBOL_PARSE_FAILED", "message": "The Volatility 2 profile could not be converted."}))
        print(repr(exc), file=sys.stderr)
        return 0
    Path(argv[4]).write_text(json.dumps(isf), encoding="utf-8")
    print(json.dumps({"ok": True, "kernel_release": isf["metadata"]["linux"]["kernel_release"], "types": len(isf["user_types"]), "symbols": len(isf["symbols"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
