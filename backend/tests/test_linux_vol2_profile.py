"""Volatility 2 Linux profile -> Volatility 3 ISF, on a hand-written profile.

The profile is a 32-bit kernel "2.6.26-2-686": dwarfdump text for a few
structures and a System.map whose linux_banner sits at 0xc02bf000, i.e. at
physical 0x2bf000 in a raw image."""

from __future__ import annotations

import base64
import io
import json
import struct
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.memory import linux_vol2_profile as vol2
from app.services.memory.linux_vol2_profile import Vol2ProfileError, convert_profile

BANNER = "Linux version 2.6.26-2-686 (Debian 2.6.26-26lenny1) (dannf@debian.org) #1 SMP Thu Nov 25 01:53:57 UTC 2010"
BANNER_ADDRESS = 0xC02BF000

DWARF = """.debug_info

<0><0+11><DW_TAG_compile_unit> DW_AT_producer<GNU C 4.1.3> DW_AT_name</root/volatility/tools/linux/module.c> DW_AT_comp_dir</usr/src/linux-headers-2.6.26-2-686>

<1><37><DW_TAG_base_type> DW_AT_name<int> DW_AT_byte_size<4> DW_AT_encoding<DW_ATE_signed>

<1><44><DW_TAG_base_type> DW_AT_name<unsigned int> DW_AT_byte_size<4> DW_AT_encoding<DW_ATE_unsigned>

<1><51><DW_TAG_base_type> DW_AT_name<char> DW_AT_byte_size<1> DW_AT_encoding<DW_ATE_signed_char>

<1><54><DW_TAG_base_type> DW_AT_name<long unsigned int> DW_AT_byte_size<4> DW_AT_encoding<DW_ATE_unsigned>

<1><58><DW_TAG_structure_type> DW_AT_name<list_head> DW_AT_byte_size<8>

<2><70><DW_TAG_member> DW_AT_name<next> DW_AT_type<<90>> DW_AT_data_member_location<DW_OP_plus_uconst 0>

<2><80><DW_TAG_member> DW_AT_name<prev> DW_AT_type<<90>> DW_AT_data_member_location<DW_OP_plus_uconst 4>

<1><90><DW_TAG_pointer_type> DW_AT_byte_size<4> DW_AT_type<<58>>

<1><100><DW_TAG_structure_type> DW_AT_name<task_struct> DW_AT_byte_size<64>

<2><110><DW_TAG_member> DW_AT_name<tasks> DW_AT_type<<58>> DW_AT_data_member_location<DW_OP_plus_uconst 0>

<2><120><DW_TAG_member> DW_AT_name<pid> DW_AT_type<<150>> DW_AT_data_member_location<DW_OP_plus_uconst 8>

<2><130><DW_TAG_member> DW_AT_name<uid> DW_AT_type<<44>> DW_AT_data_member_location<DW_OP_plus_uconst 12>

<2><135><DW_TAG_member> DW_AT_name<did_exec> DW_AT_type<<44>> DW_AT_byte_size<4> DW_AT_bit_size<1> DW_AT_bit_offset<30> DW_AT_data_member_location<DW_OP_plus_uconst 16>

<2><140><DW_TAG_member> DW_AT_name<comm> DW_AT_type<<160>> DW_AT_data_member_location<DW_OP_plus_uconst 20>

<1><150><DW_TAG_typedef> DW_AT_name<pid_t> DW_AT_type<<37>>

<1><160><DW_TAG_array_type> DW_AT_type<<51>>

<2><170><DW_TAG_subrange_type> DW_AT_type<<44>> DW_AT_upper_bound<15>

<1><180><DW_TAG_structure_type> DW_AT_byte_size<4>

<2><190><DW_TAG_member> DW_AT_name<pte_low> DW_AT_type<<44>> DW_AT_data_member_location<DW_OP_plus_uconst 0>

<1><200><DW_TAG_typedef> DW_AT_name<pte_t> DW_AT_type<<180>>

<1><210><DW_TAG_structure_type> DW_AT_name<socket> DW_AT_byte_size<38>

<2><220><DW_TAG_member> DW_AT_name<state> DW_AT_type<<240>> DW_AT_data_member_location<DW_OP_plus_uconst 0>

<1><230><DW_TAG_structure_type> DW_AT_name<inode> DW_AT_byte_size<340>

<1><240><DW_TAG_enumeration_type> DW_AT_name<socket_state> DW_AT_byte_size<4>

<2><250><DW_TAG_enumerator> DW_AT_name<SS_FREE> DW_AT_const_value<0>

<2><260><DW_TAG_enumerator> DW_AT_name<SS_CONNECTED> DW_AT_const_value<3>

<1><270><DW_TAG_structure_type> DW_AT_name<timespec> DW_AT_byte_size<8>
"""

SYSTEM_MAP = """c0100000 T _text
c02bf000 R linux_banner
c034e300 D init_task
c03bc000 B swapper_pg_dir
c040a4c0 b pkmap_count
c03f5190 B wall_to_monotonic
c03f519c b total_sleep_time
"""


def _profile(tmp_path: Path, *, system_map_name: str = "boot/System.map-2.6.26-2-686", dwarf: str = DWARF) -> Path:
    path = tmp_path / "Debian5_26.zip"
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("volatility/tools/linux/module.dwarf", dwarf)
        bundle.writestr(system_map_name, SYSTEM_MAP)
    return path


def _raw_image(tmp_path: Path, *, banner_offset: int = BANNER_ADDRESS - 0xC0000000) -> Path:
    image = bytearray(banner_offset + 0x1000)
    data = BANNER.encode() + b"\n\0"
    image[banner_offset:banner_offset + len(data)] = data
    image[0x1000:0x1000 + len(data)] = data  # a stray copy elsewhere (page cache) is ignored
    path = tmp_path / "memory.raw"
    path.write_bytes(bytes(image))
    return path


def test_a_profile_becomes_an_isf_volatility_can_pick_by_banner(tmp_path):
    isf = convert_profile(_profile(tmp_path), _raw_image(tmp_path), BANNER)

    assert base64.b64decode(isf["symbols"]["linux_banner"]["constant_data"]) == BANNER.encode() + b"\n\0"
    assert isf["metadata"]["linux"]["kernel_release"] == "2.6.26-2-686"
    assert isf["metadata"]["linux"]["banner"] == BANNER
    task = isf["user_types"]["task_struct"]
    assert task["size"] == 64
    assert task["fields"]["pid"] == {"offset": 8, "type": {"kind": "base", "name": "int"}}  # typedefs resolved
    assert task["fields"]["comm"]["type"] == {"kind": "array", "count": 16, "subtype": {"kind": "base", "name": "char"}}
    assert task["fields"]["tasks"]["type"] == {"kind": "struct", "name": "list_head"}
    # DWARF 2 counts bit_offset from the most significant bit: 32 - 30 - 1.
    assert task["fields"]["did_exec"]["type"] == {"kind": "bitfield", "bit_length": 1, "bit_position": 1, "type": {"kind": "base", "name": "unsigned int"}}
    assert isf["user_types"]["list_head"]["fields"]["next"]["type"] == {"kind": "pointer", "subtype": {"kind": "struct", "name": "list_head"}}
    assert isf["enums"]["socket_state"]["constants"] == {"SS_FREE": 0, "SS_CONNECTED": 3}
    assert isf["base_types"]["pointer"]["size"] == 4


def test_what_the_profile_lacks_is_filled_in(tmp_path):
    isf = convert_profile(_profile(tmp_path), _raw_image(tmp_path), BANNER)
    symbols, types = isf["symbols"], isf["user_types"]

    assert symbols["init_task"]["type"] == {"kind": "struct", "name": "task_struct"}
    # Non-PAE paging (4-byte pte_t) is told to Volatility by pkmap_count's length.
    assert symbols["pkmap_count"]["type"]["count"] == 1024
    assert symbols["wall_to_monotonic"]["type"] == {"kind": "struct", "name": "timespec"}
    # Before 2.6.32 total_sleep_time is seconds in an unsigned long.
    assert symbols["total_sleep_time"]["type"] == {"kind": "base", "name": "long unsigned int"}
    # struct cred did not exist before 2.6.29: an empty placeholder keeps Volatility loading the table.
    assert types["cred"] == {"kind": "struct", "size": 0, "fields": {}}
    # socket_alloc = socket + inode, the inode aligned after the socket.
    assert types["socket_alloc"]["fields"]["vfs_inode"]["offset"] == 40
    assert types["socket_alloc"]["size"] == 380


def test_a_profile_for_another_kernel_build_is_refused(tmp_path):
    # Same release name, but this image's banner is not where System.map says.
    with pytest.raises(Vol2ProfileError) as error:
        convert_profile(_profile(tmp_path), _raw_image(tmp_path, banner_offset=0x2C0123), BANNER)
    assert error.value.code == "SYMBOL_PROFILE_MISMATCH"


def test_a_profile_for_another_release_is_refused(tmp_path):
    with pytest.raises(Vol2ProfileError) as error:
        convert_profile(_profile(tmp_path, system_map_name="boot/System.map-2.6.32-5-686"), _raw_image(tmp_path), BANNER)
    assert error.value.code == "SYMBOL_PROFILE_MISMATCH"
    assert "2.6.32-5-686" in error.value.message


def test_a_relocated_kernel_is_matched_by_physical_alignment(tmp_path):
    image = _raw_image(tmp_path, banner_offset=BANNER_ADDRESS - 0xC0000000 + 0x400000)
    assert convert_profile(_profile(tmp_path), image, BANNER)["metadata"]["linux"]["kernel_release"] == "2.6.26-2-686"


def test_a_lime_image_is_read_through_its_ranges(tmp_path):
    banner_physical = BANNER_ADDRESS - 0xC0000000
    first = bytes(0x1000)
    second = bytearray(0x1000)
    second[0:len(BANNER) + 2] = BANNER.encode() + b"\n\0"
    image = (
        struct.pack("<4sIQQQ", b"EMiL", 1, 0, len(first) - 1, 0) + first
        + struct.pack("<4sIQQQ", b"EMiL", 1, banner_physical, banner_physical + len(second) - 1, 0) + bytes(second)
    )
    path = tmp_path / "memory.lime"
    path.write_bytes(image)
    assert convert_profile(_profile(tmp_path), path, BANNER)["symbols"]["linux_banner"]["constant_data"]


@pytest.mark.parametrize("entries", [{"module.dwarf": DWARF}, {"System.map-2.6.26-2-686": SYSTEM_MAP}, {}])
def test_a_zip_that_is_not_a_profile_is_unsupported(tmp_path, entries):
    path = tmp_path / "other.zip"
    with zipfile.ZipFile(path, "w") as bundle:
        for name, content in entries.items():
            bundle.writestr(name, content)
        bundle.writestr("readme.txt", "hello")
    with pytest.raises(Vol2ProfileError) as error:
        convert_profile(path, _raw_image(tmp_path), BANNER)
    assert error.value.code == "SYMBOL_UNSUPPORTED_FORMAT"


def test_an_oversized_member_is_refused_before_reading_it(tmp_path, monkeypatch):
    monkeypatch.setattr(vol2, "MAX_DWARF_BYTES", 100)
    with pytest.raises(Vol2ProfileError) as error:
        convert_profile(_profile(tmp_path), _raw_image(tmp_path), BANNER)
    assert error.value.code == "SYMBOL_IMPORT_REJECTED"


def test_the_command_line_writes_the_isf_and_reports_errors_as_json(tmp_path):
    out = tmp_path / "out.json"
    ok = subprocess.run([sys.executable, "-m", "app.services.memory.linux_vol2_profile", str(_profile(tmp_path)), str(_raw_image(tmp_path)), BANNER, str(out)], capture_output=True, check=True)
    assert json.loads(ok.stdout)["ok"] is True
    assert json.loads(out.read_text())["metadata"]["linux"]["kernel_release"] == "2.6.26-2-686"
    bad = subprocess.run([sys.executable, "-m", "app.services.memory.linux_vol2_profile", str(tmp_path / "out.json"), str(_raw_image(tmp_path)), BANNER, str(tmp_path / "x.json")], capture_output=True, check=True)
    assert json.loads(bad.stdout) == {"ok": False, "code": "SYMBOL_UNSUPPORTED_FORMAT", "message": "The file is not a zip archive."}


# --- volatility_legacy_linux: Volatility 3 on kernels before 2.6.29 ----------


class _Member(int):
    def __new__(cls, value, offset=0):
        item = super().__new__(cls, value)
        item.vol = SimpleNamespace(offset=offset)
        return item


class _Struct:
    def __init__(self, **members):
        self._members = members

    def has_member(self, name):
        return name in self._members

    def member(self, name):
        return self._members[name]

    def __getattr__(self, name):
        if name.startswith("_") and name != "__sk_common":
            raise AttributeError(name)
        if name in self._members:
            return self._members[name]
        raise AttributeError(f"StructType has no attribute: {name}")


def _fake_volatility(monkeypatch):
    class task_struct(_Struct):
        pass

    class inet_sock(_Struct):
        def get_dst_addr(self):
            return getattr(self.sk, "__sk_common").skc_daddr

    extensions = SimpleNamespace(task_struct=task_struct)
    network = SimpleNamespace(inet_sock=inet_sock)
    extensions.network = network
    modules = {
        "volatility3": SimpleNamespace(),
        "volatility3.framework": SimpleNamespace(),
        "volatility3.framework.symbols": SimpleNamespace(),
        "volatility3.framework.symbols.linux": SimpleNamespace(extensions=extensions),
        "volatility3.framework.symbols.linux.extensions": extensions,
        "volatility3.framework.symbols.linux.extensions.network": network,
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    return task_struct, inet_sock


def test_old_tasks_get_their_ids_through_cred(monkeypatch):
    from app.services.memory import volatility_legacy_linux

    task_struct, _ = _fake_volatility(monkeypatch)
    volatility_legacy_linux.install()
    old = task_struct(uid=33, gid=33, euid=0, egid=0)
    assert old.cred and old.cred.is_readable()
    assert (old.cred.uid, old.cred.gid, old.cred.euid, old.cred.egid) == (33, 33, 0, 0)
    modern_cred = SimpleNamespace(uid=1000)
    assert task_struct(cred=modern_cred).cred is modern_cred


def test_a_listening_socket_on_an_old_kernel_has_a_destination(monkeypatch):
    from app.services.memory import volatility_legacy_linux

    _, inet_sock = _fake_volatility(monkeypatch)
    volatility_legacy_linux.install()
    layer = SimpleNamespace(read=lambda offset, size: bytes([192, 168, 56, 1]) if offset == 0x40 else b"\0" * size)
    old = inet_sock(daddr=_Member(0, offset=0x40), sk=_Struct(__sk_common=_Struct(skc_family=2)))
    old._context = SimpleNamespace(layers={"kernel": layer})
    old.vol = SimpleNamespace(layer_name="kernel")
    assert old.get_dst_addr() == "192.168.56.1"
    modern = inet_sock(sk=_Struct(__sk_common=_Struct(skc_family=2, skc_daddr="10.0.0.1")))
    assert modern.get_dst_addr() == "10.0.0.1"


def test_linux_plugins_run_through_the_legacy_entry_point_when_volatility_is_importable(monkeypatch):
    from app.services.memory import volatility_runner

    monkeypatch.setattr(volatility_runner.importlib.util, "find_spec", lambda name: object())
    argv = volatility_runner._linux_invocation(["vol"])
    assert argv == [sys.executable, "-I", str(volatility_runner.LEGACY_LINUX_ENTRY_POINT)]
    assert volatility_runner.LEGACY_LINUX_ENTRY_POINT.is_file()
    monkeypatch.setattr(volatility_runner.importlib.util, "find_spec", lambda name: None)
    assert volatility_runner._linux_invocation(["vol"]) == ["vol"]
