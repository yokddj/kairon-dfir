"""Unit tests for app.ingest.windows.sam_identity's binary decoding.

These build synthetic F/V/Account-V blobs matching the real, documented
byte layouts (verified against a real SAM hive during the sprint audit --
see the delivery report) rather than depending on a fixture hive file.
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone

from app.ingest.windows.sam_identity import (
    classify_account_status,
    decode_account_flag_labels,
    decode_account_flags,
    decode_f_value,
    decode_machine_sid,
    decode_rid_from_names_value,
    decode_v_string,
    format_rid_subkey_name,
    format_sid,
)


def _filetime_bytes(dt: datetime) -> bytes:
    delta = dt - datetime(1601, 1, 1, tzinfo=timezone.utc)
    ticks = int(delta.total_seconds() * 10_000_000)
    return struct.pack("<Q", ticks)


def _f_value(*, flags: int = 0x0200, last_logon: datetime | None = None, last_password_set: datetime | None = None, bad_password_count: int = 0, logon_count: int = 0) -> bytes:
    buf = bytearray(80)
    buf[8:16] = _filetime_bytes(last_logon) if last_logon else b"\x00" * 8
    buf[24:32] = _filetime_bytes(last_password_set) if last_password_set else b"\x00" * 8
    buf[56:58] = struct.pack("<H", flags)
    buf[64:66] = struct.pack("<H", bad_password_count)
    buf[66:68] = struct.pack("<H", logon_count)
    return bytes(buf)


def _v_value(*, username: str = "", full_name: str = "", comment: str = "") -> bytes:
    base = 0xCC
    parts = [username.encode("utf-16-le"), full_name.encode("utf-16-le"), comment.encode("utf-16-le")]
    header = bytearray(0x2C)
    offset = 0
    for i, part in enumerate(parts):
        header_pos = 0x0C + i * 0x0C
        struct.pack_into("<II", header, header_pos, offset, len(part))
        offset += len(part)
    return bytes(header) + b"\x00" * (base - len(header)) + b"".join(parts)


def _account_v_value(machine_sid: str) -> bytes:
    parts = machine_sid.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    sub_authorities = [int(p) for p in parts[3:]]
    sid_bytes = bytes([revision, len(sub_authorities)]) + authority.to_bytes(6, "big") + struct.pack("<" + "I" * len(sub_authorities), *sub_authorities)
    return b"\x00" * 40 + sid_bytes


class TestRidDecoding:
    def test_rid_comes_from_value_type_field(self) -> None:
        assert decode_rid_from_names_value(1001) == 1001

    def test_format_rid_subkey_name_is_uppercase_hex(self) -> None:
        assert format_rid_subkey_name(1001) == "000003E9"
        assert format_rid_subkey_name(500) == "000001F4"


class TestFValueDecoding:
    def test_disabled_flag_classified_as_disabled(self) -> None:
        f = _f_value(flags=0x0211)  # disabled + password_never_expires
        decoded = decode_f_value(f)
        assert decoded["account_status"] == "disabled"
        assert "disabled" in decoded["flag_labels"]
        assert "password_never_expires" in decoded["flag_labels"]

    def test_locked_flag_takes_precedence_over_disabled(self) -> None:
        flags = (1 << 0) | (1 << 10)  # disabled AND auto_locked
        assert classify_account_status(flags) == "locked"

    def test_disabled_bit_never_lost_when_locked_takes_precedence(self) -> None:
        # account_status is a single "primary state" (locked wins over
        # disabled when both bits are set -- Windows itself treats a
        # locked-out account as unusable regardless of its disabled bit),
        # but the underlying disabled condition must still be visible: it
        # is never dropped from the full flag list, only demoted from the
        # single-value summary. Callers that need every coexisting
        # condition read attributes.account_flags (all raised bits),
        # never account_status alone.
        f = _f_value(flags=(1 << 0) | (1 << 10) | (1 << 9))  # disabled + auto_locked + password_never_expires
        decoded = decode_f_value(f)
        assert decoded["account_status"] == "locked"
        assert set(decoded["flag_labels"]) == {"disabled", "account_auto_locked", "password_never_expires"}

    def test_normal_unflagged_account_is_active(self) -> None:
        f = _f_value(flags=0x0210)  # only password_never_expires
        decoded = decode_f_value(f)
        assert decoded["account_status"] == "active"

    def test_last_logon_and_password_set_decode_real_timestamps(self) -> None:
        last_logon = datetime(2024, 3, 22, 10, 57, 33, tzinfo=timezone.utc)
        last_pwd_set = datetime(2024, 1, 11, 17, 46, 26, tzinfo=timezone.utc)
        f = _f_value(last_logon=last_logon, last_password_set=last_pwd_set, logon_count=8, bad_password_count=2)
        decoded = decode_f_value(f)
        assert abs((decoded["last_logon"] - last_logon).total_seconds()) < 1
        assert abs((decoded["last_password_set"] - last_pwd_set).total_seconds()) < 1
        assert decoded["logon_count"] == 8
        assert decoded["bad_password_count"] == 2

    def test_zero_filetime_is_never_logged_in_as_a_real_date(self) -> None:
        f = _f_value()
        decoded = decode_f_value(f)
        assert decoded["last_logon"] is None
        assert decoded["last_password_set"] is None

    def test_truncated_blob_never_guesses_a_partial_field(self) -> None:
        assert decode_f_value(b"\x00" * 10) == {}
        assert decode_account_flags(b"\x00" * 10) is None

    def test_flag_labels_decode_multiple_bits(self) -> None:
        flags = (1 << 2) | (1 << 9)  # password_not_required + password_never_expires
        labels = decode_account_flag_labels(flags)
        assert set(labels) == {"password_not_required", "password_never_expires"}


class TestVValueDecoding:
    def test_decodes_username_fullname_comment(self) -> None:
        v = _v_value(username="bob", full_name="", comment="")
        assert decode_v_string(v, 0x0C) == "bob"

    def test_empty_string_field_returns_none_not_empty_string(self) -> None:
        v = _v_value(username="Administrator", comment="Built-in account")
        assert decode_v_string(v, 0x18) is None  # full_name empty
        assert decode_v_string(v, 0x24) == "Built-in account"

    def test_out_of_range_offset_returns_none_not_garbage(self) -> None:
        v = _v_value(username="bob")
        # Corrupt the header to point past the end of the blob.
        corrupted = bytearray(v)
        struct.pack_into("<II", corrupted, 0x0C, 999999, 10)
        assert decode_v_string(bytes(corrupted), 0x0C) is None

    def test_truncated_blob_never_crashes(self) -> None:
        assert decode_v_string(b"\x00" * 4, 0x0C) is None


class TestMachineSidDecoding:
    def test_decodes_real_shaped_machine_sid(self) -> None:
        sid = "S-1-5-21-3104471185-970636935-942730776"
        account_v = _account_v_value(sid)
        assert decode_machine_sid(account_v) == sid

    def test_format_sid_appends_rid(self) -> None:
        assert format_sid("S-1-5-21-1-2-3", 1001) == "S-1-5-21-1-2-3-1001"

    def test_truncated_blob_never_guesses_a_sid(self) -> None:
        assert decode_machine_sid(b"\x00" * 4) is None
