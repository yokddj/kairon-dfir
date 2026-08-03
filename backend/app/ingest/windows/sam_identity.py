"""Binary decoding for the Windows SAM registry hive's local-account
structures (SAM\\Domains\\Account\\Users).

This is the actual account database Windows itself reads at logon -- the
highest-confidence source for "which local accounts exist on this
machine" available to Kairon. Every offset below was validated against a
real SAM hive (see the sprint audit) before being written here; none of it
is guessed from documentation alone.

Structures decoded (per SysKey-independent, unencrypted fields only --
Kairon never attempts to decrypt password hashes):

- SAM\\Domains\\Account\\Users\\Names\\<username>: a quirk of the SAM
  format stores the account's RID not in the (unnamed) value's *data*, but
  in its *type* field. decode_rid_from_names_value() reads that.
- SAM\\Domains\\Account\\Users\\<RID as 8-digit hex>\\F: a fixed-layout
  binary blob. decode_f_value() reads last_logon / last_password_set /
  bad_password_count / logon_count (FILETIME/WORD fields at fixed offsets)
  and the account-control flag word (offset 0x38) classified by
  classify_account_status()/decode_account_flag_labels().
- SAM\\Domains\\Account\\Users\\<RID as 8-digit hex>\\V: a header of
  (offset, length) pairs relative to a fixed base (0xCC), each pointing at
  a UTF-16LE string in the same blob. decode_v_string() reads one field;
  USERNAME/FULL_NAME/COMMENT_OFFSET_FIELD are the header positions this
  module actually uses.
- SAM\\Domains\\Account\\V: the domain (== local machine, for a
  standalone/non-DC host) SID, stored as the trailing 24 bytes of the
  blob. decode_machine_sid() reads it -- this is what lets the
  ProfileList producer (app.ingest.raw_parsers.profile_list_parser)
  determine whether a cached profile SID actually belongs to *this*
  machine's own account store, or to a different (e.g. domain) authority,
  without ever guessing.

Deliberately NOT decoded here: local group membership (Administrators/
Users/... via SAM\\Domains\\Builtin\\Aliases) -- real, decodable data, but
out of scope for this sprint; documented as a known gap the same way
host.kernel was in the Host Facts sprint. Never inferred from account-
control flags or RID alone.
"""
from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone

# --- F value (account control) -------------------------------------------

F_LAST_LOGON_OFFSET = 8
F_LAST_PASSWORD_SET_OFFSET = 24
F_ACCOUNT_FLAGS_OFFSET = 56
F_BAD_PASSWORD_COUNT_OFFSET = 64
F_LOGON_COUNT_OFFSET = 66

# Bit -> (attribute label, account_status this bit forces). Order matters
# for classify_account_status: disabled/locked take precedence over any
# other bit, mirroring how Windows itself treats these as mutually
# overriding an "active" account.
_FLAG_BITS: dict[int, str] = {
    0: "disabled",
    1: "home_directory_required",
    2: "password_not_required",
    3: "temporary_duplicate_account",
    4: "normal_account",
    5: "mns_logon_account",
    6: "interdomain_trust_account",
    7: "workstation_trust_account",
    8: "server_trust_account",
    9: "password_never_expires",
    10: "account_auto_locked",
    11: "encrypted_text_password_allowed",
}


def decode_rid_from_names_value(value_type: int) -> int:
    """SAM\\...\\Users\\Names\\<username>'s single value stores the
    account's RID in its *type* field, not its data -- a documented quirk
    of the SAM format, not a Kairon convention."""
    return int(value_type)


def format_rid_subkey_name(rid: int) -> str:
    return format(rid, "08X")


def _filetime_to_datetime(raw: bytes) -> datetime | None:
    if len(raw) != 8:
        return None
    value = struct.unpack("<Q", raw)[0]
    if value == 0:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value / 10)
    except OverflowError:
        return None


def decode_account_flags(f_value: bytes) -> int | None:
    if len(f_value) < F_ACCOUNT_FLAGS_OFFSET + 2:
        return None
    return struct.unpack("<H", f_value[F_ACCOUNT_FLAGS_OFFSET:F_ACCOUNT_FLAGS_OFFSET + 2])[0]


def decode_account_flag_labels(flags: int) -> list[str]:
    return [label for bit, label in _FLAG_BITS.items() if flags & (1 << bit)]


def classify_account_status(flags: int) -> str:
    """The only account_status classification Kairon trusts for Windows --
    read directly from SAM's own control-flag bits, never inferred from
    anything else (privileges, group membership, shell-equivalent, ...).

    Contract: account_status is deliberately a single PRIMARY state, not a
    union of every coexisting condition -- "locked" wins over "disabled"
    when both bits are set, because Windows itself treats a locked-out
    account as unusable regardless of its disabled bit. This never drops
    information: every raised bit (disabled, locked, password_never_
    expires, password_not_required, ...) is separately preserved, in full,
    as attributes.account_flags (see decode_account_flag_labels()) on the
    emitted HostUserFact row. A caller that needs to know about a
    coexisting condition reads attributes.account_flags, never infers it
    from account_status alone.

    Only three values are ever returned: "active", "disabled", "locked".
    Never "password_expired" -- SAM's control-flag word has no such bit;
    determining actual password expiry needs the domain/local password-age
    policy, which Kairon does not have, so that is never guessed. Never
    "unknown" from this function either -- when the F value can't be read
    at all, the caller (see sam_identity_parser.py) leaves account_status
    as None (which resolves as the standard "missing" field state,
    identical to every other not-observed fact in Kairon), rather than
    this function fabricating a fourth string value for "I don't know".
    """
    if flags & (1 << 10):  # account_auto_locked
        return "locked"
    if flags & (1 << 0):  # disabled
        return "disabled"
    return "active"


def decode_f_value(f_value: bytes) -> dict:
    """Returns {} for a blob too short to safely read -- never guesses a
    partial/truncated field."""
    flags = decode_account_flags(f_value)
    result: dict = {}
    if len(f_value) >= F_LAST_LOGON_OFFSET + 8:
        result["last_logon"] = _filetime_to_datetime(f_value[F_LAST_LOGON_OFFSET:F_LAST_LOGON_OFFSET + 8])
    if len(f_value) >= F_LAST_PASSWORD_SET_OFFSET + 8:
        result["last_password_set"] = _filetime_to_datetime(f_value[F_LAST_PASSWORD_SET_OFFSET:F_LAST_PASSWORD_SET_OFFSET + 8])
    if flags is not None:
        result["flags"] = flags
        result["account_status"] = classify_account_status(flags)
        result["flag_labels"] = decode_account_flag_labels(flags)
    if len(f_value) >= F_BAD_PASSWORD_COUNT_OFFSET + 2:
        result["bad_password_count"] = struct.unpack("<H", f_value[F_BAD_PASSWORD_COUNT_OFFSET:F_BAD_PASSWORD_COUNT_OFFSET + 2])[0]
    if len(f_value) >= F_LOGON_COUNT_OFFSET + 2:
        result["logon_count"] = struct.unpack("<H", f_value[F_LOGON_COUNT_OFFSET:F_LOGON_COUNT_OFFSET + 2])[0]
    return result


# --- V value (username / full name / comment) ----------------------------

V_STRING_BASE_OFFSET = 0xCC
V_USERNAME_HEADER_OFFSET = 0x0C
V_FULL_NAME_HEADER_OFFSET = 0x18
V_COMMENT_HEADER_OFFSET = 0x24


def decode_v_string(v_value: bytes, header_offset: int) -> str | None:
    """Reads one (relative_offset, length) pair from the V blob's header
    and decodes the UTF-16LE string it points to. Returns None (never a
    guessed/partial string) if the header or the pointed-to range doesn't
    actually fit inside this blob."""
    if len(v_value) < header_offset + 8:
        return None
    relative_offset, length = struct.unpack("<II", v_value[header_offset:header_offset + 8])
    start = V_STRING_BASE_OFFSET + relative_offset
    end = start + length
    if start < 0 or length < 0 or end > len(v_value):
        return None
    try:
        value = v_value[start:end].decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    return value or None


# --- Domain/machine SID (SAM\Domains\Account\V) ---------------------------

def decode_machine_sid(account_v_value: bytes) -> str | None:
    """The domain SID trails the SAM\\Domains\\Account\\V blob as a
    standard SID structure (revision, sub-authority count, 6-byte
    authority, N little-endian sub-authorities). For a standalone or
    workgroup host (never joined to an Active Directory domain) this SID
    IS the local machine's own SID -- the same authority every local
    account's RID is minted under."""
    if len(account_v_value) < 8:
        return None
    tail = account_v_value[-24:] if len(account_v_value) >= 24 else account_v_value
    if len(tail) < 8:
        return None
    revision = tail[0]
    sub_authority_count = tail[1]
    if sub_authority_count == 0 or sub_authority_count > 15:
        return None
    authority = int.from_bytes(tail[2:8], "big")
    needed = 8 + 4 * sub_authority_count
    if len(tail) < needed:
        return None
    sub_authorities = struct.unpack("<" + "I" * sub_authority_count, tail[8:needed])
    return f"S-{revision}-{authority}-" + "-".join(str(value) for value in sub_authorities)


def format_sid(machine_sid: str, rid: int) -> str:
    return f"{machine_sid}-{rid}"
