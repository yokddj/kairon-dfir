from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import PureWindowsPath
import base64
import re
import struct

from app.analysis.suspicious import is_suspicious_double_extension


RECYCLE_SID_RE = re.compile(r"\$recycle\.bin[\\/](?P<sid>S-\d-(?:\d+-){1,14}\d+)[\\/](?P<name>\$[ir].+)$", re.IGNORECASE)
RECYCLE_I_RE = re.compile(r"\$i.+", re.IGNORECASE)
RECYCLE_R_RE = re.compile(r"\$r.+", re.IGNORECASE)
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".msi"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".img"}
SUSPICIOUS_NAME_TOKENS = {"mimikatz", "rclone", "anydesk", "teamviewer", "ngrok", "payload", "password", "credential", "dump", "lsass", "invoice", "runme"}
USER_WRITABLE_TOKENS = ("\\downloads\\", "\\desktop\\", "\\temp\\", "\\appdata\\", "\\users\\public\\", "\\programdata\\")
STARTUP_PATH_TOKENS = ("\\start menu\\programs\\startup\\", "\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\")


def looks_like_recycle_bin_artifact(path, headers: list[str] | None = None) -> bool:
    lower_name = str(getattr(path, "name", path)).lower()
    header_set = {str(header).strip().lower() for header in (headers or []) if header}
    if any(token in lower_name for token in ["rbcmd", "recyclebin", "recycle_bin", "recycle bin"]):
        return True
    if RECYCLE_SID_RE.search(str(path).replace("/", "\\")):
        return True
    return bool({"deletedon", "deletiontime", "originalfilename", "originalpath", "filesize", "sid"} & header_set)


def extract_sid_from_recycle_path(path: str | None) -> str | None:
    if not path:
        return None
    match = RECYCLE_SID_RE.search(path.replace("/", "\\"))
    return match.group("sid") if match else None


def recycle_pair_id_from_name(name: str | None) -> str | None:
    if not name:
        return None
    normalized = name.strip()
    if len(normalized) < 3 or normalized[0] != "$" or normalized[1].lower() not in {"i", "r"}:
        return None
    return normalized[2:]


def recycle_pair_id_from_path(path: str | None) -> str | None:
    if not path:
        return None
    return recycle_pair_id_from_name(path.replace("\\", "/").split("/")[-1])


def is_recycle_i_path(path: str | None) -> bool:
    if not path:
        return False
    return bool(RECYCLE_I_RE.fullmatch(path.replace("\\", "/").split("/")[-1]))


def is_recycle_r_path(path: str | None) -> bool:
    if not path:
        return False
    return bool(RECYCLE_R_RE.fullmatch(path.replace("\\", "/").split("/")[-1]))


def parse_windows_filetime(value: int | None) -> str | None:
    if value in (None, 0):
        return None
    try:
        epoch = datetime(1601, 1, 1, tzinfo=UTC)
        return (epoch + timedelta(microseconds=value / 10)).isoformat()
    except Exception:  # noqa: BLE001
        return None


def basename(path: str | None) -> str | None:
    if not path:
        return None
    normalized = path.replace("/", "\\")
    try:
        return PureWindowsPath(normalized).name or normalized
    except Exception:  # noqa: BLE001
        return normalized.split("\\")[-1] or normalized


def extension(path: str | None) -> str | None:
    name = basename(path)
    if not name or "." not in name:
        return None
    return "." + name.split(".")[-1].lower()


def normalize_windows_path(path: str | None) -> str | None:
    if not path:
        return None
    return str(path).strip().replace("/", "\\")


def infer_drive_letter(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized or len(normalized) < 2:
        return None
    if normalized[1] == ":" and normalized[0].isalpha():
        return normalized[:2].upper()
    return None


def decode_utf16le_path(raw: bytes) -> str | None:
    if not raw:
        return None
    try:
        text = raw.decode("utf-16le", errors="ignore").split("\x00", 1)[0].strip()
        return normalize_windows_path(text) if text else None
    except Exception:  # noqa: BLE001
        return None


def is_valid_windows_original_path(value: str | None) -> bool:
    if not value:
        return False
    normalized = normalize_windows_path(value)
    if not normalized:
        return False
    stripped = normalized.strip().strip("\x00")
    if len(stripped) < 4:
        return False
    if re.fullmatch(r"[A-Za-z0-9^]", stripped):
        return False
    if re.fullmatch(r"[A-Za-z]:?", stripped):
        return False
    if "\\" not in stripped and "/" not in stripped:
        return False
    if re.match(r"^[A-Za-z]:\\", stripped):
        return True
    if stripped.startswith("\\\\"):
        parts = [part for part in stripped.split("\\") if part]
        return len(parts) >= 2
    return False


def _decode_utf16le_candidate(raw: bytes, *, path_length_chars: int | None = None) -> str | None:
    if not raw:
        return None
    try:
        if path_length_chars and path_length_chars > 0:
            text = raw[: path_length_chars * 2].decode("utf-16le", errors="ignore")
        else:
            text = raw.decode("utf-16le", errors="ignore").split("\x00", 1)[0]
        text = text.split("\x00", 1)[0].strip()
        normalized = normalize_windows_path(text) if text else None
        return normalized if is_valid_windows_original_path(normalized) else None
    except Exception:  # noqa: BLE001
        return None


def extract_windows_path_from_i_file_blob(blob: bytes) -> str | None:
    if not blob:
        return None
    for start in range(0, max(len(blob) - 6, 0)):
        drive_match = (
            start + 5 < len(blob)
            and 65 <= blob[start] <= 90
            and blob[start + 1] == 0
            and blob[start + 2] == 58
            and blob[start + 3] == 0
            and blob[start + 4] == 92
            and blob[start + 5] == 0
        )
        unc_match = start + 3 < len(blob) and blob[start : start + 4] == b"\\\x00\\\x00"
        if not drive_match and not unc_match:
            continue
        cursor = start
        collected = bytearray()
        while cursor + 1 < len(blob):
            pair = blob[cursor : cursor + 2]
            if pair == b"\x00\x00":
                break
            collected.extend(pair)
            cursor += 2
            if len(collected) > 2048:
                break
        candidate = _decode_utf16le_candidate(bytes(collected))
        if candidate:
            return candidate
    return None


def parse_recycle_i_bytes(data: bytes) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    if len(data) < 24:
        return {"version": None, "original_file_size": None, "deleted_time": None, "original_path": None}, ["$I file too small to parse"]
    version = struct.unpack_from("<Q", data, 0)[0]
    original_size = struct.unpack_from("<Q", data, 8)[0]
    deleted_filetime = struct.unpack_from("<Q", data, 16)[0]
    original_path = None
    fallback_used = False
    if version >= 2 and len(data) >= 28:
        path_length_chars = struct.unpack_from("<I", data, 24)[0]
        if 0 < path_length_chars <= 4096:
            original_path = _decode_utf16le_candidate(data[28:], path_length_chars=path_length_chars)
        if not original_path:
            original_path = _decode_utf16le_candidate(data[28:])
    if not original_path:
        original_path = _decode_utf16le_candidate(data[24:])
    if not original_path:
        original_path = extract_windows_path_from_i_file_blob(data[24:])
        if original_path:
            warnings.append("original_path_extracted_by_utf16_fallback")
            fallback_used = True
    if not original_path:
        warnings.append("Could not decode original path from $I file")
    return {
        "version": str(version),
        "original_file_size": int(original_size),
        "deleted_time": parse_windows_filetime(deleted_filetime),
        "original_path": original_path,
        "used_utf16_fallback": fallback_used,
    }, warnings


def suspicious_recycle_markers(original_path: str | None, has_r_file: bool, *, file_name: str | None = None) -> tuple[set[str], list[str], int]:
    tags = {"recycle_bin", "file_recycled", "deleted_file"}
    reasons: list[str] = []
    risk = 5
    normalized_path = (original_path or "").lower()
    name = (file_name or basename(original_path) or "").lower()
    ext = extension(original_path or file_name)

    if ext in EXECUTABLE_EXTENSIONS:
        tags.update({"suspicious", "suspicious_deleted_file", "executable_deleted"})
        reasons.append("Deleted executable found in Recycle Bin")
        risk = max(risk, 68)
        if ext in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}:
            tags.add("script_deleted")
            reasons.append("Deleted script found in Recycle Bin")
            risk = max(risk, 78)
    elif ext in ARCHIVE_EXTENSIONS:
        tags.update({"suspicious", "archive_deleted"})
        reasons.append("Deleted archive found in Recycle Bin")
        risk = max(risk, 45)

    if normalized_path and any(token in normalized_path for token in USER_WRITABLE_TOKENS):
        tags.update({"user_writable_path", "suspicious"})
        reasons.append("Deleted file from user-writable path")
        risk = max(risk, 45)
        if "\\downloads\\" in normalized_path:
            tags.add("deleted_download")
            reasons.append("Deleted file from Downloads")
            risk = max(risk, 62)
        if any(token in normalized_path for token in STARTUP_PATH_TOKENS):
            tags.add("startup_path")
            reasons.append("Deleted file from Startup folder")
            risk = max(risk, 82)

    if is_suspicious_double_extension(name):
        tags.update({"double_extension", "suspicious"})
        reasons.append("Deleted file has double extension")
        risk = max(risk, 82)

    if any(token in name for token in SUSPICIOUS_NAME_TOKENS) or any(token in normalized_path for token in SUSPICIOUS_NAME_TOKENS):
        tags.update({"suspicious", "suspicious_deleted_file"})
        reasons.append("Deleted file name contains suspicious keyword")
        risk = max(risk, 62)

    if not has_r_file:
        tags.add("content_missing")
        reasons.append("Recycle Bin pair missing $R content")
        risk = max(risk, 35)

    return tags, reasons, risk


def preview_bytes_as_base64(data: bytes, limit: int = 64) -> str | None:
    if not data:
        return None
    return base64.b64encode(data[:limit]).decode("ascii")
