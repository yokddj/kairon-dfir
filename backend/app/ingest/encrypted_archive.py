"""Password-protected archives: ZIP (ZipCrypto or AES), 7z and RAR.

Detected without a password (ZIP from its central directory; 7z and RAR from
their listing, which 7-Zip/unar can produce for an encrypted-content archive,
and unar also for one with an encrypted header). With the password, the
archive is decrypted once at registration into a plain ZIP that becomes the
evidence's working container, so extraction, discovery and the raw backends
that call 7-Zip on the original archive never need it again. The password is
used for that one run and is not stored.

ZIP and 7z are decrypted with 7-Zip (``7z``); RAR goes through ``unar``
instead, because 7-Zip's own RAR reader cannot decompress RAR's encrypted
data streams (it can only read an encrypted member stored without
compression) -- confirmed against real RAR3 and RAR5 archives, where 7-Zip
fails with "Unsupported Method" and unar extracts them correctly.
"""

from __future__ import annotations

from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import zipfile

from app.core.config import get_settings

_ENCRYPTED_FLAG = 0x1

ENCRYPTED_ARCHIVE_SUFFIXES = (".zip", ".7z", ".rar")


class ArchivePasswordError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def encrypted_zip_members(path: Path) -> list[zipfile.ZipInfo]:
    path = Path(path)
    if path.suffix.lower() != ".zip" or not path.is_file():
        return []
    try:
        with zipfile.ZipFile(path) as archive:
            return [member for member in archive.infolist() if member.flag_bits & _ENCRYPTED_FLAG and not member.is_dir()]
    except (zipfile.BadZipFile, OSError):
        return []


def is_encrypted_zip(path: Path) -> bool:
    return bool(encrypted_zip_members(path))


def _is_encrypted_seven_zip(path: Path) -> bool:
    """A .7z with an encrypted member, from 7-Zip's listing (``Encrypted = +``);
    reading it never needs the password. With an encrypted header (``-mhe``),
    7-Zip cannot even list member names without the password and fails the
    same way a wrong password would -- that failure means encrypted here,
    since no password was given."""
    try:
        result = _run_7z(["l", "-slt", "-p", str(path)], timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        # 7z missing or unresponsive: extraction will raise its own clear
        # error later (app.ingest.archive); detection conservatively says
        # "not encrypted" rather than failing preflight entirely.
        return False
    if result.returncode != 0:
        return _wrong_password(result)
    return "\nEncrypted = +" in f"\n{result.stdout}"


def _is_encrypted_rar(path: Path) -> bool:
    """A .rar that is encrypted (content or header), from unar's own listing
    (``lsarProperties.XADIsEncrypted``). A header-encrypted archive cannot
    even list its member names without the password -- lsar asks for one on
    stderr and never finishes its JSON on stdout, so that is checked first."""
    try:
        result = _run_lsar(["-j", str(path)], timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if "password" in result.stderr.lower():
        return True
    try:
        report = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return False
    if report.get("lsarProperties", {}).get("XADIsEncrypted"):
        return True
    return any(entry.get("XADIsEncrypted") for entry in report.get("lsarContents") or [])


def is_encrypted_archive(path: Path) -> bool:
    """Any supported container format (ZIP, 7z, RAR) whose content needs a
    password to read, detected without one."""
    path = Path(path)
    suffix = path.suffix.lower()
    if not path.is_file():
        return False
    if suffix == ".zip":
        return is_encrypted_zip(path)
    if suffix == ".7z":
        return _is_encrypted_seven_zip(path)
    if suffix == ".rar":
        return _is_encrypted_rar(path)
    return False


def password_required_message(name: str) -> str:
    return f"{name} is password-protected. Enter its password to process it."


def _run_7z(args: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    # -p is always passed, so 7-Zip never waits for a password on stdin.
    return subprocess.run(["7z", *args], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout, check=False)


def _run_lsar(args: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["lsar", *args], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout, check=False)


def _run_unar(args: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["unar", *args], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout, check=False)


def _wrong_password(result: subprocess.CompletedProcess[str]) -> bool:
    output = f"{result.stdout}\n{result.stderr}".lower()
    return "wrong password" in output or "cannot open encrypted archive" in output or "missing or wrong password" in output


def _smallest_rar_member(path: Path) -> str | None:
    """The smallest non-empty member's name, read from unar's listing;
    probing it is cheaper than extracting (or testing) the whole archive.
    ``None`` when the header itself is encrypted (there is no name to read
    without the password) or every member is empty (an empty file decrypts
    to nothing with any password, so it cannot verify one) -- the password
    check below extracts the whole archive instead."""
    result = _run_lsar(["-j", str(path)], timeout=120)
    try:
        report = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return None
    entries = [entry for entry in report.get("lsarContents") or [] if entry.get("XADFileName") and (entry.get("XADCompressedSize") or 0) > 0]
    if not entries:
        return None
    smallest = min(entries, key=lambda entry: entry.get("XADCompressedSize") or 0)
    return smallest.get("XADFileName")


def check_zip_password(path: Path, password: str | None) -> None:
    """Raises unless ``password`` opens the archive. Tests the smallest
    encrypted member only, so a large archive is not read twice."""
    members = encrypted_zip_members(path)
    if not members:
        return
    if not password:
        raise ArchivePasswordError("archive_password_required", password_required_message(Path(path).name))
    probe = min(members, key=lambda member: member.file_size)
    result = _run_7z(["t", f"-p{password}", "-y", str(path), probe.filename], timeout=600)
    if result.returncode != 0:
        if _wrong_password(result):
            raise ArchivePasswordError("archive_password_invalid", f"The password for {Path(path).name} is not correct.")
        raise ArchivePasswordError("archive_password_check_failed", f"{Path(path).name} could not be opened with that password: {(result.stderr or result.stdout).strip()[-300:]}")


def _check_seven_zip_password(path: Path, password: str | None) -> None:
    if not _is_encrypted_seven_zip(path):
        return
    if not password:
        raise ArchivePasswordError("archive_password_required", password_required_message(Path(path).name))
    result = _run_7z(["t", f"-p{password}", "-y", str(path)], timeout=600)
    if result.returncode != 0:
        if _wrong_password(result):
            raise ArchivePasswordError("archive_password_invalid", f"The password for {Path(path).name} is not correct.")
        raise ArchivePasswordError("archive_password_check_failed", f"{Path(path).name} could not be opened with that password: {(result.stderr or result.stdout).strip()[-300:]}")


def _check_rar_password(path: Path, password: str | None) -> None:
    if not _is_encrypted_rar(path):
        return
    if not password:
        raise ArchivePasswordError("archive_password_required", password_required_message(Path(path).name))
    with tempfile.TemporaryDirectory(dir=get_settings().backend_temp_dir) as scratch:
        probe = _smallest_rar_member(path)
        args = ["-p", password, "-f", "-D", str(path)]
        if probe:
            args.append(probe)
        args += ["-o", scratch]
        result = _run_unar(args, timeout=600)
        if result.returncode != 0:
            if _wrong_password(result):
                raise ArchivePasswordError("archive_password_invalid", f"The password for {Path(path).name} is not correct.")
            raise ArchivePasswordError("archive_password_check_failed", f"{Path(path).name} could not be opened with that password: {(result.stderr or result.stdout).strip()[-300:]}")


def check_archive_password(path: Path, password: str | None) -> None:
    """Raises unless ``password`` opens the archive (ZIP, 7z or RAR).
    A no-op for an archive that is not encrypted."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".zip":
        check_zip_password(path, password)
    elif suffix == ".7z":
        _check_seven_zip_password(path, password)
    elif suffix == ".rar":
        _check_rar_password(path, password)


def _repack_as_zip(scratch_dir: Path, target: Path) -> dict:
    partial = target.with_name(f"{target.name}.partial")
    files = 0
    size = 0
    try:
        with zipfile.ZipFile(partial, "w", compression=zipfile.ZIP_STORED, allowZip64=True, strict_timestamps=False) as archive:
            for path in sorted(scratch_dir.rglob("*")):
                if not path.is_file() or path.is_symlink():
                    continue
                archive.write(path, path.relative_to(scratch_dir).as_posix())
                files += 1
                size += path.stat().st_size
                path.unlink()
        partial.replace(target)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    return {"files": files, "bytes": size}


def decrypt_zip(source: Path, password: str, target: Path) -> dict:
    """Extract with 7-Zip into a scratch folder and repack as a plain ZIP
    (stored, written atomically). Member times are kept."""
    check_zip_password(source, password)
    settings = get_settings()
    with tempfile.TemporaryDirectory(dir=settings.backend_temp_dir) as scratch:
        scratch_dir = Path(scratch)
        result = _run_7z(["x", f"-p{password}", "-y", f"-o{scratch_dir}", str(source)], timeout=settings.archive_extraction_timeout_seconds)
        if result.returncode != 0:
            if _wrong_password(result):
                raise ArchivePasswordError("archive_password_invalid", f"The password for {source.name} is not correct.")
            raise ArchivePasswordError("archive_decryption_failed", f"{source.name} could not be decrypted: {(result.stderr or result.stdout).strip()[-300:]}")
        summary = _repack_as_zip(scratch_dir, target)
    return {"format": "encrypted_zip", **summary}


def decrypt_seven_zip(source: Path, password: str, target: Path) -> dict:
    """Extract with 7-Zip (which decompresses 7z's own encrypted content
    fine, unlike RAR's) into a scratch folder and repack as a plain ZIP."""
    _check_seven_zip_password(source, password)
    settings = get_settings()
    with tempfile.TemporaryDirectory(dir=settings.backend_temp_dir) as scratch:
        scratch_dir = Path(scratch)
        result = _run_7z(["x", f"-p{password}", "-y", f"-o{scratch_dir}", str(source)], timeout=settings.archive_extraction_timeout_seconds)
        if result.returncode != 0:
            if _wrong_password(result):
                raise ArchivePasswordError("archive_password_invalid", f"The password for {source.name} is not correct.")
            raise ArchivePasswordError("archive_decryption_failed", f"{source.name} could not be decrypted: {(result.stderr or result.stdout).strip()[-300:]}")
        summary = _repack_as_zip(scratch_dir, target)
    return {"format": "encrypted_7z", **summary}


def decrypt_rar(source: Path, password: str, target: Path) -> dict:
    """Extract with unar (7-Zip's RAR reader cannot decompress RAR's own
    encrypted data streams) into a scratch folder and repack as a plain ZIP."""
    _check_rar_password(source, password)
    settings = get_settings()
    with tempfile.TemporaryDirectory(dir=settings.backend_temp_dir) as scratch:
        scratch_dir = Path(scratch)
        result = _run_unar(["-p", password, "-f", "-D", str(source), "-o", str(scratch_dir)], timeout=settings.archive_extraction_timeout_seconds)
        if result.returncode != 0:
            if _wrong_password(result):
                raise ArchivePasswordError("archive_password_invalid", f"The password for {source.name} is not correct.")
            raise ArchivePasswordError("archive_decryption_failed", f"{source.name} could not be decrypted: {(result.stderr or result.stdout).strip()[-300:]}")
        summary = _repack_as_zip(scratch_dir, target)
    return {"format": "encrypted_rar", **summary}


def decrypt_archive(source: Path, password: str, target: Path) -> dict:
    """Decrypt a password-protected ZIP, 7z or RAR into a plain ZIP at
    ``target``. Raises ``ValueError`` for any other suffix."""
    source = Path(source)
    suffix = source.suffix.lower()
    if suffix == ".zip":
        return decrypt_zip(source, password, target)
    if suffix == ".7z":
        return decrypt_seven_zip(source, password, target)
    if suffix == ".rar":
        return decrypt_rar(source, password, target)
    raise ValueError(f"Unsupported encrypted archive suffix: {suffix}")


def move_aside(path: Path, folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    destination = folder / path.name
    shutil.move(str(path), destination)
    return destination
