"""Password-protected ZIP archives (ZipCrypto or AES).

Detected from the central directory (no password needed). With the password,
the archive is decrypted once at registration into a plain ZIP that becomes
the evidence's working container, so extraction, discovery and the raw
backends that call 7-Zip on the original archive never need it again. The
password is used for that one 7-Zip run and is not stored.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

from app.core.config import get_settings

_ENCRYPTED_FLAG = 0x1


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


def password_required_message(name: str) -> str:
    return f"{name} is password-protected. Enter its password to process it."


def _run_7z(args: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    # -p is always passed, so 7-Zip never waits for a password on stdin.
    return subprocess.run(["7z", *args], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout, check=False)


def _wrong_password(result: subprocess.CompletedProcess[str]) -> bool:
    output = f"{result.stdout}\n{result.stderr}".lower()
    return "wrong password" in output or "cannot open encrypted archive" in output


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


def decrypt_zip(source: Path, password: str, target: Path) -> dict:
    """Extract with 7-Zip into a scratch folder and repack as a plain ZIP
    (stored, written atomically). Member times are kept."""
    check_zip_password(source, password)
    settings = get_settings()
    partial = target.with_name(f"{target.name}.partial")
    files = 0
    size = 0
    with tempfile.TemporaryDirectory(dir=settings.backend_temp_dir) as scratch:
        scratch_dir = Path(scratch)
        result = _run_7z(["x", f"-p{password}", "-y", f"-o{scratch_dir}", str(source)], timeout=settings.archive_extraction_timeout_seconds)
        if result.returncode != 0:
            if _wrong_password(result):
                raise ArchivePasswordError("archive_password_invalid", f"The password for {source.name} is not correct.")
            raise ArchivePasswordError("archive_decryption_failed", f"{source.name} could not be decrypted: {(result.stderr or result.stdout).strip()[-300:]}")
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
    return {"format": "encrypted_zip", "files": files, "bytes": size}


def move_aside(path: Path, folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    destination = folder / path.name
    shutil.move(str(path), destination)
    return destination
