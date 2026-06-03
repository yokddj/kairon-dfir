from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import io
import subprocess
import shutil
from pathlib import Path
from shutil import which
from zipfile import ZipFile

from app.core.storage import ensure_within_directory, sanitize_relative_path
from app.ingest.archive import should_ignore_path

SEVEN_ZIP_CONTAINER_SUFFIXES: tuple[tuple[str, ...], ...] = (
    (".7z",),
    (".rar",),
    (".tar",),
    (".gz",),
    (".bz2",),
    (".xz",),
    (".tgz",),
    (".tbz2",),
    (".txz",),
    (".tar", ".gz"),
    (".tar", ".bz2"),
    (".tar", ".xz"),
)


@dataclass
class ContainerEntry:
    path: str
    size: int
    compressed_size: int | None
    mtime: str | None
    is_dir: bool
    ignored: bool
    reason: str | None
    container_type: str
    local_path: str | None = None

    @property
    def extension(self) -> str:
        return Path(self.path).suffix.lower()


class EvidenceContainer:
    type: str

    def list_entries(self) -> list[ContainerEntry]:
        raise NotImplementedError

    def open_entry(self, path: str):
        raise NotImplementedError

    def extract_entry(self, path: str, destination: Path) -> Path:
        raise NotImplementedError

    def extract_entries(self, paths: list[str], destination: Path) -> list[dict]:
        results: list[dict] = []
        for item in paths:
            try:
                extracted = self.extract_entry(item, destination)
                results.append({"path": item, "status": "extracted", "local_path": str(extracted), "error": None})
            except Exception as exc:  # noqa: BLE001
                results.append({"path": item, "status": "failed", "local_path": None, "error": str(exc)})
        return results

    def get_metadata(self, path: str) -> ContainerEntry | None:
        for entry in self.list_entries():
            if entry.path == path:
                return entry
        return None


def _resolve_7z_binary() -> str:
    for candidate in ("7z", "7za"):
        resolved = which(candidate)
        if resolved:
            return resolved
    raise RuntimeError("7z binary not available")


def _matches_suffix_parts(path: Path, suffix_parts: tuple[str, ...]) -> bool:
    suffixes = tuple(part.lower() for part in path.suffixes)
    return suffixes[-len(suffix_parts):] == suffix_parts


def is_supported_archive_container(path: Path) -> bool:
    source = Path(path)
    if source.suffix.lower() == ".zip":
        return True
    return any(_matches_suffix_parts(source, suffix_parts) for suffix_parts in SEVEN_ZIP_CONTAINER_SUFFIXES)


def _run_7z_command(args: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [_resolve_7z_binary(), *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class _SevenZipEntryStream(io.RawIOBase):
    def __init__(self, process: subprocess.Popen[bytes]):
        self._process = process
        self._stdout = process.stdout

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if self._stdout is None:
            return b""
        return self._stdout.read(size)

    def close(self) -> None:
        try:
            if self._stdout is not None and not self._stdout.closed:
                self._stdout.close()
            if self._process.stderr is not None and not self._process.stderr.closed:
                self._process.stderr.close()
            if self._process.poll() is None:
                self._process.terminate()
            self._process.wait(timeout=5)
        except Exception:
            if self._process.poll() is None:
                self._process.kill()
        finally:
            super().close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def _safe_zip_mtime(date_time: tuple[int, int, int, int, int, int] | None) -> str | None:
    if not date_time:
        return None
    try:
        year, month, day, hour, minute, second = (list(date_time) + [0, 0, 0, 0, 0, 0])[:6]
        if year < 1980:
            year = 1980
        if month < 1 or month > 12:
            return None
        if day < 1 or day > 31:
            return None
        if hour < 0 or hour > 23:
            return None
        if minute < 0 or minute > 59:
            return None
        if second < 0 or second > 59:
            return None
        return datetime(year, month, day, hour, minute, second, tzinfo=UTC).isoformat()
    except (TypeError, ValueError):
        return None


class ZipEvidenceContainer(EvidenceContainer):
    def __init__(self, archive_path: Path):
        self.archive_path = Path(archive_path)
        self.type = "zip"
        self._entries: list[ContainerEntry] | None = None

    def list_entries(self) -> list[ContainerEntry]:
        if self._entries is not None:
            return self._entries
        entries: list[ContainerEntry] = []
        with ZipFile(self.archive_path) as archive:
            for member in archive.infolist():
                member_path = member.filename.rstrip("/")
                if not member_path:
                    continue
                is_dir = member.is_dir()
                ignored, reason = should_ignore_path(Path(member_path), size=member.file_size, is_dir=is_dir)
                mtime = _safe_zip_mtime(member.date_time)
                entries.append(
                    ContainerEntry(
                        path=member_path,
                        size=member.file_size,
                        compressed_size=member.compress_size,
                        mtime=mtime,
                        is_dir=is_dir,
                        ignored=ignored,
                        reason=reason,
                        container_type="zip",
                        local_path=None,
                    )
                )
        self._entries = entries
        return entries

    def open_entry(self, path: str):
        archive = ZipFile(self.archive_path)
        return archive.open(path)

    def extract_entry(self, path: str, destination: Path) -> Path:
        destination.mkdir(parents=True, exist_ok=True)
        relative = sanitize_relative_path(path)
        target = destination / relative
        ensure_within_directory(destination, target)
        target.parent.mkdir(parents=True, exist_ok=True)
        with ZipFile(self.archive_path) as archive:
            with archive.open(path) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)
        return target

    def extract_entries(self, paths: list[str], destination: Path) -> list[dict]:
        destination.mkdir(parents=True, exist_ok=True)
        results: list[dict] = []
        with ZipFile(self.archive_path) as archive:
            for item in paths:
                try:
                    relative = sanitize_relative_path(item)
                    target = destination / relative
                    ensure_within_directory(destination, target)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(item) as src, target.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
                    results.append({"path": item, "status": "extracted", "local_path": str(target), "error": None})
                except Exception as exc:  # noqa: BLE001
                    results.append({"path": item, "status": "failed", "local_path": None, "error": str(exc)})
        return results


class DirectoryEvidenceContainer(EvidenceContainer):
    def __init__(self, root: Path):
        self.root = Path(root)
        self.type = "directory"
        self._entries: list[ContainerEntry] | None = None

    def list_entries(self) -> list[ContainerEntry]:
        if self._entries is not None:
            return self._entries
        entries: list[ContainerEntry] = []
        for item in sorted(self.root.rglob("*")):
            relative = str(item.relative_to(self.root)).replace("\\", "/")
            is_dir = item.is_dir()
            size = item.stat().st_size if item.is_file() else 0
            ignored, reason = should_ignore_path(Path(relative), size=size, is_dir=is_dir)
            entries.append(
                ContainerEntry(
                    path=relative,
                    size=size,
                    compressed_size=None,
                    mtime=datetime.fromtimestamp(item.stat().st_mtime, tz=UTC).isoformat(),
                    is_dir=is_dir,
                    ignored=ignored,
                    reason=reason,
                    container_type="directory",
                    local_path=str(item),
                )
            )
        self._entries = entries
        return entries

    def open_entry(self, path: str):
        return (self.root / path).open("rb")

    def extract_entry(self, path: str, destination: Path) -> Path:
        destination.mkdir(parents=True, exist_ok=True)
        source = self.root / path
        relative = sanitize_relative_path(path)
        target = destination / relative
        ensure_within_directory(destination, target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        return target

    def extract_entries(self, paths: list[str], destination: Path) -> list[dict]:
        destination.mkdir(parents=True, exist_ok=True)
        results: list[dict] = []
        for item in paths:
            try:
                source = self.root / item
                relative = sanitize_relative_path(item)
                target = destination / relative
                ensure_within_directory(destination, target)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                results.append({"path": item, "status": "extracted", "local_path": str(target), "error": None})
            except Exception as exc:  # noqa: BLE001
                results.append({"path": item, "status": "failed", "local_path": None, "error": str(exc)})
        return results


class SevenZipEvidenceContainer(EvidenceContainer):
    def __init__(self, archive_path: Path):
        self.archive_path = Path(archive_path)
        self.type = "7z"
        self._entries: list[ContainerEntry] | None = None

    def list_entries(self) -> list[ContainerEntry]:
        if self._entries is not None:
            return self._entries
        result = _run_7z_command(["l", "-slt", str(self.archive_path)])
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode("utf-8", errors="replace") or f"Unable to inspect 7z archive: {self.archive_path}")
        lines = result.stdout.decode("utf-8", errors="replace").splitlines()
        entries: list[ContainerEntry] = []
        current: dict[str, str] = {}
        listing_started = False

        def flush_entry() -> None:
            path = (current.get("Path") or "").rstrip("/")
            if not path or path == str(self.archive_path):
                current.clear()
                return
            if "Size" not in current and "Folder" not in current:
                current.clear()
                return
            is_dir = current.get("Folder") == "+"
            size = int(current.get("Size") or 0)
            packed_size_raw = current.get("Packed Size") or None
            compressed_size = int(packed_size_raw) if packed_size_raw and packed_size_raw.isdigit() else None
            ignored, reason = should_ignore_path(Path(path), size=size, is_dir=is_dir)
            entries.append(
                ContainerEntry(
                    path=path,
                    size=size,
                    compressed_size=compressed_size,
                    mtime=current.get("Modified") or None,
                    is_dir=is_dir,
                    ignored=ignored,
                    reason=reason,
                    container_type="7z",
                    local_path=None,
                )
            )
            current.clear()

        for raw_line in lines:
            line = raw_line.strip()
            if line.startswith("----------"):
                listing_started = True
                continue
            if not listing_started:
                continue
            if not line:
                flush_entry()
                continue
            if " = " not in line:
                continue
            key, value = line.split(" = ", 1)
            current[key] = value
        flush_entry()
        self._entries = entries
        return entries

    def open_entry(self, path: str):
        process = subprocess.Popen(
            [_resolve_7z_binary(), "x", "-so", str(self.archive_path), path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return _SevenZipEntryStream(process)

    def extract_entry(self, path: str, destination: Path) -> Path:
        destination.mkdir(parents=True, exist_ok=True)
        relative = sanitize_relative_path(path)
        target = destination / relative
        ensure_within_directory(destination, target)
        target.parent.mkdir(parents=True, exist_ok=True)
        result = _run_7z_command(["x", "-so", str(self.archive_path), path])
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode("utf-8", errors="replace") or f"Unable to extract {path} from {self.archive_path}")
        with target.open("wb") as handle:
            handle.write(result.stdout)
        return target

    def extract_entries(self, paths: list[str], destination: Path) -> list[dict]:
        destination.mkdir(parents=True, exist_ok=True)
        results: list[dict] = []
        safe_paths: list[tuple[str, Path]] = []
        for item in paths:
            try:
                relative = sanitize_relative_path(item)
                target = destination / relative
                ensure_within_directory(destination, target)
                target.parent.mkdir(parents=True, exist_ok=True)
                safe_paths.append((item, target))
            except Exception as exc:  # noqa: BLE001
                results.append({"path": item, "status": "failed", "local_path": None, "error": str(exc)})

        if not safe_paths:
            return results

        extracted_by_path: dict[str, dict] = {}
        chunk_size = 250
        for index in range(0, len(safe_paths), chunk_size):
            chunk = safe_paths[index : index + chunk_size]
            chunk_paths = [item for item, _target in chunk]
            batch = _run_7z_command(["x", str(self.archive_path), f"-o{destination}", "-y", *chunk_paths])
            batch_error = (batch.stderr or batch.stdout or b"").decode("utf-8", errors="replace").strip() or None
            for item, target in chunk:
                if target.exists() and target.is_file():
                    extracted_by_path[item] = {"path": item, "status": "extracted", "local_path": str(target), "error": None}
                    continue
                if batch.returncode == 0:
                    extracted_by_path[item] = {"path": item, "status": "failed", "local_path": None, "error": "7z reported success but output file is missing"}
                    continue
                try:
                    extracted = self.extract_entry(item, destination)
                    extracted_by_path[item] = {"path": item, "status": "extracted", "local_path": str(extracted), "error": None}
                except Exception as exc:  # noqa: BLE001
                    extracted_by_path[item] = {"path": item, "status": "failed", "local_path": None, "error": str(exc) or batch_error}

        results.extend(extracted_by_path[item] for item, _target in safe_paths)
        return results


def open_evidence_container(source: Path) -> EvidenceContainer:
    source = Path(source)
    if source.is_dir():
        return DirectoryEvidenceContainer(source)
    if source.suffix.lower() == ".zip":
        return ZipEvidenceContainer(source)
    if any(_matches_suffix_parts(source, suffix_parts) for suffix_parts in SEVEN_ZIP_CONTAINER_SUFFIXES):
        return SevenZipEvidenceContainer(source)
    raise ValueError(f"Unsupported Velociraptor container type: {source}")


def inventory_summary(entries: list[ContainerEntry]) -> dict:
    return {
        "total_entries": len(entries),
        "ignored_entries": sum(1 for entry in entries if entry.ignored),
        "ignored_macos_entries": sum(1 for entry in entries if entry.reason in {"ignored_macos_directory", "ignored_macos_metadata"}),
        "total_size": sum(entry.size for entry in entries if not entry.is_dir),
    }
