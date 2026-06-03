from abc import ABC, abstractmethod
import csv
from pathlib import Path
import sys


class ArtifactParser(ABC):
    @abstractmethod
    def can_parse(self, path: Path, headers: list[str] | None = None) -> bool:
        raise NotImplementedError

    @abstractmethod
    def parse(self, path: Path, **kwargs):
        raise NotImplementedError


def ensure_csv_field_limit() -> int:
    limit = sys.maxsize
    while True:
        try:
            return csv.field_size_limit(limit)
        except OverflowError:
            limit //= 10


def iter_delimited_rows(path: Path):
    ensure_csv_field_limit()
    encodings = ("utf-8-sig", "utf-8", "latin-1")
    delimiter_fallbacks = [",", ";", "\t", "|"]
    last_error: Exception | None = None
    for encoding in encodings:
        try:
            with path.open("r", encoding=encoding, errors="ignore", newline="") as handle:
                sample = handle.read(4096)
                handle.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|") if sample.strip() else csv.excel
                    reader = csv.DictReader(handle, dialect=dialect)
                    for row in reader:
                        yield dict(row)
                    return
                except csv.Error:
                    handle.seek(0)
                    for delimiter in delimiter_fallbacks:
                        reader = csv.DictReader(handle, delimiter=delimiter)
                        rows = [dict(row) for row in reader]
                        populated_headers = [header for header in (reader.fieldnames or []) if str(header or "").strip()]
                        if populated_headers and rows:
                            for row in rows:
                                yield row
                            return
                        handle.seek(0)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
    if last_error:
        raise last_error


def read_delimited_rows(path: Path) -> list[dict]:
    return list(iter_delimited_rows(path))
