from pathlib import Path
import re

from app.ingest.eztools.base import ArtifactParser, iter_delimited_rows


AMC_NAME_HINTS = ("amcacheparser", "amcache")
AMC_HEADER_HINTS = {
    "programname",
    "programversion",
    "publisher",
    "productname",
    "path",
    "fullpath",
    "filepath",
    "lowercaselongpath",
    "sha1",
    "sha256",
    "md5",
    "compiletime",
    "installdate",
    "keylastwritetimestamp",
}


def _canonicalize(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


class AmcacheParser(ArtifactParser):
    def can_parse(self, path: Path, headers: list[str] | None = None) -> bool:
        lower_name = path.name.lower()
        if any(token in lower_name for token in AMC_NAME_HINTS):
            return True
        header_set = {_canonicalize(header) for header in (headers or []) if header}
        return len(header_set & AMC_HEADER_HINTS) >= 4 and bool({"sha1", "compiletime", "installdate", "path"} & header_set)

    def parse(self, path: Path, **kwargs):
        yield from iter_delimited_rows(path)


def read_amcache_rows(path: Path):
    yield from iter_delimited_rows(path)
