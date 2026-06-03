from pathlib import Path
import re

from app.ingest.eztools.base import ArtifactParser, iter_delimited_rows


SHIM_NAME_HINTS = ("appcompatcacheparser", "shimcacheparser", "shimcache", "appcompatcache", "recentfilecache")
SHIM_HEADER_HINTS = {
    "path",
    "filepath",
    "fullpath",
    "name",
    "filename",
    "entrynumber",
    "cacheentryposition",
    "executed",
    "executionflag",
    "lastmodifiedtime",
    "lastmodifiedtimeutc",
    "lastupdate",
    "insertflags",
    "shimflags",
    "controlset",
    "appcompatflags",
    "datasource",
}


def _canonicalize(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


class ShimCacheParser(ArtifactParser):
    def can_parse(self, path: Path, headers: list[str] | None = None) -> bool:
        lower_name = path.name.lower()
        if any(token in lower_name for token in SHIM_NAME_HINTS):
            return True
        header_set = {_canonicalize(header) for header in (headers or []) if header}
        return len(header_set & SHIM_HEADER_HINTS) >= 3 and bool({"lastmodifiedtime", "entrynumber", "executed", "cacheentryposition", "path"} & header_set)

    def parse(self, path: Path, **kwargs):
        yield from iter_delimited_rows(path)


def read_shimcache_rows(path: Path):
    yield from iter_delimited_rows(path)
