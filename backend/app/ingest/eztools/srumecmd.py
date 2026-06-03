from pathlib import Path
import re

from app.ingest.eztools.base import ArtifactParser, iter_delimited_rows


SRUM_NAME_HINTS = (
    "srumecmd",
    "srum",
    "networkusage",
    "applicationresourceusage",
    "appresource",
    "energyusage",
    "networkconnectivity",
)

SRUM_HEADER_HINTS = {
    "sourcefile",
    "table",
    "id",
    "timestamp",
    "starttime",
    "endtime",
    "usersid",
    "username",
    "appid",
    "appname",
    "application",
    "exeinfo",
    "exepath",
    "path",
    "filename",
    "packagefullname",
    "bytessent",
    "bytesreceived",
    "bytestotal",
    "sendbytes",
    "receivebytes",
    "totalbytes",
    "foregroundbytessent",
    "foregroundbytesreceived",
    "backgroundbytessent",
    "backgroundbytesreceived",
    "interfaceguid",
    "interfaceprofile",
    "networkprofile",
    "connectedtime",
    "duration",
    "energyusage",
    "cycletime",
    "provider",
    "description",
}


def _canonicalize(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


class SrumECmdParser(ArtifactParser):
    def can_parse(self, path: Path, headers: list[str] | None = None) -> bool:
        lower_name = path.name.lower()
        if any(token in lower_name for token in SRUM_NAME_HINTS):
            return True
        header_set = {_canonicalize(header) for header in (headers or []) if header}
        if len(header_set & SRUM_HEADER_HINTS) < 4:
            return False
        return bool(
            {
                "appid",
                "appname",
                "application",
                "bytessent",
                "bytesreceived",
                "sendbytes",
                "receivebytes",
                "usersid",
                "interfaceprofile",
                "networkprofile",
            }
            & header_set
        )

    def parse(self, path: Path, **kwargs):
        yield from iter_delimited_rows(path)


def read_srum_rows(path: Path):
    yield from iter_delimited_rows(path)
