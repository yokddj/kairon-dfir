from pathlib import Path

from app.ingest.raw.base import ArtifactParser


class RawEvtxParser(ArtifactParser):
    def can_parse(self, path: Path, headers: list[str] | None = None) -> bool:
        return path.suffix.lower() == ".evtx"

    def parse(self, path: Path, **kwargs):
        raise NotImplementedError("Raw EVTX parsing is planned for a future iteration")
