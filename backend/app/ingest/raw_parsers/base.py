from abc import ABC, abstractmethod
from pathlib import Path

from app.ingest.raw_parsers.models import RawParserResult


class BaseRawParser(ABC):
    parser_name = "raw"
    artifact_type = "raw"
    statuses = {"parsed_native"}

    @abstractmethod
    def can_parse(self, candidate_or_path: object) -> bool:
        raise NotImplementedError

    @abstractmethod
    def parse(
        self,
        path: Path,
        *,
        case_id: str,
        evidence_id: str,
        artifact_id: str,
        artifact_meta: dict,
        progress_cb=None,
    ) -> RawParserResult:
        raise NotImplementedError
