from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ArtifactCandidate:
    name: str
    source_path: str
    artifact_type: str
    parser: str
    profile: str
    path: Path
    metadata: dict = field(default_factory=dict)


@dataclass
class ParsedRecord:
    record: dict
    metadata: dict = field(default_factory=dict)


@dataclass
class ParserResult:
    records: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class ParserPlugin:
    name: str = "base"
    supported_evidence_types: list[str] = []

    def detect(self, root: Path) -> list[ArtifactCandidate]:
        return []

    def parse(self, artifact: ArtifactCandidate) -> Iterable[dict]:
        return []

