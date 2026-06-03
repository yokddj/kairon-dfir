from dataclasses import dataclass, field


@dataclass(slots=True)
class RawParserResult:
    parser_name: str
    artifact_type: str
    source_path: str
    records_read: int = 0
    events: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    parser_status: str = "parsed_native"
    metadata: dict = field(default_factory=dict)

