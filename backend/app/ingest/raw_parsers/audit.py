from app.ingest.raw_parsers.models import RawParserResult


def build_raw_parser_audit(result: RawParserResult) -> dict:
    return {
        "parser_name": result.parser_name,
        "source_file": result.source_path,
        "artifact_type": result.artifact_type,
        "records_read": result.records_read,
        "events_indexed": len(result.events),
        "events_skipped": max(result.records_read - len(result.events), 0),
        "warnings_count": len(result.warnings),
        "errors_count": len(result.errors),
        "parse_duration_ms": result.metadata.get("parse_duration_ms"),
        "deduplicated_count": result.metadata.get("deduplicated_count", 0),
        "parser_status": result.parser_status,
        **{key: value for key, value in result.metadata.items() if key not in {"parse_duration_ms", "deduplicated_count"}},
    }

