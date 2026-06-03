from __future__ import annotations

from pathlib import Path

from app.ingest.recycle_bin.helpers import (
    basename,
    extension,
    extract_sid_from_recycle_path,
    parse_recycle_i_bytes,
    recycle_pair_id_from_path,
    preview_bytes_as_base64,
)


def parse_recycle_i_file(path: Path, *, source_path: str | None = None, paired_r_path: str | None = None) -> tuple[dict, list[str]]:
    data = path.read_bytes()
    parsed, warnings = parse_recycle_i_bytes(data)
    original_path = parsed.get("original_path")
    original_name = basename(original_path)
    content_status = "present" if paired_r_path else "content_missing_confirmed"
    return (
        {
            "ArtifactType": "recycle_pair" if paired_r_path else "recycle_i_file",
            "SourceFile": source_path or str(path),
            "IPath": source_path or str(path),
            "RPath": paired_r_path,
            "OriginalPath": original_path,
            "OriginalFileName": original_name,
            "FileName": original_name,
            "FileSize": parsed.get("original_file_size"),
            "DeletedOn": parsed.get("deleted_time"),
            "DeletedTime": parsed.get("deleted_time"),
            "SID": extract_sid_from_recycle_path(source_path or str(path)),
            "PairId": recycle_pair_id_from_path(source_path or str(path)),
            "Version": parsed.get("version"),
            "Extension": extension(original_path or original_name),
            "HasContentFile": bool(paired_r_path),
            "HasMetadataFile": True,
            "ContentStatus": content_status,
            "UsedUtf16Fallback": parsed.get("used_utf16_fallback"),
            "ParseWarnings": " | ".join(warnings) if warnings else None,
            "RawPreviewBase64": preview_bytes_as_base64(data),
        },
        warnings,
    )


def parse_recycle_r_file(path: Path, *, source_path: str | None = None) -> tuple[dict, list[str]]:
    return (
        {
            "ArtifactType": "recycle_orphan_r",
            "SourceFile": source_path or str(path),
            "RPath": source_path or str(path),
            "OriginalFileName": path.name,
            "FileName": path.name,
            "SID": extract_sid_from_recycle_path(source_path or str(path)),
            "PairId": recycle_pair_id_from_path(source_path or str(path)),
            "HasContentFile": True,
            "HasMetadataFile": False,
            "Extension": extension(path.name),
        },
        ["Recycle content file found without matching $I metadata"],
    )
