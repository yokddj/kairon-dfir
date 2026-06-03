from pathlib import Path
import csv

from app.ingest.defender.helpers import DEFENDER_HEADER_HINTS, canonicalize_header, parse_json_loose, parse_jsonl_loose, parse_text_record_blocks, read_text_with_fallbacks, choose_delimiter


def read_defender_csv_rows(path: Path):
    text, encoding = read_text_with_fallbacks(path)
    stripped = text.strip()
    if not stripped:
        return [], {"encoding": encoding, "delimiter": None, "delimiter_note": None, "warnings": ["empty_defender_source"], "errors": []}

    json_rows = parse_json_loose(stripped)
    if json_rows:
        return json_rows, {"encoding": encoding, "delimiter": None, "delimiter_note": "structured_json_fallback", "warnings": ["defender_json_fallback"], "errors": []}

    jsonl_rows = parse_jsonl_loose(stripped)
    if jsonl_rows:
        return jsonl_rows, {"encoding": encoding, "delimiter": None, "delimiter_note": "structured_jsonl_fallback", "warnings": ["defender_jsonl_fallback"], "errors": []}

    delimiter, delimiter_note = choose_delimiter(text)
    if delimiter:
        def _collect_rows_with_reader(reader_obj):
            parsed_rows = []
            seen: set[tuple[tuple[str, str], ...]] = set()
            for row in reader_obj:
                normalized = {str(key).strip(): (value.lstrip("\ufeff").strip() if isinstance(value, str) else value) for key, value in dict(row).items() if key not in (None, "")}
                if not normalized:
                    continue
                if not any(str(value or "").strip() for value in normalized.values()):
                    continue
                non_empty = {key: str(value or "").strip() for key, value in normalized.items() if str(value or "").strip()}
                if len(non_empty) < 2:
                    continue
                lowered_keys = {canonicalize_header(key) for key in non_empty}
                if not (lowered_keys & DEFENDER_HEADER_HINTS):
                    continue
                key = tuple(sorted((str(k), str(v)) for k, v in non_empty.items()))
                if key in seen:
                    continue
                seen.add(key)
                parsed_rows.append(non_empty)
            return parsed_rows

        reader = csv.DictReader(text.splitlines(), delimiter=delimiter)
        rows = _collect_rows_with_reader(reader)
        if not rows:
            plain_reader = csv.reader(text.splitlines(), delimiter=delimiter)
            plain_rows = [line for line in plain_reader if any(str(cell or "").strip() for cell in line)]
            if len(plain_rows) >= 2:
                header = [str(cell).lstrip("\ufeff").strip() for cell in plain_rows[0]]
                if {canonicalize_header(item) for item in header} & DEFENDER_HEADER_HINTS:
                    manual_reader = (dict(zip(header, line, strict=False)) for line in plain_rows[1:])
                    rows = _collect_rows_with_reader(manual_reader)
        return rows, {"encoding": encoding, "delimiter": delimiter, "delimiter_note": delimiter_note, "warnings": [], "errors": []}

    blocks = parse_text_record_blocks(text)
    if blocks:
        return blocks, {"encoding": encoding, "delimiter": None, "delimiter_note": "key_value_fallback", "warnings": ["defender_key_value_fallback"], "errors": []}

    return [], {
        "encoding": encoding,
        "delimiter": None,
        "delimiter_note": None,
        "warnings": ["unsupported_defender_source"],
        "errors": ["Could not determine delimiter or alternate structured format"],
    }
