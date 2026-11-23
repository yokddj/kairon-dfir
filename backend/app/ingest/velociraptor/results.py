"""Velociraptor ``results/`` tables.

A collection keeps the rows its VQL artifacts produced next to the raw uploads:
``results/<Artifact>%2F<Source>.csv`` and ``.json`` (JSON Lines, despite the name),
plus a ``.json.index`` row-offset file. Each table is written twice, in CSV and
in JSON, so only one of them is kept: the CSV when there is one.

The file name says which artifact and source produced the rows; that is what
picks the view. Names are matched case-insensitively on the source part, so a
custom artifact reusing SQLiteHunter's source names lands in the same view.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from urllib.parse import unquote

RESULTS_DIR = "results"
RESULT_SUFFIXES = (".csv", ".json", ".jsonl")

# Source name prefix -> browser subtype. The subtype tells the browser
# normalizer what a row is: SQLiteHunter's column names (VisitTime, URLTitle,
# KeywordSearchTerm...) are not ones the row-based guess recognizes on its own.
_BROWSER_SOURCES: tuple[tuple[str, str], ...] = (
    ("chromium browser history_visits", "history"),
    ("chromium browser history_downloads", "download"),
    ("chromium browser history_keywords", "search_term"),
    ("edge browser navigation history", "history"),
    ("firefox places history", "history"),
    ("firefox places_downloads", "download"),
    ("firefox downloads", "download"),
    ("safari browser history", "history"),
    # Highlights is the history subset of the WebCache; "All Data" repeats it
    # alongside cookies and DOM storage, so it stays a generic table.
    ("ie or edge webcachev01_highlights", "history"),
)

# Stores whose values are credentials or personal data. The raw files are
# not parsed for the same reason (see app.ingest.detector).
_SENSITIVE_TOKENS = ("cookies", "autofill", "credit card", "login data", "logins", "passwords")

# Tables that describe the collection itself rather than the host.
_COLLECTION_METADATA_SOURCES = {
    "generic.forensic.sqlitehunter/allfiles",
    "windows.triage.targets/uploads",
    "windows.triage.targets/all matches metadata",
    "windows.triage.targets/searchglobs",
}


def _parts(path: str) -> list[str]:
    return [part for part in str(path).replace("\\", "/").split("/") if part]


def is_velociraptor_result_path(path: str) -> bool:
    """A table file directly under a ``results`` directory of the collection."""
    parts = _parts(path)
    if len(parts) < 2 or parts[-2].lower() != RESULTS_DIR:
        return False
    # "uploads/.../results/x.csv" is a file collected from the host, not a table.
    if any(part.lower() == "uploads" for part in parts[:-2]):
        return False
    return parts[-1].lower().endswith(RESULT_SUFFIXES)


def result_table_name(path: str) -> str:
    """``Generic.Forensic.SQLiteHunter%2FChromium Browser History_Visits.csv`` ->
    ``Generic.Forensic.SQLiteHunter/Chromium Browser History_Visits``."""
    name = _parts(path)[-1]
    stem = name[: -len(PurePosixPath(name).suffix)] if PurePosixPath(name).suffix else name
    return unquote(stem)


def _split_table_name(table: str) -> tuple[str, str]:
    artifact, _, source = table.partition("/")
    return artifact, source


def preferred_result_paths(paths: list[str]) -> set[str]:
    """Of the result files in ``paths``, the ones to ingest: the CSV of each
    table, or its JSON when there is no CSV. Index files are left out."""
    by_table: dict[tuple[str, str], dict[str, str]] = {}
    for path in paths:
        if not is_velociraptor_result_path(path):
            continue
        parent = "/".join(_parts(path)[:-1]).lower()
        suffix = PurePosixPath(_parts(path)[-1]).suffix.lower()
        by_table.setdefault((parent, result_table_name(path).lower()), {})[suffix] = path
    chosen: set[str] = set()
    for variants in by_table.values():
        for suffix in (".csv", ".jsonl", ".json"):
            if suffix in variants:
                chosen.add(variants[suffix])
                break
    return chosen


def _source_format(path: str) -> str:
    # Velociraptor's .json tables are JSON Lines.
    suffix = PurePosixPath(_parts(path)[-1]).suffix.lower()
    return "csv" if suffix == ".csv" else "jsonl"


def classify_velociraptor_result(path: str) -> dict:
    """How to ingest one result table, from its artifact/source name.

    Returns the artifact fields plus ``supported`` (whether it is ingested by
    default) and ``display_name``."""
    table = result_table_name(path)
    artifact, source = _split_table_name(table)
    lowered_table = table.lower()
    lowered_source = (source or artifact).lower()
    source_format = _source_format(path)
    base = {
        "display_name": f"Velociraptor result - {table}",
        "velociraptor_artifact": artifact,
        "velociraptor_source": source or None,
        "source_tool": "velociraptor",
        "source_format": source_format,
    }
    if any(token in lowered_source for token in _SENSITIVE_TOKENS):
        return {
            **base,
            "artifact_type": "browser",
            "profile": "browser_usage",
            "parser": "unsupported_sensitive_artifact",
            "supported": False,
            "reason": "Credential, cookie or autofill table; values are intentionally not parsed or indexed.",
        }
    if lowered_table in _COLLECTION_METADATA_SOURCES:
        return {
            **base,
            "artifact_type": "collection_metadata",
            "profile": "collection_metadata",
            "parser": "not_implemented",
            "supported": False,
            "reason": "Describes the collection (files matched or uploaded), not host activity.",
        }
    for prefix, subtype in _BROWSER_SOURCES:
        if lowered_source.startswith(prefix):
            return {
                **base,
                "artifact_type": "browser",
                "profile": "browser_usage",
                "parser": "browser_csv" if source_format == "csv" else "browser_jsonl",
                "browser_artifact_type": subtype,
                "supported": True,
                "reason": None,
            }
    return {
        **base,
        "artifact_type": "generic_csv" if source_format == "csv" else "generic_json",
        "profile": "unknown",
        "parser": "generic_csv" if source_format == "csv" else "generic_json",
        "supported": True,
        "reason": "Indexed as a generic table; no dedicated view for this source.",
    }

