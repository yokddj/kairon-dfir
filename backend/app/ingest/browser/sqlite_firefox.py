from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from app.ingest.browser.sqlite_common import open_sqlite_readonly, prepare_sqlite_for_reading, table_columns
from app.ingest.identity_extraction import extract_user_from_path


SEARCH_PARAMS = {
    "google.": ("Google", "q"),
    "bing.com": ("Bing", "q"),
    "duckduckgo.com": ("DuckDuckGo", "q"),
    "search.yahoo.com": ("Yahoo", "p"),
    "yandex.": ("Yandex", "text"),
}


def _firefox_ts_to_iso(value: int | None) -> str | None:
    if value in (None, 0):
        return None
    try:
        return datetime.fromtimestamp(int(value) / 1_000_000, tz=UTC).isoformat()
    except Exception:  # noqa: BLE001
        return None


def _infer_profile(path: Path) -> str | None:
    parts = list(path.parts)
    if "Profiles" in parts:
        index = parts.index("Profiles")
        if index + 1 < len(parts):
            return parts[index + 1]
    return None


def _derive_search_term(url: str | None) -> tuple[str | None, str | None]:
    if not url:
        return None, None
    parsed = urlparse(url)
    domain = (parsed.netloc or "").lower()
    query = parse_qs(parsed.query)
    for needle, (engine, param) in SEARCH_PARAMS.items():
        if needle in domain:
            values = query.get(param) or []
            return (values[0] if values else None), engine
    return None, None


def parse_firefox_places_sqlite(path: Path, *, source_path: str) -> tuple[list[dict], list[str]]:
    copied_path, copied_files = prepare_sqlite_for_reading(path)
    user = extract_user_from_path(source_path)
    profile = _infer_profile(path)
    records: list[dict] = []
    with open_sqlite_readonly(copied_path) as connection:
        place_columns = table_columns(connection, "moz_places")
        visit_columns = table_columns(connection, "moz_historyvisits")
        if place_columns and visit_columns:
            rows = connection.execute(
                """
                SELECT
                  moz_places.id AS place_id,
                  moz_places.url AS url,
                  moz_places.title AS title,
                  moz_places.visit_count AS visit_count,
                  moz_places.typed AS typed_count,
                  moz_places.last_visit_date AS last_visit_date,
                  moz_historyvisits.id AS visit_id,
                  moz_historyvisits.visit_date AS visit_date,
                  moz_historyvisits.from_visit AS from_visit,
                  moz_historyvisits.visit_type AS visit_type
                FROM moz_historyvisits
                JOIN moz_places ON moz_places.id = moz_historyvisits.place_id
                ORDER BY moz_historyvisits.visit_date ASC
                """
            ).fetchall()
            for row in rows:
                search_term, search_engine = _derive_search_term(row["url"])
                records.append(
                    {
                        "Browser": "Firefox",
                        "Profile": profile,
                        "User": user,
                        "SourceFile": source_path,
                        "Profile Path": source_path,
                        "URL": row["url"],
                        "Title": row["title"],
                        "Visit Time": _firefox_ts_to_iso(row["visit_date"]),
                        "Visit Count": row["visit_count"],
                        "Typed Count": row["typed_count"],
                        "Transition": row["visit_type"],
                        "Last Visit Time": _firefox_ts_to_iso(row["last_visit_date"]),
                        "raw_place_id": row["place_id"],
                        "raw_visit_id": row["visit_id"],
                    }
                )
                if search_term:
                    records.append(
                        {
                            "Browser": "Firefox",
                            "Profile": profile,
                            "User": user,
                            "SourceFile": source_path,
                            "Profile Path": source_path,
                            "Search Term": search_term,
                            "Search Engine": search_engine,
                            "URL": row["url"],
                            "Title": row["title"],
                            "Visit Time": _firefox_ts_to_iso(row["visit_date"]),
                        }
                    )
    return records, copied_files


class FirefoxPlacesParser:
    def parse(self, path: str) -> list[dict]:
        rows, _copied = parse_firefox_places_sqlite(Path(path), source_path=str(path))
        return rows
