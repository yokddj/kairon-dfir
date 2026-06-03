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


def _chromium_ts_to_iso(value: int | None) -> str | None:
    if value in (None, 0):
        return None
    try:
        return (datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=int(value))).isoformat()
    except Exception:  # noqa: BLE001
        return None


def _infer_browser_profile(path: Path, source_path: str) -> tuple[str, str | None]:
    lower = source_path.lower()
    if "google/chrome" in lower or "google\\chrome" in lower:
        browser = "Chrome"
    elif "microsoft/edge" in lower or "microsoft\\edge" in lower:
        browser = "Edge"
    elif "bravesoftware" in lower:
        browser = "Brave"
    elif "opera software" in lower:
        browser = "Opera"
    else:
        browser = "Chromium"
    parts = list(path.parts)
    profile = None
    if "User Data" in parts:
        index = parts.index("User Data")
        if index + 1 < len(parts):
            profile = parts[index + 1]
    elif "Opera Stable" in parts:
        profile = "Opera Stable"
    return browser, profile


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


def parse_chromium_history_sqlite(path: Path, *, source_path: str) -> tuple[list[dict], list[str]]:
    copied_path, copied_files = prepare_sqlite_for_reading(path)
    browser, profile = _infer_browser_profile(path, source_path)
    user = extract_user_from_path(source_path)
    records: list[dict] = []
    with open_sqlite_readonly(copied_path) as connection:
        urls_columns = table_columns(connection, "urls")
        visits_columns = table_columns(connection, "visits")
        downloads_columns = table_columns(connection, "downloads")
        chain_columns = table_columns(connection, "downloads_url_chains")
        search_columns = table_columns(connection, "keyword_search_terms")

        if urls_columns and visits_columns:
            rows = connection.execute(
                """
                SELECT
                  urls.id AS url_id,
                  urls.url AS url,
                  urls.title AS title,
                  urls.visit_count AS visit_count,
                  urls.typed_count AS typed_count,
                  urls.last_visit_time AS last_visit_time,
                  visits.id AS visit_id,
                  visits.visit_time AS visit_time,
                  visits.from_visit AS from_visit,
                  visits.transition AS transition
                FROM visits
                JOIN urls ON urls.id = visits.url
                ORDER BY visits.visit_time ASC
                """
            ).fetchall()
            for row in rows:
                url_value = row["url"]
                search_term, search_engine = _derive_search_term(url_value)
                records.append(
                    {
                        "Browser": browser,
                        "Profile": profile,
                        "User": user,
                        "SourceFile": source_path,
                        "Profile Path": source_path,
                        "URL": url_value,
                        "Title": row["title"],
                        "Visit Time": _chromium_ts_to_iso(row["visit_time"]),
                        "Visit Count": row["visit_count"],
                        "Typed Count": row["typed_count"],
                        "Transition": row["transition"],
                        "Last Visit Time": _chromium_ts_to_iso(row["last_visit_time"]),
                        "raw_url_id": row["url_id"],
                        "raw_visit_id": row["visit_id"],
                    }
                )
                if search_term:
                    records.append(
                        {
                            "Browser": browser,
                            "Profile": profile,
                            "User": user,
                            "SourceFile": source_path,
                            "Profile Path": source_path,
                            "Search Term": search_term,
                            "Search Engine": search_engine,
                            "URL": url_value,
                            "Title": row["title"],
                            "Visit Time": _chromium_ts_to_iso(row["visit_time"]),
                        }
                    )

        if downloads_columns:
            chain_map: dict[int, list[str]] = {}
            if chain_columns:
                chain_rows = connection.execute(
                    "SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id ASC, chain_index ASC"
                ).fetchall()
                for row in chain_rows:
                    chain_map.setdefault(int(row["id"]), []).append(str(row["url"]))
            rows = connection.execute(
                """
                SELECT
                  id, guid, current_path, target_path, start_time, end_time,
                  received_bytes, total_bytes, state, danger_type, interrupt_reason,
                  mime_type, tab_url, tab_referrer_url, original_mime_type, opened,
                  site_url, referrer, by_ext_id, by_ext_name
                FROM downloads
                ORDER BY start_time ASC
                """
            ).fetchall()
            for row in rows:
                chain_urls = chain_map.get(int(row["id"]), [])
                download_url = chain_urls[0] if chain_urls else None
                final_url = chain_urls[-1] if chain_urls else row["site_url"]
                target_path = row["target_path"] or row["current_path"]
                records.append(
                    {
                        "Browser": browser,
                        "Profile": profile,
                        "User": user,
                        "SourceFile": source_path,
                        "Profile Path": source_path,
                        "Download URL": download_url,
                        "Final URL": final_url,
                        "Referrer URL": row["referrer"] or row["tab_referrer_url"],
                        "Tab URL": row["tab_url"],
                        "Target Path": target_path,
                        "Filename": Path(target_path).name if target_path else None,
                        "Start Time": _chromium_ts_to_iso(row["start_time"]),
                        "End Time": _chromium_ts_to_iso(row["end_time"]),
                        "Received Bytes": row["received_bytes"],
                        "Total Bytes": row["total_bytes"],
                        "MIME Type": row["mime_type"] or row["original_mime_type"],
                        "State": row["state"],
                        "Danger Type": row["danger_type"],
                        "Interrupt Reason": row["interrupt_reason"],
                        "raw_download_id": row["id"],
                    }
                )

        if search_columns and urls_columns:
            rows = connection.execute(
                """
                SELECT
                  keyword_search_terms.term AS term,
                  urls.url AS url,
                  urls.title AS title,
                  urls.last_visit_time AS last_visit_time
                FROM keyword_search_terms
                JOIN urls ON urls.id = keyword_search_terms.url_id
                ORDER BY urls.last_visit_time ASC
                """
            ).fetchall()
            for row in rows:
                records.append(
                    {
                        "Browser": browser,
                        "Profile": profile,
                        "User": user,
                        "SourceFile": source_path,
                        "Profile Path": source_path,
                        "Search Term": row["term"],
                        "URL": row["url"],
                        "Title": row["title"],
                        "Visit Time": _chromium_ts_to_iso(row["last_visit_time"]),
                    }
                )
    return records, copied_files


class ChromiumHistoryParser:
    def parse(self, path: str) -> list[dict]:
        rows, _copied = parse_chromium_history_sqlite(Path(path), source_path=str(path))
        return rows
