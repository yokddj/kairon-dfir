"""Safari's browsing history (``~/Library/Safari/History.db``).

``history_items`` holds one row per URL and ``history_visits`` one row per visit, timed in Cocoa
seconds (since 2001-01-01 UTC). Rows come out in the same shape as the Firefox and Chromium
parsers so the shared browser normalizer handles them. Reading the live database needs Full Disk
Access on the Mac; collections taken without it simply do not contain the file.
"""
from __future__ import annotations

from pathlib import Path

from app.ingest.browser.sqlite_common import open_sqlite_readonly, prepare_sqlite_for_reading, table_columns
from app.ingest.browser.sqlite_firefox import _derive_search_term
from app.ingest.identity_extraction import extract_user_from_path
from app.ingest.macos.common import cocoa_to_iso, user_from_path


def parse_safari_history_sqlite(path: Path, *, source_path: str) -> tuple[list[dict], list[str]]:
    copied_path, copied_files = prepare_sqlite_for_reading(path)
    user = user_from_path(source_path) or extract_user_from_path(source_path)
    records: list[dict] = []
    with open_sqlite_readonly(copied_path) as connection:
        item_columns = table_columns(connection, "history_items")
        visit_columns = table_columns(connection, "history_visits")
        if not ({"id", "url"} <= item_columns and {"history_item", "visit_time"} <= visit_columns):
            return records, copied_files
        title = "history_visits.title" if "title" in visit_columns else "NULL"
        visit_count = "history_items.visit_count" if "visit_count" in item_columns else "NULL"
        load_successful = "history_visits.load_successful" if "load_successful" in visit_columns else "NULL"
        redirect_source = "history_visits.redirect_source" if "redirect_source" in visit_columns else "NULL"
        rows = connection.execute(
            f"""
            SELECT history_items.id AS item_id, history_items.url AS url, {visit_count} AS visit_count,
                   history_visits.id AS visit_id, history_visits.visit_time AS visit_time, {title} AS title,
                   {load_successful} AS load_successful, {redirect_source} AS redirect_source
            FROM history_visits JOIN history_items ON history_items.id = history_visits.history_item
            ORDER BY history_visits.visit_time ASC
            """
        ).fetchall()
        for row in rows:
            visit_time = cocoa_to_iso(row["visit_time"])
            record = {
                "Browser": "Safari",
                "Profile": "Default",
                "User": user,
                "SourceFile": source_path,
                "Profile Path": source_path,
                "URL": row["url"],
                "Title": row["title"],
                "Visit Time": visit_time,
                "Visit Count": row["visit_count"],
                "Transition": "redirect" if row["redirect_source"] else None,
                "raw_place_id": row["item_id"],
                "raw_visit_id": row["visit_id"],
            }
            if row["load_successful"] == 0:
                record["Load Successful"] = False
            records.append(record)
            search_term, search_engine = _derive_search_term(row["url"])
            if search_term:
                records.append({
                    "Browser": "Safari",
                    "Profile": "Default",
                    "User": user,
                    "SourceFile": source_path,
                    "Profile Path": source_path,
                    "Search Term": search_term,
                    "Search Engine": search_engine,
                    "URL": row["url"],
                    "Title": row["title"],
                    "Visit Time": visit_time,
                })
    return records, copied_files
