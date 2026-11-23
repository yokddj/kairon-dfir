"""Velociraptor results/ tables: discovered as candidates, extracted when
selected, and routed to the view their artifact/source name calls for."""

import csv
import json
import zipfile
from pathlib import Path

from app.ingest.normalizer import normalize_file
from app.ingest.velociraptor import discover_velociraptor_evidences, list_velociraptor_artifacts, open_evidence_container
from app.ingest.velociraptor.results import classify_velociraptor_result, is_velociraptor_result_path, preferred_result_paths

HUNTER = "Generic.Forensic.SQLiteHunter%2F"
OSPATH = "C:\\Users\\alex\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"

# Column sets as SQLiteHunter writes them.
VISITS = [
    {"ID": "1", "VisitTime": "2025-11-20T10:00:00Z", "LastVisitedTime": "2025-11-20T10:30:00Z", "URLTitle": "Example", "URL": "https://example.com/page", "VisitCount": "3", "TypedCount": "1", "Hidden": "0", "VisitID": "11", "FromVisitID": "0", "VisitDurationInSeconds": "5", "OSPath": OSPATH},
]
EDGE_NAVIGATION = [
    {"ID": "1", "Last Visited Time": "2025-11-20T11:00:00Z", "Title": "Docs", "URL": "https://docs.example.com/", "VisitCount": "2", "OSPath": "C:\\Users\\alex\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History"},
]
WEBCACHE_HIGHLIGHTS = [
    {"AccessedTime": "2025-11-20T12:00:00Z", "ModifiedTime": "2025-11-20T12:00:00Z", "ExpiryTime": "2025-12-20T12:00:00Z", "Url": "https://intranet.example.com/"},
]
DOWNLOADS = [
    {
        "ID": "7",
        "TargetPath": "C:\\Users\\alex\\Downloads\\tool.exe",
        "OriginalMIMEType": "application/octet-stream",
        "ReceivedBytes": "1024",
        "TotalBytes": "1024",
        "StartTime": "2025-11-20T10:05:00Z",
        "EndTime": "2025-11-20T10:05:10Z",
        "ReferrerURL": "https://example.com/page",
        "DownloadURL": "https://cdn.example.com/tool.exe",
        "OSPath": OSPATH,
    }
]
KEYWORDS = [
    {"KeywordID": "2", "URLID": "9", "LastVisitedTime": "2025-11-20T09:59:00Z", "KeywordSearchTerm": "how to dump lsass", "Title": "search", "URL": "https://www.google.com/search?q=how+to+dump+lsass", "OSPath": OSPATH},
]


def _write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _collection(root: Path) -> Path:
    results = root / "results"
    results.mkdir(parents=True)
    for source, rows in [("Chromium Browser History_Visits", VISITS), ("Chromium Browser History_Downloads", DOWNLOADS), ("Chromium Browser History_Keywords", KEYWORDS)]:
        _write_csv(results / f"{HUNTER}{source}.csv", rows)
        _write_jsonl(results / f"{HUNTER}{source}.json", rows)
        (results / f"{HUNTER}{source}.json.index").write_bytes(b"\x00" * 8)
    # Only a JSON table, as a collector configured for JSON output writes it.
    _write_jsonl(results / f"{HUNTER}Chromium Browser Top Sites.json", [{"URL": "https://example.com", "URLRank": "1"}])
    _write_csv(results / f"{HUNTER}Chromium Browser Cookies_Cookies.csv", [{"HostKey": ".example.com", "Name": "session", "Value": "secret"}])
    _write_csv(results / "Windows.Triage.Targets%2FUploads.csv", [{"Path": "C:\\x", "Size": "1"}])
    (results / f"{HUNTER}Firefox Downloads.csv").write_text("", encoding="utf-8")
    upload = root / "uploads" / "auto" / "C%3A" / "Users" / "alex" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
    upload.mkdir(parents=True)
    (upload / "ConsoleHost_history.txt").write_text("whoami\n", encoding="utf-8")
    return root


def _result_candidates(discovery) -> dict[str, object]:
    return {Path(item.original_path).name: item for item in discovery.candidates if item.category == "velociraptor_result"}


def test_result_path_detection() -> None:
    assert is_velociraptor_result_path(f"results/{HUNTER}Chromium Browser History_Visits.csv")
    assert is_velociraptor_result_path(f"collection/results/{HUNTER}Chromium Browser History_Visits.json")
    assert not is_velociraptor_result_path(f"results/{HUNTER}Chromium Browser History_Visits.json.index")
    assert not is_velociraptor_result_path("uploads/auto/C%3A/tools/results/out.csv")
    assert not is_velociraptor_result_path("results.csv")


def test_preferred_result_paths_keeps_one_format_per_table() -> None:
    chosen = preferred_result_paths(
        [
            "results/A%2FX.csv",
            "results/A%2FX.json",
            "results/A%2FX.json.index",
            "results/A%2FY.json",
        ]
    )
    assert chosen == {"results/A%2FX.csv", "results/A%2FY.json"}


def test_classification_by_source_name() -> None:
    visits = classify_velociraptor_result(f"results/{HUNTER}Chromium Browser History_Visits.csv")
    assert (visits["artifact_type"], visits["parser"], visits["browser_artifact_type"], visits["supported"]) == ("browser", "browser_csv", "history", True)
    assert classify_velociraptor_result(f"results/{HUNTER}Chromium Browser History_Downloads.csv")["browser_artifact_type"] == "download"
    assert classify_velociraptor_result(f"results/{HUNTER}Chromium Browser History_Keywords.json")["parser"] == "browser_jsonl"
    assert classify_velociraptor_result(f"results/{HUNTER}Edge Browser Navigation History_Navigation History.csv")["browser_artifact_type"] == "history"
    cookies = classify_velociraptor_result(f"results/{HUNTER}Chromium Browser Cookies_Cookies.csv")
    assert cookies["parser"] == "unsupported_sensitive_artifact" and cookies["supported"] is False
    assert classify_velociraptor_result(f"results/{HUNTER}Chromium Browser Autofill_Profiles.csv")["supported"] is False
    assert classify_velociraptor_result("results/Windows.Triage.Targets%2FUploads.csv")["supported"] is False
    bookmarks = classify_velociraptor_result(f"results/{HUNTER}Chromium Browser Bookmarks.csv")
    assert (bookmarks["parser"], bookmarks["supported"]) == ("generic_csv", True)
    assert bookmarks["display_name"] == "Velociraptor result - Generic.Forensic.SQLiteHunter/Chromium Browser Bookmarks"


def test_discovery_lists_result_tables_as_candidates(tmp_path: Path) -> None:
    discovery = discover_velociraptor_evidences(_collection(tmp_path))
    results = _result_candidates(discovery)
    assert set(results) == {
        f"{HUNTER}Chromium Browser History_Visits.csv",
        f"{HUNTER}Chromium Browser History_Downloads.csv",
        f"{HUNTER}Chromium Browser History_Keywords.csv",
        f"{HUNTER}Chromium Browser Top Sites.json",
        f"{HUNTER}Chromium Browser Cookies_Cookies.csv",
        "Windows.Triage.Targets%2FUploads.csv",
    }
    assert results[f"{HUNTER}Chromium Browser History_Visits.csv"].supported is True
    assert results[f"{HUNTER}Chromium Browser Cookies_Cookies.csv"].supported is False
    assert results["Windows.Triage.Targets%2FUploads.csv"].supported is False
    # The upload detectors still see the host files.
    assert any(item.category == "powershell" for item in discovery.candidates)
    assert discovery.summary["velociraptor_result_count"] == 6


def test_selected_result_tables_are_extracted_and_listed_once(tmp_path: Path) -> None:
    root = _collection(tmp_path / "collection")
    archive = tmp_path / "collection.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                handle.write(path, path.relative_to(root).as_posix())
    container = open_evidence_container(archive)
    discovery = discover_velociraptor_evidences(container)
    selected = [item.as_dict() for item in discovery.candidates if item.supported]
    staging = tmp_path / "staging"
    extracted = {item["path"]: item["local_path"] for item in container.extract_entries([item["original_path"] for item in selected], staging)}
    prepared = [{**item, "local_path": extracted[item["original_path"]]} for item in selected]

    first_batch = list_velociraptor_artifacts(staging, prepared[:2])
    second_batch = list_velociraptor_artifacts(staging, prepared[2:])
    artifacts = [item for item in first_batch + second_batch if str(item["source_path"]).startswith("results/")]

    assert sorted(item["source_path"] for item in artifacts) == sorted(
        [
            f"results/{HUNTER}Chromium Browser History_Visits.csv",
            f"results/{HUNTER}Chromium Browser History_Downloads.csv",
            f"results/{HUNTER}Chromium Browser History_Keywords.csv",
            f"results/{HUNTER}Chromium Browser Top Sites.json",
        ]
    )
    visits = next(item for item in artifacts if "Visits" in item["source_path"])
    assert visits["artifact_type"] == "browser"
    assert visits["browser_artifact_type"] == "history"
    assert Path(visits["path"]).is_file()


def test_whole_collection_lists_supported_result_tables(tmp_path: Path) -> None:
    root = _collection(tmp_path)
    artifacts = list_velociraptor_artifacts(root, None)
    parsed = sorted(item["source_path"] for item in artifacts if item.get("status") == "processing" and str(item["source_path"]).startswith("results"))
    assert parsed == sorted(
        [
            f"results/{HUNTER}Chromium Browser History_Visits.csv",
            f"results/{HUNTER}Chromium Browser History_Downloads.csv",
            f"results/{HUNTER}Chromium Browser History_Keywords.csv",
            f"results/{HUNTER}Chromium Browser Top Sites.json",
        ]
    )


def _normalize(path: Path, source_path: str) -> list[dict]:
    classification = classify_velociraptor_result(source_path)
    meta = {key: value for key, value in classification.items() if key not in {"supported", "display_name", "reason"}}
    return normalize_file("case-1", "ev-1", "art-1", path, {**meta, "name": classification["display_name"], "source_path": source_path})


def test_sqlitehunter_visits_downloads_and_keywords_normalize_as_browser_events(tmp_path: Path) -> None:
    root = _collection(tmp_path)
    results = root / "results"

    [visit] = _normalize(results / f"{HUNTER}Chromium Browser History_Visits.csv", f"results/{HUNTER}Chromium Browser History_Visits.csv")
    assert visit["event"]["type"] == "browser_visit"
    assert visit["browser"]["url"] == "https://example.com/page"
    assert visit["browser"]["title"] == "Example"
    assert visit["browser"]["browser"] == "chrome"
    assert visit["user"]["name"] == "alex"
    assert visit["@timestamp"].startswith("2025-11-20T10:00:00")

    [download] = _normalize(results / f"{HUNTER}Chromium Browser History_Downloads.csv", f"results/{HUNTER}Chromium Browser History_Downloads.csv")
    assert download["event"]["type"] == "file_downloaded"
    assert download["download"]["url"] == "https://cdn.example.com/tool.exe"
    assert download["download"]["target_path"] == "C:\\Users\\alex\\Downloads\\tool.exe"
    assert download["download"]["mime_type"] == "application/octet-stream"

    # The JSON copy (JSON Lines) reads the same as the CSV.
    [keyword] = _normalize(results / f"{HUNTER}Chromium Browser History_Keywords.json", f"results/{HUNTER}Chromium Browser History_Keywords.json")
    assert keyword["browser"]["artifact_type"] == "search_term"
    assert keyword["browser"]["search_terms"] == "how to dump lsass"
    assert keyword["@timestamp"].startswith("2025-11-20T09:59:00")


def test_edge_navigation_and_webcache_highlights_normalize_as_visits(tmp_path: Path) -> None:
    results = tmp_path / "results"
    results.mkdir()
    for source, rows, url, timestamp in [
        ("Edge Browser Navigation History_Navigation History", EDGE_NAVIGATION, "https://docs.example.com/", "2025-11-20T11:00:00"),
        ("IE or Edge WebCacheV01_Highlights", WEBCACHE_HIGHLIGHTS, "https://intranet.example.com/", "2025-11-20T12:00:00"),
    ]:
        source_path = f"results/{HUNTER}{source}.csv"
        _write_csv(tmp_path / source_path, rows)
        [doc] = _normalize(tmp_path / source_path, source_path)
        assert doc["event"]["type"] == "browser_visit"
        assert doc["browser"]["url"] == url
        assert doc["@timestamp"].startswith(timestamp)
        assert doc["timestamp_precision"] == "browser_visit_time"


def test_generic_json_lines_table_is_read(tmp_path: Path) -> None:
    root = _collection(tmp_path)
    source_path = f"results/{HUNTER}Chromium Browser Top Sites.json"
    docs = _normalize(root / source_path, source_path)
    assert len(docs) == 1
