"""WebCacheV01.dat (legacy IE / pre-Chromium Edge browsing history + downloads,
stored as an ESE database) -- found on the real CyberDefenders "SpottedInTheWild"
CTF image: Chrome's own History file didn't exist on that machine, but this ESE
database held 31 real page visits and a completed download, all invisible to
Kairon until this parser existed (the disk-image extraction filter was also
dropping the file outright before it could reach classification)."""

from __future__ import annotations

from pathlib import Path

from app.ingest.browser.webcache_ese import (
    _decode_download_fields,
    _decode_history_url,
    _extract_utf16le_strings,
    looks_like_webcache_database,
    read_webcache_records,
)
from app.ingest.browser.detector import classify_browser_artifact, looks_like_browser_artifact
from app.ingest.normalizer import normalize_row


def _utf16le(value: str) -> bytes:
    return value.encode("utf-16-le") + b"\x00\x00"


def test_looks_like_webcache_database_matches_filename_case_insensitively():
    assert looks_like_webcache_database(Path("C:/Users/x/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat"))
    assert looks_like_webcache_database(Path("webcachev01.dat"))
    assert not looks_like_webcache_database(Path("WebCacheV01.jfm"))
    assert not looks_like_webcache_database(Path("History"))


def test_decode_history_url_strips_visited_prefix_and_user():
    assert _decode_history_url("Visited: Administrator@https://example.com/page") == "https://example.com/page"


def test_decode_history_url_strips_mshist01_date_range_prefix():
    assert _decode_history_url(":2023120620231207: Administrator@https://example.com/") == "https://example.com/"


def test_decode_history_url_rejects_host_summary_entries():
    assert _decode_history_url(":2023120620231207: Administrator@:Host: example.com") is None


def test_decode_history_url_rejects_non_uri_values():
    assert _decode_history_url("Visited: Administrator@not-a-url") is None


def test_extract_utf16le_strings_finds_embedded_text_in_binary_blob():
    blob = b"\x00\x01\x02" + _utf16le("Google LLC") + b"\xff\xfe\xfe" + _utf16le("https://example.com/setup.exe")
    strings = _extract_utf16le_strings(blob)
    assert "Google LLC" in strings
    assert "https://example.com/setup.exe" in strings


def test_decode_download_fields_extracts_url_and_windows_path():
    blob = b"\x00" * 20 + _utf16le("Google LLC") + _utf16le("https://dl.example.com/ChromeSetup.exe") + _utf16le("C:\\Users\\admin\\Downloads\\ChromeSetup.exe")
    url, path = _decode_download_fields(blob)
    assert url == "https://dl.example.com/ChromeSetup.exe"
    assert path == "C:\\Users\\admin\\Downloads\\ChromeSetup.exe"


def test_decode_download_fields_handles_missing_blob():
    assert _decode_download_fields(None) == (None, None)


def test_decode_download_fields_handles_blob_with_no_recognizable_strings():
    assert _decode_download_fields(b"\x00\x01\x02\x03") == (None, None)


class _FakeColumn:
    def __init__(self, name: str):
        self.name = name


class _FakeRecord:
    def __init__(self, values: dict):
        self._values = values

    def get(self, key, default=None):
        return self._values.get(key, default)


class _FakeTable:
    def __init__(self, columns: list[str], rows: list[dict]):
        self.columns = [_FakeColumn(name) for name in columns]
        self._rows = rows

    def records(self):
        return iter(_FakeRecord(row) for row in self._rows)


class _FakeEseDB:
    def __init__(self, fh):
        self.fh = fh
        containers = [
            {"ContainerId": 2, "Name": "History"},
            {"ContainerId": 5, "Name": "Cookies"},
            {"ContainerId": 25, "Name": "iedownload"},
        ]
        history_rows = [
            {"Url": "Visited: admin@https://example.com/", "AccessedTime": 133463044543728138, "AccessCount": 1},
            {"Url": "Visited: admin@:Host: example.com", "AccessedTime": 133463044543728138, "AccessCount": 1},
        ]
        download_blob = _utf16le("Publisher") + _utf16le("https://dl.example.com/tool.exe") + _utf16le("C:\\Users\\admin\\Downloads\\tool.exe")
        download_rows = [
            {"Url": "iedownload:{guid}", "AccessedTime": 133463540406307304, "ResponseHeaders": download_blob},
        ]
        self._tables = {
            "Containers": _FakeTable(["ContainerId", "Name"], containers),
            "Container_2": _FakeTable(list(history_rows[0].keys()), history_rows),
            "Container_25": _FakeTable(list(download_rows[0].keys()), download_rows),
        }

    def table(self, name):
        if name not in self._tables:
            raise KeyError(name)
        return self._tables[name]


def test_read_webcache_records_yields_history_and_download_rows_skips_cookies(monkeypatch, tmp_path):
    import dissect.esedb.esedb as esedb_module

    monkeypatch.setattr(esedb_module, "EseDB", _FakeEseDB)
    path = tmp_path / "WebCacheV01.dat"
    path.write_bytes(b"\x00")

    records = list(read_webcache_records(path))

    history = [r for r in records if "URL" in r]
    downloads = [r for r in records if "Download URL" in r]
    assert len(history) == 1
    assert history[0]["URL"] == "https://example.com/"
    assert len(downloads) == 1
    assert downloads[0]["Download URL"] == "https://dl.example.com/tool.exe"
    assert downloads[0]["Target Path"] == "C:\\Users\\admin\\Downloads\\tool.exe"


def test_webcache_database_classifies_as_browser_with_dedicated_parser():
    path = Path("C:/Users/admin/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat")
    assert looks_like_browser_artifact(path)
    result = classify_browser_artifact(path)
    assert result["artifact_type"] == "browser"
    assert result["parser"] == "webcache_ese"
    assert result["source_format"] == "ese"


def test_webcache_history_row_normalizes_to_browser_visit_event():
    artifact_meta = {
        "artifact_type": "browser",
        "parser": "webcache_ese",
        "name": "WebCacheV01.dat",
        "source_path": "C:\\Users\\admin\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat",
        "source_tool": "native_browser",
        "source_format": "ese",
    }
    row = {
        "URL": "https://example.com/page",
        "Visit Time": "2023-12-06T02:47:34.372814+00:00",
        "Visit Count": 1,
        "Browser": "Internet Explorer / Edge (legacy)",
    }
    document = normalize_row("case-1", "ev-1", "art-1", row, artifact_meta)
    assert document["event"]["type"] == "browser_visit"
    assert document["browser"]["url"] == "https://example.com/page"
    assert document["@timestamp"] == "2023-12-06T02:47:34.372814+00:00"


def test_webcache_download_row_normalizes_to_file_downloaded_event():
    artifact_meta = {
        "artifact_type": "browser",
        "parser": "webcache_ese",
        "name": "WebCacheV01.dat",
        "source_path": "C:\\Users\\admin\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat",
        "source_tool": "native_browser",
        "source_format": "ese",
    }
    row = {
        "Download URL": "https://dl.example.com/tool.exe",
        "Target Path": "C:\\Users\\admin\\Downloads\\tool.exe",
        "Download End Time": "2023-12-06T16:34:00.630730+00:00",
        "Browser": "Internet Explorer / Edge (legacy)",
    }
    document = normalize_row("case-1", "ev-1", "art-1", row, artifact_meta)
    assert document["event"]["type"] == "file_downloaded"
    assert document["download"]["url"] == "https://dl.example.com/tool.exe"
    assert document["download"]["target_path"] == "C:\\Users\\admin\\Downloads\\tool.exe"
    assert "suspicious_download" in document["tags"]


def test_kape_extraction_no_longer_drops_webcache_database(tmp_path):
    from app.ingest.kape import list_kape_artifacts

    webcache_dir = tmp_path / "C" / "Users" / "admin" / "AppData" / "Local" / "Microsoft" / "Windows" / "WebCache"
    webcache_dir.mkdir(parents=True)
    (webcache_dir / "WebCacheV01.dat").write_bytes(b"\x00" * 32)
    (webcache_dir / "WebCacheV01.jfm").write_bytes(b"\x00" * 32)

    artifacts = list_kape_artifacts(tmp_path)

    names = {a["name"] for a in artifacts}
    assert "WebCacheV01.dat" in names
    assert "WebCacheV01.jfm" not in names
    webcache_artifact = next(a for a in artifacts if a["name"] == "WebCacheV01.dat")
    assert webcache_artifact["parser"] == "webcache_ese"
