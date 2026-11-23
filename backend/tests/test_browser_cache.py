"""Browser HTTP caches: Chromium blockfile and Simple Cache, Firefox cache2.

The builders below write the on-disk layouts the readers expect. The Chromium
readers were checked against real caches (Chromium's own blockfile test caches
and a Simple Cache written by Chrome); the builders follow the same layout.
"""

import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.ingest.browser.cache import cache_directory_for, detect_cache_format, read_browser_cache
from app.ingest.browser.cache_chromium import iter_chromium_cache, parse_cache_key, parse_http_response_info
from app.ingest.browser.cache_firefox import parse_firefox_cache_key, read_firefox_cache_entry
from app.ingest.normalizer import normalize_file
from app.ingest.velociraptor import discover_velociraptor_evidences, list_velociraptor_artifacts

EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
REQUEST = datetime(2025, 11, 20, 10, 0, 0, tzinfo=UTC)
RESPONSE = datetime(2025, 11, 20, 10, 0, 1, tzinfo=UTC)
PAGE_KEY = "1/0/_dk_https://news.example https://news.example https://cdn.tracker.net/pixel.js"
PAGE_URL = "https://cdn.tracker.net/pixel.js"


def _internal(moment: datetime) -> int:
    return (moment - EPOCH) // timedelta(microseconds=1)


def _pickle_string(data: bytes) -> bytes:
    return struct.pack("<i", len(data)) + data + b"\0" * ((-len(data)) % 4)


def response_info(*, status: str = "HTTP/1.1 200", headers: dict[str, str] | None = None, ip: str = "203.0.113.7", port: int = 443) -> bytes:
    """A pickled HttpResponseInfo as Chrome 120+ writes it: flags (version 3,
    extra flags), extra flags, three times, the headers, certificate-like bytes,
    then the server address."""
    raw = "\0".join([status, *(f"{name}: {value}" for name, value in (headers or {"content-type": "application/javascript", "server": "cloudflare"}).items())]) + "\0\0"
    payload = struct.pack("<I", 0x8A476D03) + struct.pack("<I", 6)
    payload += struct.pack("<qqq", _internal(REQUEST), _internal(RESPONSE), _internal(RESPONSE))
    payload += _pickle_string(raw.encode("latin-1"))
    payload += struct.pack("<i", 1) + _pickle_string(b"\x30\x82\x01\x0a" + b"\x00" * 60)  # a certificate
    payload += _pickle_string(ip.encode("ascii")) + struct.pack("<H", port) + b"\0\0"
    return struct.pack("<I", len(payload)) + payload


# --- Chromium Simple Cache ----------------------------------------------------


def write_simple_entry(directory: Path, name: str, key: str, metadata: bytes, body: bytes = b"console.log(1)") -> None:
    data = struct.pack("<QIII", 0xFCFB6D1BA7725C30, 5, len(key), 0) + b"\0" * 4 + key.encode()
    data += body + struct.pack("<QIII", 0xF4FA6F45970D41D8, 1, 0, len(body)) + b"\0" * 4
    data += metadata + b"\x11" * 32  # SHA-256 of the key
    data += struct.pack("<QIII", 0xF4FA6F45970D41D8, 3, 0, len(metadata)) + b"\0" * 4
    (directory / name).write_bytes(data)


def simple_cache(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "index").write_bytes(struct.pack("<QQQ", 0xFCFB6D1BA7725C30, 9, 0))
    write_simple_entry(directory, "0123456789abcdef_0", PAGE_KEY, response_info())
    write_simple_entry(directory, "fedcba9876543210_0", "https://news.example/", response_info(headers={"content-type": "text/html"}, ip="2001:db8::1"))
    return directory


# --- Chromium blockfile -------------------------------------------------------

BLOCK_SIZE = {0: 36, 1: 256, 2: 1024, 3: 4096}


def _address(file_type: int, file_number: int, start: int, blocks: int = 1) -> int:
    return 0x80000000 | (file_type << 28) | ((blocks - 1) << 24) | (file_number << 16) | start


def blockfile_cache(directory: Path, entries: list[tuple[str, bytes]]) -> Path:
    """index + data_0 (rankings) + data_1 (entries) + data_2 (stream 0) + data_3."""
    directory.mkdir(parents=True, exist_ok=True)
    data = {number: bytearray(8192) for number in range(4)}
    table = [0] * 64
    for slot, (key, metadata) in enumerate(entries):
        ranking = struct.pack("<QQ", _internal(RESPONSE) + 5_000_000, _internal(RESPONSE))
        data[0] += ranking + b"\0" * (36 - len(ranking))
        stream_address = _address(3, 2, slot)
        data[2] += metadata + b"\0" * (1024 - len(metadata))
        entry = struct.pack("<IIIiiiQiI", 0, 0, _address(1, 0, slot), 0, 0, 0, _internal(REQUEST), len(key), 0)
        entry += struct.pack("<4i", len(metadata), 512, 0, 0) + struct.pack("<4I", stream_address, 0, 0, 0)
        entry += struct.pack("<I", 0) + b"\0" * 16 + struct.pack("<I", 0)
        entry += key.encode().ljust(160, b"\0")
        assert len(entry) == 256
        data[1] += entry
        table[slot * 7 % 64] = _address(2, 1, slot)
    header = struct.pack("<IIii", 0xC103CAC3, 0x30000, len(entries), 0) + struct.pack("<iiIi", 0, 0, 0, len(table))
    (directory / "index").write_bytes(header.ljust(368, b"\0") + struct.pack(f"<{len(table)}I", *table))
    for number, content in data.items():
        content[0:4] = struct.pack("<I", 0xC104CAC3)
        (directory / f"data_{number}").write_bytes(bytes(content))
    return directory


# --- Firefox cache2 -------------------------------------------------------------


def write_firefox_entry(directory: Path, name: str, key: str, response_head: str, body: bytes = b"<html></html>") -> None:
    elements = b"request-method\0GET\0response-head\0" + response_head.encode("latin-1") + b"\0"
    last_fetched = int(RESPONSE.timestamp()) + 60
    header = struct.pack(">8I", 3, 2, last_fetched, int(RESPONSE.timestamp()), 0, 0, len(key), 0)
    metadata = struct.pack(">I", 0) + struct.pack(">H", 0) + header + key.encode() + b"\0" + elements
    (directory / name).write_bytes(body + metadata + struct.pack(">I", len(body)))


# --- tests ------------------------------------------------------------------------


def test_cache_key_names_the_page_that_loaded_the_resource() -> None:
    assert parse_cache_key(PAGE_KEY) == ("https://news.example", "https://news.example", PAGE_URL)
    assert parse_cache_key("1/0/_dk_cn_https://a.example https://a.example https://b.example/x") == ("https://a.example", "https://a.example", "https://b.example/x")
    assert parse_cache_key("https://old.example/style.css") == (None, None, "https://old.example/style.css")


def test_response_info_fields() -> None:
    info = parse_http_response_info(response_info())
    assert info["request_time"] == REQUEST
    assert info["response_time"] == RESPONSE
    assert info["status_code"] == 200
    assert info["headers"] == {"content-type": "application/javascript", "server": "cloudflare"}
    assert (info["server_ip"], info["server_port"]) == ("203.0.113.7", 443)
    assert parse_http_response_info(b"\0" * 8)["status_code"] is None


def test_simple_cache_reads_key_metadata_and_body_size(tmp_path: Path) -> None:
    directory = simple_cache(tmp_path / "Cache_Data")
    assert detect_cache_format(directory) == "simple"
    records = {record.url: record for record in iter_chromium_cache(directory)}
    pixel = records[PAGE_URL]
    assert pixel.top_frame_site == "https://news.example"
    assert pixel.response_time == RESPONSE
    assert pixel.server_ip == "203.0.113.7"
    assert pixel.body_size == len(b"console.log(1)")
    assert records["https://news.example/"].server_ip == "2001:db8::1"


def test_blockfile_cache_walks_the_index(tmp_path: Path) -> None:
    directory = blockfile_cache(tmp_path / "Cache_Data", [(PAGE_KEY, response_info()), ("https://news.example/", response_info(status="HTTP/1.1 304"))])
    assert detect_cache_format(directory) == "blockfile"
    records = {record.url: record for record in iter_chromium_cache(directory)}
    assert set(records) == {PAGE_URL, "https://news.example/"}
    pixel = records[PAGE_URL]
    assert pixel.cache_format == "blockfile"
    assert pixel.created == REQUEST
    assert pixel.last_used == RESPONSE + timedelta(seconds=5)
    assert pixel.top_frame_site == "https://news.example"
    assert pixel.server_ip == "203.0.113.7"
    assert pixel.body_size == 512
    assert records["https://news.example/"].status_code == 304


def test_blockfile_entry_without_stream_zero_still_yields_its_key(tmp_path: Path) -> None:
    directory = blockfile_cache(tmp_path / "Cache_Data", [(PAGE_KEY, b"")])
    [record] = list(iter_chromium_cache(directory))
    assert record.url == PAGE_URL and record.status_code is None


def test_firefox_cache_entry(tmp_path: Path) -> None:
    entries = tmp_path / "cache2" / "entries"
    entries.mkdir(parents=True)
    (tmp_path / "cache2" / "index").write_bytes(b"\0" * 12)
    key = "O^partitionKey=%28https%2Cnews.example%29,a,:https://cdn.tracker.net/pixel.js"
    write_firefox_entry(entries, "A" * 40, key, "HTTP/1.1 200 OK\r\nContent-Type: image/gif\r\nServer: nginx\r\n")
    assert parse_firefox_cache_key(key) == ("https://news.example", PAGE_URL)
    assert parse_firefox_cache_key("a,:https://plain.example/") == (None, "https://plain.example/")
    record = read_firefox_cache_entry(entries / ("A" * 40))
    assert record.url == PAGE_URL
    assert record.top_frame_site == "https://news.example"
    assert record.status_code == 200
    assert record.headers == {"content-type": "image/gif", "server": "nginx"}
    assert record.last_used == RESPONSE + timedelta(seconds=60)
    assert record.body_size == len(b"<html></html>")
    assert cache_directory_for(tmp_path / "cache2" / "index") == entries
    assert len(read_browser_cache(tmp_path / "cache2" / "index", source_path="x")) == 1


def test_cache_rows_normalize_as_browser_cache_events(tmp_path: Path) -> None:
    directory = blockfile_cache(tmp_path / "Cache_Data", [(PAGE_KEY, response_info()), ("1/0/_dk_https://news.example https://news.example https://static.news.example/app.js", response_info())])
    source = "C:\\Users\\alex\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\Cache_Data\\index"
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        directory / "index",
        {"artifact_type": "browser", "parser": "browser_cache", "browser_artifact_type": "cache_resource", "source_path": source, "name": "Chrome Cache"},
    )
    by_url = {doc["url"]["full"]: doc for doc in docs}
    pixel = by_url[PAGE_URL]
    assert pixel["event"]["type"] == "browser_cache_entry"
    assert pixel["browser"]["artifact_type"] == "cache_resource"
    assert pixel["browser"]["browser"] == "chrome"
    assert pixel["user"]["name"] == "alex"
    assert pixel["@timestamp"].startswith("2025-11-20T10:00:01")
    assert pixel["timestamp_precision"] == "browser_cache_response_time"
    assert pixel["browser"]["cache"]["top_frame_domain"] == "news.example"
    assert pixel["browser"]["cache"]["third_party"] is True
    assert pixel["browser"]["cache"]["content_type"] == "application/javascript"
    assert pixel["network"]["destination_ip"] == "203.0.113.7"
    assert pixel["network"]["domain"] == "cdn.tracker.net"
    assert "loaded by news.example" in pixel["event"]["message"]
    assert by_url["https://static.news.example/app.js"]["browser"]["cache"]["third_party"] is False


def test_cached_url_path_words_are_not_flagged_as_downloaded_files(tmp_path: Path) -> None:
    directory = blockfile_cache(tmp_path / "Cache_Data", [("1/0/_dk_https://a.example https://a.example https://a.example/api/token", response_info())])
    [doc] = normalize_file("c", "e", "a", directory / "index", {"artifact_type": "browser", "parser": "browser_cache", "browser_artifact_type": "cache_resource", "source_path": "x", "name": "x"})
    assert "suspicious" not in doc["tags"]


def _velociraptor_profile(root: Path) -> Path:
    return root / "uploads" / "auto" / "C%3A" / "Users" / "alex" / "AppData" / "Local"


def test_discovery_finds_caches_and_selection_parses_them(tmp_path: Path) -> None:
    local = _velociraptor_profile(tmp_path)
    blockfile_cache(local / "Google" / "Chrome" / "User Data" / "Default" / "Cache" / "Cache_Data", [(PAGE_KEY, response_info())])
    (local / "Google" / "Chrome" / "User Data" / "Default" / "Cache" / "Cache_Data" / "f_000001").write_bytes(b"\0" * 4096)
    simple_cache(local / "Microsoft" / "Edge" / "User Data" / "Profile 1" / "Cache" / "Cache_Data")
    firefox = local / "Mozilla" / "Firefox" / "Profiles" / "abcd.default-release" / "cache2"
    (firefox / "entries").mkdir(parents=True)
    (firefox / "index").write_bytes(b"\0" * 12)
    write_firefox_entry(firefox / "entries", "B" * 40, "a,:https://news.example/", "HTTP/1.1 200 OK\r\n")

    discovery = discover_velociraptor_evidences(tmp_path)
    caches = {item.browser: item for item in discovery.candidates if item.artifact_type in {"chromium_cache", "firefox_cache"}}
    assert set(caches) == {"Chrome", "Edge", "Firefox"}
    chrome = caches["Chrome"]
    assert chrome.supported is True and chrome.parser == "browser_cache"
    assert chrome.profile == "Default" and chrome.user == "alex"
    # Block files are needed; the external body file is not.
    assert sorted(Path(path).name for path in chrome.companion_files) == ["data_0", "data_1", "data_2", "data_3"]
    assert [Path(path).name for path in caches["Edge"].companion_files] == ["0123456789abcdef_0", "fedcba9876543210_0"]
    assert [Path(path).name for path in caches["Firefox"].companion_files] == ["B" * 40]
    # The files of a cache are not reported again as separate candidates.
    cache_files = {path for item in caches.values() for path in [item.original_path, *item.companion_files]}
    assert not [item for item in discovery.candidates if item.artifact_type not in {"chromium_cache", "firefox_cache"} and item.original_path in cache_files]
    assert discovery.summary["browser_cache_count"] == 3

    artifacts = list_velociraptor_artifacts(tmp_path, [item.as_dict() for item in caches.values()])
    assert {item["parser"] for item in artifacts} == {"browser_cache"}
    assert {item["browser_artifact_type"] for item in artifacts} == {"cache_resource"}
    chrome_artifact = next(item for item in artifacts if "Chrome" in item["source_path"])
    rows = read_browser_cache(chrome_artifact["path"], source_path=chrome_artifact["source_path"])
    assert [row["URL"] for row in rows] == [PAGE_URL]


def test_selected_cache_extracted_from_a_zip_is_readable(tmp_path: Path) -> None:
    import zipfile

    from app.ingest.velociraptor import open_evidence_container

    root = tmp_path / "collection"
    cache_dir = _velociraptor_profile(root) / "Google" / "Chrome" / "User Data" / "Default" / "Cache" / "Cache_Data"
    blockfile_cache(cache_dir, [(PAGE_KEY, response_info())])
    (cache_dir / "f_000001").write_bytes(b"\1" * 4096)
    archive = tmp_path / "collection.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                handle.write(path, path.relative_to(root).as_posix())
    container = open_evidence_container(archive)
    [candidate] = [item.as_dict() for item in discover_velociraptor_evidences(container).candidates if item.artifact_type == "chromium_cache"]
    staging = tmp_path / "staging"
    wanted = [candidate["original_path"], *candidate["companion_files"]]
    extracted = {item["path"]: item["local_path"] for item in container.extract_entries(wanted, staging)}
    assert not any(Path(path).name.startswith("f_") for path in extracted)
    [artifact] = list_velociraptor_artifacts(staging, [{**candidate, "local_path": extracted[candidate["original_path"]]}])
    [row] = read_browser_cache(Path(artifact["path"]), source_path=artifact["source_path"])
    assert row["URL"] == PAGE_URL and row["Server IP"] == "203.0.113.7"


def test_blockfile_entries_pointing_at_uncollected_files_are_read(tmp_path: Path) -> None:
    """f_* bodies are not collected, and a data_N can be missing: the entries
    that point there still come out, and the cache is not lost."""
    directory = blockfile_cache(tmp_path / "Cache_Data", [(PAGE_KEY, response_info()), ("https://news.example/", response_info())])
    entry_at = 8192 + 256  # the second entry in data_1
    data_1 = bytearray((directory / "data_1").read_bytes())
    data_1[entry_at + 56:entry_at + 60] = struct.pack("<I", 0x80000000 | 0x00000ABC)  # stream 0 in f_000abc
    (directory / "data_1").write_bytes(bytes(data_1))
    (directory / "data_3").unlink()
    records = {record.url: record for record in iter_chromium_cache(directory)}
    assert set(records) == {PAGE_URL, "https://news.example/"}
    assert records[PAGE_URL].server_ip == "203.0.113.7"
    assert records["https://news.example/"].status_code is None
