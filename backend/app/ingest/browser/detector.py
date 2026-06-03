from pathlib import Path


BROWSER_FILENAME_HINTS = [
    "browserhistoryview",
    "browsinghistoryview",
    "chromehistory",
    "chromedownload",
    "edgehistory",
    "edgedownload",
    "firefoxhistory",
    "firefoxdownload",
    "webcache",
]

HISTORY_HEADERS = {
    "url",
    "visit url",
    "visiturl",
    "visit time",
    "visittime",
    "lastvisittime",
    "page title",
    "title",
    "web site",
    "website",
    "last visit time",
}
DOWNLOAD_HEADERS = {
    "download url",
    "downloadurl",
    "target path",
    "targetpath",
    "download path",
    "downloadpath",
    "filename",
    "download start time",
    "downloadstarttime",
    "start time",
    "starttime",
    "download end time",
    "downloadendtime",
    "endtime",
    "final url",
    "finalurl",
    "receivedbytes",
    "totalbytes",
    "dangertype",
    "interruptreason",
    "mimetype",
}
SEARCH_HEADERS = {
    "search term",
    "searchterm",
    "search terms",
    "searchterms",
    "query",
    "keyword",
    "term",
}
COMMON_HEADERS = {
    "url",
    "title",
    "browser",
    "profile",
    "sourcefile",
    "profilepath",
}
CHROMIUM_DB_NAMES = {"history"}
FIREFOX_DB_NAMES = {"places.sqlite"}
SENSITIVE_BROWSER_FILES = {"login data", "logins.json", "cookies", "cookies.sqlite"}
BROWSER_PATH_TOKENS = (
    "google\\chrome\\user data\\",
    "microsoft\\edge\\user data\\",
    "bravesoftware\\brave-browser\\user data\\",
    "opera software\\opera stable\\",
    "chromium\\user data\\",
    "mozilla\\firefox\\profiles\\",
)


def _normalized_headers(headers: list[str] | None) -> set[str]:
    return {str(header).strip().lower() for header in (headers or []) if str(header).strip()}


def _looks_like_sensitive_browser_name(name: str) -> bool:
    normalized = name.lower().replace("_", " ").replace("-", " ")
    return any(token in normalized for token in SENSITIVE_BROWSER_FILES)


def looks_like_browser_artifact(path: Path, headers: list[str] | None = None) -> bool:
    lower_name = path.name.lower()
    lower_path = str(path).replace("/", "\\").lower()
    header_set = _normalized_headers(headers)
    if lower_name in CHROMIUM_DB_NAMES | FIREFOX_DB_NAMES | SENSITIVE_BROWSER_FILES or _looks_like_sensitive_browser_name(lower_name):
        return True
    if any(hint in lower_name for hint in BROWSER_FILENAME_HINTS):
        return True
    if len(header_set & COMMON_HEADERS) >= 2 and (
        header_set & HISTORY_HEADERS or header_set & DOWNLOAD_HEADERS or header_set & SEARCH_HEADERS
    ):
        return True
    if "browser" in header_set and (header_set & HISTORY_HEADERS or header_set & DOWNLOAD_HEADERS or header_set & SEARCH_HEADERS):
        return True
    if {"url", "browser"} <= header_set:
        return True
    if any(token in lower_path for token in BROWSER_PATH_TOKENS):
        return lower_name in CHROMIUM_DB_NAMES | FIREFOX_DB_NAMES | SENSITIVE_BROWSER_FILES
    return False


def _infer_browser_parser(path: Path, headers: list[str] | None = None) -> str:
    lower_name = path.name.lower()
    lower_path = str(path).replace("/", "\\").lower()
    header_set = _normalized_headers(headers)
    if lower_name in SENSITIVE_BROWSER_FILES or _looks_like_sensitive_browser_name(lower_name):
        return "unsupported_sensitive_artifact"
    if lower_name in FIREFOX_DB_NAMES or "mozilla\\firefox\\profiles\\" in lower_path:
        return "browser_firefox_places"
    if lower_name in CHROMIUM_DB_NAMES or any(token in lower_path for token in ["google\\chrome\\user data\\", "microsoft\\edge\\user data\\", "bravesoftware\\brave-browser\\user data\\", "opera software\\opera stable\\", "chromium\\user data\\"]):
        return "browser_chromium_history"
    if path.suffix.lower() == ".json":
        return "browser_json"
    if path.suffix.lower() == ".jsonl":
        return "browser_jsonl"
    if path.suffix.lower() == ".csv":
        return "browser_csv"
    return "browser_csv"


def infer_browser_artifact_subtype(path: Path, headers: list[str] | None = None) -> str:
    lower_name = path.name.lower()
    header_set = _normalized_headers(headers)
    if lower_name in SENSITIVE_BROWSER_FILES or _looks_like_sensitive_browser_name(lower_name):
        return "sensitive_artifact"
    if header_set & SEARCH_HEADERS:
        return "search_term"
    if any(token in lower_name for token in ["download", "downloads"]) or header_set & DOWNLOAD_HEADERS:
        return "download"
    if any(token in lower_name for token in ["history", "browsing", "webcache"]) or header_set & HISTORY_HEADERS:
        return "history"
    if "profile" in header_set or "profile path" in header_set:
        return "browser_profile"
    return "browser_generic"


def classify_browser_artifact(path: Path, headers: list[str] | None = None) -> dict:
    parser = _infer_browser_parser(path, headers)
    return {
        "artifact_type": "browser",
        "profile": "browser_usage",
        "parser": parser,
        "browser_artifact_type": infer_browser_artifact_subtype(path, headers),
        "source_tool": "native_browser" if parser in {"browser_chromium_history", "browser_firefox_places", "browser_chromium_downloads"} else "browser",
        "source_format": "sqlite" if parser in {"browser_chromium_history", "browser_firefox_places", "browser_chromium_downloads"} else (path.suffix.lower().lstrip(".") or "csv"),
    }
