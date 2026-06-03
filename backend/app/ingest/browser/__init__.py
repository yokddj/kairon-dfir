from importlib import import_module


__all__ = [
    "ChromiumHistoryParser",
    "FirefoxPlacesParser",
    "classify_browser_artifact",
    "looks_like_browser_artifact",
    "normalize_browser_event",
    "parse_chromium_history_sqlite",
    "parse_firefox_places_sqlite",
    "read_browser_records",
]


_EXPORTS = {
    "classify_browser_artifact": ("app.ingest.browser.detector", "classify_browser_artifact"),
    "looks_like_browser_artifact": ("app.ingest.browser.detector", "looks_like_browser_artifact"),
    "normalize_browser_event": ("app.ingest.browser.normalizer", "normalize_browser_event"),
    "read_browser_records": ("app.ingest.browser.parser", "read_browser_records"),
    "ChromiumHistoryParser": ("app.ingest.browser.sqlite_chromium", "ChromiumHistoryParser"),
    "parse_chromium_history_sqlite": ("app.ingest.browser.sqlite_chromium", "parse_chromium_history_sqlite"),
    "FirefoxPlacesParser": ("app.ingest.browser.sqlite_firefox", "FirefoxPlacesParser"),
    "parse_firefox_places_sqlite": ("app.ingest.browser.sqlite_firefox", "parse_firefox_places_sqlite"),
}


def __getattr__(name: str):
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    module_name, attr_name = target
    module = import_module(module_name)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value
