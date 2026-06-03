from pathlib import Path

from app.ingest.raw_parsers.amcache_parser import amcache_native_available
from app.ingest.raw_parsers.evtx_parser import evtx_native_available
from app.ingest.raw_parsers.errors import RawParserUnsupportedError
from app.ingest.raw_parsers.registry import get_raw_parsers
from app.ingest.raw_parsers.service_parser import windows_service_native_available
from app.ingest.raw_parsers.shimcache_parser import shimcache_native_available


RAW_PARSEABLE = {
    "evtx_raw": {
        "parser": "evtx_raw",
        "parser_status": "parsed_native",
        "supported": True,
        "reason": "EVTX raw file can be parsed natively.",
        "source_tool": "native_evtx",
        "source_format": "evtx",
    },
    "lnk_raw": {
        "parser": "lnk_raw",
        "parser_status": "parsed_native",
        "supported": True,
        "reason": "LNK raw file can be parsed natively.",
        "source_tool": "native_lnk",
        "source_format": "lnk",
    },
    "prefetch_raw": {
        "parser": "prefetch_raw",
        "parser_status": "parsed_native",
        "supported": True,
        "reason": "Prefetch raw file can be parsed natively.",
        "source_tool": "native_prefetch",
        "source_format": "pf",
    },
    "amcache": {
        "parser": "amcache_raw",
        "parser_status": "parsed_native",
        "supported": True,
        "reason": "Amcache raw hive can be parsed natively.",
        "source_tool": "native_amcache",
        "source_format": "registry_hive",
    },
    "shimcache": {
        "parser": "shimcache_raw",
        "parser_status": "parsed_native",
        "supported": True,
        "reason": "Shimcache/AppCompatCache raw SYSTEM hive can be parsed natively.",
        "source_tool": "native_shimcache",
        "source_format": "registry_hive",
    },
    "service": {
        "parser": "windows_service_registry",
        "parser_status": "parsed_native",
        "supported": True,
        "reason": "Windows Services raw SYSTEM hive can be parsed natively.",
        "source_tool": "native_windows_service",
        "source_format": "registry_hive",
    },
}


def describe_raw_candidate(path: str | Path, artifact_type: str) -> dict | None:
    artifact_key = str(artifact_type or "").lower()
    descriptor = RAW_PARSEABLE.get(artifact_key)
    if not descriptor:
        return None
    if artifact_key == "evtx_raw" and not evtx_native_available():
        return {
            "parser": "evtx_raw",
            "parser_status": "detected_not_implemented",
            "supported": False,
            "reason": "EVTX raw files detected, but native EVTX parsing is not enabled in this build. Upload EvtxECmd/Hayabusa/Chainsaw output or enable the native EVTX parser.",
            "source_tool": "native_evtx",
            "source_format": "evtx",
        }
    if artifact_key == "amcache" and not amcache_native_available():
        return {
            "parser": "amcache_raw",
            "parser_status": "detected_not_implemented",
            "supported": False,
            "reason": "Amcache raw hive detected, but native Amcache parsing is not enabled in this build. Upload AmcacheParser/RECmd parsed output or enable the native Amcache parser dependency.",
            "source_tool": "native_amcache",
            "source_format": "registry_hive",
        }
    if artifact_key == "shimcache" and not shimcache_native_available():
        return {
            "parser": "shimcache_raw",
            "parser_status": "detected_not_implemented",
            "supported": False,
            "reason": "SYSTEM raw hive detected, but native Shimcache parsing is not enabled in this build. Upload AppCompatCacheParser/RECmd parsed output or enable the native Shimcache parser dependency.",
            "source_tool": "native_shimcache",
            "source_format": "registry_hive",
        }
    if artifact_key == "service" and not windows_service_native_available():
        return {
            "parser": "windows_service_registry",
            "parser_status": "detected_not_implemented",
            "supported": False,
            "reason": "SYSTEM raw hive detected, but native Windows Services parsing is not enabled in this build. Upload RECmd parsed output or enable the native registry hive parser dependency.",
            "source_tool": "native_windows_service",
            "source_format": "registry_hive",
        }
    return descriptor


def route_raw_parser(candidate_or_path: object, parser_name_hint: str | None = None):
    if parser_name_hint:
        for parser in get_raw_parsers():
            if parser.parser_name == str(parser_name_hint or "").lower() and parser.can_parse(candidate_or_path):
                return parser
    for parser in get_raw_parsers():
        if parser.can_parse(candidate_or_path):
            return parser
    raise RawParserUnsupportedError(f"No native raw parser supports {candidate_or_path!r}")
