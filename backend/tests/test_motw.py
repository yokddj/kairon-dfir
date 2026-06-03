from __future__ import annotations

import sys
import importlib.util
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_motw_path = Path(__file__).resolve().parents[1] / "app" / "services" / "motw.py"
_motw_spec = importlib.util.spec_from_file_location("motw_under_test", _motw_path)
assert _motw_spec and _motw_spec.loader
motw = importlib.util.module_from_spec(_motw_spec)
_motw_spec.loader.exec_module(motw)

_indicator_path = Path(__file__).resolve().parents[1] / "app" / "services" / "indicator_resolution.py"
_indicator_spec = importlib.util.spec_from_file_location("indicator_resolution_under_test", _indicator_path)
assert _indicator_spec and _indicator_spec.loader
indicator_resolution = importlib.util.module_from_spec(_indicator_spec)
_indicator_spec.loader.exec_module(indicator_resolution)


class _Db:
    pass


def _row(**fields):
    raw = {
        "event_id": fields.get("event_id", "evt-1"),
        "@timestamp": fields.get("timestamp", "2024-03-22T10:00:00Z"),
        "evidence_id": "ev-1",
        "host": {"name": "HOSTA"},
        "artifact": {"type": fields.get("artifact_type", "mft")},
        "event": {"message": fields.get("message", "")},
        "file": {"path": fields.get("file_path", r"C:\Users\usera\Downloads\sample.iso:Zone.Identifier")},
        **fields.get("raw_extra", {}),
    }
    return {
        "id": raw["event_id"],
        "timestamp": raw["@timestamp"],
        "host": "HOSTA",
        "summary": fields.get("summary", fields.get("message", "")),
        "artifact_type": raw["artifact"]["type"],
        "raw": raw,
    }


def test_parse_zone_identifier_content_and_mapping():
    parsed = motw.parse_zone_identifier_content(
        "[ZoneTransfer]\nZoneId=3\nReferrerUrl=https://mail.example/a\nHostUrl=https://file.io/sample.iso\n"
    )

    assert parsed["zone_id"] == 3
    assert parsed["zone_name"] == "Internet"
    assert parsed["host_url"] == "https://file.io/sample.iso"
    assert parsed["referrer_url"] == "https://mail.example/a"


def test_mft_ads_path_normalizes_to_base_file(monkeypatch):
    def fake_search(_case_id, params, **_kwargs):
        if "mft" in (params.get("artifact_type") or []):
            return 1, [_row()], [], {}
        return 0, [], [], {}

    monkeypatch.setattr(motw, "search_events_v2", fake_search)

    result = motw.list_motw_items(_Db(), "case-1", {"page_size": 50})
    item = result["items"][0]

    assert item["artifact_type"] == "motw"
    assert item["file_path"] == r"C:\Users\usera\Downloads\sample.iso"
    assert item["file_name"] == "sample.iso"
    assert item["zone_identifier_path"].endswith(":Zone.Identifier")


def test_sysmon_event_15_motw_like_event_normalized(monkeypatch):
    def fake_search(_case_id, params, **_kwargs):
        if "windows_event" in (params.get("artifact_type") or []):
            return 1, [
                _row(
                    artifact_type="windows_event",
                    file_path="",
                    message="FileCreateStreamHash TargetFilename C:\\Users\\usera\\Downloads\\sample.iso:Zone.Identifier ZoneId=3 HostUrl=https://file.io/a",
                    raw_extra={
                        "windows": {
                            "event_id": 15,
                            "event_data": {
                                "TargetFilename": r"C:\Users\usera\Downloads\sample.iso:Zone.Identifier",
                                "Contents": "[ZoneTransfer]\nZoneId=3\nHostUrl=https://file.io/a\n",
                            },
                        }
                    },
                )
            ], [], {}
        return 0, [], [], {}

    monkeypatch.setattr(motw, "search_events_v2", fake_search)

    result = motw.list_motw_items(_Db(), "case-1", {"source": ["sysmon_15"], "page_size": 50})
    item = result["items"][0]

    assert item["source_artifact"] == "sysmon_15"
    assert item["zone_id"] == 3
    assert item["zone_name"] == "Internet"
    assert item["host_url"] == "https://file.io/a"
    assert "file_sharing_host_url" in item["risk_reasons"]


def test_risk_scoring_iso_from_internet_zone():
    score, reasons = motw._score_motw(r"C:\Users\usera\Downloads\sample.iso", 3, "https://file.io/a", "", "")

    assert score >= 70
    assert "internet_or_restricted_zone" in reasons
    assert "downloaded_executable_script_archive_or_iso" in reasons
    assert "user_writable_download_path" in reasons


def test_no_hosturl_hallucination_when_absent(monkeypatch):
    monkeypatch.setattr(motw, "search_events_v2", lambda *_args, **_kwargs: (1, [_row()], [], {}))

    result = motw.list_motw_items(_Db(), "case-1", {"source": ["mft_ads"], "page_size": 50})

    assert result["items"][0]["host_url"] == ""
    assert result["items"][0]["referrer_url"] == ""


def test_indicator_resolver_counts_ads_as_motw(monkeypatch):
    monkeypatch.setattr(indicator_resolution, "_motw_count", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(indicator_resolution, "_exact_file_count", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(indicator_resolution, "_event_count", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(indicator_resolution, "_command_count", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(indicator_resolution, "_time_bounds", lambda *_args, **_kwargs: (None, None))

    result = indicator_resolution.resolve_indicators(
        _Db(),
        "case-1",
        {"indicators": [{"indicator": r"C:\Users\usera\Downloads\sample.iso:Zone.Identifier", "type": "path"}]},
    )

    resolved = result["results"][0]
    assert resolved["status"] == "found"
    assert resolved["counts_by_source"]["motw"] == 1


def test_motw_count_queries_ads_indicator(monkeypatch):
    seen = {}

    def fake_search(_case_id, params, **_kwargs):
        seen["q"] = params.get("q")
        seen["artifact_type"] = params.get("artifact_type")
        return 1, [], [], {}

    monkeypatch.setattr(indicator_resolution, "search_events_v2", fake_search)

    count = indicator_resolution._motw_count(
        _Db(),
        "case-1",
        r"C:\Users\usera\Downloads\sample.iso:Zone.Identifier",
        evidence_id=None,
        host=None,
    )

    assert count == 1
    assert "Zone.Identifier" in seen["q"]
    assert "mft" in seen["artifact_type"]
