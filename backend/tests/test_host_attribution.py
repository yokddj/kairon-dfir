from types import SimpleNamespace

from app.services import host_attribution


def test_classify_host_candidate_rejects_driver_and_remote_domain() -> None:
    driver = host_attribution.classify_host_candidate("applockerfltr", source="evtx_computer")
    remote = host_attribution.classify_host_candidate("client.wns.windows.com", source="evtx_computer")

    assert driver["accepted"] is False
    assert driver["rejected_reason"] == "driver_or_filter_name"
    assert remote["accepted"] is False
    assert remote["rejected_reason"] == "remote_domain"


def test_choose_primary_host_prefers_collection_candidate_over_noisy_values() -> None:
    primary = host_attribution.choose_primary_host(
        collection_candidate="movistar-pc",
        host_counts={"applockerfltr": 2000, "movistar-pc": 100, "desktop-b52vgbl": 20},
    )

    assert primary["host"] == "movistar-pc"
    assert primary["confidence"] == "high"


def test_build_host_attribution_keeps_primary_and_aliases_but_rejects_noise(monkeypatch) -> None:
    evidence = SimpleNamespace(
        id="ev-1",
        original_filename="Collection-movistar-pc-2026-05-15T08_25_02Z.zip",
        stored_path="/tmp/Collection-movistar-pc-2026-05-15T08_25_02Z.zip",
        original_path="/tmp/Collection-movistar-pc-2026-05-15T08_25_02Z.zip",
        detected_host=None,
        metadata_json={},
    )
    finding = SimpleNamespace(severity="high", risk_score=90, related_hosts=["movistar-pc"])

    monkeypatch.setattr(
        host_attribution,
        "aggregate_host_counts",
        lambda case_id, evidence_id=None, size=25: {
            "movistar-pc": 92512,
            "desktop-b52vgbl": 2321,
            "win-2vetvgkglqv": 1185,
            "applockerfltr": 2073,
            "client.wns.windows.com": 51,
            "cldflt": 42,
        },
    )
    monkeypatch.setattr(
        host_attribution,
        "sample_host_events",
        lambda case_id, host_value, evidence_id=None, size=5: [{"windows": {"computer": host_value}}]
        if host_value in {"movistar-pc", "desktop-b52vgbl", "win-2vetvgkglqv"}
        else [{"windows": {"computer": None}}],
    )

    attribution = host_attribution.build_host_attribution("case-1", evidences=[evidence], findings=[finding])

    assert attribution["primary_host"] == "movistar-pc"
    assert [item["host"] for item in attribution["hosts"]] == ["movistar-pc", "desktop-b52vgbl", "win-2vetvgkglqv"]
    rejected = {item["value"]: item["reason"] for item in attribution["rejected_host_candidates"]}
    assert rejected["applockerfltr"] == "driver_or_filter_name"
    assert rejected["client.wns.windows.com"] == "remote_domain"


def test_build_host_attribution_rejects_remote_workstation_name_candidates(monkeypatch) -> None:
    evidence = SimpleNamespace(
        id="ev-1",
        original_filename="Collection-movistar-pc-2026-05-15T08_25_02Z.zip",
        stored_path="/tmp/Collection-movistar-pc-2026-05-15T08_25_02Z.zip",
        original_path="/tmp/Collection-movistar-pc-2026-05-15T08_25_02Z.zip",
        detected_host=None,
        metadata_json={},
    )

    monkeypatch.setattr(
        host_attribution,
        "aggregate_host_counts",
        lambda case_id, evidence_id=None, size=25: {
            "movistar-pc": 94116,
            "desktop-b52vgbl": 2345,
            "win-2vetvgkglqv": 1197,
            "proxmox": 1,
        },
    )

    def _samples(case_id, host_value, evidence_id=None, size=5):
        if host_value in {"movistar-pc", "desktop-b52vgbl", "win-2vetvgkglqv"}:
            return [{"windows": {"computer": host_value, "event_data": {}}}]
        if host_value == "proxmox":
            return [{
                "windows": {
                    "computer": "proxmox",
                    "event_data": {
                        "WorkstationName": "proxmox",
                        "TargetDomainName": "movistar-pc",
                        "IpAddress": "192.168.1.14",
                        "LogonType": "3",
                    },
                }
            }]
        return [{"windows": {"computer": None, "event_data": {}}}]

    monkeypatch.setattr(host_attribution, "sample_host_events", _samples)

    attribution = host_attribution.build_host_attribution("case-1", evidences=[evidence], findings=[])

    assert [item["host"] for item in attribution["hosts"]] == ["movistar-pc", "desktop-b52vgbl", "win-2vetvgkglqv"]
    rejected = {item["value"]: item["reason"] for item in attribution["rejected_host_candidates"]}
    assert rejected["proxmox"] == "remote_workstation_name"


def test_host_attribution_report_contains_primary_alias_and_rejected(monkeypatch) -> None:
    evidence = SimpleNamespace(
        id="ev-1",
        original_filename="Collection-movistar-pc-2026-05-15T08_25_02Z.zip",
        stored_path="/tmp/Collection-movistar-pc-2026-05-15T08_25_02Z.zip",
        original_path="/tmp/Collection-movistar-pc-2026-05-15T08_25_02Z.zip",
        detected_host=None,
        metadata_json={},
    )
    monkeypatch.setattr(
        host_attribution,
        "build_host_attribution",
        lambda case_id, evidences, findings, top_host_counts=None: {
            "primary_host": "movistar-pc",
            "hosts": [{"host": "movistar-pc", "is_primary": True}],
            "host_candidates": [{"value": "desktop-b52vgbl", "classification": "possible_alias"}],
            "rejected_host_candidates": [{"value": "applockerfltr", "reason": "driver_or_filter_name"}],
            "evidence_summaries": {
                "ev-1": {
                    "primary_host": "movistar-pc",
                    "primary_host_source": "collection_metadata|evtx_computer",
                    "primary_host_confidence": "high",
                }
            },
            "top_raw_host_values": {"movistar-pc": 10, "applockerfltr": 5},
        },
    )

    report = host_attribution.build_host_attribution_report("case-1", evidences=[evidence], findings=[])

    assert report["primary_host"] == "movistar-pc"
    assert report["primary_host_confidence"] == "high"
    assert report["host_alias_candidates"][0]["value"] == "desktop-b52vgbl"
    assert report["host_candidates_rejected"][0]["value"] == "applockerfltr"
