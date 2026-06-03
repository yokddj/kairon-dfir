from __future__ import annotations

from app.services import indicator_resolution


class _Db:
    pass


def test_extracts_windows_relative_ads_url_domain_email_and_registry():
    result = indicator_resolution.extract_indicators(
        {
            "source": {
                "command_line": r'powershell.exe -NoExit .\f\script.ps1',
                "file_path": r"C:\Users\usera\Downloads\sample.iso:Zone.Identifier",
                "url": "https://files.example/download",
                "email": "user.a@outlook.es",
                "registry": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive",
            }
        }
    )
    values = {(item["type"], item["normalized"]) for item in result["indicators"]}

    assert ("path", r".\f\script.ps1") in values
    assert ("path", r"C:\Users\usera\Downloads\sample.iso:Zone.Identifier") in values
    assert ("url", "https://files.example/download") in values
    assert ("email", "user.a@outlook.es") in values
    assert any(item[0] == "registry" and "CurrentVersion" in item[1] for item in values)


def test_extractor_avoids_narrative_as_basename():
    result = indicator_resolution.extract_indicators(
        {
            "source": {
                "title": "Suspicious ISO appears on HOSTA",
                "description": "User activity and filesystem evidence identify the lure that starts the investigation. sample.iso",
            }
        }
    )

    names = [item["indicator"] for item in result["indicators"] if item["type"] in {"file", "path"}]
    assert "sample.iso" in names
    assert not any("Suspicious ISO appears" in name for name in names)


def test_resolver_returns_found_for_file_artifact(monkeypatch):
    monkeypatch.setattr(indicator_resolution, "_exact_file_count", lambda *args, **kwargs: 1)
    monkeypatch.setattr(indicator_resolution, "_event_count", lambda *args, **kwargs: 0)
    monkeypatch.setattr(indicator_resolution, "_command_count", lambda *args, **kwargs: 0)
    monkeypatch.setattr(indicator_resolution, "_time_bounds", lambda *args, **kwargs: ("2024-03-22T11:26:00Z", "2024-03-22T11:26:17Z"))

    result = indicator_resolution.resolve_indicators(
        _Db(),
        "case-1",
        {"indicators": [{"indicator": "sample.iso", "type": "file"}], "context": {"host": "HOSTA", "evidence_id": "ev-1"}},
    )

    resolved = result["results"][0]
    assert resolved["status"] == "found"
    assert resolved["counts_by_source"]["mft"] == 1
    assert any(pivot["label"] == "Find this file" for pivot in resolved["suggested_pivots"])


def test_resolver_returns_command_only_for_missing_referenced_file(monkeypatch):
    monkeypatch.setattr(indicator_resolution, "_exact_file_count", lambda *args, **kwargs: 0)

    def fake_event_count(_db, _case_id, _query, artifact_types, *_args):
        return 1 if artifact_types and "windows_event" in artifact_types else 0

    monkeypatch.setattr(indicator_resolution, "_event_count", fake_event_count)
    monkeypatch.setattr(indicator_resolution, "_command_count", lambda *args, **kwargs: 2)
    monkeypatch.setattr(indicator_resolution, "_time_bounds", lambda *args, **kwargs: ("2024-03-22T11:26:39Z", "2024-03-22T11:26:39Z"))

    result = indicator_resolution.resolve_indicators(
        _Db(),
        "case-1",
        {"indicators": [{"indicator": r".\f\script.ps1", "type": "path"}], "context": {"host": "HOSTA", "evidence_id": "ev-1"}},
    )

    resolved = result["results"][0]
    assert resolved["status"] == "command_only"
    assert resolved["counts_by_source"]["mft"] == 0
    assert resolved["counts_by_source"]["command_history"] == 2
    assert "no exact filesystem artifact" in resolved["explanation"]


def test_pivots_generated_by_type():
    file_pivots = indicator_resolution._pivots("case-1", {"indicator": "readme.txt", "type": "file"}, {"host": "SERVERA"}, None)
    domain_pivots = indicator_resolution._pivots("case-1", {"indicator": "example.com", "type": "domain"}, {}, None)
    registry_pivots = indicator_resolution._pivots("case-1", {"indicator": r"HKCU\Software\Run", "type": "registry"}, {}, None)

    assert any(pivot["label"] == "Open File Story" for pivot in file_pivots)
    assert any("network" in pivot["label"].lower() for pivot in domain_pivots)
    assert any("registry" in pivot["label"].lower() for pivot in registry_pivots)
