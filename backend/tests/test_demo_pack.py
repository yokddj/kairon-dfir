from __future__ import annotations

from pathlib import Path
import sys
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DEMO = REPO_ROOT / "tools" / "demo"
if str(TOOLS_DEMO) not in sys.path:
    sys.path.insert(0, str(TOOLS_DEMO))

from generate_demo_evidence import generate_demo_evidence  # noqa: E402


def test_demo_generator_creates_zip_with_expected_artifacts(tmp_path: Path) -> None:
    output = tmp_path / "acme_incident_001.zip"
    generated = generate_demo_evidence(output)
    assert generated.exists()
    with zipfile.ZipFile(generated) as archive:
        names = set(archive.namelist())
    expected = {
        "Security-EvtxECmd.csv",
        "PowerShell-EvtxECmd.csv",
        "Defender.csv",
        "phishing.eml",
        "RECmd_UserActivity_HighSignal.csv",
        "zone_identifier.csv",
        "thumbcache.csv",
        "OneDrive_Audit.csv",
        "usb_registry_sample.csv",
        "malicious_marker.txt",
    }
    assert expected.issubset(names)


def test_demo_generator_uses_generic_names_only(tmp_path: Path) -> None:
    output = tmp_path / "acme_incident_001.zip"
    generated = generate_demo_evidence(output)
    forbidden = ("movistar", "movistar-pc", "desktop-b52vgbl", "win-2vetvgkglqv", "192.168.1.19")
    with zipfile.ZipFile(generated) as archive:
        for name in archive.namelist():
            lower_name = name.lower()
            assert not any(token in lower_name for token in forbidden)
            if name.endswith((".csv", ".json", ".jsonl", ".txt", ".eml", ".yml", ".yaml", ".yar", ".ps1")):
                content = archive.read(name).decode("utf-8", errors="ignore").lower()
                assert not any(token in content for token in forbidden)
