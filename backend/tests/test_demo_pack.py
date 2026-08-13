from __future__ import annotations

import importlib.util
from pathlib import Path
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DEMO = REPO_ROOT / "tools" / "demo"

# Imported by file path rather than via sys.path.insert() so this module
# doesn't leave a global sys.path entry for the rest of the pytest session
# to trip over.
_spec = importlib.util.spec_from_file_location("generate_demo_evidence", TOOLS_DEMO / "generate_demo_evidence.py")
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
generate_demo_evidence = _module.generate_demo_evidence


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
