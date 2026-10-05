from __future__ import annotations

import importlib.util
import hashlib
import re
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


# Names and an address from a real environment that must never reach the demo pack. Only their
# SHA-256 digests are kept here, so this guard does not publish them itself.
_FORBIDDEN_DIGESTS = frozenset({
    "351e239b49558dd91a5418fe692951af9c4a4e55417c90bd04b472bf7e8cf403",
    "15ba571a9202acf4a879aeb65e4a0756b298001020bd6fb6a5bc4b7d7f7ebf59",
    "29ab7b0a155839e40716b7c676af00dd334e4a1370662487c0fba523fef39b97",
    "0aec5c96e8db72bb2b145889d96e380e6d2e4d9a488f6ee1af583f00c0aa2b28",
    "8d6dd59fcb9d94f78077ea9ac8b69bc7deb27efc69240e7c4a283f503c3c4685",
})


def _contains_forbidden(text: str) -> bool:
    words = set(re.findall(r"[a-z0-9][a-z0-9.\-]*", text.lower()))
    candidates = words | {part for word in words for part in word.split("-") if part} | {word.rstrip(".") for word in words}
    return any(hashlib.sha256(candidate.encode()).hexdigest() in _FORBIDDEN_DIGESTS for candidate in candidates)


def test_demo_generator_uses_generic_names_only(tmp_path: Path) -> None:
    output = tmp_path / "acme_incident_001.zip"
    generated = generate_demo_evidence(output)
    with zipfile.ZipFile(generated) as archive:
        for name in archive.namelist():
            assert not _contains_forbidden(name)
            if name.endswith((".csv", ".json", ".jsonl", ".txt", ".eml", ".yml", ".yaml", ".yar", ".ps1")):
                assert not _contains_forbidden(archive.read(name).decode("utf-8", errors="ignore"))
