from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET


def _text(node: ET.Element | None, tag: str) -> str | None:
    if node is None:
        return None
    value = node.findtext(f".//{{*}}{tag}")
    if value is None:
        value = node.findtext(f".//{tag}")
    return value.strip() if value and value.strip() else None


def parse_wlan_profile_xml(path: Path) -> list[dict]:
    root = ET.fromstring(path.read_text(encoding="utf-8-sig", errors="ignore"))
    shared_key = root.find(".//{*}sharedKey")
    if shared_key is None:
        shared_key = root.find(".//sharedKey")
    key_material = _text(shared_key, "keyMaterial")
    return [
        {
            "ArtifactType": "wlan_profile_xml",
            "ProfileName": _text(root, "name"),
            "SSID": _text(root, "name"),
            "SSIDHex": _text(root, "hex"),
            "ConnectionType": _text(root, "connectionType"),
            "ConnectionMode": _text(root, "connectionMode"),
            "Authentication": _text(root, "authentication"),
            "Encryption": _text(root, "encryption"),
            "UseOneX": _text(root, "useOneX"),
            "KeyType": _text(shared_key, "keyType"),
            "KeyProtected": _text(shared_key, "protected"),
            "KeyMaterial": "[REDACTED]" if key_material else None,
            "KeyMaterialPresent": bool(key_material),
            "AutoSwitch": _text(root, "autoSwitch"),
            "MacRandomization": _text(root, "enableRandomization"),
        }
    ]
