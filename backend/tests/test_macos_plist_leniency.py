"""A malformed XML property list never fails a macOS parser: a bare "&" is read, anything else is
reported as an unreadable plist. Synthetic plists only."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.ingest.macos.common import load_plist
from app.ingest.macos.launchd import parse_launchd_plist

HEADER = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n'


def _plist(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "com.example.agent.plist"
    path.write_text(HEADER + body + "\n</plist>\n", encoding="utf-8")
    return path


def test_a_bare_ampersand_is_read(tmp_path: Path) -> None:
    path = _plist(tmp_path, "<dict><key>Label</key><string>com.example.agent</string><key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>a && b &amp; c</string></array></dict>")
    plist = load_plist(path)
    assert plist["ProgramArguments"][-1] == "a && b & c"
    rows = parse_launchd_plist(path, source_path="[root]/Library/LaunchAgents/com.example.agent.plist")
    assert rows[0].get("event_action") != "launchd_plist_unreadable"


def test_other_malformed_xml_is_an_unreadable_plist_not_a_failure(tmp_path: Path) -> None:
    path = _plist(tmp_path, "<dict><key>Label</key><string>broken <here</string></dict>")
    with pytest.raises(ValueError, match="not a readable property list"):
        load_plist(path)
    rows = parse_launchd_plist(path, source_path="[root]/Library/LaunchAgents/com.example.agent.plist")
    assert [row["event_action"] for row in rows] == ["launchd_plist_unreadable"]
