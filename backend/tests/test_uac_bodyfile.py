"""UAC bodyfile parsing and on-demand search (synthetic lines)."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from app.ingest.uac.bodyfile import parse_line
from app.services import uac_bodyfile


def test_line_read_from_the_right() -> None:
    record = parse_line("0|/Users/alice/a|b.txt|12|-rw-r--r--|501|20|42|1767225600|1767312000|1767312000|0\n")
    assert record["path"] == "/Users/alice/a|b.txt"
    assert record["size"] == 42 and record["uid"] == "501"
    assert record["mtime"] == "2026-01-02T00:00:00+00:00" and record["crtime"] is None
    link = parse_line("0|/home -> /System/Volumes/Data/home|1|lrwxr-xr-x|0|0|25|1|1|1|1\n")
    assert link["path"] == "/home" and link["link_target"] == "/System/Volumes/Data/home"
    assert parse_line("too|short\n") is None


def test_search_on_demand(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "collection"
    (root / "bodyfile").mkdir(parents=True)
    (root / "live_response").mkdir()
    (root / "uac.log").write_text("x")
    (root / "bodyfile/bodyfile.txt").write_text(
        "0|/Users/alice/Downloads/old.dmg|1|-rw-r--r--|501|20|10|0|1700000000|1700000000|1700000000\n"
        "0|/Users/alice/Downloads/new.dmg|2|-rw-r--r--|501|20|10|0|1767225600|1767225600|1767225600\n"
        "0|/etc/hosts|3|-rw-r--r--|0|0|10|0|1600000000|1600000000|1600000000\n"
    )
    monkeypatch.setattr(uac_bodyfile, "evidence_extract_dir", lambda case_id, evidence_id: tmp_path)
    evidence = SimpleNamespace(id="e", case_id="c", stored_path=None)
    found = uac_bodyfile.search(evidence, path_contains="downloads/")
    assert [record["path"] for record in found["records"]] == ["/Users/alice/Downloads/new.dmg", "/Users/alice/Downloads/old.dmg"]
    assert found["total_matches"] == 2
    limited = uac_bodyfile.search(evidence, path_contains="/", limit=1)
    assert limited["truncated"] and limited["records"][0]["path"].endswith("new.dmg")
    assert uac_bodyfile.summarize(evidence)["available"] is True
