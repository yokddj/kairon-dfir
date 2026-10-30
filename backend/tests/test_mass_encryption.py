"""Built-in detection of files encrypted in bulk (app.services.mass_encryption)."""

from __future__ import annotations

from app.rules_engine.builtin_catalog import get_builtin_detection_definition
from app.services import mass_encryption
from app.services.mass_encryption import find_bursts, renamed_file


def _event(path: str, time: str, host: str = "PC1", event_id: str | None = None) -> dict:
    return {"event_id": event_id or f"{path}|{time}", "@timestamp": time, "file": {"path": path, "name": path.rsplit("\\", 1)[-1]}, "host": {"name": host}}


DOCUMENTS = ["Memo.docx", "Q1 Minutes.docx", "Finance.xlsx", "handbook.docx", "Slides.pptx", "scan.pdf"]


def test_a_data_file_with_an_extension_appended_is_a_rename_candidate() -> None:
    assert renamed_file("Memo.docx.enc") == ("Memo.docx", "enc")
    assert renamed_file("REPORT.PDF.LOCKED") == ("REPORT.PDF", "locked")


def test_routine_suffixes_and_ordinary_names_are_not() -> None:
    # The Recent folder's shortcuts, downloads in progress, backups and plain files.
    for name in ("Memo.docx.lnk", "setup.zip.crdownload", "Memo.docx.bak", "Memo.docx", "archive.tar.gz", "photo.jpg.png", "backup.exe", None):
        assert renamed_file(name) is None


def test_many_documents_renamed_within_minutes_are_one_burst() -> None:
    events = [_event(f"C:\\Users\\a\\Desktop\\{name}.enc", f"2025-03-07T19:41:{index:02d}Z") for index, name in enumerate(DOCUMENTS)]
    # The same file read and written again does not count twice.
    events.append(_event("C:\\Users\\a\\Desktop\\Memo.docx.enc", "2025-03-07T19:41:30Z", event_id="again"))
    bursts = find_bursts(events)
    assert len(bursts) == 1
    assert bursts[0]["extension"] == "enc" and bursts[0]["host"] == "PC1" and len(bursts[0]["members"]) == len(DOCUMENTS)
    assert bursts[0]["members"][0]["event_id"].startswith("C:\\Users\\a\\Desktop\\Memo.docx.enc|")


def test_a_few_files_or_files_spread_over_hours_are_not() -> None:
    few = [_event(f"C:\\d\\{name}.enc", "2025-03-07T19:41:00Z") for name in DOCUMENTS[: mass_encryption.MIN_FILES - 1]]
    assert find_bursts(few) == []
    spread = [_event(f"C:\\d\\{name}.enc", f"2025-03-07T{10 + index:02d}:00:00Z") for index, name in enumerate(DOCUMENTS)]
    assert find_bursts(spread) == []


def test_hosts_and_extensions_are_judged_apart() -> None:
    events = [_event(f"C:\\d\\{name}.enc", "2025-03-07T19:41:00Z", host="PC1" if index % 2 else "PC2") for index, name in enumerate(DOCUMENTS)]
    events += [_event(f"C:\\d\\{name}.crypt", "2025-03-07T19:41:00Z") for name in DOCUMENTS[:3]]
    assert find_bursts(events) == []


def test_detections_link_the_first_file_and_list_the_rest(monkeypatch) -> None:
    import app.core.detections as detections

    events = [_event(f"C:\\Users\\a\\Desktop\\{name}.enc", f"2025-03-07T19:41:{index:02d}Z") for index, name in enumerate(DOCUMENTS)]
    monkeypatch.setattr(mass_encryption, "_query_events", lambda case_id, evidence_id: events)
    created: list[dict] = []
    monkeypatch.setattr(detections, "create_detection_if_missing", lambda db, **kwargs: (created.append(kwargs), (None, True))[1])

    class FakeDb:
        def commit(self) -> None:
            pass

    assert mass_encryption.detect_mass_file_encryption(FakeDb(), case_id="c", evidence_id="e") == 1
    detection = created[0]
    assert detection["rule_name"] == "Built-in: Possible mass file encryption" and detection["engine"] == "builtin"
    assert detection["event_id"] == events[0]["event_id"] and len(detection["related_event_ids"]) == len(DOCUMENTS)
    assert detection["mitre"] == ["T1486"] and detection["matched_at"] == "2025-03-07T19:41:00Z"
    assert "6 data files reappeared with the extension .enc in 1 folder within 5 s" in detection["message"]
    assert get_builtin_detection_definition(mass_encryption.RULE_KEY).name == "Possible mass file encryption"
