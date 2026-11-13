"""Memory tools of the assistant / MCP server: ids that resolve, rows that keep
their process, Defender download URLs, recovered file reads, executions.

All data here is synthetic.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.ai import memory_tools
from app.services.ai import tools as tools_module

WEBFILE = (
    "AV:[Windows Defender] EVENT:[2024-01-02T10:00:00.000Z DETECTIONEVENT MPSOURCE_IOAV "
    "Trojan:Win32/Example.A file:C:\\Users\\analyst\\Downloads\\tool.exe;"
    "webfile:C:\\Users\\analyst\\Downloads\\tool.exe|http://203.0.113.10:8080/tool.exe|pid:4242,ProcessStart:1;]"
)


class FakeClient:
    def __init__(self, *, search=None, get=None):
        self._search = search or (lambda **kw: {"hits": {"hits": []}})
        self._get = get
        self.searches = []

    def search(self, index, body, params=None):
        self.searches.append((index, body))
        return self._search(index=index, body=body)

    def get(self, index, id):
        if self._get is None:
            raise LookupError("not found")
        return self._get(index=index, id=id)


# --------------------------------------------------------------------------
# Rows and ids
# --------------------------------------------------------------------------

def test_a_network_row_keeps_its_process_and_endpoints():
    item = {
        "id": "memory:doc-1", "title": "TCPv4", "artifact_type": "memory_network_connection",
        "raw": {"pid": 4242, "process_name": "tool.exe", "protocol": "TCPv4", "local_address": "192.0.2.5",
                "local_port": 49700, "remote_address": "203.0.113.10", "remote_port": 443,
                "connection_state": "ESTABLISHED", "evidence_id": "ev-1"},
    }
    row = memory_tools.memory_row(item, ("id", "title", "artifact_type"))
    assert row["pid"] == 4242
    assert row["process_name"] == "tool.exe"
    assert row["remote_address"] == "203.0.113.10"
    assert row["remote_port"] == 443
    assert row["state"] == "ESTABLISHED"
    assert row["id"] == "memory:doc-1"


def test_a_memory_timeline_row_hands_out_an_id_get_event_detail_can_read():
    memory_row = {"id": "memory-timeline:abc", "raw": {"raw_reference": {"document_id": "run:memory_process_entity:x"}}}
    disk_row = {"id": "memory-timeline:def", "raw": {"raw_reference": {"opensearch_id": "evt-9"}}}
    plain = {"id": "evt-1"}
    assert memory_tools.detail_id(memory_row) == "memory:run:memory_process_entity:x"
    assert memory_tools.detail_id(disk_row) == "evt-9"
    assert memory_tools.detail_id(plain) == "evt-1"


def test_get_timeline_returns_resolvable_ids(monkeypatch):
    monkeypatch.setattr(
        "app.services.timeline_service.build_lightweight_timeline_response",
        lambda db, case_id, params: {"total": 1, "items": [
            {"id": "memory-timeline:abc", "timestamp": "2024-01-02T10:00:00Z", "title": "Process start",
             "raw": {"raw_reference": {"document_id": "doc-7"}}},
        ]},
    )
    result = tools_module.tool_get_timeline(None, "case-1", {})
    entry = result["entries"][0]
    assert entry["id"] == "memory:doc-7"
    # A memory artifact is not in Search; no pivot link that would find nothing.
    assert "open_in_search" not in entry


def test_get_event_detail_reads_memory_ids_from_the_memory_index(monkeypatch):
    seen = {}

    def fake_detail(db, case_id, event_id):
        seen["id"] = event_id
        return {"found": True, "event_id": event_id, "source": "memory", "fields": {"pid": 1}}

    monkeypatch.setattr(memory_tools, "memory_event_detail", fake_detail)
    result = tools_module.tool_get_event_detail(None, "case-1", {"event_id": "memory:doc-7"})
    assert result["found"] is True and result["source"] == "memory"
    assert seen["id"] == "memory:doc-7"


def test_an_unknown_memory_id_says_so_instead_of_searching_the_event_index(monkeypatch):
    monkeypatch.setattr(memory_tools, "memory_event_detail", lambda db, case_id, event_id: None)
    monkeypatch.setattr(
        "app.core.opensearch.fetch_event_by_id",
        lambda *a, **kw: pytest.fail("a memory id must not be looked up as an event"),
    )
    result = tools_module.tool_get_event_detail(None, "case-1", {"event_id": "memory:gone"})
    assert result["found"] is False


def test_memory_event_detail_refuses_a_document_of_another_case(monkeypatch):
    client = FakeClient(get=lambda index, id: {"_id": id, "_source": {"case_id": "other-case", "document_type": "memory_handle"}})
    monkeypatch.setattr("app.core.opensearch.get_opensearch_client", lambda **kw: client)
    db = SimpleNamespace(get=lambda model, key: None)
    assert memory_tools.memory_event_detail(db, "case-1", "memory:doc-1") is None


def test_memory_event_detail_returns_the_document_fields(monkeypatch):
    source = {"case_id": "case-1", "evidence_id": "ev-1", "document_type": "memory_network_connection",
              "pid": 4242, "process_name": "tool.exe", "remote_address": "203.0.113.10", "remote_port": 443}
    client = FakeClient(get=lambda index, id: {"_id": id, "_source": source})
    monkeypatch.setattr("app.core.opensearch.get_opensearch_client", lambda **kw: client)
    db = SimpleNamespace(get=lambda model, key: SimpleNamespace(id=key, original_filename="image.raw"))
    detail = memory_tools.memory_event_detail(db, "case-1", "memory:doc-1")
    assert detail["found"] is True
    assert detail["evidence_name"] == "image.raw"
    assert detail["fields"]["pid"] == 4242
    assert detail["fields"]["remote_address"] == "203.0.113.10"


# --------------------------------------------------------------------------
# Defender download URLs
# --------------------------------------------------------------------------

def test_a_defender_webfile_resource_gives_path_url_and_pid():
    assert memory_tools.parse_webfile(WEBFILE) == [{
        "file_path": "C:\\Users\\analyst\\Downloads\\tool.exe",
        "url": "http://203.0.113.10:8080/tool.exe",
        "downloading_pid": 4242,
    }]


def test_a_webfile_without_a_url_is_not_a_download():
    assert memory_tools.parse_webfile("webfile:C:\\x\\a.exe|pid:1") == []
    assert memory_tools.parse_webfile("file:C:\\x\\a.exe") == []
    assert memory_tools.parse_webfile(None) == []


def test_defender_downloads_come_from_memory_and_from_the_logs(monkeypatch):
    def search(index, body):
        if index.startswith("mem"):
            return {"hits": {"hits": [{"_source": {"description": WEBFILE, "evidence_id": "ev-1"}},
                                      {"_source": {"description": WEBFILE, "evidence_id": "ev-1"}}]}}
        return {"hits": {"hits": [{"_id": "evt-1", "_source": {
            "@timestamp": "2024-01-03T00:00:00Z",
            "defender": {"resource": "webfile:_C:\\Temp\\b.ps1|https://example.com/b.ps1|pid:7", "threat_name": "X"},
            "host": {"name": "WS01"}}}]}}

    client = FakeClient(search=search)
    monkeypatch.setattr("app.core.opensearch.get_opensearch_client", lambda **kw: client)
    monkeypatch.setattr("app.core.opensearch.get_memory_index", lambda case_id: "mem-case")
    monkeypatch.setattr("app.core.opensearch.get_events_index", lambda case_id=None: "events-case")
    monkeypatch.setattr(memory_tools, "_memory_evidences", lambda db, case_id, evidence_id: [SimpleNamespace(id="ev-1", host_id=None, detected_host=None)])

    result = memory_tools.defender_downloads(None, "case-1", None, 10)
    assert result["warnings"] == []
    # The same detection reported twice in memory is one download.
    assert result["total"] == 2
    by_source = {row["source"]: row for row in result["rows"]}
    assert by_source["defender_in_memory"]["url"] == "http://203.0.113.10:8080/tool.exe"
    assert by_source["defender_in_memory"]["downloading_pid"] == 4242
    assert by_source["defender_log"]["file_path"] == "C:\\Temp\\b.ps1"
    assert by_source["defender_log"]["id"] == "evt-1"


def test_list_downloads_counts_defender_as_its_own_source(monkeypatch):
    monkeypatch.setattr("app.services.motw.list_motw_items", lambda db, case_id, params: {"total": 0, "summary": {}, "items": []})
    monkeypatch.setattr("app.services.search_service.search_events_v2", lambda case_id, params, db=None: (0, [], [], {}))
    monkeypatch.setattr("app.services.search_service.build_search_v2_params", lambda **kw: dict(kw))
    monkeypatch.setattr(
        memory_tools, "defender_downloads",
        lambda db, case_id, host, limit: {"total": 1, "rows": [{"url": "http://203.0.113.10/a.exe", "source": "defender_in_memory"}], "warnings": []},
    )
    result = tools_module.tool_list_downloads(None, "case-1", {})
    assert result["by_source"]["defender_detections"] == 1
    assert result["total_downloads"] == 1
    assert result["downloads"][0]["source"] == "defender_in_memory"
    assert result["note"] is None


# --------------------------------------------------------------------------
# Recovered files
# --------------------------------------------------------------------------

def _extraction(tmp_path, content: bytes, monkeypatch, case_id="case-1"):
    path = tmp_path / "file.dat"
    path.write_bytes(content)
    extraction = SimpleNamespace(id="x-1", case_id=case_id, evidence_id="ev-1", requested_path="\\Temp\\note.txt", results_json=[{}])
    monkeypatch.setattr("app.services.memory.file_extraction.get_memory_file_extraction", lambda db, extraction_id: extraction)
    monkeypatch.setattr("app.services.memory.file_extraction.resolve_extraction_result_file", lambda extraction, index: path)
    return SimpleNamespace(get=lambda model, key: SimpleNamespace(id=key, case_id=case_id))


def test_reading_a_recovered_file_as_text(tmp_path, monkeypatch):
    db = _extraction(tmp_path, b"hello from memory\n", monkeypatch)
    result = memory_tools.tool_read_memory_extracted_file(db, "case-1", {"extraction_id": "x-1"})
    assert result["text"] == "hello from memory\n"
    assert result["more"] is False


def test_utf16_text_is_decoded(tmp_path, monkeypatch):
    db = _extraction(tmp_path, "net user admin /add".encode("utf-16le"), monkeypatch)
    result = memory_tools.tool_read_memory_extracted_file(db, "case-1", {"extraction_id": "x-1"})
    assert result["encoding"] == "utf-16le"
    assert result["text"] == "net user admin /add"


def test_zero_filled_pages_are_called_out_with_where_content_starts(tmp_path, monkeypatch):
    db = _extraction(tmp_path, b"\x00" * 8192 + b"real content", monkeypatch)
    result = memory_tools.tool_read_memory_extracted_file(db, "case-1", {"extraction_id": "x-1", "length": 64})
    assert result["zero_filled"] is True
    assert result["next_content_offset"] == 8192


def test_hex_and_strings_modes(tmp_path, monkeypatch):
    content = b"\x00\x01MZ\x90\x00" + b"http://203.0.113.10/c2" + b"\x00" * 4 + "secret".encode("utf-16le")
    db = _extraction(tmp_path, content, monkeypatch)
    hexed = memory_tools.tool_read_memory_extracted_file(db, "case-1", {"extraction_id": "x-1", "mode": "hex", "length": 16})
    assert hexed["hex"].startswith("00000000  00 01 4d 5a 90 00")
    strings = memory_tools.tool_read_memory_extracted_file(db, "case-1", {"extraction_id": "x-1", "mode": "strings"})
    texts = {(s["encoding"], s["text"]) for s in strings["strings"]}
    assert ("ascii", "http://203.0.113.10/c2") in texts
    assert ("utf-16le", "secret") in texts
    filtered = memory_tools.tool_read_memory_extracted_file(db, "case-1", {"extraction_id": "x-1", "mode": "strings", "query": "secret"})
    assert [s["text"] for s in filtered["strings"]] == ["secret"]


def test_an_extraction_of_another_case_is_refused(tmp_path, monkeypatch):
    db = _extraction(tmp_path, b"x", monkeypatch, case_id="other-case")
    result = tools_module.run_tool(db, "case-1", "read_memory_extracted_file", {"extraction_id": "x-1"})
    assert "No extraction" in result["error"]


def test_a_bad_mode_is_an_error_the_model_can_fix(tmp_path, monkeypatch):
    db = _extraction(tmp_path, b"x", monkeypatch)
    db.rollback = lambda: None
    result = tools_module.run_tool(db, "case-1", "read_memory_extracted_file", {"extraction_id": "x-1", "mode": "pdf"})
    assert "mode must be" in result["error"]


# --------------------------------------------------------------------------
# Executions and file objects
# --------------------------------------------------------------------------

def test_list_executions_reports_each_source(monkeypatch):
    monkeypatch.setattr(memory_tools, "_memory_evidences_for_host", lambda db, case_id, host: [SimpleNamespace(id="ev-1")])
    monkeypatch.setattr(memory_tools, "_registry_run_id", lambda evidence_id, case_id, db=None: "run-1")
    monkeypatch.setattr(memory_tools, "_registry_executions", lambda case_id, run_ids, name, limit: {
        "by_category": {"memory_registry_bam": 1},
        "rows": [{"source": "memory_registry_bam", "program": "\\Device\\HarddiskVolume3\\Tools\\tool.exe"}],
    })
    monkeypatch.setattr(memory_tools, "_memory_process_executions", lambda db, case_id, host, name, limit: {
        "total": 2,
        "rows": [{"pid": 10, "process_name": "tool.exe", "terminated": True}],
        "notes": [],
        "warnings": [],
    })
    monkeypatch.setattr(memory_tools, "_event_executions", lambda db, case_id, host, name, limit: {
        "by_artifact": {"memprocfs_prefetch": 3},
        "rows": [{"id": "e1", "artifact_type": "memprocfs_prefetch"}],
        "warnings": [],
    })
    result = memory_tools.tool_list_executions(None, "case-1", {"process_name": "tool"})
    assert result["by_source"] == {"memory_processes": 2, "memprocfs_prefetch": 3, "memory_registry_bam": 1}
    assert result["registry_in_memory"][0]["source"] == "memory_registry_bam"
    assert result["memory_processes"][0]["terminated"] is True
    assert result["note"] is None


def test_no_execution_source_is_explained_not_reported_as_nothing_ran(monkeypatch):
    monkeypatch.setattr(memory_tools, "_memory_evidences_for_host", lambda db, case_id, host: [])
    monkeypatch.setattr(memory_tools, "_registry_executions", lambda *a: {"by_category": {}, "rows": []})
    monkeypatch.setattr(memory_tools, "_memory_process_executions", lambda *a: {"total": 0, "rows": [], "notes": ["No process pool scan (psscan) on image.raw"], "warnings": []})
    monkeypatch.setattr(memory_tools, "_event_executions", lambda *a: {"by_artifact": {}, "rows": [], "warnings": []})
    result = memory_tools.tool_list_executions(None, "case-1", {})
    assert "psscan" in result["note"]
    assert "No execution evidence found" in result["note"]


def test_list_memory_files_says_which_images_had_no_file_scan(monkeypatch):
    monkeypatch.setattr(memory_tools, "_memory_evidences", lambda db, case_id, evidence_id: [SimpleNamespace(id="ev-1", original_filename="image.raw")])
    monkeypatch.setattr(memory_tools, "_active_run_id", lambda db, case_id, evidence_id, family: None)
    result = memory_tools.tool_list_memory_files(None, "case-1", {"name": "Downloads"})
    assert result["total_matches"] == 0
    assert "not analysed" in result["note"]


def test_list_memory_files_lists_matching_paths(monkeypatch):
    monkeypatch.setattr(memory_tools, "_memory_evidences", lambda db, case_id, evidence_id: [SimpleNamespace(id="ev-1", original_filename="image.raw")])
    monkeypatch.setattr(memory_tools, "_active_run_id", lambda db, case_id, evidence_id, family: "run-1")
    captured = {}

    def fake_search(case_id, **kw):
        captured.update(kw)
        return {"total": 1, "items": [{"name": "\\Users\\analyst\\Downloads\\tool.exe", "offset": "1", "source_plugin": "windows.filescan"}]}

    monkeypatch.setattr("app.services.memory.artifact_indexing.search_artifact_documents", fake_search)
    result = memory_tools.tool_list_memory_files(None, "case-1", {"name": "Downloads"})
    assert captured["document_type"] == "memory_file_object"
    assert captured["run_id"] == "run-1"
    assert captured["filters"] == {"name": "Downloads"}
    assert result["files"][0]["name"].endswith("tool.exe")
    assert result["note"] is None


def test_find_evil_filters_by_indicator_prefix(monkeypatch):
    monkeypatch.setattr(memory_tools, "_memory_evidences", lambda db, case_id, evidence_id: [SimpleNamespace(id="ev-1", original_filename="image.raw")])
    monkeypatch.setattr(memory_tools, "_active_run_id", lambda db, case_id, evidence_id, family: "run-1")
    monkeypatch.setattr("app.services.memory.artifact_indexing.search_artifact_documents", lambda case_id, **kw: {"total": 3, "items": [
        {"document_id": "d1", "indicator_type": "YR_EXAMPLE", "process_name": "a.exe"},
        {"document_id": "d2", "indicator_type": "AV_DETECT", "description": WEBFILE},
        {"document_id": "d3", "indicator_type": "YR_OTHER", "process_name": "b.exe"},
    ]})
    result = memory_tools.tool_list_find_evil(None, "case-1", {"indicator_type": "yr_"})
    assert result["total"] == 2
    assert result["by_indicator_type"] == {"YR_EXAMPLE": 1, "YR_OTHER": 1}
    assert result["records"][0]["id"] == "memory:d1"


def test_every_new_memory_tool_is_advertised():
    names = {spec["name"] for spec in tools_module.TOOL_SPECS}
    for name in ("list_executions", "list_memory_files", "list_memory_file_extractions", "read_memory_extracted_file", "list_find_evil"):
        assert name in names
        assert name in tools_module.HANDLERS


def test_the_defender_normalizer_records_the_download_url():
    from app.ingest.defender.normalizer import normalize_defender_row

    row = {"ThreatName": "Trojan:Win32/Example.A", "EventID": "1116",
           "Path": "file:_C:\\Users\\analyst\\Downloads\\tool.exe; webfile:_C:\\Users\\analyst\\Downloads\\tool.exe|http://203.0.113.10:8080/tool.exe|pid:4242,ProcessStart:1"}
    document = normalize_defender_row({"artifact": {}, "event": {}}, row, {"defender_artifact_type": "defender_evtx"})
    assert document["url"]["full"] == "http://203.0.113.10:8080/tool.exe"
    assert document["url"]["domain"] == "203.0.113.10"
    assert document["defender"]["download_url"] == "http://203.0.113.10:8080/tool.exe"
