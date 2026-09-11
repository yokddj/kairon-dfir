"""Command History was blind to windows.consoles / linux.bash.

Both plugins recover literal shell/console input directly from memory
(cmd.exe/PowerShell console buffers on Windows, bash's in-memory history on
Linux) and are already normalized into searchable "memory_shell_history"
documents (see app.services.memory.artifact_normalizers /
app.services.memory.search's "shell_history" family) -- but
_memory_command_history only ever read process-command-line
reconstruction (windows.cmdline/pslist-family output), so a memory-only
case where no process happened to still be resident with a recoverable
command line showed an empty Command History even when the console
history plugin recovered real commands.
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType
from app.services import investigation_memory

CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
EVIDENCE_ID = "cccccccc-3333-4333-8333-cccccccccccc"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, future=True)()
    db.add(Case(id=CASE_ID, name="Memory-only case"))
    db.add(
        Evidence(
            id=EVIDENCE_ID,
            case_id=CASE_ID,
            original_filename="mem.raw",
            stored_path="/tmp/mem.raw",
            original_path="/tmp/mem.raw",
            storage_mode=EvidenceStorageMode.uploaded,
            is_external=False,
            copy_to_storage=True,
            evidence_type=EvidenceType.memory_dump,
            sha256="0" * 64,
            size_bytes=128,
            provided_platform="auto",
            detected_platform="memory",
            effective_platform="memory",
            path_validation={},
            ingest_source={},
            metadata_json={},
            error_log={},
        )
    )
    db.commit()
    return db


def test_command_history_includes_console_recovered_shell_history(monkeypatch):
    monkeypatch.setattr(
        investigation_memory,
        "build_command_line_history",
        lambda **kwargs: {"items": [], "selected_run": {"id": "run-1"}},
    )
    monkeypatch.setattr(
        investigation_memory,
        "search_memory_artifacts",
        lambda db, **kwargs: {
            "results": [
                {
                    "result_id": "doc-1",
                    "memory_run_id": "run-1",
                    "source_plugin": "windows.consoles",
                    "pid": 4321,
                    "process_name": "powershell.exe",
                    "raw": {
                        "document_id": "doc-1",
                        "command": "whoami /all",
                        "pid": 4321,
                        "process_name": "powershell.exe",
                        "process_entity_id": None,
                    },
                }
            ]
        },
    )

    db = _db()
    result = investigation_memory.memory_command_history(db, CASE_ID, {})

    assert result["total"] == 1
    row = result["items"][0]
    assert row["command"] == "whoami /all"
    assert row["artifact_type"] == "memory_shell_history"
    assert row["source_plugin_or_parser"] == "windows.consoles"
    assert row["timestamp"] is None
    assert row["timestamp_status"] == "undated"
    assert row["process"]["name"] == "powershell.exe"


def test_command_history_merges_both_sources(monkeypatch):
    monkeypatch.setattr(
        investigation_memory,
        "build_command_line_history",
        lambda **kwargs: {
            "items": [{"process_entity_id": "pe-1", "pid": 111, "process_name": "cmd.exe", "command_line": "dir C:\\", "create_time": "2024-02-03T07:34:18Z"}],
            "selected_run": {"id": "run-1"},
        },
    )
    monkeypatch.setattr(
        investigation_memory,
        "search_memory_artifacts",
        lambda db, **kwargs: {
            "results": [
                {
                    "result_id": "doc-1",
                    "memory_run_id": "run-1",
                    "source_plugin": "windows.consoles",
                    "raw": {"document_id": "doc-1", "command": "net user", "pid": 222, "process_name": "cmd.exe"},
                }
            ]
        },
    )

    db = _db()
    result = investigation_memory.memory_command_history(db, CASE_ID, {})

    assert result["total"] == 2
    commands = {row["command"] for row in result["items"]}
    assert commands == {"dir C:\\", "net user"}
    artifact_types = {row["artifact_type"] for row in result["items"]}
    assert artifact_types == {"memory_command_line", "memory_shell_history"}
