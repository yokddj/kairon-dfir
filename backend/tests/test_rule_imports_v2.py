from __future__ import annotations

from io import BytesIO
from zipfile import ZipFile

from fastapi import UploadFile
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.routes_rules import cancel_rule_import, get_rule_import, import_rule_archive, import_rule_file, list_rule_imports, list_rules
from app.models.rule_import_run import RuleImportRun, RuleImportRunStatus
from app.core.database import Base
from app.models.case import Case
from app.models.rule import Rule, RuleEngine
from app.rules_engine.sigma import compile_sigma_rule

CASE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return Session()


def _seed_case(db):
    item = Case(id=CASE_ID, name="Case")
    db.add(item)
    db.commit()
    return item


def _upload_file(name: str, content: str | bytes) -> UploadFile:
    payload = content if isinstance(content, bytes) else content.encode("utf-8")
    return UploadFile(filename=name, file=BytesIO(payload))


def _zip_file(entries: dict[str, str]) -> UploadFile:
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        for path, content in entries.items():
            archive.writestr(path, content)
    buffer.seek(0)
    return UploadFile(filename="rules.zip", file=buffer)


def test_sigma_condition_expands_one_of_selection_star() -> None:
    compiled = compile_sigma_rule(
        {
            "title": "One Of Selection",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "selection_img": {"Image|endswith": "powershell.exe"},
                "selection_cli": {"CommandLine|contains": "whoami"},
                "condition": "1 of selection*",
            },
        }
    )

    assert compiled["compile_status"] == "compiled"
    assert compiled["expanded_condition"] == "(selection_img or selection_cli)"
    assert "condition_1_of" in compiled["supported_features"]


def test_sigma_condition_expands_all_of_selection_star() -> None:
    compiled = compile_sigma_rule(
        {
            "title": "All Of Selection",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "selection_a": {"Image|endswith": "powershell.exe"},
                "selection_b": {"CommandLine|contains": "-enc"},
                "condition": "all of selection*",
            },
        }
    )

    assert compiled["compile_status"] == "compiled"
    assert compiled["expanded_condition"] == "(selection_a and selection_b)"
    assert "condition_all_of" in compiled["supported_features"]


def test_sigma_condition_expands_not_one_of_filters() -> None:
    compiled = compile_sigma_rule(
        {
            "title": "Filter Negation",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "selection": {"Image|endswith": "powershell.exe"},
                "filter_main": {"CommandLine|contains": "benign"},
                "filter_optional": {"CommandLine|contains": "lab"},
                "condition": "selection and not 1 of filter*",
            },
        }
    )

    assert compiled["compile_status"] == "compiled"
    assert compiled["expanded_condition"] == "selection and not (filter_main or filter_optional)"


def test_sigma_condition_expands_one_of_them_excluding_filters() -> None:
    compiled = compile_sigma_rule(
        {
            "title": "One Of Them",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "selection_a": {"Image|endswith": "cmd.exe"},
                "selection_b": {"CommandLine|contains": "whoami"},
                "filter_main": {"CommandLine|contains": "benign"},
                "condition": "1 of them",
            },
        }
    )

    assert compiled["compile_status"] == "compiled"
    assert compiled["expanded_condition"] == "(selection_a or selection_b)"
    assert "condition_them_excluded_filter_blocks" in compiled["compile_warnings"]


def test_sigma_condition_empty_selector_returns_clear_reason() -> None:
    compiled = compile_sigma_rule(
        {
            "title": "Missing Selector",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "selection": {"Image|endswith": "cmd.exe"},
                "condition": "1 of missing*",
            },
        }
    )

    assert compiled["compile_status"] == "skipped_unsupported_condition_empty_selector"
    assert compiled["compile_error"] == "unsupported_condition_empty_selector"


def test_sigma_condition_too_large_is_rejected() -> None:
    detection = {f"selection_{index}": {"Image|endswith": f"proc{index}.exe"} for index in range(201)}
    detection["condition"] = "1 of selection*"
    compiled = compile_sigma_rule(
        {
            "title": "Too Large",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": detection,
        }
    )

    assert compiled["compile_status"] == "skipped_expanded_condition_too_large"
    assert compiled["compile_error"] == "expanded_condition_too_large"


def test_import_single_sigma_returns_import_run_and_summary() -> None:
    db = _session()
    _seed_case(db)
    result = import_rule_file(
        file=_upload_file(
            "test.yml",
            """
title: Encoded PowerShell
id: sigma-encoded-ps
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: powershell.exe
  condition: selection
""",
        ),
        engine="sigma",
        import_mode="split",
        case_id=CASE_ID,
        namespace="lab",
        enabled=True,
        db=db,
    )

    assert result.import_run_id
    assert result.status == "completed"
    assert result.summary["status"] == "completed"
    assert result.summary["imported_count"] == 1
    assert result.imported_count == 1
    assert result.invalid_count == 0
    assert result.compiled_count == 1
    detail = get_rule_import(result.import_run_id, db)
    assert detail.current_phase == "completed"
    assert detail.processed_rules == 1
    assert detail.details_json["performance"]["total_seconds"] >= 0
    assert detail.details_json["sigma_engine_coverage_report"]["executable_by_current_engine"] == 1
    assert "pysigma_evaluation" in detail.details_json

    filtered = list_rules(case_id=CASE_ID, scope="all", import_run_id=result.import_run_id, page=1, page_size=10, db=db)
    metadata = filtered.items[0].metadata_json
    assert metadata["compile_source"] == "internal"
    assert metadata["compile_version"] == "rules_v3"
    assert metadata["rule_hash"] == filtered.items[0].content_hash
    assert metadata["engine_compatibility"]["executable_by_current_engine"] is True


def test_import_sigma_pack_counts_duplicate_updated_invalid_and_unsupported() -> None:
    db = _session()
    _seed_case(db)
    base = """
title: Encoded PowerShell
id: sigma-encoded-ps
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: powershell.exe
  condition: selection
"""
    changed = """
title: Encoded PowerShell Changed
id: sigma-encoded-ps
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: pwsh.exe
  condition: selection
"""
    unsupported = """
title: Unsupported One Of
id: sigma-unsupported-1
logsource:
  product: windows
  category: process_creation
detection:
  selection_a:
    Image|endswith: powershell.exe
  selection_b:
    Image|endswith: cmd.exe
  condition: 1 of selection_*
"""
    invalid = "title: broken\ndetection: nope"

    first = import_rule_archive(
        file=_zip_file({"a.yml": base, "__MACOSX/._a.yml": "x", ".DS_Store": "x"}),
        engine="sigma",
        import_mode="split",
        case_id=CASE_ID,
        namespace="lab",
        enabled=True,
        db=db,
    )
    second = import_rule_archive(
        file=_zip_file({"a.yml": base, "changed.yml": changed, "linux.yml": unsupported, "broken.yml": invalid}),
        engine="sigma",
        import_mode="split",
        case_id=CASE_ID,
        namespace="lab",
        enabled=True,
        db=db,
    )

    assert first.imported_count == 1
    assert first.skipped_count >= 1
    assert any("macOS metadata" in item for item in first.warnings)
    assert second.updated_count == 1
    assert second.duplicate_count == 1
    assert second.invalid_count == 1
    assert second.status == "completed_with_warnings"
    assert second.summary["sigma_engine_coverage_report"]["not_executable_by_current_engine"] == 0
    assert second.summary["sigma_engine_coverage_report"]["executable_by_current_engine"] == 2
    assert second.summary["sigma_engine_coverage_report"]["newly_supported_condition_1_of"] == 1


def test_linux_rule_is_valid_at_import_not_engine_unsupported() -> None:
    db = _session()
    _seed_case(db)
    result = import_rule_file(
        file=_upload_file(
            "linux.yml",
            """
title: Linux Curl Execution
id: sigma-linux-curl
logsource:
  product: linux
detection:
  selection:
    CommandLine|contains: curl
  condition: selection
""",
        ),
        engine="sigma",
        import_mode="split",
        case_id=CASE_ID,
        namespace="lab",
        enabled=True,
        db=db,
    )

    assert result.imported_count == 1
    assert result.unsupported_count == 0
    assert result.summary["sigma_engine_coverage_report"]["executable_by_current_engine"] == 1


def test_same_rule_hash_recompiles_when_compiler_version_changes() -> None:
    db = _session()
    _seed_case(db)
    first = import_rule_file(
        file=_upload_file(
            "test.yml",
            """
title: Encoded PowerShell
id: sigma-encoded-ps
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: powershell.exe
  condition: selection
""",
        ),
        engine="sigma",
        import_mode="split",
        case_id=CASE_ID,
        namespace="lab",
        enabled=True,
        db=db,
    )
    rule = db.query(Rule).filter(Rule.case_id == CASE_ID, Rule.engine == RuleEngine.sigma).first()
    assert rule is not None
    rule.metadata_json["compile_version"] = "rules_v2"
    db.add(rule)
    db.commit()

    second = import_rule_file(
        file=_upload_file(
            "test.yml",
            """
title: Encoded PowerShell
id: sigma-encoded-ps
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: powershell.exe
  condition: selection
""",
        ),
        engine="sigma",
        import_mode="split",
        case_id=CASE_ID,
        namespace="lab",
        enabled=True,
        db=db,
    )

    assert second.updated_count == 1
    refreshed = list_rules(case_id=CASE_ID, scope="all", import_run_id=second.import_run_id, page=1, page_size=10, db=db).items[0]
    assert refreshed.metadata_json["compile_version"] == "rules_v3"


def test_import_mixed_archive_and_history_details() -> None:
    db = _session()
    _seed_case(db)
    result = import_rule_archive(
        file=_zip_file(
            {
                "sigma.yml": """
title: Encoded PowerShell
id: sigma-encoded-ps
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: powershell.exe
  condition: selection
""",
                "marker.yar": "rule MarkerRule { condition: true }",
            }
        ),
        engine="auto",
        import_mode="auto",
        case_id=CASE_ID,
        namespace="lab",
        enabled=True,
        db=db,
    )

    history = list_rule_imports(case_id=CASE_ID, limit=50, db=db)
    detail = get_rule_import(result.import_run_id, db)

    assert result.engine == "mixed"
    assert history.total == 1
    assert history.items[0].id == result.import_run_id
    assert detail.id == result.import_run_id
    assert detail.details_json["detected_engine_counts"]["sigma"] == 1
    assert detail.details_json["detected_engine_counts"]["yara"] == 1


def test_cancel_rule_import_marks_queued_run_cancelled() -> None:
    db = _session()
    _seed_case(db)
    run = RuleImportRun(
        case_id=CASE_ID,
        engine="sigma",
        source_name="sigma_all_rules.zip",
        source_type="archive",
        uploaded_filename="sigma_all_rules.zip",
        pack_name="sigma_all_rules",
        status=RuleImportRunStatus.queued,
        started_at="2026-05-23T00:00:00+00:00",
        current_phase="queued",
        import_options={"engine": "sigma"},
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    cancelled = cancel_rule_import(run.id, db)
    assert cancelled.status == RuleImportRunStatus.cancelled
    assert cancelled.cancel_requested is True
    assert cancelled.cancelled_at is not None


def test_rule_library_can_filter_by_import_run_and_source_pack() -> None:
    db = _session()
    _seed_case(db)
    result = import_rule_file(
        file=_upload_file(
            "test.yml",
            """
title: Encoded PowerShell
id: sigma-encoded-ps
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: powershell.exe
  condition: selection
""",
        ),
        engine="sigma",
        import_mode="split",
        case_id=CASE_ID,
        namespace="lab",
        enabled=True,
        db=db,
    )

    filtered = list_rules(case_id=CASE_ID, scope="all", import_run_id=result.import_run_id, source_pack="test", page=1, page_size=50, db=db)
    assert filtered.total == 1
    assert filtered.items[0].metadata_json["import_run_id"] == result.import_run_id

    missing = list_rules(case_id=CASE_ID, scope="all", import_run_id="missing", page=1, page_size=50, db=db)
    assert missing.total == 0
