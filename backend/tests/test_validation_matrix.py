from app.services.validation_matrix import (
    get_validation_matrix,
    render_validation_matrix_markdown,
    should_show_validation_matrix,
    validation_matrix_visibility,
)


def test_validation_matrix_returns_empty_when_no_dataset_bundled() -> None:
    matrix = get_validation_matrix("validation-case")

    assert matrix["items"] == []
    assert matrix["summary"]["total_expected"] == 0
    assert matrix["source_parts"] == []
    assert matrix["warnings"] == ["No validation dataset is bundled with this repository. Import a validation matrix for demo/training/QA workflows."]


def test_validation_matrix_filters_are_safe_without_dataset() -> None:
    matrix = get_validation_matrix("validation-case", host="SERVER-A", result="found", source_part="scenario", memory_required=False)

    assert matrix["items"] == []
    assert matrix["filtered_summary"]["total_expected"] == 0
    assert matrix["filters"]["results"]


def test_validation_matrix_visibility_respects_case_mode_and_feature_flags() -> None:
    investigation = validation_matrix_visibility("validation-case", "investigation")
    validation_disabled = validation_matrix_visibility("validation-case", "validation")
    validation_enabled = validation_matrix_visibility("validation-case", "validation", validation_mode_enabled=True, demo_cases_enabled=True)

    assert investigation["mode"] == "investigation"
    assert investigation["has_validation_matrix"] is False
    assert investigation["show_validation_matrix"] is False
    assert investigation["reason"] == "investigation_mode"
    assert validation_disabled["show_validation_matrix"] is False
    assert validation_disabled["reason"] == "validation_features_disabled"
    assert validation_enabled["mode"] == "validation"
    assert validation_enabled["show_validation_matrix"] is True
    assert validation_enabled["has_validation_matrix"] is False
    assert validation_enabled["reason"] == "case_mode_enabled_without_matrix"
    assert validation_enabled["label"] == "Demo/training ground truth enabled"
    assert should_show_validation_matrix("normal-case", "investigation") is False
    assert should_show_validation_matrix("validation-case", "validation") is False
    assert should_show_validation_matrix("validation-case", "validation", validation_mode_enabled=True) is True


def test_validation_matrix_markdown_exports_empty_summary() -> None:
    markdown = render_validation_matrix_markdown(get_validation_matrix("validation-case"))

    assert "Ground Truth Coverage" in markdown
    assert "Total expected: 0" in markdown
    assert "Validation source: not available" in markdown
