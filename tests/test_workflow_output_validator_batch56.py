import json

import pytest

from reporting.workflow_output_validator import (
    WorkflowOutputValidationError,
    validate_workflow_outputs,
)


def test_valid_json_and_markdown_pass(tmp_path):
    (tmp_path / "report.json").write_text('{"findings": []}', encoding="utf-8")
    (tmp_path / "report.md").write_text("# Audit", encoding="utf-8")

    result = validate_workflow_outputs(
        tmp_path, ["report.json", "report.md"]
    )

    assert result["status"] == "PASS"
    assert result["valid_count"] == 2
    assert result["error_count"] == 0
    assert result["read_only"] is True
    assert result["automatic_remediation"] is False


def test_missing_file_fails(tmp_path):
    result = validate_workflow_outputs(tmp_path, ["missing.json"])
    assert result["status"] == "FAIL"
    assert result["errors"][0]["type"] == "MISSING_FILE"


def test_invalid_json_fails(tmp_path):
    (tmp_path / "bad.json").write_text("{broken", encoding="utf-8")
    result = validate_workflow_outputs(tmp_path, ["bad.json"])
    assert result["status"] == "FAIL"
    assert result["errors"][0]["type"] == "INVALID_JSON"


def test_empty_file_fails(tmp_path):
    (tmp_path / "empty.md").write_text("", encoding="utf-8")
    result = validate_workflow_outputs(tmp_path, ["empty.md"])
    assert result["errors"][0]["type"] == "EMPTY_FILE"


def test_empty_expected_list_rejected(tmp_path):
    with pytest.raises(WorkflowOutputValidationError):
        validate_workflow_outputs(tmp_path, [])


def test_duplicate_names_rejected(tmp_path):
    with pytest.raises(WorkflowOutputValidationError):
        validate_workflow_outputs(tmp_path, ["a.json", "a.json"])


@pytest.mark.parametrize("name", ["../outside.json", "/tmp/outside.json"])
def test_unsafe_path_rejected(tmp_path, name):
    with pytest.raises(WorkflowOutputValidationError):
        validate_workflow_outputs(tmp_path, [name])


def test_missing_directory_rejected(tmp_path):
    with pytest.raises(WorkflowOutputValidationError):
        validate_workflow_outputs(tmp_path / "missing", ["a.json"])


def test_valid_json_can_contain_array(tmp_path):
    (tmp_path / "array.json").write_text("[1, 2, 3]", encoding="utf-8")
    result = validate_workflow_outputs(tmp_path, ["array.json"])
    assert result["status"] == "PASS"


def test_validation_does_not_modify_source(tmp_path):
    path = tmp_path / "source.json"
    original = '{"safe": true}\n'
    path.write_text(original, encoding="utf-8")

    validate_workflow_outputs(tmp_path, ["source.json"])

    assert path.read_text(encoding="utf-8") == original


def test_reports_artifact_sizes(tmp_path):
    path = tmp_path / "report.md"
    path.write_text("Audit report", encoding="utf-8")

    result = validate_workflow_outputs(tmp_path, ["report.md"])

    assert result["artifacts"][0]["size_bytes"] == len(b"Audit report")
    assert result["artifacts"][0]["valid"] is True
