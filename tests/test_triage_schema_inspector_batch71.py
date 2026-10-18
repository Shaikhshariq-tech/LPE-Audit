import json

import pytest

from reporting.triage_schema_inspector import (
    SchemaInspectionError,
    audit_files,
    build_inspection,
    discover_records,
    inspect_report,
    render_markdown,
)


def matrix():
    return {
        "report_type": "historical_evidence_coverage_matrix",
        "classified_gaps": [
            {"gap_id": "EG-001", "classification": "OTHER"},
            {"gap_id": "EG-002", "classification": "OTHER"},
        ],
    }


def triage():
    return {
        "report_type": "evidence_gap_triage",
        "summary": {"total": 2},
        "details": {
            "gap_items": [
                {"gap_id": "EG-001", "description": "Evidence gap"},
                {"gap_id": "EG-002", "description": "Second gap"},
            ]
        },
    }


def test_discovers_nested_records():
    records = discover_records(triage())
    assert {item["record_id"] for item in records} == {"EG-001", "EG-002"}


def test_records_contain_json_paths():
    records = discover_records(triage())
    assert all("$.details.gap_items[" in item["path"] for item in records)


def test_comparison_matches_nested_ids():
    result = build_inspection(matrix(), triage())
    assert result["identity_comparison"]["shared_ids"] == ["EG-001", "EG-002"]
    assert result["identity_comparison"]["matrix_only_ids"] == []
    assert result["identity_comparison"]["triage_only_ids"] == []


def test_detects_duplicate_identifiers():
    data = {"items": [{"gap_id": "EG-1"}, {"gap_id": "EG-1"}]}
    result = inspect_report(data, "test")
    assert result["duplicate_record_ids"] == ["EG-1"]


def test_rejects_scalar_root():
    with pytest.raises(SchemaInspectionError, match="root must be"):
        inspect_report("invalid", "test")


def test_safety_flags_are_read_only():
    result = build_inspection(matrix(), triage())
    assert result["safety"]["read_only"] is True
    assert result["safety"]["automatic_reclassification"] is False
    assert result["safety"]["automatic_remediation"] is False
    assert result["safety"]["source_files_modified"] is False
    assert result["safety"]["system_changes_performed"] is False


def test_markdown_contains_nested_paths():
    result = build_inspection(matrix(), triage())
    markdown = render_markdown(result)
    assert "$.details.gap_items[0]" in markdown
    assert "## Safety" in markdown


def test_file_round_trip(tmp_path):
    matrix_path = tmp_path / "matrix.json"
    triage_path = tmp_path / "triage.json"
    json_out = tmp_path / "out.json"
    md_out = tmp_path / "out.md"
    matrix_path.write_text(json.dumps(matrix()), encoding="utf-8")
    triage_path.write_text(json.dumps(triage()), encoding="utf-8")

    result = audit_files(matrix_path, triage_path, json_out, md_out)
    assert json.loads(json_out.read_text(encoding="utf-8")) == result
    assert "# Triage Schema Inspection" in md_out.read_text(encoding="utf-8")


def test_refuses_input_overwrite(tmp_path):
    matrix_path = tmp_path / "matrix.json"
    triage_path = tmp_path / "triage.json"
    matrix_path.write_text(json.dumps(matrix()), encoding="utf-8")
    triage_path.write_text(json.dumps(triage()), encoding="utf-8")

    with pytest.raises(SchemaInspectionError, match="overwrite an input"):
        audit_files(matrix_path, triage_path, matrix_path, tmp_path / "out.md")


def test_refuses_existing_output(tmp_path):
    matrix_path = tmp_path / "matrix.json"
    triage_path = tmp_path / "triage.json"
    output = tmp_path / "out.json"
    matrix_path.write_text(json.dumps(matrix()), encoding="utf-8")
    triage_path.write_text(json.dumps(triage()), encoding="utf-8")
    output.write_text("{}", encoding="utf-8")

    with pytest.raises(SchemaInspectionError, match="existing output"):
        audit_files(matrix_path, triage_path, output, tmp_path / "out.md")
