import json

import pytest

from reporting.evidence_field_inventory import (
    EvidenceInventoryError,
    audit_files,
    build_inventory,
    inventory_report,
    render_markdown,
)


def matrix(gaps=None):
    return {
        "report_type": "historical_evidence_coverage_matrix",
        "classified_gaps": gaps if gaps is not None else [
            {
                "gap_id": "EG-001",
                "classification": "OTHER",
                "description": "Issue record requires manual inspection.",
                "metadata": {"reason": "No evidence supplied"},
            }
        ],
    }


def triage(records=None):
    return {
        "report_type": "evidence_gap_triage",
        "gap_items": records if records is not None else [
            {
                "gap_id": "EG-001",
                "description": "Evidence needs review",
                "recommended_manual_action": "Inspect the original report",
            }
        ],
    }


def test_inventory_lists_nested_text_fields():
    result = inventory_report(matrix(), "test")
    names = {item["field"] for item in result["text_field_candidates"]}
    assert "description" in names
    assert "reason" in names


def test_inventory_preserves_record_id():
    result = inventory_report(matrix(), "test")
    assert result["records"][0]["record_id"] == "EG-001"


def test_cross_report_ids_are_matched():
    result = build_inventory(matrix(), triage())
    assert result["cross_report"]["shared_record_ids"] == ["EG-001"]


def test_cross_report_reports_unmatched_ids():
    result = build_inventory(
        matrix([{"gap_id": "EG-A"}]),
        triage([{"gap_id": "EG-B"}]),
    )
    assert result["cross_report"]["matrix_only_record_ids"] == ["EG-A"]
    assert result["cross_report"]["triage_only_record_ids"] == ["EG-B"]


def test_safety_flags_are_read_only():
    result = build_inventory(matrix(), triage())
    assert result["safety"]["read_only"] is True
    assert result["safety"]["automatic_reclassification"] is False
    assert result["safety"]["automatic_remediation"] is False
    assert result["safety"]["source_files_modified"] is False
    assert result["safety"]["system_changes_performed"] is False


def test_markdown_includes_both_sources_and_safety():
    result = build_inventory(matrix(), triage())
    markdown = render_markdown(result)
    assert "Batch 66 Coverage Matrix" in markdown
    assert "Batch 65 Evidence Triage" in markdown
    assert "## Safety" in markdown


def test_rejects_non_object_report_root():
    with pytest.raises(EvidenceInventoryError, match="root must be"):
        inventory_report([], "test")


def test_handles_empty_record_arrays():
    result = inventory_report(
        {"report_type": "empty", "classified_gaps": []},
        "test",
    )
    assert result["summary"]["records_inspected"] == 1


def test_file_round_trip(tmp_path):
    matrix_path = tmp_path / "matrix.json"
    triage_path = tmp_path / "triage.json"
    json_out = tmp_path / "audit.json"
    md_out = tmp_path / "audit.md"

    matrix_path.write_text(json.dumps(matrix()), encoding="utf-8")
    triage_path.write_text(json.dumps(triage()), encoding="utf-8")

    result = audit_files(matrix_path, triage_path, json_out, md_out)
    assert json.loads(json_out.read_text(encoding="utf-8")) == result
    assert "# Evidence Field Inventory" in md_out.read_text(encoding="utf-8")


def test_refuses_input_overwrite(tmp_path):
    matrix_path = tmp_path / "matrix.json"
    triage_path = tmp_path / "triage.json"
    matrix_path.write_text(json.dumps(matrix()), encoding="utf-8")
    triage_path.write_text(json.dumps(triage()), encoding="utf-8")

    with pytest.raises(EvidenceInventoryError, match="overwrite an input"):
        audit_files(matrix_path, triage_path, matrix_path, tmp_path / "out.md")


def test_refuses_existing_output(tmp_path):
    matrix_path = tmp_path / "matrix.json"
    triage_path = tmp_path / "triage.json"
    out = tmp_path / "out.json"
    matrix_path.write_text(json.dumps(matrix()), encoding="utf-8")
    triage_path.write_text(json.dumps(triage()), encoding="utf-8")
    out.write_text("{}", encoding="utf-8")

    with pytest.raises(EvidenceInventoryError, match="existing output"):
        audit_files(matrix_path, triage_path, out, tmp_path / "out.md")
