import json

import pytest

from reporting.classification_rule_coverage import (
    RuleCoverageError,
    audit_files,
    build_coverage,
    render_markdown,
)


def gap(gap_id="EG-1", description="Missing evidence metadata", classification="OTHER"):
    return {
        "gap_id": gap_id,
        "description": description,
        "classification": classification,
        "source_path": "$.checks[0]",
    }


def matrix(gaps):
    return {
        "report_type": "historical_evidence_coverage_matrix",
        "classified_gaps": gaps,
    }


def triage(records):
    return {"report_type": "evidence_gap_triage", "gap_items": records}


def test_detects_evidence_metadata_rule_coverage():
    result = build_coverage(matrix([gap()]), triage([]))
    record = result["records"][0]
    assert record["unmatched"] is False
    assert record["matched_categories"][0]["category"] == "EVIDENCE_METADATA"


def test_reports_unmatched_record_without_inventing_suggestion():
    result = build_coverage(
        matrix([gap(description="Unrelated unspecified issue")]),
        triage([]),
    )
    assert result["summary"]["records_without_rule_match"] == 1
    assert result["records"][0]["matched_categories"] == []
    assert result["records"][0]["review_required"] is True


def test_ignores_non_other_classifications():
    result = build_coverage(
        matrix([gap(classification="EVIDENCE_METADATA")]),
        triage([]),
    )
    assert result["summary"]["other_records_audited"] == 0
    assert result["status"] == "PASS"


def test_matches_triage_evidence_by_gap_id():
    result = build_coverage(
        matrix([gap(description="Issue")]),
        triage([{"gap_id": "EG-1", "description": "snapshot traceability gap"}]),
    )
    assert any(
        item["category"] == "SNAPSHOT_TRACEABILITY"
        for item in result["records"][0]["matched_categories"]
    )


def test_safety_flags_are_read_only():
    result = build_coverage(matrix([gap()]), triage([]))
    assert result["safety"] == {
        "read_only": True,
        "automatic_reclassification": False,
        "automatic_remediation": False,
        "source_files_modified": False,
        "system_changes_performed": False,
    }


def test_markdown_includes_coverage_and_safety():
    result = build_coverage(matrix([gap()]), triage([]))
    markdown = render_markdown(result)
    assert "# Classification Rule Coverage Audit" in markdown
    assert "## Category Coverage" in markdown
    assert "## Safety" in markdown


def test_rejects_invalid_matrix_root():
    with pytest.raises(RuleCoverageError, match="JSON object"):
        build_coverage([], triage([]))


def test_rejects_wrong_matrix_type():
    with pytest.raises(RuleCoverageError, match="Unsupported Batch 66"):
        build_coverage({"report_type": "wrong", "classified_gaps": []}, triage([]))


def test_file_round_trip(tmp_path):
    matrix_path = tmp_path / "matrix.json"
    triage_path = tmp_path / "triage.json"
    json_out = tmp_path / "audit.json"
    md_out = tmp_path / "audit.md"
    matrix_path.write_text(json.dumps(matrix([gap()])), encoding="utf-8")
    triage_path.write_text(json.dumps(triage([])), encoding="utf-8")

    data = audit_files(matrix_path, triage_path, json_out, md_out)
    assert json.loads(json_out.read_text(encoding="utf-8")) == data
    assert "# Classification Rule Coverage Audit" in md_out.read_text(encoding="utf-8")


def test_refuses_input_overwrite(tmp_path):
    matrix_path = tmp_path / "matrix.json"
    triage_path = tmp_path / "triage.json"
    matrix_path.write_text(json.dumps(matrix([])), encoding="utf-8")
    triage_path.write_text(json.dumps(triage([])), encoding="utf-8")
    with pytest.raises(RuleCoverageError, match="overwrite an input"):
        audit_files(matrix_path, triage_path, matrix_path, tmp_path / "out.md")


def test_refuses_existing_output(tmp_path):
    matrix_path = tmp_path / "matrix.json"
    triage_path = tmp_path / "triage.json"
    out = tmp_path / "out.json"
    matrix_path.write_text(json.dumps(matrix([])), encoding="utf-8")
    triage_path.write_text(json.dumps(triage([])), encoding="utf-8")
    out.write_text("{}", encoding="utf-8")
    with pytest.raises(RuleCoverageError, match="existing output"):
        audit_files(matrix_path, triage_path, out, tmp_path / "out.md")
