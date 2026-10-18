import json

import pytest

from reporting.evidence_classification_suggestions import (
    ClassificationSuggestionError,
    audit_files,
    build_suggestions,
    render_markdown,
)


def gap(gap_id="EG-1", description="Missing evidence metadata", category="OTHER"):
    return {
        "gap_id": gap_id,
        "source_path": "$.checks[0]",
        "description": description,
        "category": "evidence_metadata",
        "classification": category,
        "severity_normalized": "LOW",
    }


def matrix_report(gaps):
    return {
        "report_type": "historical_evidence_coverage_matrix",
        "classified_gaps": gaps,
    }


def triage_report(records):
    return {
        "report_type": "evidence_gap_triage",
        "gap_items": records,
    }


def test_suggests_evidence_metadata_from_matching_phrase():
    result = build_suggestions(
        matrix_report([gap()]),
        triage_report([]),
    )
    item = result["suggestions"][0]
    assert item["suggested_category"] == "EVIDENCE_METADATA"
    assert item["confidence"] == "MEDIUM"
    assert item["review_required"] is True
    assert item["accepted"] is False


def test_no_match_keeps_suggestion_empty():
    result = build_suggestions(
        matrix_report([gap(description="An unrelated unspecified issue")]),
        triage_report([]),
    )
    item = result["suggestions"][0]
    assert item["suggested_category"] is None
    assert item["confidence"] == "LOW"


def test_multiple_equal_category_matches_do_not_choose():
    result = build_suggestions(
        matrix_report([gap(description="snapshot and risk score")]),
        triage_report([]),
    )
    item = result["suggestions"][0]
    assert item["suggested_category"] is None
    assert item["confidence"] == "LOW"


def test_non_other_records_are_ignored():
    result = build_suggestions(
        matrix_report([gap(category="EVIDENCE_METADATA")]),
        triage_report([]),
    )
    assert result["summary"]["other_records_reviewed"] == 0
    assert result["status"] == "PASS"


def test_matches_triage_record_by_gap_id():
    triage = {"gap_id": "EG-1", "description": "Source triage record"}
    result = build_suggestions(matrix_report([gap()]), triage_report([triage]))
    assert result["suggestions"][0]["triage_record_matched"] is True


def test_reports_unmatched_triage_record():
    result = build_suggestions(matrix_report([gap()]), triage_report([]))
    assert result["summary"]["triage_record_matched_count"] == 0


def test_safety_flags_are_read_only():
    result = build_suggestions(matrix_report([gap()]), triage_report([]))
    assert result["safety"] == {
        "read_only": True,
        "automatic_remediation": False,
        "automatic_reclassification": False,
        "source_files_modified": False,
        "system_changes_performed": False,
    }


def test_markdown_has_explanation_and_safety():
    result = build_suggestions(matrix_report([gap()]), triage_report([]))
    markdown = render_markdown(result)
    assert "# Evidence Classification Suggestion Preview" in markdown
    assert "## Suggestions" in markdown
    assert "## Safety" in markdown
    assert "Accepted:** No" in markdown


def test_rejects_wrong_matrix_type():
    with pytest.raises(ClassificationSuggestionError, match="Unsupported Batch 66"):
        build_suggestions({"report_type": "wrong", "classified_gaps": []}, {})


def test_rejects_invalid_triage_root():
    with pytest.raises(ClassificationSuggestionError, match="input root must be a JSON object"):
        build_suggestions(matrix_report([]), [])


def test_file_round_trip(tmp_path):
    matrix = tmp_path / "matrix.json"
    triage = tmp_path / "triage.json"
    out_json = tmp_path / "suggestions.json"
    out_md = tmp_path / "suggestions.md"
    matrix.write_text(json.dumps(matrix_report([gap()])), encoding="utf-8")
    triage.write_text(json.dumps(triage_report([])), encoding="utf-8")

    result = audit_files(matrix, triage, out_json, out_md)
    assert json.loads(out_json.read_text(encoding="utf-8")) == result
    assert "Evidence Classification Suggestion Preview" in out_md.read_text(encoding="utf-8")


def test_refuses_input_overwrite(tmp_path):
    matrix = tmp_path / "matrix.json"
    triage = tmp_path / "triage.json"
    matrix.write_text(json.dumps(matrix_report([])), encoding="utf-8")
    triage.write_text(json.dumps(triage_report([])), encoding="utf-8")
    with pytest.raises(ClassificationSuggestionError, match="overwrite an input"):
        audit_files(matrix, triage, matrix, tmp_path / "out.md")


def test_refuses_existing_output(tmp_path):
    matrix = tmp_path / "matrix.json"
    triage = tmp_path / "triage.json"
    output = tmp_path / "out.json"
    matrix.write_text(json.dumps(matrix_report([])), encoding="utf-8")
    triage.write_text(json.dumps(triage_report([])), encoding="utf-8")
    output.write_text("{}", encoding="utf-8")
    with pytest.raises(ClassificationSuggestionError, match="existing output"):
        audit_files(matrix, triage, output, tmp_path / "out.md")
