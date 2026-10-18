import json

import pytest

from reporting.evidence_classification_quality import (
    ClassificationQualityError,
    audit_classification_quality,
    audit_file,
    render_markdown,
)


def make_report(gaps=None):
    gaps = gaps or []
    categories = [
        "EVIDENCE_METADATA", "SNAPSHOT_TRACEABILITY", "RISK_SCORE_INTEGRITY",
        "FINDING_IDENTITY", "REPORT_CONSISTENCY", "OTHER",
    ]
    matrix = []
    for category in categories:
        matches = [item for item in gaps if item["classification"] == category]
        matrix.append({
            "category": category,
            "triaged_gap_count": len(matches),
            "high": sum(item["severity_normalized"] == "HIGH" for item in matches),
            "medium": sum(item["severity_normalized"] == "MEDIUM" for item in matches),
            "low": sum(item["severity_normalized"] == "LOW" for item in matches),
            "unknown_severity": sum(item["severity_normalized"] == "UNKNOWN" for item in matches),
            "gap_ids": [item["gap_id"] for item in matches],
            "coverage_status": "GAPS_REPORTED" if matches else "NO_GAPS_REPORTED",
        })
    return {
        "report_type": "historical_evidence_coverage_matrix",
        "summary": {
            "classified_gap_count": len(gaps),
            "categories_with_gaps": sum(row["triaged_gap_count"] > 0 for row in matrix),
            "unclassified_gap_count": sum(item["classification"] == "OTHER" for item in gaps),
        },
        "coverage_matrix": matrix,
        "classified_gaps": gaps,
        "safety": {
            "read_only": True,
            "automatic_remediation": False,
            "source_files_modified": False,
            "system_changes_performed": False,
        },
    }


def make_gap(gap_id="EG-001", classification="EVIDENCE_METADATA"):
    return {
        "gap_id": gap_id,
        "source_path": "$.checks[0]",
        "category": "evidence_metadata",
        "description": "Missing evidence metadata",
        "classification": classification,
        "severity_normalized": "LOW",
    }


def test_consistent_report_passes_all_checks_except_other_review_when_needed():
    result = audit_classification_quality(make_report([make_gap()]))
    assert result["status"] == "PASS"
    assert result["summary"]["checks_failed"] == 0


def test_other_category_requires_review():
    result = audit_classification_quality(make_report([make_gap(classification="OTHER")]))
    assert result["status"] == "REVIEW_REQUIRED"
    assert result["summary"]["other_category_count"] == 1
    assert any(issue["check_id"] == "other_category_review" for issue in result["issues"])


def test_detects_wrong_declared_gap_count():
    report = make_report([make_gap()])
    report["summary"]["classified_gap_count"] = 5
    result = audit_classification_quality(report)
    assert any(issue["check_id"] == "classified_count" for issue in result["issues"])


def test_detects_matrix_traceability_mismatch():
    report = make_report([make_gap()])
    report["coverage_matrix"][0]["gap_ids"] = []
    result = audit_classification_quality(report)
    assert any(issue["check_id"] == "matrix_gap_traceability" for issue in result["issues"])


def test_detects_unknown_classification():
    result = audit_classification_quality(make_report([make_gap(classification="UNKNOWN_CLASS")]))
    assert any(issue["check_id"] == "known_categories" for issue in result["issues"])


def test_rejects_wrong_report_type():
    with pytest.raises(ClassificationQualityError, match="Unsupported"):
        audit_classification_quality({"report_type": "wrong"})


def test_rejects_duplicate_gap_ids():
    with pytest.raises(ClassificationQualityError, match="Duplicate gap_id"):
        audit_classification_quality(make_report([make_gap(), make_gap()]))


def test_markdown_includes_safety_and_checks():
    result = audit_classification_quality(make_report([make_gap()]))
    markdown = render_markdown(result)
    assert "# Evidence Classification Quality Audit" in markdown
    assert "## Checks" in markdown
    assert "Read-only audit" in markdown


def test_file_output_round_trip(tmp_path):
    source = tmp_path / "coverage.json"
    out_json = tmp_path / "quality.json"
    out_md = tmp_path / "quality.md"
    source.write_text(json.dumps(make_report([make_gap()])), encoding="utf-8")
    result = audit_file(source, out_json, out_md)
    assert json.loads(out_json.read_text(encoding="utf-8")) == result
    assert "Evidence Classification Quality Audit" in out_md.read_text(encoding="utf-8")


def test_refuses_source_overwrite(tmp_path):
    source = tmp_path / "coverage.json"
    source.write_text(json.dumps(make_report()), encoding="utf-8")
    with pytest.raises(ClassificationQualityError, match="overwrite source"):
        audit_file(source, source, tmp_path / "quality.md")


def test_refuses_existing_output(tmp_path):
    source = tmp_path / "coverage.json"
    out_json = tmp_path / "quality.json"
    source.write_text(json.dumps(make_report()), encoding="utf-8")
    out_json.write_text("{}", encoding="utf-8")
    with pytest.raises(ClassificationQualityError, match="existing output"):
        audit_file(source, out_json, tmp_path / "quality.md")


def test_safety_flags_are_fixed():
    result = audit_classification_quality(make_report())
    assert result["safety"] == {
        "read_only": True,
        "automatic_remediation": False,
        "source_files_modified": False,
        "system_changes_performed": False,
    }
