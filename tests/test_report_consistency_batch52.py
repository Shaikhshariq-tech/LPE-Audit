import json
import pytest

from reporting.report_consistency_audit import (
    ReportConsistencyError,
    audit_report_consistency,
    audit_report_consistency_file,
)


def sample_report():
    return {
        "findings": [{
            "finding_id": "F-001",
            "title": "Writable service configuration",
            "category": "permissions",
            "scanner": "services",
            "affected_path": "/etc/example.conf",
            "severity": "LOW",
            "risk_score": 20,
            "evidence": "The configuration file is writable by an unprivileged user.",
            "detection_reason": "File permissions allow an unprivileged write.",
            "mitigation": "Restrict file ownership and write permissions to administrators.",
        }]
    }


def test_consolidates_all_three_audits():
    result = audit_report_consistency(sample_report())
    assert set(result["subaudit_summaries"]) == {"quality", "evidence", "traceability"}
    assert set(result["subaudit_details"]) == {"quality", "evidence", "traceability"}


def test_output_is_read_only_and_requires_human_review():
    result = audit_report_consistency(sample_report())
    assert result["read_only"] is True
    assert result["automatic_remediation"] is False
    assert result["human_review_required"] is True


def test_reports_finding_and_id_counts():
    result = audit_report_consistency(sample_report())
    assert result["source_findings"] == 1
    assert result["findings_with_ids"] == 1
    assert result["duplicate_finding_ids"] == 0


def test_duplicate_ids_detected_at_summary_level():
    report = sample_report()
    report["findings"].append(dict(report["findings"][0]))
    result = audit_report_consistency(report)
    assert result["duplicate_finding_ids"] == 1


def test_invalid_report_shapes_rejected():
    with pytest.raises(ReportConsistencyError):
        audit_report_consistency([])
    with pytest.raises(ReportConsistencyError):
        audit_report_consistency({"findings": "invalid"})
    with pytest.raises(ReportConsistencyError):
        audit_report_consistency({"findings": [None]})


def test_recommendations_are_present():
    result = audit_report_consistency(sample_report())
    assert result["recommendations"]
    assert all(isinstance(item, str) for item in result["recommendations"])


def test_file_output_valid_json_and_source_unchanged(tmp_path):
    source = tmp_path / "source.json"
    output = tmp_path / "audit.json"
    source.write_text(json.dumps(sample_report()), encoding="utf-8")
    before = source.read_bytes()
    result, _ = audit_report_consistency_file(source, output)
    assert json.loads(output.read_text(encoding="utf-8")) == result
    assert source.read_bytes() == before


def test_refuses_to_overwrite_source(tmp_path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(sample_report()), encoding="utf-8")
    with pytest.raises(ReportConsistencyError, match="must not overwrite"):
        audit_report_consistency_file(source, source)


def test_invalid_json_is_rejected(tmp_path):
    source = tmp_path / "broken.json"
    source.write_text("{invalid", encoding="utf-8")
    with pytest.raises(ReportConsistencyError, match="Cannot read"):
        audit_report_consistency_file(source, tmp_path / "audit.json")
