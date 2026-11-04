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

def test_id_summary_counts_only_nonempty_string_ids():
    report = sample_report()
    report["findings"] = [
        {"finding_id": "F-001"},
        {"finding_id": None},
        {"finding_id": 123},
        {"finding_id": True},
        {"finding_id": ""},
        {"finding_id": "   "},
        {"finding_id": "F-002"},
        {"finding_id": " F-002 "},
    ]

    result = audit_report_consistency(report)

    assert result["source_findings"] == 8
    assert result["findings_with_ids"] == 3
    assert result["duplicate_finding_ids"] == 1


@pytest.mark.parametrize("invalid_id", [None, 123, True, False, [], {}])
def test_invalid_id_types_are_not_counted(invalid_id):
    report = {"findings": [{"finding_id": invalid_id}]}

    result = audit_report_consistency(report)

    assert result["findings_with_ids"] == 0
    assert result["duplicate_finding_ids"] == 0


def test_whitespace_only_id_is_not_counted():
    report = {"findings": [{"finding_id": "   "}]}

    result = audit_report_consistency(report)

    assert result["findings_with_ids"] == 0
    assert result["duplicate_finding_ids"] == 0

def test_underlying_audit_exception_message_is_sanitized(monkeypatch):
    import reporting.report_quality_audit as quality_audit

    def fail_with_sensitive_message(report):
        raise RuntimeError("sensitive filesystem path /private/example")

    monkeypatch.setattr(
        quality_audit,
        "audit_report_quality",
        fail_with_sensitive_message,
    )

    with pytest.raises(ReportConsistencyError) as exc_info:
        audit_report_consistency(sample_report())

    message = str(exc_info.value)
    assert "RuntimeError" in message
    assert "sensitive filesystem path" not in message
    assert "/private/example" not in message


def test_source_read_error_message_is_sanitized(tmp_path, monkeypatch):
    from pathlib import Path

    source = tmp_path / "source.json"
    original_open = Path.open

    def failing_open(path, *args, **kwargs):
        if path == source.resolve():
            raise PermissionError("sensitive read path /private/source")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_open)

    with pytest.raises(ReportConsistencyError) as exc_info:
        audit_report_consistency_file(source, tmp_path / "audit.json")

    assert "PermissionError" in str(exc_info.value)
    assert "/private/source" not in str(exc_info.value)


def test_output_write_error_message_is_sanitized(tmp_path, monkeypatch):
    from pathlib import Path

    source = tmp_path / "source.json"
    output = tmp_path / "audit.json"
    source.write_text(json.dumps(sample_report()), encoding="utf-8")
    original_open = Path.open

    def failing_open(path, *args, **kwargs):
        if path == output.resolve():
            raise PermissionError("sensitive write path /private/output")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_open)

    with pytest.raises(ReportConsistencyError) as exc_info:
        audit_report_consistency_file(source, output)

    assert "PermissionError" in str(exc_info.value)
    assert "/private/output" not in str(exc_info.value)
