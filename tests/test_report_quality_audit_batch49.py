import json

import pytest

from reporting.report_quality_audit import (
    ReportQualityAuditError,
    audit_report_file,
    audit_report_quality,
)


def item(title, severity="LOW", score=20, rank=1):
    return {
        "title": title,
        "severity": severity,
        "risk_score": score,
        "priority_rank": rank,
    }


def test_reports_severity_score_mismatch_without_mutating_finding():
    finding = item("Mismatch", "LOW", 90)
    original = finding.copy()

    result = audit_report_quality({"findings": [finding]})

    assert finding == original
    assert any(
        issue["type"] == "SEVERITY_SCORE_MISMATCH"
        for issue in result["issues"]
    )
    assert result["read_only"] is True


def test_matching_score_policy_severity_has_no_mismatch():
    from analysis.severity import severity_for_score

    score = 20
    finding = item("Consistent", severity_for_score(score), score, 1)
    result = audit_report_quality({"findings": [finding]})

    assert not any(
        issue["type"] == "SEVERITY_SCORE_MISMATCH"
        for issue in result["issues"]
    )


def test_detects_duplicate_priority_ranks():
    result = audit_report_quality({
        "findings": [
            item("First", rank=1),
            item("Second", rank=1),
        ]
    })
    assert any(
        issue["type"] == "DUPLICATE_PRIORITY_RANKS"
        for issue in result["issues"]
    )


def test_detects_missing_or_nonsequential_priority_ranks():
    result = audit_report_quality({
        "findings": [
            item("First", rank=1),
            item("Second", rank=3),
        ]
    })
    assert any(
        issue["type"] == "NON_SEQUENTIAL_PRIORITY_RANKS"
        for issue in result["issues"]
    )


def test_detects_invalid_severity():
    result = audit_report_quality({
        "findings": [item("Bad severity", "URGENT", 20)]
    })
    assert any(
        issue["type"] == "INVALID_SEVERITY"
        for issue in result["issues"]
    )


def test_detects_invalid_risk_score():
    result = audit_report_quality({
        "findings": [item("Bad score", "LOW", 101)]
    })
    assert any(
        issue["type"] == "INVALID_RISK_SCORE"
        for issue in result["issues"]
    )


def test_reports_distributions_and_empty_report():
    result = audit_report_quality({
        "findings": [
            item("One", "LOW", 20, 1),
            item("Two", "LOW", 20, 2),
        ]
    })
    assert result["source_findings"] == 2
    assert result["severity_distribution"]["LOW"] == 2
    assert result["risk_score_distribution"]["20"] == 2

    empty = audit_report_quality({"findings": []})
    assert empty["source_findings"] == 0
    assert empty["issue_count"] == 0


def test_rejects_invalid_report_structure():
    with pytest.raises(ReportQualityAuditError, match="JSON object"):
        audit_report_quality([])

    with pytest.raises(ReportQualityAuditError, match="JSON array"):
        audit_report_quality({"findings": {}})


def test_writes_audit_without_changing_source(tmp_path):
    source = tmp_path / "source.json"
    output = tmp_path / "audit.json"
    original = {
        "findings": [
            item("Example", "LOW", 90, 1),
        ]
    }
    source.write_text(json.dumps(original), encoding="utf-8")
    before = source.read_bytes()

    result, path = audit_report_file(source, output)

    assert path == output.resolve()
    assert json.loads(output.read_text(encoding="utf-8")) == result
    assert source.read_bytes() == before


def test_refuses_to_overwrite_source(tmp_path):
    source = tmp_path / "source.json"
    source.write_text('{"findings":[]}', encoding="utf-8")

    with pytest.raises(ReportQualityAuditError, match="must not overwrite"):
        audit_report_file(source, source)
