import json

import pytest

from reporting.finding_evidence_audit import (
    FindingEvidenceAuditError,
    audit_finding_evidence,
    audit_finding_evidence_file,
)


def finding(**overrides):
    result = {
        "title": "Writable service configuration",
        "category": "permissions",
        "scanner": "services",
        "affected_path": "/etc/example.conf",
        "evidence": "File is writable by an unprivileged group.",
        "detection_reason": "The file permission allows an untrusted group to edit it.",
        "mitigation": "Review ownership and restrict write access to trusted administrators.",
    }
    result.update(overrides)
    return result


def test_complete_finding_has_no_quality_issues():
    result = audit_finding_evidence({"findings": [finding()]})
    assert result["source_findings"] == 1
    assert result["issue_count"] == 0
    assert result["read_only"] is True


def test_flags_missing_evidence_guidance_and_metadata():
    result = audit_finding_evidence({
        "findings": [finding(evidence="", mitigation="", category="")]
    })
    fields = {issue["field"] for issue in result["issues"]}
    assert {"evidence", "mitigation", "category"} <= fields


def test_flags_short_evidence_reason_and_mitigation():
    result = audit_finding_evidence({
        "findings": [finding(
            evidence="bad",
            detection_reason="weak",
            mitigation="fix it",
        )]
    })
    types = {issue["type"] for issue in result["issues"]}
    assert {"WEAK_EVIDENCE", "WEAK_DETECTION_REASON", "WEAK_MITIGATION"} <= types


def test_reports_scanner_counts():
    result = audit_finding_evidence({
        "findings": [finding(), finding(title="Second")]
    })
    assert result["scanner_finding_counts"] == {"services": 2}


def test_reports_explicit_coverage_gap_and_failure():
    result = audit_finding_evidence({
        "findings": [],
        "coverage": {
            "expected_scanners": ["suid", "sudo", "cron"],
            "completed_scanners": ["suid"],
            "failed_scanners": ["sudo"],
        },
    })
    types = [issue["type"] for issue in result["issues"]]
    assert "SCANNER_FAILED" in types
    assert "SCANNER_COVERAGE_GAP" in types
    assert result["coverage"]["unaccounted_expected_scanners"] == ["cron"]


def test_does_not_infer_scanner_failure_without_coverage_metadata():
    result = audit_finding_evidence({"findings": [finding()]})
    assert result["coverage"]["metadata_available"] is False
    assert not any(
        issue["type"] in {"SCANNER_FAILED", "SCANNER_COVERAGE_GAP"}
        for issue in result["issues"]
    )


def test_rejects_invalid_report_and_finding():
    with pytest.raises(FindingEvidenceAuditError, match="JSON object"):
        audit_finding_evidence([])
    with pytest.raises(FindingEvidenceAuditError, match="JSON array"):
        audit_finding_evidence({"findings": {}})
    with pytest.raises(FindingEvidenceAuditError, match="must be an object"):
        audit_finding_evidence({"findings": ["bad"]})


def test_writes_output_without_changing_source(tmp_path):
    source = tmp_path / "source.json"
    output = tmp_path / "audit.json"
    source.write_text(json.dumps({"findings": [finding()]}), encoding="utf-8")
    original = source.read_bytes()
    result, path = audit_finding_evidence_file(source, output)
    assert path == output.resolve()
    assert json.loads(output.read_text(encoding="utf-8")) == result
    assert source.read_bytes() == original


def test_refuses_to_overwrite_source(tmp_path):
    source = tmp_path / "source.json"
    source.write_text('{"findings":[]}', encoding="utf-8")
    with pytest.raises(FindingEvidenceAuditError, match="must not overwrite"):
        audit_finding_evidence_file(source, source)
