import json

import pytest

from reporting.report_comparison import (
    ReportComparisonError,
    compare_reports,
    write_comparison,
)


def finding(title="Example finding", severity="LOW", path="/tmp/example"):
    return {
        "category": "permissions",
        "title": title,
        "description": "Example",
        "severity": severity,
        "affected_path": path,
        "scanner": "permissions",
        "finding_id": "random-id-does-not-define-identity",
    }


def report(findings, coverage_status="COMPLETE"):
    return {
        "tool": "LPE-Audit",
        "audit_time": "2026-01-01T00:00:00+00:00",
        "findings": findings,
        "scan_coverage": {
            "status": coverage_status,
            "failed_modules": [],
            "not_run_modules": [],
        },
    }


def save(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_new_resolved_persistent_and_severity_change(tmp_path):
    baseline = save(tmp_path / "baseline.json", report([
        finding("Persistent", "LOW", "/a"),
        finding("Resolved", "MEDIUM", "/b"),
        finding("Changed", "LOW", "/c"),
    ]))
    current = save(tmp_path / "current.json", report([
        finding("Persistent", "LOW", "/a"),
        finding("New", "HIGH", "/d"),
        finding("Changed", "CRITICAL", "/c"),
    ]))

    result = compare_reports(baseline, current)

    assert result["summary"] == {
        "new": 1,
        "resolved": 1,
        "persistent": 2,
        "severity_changed": 1,
        "net_change": 0,
    }
    assert result["new_findings"][0]["title"] == "New"
    assert result["resolved_findings"][0]["title"] == "Resolved"
    assert result["severity_changes"][0]["direction"] == "increased"
    assert result["severity_changes"][0]["baseline_severity"] == "LOW"
    assert result["severity_changes"][0]["current_severity"] == "CRITICAL"


def test_random_finding_id_does_not_change_identity(tmp_path):
    before = finding("Same", "LOW", "/same")
    after = finding("Same", "HIGH", "/same")
    after["finding_id"] = "different-random-id"

    old = save(tmp_path / "old.json", report([before]))
    new = save(tmp_path / "new.json", report([after]))
    result = compare_reports(old, new)

    assert result["summary"]["new"] == 0
    assert result["summary"]["resolved"] == 0
    assert result["summary"]["persistent"] == 1
    assert result["summary"]["severity_changed"] == 1


def test_coverage_change_is_reported(tmp_path):
    old = save(tmp_path / "old.json", report([], "COMPLETE"))
    new = save(tmp_path / "new.json", report([], "PARTIAL"))

    result = compare_reports(old, new)
    assert result["coverage_changed"] is True


def test_invalid_json_is_rejected(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(ReportComparisonError):
        compare_reports(path, path)


def test_invalid_finding_severity_is_rejected(tmp_path):
    old = save(tmp_path / "old.json", report([finding(severity="UNKNOWN")]))
    new = save(tmp_path / "new.json", report([]))

    with pytest.raises(ReportComparisonError, match="invalid severity"):
        compare_reports(old, new)


def test_duplicate_stable_identity_is_rejected(tmp_path):
    item = finding()
    old = save(tmp_path / "old.json", report([item, dict(item)]))
    new = save(tmp_path / "new.json", report([]))

    with pytest.raises(ReportComparisonError, match="duplicate finding identity"):
        compare_reports(old, new)


def test_output_cannot_overwrite_input(tmp_path):
    old = save(tmp_path / "old.json", report([]))
    new = save(tmp_path / "new.json", report([]))

    with pytest.raises(ReportComparisonError, match="must not overwrite"):
        write_comparison(old, new, old)


def test_comparison_json_is_written(tmp_path):
    old = save(tmp_path / "old.json", report([finding()]))
    new = save(tmp_path / "new.json", report([]))
    output = tmp_path / "results" / "comparison.json"

    result = write_comparison(old, new, output)

    assert output.exists()
    stored = json.loads(output.read_text(encoding="utf-8"))
    assert stored["summary"]["resolved"] == 1
    assert stored["summary"] == result["summary"]
