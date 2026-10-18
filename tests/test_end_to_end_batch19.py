import json
from pathlib import Path

import pytest

import main as app
from reporting.report_builder import build_report
from reporting.report_validator import assert_valid_report, validate_report


def test_real_scan_writes_valid_json_and_text_reports(tmp_path):
    report_dir = tmp_path / "reports"

    # Run the project's real scan/report pipeline using its CLI.
    # This does not request privilege escalation or modify system settings.
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--full-scan",
            "--report-dir",
            str(report_dir),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, (
        f"CLI exited with {result.returncode}\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    json_files = list(report_dir.rglob("*.json"))
    text_files = list(report_dir.rglob("*.txt"))

    assert json_files, f"No JSON report found under {report_dir}"
    assert text_files, f"No text report found under {report_dir}"

    for json_path in json_files:
        report = json.loads(json_path.read_text(encoding="utf-8"))
        assert_valid_report(report)

        findings = report["findings"]
        summary = report["summary"]
        assert summary["total_findings"] == len(findings)

        for severity in ("critical", "high", "medium", "low", "info"):
            expected = sum(
                isinstance(item, dict)
                and isinstance(item.get("severity"), str)
                and item["severity"].upper() == severity.upper()
                for item in findings
            )
            assert summary[severity] == expected


def test_report_validator_rejects_malformed_findings():
    report = build_report({}, [], ["test"])
    report["findings"] = "not-a-list"

    errors = validate_report(report)

    assert errors


def test_report_validator_rejects_invalid_risk_score():
    report = build_report({}, [], ["test"])
    report["findings"] = [
        {
            "title": "Test finding",
            "severity": "HIGH",
            "risk_score": 101,
        }
    ]
    report["summary"]["total_findings"] = 1
    report["summary"]["high_risk_findings"] = 1

    errors = validate_report(report)

    assert any("risk_score" in error for error in errors)


def test_empty_report_is_valid():
    report = build_report({}, [], ["test"])
    assert validate_report(report) == []
    assert_valid_report(report)
