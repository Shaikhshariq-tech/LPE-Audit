import copy
import json

import pytest

from core.analyzer import analyze_findings
from core.finding import Finding
from reporting.report_builder import build_report
from reporting.report_validator import assert_valid_report, validate_report


def make_report():
    findings = [
        Finding(
            category="permissions",
            title="Example lower-risk finding",
            description="A test finding.",
            severity="LOW",
            risk_score=20,
            confidence="MEDIUM",
        ),
        Finding(
            category="sudo",
            title="Example higher-risk finding",
            description="Another test finding.",
            severity="HIGH",
            risk_score=70,
            confidence="HIGH",
        ),
    ]
    analyzed = analyze_findings(findings)
    return build_report({}, analyzed, ["test"])


def test_generated_report_passes_validation():
    report = make_report()
    assert validate_report(report) == []
    assert_valid_report(report)


def test_valid_report_can_be_json_serialized():
    report = make_report()
    encoded = json.dumps(report)
    decoded = json.loads(encoded)
    assert validate_report(decoded) == []


def test_validator_detects_mismatched_total():
    report = make_report()
    report["summary"]["total_findings"] += 1

    assert any(
        "total_findings does not match" in error
        for error in validate_report(report)
    )


def test_validator_detects_invalid_risk_score():
    report = make_report()
    report["findings"][0]["risk_score"] = 101

    assert any(
        "risk_score outside" in error
        for error in validate_report(report)
    )


def test_validator_detects_invalid_severity():
    report = make_report()
    report["findings"][0]["severity"] = "EXTREME"

    assert any(
        "invalid or missing severity" in error
        for error in validate_report(report)
    )


def test_validator_detects_empty_title():
    report = make_report()
    report["findings"][0]["title"] = "   "

    assert any(
        "missing or empty title" in error
        for error in validate_report(report)
    )


def test_validator_does_not_mutate_report():
    report = make_report()
    before = copy.deepcopy(report)

    validate_report(report)

    assert report == before


def test_assert_valid_report_raises_with_details():
    with pytest.raises(ValueError, match="Report validation failed"):
        assert_valid_report({"summary": {}, "findings": "not-a-list"})


def test_validator_rejects_boolean_risk_score():
    report = make_report()
    report["findings"][0]["risk_score"] = True

    assert any(
        "risk_score outside" in error
        for error in validate_report(report)
    )
