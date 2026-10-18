from copy import deepcopy

from reporting.report_validator import validate_report


def make_report(findings=None):
    if findings is None:
        findings = []

    return {
        "summary": {
            "total_findings": len(findings),
            "severity_counts": {},
        },
        "findings": findings,
    }


def valid_finding(**overrides):
    finding = {
        "category": "test",
        "title": "Example finding",
        "description": "Test-only finding.",
        "severity": "LOW",
        "risk_score": 25,
        "scanner": "test_scanner",
    }
    finding.update(overrides)
    return finding


def test_non_mapping_finding_is_reported():
    errors = validate_report(make_report([None]))

    assert any("index 0" in error and "mapping" in error for error in errors)


def test_boolean_risk_score_is_rejected():
    errors = validate_report(make_report([valid_finding(risk_score=True)]))

    assert any("risk_score" in error for error in errors)


def test_out_of_range_risk_score_is_rejected():
    errors = validate_report(make_report([valid_finding(risk_score=101)]))

    assert any("risk_score" in error for error in errors)


def test_empty_title_is_rejected():
    errors = validate_report(make_report([valid_finding(title="   ")]))

    assert any("title" in error for error in errors)


def test_mismatched_total_findings_is_rejected():
    report = make_report([valid_finding()])
    report["summary"]["total_findings"] = 0

    errors = validate_report(report)

    assert any("total_findings" in error for error in errors)


def test_validation_keeps_nested_input_unchanged_on_errors():
    report = make_report([valid_finding(risk_score=-1)])
    before = deepcopy(report)

    errors = validate_report(report)

    assert errors
    assert report == before
