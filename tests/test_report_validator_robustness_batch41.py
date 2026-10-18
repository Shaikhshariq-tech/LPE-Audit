from reporting.report_validator import validate_report


def test_boolean_risk_score_is_rejected():
    errors = validate_report({
        "summary": {},
        "findings": [{
            "title": "Boolean risk score",
            "severity": "LOW",
            "risk_score": True,
        }],
    })

    assert any("risk_score" in error for error in errors)


def test_out_of_range_risk_score_is_rejected():
    errors = validate_report({
        "summary": {},
        "findings": [{
            "title": "Out-of-range risk score",
            "severity": "MEDIUM",
            "risk_score": 101,
        }],
    })

    assert any("risk_score" in error for error in errors)


def test_unknown_severity_is_rejected():
    errors = validate_report({
        "summary": {},
        "findings": [{
            "title": "Unknown severity",
            "severity": "EXTREME",
            "risk_score": 20,
        }],
    })

    assert any("severity" in error.lower() for error in errors)


def test_summary_total_must_match_findings():
    errors = validate_report({
        "summary": {"total_findings": 2},
        "findings": [{
            "title": "Single finding",
            "severity": "INFO",
            "risk_score": 0,
        }],
    })

    assert any("total_findings" in error for error in errors)


def test_invalid_finding_entry_does_not_crash_validator():
    errors = validate_report({
        "summary": {},
        "findings": [None],
    })

    assert any("mapping/object" in error for error in errors)
