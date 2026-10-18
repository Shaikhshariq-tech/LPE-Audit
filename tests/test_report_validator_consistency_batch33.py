from reporting.report_validator import validate_report


def test_mismatched_total_findings_is_rejected():
    errors = validate_report({
        "summary": {"total_findings": 2},
        "findings": [],
    })

    assert any("total_findings" in error.lower() for error in errors)


def test_mismatched_high_risk_count_is_rejected():
    errors = validate_report({
        "summary": {"high_risk_findings": 1},
        "findings": [
            {
                "title": "Low-risk example",
                "severity": "LOW",
                "risk_score": 10,
            }
        ],
    })

    assert any("high_risk_findings" in error.lower() for error in errors)


def test_mismatched_high_severity_count_is_rejected():
    errors = validate_report({
        "summary": {"high": 1},
        "findings": [
            {
                "title": "Low-severity example",
                "severity": "LOW",
                "risk_score": 10,
            }
        ],
    })

    assert any("summary high" in error.lower() for error in errors)


def test_invalid_severity_counts_container_is_not_crash():
    errors = validate_report({
        "summary": {"severity_counts": []},
        "findings": [],
    })

    assert isinstance(errors, list)


def test_severity_count_boolean_is_rejected():
    errors = validate_report({
        "summary": {"severity_counts": {"HIGH": True}},
        "findings": [],
    })

    assert any("severity count" in error.lower() for error in errors)


def test_valid_empty_report_is_accepted():
    errors = validate_report({
        "summary": {
            "total_findings": 0,
            "high_risk_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "correlated_findings": 0,
            "duplicate_findings": 0,
            "correlated_groups": 0,
        },
        "findings": [],
    })

    assert errors == []
