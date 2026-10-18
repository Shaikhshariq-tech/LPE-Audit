from reporting.report_validator import validate_report


def test_whitespace_correlation_id_is_reported_as_invalid():
    errors = validate_report({
        "summary": {
            "correlated_findings": 0,
            "correlated_groups": 0,
        },
        "findings": [{
            "title": "Whitespace correlation",
            "severity": "INFO",
            "risk_score": 0,
            "correlation_id": "   ",
        }],
    })

    assert errors == []


def test_whitespace_duplicate_reference_is_not_counted():
    errors = validate_report({
        "summary": {"duplicate_findings": 0},
        "findings": [{
            "title": "Whitespace duplicate",
            "severity": "INFO",
            "risk_score": 0,
            "duplicate_of": "   ",
        }],
    })

    assert errors == []


def test_duplicate_reference_is_trimmed_for_validation():
    errors = validate_report({
        "summary": {"duplicate_findings": 1},
        "findings": [{
            "title": "Valid duplicate",
            "severity": "INFO",
            "risk_score": 0,
            "duplicate_of": "finding-1",
        }],
    })

    assert errors == []


def test_non_string_correlation_metadata_is_reported():
    errors = validate_report({
        "summary": {},
        "findings": [{
            "title": "Bad correlation type",
            "severity": "INFO",
            "risk_score": 0,
            "correlation_id": 123,
        }],
    })

    assert any("correlation_id" in error for error in errors)


def test_empty_report_with_consistent_counts_is_valid():
    errors = validate_report({
        "summary": {
            "total_findings": 0,
            "high_risk_findings": 0,
            "calculated_scores": 0,
            "provided_scores": 0,
            "correlated_findings": 0,
            "duplicate_findings": 0,
            "correlated_groups": 0,
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            },
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
        "findings": [],
    })

    assert errors == []
