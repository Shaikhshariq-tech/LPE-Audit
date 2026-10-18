from reporting.report_validator import validate_report


def test_non_mapping_report_is_rejected():
    errors = validate_report([])

    assert errors
    assert any("report" in error.lower() for error in errors)


def test_missing_finding_title_is_rejected():
    errors = validate_report({
        "summary": {},
        "findings": [{
            "severity": "LOW",
            "risk_score": 10,
        }],
    })

    assert any("title" in error.lower() for error in errors)


def test_missing_finding_severity_is_rejected():
    errors = validate_report({
        "summary": {},
        "findings": [{
            "title": "Missing severity",
            "risk_score": 10,
        }],
    })

    assert any("severity" in error.lower() for error in errors)


def test_missing_finding_risk_score_is_rejected():
    errors = validate_report({
        "summary": {},
        "findings": [{
            "title": "Missing risk score",
            "severity": "LOW",
        }],
    })

    assert any("risk_score" in error.lower() for error in errors)


def test_non_string_correlation_id_does_not_crash():
    errors = validate_report({
        "summary": {
            "correlated_findings": 0,
            "correlated_groups": 0,
        },
        "findings": [{
            "title": "Unusual metadata",
            "severity": "INFO",
            "risk_score": 0,
            "correlation_id": [],
        }],
    })

    assert isinstance(errors, list)


def test_non_string_duplicate_reference_does_not_crash():
    errors = validate_report({
        "summary": {"duplicate_findings": 0},
        "findings": [{
            "title": "Unusual duplicate reference",
            "severity": "INFO",
            "risk_score": 0,
            "duplicate_of": {},
        }],
    })

    assert isinstance(errors, list)
