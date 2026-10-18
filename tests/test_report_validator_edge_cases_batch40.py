from reporting.report_validator import validate_report


def test_none_correlation_id_is_allowed():
    report = {
        "summary": {
            "correlated_findings": 0,
            "correlated_groups": 0,
        },
        "findings": [{
            "title": "Uncorrelated finding",
            "severity": "INFO",
            "risk_score": 0,
            "correlation_id": None,
        }],
    }

    assert validate_report(report) == []


def test_whitespace_correlation_id_is_not_counted():
    report = {
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
    }

    assert validate_report(report) == []


def test_whitespace_duplicate_reference_is_not_counted():
    report = {
        "summary": {"duplicate_findings": 0},
        "findings": [{
            "title": "Whitespace duplicate",
            "severity": "INFO",
            "risk_score": 0,
            "duplicate_of": "   ",
        }],
    }

    assert validate_report(report) == []


def test_non_string_duplicate_reference_is_rejected():
    report = {
        "summary": {},
        "findings": [{
            "title": "Invalid duplicate metadata",
            "severity": "INFO",
            "risk_score": 0,
            "duplicate_of": 123,
        }],
    }

    errors = validate_report(report)
    assert any("duplicate_of" in error for error in errors)


def test_validator_does_not_modify_nested_report_data():
    report = {
        "summary": {
            "correlated_findings": 0,
            "correlated_groups": 0,
            "duplicate_findings": 0,
        },
        "findings": [{
            "title": "Uncorrelated finding",
            "severity": "INFO",
            "risk_score": 0,
            "correlation_id": "   ",
            "duplicate_of": "   ",
        }],
    }

    original = {
        "summary": dict(report["summary"]),
        "findings": [dict(report["findings"][0])],
    }

    validate_report(report)

    assert report == original
