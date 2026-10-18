from reporting.report_validator import validate_report


def test_list_correlation_id_is_reported():
    errors = validate_report({
        "summary": {
            "correlated_findings": 0,
            "correlated_groups": 0,
        },
        "findings": [{
            "title": "Malformed correlation",
            "severity": "INFO",
            "risk_score": 0,
            "correlation_id": [],
        }],
    })

    assert any("correlation_id" in error for error in errors)


def test_dictionary_duplicate_reference_is_reported():
    errors = validate_report({
        "summary": {"duplicate_findings": 0},
        "findings": [{
            "title": "Malformed duplicate",
            "severity": "INFO",
            "risk_score": 0,
            "duplicate_of": {},
        }],
    })

    assert any("duplicate_of" in error for error in errors)


def test_string_correlation_metadata_remains_valid():
    errors = validate_report({
        "summary": {
            "correlated_findings": 1,
            "correlated_groups": 1,
            "duplicate_findings": 1,
        },
        "findings": [{
            "title": "Valid metadata",
            "severity": "INFO",
            "risk_score": 0,
            "correlation_id": "group-a",
            "duplicate_of": "finding-1",
        }],
    })

    assert errors == []
