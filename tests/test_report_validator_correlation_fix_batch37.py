from reporting.report_validator import validate_report


def test_unhashable_correlation_id_does_not_crash():
    errors = validate_report({
        "summary": {
            "correlated_findings": 0,
            "correlated_groups": 0,
        },
        "findings": [{
            "title": "Malformed correlation ID",
            "severity": "INFO",
            "risk_score": 0,
            "correlation_id": [],
        }],
    })

    assert isinstance(errors, list)


def test_duplicate_metadata_must_be_a_nonempty_string():
    errors = validate_report({
        "summary": {"duplicate_findings": 0},
        "findings": [{
            "title": "Malformed duplicate reference",
            "severity": "INFO",
            "risk_score": 0,
            "duplicate_of": {},
        }],
    })

    assert isinstance(errors, list)


def test_valid_correlation_ids_are_counted():
    errors = validate_report({
        "summary": {
            "correlated_findings": 2,
            "correlated_groups": 1,
        },
        "findings": [
            {
                "title": "Finding A",
                "severity": "LOW",
                "risk_score": 10,
                "correlation_id": "group-a",
            },
            {
                "title": "Finding B",
                "severity": "LOW",
                "risk_score": 10,
                "correlation_id": "group-a",
            },
        ],
    })

    assert errors == []
