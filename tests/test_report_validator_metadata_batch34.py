from reporting.report_validator import validate_report


def test_boolean_provided_scores_is_rejected():
    errors = validate_report({
        "summary": {"provided_scores": True},
        "findings": [],
    })

    assert any("provided_scores" in error.lower() for error in errors)


def test_negative_provided_scores_is_rejected():
    errors = validate_report({
        "summary": {"provided_scores": -1},
        "findings": [],
    })

    assert any("provided_scores" in error.lower() for error in errors)


def test_boolean_correlated_findings_is_rejected():
    errors = validate_report({
        "summary": {"correlated_findings": True},
        "findings": [],
    })

    assert any("correlated_findings" in error.lower() for error in errors)


def test_negative_correlated_groups_is_rejected():
    errors = validate_report({
        "summary": {"correlated_groups": -1},
        "findings": [],
    })

    assert any("correlated_groups" in error.lower() for error in errors)


def test_non_string_severity_count_key_does_not_crash():
    errors = validate_report({
        "summary": {"severity_counts": {1: 0}},
        "findings": [],
    })

    assert isinstance(errors, list)


def test_empty_correlation_id_is_not_counted():
    errors = validate_report({
        "summary": {
            "correlated_findings": 0,
            "correlated_groups": 0,
        },
        "findings": [
            {
                "title": "Uncorrelated example",
                "severity": "INFO",
                "risk_score": 0,
                "correlation_id": "",
            }
        ],
    })

    assert errors == []
