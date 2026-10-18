from reporting.report_validator import validate_report


def test_boolean_severity_count_is_rejected():
    errors = validate_report({
        "summary": {"high": True},
        "findings": [],
    })

    assert any("summary high" in error.lower() for error in errors)


def test_negative_severity_count_is_rejected():
    errors = validate_report({
        "summary": {"critical": -1},
        "findings": [],
    })

    assert any("summary critical" in error.lower() for error in errors)


def test_boolean_correlation_count_is_rejected():
    errors = validate_report({
        "summary": {"correlated_findings": True},
        "findings": [],
    })

    assert any("correlated_findings" in error.lower() for error in errors)


def test_negative_duplicate_count_is_rejected():
    errors = validate_report({
        "summary": {"duplicate_findings": -1},
        "findings": [],
    })

    assert any("duplicate_findings" in error.lower() for error in errors)


def test_incorrect_correlated_group_count_is_rejected():
    errors = validate_report({
        "summary": {"correlated_groups": 2},
        "findings": [
            {
                "severity": "LOW",
                "risk_score": 10,
                "title": "Example finding",
                "correlation_id": "group-a",
            }
        ],
    })

    assert any("correlated_groups" in error.lower() for error in errors)


def test_unknown_severity_count_key_is_ignored():
    errors = validate_report({
        "summary": {"NOT_A_SEVERITY": 999},
        "findings": [],
    })

    assert errors == []


def test_summary_counts_do_not_mutate_input():
    report = {
        "summary": {
            "total_findings": 0,
            "high": 0,
            "correlated_groups": 0,
        },
        "findings": [],
    }
    original = {
        "summary": {
            "total_findings": 0,
            "high": 0,
            "correlated_groups": 0,
        },
        "findings": [],
    }

    validate_report(report)

    assert report == original
