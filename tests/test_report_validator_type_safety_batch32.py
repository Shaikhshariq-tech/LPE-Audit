from reporting.report_validator import validate_report


def test_list_summary_is_rejected_without_crashing():
    errors = validate_report({
        "summary": [],
        "findings": [],
    })

    assert any("summary" in error.lower() for error in errors)


def test_string_summary_is_rejected_without_crashing():
    errors = validate_report({
        "summary": "invalid",
        "findings": [],
    })

    assert any("summary" in error.lower() for error in errors)


def test_boolean_total_findings_is_rejected():
    errors = validate_report({
        "summary": {"total_findings": True},
        "findings": [],
    })

    assert any("total_findings" in error.lower() for error in errors)


def test_negative_calculated_scores_is_rejected():
    errors = validate_report({
        "summary": {"calculated_scores": -1},
        "findings": [],
    })

    assert any("calculated_scores" in error.lower() for error in errors)


def test_boolean_high_risk_findings_is_rejected():
    errors = validate_report({
        "summary": {"high_risk_findings": True},
        "findings": [],
    })

    assert any("high_risk_findings" in error.lower() for error in errors)


def test_boolean_severity_value_is_rejected():
    errors = validate_report({
        "summary": {"severity_counts": {"HIGH": True}},
        "findings": [],
    })

    assert any("severity count" in error.lower() for error in errors)


def test_validator_handles_unusual_findings_entries():
    errors = validate_report({
        "summary": {},
        "findings": [None, [], "unexpected", 7, True],
    })

    assert isinstance(errors, list)
    assert len(errors) >= 5
