from reporting.report_validator import validate_report


def test_missing_summary_is_reported():
    errors = validate_report({"findings": []})

    assert any("summary" in error.lower() for error in errors)


def test_non_list_findings_is_reported():
    errors = validate_report({
        "summary": {},
        "findings": {},
    })

    assert any("findings" in error.lower() for error in errors)


def test_non_mapping_summary_is_reported():
    errors = validate_report({
        "summary": None,
        "findings": [],
    })

    assert any("summary" in error.lower() for error in errors)


def test_missing_findings_is_reported():
    errors = validate_report({"summary": {}})

    assert any("findings" in error.lower() for error in errors)


def test_invalid_finding_entry_does_not_crash_validation():
    errors = validate_report({
        "summary": {},
        "findings": [None, "invalid", 42],
    })

    assert isinstance(errors, list)
    assert len(errors) >= 3


def test_missing_optional_summary_counts_are_allowed():
    errors = validate_report({
        "summary": {},
        "findings": [],
    })

    assert errors == []
