from reporting.report_validator import validate_report


def test_non_mapping_report_returns_error_list():
    errors = validate_report(None)

    assert isinstance(errors, list)
    assert errors


def test_tuple_findings_container_is_rejected():
    errors = validate_report({
        "summary": {},
        "findings": (),
    })

    assert any("findings" in error.lower() for error in errors)


def test_non_mapping_finding_returns_error():
    errors = validate_report({
        "summary": {},
        "findings": [None],
    })

    assert any("finding at index 0" in error.lower() for error in errors)


def test_correlation_metadata_with_unhashable_id_does_not_crash():
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


def test_invalid_severity_counts_list_does_not_crash():
    errors = validate_report({
        "summary": {"severity_counts": ["HIGH", "LOW"]},
        "findings": [],
    })

    assert isinstance(errors, list)


def test_validator_does_not_modify_nested_input():
    report = {
        "summary": {"total_findings": 0},
        "findings": [{
            "title": "Stable input",
            "severity": "INFO",
            "risk_score": 0,
            "metadata": {"tags": ["test"]},
        }],
    }
    before = {
        "summary": {"total_findings": 0},
        "findings": [{
            "title": "Stable input",
            "severity": "INFO",
            "risk_score": 0,
            "metadata": {"tags": ["test"]},
        }],
    }

    validate_report(report)

    assert report == before
