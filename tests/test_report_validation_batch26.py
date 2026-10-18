from copy import deepcopy

from reporting.report_validator import validate_report


def valid_report():
    return {
        "summary": {
            "total_findings": 0,
            "severity_counts": {},
        },
        "findings": [],
    }


def test_empty_report_structure_is_accepted_or_reports_specific_errors():
    errors = validate_report(valid_report())

    assert isinstance(errors, list)


def test_non_dictionary_report_is_rejected():
    errors = validate_report(None)

    assert isinstance(errors, list)
    assert errors


def test_missing_findings_is_detected():
    report = valid_report()
    del report["findings"]

    errors = validate_report(report)

    assert isinstance(errors, list)
    assert errors


def test_validation_does_not_mutate_input_report():
    report = valid_report()
    before = deepcopy(report)

    validate_report(report)

    assert report == before
