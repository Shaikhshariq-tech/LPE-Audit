from reporting.report_validator import validate_report


def _finding(title, score_source):
    return {
        "title": title,
        "severity": "INFO",
        "risk_score": 10,
        "risk_score_source": score_source,
    }


def test_validator_rejects_mismatched_calculated_score_count():
    report = {
        "summary": {"calculated_scores": 0},
        "findings": [_finding("Calculated example", "calculated")],
    }

    errors = validate_report(report)

    assert any(
        "calculated_scores does not match finding score sources" in error
        for error in errors
    )


def test_validator_rejects_mismatched_provided_score_count():
    report = {
        "summary": {"provided_scores": 0},
        "findings": [_finding("Provided example", "provided")],
    }

    errors = validate_report(report)

    assert any(
        "provided_scores does not match finding score sources" in error
        for error in errors
    )


def test_validator_accepts_matching_counts_when_sources_are_recognized():
    report = {
        "summary": {
            "calculated_scores": 1,
            "provided_scores": 1,
        },
        "findings": [
            _finding("Calculated example", "calculated"),
            _finding("Provided example", "provided"),
        ],
    }

    assert validate_report(report) == []


def test_validator_preserves_compatibility_with_legacy_score_sources():
    report = {
        "summary": {
            "calculated_scores": 0,
            "provided_scores": 0,
        },
        "findings": [
            _finding("Calculated example", "calculated"),
            _finding("Legacy example", ""),
        ],
    }

    # Legacy findings have incomplete score-source metadata, so totals
    # cannot be reliably compared against all findings.
    assert validate_report(report) == []


def test_validator_keeps_score_source_summary_fields_optional():
    report = {
        "summary": {},
        "findings": [_finding("Calculated example", "calculated")],
    }

    assert validate_report(report) == []
