from reporting.report_validator import validate_report


def finding(title, severity, score, **extra):
    item = {
        "title": title,
        "severity": severity,
        "risk_score": score,
    }
    item.update(extra)
    return item


def report_with(findings, **summary_overrides):
    summary = {
        "total_findings": len(findings),
        "severity_counts": {},
    }
    summary.update(summary_overrides)
    return {"summary": summary, "findings": findings}


def test_mismatched_high_risk_count_is_rejected():
    findings = [
        finding("High risk", "HIGH", 80),
        finding("Low risk", "LOW", 20),
    ]
    report = report_with(findings, high_risk_findings=0)

    errors = validate_report(report)

    assert any("high_risk_findings" in error for error in errors)


def test_correct_high_risk_count_is_accepted():
    findings = [
        finding("High risk", "HIGH", 80),
        finding("Low risk", "LOW", 20),
    ]
    report = report_with(findings, high_risk_findings=1)

    errors = validate_report(report)

    assert not any("high_risk_findings" in error for error in errors)


def test_mismatched_severity_count_is_rejected():
    findings = [finding("Low risk", "LOW", 20)]
    report = report_with(findings, low=0)

    errors = validate_report(report)

    assert any("Summary low" in error for error in errors)


def test_negative_calculated_score_count_is_rejected():
    report = report_with([], calculated_scores=-1)

    errors = validate_report(report)

    assert any("calculated_scores" in error for error in errors)


def test_boolean_provided_score_count_is_rejected():
    report = report_with([], provided_scores=True)

    errors = validate_report(report)

    assert any("provided_scores" in error for error in errors)


def test_valid_summary_counts_are_accepted():
    findings = [
        finding("High risk", "HIGH", 80),
        finding("Low risk", "LOW", 20),
    ]
    report = report_with(
        findings,
        high_risk_findings=1,
        high=1,
        low=1,
        calculated_scores=2,
        provided_scores=0,
    )

    errors = validate_report(report)

    assert errors == []
