from reporting.report_validator import validate_report


def make_report(findings, **summary_overrides):
    summary = {
        "total_findings": len(findings),
        "severity_counts": {},
    }
    summary.update(summary_overrides)
    return {"summary": summary, "findings": findings}


def finding(title, correlation_id=None, duplicate_of=None):
    return {
        "title": title,
        "severity": "LOW",
        "risk_score": 20,
        "correlation_id": correlation_id,
        "duplicate_of": duplicate_of,
    }


def test_mismatched_correlated_finding_count_is_rejected():
    findings = [finding("A", "group-1"), finding("B")]
    report = make_report(findings, correlated_findings=0)

    errors = validate_report(report)

    assert any("correlated_findings" in error for error in errors)


def test_mismatched_duplicate_count_is_rejected():
    findings = [finding("A", duplicate_of="finding-1")]
    report = make_report(findings, duplicate_findings=0)

    errors = validate_report(report)

    assert any("duplicate_findings" in error for error in errors)


def test_mismatched_correlated_group_count_is_rejected():
    findings = [finding("A", "group-1"), finding("B", "group-1")]
    report = make_report(findings, correlated_groups=2)

    errors = validate_report(report)

    assert any("correlated_groups" in error for error in errors)


def test_correct_correlation_counts_are_accepted():
    findings = [
        finding("A", "group-1"),
        finding("B", "group-1", duplicate_of="A"),
        finding("C", "group-2"),
        finding("D"),
    ]
    report = make_report(
        findings,
        correlated_findings=3,
        duplicate_findings=1,
        correlated_groups=2,
    )

    errors = validate_report(report)

    assert errors == []


def test_boolean_correlation_count_is_rejected():
    findings = [finding("A", "group-1")]
    report = make_report(findings, correlated_findings=True)

    errors = validate_report(report)

    assert any("correlated_findings" in error for error in errors)


def test_negative_duplicate_count_is_rejected():
    report = make_report([], duplicate_findings=-1)

    errors = validate_report(report)

    assert any("duplicate_findings" in error for error in errors)
