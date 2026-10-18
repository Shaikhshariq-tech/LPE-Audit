from core.finding import Finding
from reporting.report_builder import build_report
from reporting.text_report import build_text_report


def make_finding(title, path, category="permissions"):
    return Finding(
        category=category,
        title=title,
        description="Test description",
        affected_path=path,
        evidence="Test evidence",
        detection_reason="Detected from metadata",
        potential_impact="May allow unintended modification",
        attack_path_description="Requires manual validation",
        mitigation="Review permissions",
        references=["https://example.invalid/security-guidance"],
    )


def test_report_summary_counts_correlation_metadata():
    first = make_finding("Writable file", "/opt/example")
    second = make_finding("Service file", "/opt/example", "services")
    third = make_finding("Other file", "/opt/other")

    first.correlation_id = "path-test"
    second.correlation_id = "path-test"
    first.related_finding_ids = [second.finding_id]
    second.related_finding_ids = [first.finding_id]
    second.duplicate_of = first.finding_id

    report = build_report(
        system_info={},
        findings=[first, second, third],
        modules=["test"],
    )

    summary = report["summary"]
    assert summary["total_findings"] == 3
    assert summary["correlated_findings"] == 2
    assert summary["duplicate_findings"] == 1
    assert summary["correlated_groups"] == 1
    assert summary["info"] == 3


def test_report_keeps_original_finding_fields():
    finding = make_finding("Writable file", "/opt/example")
    finding.correlation_id = "path-test"
    finding.related_finding_ids = ["related-123"]

    report = build_report({}, [finding], ["test"])
    saved = report["findings"][0]

    assert saved["finding_id"] == finding.finding_id
    assert saved["evidence"] == "Test evidence"
    assert saved["mitigation"] == "Review permissions"
    assert saved["correlation_id"] == "path-test"
    assert saved["related_finding_ids"] == ["related-123"]


def test_text_report_displays_correlation_and_analysis():
    first = make_finding("Writable file", "/opt/example")
    second = make_finding("Service file", "/opt/example", "services")

    first.correlation_id = "path-test"
    first.related_finding_ids = [second.finding_id]
    second.correlation_id = "path-test"
    second.related_finding_ids = [first.finding_id]
    second.duplicate_of = first.finding_id

    report = build_report({}, [first, second], ["test"])
    rendered = build_text_report(report)

    assert "Correlated" in rendered
    assert "Correlation groups:" in rendered
    assert "path-test" in rendered
    assert "Related IDs:" in rendered
    assert "Duplicate Of:" in rendered
    assert "Detected from metadata" in rendered
    assert "May allow unintended modification" in rendered
    assert "Requires manual validation" in rendered
    assert "https://example.invalid/security-guidance" in rendered
