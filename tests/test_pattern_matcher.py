from analysis.pattern_matcher import correlate_findings
from core.finding import Finding


def make_finding(
    category="permissions",
    title="Writable file",
    path="/opt/example.conf",
    evidence="mode 0775",
):
    return Finding(
        category=category,
        title=title,
        description="Test finding",
        affected_path=path,
        evidence=evidence,
    )


def test_empty_input_returns_empty_list():
    assert correlate_findings([]) == []


def test_unrelated_paths_are_not_correlated():
    first = make_finding(path="/opt/one.conf")
    second = make_finding(path="/opt/two.conf")

    result = correlate_findings([first, second])

    assert result == [first, second]
    assert first.correlation_id == ""
    assert second.correlation_id == ""
    assert first.duplicate_of == ""
    assert second.duplicate_of == ""


def test_same_path_findings_are_correlated():
    first = make_finding(category="permissions")
    second = make_finding(
        category="services",
        title="Service configuration",
        evidence="service file metadata",
    )

    result = correlate_findings([first, second])

    assert result == [first, second]
    assert first.correlation_id
    assert first.correlation_id == second.correlation_id
    assert second.finding_id in first.related_finding_ids
    assert first.finding_id in second.related_finding_ids


def test_exact_duplicates_reference_first_finding():
    first = make_finding()
    second = make_finding(
        title="  Writable   file ",
        path="/opt/./example.conf",
        evidence=" mode   0775 ",
    )

    result = correlate_findings([first, second])

    assert len(result) == 2
    assert second.duplicate_of == first.finding_id
    assert first.duplicate_of == ""


def test_same_title_without_path_is_not_deduplicated():
    first = make_finding(path="")
    second = make_finding(path="")

    correlate_findings([first, second])

    assert first.duplicate_of == ""
    assert second.duplicate_of == ""
    assert first.correlation_id == ""
    assert second.correlation_id == ""


def test_different_evidence_is_not_an_exact_duplicate():
    first = make_finding(evidence="mode 0775")
    second = make_finding(evidence="mode 0777")

    correlate_findings([first, second])

    assert second.duplicate_of == ""
    # They still share a path, which is reported separately.
    assert first.correlation_id == second.correlation_id


def test_correlation_preserves_finding_evidence_and_scores():
    first = make_finding()
    second = make_finding(category="services", evidence="unit metadata")
    first.risk_score = 42
    first.mitigation = "Existing remediation"
    original_evidence = first.evidence

    correlate_findings([first, second])

    assert first.risk_score == 42
    assert first.mitigation == "Existing remediation"
    assert first.evidence == original_evidence


def test_repeated_correlation_is_idempotent():
    first = make_finding()
    second = make_finding(category="services", evidence="unit metadata")

    first_pass = correlate_findings([first, second])
    correlation_id = first.correlation_id
    second_pass = correlate_findings(first_pass)

    assert second_pass == first_pass
    assert first.correlation_id == correlation_id
    assert first.related_finding_ids == [second.finding_id]
    assert second.related_finding_ids == [first.finding_id]


def test_analyzer_integrates_correlation():
    from core.analyzer import analyze_findings

    first = make_finding()
    second = make_finding(category="services", evidence="unit metadata")

    result = analyze_findings([first, second])

    assert len(result) == 2
    assert result[0].correlation_id == result[1].correlation_id
