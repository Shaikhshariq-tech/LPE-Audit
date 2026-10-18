from core.analyzer import analyze_finding, analyze_findings
from core.finding import Finding


def test_analyzer_calculates_missing_score():
    finding = Finding(
        category="test",
        title="Test finding",
        description="Example",
        severity="HIGH",
        confidence="HIGH",
    )

    result = analyze_finding(finding)

    assert result is finding
    assert finding.risk_score == 65


def test_analyzer_preserves_existing_score_and_evidence():
    finding = Finding(
        category="test",
        title="Test finding",
        description="Example",
        severity="MEDIUM",
        risk_score=33,
        confidence="HIGH",
        evidence="Observed metadata",
        mitigation="Existing approved guidance",
    )

    analyze_finding(finding)

    assert finding.risk_score == 33
    assert finding.evidence == "Observed metadata"
    assert finding.mitigation == "Existing approved guidance"


def test_analyzer_fills_missing_mitigation():
    finding = Finding(
        category="sudo",
        title="Sudo policy review",
        description="Policy requires review",
        severity="MEDIUM",
    )

    analyze_finding(finding)

    assert "administrator" in finding.mitigation.lower()
    assert finding.risk_score > 0


def test_analyze_findings_preserves_order_and_identity():
    first = Finding(category="one", title="One", description="First")
    second = Finding(category="two", title="Two", description="Second")

    results = analyze_findings([first, second])

    assert results == [first, second]
    assert results[0] is first
    assert results[1] is second


def test_analyzer_does_not_change_severity_to_match_score():
    finding = Finding(
        category="test",
        title="Test",
        description="Example",
        severity="LOW",
        risk_score=90,
    )

    analyze_finding(finding)

    assert finding.severity == "LOW"
    assert finding.risk_score == 90


def test_generic_recommendation_is_provided_when_needed():
    finding = Finding(
        category="unclassified",
        title="Unusual configuration",
        description="Needs review",
    )

    analyze_finding(finding)

    assert "validate the evidence" in finding.mitigation.lower()
