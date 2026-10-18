from analysis.prioritization import prioritize_findings
from core.analyzer import analyze_findings
from core.finding import Finding
from core.risk_engine import RiskEngine
from reporting.report_builder import build_report
from reporting.text_report import build_text_report


def make_finding(title, severity, score, confidence="MEDIUM"):
    return Finding(
        category="test",
        title=title,
        description="Test finding",
        severity=severity,
        risk_score=score,
        confidence=confidence,
    )


def test_explain_matches_existing_score_calculation():
    details = RiskEngine.explain(
        "HIGH",
        "MEDIUM",
        privileged_context=True,
        writable_by_unprivileged=True,
    )

    assert details["base_score"] == 65
    assert details["adjustment_total"] == 20
    assert details["confidence_factor"] == 0.80
    assert details["final_score"] == RiskEngine.score(
        "HIGH",
        "MEDIUM",
        privileged_context=True,
        writable_by_unprivileged=True,
    )


def test_explanation_lists_only_enabled_adjustments():
    details = RiskEngine.explain(
        "MEDIUM",
        "HIGH",
        known_vulnerability=True,
    )

    assert details["adjustments"] == [
        {"factor": "known_vulnerability", "points": 10}
    ]
    assert details["final_score"] == 50


def test_priority_orders_highest_score_first():
    low = make_finding("Low item", "LOW", 20)
    critical = make_finding("Critical item", "CRITICAL", 90)
    medium = make_finding("Medium item", "MEDIUM", 40)

    result = prioritize_findings([low, critical, medium])

    assert result == [critical, medium, low]


def test_priority_tie_breaks_by_severity():
    low = make_finding("Low severity", "LOW", 50)
    high = make_finding("High severity", "HIGH", 50)

    assert prioritize_findings([low, high]) == [high, low]


def test_analyzer_assigns_ranks_without_reordering_input():
    first = make_finding("Low", "LOW", 20)
    second = make_finding("High", "HIGH", 65)

    result = analyze_findings([first, second])

    assert result == [first, second]
    assert second.priority_rank == 1
    assert first.priority_rank == 2


def test_analyzer_explains_calculated_scores():
    finding = Finding(
        category="test",
        title="Missing score",
        description="Test",
        severity="HIGH",
        confidence="HIGH",
    )

    analyze_findings([finding])

    assert finding.risk_score == 65
    assert finding.risk_score_source == "calculated"
    assert "HIGH base 65" in finding.risk_score_explanation
    assert "confidence multiplier 1.00" in finding.risk_score_explanation


def test_analyzer_labels_preserved_scores_as_provided():
    finding = make_finding("Existing score", "MEDIUM", 37)

    analyze_findings([finding])

    assert finding.risk_score == 37
    assert finding.risk_score_source == "provided"
    assert "calculation factors were not available" in finding.risk_score_explanation


def test_report_contains_priority_and_score_explanation():
    first = make_finding("Lower", "LOW", 20)
    second = make_finding("Higher", "HIGH", 65)

    analyzed = analyze_findings([first, second])
    report = build_report({}, analyzed, ["test"])
    rendered = build_text_report(report)

    assert report["summary"]["high_risk_findings"] == 1
    assert report["summary"]["calculated_scores"] == 0
    assert report["summary"]["provided_scores"] == 2
    assert "Priority" in rendered
    assert "Score Basis" in rendered
    assert "High risk (65+): 1" in rendered
