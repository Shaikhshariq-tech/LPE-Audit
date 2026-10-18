"""Normalize findings and enrich them for safe audit reporting."""

from collections.abc import Iterable

from analysis.pattern_matcher import correlate_findings
from analysis.prioritization import prioritize_findings
from analysis.recommendations import recommendation_for_finding
from analysis.severity import normalize_severity
from core.finding import Finding
from core.risk_engine import RiskEngine


def analyze_finding(finding: Finding) -> Finding:
    """Enrich one finding without discarding scanner-provided evidence."""
    finding.severity = normalize_severity(finding.severity)

    if finding.risk_score <= 0:
        details = RiskEngine.explain(
            severity=finding.severity,
            confidence=finding.confidence,
        )
        finding.risk_score = details["final_score"]
        finding.risk_score_source = "calculated"
        finding.risk_score_explanation = RiskEngine.format_explanation(details)
    else:
        if not finding.risk_score_source:
            finding.risk_score_source = "provided"
        if not finding.risk_score_explanation:
            finding.risk_score_explanation = (
                f"Score {finding.risk_score}/100 was provided by a scanner "
                "or earlier processing. Its original calculation factors "
                "were not available to this analyzer."
            )

    finding.risk_score = max(0, min(100, int(finding.risk_score)))

    if not finding.mitigation or not finding.mitigation.strip():
        finding.mitigation = recommendation_for_finding(finding)

    return finding


def analyze_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Analyze, correlate, and rank findings while preserving input order."""
    analyzed = [analyze_finding(finding) for finding in findings]
    correlated = correlate_findings(analyzed)

    ordered = prioritize_findings(correlated)
    for rank, finding in enumerate(ordered, start=1):
        finding.priority_rank = rank

    return correlated
