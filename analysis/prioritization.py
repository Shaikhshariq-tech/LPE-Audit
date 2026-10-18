"""Deterministic finding prioritization for analyst review."""

from collections.abc import Iterable

from core.finding import Finding


_SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

_CONFIDENCE_ORDER = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def prioritize_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Return a sorted copy; do not remove, modify, or merge findings."""
    return sorted(
        findings,
        key=lambda finding: (
            -finding.risk_score,
            -_SEVERITY_ORDER.get(finding.severity.upper(), 0),
            -_CONFIDENCE_ORDER.get(finding.confidence.upper(), 0),
            finding.affected_path.casefold(),
            finding.title.casefold(),
            finding.finding_id,
        ),
    )
