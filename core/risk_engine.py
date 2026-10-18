"""Explainable, bounded risk scoring for security findings."""

from typing import Any

from core.finding import Finding


SEVERITY_BASE = {
    "INFO": 5,
    "LOW": 20,
    "MEDIUM": 40,
    "HIGH": 65,
    "CRITICAL": 85,
}

CONFIDENCE_FACTOR = {
    "LOW": 0.60,
    "MEDIUM": 0.80,
    "HIGH": 1.00,
}


class RiskEngine:
    """Calculate consistent scores without claiming exploitability."""

    @staticmethod
    def explain(
        severity: str,
        confidence: str = "MEDIUM",
        privileged_context: bool = False,
        writable_by_unprivileged: bool = False,
        known_vulnerability: bool = False,
    ) -> dict[str, Any]:
        """Return the score and the factors used to calculate it."""
        severity = str(severity).upper()
        confidence = str(confidence).upper()

        if severity not in SEVERITY_BASE:
            raise ValueError(f"Unknown severity: {severity}")
        if confidence not in CONFIDENCE_FACTOR:
            raise ValueError(f"Unknown confidence: {confidence}")

        base_score = SEVERITY_BASE[severity]
        adjustments = []

        if privileged_context:
            adjustments.append({
                "factor": "privileged_context",
                "points": 8,
            })
        if writable_by_unprivileged:
            adjustments.append({
                "factor": "writable_by_unprivileged",
                "points": 12,
            })
        if known_vulnerability:
            adjustments.append({
                "factor": "known_vulnerability",
                "points": 10,
            })

        adjustment_total = sum(item["points"] for item in adjustments)
        factor = CONFIDENCE_FACTOR[confidence]
        pre_confidence_score = base_score + adjustment_total
        final_score = max(
            0,
            min(100, round(pre_confidence_score * factor)),
        )

        return {
            "severity": severity,
            "confidence": confidence,
            "base_score": base_score,
            "adjustments": adjustments,
            "adjustment_total": adjustment_total,
            "confidence_factor": factor,
            "pre_confidence_score": pre_confidence_score,
            "final_score": final_score,
        }

    @staticmethod
    def score(
        severity: str,
        confidence: str = "MEDIUM",
        privileged_context: bool = False,
        writable_by_unprivileged: bool = False,
        known_vulnerability: bool = False,
    ) -> int:
        """Calculate a bounded score using the documented scoring factors."""
        return RiskEngine.explain(
            severity=severity,
            confidence=confidence,
            privileged_context=privileged_context,
            writable_by_unprivileged=writable_by_unprivileged,
            known_vulnerability=known_vulnerability,
        )["final_score"]

    @staticmethod
    def apply(finding: Finding, **factors: bool) -> Finding:
        """Update and return a finding's risk score."""
        finding.risk_score = RiskEngine.score(
            severity=finding.severity,
            confidence=finding.confidence,
            **factors,
        )
        finding.risk_score_source = "calculated"
        details = RiskEngine.explain(
            severity=finding.severity,
            confidence=finding.confidence,
            **factors,
        )
        finding.risk_score_explanation = RiskEngine.format_explanation(details)
        return finding

    @staticmethod
    def format_explanation(details: dict[str, Any]) -> str:
        """Convert score details to a readable audit explanation."""
        adjustment_text = ", ".join(
            f"{item['factor']} +{item['points']}"
            for item in details["adjustments"]
        ) or "no additional adjustments"

        return (
            f"{details['severity']} base {details['base_score']}; "
            f"{adjustment_text}; confidence multiplier "
            f"{details['confidence_factor']:.2f}; "
            f"final calculated score {details['final_score']}/100."
        )

    @staticmethod
    def severity_for_score(score: int) -> str:
        """Map a score to a reporting band."""
        score = max(0, min(100, int(score)))
        if score >= 85:
            return "CRITICAL"
        if score >= 65:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 20:
            return "LOW"
        return "INFO"
