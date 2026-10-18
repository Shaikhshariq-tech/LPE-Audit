"""Severity normalization and risk-band helpers."""

from core.finding import VALID_SEVERITIES
from core.risk_engine import RiskEngine


def normalize_severity(value: str, default: str = "INFO") -> str:
    """Return a validated severity label in uppercase."""
    normalized = str(value or default).strip().upper()
    fallback = str(default or "INFO").strip().upper()

    if fallback not in VALID_SEVERITIES:
        fallback = "INFO"

    if normalized not in VALID_SEVERITIES:
        return fallback

    return normalized


def severity_for_score(score: int) -> str:
    """Map a bounded numeric score to the project's standard risk band."""
    return RiskEngine.severity_for_score(score)
