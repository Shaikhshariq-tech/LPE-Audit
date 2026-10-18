import pytest

from core.finding import Finding
from core.risk_engine import RiskEngine


def test_higher_severity_has_higher_base_score():
    assert RiskEngine.score("HIGH", "HIGH") > RiskEngine.score("LOW", "HIGH")


def test_low_confidence_reduces_score():
    assert RiskEngine.score("HIGH", "LOW") < RiskEngine.score("HIGH", "HIGH")


def test_risk_score_is_bounded():
    score = RiskEngine.score(
        "CRITICAL", "HIGH", True, True, True
    )
    assert 0 <= score <= 100


def test_unknown_severity_is_rejected():
    with pytest.raises(ValueError):
        RiskEngine.score("UNKNOWN")


def test_apply_updates_finding():
    finding = Finding(category="test", title="Test", description="Test")
    result = RiskEngine.apply(finding, privileged_context=True)
    assert result is finding
    assert finding.risk_score > 0


def test_score_maps_to_severity():
    assert RiskEngine.severity_for_score(90) == "CRITICAL"
    assert RiskEngine.severity_for_score(66) == "HIGH"
    assert RiskEngine.severity_for_score(40) == "MEDIUM"
