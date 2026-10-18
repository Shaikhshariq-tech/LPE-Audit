from core.finding import Finding
from core.risk_engine import RiskEngine


def test_risk_engine_is_deterministic_for_identical_inputs():
    first = RiskEngine.score(
        severity="HIGH",
        confidence="MEDIUM",
        privileged_context=True,
    )
    second = RiskEngine.score(
        severity="HIGH",
        confidence="MEDIUM",
        privileged_context=True,
    )

    assert first == second


def test_risk_engine_increases_score_for_writable_context():
    baseline = RiskEngine.score(
        severity="HIGH",
        confidence="HIGH",
    )
    writable = RiskEngine.score(
        severity="HIGH",
        confidence="HIGH",
        writable_by_unprivileged=True,
    )

    assert writable > baseline


def test_finding_round_trip_preserves_core_fields():
    original = Finding(
        category="regression-test",
        title="Synthetic finding",
        description="No real system issue is represented.",
        severity="MEDIUM",
        risk_score=42,
        scanner="batch21-test",
    )

    restored = Finding.from_dict(original.to_dict())

    assert restored.category == original.category
    assert restored.title == original.title
    assert restored.description == original.description
    assert restored.severity == original.severity
    assert restored.risk_score == original.risk_score
    assert restored.scanner == original.scanner


def test_finding_rejects_invalid_severity():
    try:
        Finding(
            category="regression-test",
            title="Synthetic finding",
            description="Test only.",
            severity="NOT_A_SEVERITY",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid severity should be rejected")
