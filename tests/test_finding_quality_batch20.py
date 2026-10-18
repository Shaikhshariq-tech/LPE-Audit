from core.finding import Finding
from core.risk_engine import RiskEngine
from reporting.report_builder import build_report
from reporting.report_validator import validate_report


def test_finding_serialization_produces_a_mapping():
    finding = Finding(
        category="regression-test",
        title="Batch 20 test finding",
        severity="HIGH",
        description="Synthetic test data; not a real system finding.",
    )

    serialized = finding.to_dict()

    assert isinstance(serialized, dict)
    assert serialized["title"] == "Batch 20 test finding"
    assert serialized["category"] == "regression-test"
    assert serialized["severity"] == "HIGH"


def test_risk_engine_returns_bounded_score():
    score = RiskEngine.score(
        severity="HIGH",
        confidence="MEDIUM",
    )

    assert isinstance(score, int)
    assert not isinstance(score, bool)
    assert 0 <= score <= 100


def test_risk_engine_rejects_unknown_severity():
    try:
        RiskEngine.score(severity="UNRECOGNIZED")
    except ValueError:
        pass
    else:
        raise AssertionError("Unknown severity should raise ValueError")


def test_report_validator_rejects_boolean_risk_score():
    report = build_report({}, [], ["synthetic-test"])
    report["findings"] = [
        {
            "title": "Synthetic finding",
            "severity": "HIGH",
            "risk_score": True,
        }
    ]
    report["summary"]["total_findings"] = 1
    report["summary"]["high_risk_findings"] = 0

    errors = validate_report(report)

    assert any("risk_score" in error for error in errors)


def test_report_validator_rejects_missing_finding_title():
    report = build_report({}, [], ["synthetic-test"])
    report["findings"] = [
        {
            "severity": "LOW",
            "risk_score": 10,
        }
    ]
    report["summary"]["total_findings"] = 1

    errors = validate_report(report)

    assert any("title" in error.lower() for error in errors)


def test_report_validator_rejects_unknown_severity():
    report = build_report({}, [], ["synthetic-test"])
    report["findings"] = [
        {
            "title": "Synthetic finding",
            "severity": "UNRECOGNIZED",
            "risk_score": 10,
        }
    ]
    report["summary"]["total_findings"] = 1

    errors = validate_report(report)

    assert any("severity" in error.lower() for error in errors)
