import pytest

from reporting.risk_regression_detector import (
    RiskRegressionError,
    analyze_risk_regressions,
)


SENTINEL = "PRIVATE_LABEL_OR_FIELD_SENTINEL"


def valid_report():
    return {
        "findings": [{
            "category": "permissions",
            "title": "Example",
            "affected_path": "/tmp/example",
            "scanner": "test",
            "severity": "LOW",
            "risk_score": 20,
        }]
    }


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda finding: finding.update({"category": object()}),
            "invalid field",
        ),
        (
            lambda finding: finding.update({"risk_score": "invalid"}),
            "non-numeric risk score",
        ),
        (
            lambda finding: finding.update({"severity": SENTINEL}),
            "unknown severity",
        ),
    ],
)
def test_public_validation_does_not_disclose_caller_label_or_field_values(
    mutation, expected
):
    baseline = valid_report()
    current = valid_report()
    mutation(current["findings"][0])

    with pytest.raises(RiskRegressionError) as caught:
        analyze_risk_regressions(
            baseline,
            current,
            baseline_label=SENTINEL,
            current_label=SENTINEL,
        )

    message = str(caught.value)
    assert expected in message
    assert SENTINEL not in message


def test_public_validation_does_not_disclose_label_for_non_object_finding():
    baseline = valid_report()
    current = {"findings": [SENTINEL]}

    with pytest.raises(RiskRegressionError) as caught:
        analyze_risk_regressions(
            baseline,
            current,
            current_label=SENTINEL,
        )

    assert SENTINEL not in str(caught.value)
    assert "Finding 0" in str(caught.value)


def test_successful_regression_analysis_preserves_labels_and_report_data():
    baseline = valid_report()
    current = valid_report()

    result = analyze_risk_regressions(
        baseline,
        current,
        baseline_label="approved-baseline",
        current_label="current-audit",
    )

    assert result["baseline_label"] == "approved-baseline"
    assert result["current_label"] == "current-audit"
    assert baseline["findings"][0]["title"] == "Example"
    assert current["findings"][0]["risk_score"] == 20
