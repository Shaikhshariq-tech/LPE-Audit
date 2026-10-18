import pytest

from analysis.severity import normalize_severity, severity_for_score


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("info", "INFO"),
        ("low", "LOW"),
        ("MEDIUM", "MEDIUM"),
        ("high", "HIGH"),
        ("critical", "CRITICAL"),
    ],
)
def test_normalize_valid_severity(value, expected):
    assert normalize_severity(value) == expected


def test_normalize_invalid_severity_uses_default():
    assert normalize_severity("unexpected") == "INFO"


def test_normalize_uses_validated_default():
    assert normalize_severity("", default="high") == "HIGH"
    assert normalize_severity("", default="unknown") == "INFO"


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "INFO"),
        (20, "LOW"),
        (40, "MEDIUM"),
        (65, "HIGH"),
        (85, "CRITICAL"),
        (150, "CRITICAL"),
    ],
)
def test_severity_for_score(score, expected):
    assert severity_for_score(score) == expected
