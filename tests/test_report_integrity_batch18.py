import pytest

import main as app
from reporting.report_builder import build_report
from reporting.report_validator import assert_valid_report, validate_report


def test_builder_report_passes_consistency_validation():
    report = build_report({}, [], ["test"])
    assert validate_report(report) == []
    assert_valid_report(report)


@pytest.mark.parametrize(
    ("field", "bad_value", "expected_message"),
    [
        ("critical", 1, "Summary critical does not match"),
        ("high", 1, "Summary high does not match"),
        ("medium", 1, "Summary medium does not match"),
        ("low", 1, "Summary low does not match"),
        ("info", 1, "Summary info does not match"),
        (
            "correlated_findings",
            1,
            "Summary correlated_findings does not match",
        ),
        (
            "duplicate_findings",
            1,
            "Summary duplicate_findings does not match",
        ),
        (
            "correlated_groups",
            1,
            "Summary correlated_groups does not match",
        ),
    ],
)
def test_inconsistent_summary_counts_are_rejected(
    field, bad_value, expected_message
):
    report = build_report({}, [], ["test"])
    report["summary"][field] = bad_value

    errors = validate_report(report)

    assert any(expected_message in error for error in errors)


def test_assert_valid_report_rejects_inconsistent_summary():
    report = build_report({}, [], ["test"])
    report["summary"]["high"] = 1

    with pytest.raises(ValueError, match="Report validation failed"):
        assert_valid_report(report)


def test_write_reports_validates_before_writing(monkeypatch, tmp_path):
    calls = []

    monkeypatch.setattr(
        app,
        "build_report",
        lambda *args, **kwargs: {
            "summary": {},
            "findings": "invalid",
        },
    )
    monkeypatch.setattr(
        app,
        "write_json_report",
        lambda *args, **kwargs: calls.append("json"),
    )
    monkeypatch.setattr(
        app,
        "write_text_report",
        lambda *args, **kwargs: calls.append("text"),
    )

    with pytest.raises(ValueError, match="Report validation failed"):
        app.write_reports({}, [], ["test"], [], str(tmp_path))

    assert calls == []
