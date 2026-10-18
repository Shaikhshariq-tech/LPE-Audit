"""Batch 46 quality-gate tests."""
from core.finding import Finding
from core.quality_gate import evaluate_quality_gate
from reporting.report_builder import build_report
from reporting.report_validator import validate_report


def finding(severity, title="example"):
    return Finding(
        category="test",
        title=title,
        description="Test finding",
        severity=severity,
        confidence="HIGH",
        detection_reason="Test",
        potential_impact="Test",
        mitigation="Test",
        scanner="test",
    )


def test_severity_gate_triggers_at_and_above_threshold():
    result = evaluate_quality_gate(
        [finding("MEDIUM"), finding("HIGH"), finding("CRITICAL")],
        [{"name": "test", "succeeded": True}],
        ["test"],
        fail_on_severity="HIGH",
    )
    assert result["exit_code"] == 1
    assert [item["severity"] for item in result["severity_matches"]] == [
        "HIGH", "CRITICAL"
    ]


def test_severity_gate_passes_when_no_finding_reaches_threshold():
    result = evaluate_quality_gate(
        [finding("LOW")],
        [{"name": "test", "succeeded": True}],
        ["test"],
        fail_on_severity="HIGH",
    )
    assert result["exit_code"] == 0
    assert result["passed"] is True


def test_incomplete_gate_detects_selected_scan_coverage():
    result = evaluate_quality_gate(
        [],
        [{"name": "test", "succeeded": True}],
        ["test", "other"],
        fail_on_incomplete=True,
    )
    assert result["exit_code"] == 3
    assert result["not_run_modules"] == ["other"]


def test_incomplete_gate_detects_failed_scanner():
    result = evaluate_quality_gate(
        [],
        [{"name": "test", "succeeded": False}],
        ["test"],
        fail_on_incomplete=True,
    )
    assert result["exit_code"] == 3
    assert result["failed_modules"] == ["test"]


def test_incomplete_gate_takes_priority_over_severity_gate():
    result = evaluate_quality_gate(
        [finding("CRITICAL")],
        [{"name": "test", "succeeded": False}],
        ["test"],
        fail_on_severity="HIGH",
        fail_on_incomplete=True,
    )
    assert result["exit_code"] == 3


def test_gate_is_added_to_report_without_leaking_internal_metadata():
    gate = evaluate_quality_gate(
        [finding("HIGH")],
        [{"name": "test", "succeeded": True}],
        ["test"],
        fail_on_severity="HIGH",
    )
    report = build_report(
        {"hostname": "test-host", "_quality_gate": gate},
        [finding("HIGH")],
        ["test"],
    )
    assert report["quality_gate"]["exit_code"] == 1
    assert "_quality_gate" not in report["system_info"]
    assert validate_report(report) == []
