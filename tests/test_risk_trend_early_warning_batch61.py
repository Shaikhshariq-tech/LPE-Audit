import json

import pytest

from reporting.risk_trend_early_warning import (
    RiskTrendWarningError,
    analyze_files,
    analyze_risk_trend,
    render_markdown,
)


def report(findings):
    return {"findings": findings}


def finding(title="Finding A", score=20, severity="LOW", path="/tmp/a"):
    return {
        "title": title,
        "category": "permissions",
        "affected_path": path,
        "scanner": "test-scanner",
        "risk_score": score,
        "severity": severity,
    }


def test_detects_score_increase_warning():
    result = analyze_risk_trend(
        [report([finding(score=20)]), report([finding(score=30)])],
        ["old", "new"],
        warning_threshold=5,
    )
    assert result["status"] == "WARNING"
    assert result["warning_event_count"] == 1
    assert result["warning_events"][0]["risk_delta"] == 10


def test_detects_severity_increase():
    result = analyze_risk_trend(
        [report([finding(score=30, severity="LOW")]),
         report([finding(score=30, severity="HIGH")])],
        warning_threshold=5,
    )
    assert "SEVERITY_INCREASE" in result["warning_events"][0]["warning_reasons"]


def test_detects_new_high_risk_state():
    result = analyze_risk_trend(
        [report([finding(score=20)]), report([finding(score=75)])],
        warning_threshold=10,
    )
    assert "NEW_HIGH_RISK_STATE" in result["warning_events"][0]["warning_reasons"]


def test_no_warning_below_threshold():
    result = analyze_risk_trend(
        [report([finding(score=20)]), report([finding(score=22)])],
        warning_threshold=5,
    )
    assert result["status"] == "NO_THRESHOLD_WARNINGS"


def test_tracks_new_and_resolved_findings():
    result = analyze_risk_trend(
        [report([finding("Old")]), report([finding("New")])],
        ["one", "two"],
    )
    transition = result["transitions"][0]
    assert transition["new_findings"] == 1
    assert transition["resolved_findings"] == 1
    assert transition["persistent_findings"] == 0


def test_three_snapshots_produce_two_transitions():
    result = analyze_risk_trend(
        [report([finding(score=10)]), report([finding(score=20)]),
         report([finding(score=25)])],
        ["one", "two", "three"],
    )
    assert len(result["transitions"]) == 2


def test_requires_at_least_two_snapshots():
    with pytest.raises(RiskTrendWarningError):
        analyze_risk_trend([report([])])


def test_rejects_label_count_mismatch():
    with pytest.raises(RiskTrendWarningError):
        analyze_risk_trend([report([]), report([])], ["only-one"])


def test_rejects_duplicate_stable_identity():
    with pytest.raises(RiskTrendWarningError):
        analyze_risk_trend(
            [report([finding(), finding()]), report([finding()])]
        )


def test_rejects_invalid_threshold():
    with pytest.raises(RiskTrendWarningError):
        analyze_risk_trend([report([]), report([])], warning_threshold=101)


def test_read_only_and_no_auto_remediation():
    result = analyze_risk_trend([report([]), report([])])
    assert result["read_only"] is True
    assert result["automatic_remediation"] is False
    assert result["human_review_required"] is True


def test_markdown_rendering():
    result = analyze_risk_trend(
        [report([finding(score=10)]), report([finding(score=20)])],
        ["old", "new"],
    )
    rendered = render_markdown(result)
    assert "# Historical Risk Trend Early-Warning Report" in rendered
    assert "Warning events" in rendered


def test_file_outputs_and_source_preservation(tmp_path):
    source_a = tmp_path / "a.json"
    source_b = tmp_path / "b.json"
    source_a.write_text(json.dumps(report([finding(score=10)])))
    source_b.write_text(json.dumps(report([finding(score=25)])))
    original_a = source_a.read_text()
    original_b = source_b.read_text()
    json_out = tmp_path / "out" / "trend.json"
    md_out = tmp_path / "out" / "trend.md"

    result = analyze_files(
        [str(source_a), str(source_b)],
        ["a", "b"],
        5,
        str(json_out),
        str(md_out),
    )
    assert result["warning_event_count"] == 1
    assert json.loads(json_out.read_text())["read_only"] is True
    assert md_out.stat().st_size > 0
    assert source_a.read_text() == original_a
    assert source_b.read_text() == original_b


def test_refuses_to_overwrite_sources(tmp_path):
    source_a = tmp_path / "a.json"
    source_b = tmp_path / "b.json"
    source_a.write_text(json.dumps(report([])))
    source_b.write_text(json.dumps(report([])))
    with pytest.raises(RiskTrendWarningError):
        analyze_files(
            [str(source_a), str(source_b)], None, 5,
            str(source_a), str(tmp_path / "out.md"),
        )


def test_refuses_existing_output(tmp_path):
    source_a = tmp_path / "a.json"
    source_b = tmp_path / "b.json"
    source_a.write_text(json.dumps(report([])))
    source_b.write_text(json.dumps(report([])))
    output = tmp_path / "existing.json"
    output.write_text("preserve me")
    with pytest.raises(RiskTrendWarningError, match="overwrite"):
        analyze_files(
            [str(source_a), str(source_b)], None, 5,
            str(output), str(tmp_path / "out.md"),
        )
    assert output.read_text() == "preserve me"


def test_rejects_invalid_score():
    with pytest.raises(RiskTrendWarningError):
        analyze_risk_trend(
            [report([finding(score=10)]), report([finding(score=101)])]
        )


def test_severity_counts_and_snapshot_metrics():
    result = analyze_risk_trend(
        [report([finding(score=80, severity="HIGH")]),
         report([finding(score=80, severity="HIGH")])]
    )
    assert result["snapshots"][0]["high_risk_findings"] == 1
    assert result["snapshots"][0]["severity_counts"]["HIGH"] == 1


def test_cli_help_smoke():
    import subprocess
    import sys

    completed = subprocess.run(
        [sys.executable, "-m", "reporting.risk_trend_early_warning", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert "--warning-threshold" in completed.stdout
