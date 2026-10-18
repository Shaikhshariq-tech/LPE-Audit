import json

import pytest

from reporting.risk_correlation_analyzer import (
    RiskCorrelationError,
    analyze_files,
    analyze_risk_correlations,
    render_markdown,
)


def finding(title="Example", score=20, severity="LOW", **extra):
    return {
        "title": title,
        "category": "configuration",
        "affected_path": "/tmp/example",
        "scanner": "test-scanner",
        "risk_score": score,
        "severity": severity,
        **extra,
    }


def report(*findings):
    return {"findings": list(findings)}


def test_detects_increasing_score_across_three_snapshots():
    result = analyze_risk_correlations(
        [report(finding(score=10)), report(finding(score=18)), report(finding(score=25))],
        ["a", "b", "c"],
        5,
    )
    item = result["correlations"][0]
    assert item["relationship"] == "consistently_increasing"
    assert item["risk_score_deltas"] == [8.0, 7.0]
    assert len(item["threshold_events"]) == 2


def test_detects_severity_change():
    result = analyze_risk_correlations(
        [report(finding(score=20, severity="LOW")),
         report(finding(score=20, severity="MEDIUM"))]
    )
    assert result["summary"]["severity_changes"] == 1
    assert result["status"] == "REVIEW_REQUIRED"


def test_stable_finding():
    result = analyze_risk_correlations([report(finding()), report(finding())])
    assert result["correlations"][0]["relationship"] == "stable"
    assert result["summary"]["threshold_events"] == 0


def test_new_identity_in_second_snapshot():
    result = analyze_risk_correlations(
        [report(), report(finding())], ["old", "new"]
    )
    assert result["summary"]["single_snapshot_only"] == 1


def test_duplicate_identity_rejected():
    with pytest.raises(RiskCorrelationError, match="duplicate"):
        analyze_risk_correlations(
            [report(finding(), finding()), report()]
        )


@pytest.mark.parametrize("score", [-1, 101, True, float("nan"), float("inf"), "20"])
def test_invalid_score_rejected(score):
    with pytest.raises(RiskCorrelationError):
        analyze_risk_correlations([report(finding(score=score)), report()])


@pytest.mark.parametrize("threshold", [-1, float("nan"), True, "5"])
def test_invalid_threshold_rejected(threshold):
    with pytest.raises(RiskCorrelationError):
        analyze_risk_correlations(
            [report(), report()], score_delta_threshold=threshold
        )


def test_invalid_report_list_rejected():
    with pytest.raises(RiskCorrelationError):
        analyze_risk_correlations([report()])


def test_labels_must_match_reports():
    with pytest.raises(RiskCorrelationError):
        analyze_risk_correlations([report(), report()], ["only-one"])


def test_fluctuating_pattern():
    result = analyze_risk_correlations(
        [report(finding(score=10)), report(finding(score=30)),
         report(finding(score=15))]
    )
    assert result["correlations"][0]["relationship"] == "fluctuating"


def test_markdown_contains_safety_notes():
    result = analyze_risk_correlations([report(finding()), report(finding())])
    rendered = render_markdown(result)
    assert "Automatic remediation:** No" in rendered
    assert "do not establish root cause" in rendered


def test_file_outputs_and_source_preservation(tmp_path):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text(json.dumps(report(finding(score=10))), encoding="utf-8")
    second.write_text(json.dumps(report(finding(score=20))), encoding="utf-8")
    original = first.read_bytes()
    output_json = tmp_path / "out" / "result.json"
    output_md = tmp_path / "out" / "result.md"
    result = analyze_files(
        [first, second], ["first", "second"], 5, output_json, output_md
    )
    assert result["read_only"] is True
    assert result["automatic_remediation"] is False
    assert json.loads(output_json.read_text())["summary"]["threshold_events"] == 1
    assert output_md.stat().st_size > 0
    assert first.read_bytes() == original


def test_refuses_to_overwrite_source(tmp_path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(report()), encoding="utf-8")
    with pytest.raises(RiskCorrelationError, match="source"):
        analyze_files([source, source], None, 5, source, tmp_path / "out.md")


def test_refuses_existing_outputs(tmp_path):
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    first.write_text(json.dumps(report()), encoding="utf-8")
    second.write_text(json.dumps(report()), encoding="utf-8")
    out_json, out_md = tmp_path / "out.json", tmp_path / "out.md"
    out_json.write_text("keep")
    with pytest.raises(RiskCorrelationError, match="already exists"):
        analyze_files([first, second], None, 5, out_json, out_md)
    assert out_json.read_text() == "keep"
