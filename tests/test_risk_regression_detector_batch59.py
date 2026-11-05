import json
from pathlib import Path

import pytest

from reporting.risk_regression_detector import (
    _load_report,
    RiskRegressionError,
    analyze_files,
    analyze_risk_regressions,
    render_markdown,
)


def finding(title="Example", score=20, severity="LOW", path="/tmp/example", scanner="test"):
    return {
        "category": "permissions",
        "title": title,
        "affected_path": path,
        "scanner": scanner,
        "severity": severity,
        "risk_score": score,
    }


def report(*findings):
    return {"findings": list(findings)}


def test_risk_increase_is_detected():
    result = analyze_risk_regressions(
        report(finding(score=20)), report(finding(score=35))
    )
    assert result["status"] == "REGRESSION_DETECTED"
    assert result["summary"]["risk_score_increases"] == 1
    assert result["regressions"][0]["risk_delta"] == 15


def test_severity_increase_is_detected_even_without_score_increase():
    result = analyze_risk_regressions(
        report(finding(score=50, severity="MEDIUM")),
        report(finding(score=50, severity="HIGH")),
    )
    assert result["summary"]["severity_increases"] == 1
    assert any(x["regression_type"] == "SEVERITY_INCREASE" for x in result["regressions"])


def test_new_high_severity_finding_is_flagged():
    result = analyze_risk_regressions(
        report(), report(finding(title="New issue", severity="HIGH", score=60))
    )
    assert result["summary"]["new_findings"] == 1
    assert result["summary"]["high_risk_new_findings"] == 1


def test_new_finding_with_high_risk_score_is_flagged():
    result = analyze_risk_regressions(
        report(), report(finding(title="Risky new issue", severity="LOW", score=80))
    )
    assert result["summary"]["regression_count"] == 1


def test_stable_report_has_no_regression():
    item = finding(score=25)
    result = analyze_risk_regressions(report(item), report(dict(item)))
    assert result["status"] == "NO_REGRESSION_DETECTED"
    assert result["summary"]["regression_count"] == 0


def test_resolved_finding_is_counted():
    result = analyze_risk_regressions(report(finding()), report())
    assert result["summary"]["resolved_findings"] == 1


def test_severity_decrease_is_counted_not_flagged_as_regression():
    result = analyze_risk_regressions(
        report(finding(score=50, severity="HIGH")),
        report(finding(score=50, severity="LOW")),
    )
    assert result["summary"]["severity_decreases"] == 1
    assert result["summary"]["regression_count"] == 0


def test_threshold_filters_small_risk_increases():
    result = analyze_risk_regressions(
        report(finding(score=20)), report(finding(score=21)),
        risk_increase_threshold=5,
    )
    assert result["summary"]["risk_score_increases"] == 0


def test_rejects_invalid_score():
    with pytest.raises(RiskRegressionError, match="between 0 and 100"):
        analyze_risk_regressions(
            report(finding(score=20)), report(finding(score=101))
        )


def test_rejects_duplicate_identity():
    item = finding()
    with pytest.raises(RiskRegressionError, match="duplicate finding identity"):
        analyze_risk_regressions(report(item, dict(item)), report())


def test_rejects_invalid_threshold():
    with pytest.raises(RiskRegressionError, match="threshold"):
        analyze_risk_regressions(report(), report(), risk_increase_threshold=-1)


def test_read_only_flags_and_markdown():
    result = analyze_risk_regressions(report(), report())
    assert result["read_only"] is True
    assert result["automatic_remediation"] is False
    assert "Historical Risk Regression Report" in render_markdown(result)


def test_file_outputs_and_source_preservation(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    out_json = tmp_path / "out" / "result.json"
    out_md = tmp_path / "out" / "result.md"
    baseline.write_text(json.dumps(report(finding(score=20))), encoding="utf-8")
    current.write_text(json.dumps(report(finding(score=40))), encoding="utf-8")
    original_baseline = baseline.read_bytes()
    original_current = current.read_bytes()

    result = analyze_files(baseline, current, out_json, out_md)
    assert result["summary"]["risk_score_increases"] == 1
    assert json.loads(out_json.read_text(encoding="utf-8"))["read_only"] is True
    assert out_md.stat().st_size > 0
    assert baseline.read_bytes() == original_baseline
    assert current.read_bytes() == original_current


def test_refuses_existing_output(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    baseline.write_text(json.dumps(report()), encoding="utf-8")
    current.write_text(json.dumps(report()), encoding="utf-8")
    output = tmp_path / "existing.json"
    output.write_text("keep", encoding="utf-8")
    with pytest.raises(RiskRegressionError, match="already exists"):
        analyze_files(baseline, current, output, tmp_path / "out.md")
    assert output.read_text(encoding="utf-8") == "keep"


def test_rejects_malformed_json(tmp_path):
    baseline = tmp_path / "bad.json"
    current = tmp_path / "current.json"
    baseline.write_text("{bad json", encoding="utf-8")
    current.write_text(json.dumps(report()), encoding="utf-8")
    with pytest.raises(RiskRegressionError, match="Invalid JSON"):
        analyze_files(baseline, current, tmp_path / "out.json", tmp_path / "out.md")


def test_rejects_source_overwrite(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    baseline.write_text(json.dumps(report()), encoding="utf-8")
    current.write_text(json.dumps(report()), encoding="utf-8")
    with pytest.raises(RiskRegressionError, match="must not overwrite"):
        analyze_files(baseline, current, baseline, tmp_path / "out.md")


def test_report_read_error_does_not_disclose_exception_message(
    tmp_path, monkeypatch
):
    source = tmp_path / "report.json"
    source.write_text("{}", encoding="utf-8")

    def fail_read(*args, **kwargs):
        raise OSError("SECRET_EXCEPTION_SENTINEL")

    monkeypatch.setattr(Path, "read_text", fail_read)

    with pytest.raises(RiskRegressionError) as caught:
        _load_report(source)

    assert "SECRET_EXCEPTION_SENTINEL" not in str(caught.value)
    assert "OSError" in str(caught.value)
