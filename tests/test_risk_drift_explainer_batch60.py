import copy
import json
from pathlib import Path

import pytest

from reporting.risk_drift_explainer import (
    _load_report,
    RiskDriftError,
    analyze_files,
    explain_risk_drift,
    render_markdown,
)


def finding(title="Example", score=20, severity="LOW", path="/tmp/example"):
    return {
        "category": "permissions",
        "title": title,
        "affected_path": path,
        "scanner": "test-scanner",
        "risk_score": score,
        "severity": severity,
    }


def report(*findings):
    return {"findings": list(findings)}


def test_reports_score_increase_and_explanation():
    result = explain_risk_drift(report(finding(score=20)), report(finding(score=25)))
    row = result["drift"][0]
    assert row["risk_delta"] == 5
    assert row["direction"] == "INCREASED"
    assert row["threshold_exceeded"] is True
    assert "review source evidence" in row["explanation"]


def test_reports_score_decrease():
    result = explain_risk_drift(report(finding(score=30)), report(finding(score=20)))
    assert result["drift"][0]["direction"] == "DECREASED"
    assert result["summary"]["score_decreases"] == 1


def test_reports_severity_change_without_score_change():
    result = explain_risk_drift(
        report(finding(score=20, severity="LOW")),
        report(finding(score=20, severity="MEDIUM")),
    )
    assert result["summary"]["severity_changes"] == 1
    assert result["human_review_required"] is True


def test_new_and_resolved_findings():
    result = explain_risk_drift(
        report(finding(title="Old")),
        report(finding(title="New")),
    )
    assert result["summary"]["new_findings"] == 1
    assert result["summary"]["resolved_findings"] == 1
    assert result["summary"]["persistent_findings"] == 0


def test_unchanged_findings_do_not_require_review():
    result = explain_risk_drift(report(finding()), report(finding()))
    assert result["status"] == "NO_PERSISTENT_FINDING_DRIFT"
    assert result["human_review_required"] is False


@pytest.mark.parametrize("score", [-1, 101, True, float("nan"), float("inf"), "bad"])
def test_rejects_invalid_risk_scores(score):
    with pytest.raises(RiskDriftError):
        explain_risk_drift(report(finding(score=score)), report(finding()))


def test_rejects_duplicate_identity():
    with pytest.raises(RiskDriftError, match="duplicate"):
        explain_risk_drift(
            report(finding(), finding()),
            report(finding()),
        )


def test_rejects_invalid_threshold():
    with pytest.raises(RiskDriftError):
        explain_risk_drift(report(finding()), report(finding()), threshold=-1)


def test_does_not_mutate_inputs():
    baseline, current = report(finding(score=10)), report(finding(score=20))
    before = copy.deepcopy((baseline, current))
    explain_risk_drift(baseline, current)
    assert (baseline, current) == before


def test_output_is_read_only_and_markdown_renders():
    result = explain_risk_drift(report(finding(score=10)), report(finding(score=12)))
    assert result["read_only"] is True
    assert result["automatic_remediation"] is False
    assert "Historical Risk Drift Explanation" in render_markdown(result)


def test_file_workflow_writes_json_and_markdown(tmp_path):
    baseline, current = tmp_path / "base.json", tmp_path / "current.json"
    output_json, output_md = tmp_path / "out.json", tmp_path / "out.md"
    baseline.write_text(json.dumps(report(finding(score=10))), encoding="utf-8")
    current.write_text(json.dumps(report(finding(score=13))), encoding="utf-8")
    before = (baseline.read_bytes(), current.read_bytes())
    result = analyze_files(baseline, current, output_json, output_md)
    assert json.loads(output_json.read_text())["summary"]["score_increases"] == 1
    assert output_md.stat().st_size > 0
    assert (baseline.read_bytes(), current.read_bytes()) == before
    assert result["read_only"] is True


def test_refuses_to_overwrite_existing_output(tmp_path):
    baseline, current = tmp_path / "base.json", tmp_path / "current.json"
    output_json, output_md = tmp_path / "out.json", tmp_path / "out.md"
    baseline.write_text(json.dumps(report(finding())), encoding="utf-8")
    current.write_text(json.dumps(report(finding(score=21))), encoding="utf-8")
    output_json.write_text("keep", encoding="utf-8")
    with pytest.raises(RiskDriftError, match="overwrite"):
        analyze_files(baseline, current, output_json, output_md)
    assert output_json.read_text() == "keep"


def test_refuses_source_overwrite(tmp_path):
    baseline, current = tmp_path / "base.json", tmp_path / "current.json"
    output_md = tmp_path / "out.md"
    baseline.write_text(json.dumps(report(finding())), encoding="utf-8")
    current.write_text(json.dumps(report(finding(score=21))), encoding="utf-8")
    with pytest.raises(RiskDriftError, match="overwrite source"):
        analyze_files(baseline, current, baseline, output_md)


def test_threshold_boundary():
    result = explain_risk_drift(
        report(finding(score=10)), report(finding(score=11)), threshold=1
    )
    assert result["drift"][0]["threshold_exceeded"] is True


def test_empty_reports():
    result = explain_risk_drift(report(), report())
    assert result["summary"]["persistent_findings"] == 0
    assert result["status"] == "NO_PERSISTENT_FINDING_DRIFT"


def test_report_read_error_does_not_disclose_exception_message(
    tmp_path, monkeypatch
):
    source = tmp_path / "report.json"
    source.write_text("{}", encoding="utf-8")

    def fail_read(*args, **kwargs):
        raise OSError("SECRET_EXCEPTION_SENTINEL")

    monkeypatch.setattr(Path, "read_text", fail_read)

    with pytest.raises(RiskDriftError) as caught:
        _load_report(source)

    assert "SECRET_EXCEPTION_SENTINEL" not in str(caught.value)
    assert "OSError" in str(caught.value)
