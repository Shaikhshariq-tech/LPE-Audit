import json

import pytest

from reporting.risk_analyzer_consistency import (
    AnalyzerConsistencyError,
    validate_analyzer_consistency,
    validate_files,
)


def finding(title="Finding A", score=20, severity="LOW"):
    return {
        "title": title,
        "category": "config",
        "affected_path": "/etc/example",
        "scanner": "scanner-a",
        "risk_score": score,
        "severity": severity,
    }


def report(*items):
    return {"findings": list(items)}


def correlation(before, after, labels=("base", "current")):
    observations = []
    for label, items in zip(labels, (before["findings"], after["findings"])):
        observations.extend({
            "snapshot": label,
            "risk_score": item["risk_score"],
            "severity": item["severity"],
        } for item in items)
    identity = {
        "category": "config",
        "title": "Finding A",
        "affected_path": "/etc/example",
        "scanner": "scanner-a",
    }
    return {
        "snapshot_labels": list(labels),
        "correlations": [{
            "identity": identity,
            "observations": observations,
        }],
        "summary": {"single_snapshot_only": 0},
    }


def test_consistent_artifacts_pass():
    base, current = report(finding(score=20)), report(finding(score=30))
    result = validate_analyzer_consistency(
        base, current, correlation(base, current), "base", "current"
    )
    assert result["status"] == "PASS"
    assert result["summary"]["issue_count"] == 0
    assert result["read_only"] is True
    assert result["automatic_remediation"] is False


def test_detects_score_mismatch():
    base, current = report(finding(score=20)), report(finding(score=30))
    corr = correlation(base, current)
    corr["correlations"][0]["observations"][0]["risk_score"] = 44
    result = validate_analyzer_consistency(base, current, corr, "base", "current")
    assert result["status"] == "REVIEW_REQUIRED"
    assert result["details"]["score_mismatches"]


def test_detects_severity_mismatch():
    base, current = report(finding()), report(finding(score=30))
    corr = correlation(base, current)
    corr["correlations"][0]["observations"][1]["severity"] = "CRITICAL"
    result = validate_analyzer_consistency(base, current, corr, "base", "current")
    assert result["details"]["severity_mismatches"]


def test_detects_wrong_snapshot_labels():
    base, current = report(finding()), report(finding(score=25))
    result = validate_analyzer_consistency(
        base, current, correlation(base, current), "old", "new"
    )
    assert result["status"] == "REVIEW_REQUIRED"


def test_detects_missing_correlation_identity():
    base, current = report(finding()), report(finding(score=25))
    corr = correlation(base, current)
    corr["correlations"] = []
    result = validate_analyzer_consistency(base, current, corr, "base", "current")
    assert result["status"] == "REVIEW_REQUIRED"


def test_detects_duplicate_finding_identity():
    with pytest.raises(AnalyzerConsistencyError, match="duplicate"):
        validate_analyzer_consistency(
            report(finding(), finding()), report(finding()), {"correlations": []}
        )


@pytest.mark.parametrize("score", [-1, 101, True, float("nan"), "20"])
def test_rejects_invalid_score(score):
    with pytest.raises(AnalyzerConsistencyError, match="risk score"):
        validate_analyzer_consistency(
            report(finding(score=score)), report(finding()), {"correlations": []}
        )


@pytest.mark.parametrize("tolerance", [-1, float("nan"), True, "1"])
def test_rejects_invalid_tolerance(tolerance):
    with pytest.raises(AnalyzerConsistencyError, match="Tolerance"):
        validate_analyzer_consistency(
            report(), report(), {"correlations": []}, tolerance=tolerance
        )


def test_file_outputs_are_created_and_sources_preserved(tmp_path):
    base = tmp_path / "base.json"
    current = tmp_path / "current.json"
    corr = tmp_path / "corr.json"
    base.write_text(json.dumps(report(finding(score=20))))
    current.write_text(json.dumps(report(finding(score=20))))
    corr.write_text(json.dumps(correlation(
        report(finding(score=20)), report(finding(score=20))
    )))
    original = base.read_bytes()
    result = validate_files(
        base, current, corr, "base", "current", 0.01,
        tmp_path / "out" / "result.json", tmp_path / "out" / "result.md",
    )
    assert result["status"] == "PASS"
    assert base.read_bytes() == original


def test_refuses_to_overwrite_source(tmp_path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(report()))
    with pytest.raises(AnalyzerConsistencyError, match="source"):
        validate_files(
            source, source, source, "base", "current", 0.01,
            source, tmp_path / "out.md",
        )


def test_refuses_existing_output(tmp_path):
    base, current, corr = (tmp_path / name for name in ("base.json", "cur.json", "corr.json"))
    base.write_text(json.dumps(report(finding())))
    current.write_text(json.dumps(report(finding())))
    corr.write_text(json.dumps(correlation(report(finding()), report(finding()))))
    output = tmp_path / "out.json"
    output.write_text("preserve")
    with pytest.raises(AnalyzerConsistencyError, match="already exists"):
        validate_files(
            base, current, corr, "base", "current", 0.01,
            output, tmp_path / "out.md",
        )
    assert output.read_text() == "preserve"
