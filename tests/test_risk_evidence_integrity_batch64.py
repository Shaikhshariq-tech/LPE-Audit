import json

import pytest

from reporting.risk_evidence_integrity import (
    RiskEvidenceIntegrityError,
    audit_evidence_integrity,
    audit_files,
)


def finding(title="Example", score=20, severity="LOW"):
    return {
        "title": title,
        "category": "config",
        "affected_path": "/etc/example",
        "scanner": "scanner-a",
        "risk_score": score,
        "severity": severity,
        "evidence": "Observed configuration evidence",
        "detection_reason": "Scanner matched a configured audit rule",
    }


def report(*items):
    return {"findings": list(items)}


def correlation(reports, labels):
    by_identity = {}
    for label, source in zip(labels, reports):
        for item in source["findings"]:
            key = tuple(item[field] for field in (
                "category", "title", "affected_path", "scanner"
            ))
            by_identity.setdefault(key, []).append({
                "snapshot": label,
                "risk_score": item["risk_score"],
                "severity": item["severity"],
            })
    return {
        "snapshot_labels": labels,
        "correlations": [
            {
                "identity": dict(zip(
                    ("category", "title", "affected_path", "scanner"), key
                )),
                "observations": observations,
            }
            for key, observations in by_identity.items()
        ],
    }


def test_valid_artifacts_pass():
    reports = [report(finding(score=20)), report(finding(score=25))]
    result = audit_evidence_integrity(reports, ["base", "current"], correlation(
        reports, ["base", "current"]
    ))
    assert result["status"] == "PASS"
    assert result["summary"]["issue_count"] == 0


def test_detects_missing_correlation_identity():
    reports = [report(finding()), report(finding(score=25))]
    corr = correlation(reports, ["base", "current"])
    corr["correlations"] = []
    result = audit_evidence_integrity(reports, ["base", "current"], corr)
    assert result["status"] == "REVIEW_REQUIRED"


def test_detects_score_mismatch():
    reports = [report(finding()), report(finding(score=25))]
    corr = correlation(reports, ["base", "current"])
    corr["correlations"][0]["observations"][0]["risk_score"] = 99
    result = audit_evidence_integrity(reports, ["base", "current"], corr)
    assert result["summary"]["score_mismatches"] == 1


def test_detects_missing_observation():
    reports = [report(finding()), report(finding(score=25))]
    corr = correlation(reports, ["base", "current"])
    corr["correlations"][0]["observations"].pop()
    result = audit_evidence_integrity(reports, ["base", "current"], corr)
    assert result["summary"]["missing_observations"] == 1


def test_detects_missing_evidence_fields():
    item = finding()
    del item["evidence"]
    result = audit_evidence_integrity(
        [report(item)], ["one"], correlation([report(item)], ["one"])
    )
    assert result["summary"]["evidence_metadata_gaps"] == 1


def test_detects_wrong_snapshot_labels():
    reports = [report(finding()), report(finding(score=25))]
    result = audit_evidence_integrity(
        reports, ["base", "current"], correlation(reports, ["wrong", "current"])
    )
    assert result["status"] == "REVIEW_REQUIRED"


def test_rejects_duplicate_identity():
    with pytest.raises(RiskEvidenceIntegrityError, match="duplicate"):
        audit_evidence_integrity(
            [report(finding(), finding())], ["one"], {"correlations": []}
        )


@pytest.mark.parametrize("score", [-1, 101, True, float("nan"), "20"])
def test_rejects_invalid_scores(score):
    with pytest.raises(RiskEvidenceIntegrityError, match="score"):
        audit_evidence_integrity(
            [report(finding(score=score))], ["one"], {"correlations": []}
        )


def test_labels_must_be_unique():
    with pytest.raises(RiskEvidenceIntegrityError, match="Labels"):
        audit_evidence_integrity([report(), report()], ["same", "same"], {"correlations": []})


def test_source_preservation_and_outputs(tmp_path):
    reports = [report(finding()), report(finding(score=25))]
    labels = ["base", "current"]
    base, current, corr = tmp_path / "base.json", tmp_path / "current.json", tmp_path / "corr.json"
    base.write_text(json.dumps(reports[0]))
    current.write_text(json.dumps(reports[1]))
    corr.write_text(json.dumps(correlation(reports, labels)))
    original = base.read_bytes()
    result = audit_files(
        [str(base), str(current)], labels, str(corr),
        str(tmp_path / "out.json"), str(tmp_path / "out.md")
    )
    assert result["read_only"] is True
    assert result["automatic_remediation"] is False
    assert base.read_bytes() == original
    assert json.loads((tmp_path / "out.json").read_text())["status"] == "PASS"
    assert (tmp_path / "out.md").stat().st_size > 0


def test_refuses_to_overwrite_source(tmp_path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(report()))
    with pytest.raises(RiskEvidenceIntegrityError, match="source"):
        audit_files(
            [str(source)], ["one"], str(source),
            str(source), str(tmp_path / "out.md")
        )


def test_refuses_existing_output(tmp_path):
    reports = [report(finding()), report(finding(score=25))]
    labels = ["base", "current"]
    base, current, corr = tmp_path / "base.json", tmp_path / "current.json", tmp_path / "corr.json"
    base.write_text(json.dumps(reports[0]))
    current.write_text(json.dumps(reports[1]))
    corr.write_text(json.dumps(correlation(reports, labels)))
    output = tmp_path / "out.json"
    output.write_text("preserve")
    with pytest.raises(RiskEvidenceIntegrityError, match="already exists"):
        audit_files(
            [str(base), str(current)], labels, str(corr),
            str(output), str(tmp_path / "out.md")
        )
    assert output.read_text() == "preserve"
