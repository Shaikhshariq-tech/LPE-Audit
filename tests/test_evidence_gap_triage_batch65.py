import json

import pytest

from reporting.evidence_gap_triage import (
    EvidenceGapTriageError,
    audit_evidence_gaps,
    audit_file,
    render_markdown,
)


def test_failed_evidence_check_is_triaged():
    source = {
        "status": "REVIEW_REQUIRED",
        "checks": [
            {"name": "evidence_metadata", "status": "FAIL",
             "message": "Evidence metadata gaps detected"}
        ],
    }
    report = audit_evidence_gaps(source)
    assert report["status"] == "REVIEW_REQUIRED"
    assert report["summary"]["triaged_gap_count"] >= 1
    assert report["safety"]["read_only"] is True
    assert all(item["automatic_remediation"] is False for item in report["gaps"])


def test_clean_report_has_no_gaps():
    report = audit_evidence_gaps({"status": "PASS", "checks": [
        {"name": "evidence_integrity", "status": "PASS"}
    ]})
    assert report["status"] == "NO_GAPS_DETECTED"
    assert report["summary"]["triaged_gap_count"] == 0


def test_rejects_scalar_root():
    with pytest.raises(EvidenceGapTriageError):
        audit_evidence_gaps("not an object")


def test_markdown_is_human_review_oriented():
    report = audit_evidence_gaps({"issues": ["missing evidence metadata"]})
    markdown = render_markdown(report)
    assert "# Historical Evidence Gap Triage" in markdown
    assert "Automatic remediation:** No" in markdown
    assert "human review" in markdown.lower()


def test_file_outputs_and_json_round_trip(tmp_path):
    source = tmp_path / "source.json"
    json_out = tmp_path / "out.json"
    md_out = tmp_path / "out.md"
    source.write_text(json.dumps({"status": "REVIEW_REQUIRED",
                                  "issues": [{"message": "missing evidence metadata"}]}))
    report = audit_file(source, json_out, md_out)
    assert json.loads(json_out.read_text()) == report
    assert "Historical Evidence Gap Triage" in md_out.read_text()


def test_refuses_source_overwrite(tmp_path):
    source = tmp_path / "source.json"
    other = tmp_path / "other.md"
    source.write_text('{"status":"PASS"}')
    with pytest.raises(EvidenceGapTriageError, match="source input"):
        audit_file(source, source, other)


def test_refuses_existing_output(tmp_path):
    source = tmp_path / "source.json"
    out = tmp_path / "out.json"
    md = tmp_path / "out.md"
    source.write_text('{"status":"PASS"}')
    out.write_text("{}")
    with pytest.raises(EvidenceGapTriageError, match="existing output"):
        audit_file(source, out, md)


def test_refuses_same_output_path(tmp_path):
    source = tmp_path / "source.json"
    source.write_text('{"status":"PASS"}')
    with pytest.raises(EvidenceGapTriageError, match="different paths"):
        audit_file(source, tmp_path / "out", tmp_path / "out")


def test_invalid_json_is_reported(tmp_path):
    source = tmp_path / "source.json"
    source.write_text("{")
    with pytest.raises(EvidenceGapTriageError, match="valid JSON"):
        audit_file(source, tmp_path / "out.json", tmp_path / "out.md")


def test_severity_and_action_are_advisory():
    report = audit_evidence_gaps({
        "checks": [{"name": "risk_score_mismatch", "status": "FAIL",
                    "message": "Risk score mismatch detected"}]
    })
    assert report["gaps"]
    assert report["gaps"][0]["severity"] in {"HIGH", "MEDIUM", "LOW"}
    assert report["gaps"][0]["recommended_manual_action"]
    assert report["safety"]["system_changes_performed"] is False
