import json

import pytest

from reporting.evidence_coverage_matrix import (
    EvidenceCoverageError,
    audit_files,
    build_coverage_matrix,
    render_markdown,
)


def triage(gaps=None):
    return {
        "report_type": "historical_evidence_gap_triage",
        "source": "sample-triage.json",
        "gaps": gaps or [],
    }


def gap(gap_id="EG-001", category="evidence_metadata",
        description="Missing evidence metadata", severity="MEDIUM"):
    return {
        "gap_id": gap_id,
        "source_path": "$.checks[0]",
        "category": category,
        "description": description,
        "severity": severity,
        "recommended_manual_action": "Review evidence metadata",
        "automatic_remediation": False,
    }


def test_classifies_evidence_metadata_gap():
    report = build_coverage_matrix(
        triage([gap()]), {"status": "REVIEW_REQUIRED", "checks": []}
    )
    assert report["classified_gaps"][0]["classification"] == "EVIDENCE_METADATA"
    assert report["summary"]["medium"] == 1


def test_classifies_snapshot_traceability():
    report = build_coverage_matrix(
        triage([gap(category="snapshot_label", description="Snapshot label mismatch")]),
        {"status": "REVIEW_REQUIRED"},
    )
    assert report["classified_gaps"][0]["classification"] == "SNAPSHOT_TRACEABILITY"


def test_classifies_risk_score_integrity():
    report = build_coverage_matrix(
        triage([gap(category="risk_score", description="Risk score mismatch")]),
        {},
    )
    assert report["classified_gaps"][0]["classification"] == "RISK_SCORE_INTEGRITY"


def test_classifies_finding_identity():
    report = build_coverage_matrix(
        triage([gap(category="finding_identity", description="Duplicate finding identity")]),
        {},
    )
    assert report["classified_gaps"][0]["classification"] == "FINDING_IDENTITY"


def test_classifies_report_consistency():
    report = build_coverage_matrix(
        triage([gap(category="cross-report consistency", description="Correlation consistency issue")]),
        {},
    )
    assert report["classified_gaps"][0]["classification"] == "REPORT_CONSISTENCY"


def test_unknown_severity_is_not_silently_low():
    report = build_coverage_matrix(
        triage([gap(severity="URGENT")]), {}
    )
    assert report["summary"]["unknown_severity"] == 1
    assert report["summary"]["low"] == 0


def test_matrix_counts_match_gap_count():
    report = build_coverage_matrix(triage([gap(), gap("EG-002", "risk_score", "Risk score mismatch")]), {})
    assert sum(row["triaged_gap_count"] for row in report["coverage_matrix"]) == 2
    assert report["summary"]["classified_gap_count"] == 2


def test_clean_triage_does_not_claim_certified_completeness():
    report = build_coverage_matrix(triage(), {"status": "PASS"})
    assert report["status"] == "NO_GAPS_REPORTED"
    assert any("not proof of complete evidence" in item for item in report["limitations"])


def test_rejects_wrong_triage_report_type():
    with pytest.raises(EvidenceCoverageError, match="not a supported"):
        build_coverage_matrix({"report_type": "other", "gaps": []}, {})


def test_rejects_duplicate_gap_ids():
    with pytest.raises(EvidenceCoverageError, match="Duplicate gap_id"):
        build_coverage_matrix(triage([gap(), gap()]), {})


def test_rejects_gap_missing_source_path():
    bad = gap()
    bad.pop("source_path")
    with pytest.raises(EvidenceCoverageError, match="no source_path"):
        build_coverage_matrix(triage([bad]), {})


def test_markdown_contains_matrix_and_safety():
    report = build_coverage_matrix(triage([gap()]), {})
    markdown = render_markdown(report)
    assert "## Coverage matrix" in markdown
    assert "EVIDENCE_METADATA" in markdown
    assert "Read-only analysis" in markdown
    assert "No source files or system configuration were modified." in markdown


def test_file_outputs_round_trip(tmp_path):
    triage_file = tmp_path / "triage.json"
    source_file = tmp_path / "source.json"
    json_out = tmp_path / "coverage.json"
    md_out = tmp_path / "coverage.md"
    triage_file.write_text(json.dumps(triage([gap()])), encoding="utf-8")
    source_file.write_text(json.dumps({"status": "REVIEW_REQUIRED"}), encoding="utf-8")

    report = audit_files(triage_file, source_file, json_out, md_out)
    assert json.loads(json_out.read_text(encoding="utf-8")) == report
    assert "Coverage matrix" in md_out.read_text(encoding="utf-8")
    assert report["safety"]["automatic_remediation"] is False


def test_refuses_input_overwrite(tmp_path):
    triage_file = tmp_path / "triage.json"
    source_file = tmp_path / "source.json"
    md_out = tmp_path / "coverage.md"
    triage_file.write_text(json.dumps(triage()), encoding="utf-8")
    source_file.write_text("{}", encoding="utf-8")
    with pytest.raises(EvidenceCoverageError, match="overwrite an input"):
        audit_files(triage_file, source_file, triage_file, md_out)


def test_refuses_existing_output(tmp_path):
    triage_file = tmp_path / "triage.json"
    source_file = tmp_path / "source.json"
    json_out = tmp_path / "coverage.json"
    md_out = tmp_path / "coverage.md"
    triage_file.write_text(json.dumps(triage()), encoding="utf-8")
    source_file.write_text("{}", encoding="utf-8")
    json_out.write_text("{}", encoding="utf-8")
    with pytest.raises(EvidenceCoverageError, match="existing output"):
        audit_files(triage_file, source_file, json_out, md_out)


def test_rejects_invalid_source_json(tmp_path):
    triage_file = tmp_path / "triage.json"
    source_file = tmp_path / "source.json"
    triage_file.write_text(json.dumps(triage()), encoding="utf-8")
    source_file.write_text("{", encoding="utf-8")
    with pytest.raises(EvidenceCoverageError, match="Invalid JSON"):
        audit_files(triage_file, source_file, tmp_path / "out.json", tmp_path / "out.md")


def test_safety_flags_are_fixed():
    report = build_coverage_matrix(triage([gap()]), {})
    assert report["safety"] == {
        "read_only": True,
        "automatic_remediation": False,
        "source_files_modified": False,
        "system_changes_performed": False,
    }
